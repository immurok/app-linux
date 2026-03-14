"""
immurok BLE 通信模块 — dbus-fast 直接访问 BlueZ GATT

设备作为 HID 键盘已由 BlueZ 管理连接，daemon 通过 D-Bus 直接访问
已连接设备的自定义 GATT 服务，无需 BleakClient.connect()。

协议严格匹配 docs/protocol.md + docs/security.md。
"""

import asyncio
import logging
import struct
from typing import Callable, Optional

from dbus_fast import BusType, Variant
from dbus_fast.aio import MessageBus

from .config import (
    BLE_AUTH_TIMEOUT,
    BLE_COMMAND_TIMEOUT,
    BLE_DEVICE_NAME_PREFIX,
    BLE_FP_GATE_TIMEOUT,
    BLE_PAIR_TIMEOUT,
    BLE_RECONNECT_INTERVAL,
    CHAR_CMD_UUID,
    CHAR_RSP_UUID,
    CMD_AUTH_REQUEST,
    CMD_DELETE_FP,
    CMD_ENROLL_START,
    CMD_ENROLL_STATUS,
    CMD_FACTORY_RESET,
    CMD_FP_LIST,
    CMD_FP_MATCH_ACK,
    CMD_FP_MATCH_SIGNED,
    CMD_GET_STATUS,
    CMD_PAIR_CONFIRM,
    CMD_PAIR_INIT,
    CMD_PAIR_STATUS,
    COMPRESSED_PUBKEY_LEN,
    FP_GATE_MAX_FAILURES,
    OTA_CHAR_UUID,
    OTA_READ_POLL_INTERVAL,
    SERVICE_UUID,
    STATUS_BUSY,
    STATUS_ERROR,
    STATUS_FP_GATE_APPROVED,
    STATUS_FP_NOT_MATCH,
    STATUS_INVALID_PARAM,
    STATUS_OK,
    STATUS_TIMEOUT,
    STATUS_WAIT_FP,
)
from .security import (
    PairingData,
    derive_shared_key,
    ecdh_shared_secret,
    generate_p256_keypair,
    verify_fp_match_signed,
)

log = logging.getLogger("immurok.ble")


class BLEError(Exception):
    pass


class PairingError(Exception):
    pass


class AuthError(Exception):
    pass


class ImmurokBLE:
    """immurok 设备 BLE 通信 — 通过 BlueZ D-Bus 直接访问 GATT"""

    def __init__(self) -> None:
        # D-Bus 连接与 GATT 接口
        self._bus: Optional[MessageBus] = None
        self._device_path: Optional[str] = None
        self._device_address: Optional[str] = None
        self._cmd_iface = None   # GattCharacteristic1 for CMD
        self._rsp_iface = None   # GattCharacteristic1 for RSP
        self._ota_iface = None   # GattCharacteristic1 for OTA (0xFEE1)

        self._connected = False
        self._reconnect_enabled = True
        self._pairing: Optional[PairingData] = None

        # 连接参数 (固件通过 0xF0 通知上报)
        self._conn_interval: int = 0   # 单位 1.25ms
        self._conn_latency: int = 0
        self._conn_timeout: int = 0    # 单位 10ms

        # 固件版本 (GET_STATUS 返回)
        self._firmware_version: Optional[str] = None

        # 命令响应（通过通知接收）
        self._cmd_event = asyncio.Event()
        self._cmd_response: Optional[bytes] = None

        # FP-gate 完成事件
        self._gate_event = asyncio.Event()
        self._gate_result: Optional[tuple] = None  # (success, data_or_error)
        self._gate_pending = False
        self._pair_fp_gate = False  # 配对 FP-gate 模式：ACK 不验证 HMAC

        # AUTH 完成事件
        self._auth_event = asyncio.Event()
        self._auth_result: Optional[bool] = None
        self._auth_pending = False
        self._auth_failures = 0

        # 回调
        self.on_connected: Optional[Callable[[], None]] = None
        self.on_disconnected: Optional[Callable[[], None]] = None
        self.on_fp_match: Optional[Callable[[int], None]] = None
        self.on_enroll_progress: Optional[Callable[[int, int, int], None]] = None
        self.on_fp_attempt_failed: Optional[Callable[[int], None]] = None

        # 加载已有配对
        self._pairing = PairingData.load()

    # ── 属性 ───────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def paired(self) -> bool:
        return self._pairing is not None

    @property
    def pairing(self) -> Optional[PairingData]:
        return self._pairing

    # ── 通知处理 ───────────────────────────────────────────────

    def _on_notification(self, _sender, data: bytearray) -> None:
        """RSP 特征值通知路由 — 按 docs/protocol.md 优先级处理"""
        length = len(data)
        if length == 0:
            return

        cmd = data[0]

        # 1. 签名 FP 匹配通知: [0x21][page_id:2B LE][hmac:8B] = 11 字节
        if cmd == CMD_FP_MATCH_SIGNED and length == 11:
            self._handle_fp_match_signed(data)
            return

        # 2. 录入进度通知: [0x11][status:1B][current:1B][total:1B] = 4 字节
        if cmd == CMD_ENROLL_STATUS and length == 4:
            self._handle_enroll_status(data)
            return

        # 3. 连接参数更新通知: [0xF0][interval:2B BE][latency:1B][timeout:2B BE] = 6 字节
        if cmd == 0xF0 and length == 6:
            interval = (data[1] << 8) | data[2]
            latency = data[3]
            timeout = (data[4] << 8) | data[5]
            self._conn_interval = interval
            self._conn_latency = latency
            self._conn_timeout = timeout
            log.info("连接参数更新: interval=%d (%.2fms), latency=%d, timeout=%d (%dms)",
                     interval, interval * 1.25, latency, timeout, timeout * 10)
            return

        # 4. FP-gate: 指纹验证通过 (0x10, 1 字节)
        if cmd == STATUS_FP_GATE_APPROVED and length == 1 and (
            self._gate_pending or self._pair_fp_gate
        ):
            log.debug("FP-gate: 指纹验证通过，等待操作完成")
            return  # 操作仍在进行，继续等待

        # 4. FP 不匹配 (0x07, 1 字节) — gate 或 AUTH
        if cmd == STATUS_FP_NOT_MATCH and length == 1:
            if self._gate_pending:
                self._auth_failures += 1
                remaining = FP_GATE_MAX_FAILURES - self._auth_failures
                log.warning("FP-gate: 指纹不匹配 (剩余 %d 次)", remaining)
                if self.on_fp_attempt_failed:
                    self.on_fp_attempt_failed(remaining)
                if remaining <= 0:
                    self._gate_result = (False, STATUS_FP_NOT_MATCH)
                    self._gate_event.set()
                return
            if self._auth_pending:
                self._auth_failures += 1
                remaining = FP_GATE_MAX_FAILURES - self._auth_failures
                log.warning("AUTH: 指纹不匹配 (剩余 %d 次)", remaining)
                if self.on_fp_attempt_failed:
                    self.on_fp_attempt_failed(remaining)
                if remaining <= 0:
                    self._auth_result = False
                    self._auth_event.set()
                return

        # 5. 操作成功 (0x00, 1 字节) — gate 或 AUTH
        if cmd == STATUS_OK and length == 1:
            if self._gate_pending:
                self._gate_result = (True, None)
                self._gate_event.set()
                return
            if self._auth_pending:
                self._auth_result = True
                self._auth_event.set()
                return

        # 6. 错误状态 (gate 进行中)
        if length == 1 and self._gate_pending and cmd in (
            STATUS_TIMEOUT, STATUS_INVALID_PARAM, STATUS_ERROR
        ):
            log.warning("FP-gate 错误: 0x%02x", cmd)
            self._gate_result = (False, cmd)
            self._gate_event.set()
            return

        # 7. 其他通知 → 命令响应
        log.debug("命令响应通知: cmd=0x%02x len=%d data=%s",
                  cmd, length, data.hex())
        self._cmd_response = bytes(data)
        self._cmd_event.set()

    def _handle_fp_match_signed(self, data: bytearray) -> None:
        """处理签名 FP 通知 [0x21][page_id:2B LE][hmac:8B] (11 字节)"""
        page_id = struct.unpack_from("<H", data, 1)[0]
        hmac_val = bytes(data[3:11])

        # 配对 FP-gate：跳过 HMAC 验证，直接 ACK
        # （重新配对时旧密钥可能已丢失，无法验证）
        if self._pair_fp_gate:
            log.info("配对 FP-gate: page_id=%d (跳过 HMAC 验证)", page_id)
            try:
                asyncio.get_running_loop().create_task(
                    self._send_fp_match_ack()
                )
            except RuntimeError:
                pass
            return

        if self._pairing is None:
            log.warning("收到签名 FP 通知但未配对，忽略")
            return

        if not verify_fp_match_signed(
            self._pairing.shared_key, page_id, hmac_val
        ):
            log.warning("FP 通知 HMAC 验证失败 (page_id=%d)", page_id)
            return

        log.info("指纹匹配 (签名): page_id=%d", page_id)

        # 发送 ACK
        try:
            asyncio.get_running_loop().create_task(self._send_fp_match_ack())
        except RuntimeError:
            pass

        # FP-gate 中收到 FP 匹配 → 等待设备执行结果（不在此处 set gate_event）

        if self.on_fp_match:
            self.on_fp_match(page_id)

    def _handle_enroll_status(self, data: bytearray) -> None:
        """处理录入进度通知 [0x11][status:1B][current:1B][total:1B]"""
        status, current, total = data[1], data[2], data[3]
        log.info("录入进度: status=%d, %d/%d", status, current, total)
        if self.on_enroll_progress:
            self.on_enroll_progress(status, current, total)

    # ── FP_MATCH_ACK ────────────────────────────────────────────

    async def _send_fp_match_ack(self) -> None:
        """发送 FP_MATCH_ACK [0x22][0x00]"""
        if not self._connected or not self._cmd_iface:
            return
        try:
            data = bytes([CMD_FP_MATCH_ACK, 0x00])
            await self._cmd_iface.call_write_value(data, {})
            log.debug("FP_MATCH_ACK 已发送")
        except Exception:
            log.warning("FP_MATCH_ACK 发送失败", exc_info=True)

    # ── 命令发送 ──────────────────────────────────────────────

    async def send_command(self, cmd: int, payload: bytes = b"",
                          timeout: float = BLE_COMMAND_TIMEOUT) -> bytes:
        """
        发送命令并等待响应通知。
        命令格式: [CMD:1][LEN:1][PAYLOAD:N]
        """
        if not self._connected or not self._cmd_iface:
            raise BLEError("未连接")

        data = bytes([cmd, len(payload)]) + payload
        log.debug("发送命令: cmd=0x%02x payload=%s", cmd, payload.hex())

        self._cmd_event.clear()
        self._cmd_response = None

        await self._cmd_iface.call_write_value(data, {})

        try:
            await asyncio.wait_for(self._cmd_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            raise BLEError(f"命令响应超时: cmd=0x{cmd:02x}")

        return self._cmd_response

    # ── FP-gate 命令 ──────────────────────────────────────────

    async def send_fp_gated_command(
        self, cmd: int, payload: bytes = b"",
        timeout: float = BLE_FP_GATE_TIMEOUT,
    ) -> tuple[bool, Optional[int]]:
        """
        发送需要 FP-gate 的命令。

        流程 (docs/protocol.md):
        1. 发送命令
        2. 响应 0x00 → 直接成功 (cooldown 内)
        3. 响应 0x11 → 等待指纹
        4. 设备发 0x21 通知 (FP 匹配) → App 发 0x22 ACK
        5. 设备执行命令 → 发 0x00 (成功) 或错误码

        返回 (success, error_code)。
        """
        rsp = await self.send_command(cmd, payload)
        status = rsp[0]

        if status == STATUS_OK:
            return (True, None)

        if status != STATUS_WAIT_FP:
            return (False, status)

        # 等待 FP-gate 完成
        self._gate_event.clear()
        self._gate_result = None
        self._gate_pending = True
        self._auth_failures = 0

        try:
            try:
                await asyncio.wait_for(
                    self._gate_event.wait(), timeout=timeout
                )
            except asyncio.TimeoutError:
                return (False, STATUS_TIMEOUT)

            if self._gate_result is None:
                return (False, STATUS_ERROR)

            return self._gate_result
        finally:
            self._gate_pending = False

    # ── 高层命令 ───────────────────────────────────────────────

    async def get_status(self) -> tuple[int, bool, int | None]:
        """GET_STATUS → [0x00][fp_bitmap:1B][paired:1B][battery:1B][major][minor][patch][build_hi][build_lo]

        返回 (bitmap, is_paired, battery_level)。
        battery_level 可能为 None（旧固件不发电量）。
        同时更新 firmware_version。
        """
        rsp = await self.send_command(CMD_GET_STATUS)
        if rsp[0] != STATUS_OK or len(rsp) < 3:
            return (0, False, None)
        bitmap = rsp[1]
        is_paired = rsp[2] != 0
        battery = rsp[3] if len(rsp) >= 4 else None
        if len(rsp) >= 9:
            build = (rsp[7] << 8) | rsp[8]
            self._firmware_version = f"{rsp[4]}.{rsp[5]}.{rsp[6]}.{build:x}"
        elif len(rsp) >= 7:
            self._firmware_version = f"{rsp[4]}.{rsp[5]}.{rsp[6]}"
        return (bitmap, is_paired, battery)

    async def get_pair_status(self) -> int:
        """PAIR_STATUS → [0x32][paired:1B]"""
        rsp = await self.send_command(CMD_PAIR_STATUS)
        if len(rsp) >= 2 and rsp[0] == CMD_PAIR_STATUS:
            return rsp[1]
        return rsp[0]

    async def fp_list(self) -> int:
        """FP_LIST → [0x00][bitmap:1B]。返回 bitmap。"""
        rsp = await self.send_command(CMD_FP_LIST)
        if rsp[0] != STATUS_OK or len(rsp) < 2:
            return 0
        return rsp[1]

    async def enroll_start(self, slot_id: int) -> tuple[bool, Optional[int]]:
        """开始指纹录入 (FP-gated)。"""
        return await self.send_fp_gated_command(
            CMD_ENROLL_START, bytes([slot_id])
        )

    async def delete_fp(self, slot_id: int) -> tuple[bool, Optional[int]]:
        """删除指纹 (FP-gated)。"""
        return await self.send_fp_gated_command(
            CMD_DELETE_FP, bytes([slot_id])
        )

    # ── ECDH 配对流程 ────────────────────────────────────────

    async def pair(self, _retries: int = 3) -> PairingData:
        """
        执行 ECDH P-256 配对流程 (docs/security.md)。

        1. PAIR_INIT [0x30][0x00] → [0x30][device_pubkey:33B]
           (若设备已有指纹，会先 FP-gate: 0x11 → 触摸 → 0x21/ACK → 0x30)
        2. App 生成 P-256 密钥对
        3. PAIR_CONFIRM [0x31][app_pubkey:33B] → [0x31][0x00]
        4. ECDH → HKDF → shared_key
        5. 持久化
        """
        # Step 1: PAIR_INIT
        rsp = await self.send_command(
            CMD_PAIR_INIT, b"", timeout=BLE_PAIR_TIMEOUT
        )

        # 0xE1 = BLE supervision timeout 不足，固件已请求参数更新，等待后重试
        if len(rsp) == 1 and rsp[0] == 0xE1:
            if _retries > 0:
                log.warning("PAIR_INIT 被拒 (连接参数不足)，5s 后重试 (剩余 %d 次)", _retries)
                await asyncio.sleep(5.0)
                return await self.pair(_retries=_retries - 1)
            raise PairingError("PAIR_INIT 失败: BLE 连接参数更新未完成")

        # FP-gated: 设备已有指纹，需先验证
        if len(rsp) == 1 and rsp[0] == STATUS_WAIT_FP:
            log.info("配对需要指纹验证，请触摸传感器")
            rsp = await self._wait_pair_fp_gate()

        # 0xE1 也可能在 FP-gate 之后返回（gate 通过后固件才检查连接参数）
        if len(rsp) == 1 and rsp[0] == 0xE1:
            if _retries > 0:
                log.warning("PAIR_INIT 被拒 (连接参数不足)，5s 后重试 (剩余 %d 次)", _retries)
                await asyncio.sleep(5.0)
                return await self.pair(_retries=_retries - 1)
            raise PairingError("PAIR_INIT 失败: BLE 连接参数更新未完成")

        if len(rsp) < 1 + COMPRESSED_PUBKEY_LEN or rsp[0] != CMD_PAIR_INIT:
            raise PairingError(
                f"PAIR_INIT 失败: len={len(rsp)}, data={rsp.hex()}"
            )
        device_pubkey = bytes(rsp[1 : 1 + COMPRESSED_PUBKEY_LEN])
        log.info("收到设备公钥: %s", device_pubkey.hex()[:20] + "...")

        # Step 2: 生成 App 密钥对
        app_privkey, app_pubkey = generate_p256_keypair()

        # Step 3: PAIR_CONFIRM
        rsp = await self.send_command(
            CMD_PAIR_CONFIRM, app_pubkey, timeout=BLE_PAIR_TIMEOUT
        )
        if len(rsp) < 2 or rsp[0] != CMD_PAIR_CONFIRM or rsp[1] != STATUS_OK:
            raise PairingError(
                f"PAIR_CONFIRM 失败: data={rsp.hex()}"
            )

        # Step 4: ECDH + HKDF
        shared_secret = ecdh_shared_secret(app_privkey, device_pubkey)
        shared_key = derive_shared_key(shared_secret)

        # Step 5: 持久化
        pairing = PairingData(shared_key=shared_key)
        pairing.save()
        self._pairing = pairing
        log.info("ECDH 配对成功")
        return pairing

    async def _wait_pair_fp_gate(self) -> bytes:
        """
        等待配对 FP-gate 完成。

        流程: 0x11(WAIT_FP) → 用户触摸 → 0x21(FP 匹配,ACK) →
              0x10(gate 通过) → [0x30][pubkey:33B]
        0x10 会被通知处理器拦截，不会到达此处。
        0x07(FP 不匹配) 会路由到 _cmd_event。
        """
        self._pair_fp_gate = True
        self._auth_failures = 0

        try:
            while True:
                self._cmd_event.clear()
                self._cmd_response = None
                try:
                    await asyncio.wait_for(
                        self._cmd_event.wait(), timeout=BLE_PAIR_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    raise PairingError("配对超时")

                rsp = self._cmd_response
                if rsp is None:
                    raise PairingError("配对失败: 连接断开")

                # FP 不匹配 → 计数，继续等待
                if len(rsp) == 1 and rsp[0] == STATUS_FP_NOT_MATCH:
                    self._auth_failures += 1
                    remaining = FP_GATE_MAX_FAILURES - self._auth_failures
                    log.warning("配对指纹不匹配 (剩余 %d 次)", remaining)
                    if self.on_fp_attempt_failed:
                        self.on_fp_attempt_failed(remaining)
                    if remaining <= 0:
                        raise PairingError("指纹验证失败次数过多")
                    continue

                # 其他错误
                if len(rsp) == 1 and rsp[0] in (
                    STATUS_TIMEOUT, STATUS_ERROR, STATUS_BUSY,
                ):
                    raise PairingError(
                        f"配对 FP-gate 失败: 0x{rsp[0]:02x}"
                    )

                # 实际响应 (应为 [0x30][pubkey:33B])
                return rsp
        finally:
            self._pair_fp_gate = False

    # ── AUTH_REQUEST 流程 ──────────────────────────────────────

    async def auth_request(self) -> bool:
        """
        执行认证请求 (docs/protocol.md)。

        1. 发送 [0x33][0x00]
        2. 响应 [0x11] = WAIT_FP
        3. 用户触摸传感器
        4. 通知 [0x00] = 成功 / [0x07] = 不匹配
        """
        if self._pairing is None:
            raise AuthError("未配对")

        rsp = await self.send_command(CMD_AUTH_REQUEST)
        status = rsp[0]
        if status != STATUS_WAIT_FP:
            raise AuthError(f"AUTH_REQUEST 失败: 0x{status:02x}")

        log.info("等待指纹验证...")
        self._auth_event.clear()
        self._auth_result = None
        self._auth_pending = True
        self._auth_failures = 0

        try:
            try:
                await asyncio.wait_for(
                    self._auth_event.wait(), timeout=BLE_AUTH_TIMEOUT
                )
            except asyncio.TimeoutError:
                log.warning("认证超时")
                return False

            if self._auth_result is True:
                log.info("认证成功")
                return True
            else:
                log.warning("认证失败")
                return False
        finally:
            self._auth_pending = False

    # ── 出厂重置 ───────────────────────────────────────────────

    async def factory_reset(self) -> tuple[bool, Optional[int]]:
        """出厂重置 (FP-gated)。"""
        return await self.send_fp_gated_command(CMD_FACTORY_RESET)

    # ── OTA 方法 ───────────────────────────────────────────────

    @property
    def ota_available(self) -> bool:
        return self._connected and self._ota_iface is not None

    async def ota_write_and_read(
        self, data: bytes, timeout: float = 5.0,
        poll_interval: float = OTA_READ_POLL_INTERVAL,
    ) -> Optional[bytes]:
        """写入 OTA 特征并轮询读取响应（用于需要回复的命令）"""
        if not self._ota_iface:
            return None
        await self._ota_iface.call_write_value(data, {})
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            await asyncio.sleep(poll_interval)
            try:
                result = await self._ota_iface.call_read_value({})
                if result and len(result) > 0:
                    return bytes(result)
            except Exception:
                pass
        return None

    async def ota_write(self, data: bytes) -> bool:
        """写入 OTA 特征（write-with-response，等待 BLE 确认）"""
        if not self._ota_iface:
            return False
        try:
            await self._ota_iface.call_write_value(data, {})
            return True
        except Exception:
            log.warning("OTA write 失败", exc_info=True)
            return False

    # ── 连接管理 ──────────────────────────────────────────────

    async def _attach_gatt(self, device_path: str, address: str) -> None:
        """通过 D-Bus 直接访问已连接设备的 GATT 服务。"""
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

        try:
            introspection = await bus.introspect("org.bluez", "/")
            obj = bus.get_proxy_object("org.bluez", "/", introspection)
            manager = obj.get_interface(
                "org.freedesktop.DBus.ObjectManager"
            )
            objects = await manager.call_get_managed_objects()

            cmd_path = None
            rsp_path = None
            ota_path = None
            for path, interfaces in objects.items():
                if not path.startswith(device_path):
                    continue
                if "org.bluez.GattCharacteristic1" not in interfaces:
                    continue
                props = interfaces["org.bluez.GattCharacteristic1"]
                uuid = props.get("UUID", "")
                if hasattr(uuid, "value"):
                    uuid = uuid.value
                if uuid.lower() == CHAR_CMD_UUID:
                    cmd_path = path
                elif uuid.lower() == CHAR_RSP_UUID:
                    rsp_path = path
                elif uuid.lower() == OTA_CHAR_UUID:
                    ota_path = path

            if not cmd_path or not rsp_path:
                bus.disconnect()
                raise BLEError(
                    f"未找到 immurok GATT 特征 (CMD={cmd_path}, RSP={rsp_path})"
                )

            log.debug("GATT 特征: CMD=%s, RSP=%s", cmd_path, rsp_path)

            # CMD 特征接口
            cmd_intro = await bus.introspect("org.bluez", cmd_path)
            cmd_obj = bus.get_proxy_object("org.bluez", cmd_path, cmd_intro)
            self._cmd_iface = cmd_obj.get_interface(
                "org.bluez.GattCharacteristic1"
            )

            # RSP 特征接口 + 订阅通知
            rsp_intro = await bus.introspect("org.bluez", rsp_path)
            rsp_obj = bus.get_proxy_object("org.bluez", rsp_path, rsp_intro)
            self._rsp_iface = rsp_obj.get_interface(
                "org.bluez.GattCharacteristic1"
            )

            rsp_props = rsp_obj.get_interface(
                "org.freedesktop.DBus.Properties"
            )
            rsp_props.on_properties_changed(self._on_rsp_properties_changed)
            await self._rsp_iface.call_start_notify()

            # OTA 特征接口 (可选)
            if ota_path:
                ota_intro = await bus.introspect("org.bluez", ota_path)
                ota_obj = bus.get_proxy_object(
                    "org.bluez", ota_path, ota_intro
                )
                self._ota_iface = ota_obj.get_interface(
                    "org.bluez.GattCharacteristic1"
                )
                log.info("OTA 特征已发现: %s", ota_path)
            else:
                log.debug("未发现 OTA 特征")

            # 设备断线检测
            dev_intro = await bus.introspect("org.bluez", device_path)
            dev_obj = bus.get_proxy_object(
                "org.bluez", device_path, dev_intro
            )
            dev_props = dev_obj.get_interface(
                "org.freedesktop.DBus.Properties"
            )
            dev_props.on_properties_changed(
                self._on_device_properties_changed
            )

        except Exception:
            bus.disconnect()
            raise

        self._bus = bus
        self._device_path = device_path
        self._device_address = address
        self._connected = True
        log.info("已连接 GATT: %s (%s)", address, device_path)

        if self.on_connected:
            self.on_connected()

    def _on_rsp_properties_changed(
        self, interface: str, changed: dict, invalidated: list
    ) -> None:
        if interface != "org.bluez.GattCharacteristic1":
            return
        if "Value" not in changed:
            return
        value = changed["Value"]
        if hasattr(value, "value"):
            value = value.value
        self._on_notification(None, bytearray(value))

    def _on_device_properties_changed(
        self, interface: str, changed: dict, invalidated: list
    ) -> None:
        if interface != "org.bluez.Device1":
            return
        if "Connected" not in changed:
            return
        connected = changed["Connected"]
        if hasattr(connected, "value"):
            connected = connected.value
        if not connected:
            self._handle_disconnect()

    def _handle_disconnect(self) -> None:
        if not self._connected:
            return
        self._connected = False
        self._cmd_iface = None
        self._rsp_iface = None
        self._ota_iface = None
        self._device_path = None
        self._device_address = None
        self._conn_interval = 0
        self._conn_latency = 0
        self._conn_timeout = 0
        self._firmware_version = None
        if self._bus:
            self._bus.disconnect()
            self._bus = None
        log.info("连接断开")
        if self.on_disconnected:
            self.on_disconnected()
        # 唤醒等待中的 gate/auth
        if self._gate_pending:
            self._gate_result = (False, "disconnected")
            self._gate_event.set()
        if self._auth_pending:
            self._auth_result = False
            self._auth_event.set()

    async def scan_and_connect(self) -> None:
        """查找并连接 immurok 设备，断线自动重连。"""
        while self._reconnect_enabled:
            try:
                result = await self._find_connected_device()
                if result:
                    address, device_path = result
                    log.info(
                        "在 BlueZ 已连接设备中找到 immurok: %s", address
                    )
                    await self._attach_gatt(device_path, address)
                    while self._connected:
                        await asyncio.sleep(1.0)
                else:
                    log.debug("未发现已连接的 immurok 设备")
            except BLEError as e:
                log.debug("BLE 错误: %s", e)
            except Exception:
                log.exception("scan_and_connect 异常")

            if self._reconnect_enabled:
                await asyncio.sleep(BLE_RECONNECT_INTERVAL)

    async def _find_connected_device(
        self,
    ) -> Optional[tuple[str, str]]:
        """在 BlueZ 已连接设备中查找 immurok。"""
        try:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                introspection = await bus.introspect("org.bluez", "/")
                obj = bus.get_proxy_object("org.bluez", "/", introspection)
                manager = obj.get_interface(
                    "org.freedesktop.DBus.ObjectManager"
                )
                objects = await manager.call_get_managed_objects()

                for path, interfaces in objects.items():
                    if "org.bluez.Device1" not in interfaces:
                        continue
                    props = interfaces["org.bluez.Device1"]
                    name = props.get("Name", props.get("Alias", ""))
                    if hasattr(name, "value"):
                        name = name.value
                    connected = props.get("Connected", False)
                    if hasattr(connected, "value"):
                        connected = connected.value
                    address = props.get("Address", "")
                    if hasattr(address, "value"):
                        address = address.value

                    if (
                        isinstance(name, str)
                        and name.lower().startswith(BLE_DEVICE_NAME_PREFIX)
                        and connected
                    ):
                        return (address, path)
            finally:
                bus.disconnect()
        except Exception:
            log.debug("BlueZ D-Bus 查询失败", exc_info=True)

        return None

    async def disconnect(self) -> None:
        self._reconnect_enabled = False
        if self._rsp_iface and self._connected:
            try:
                await self._rsp_iface.call_stop_notify()
            except Exception:
                pass
        self._handle_disconnect()

    def enable_reconnect(self) -> None:
        self._reconnect_enabled = True

    def disable_reconnect(self) -> None:
        self._reconnect_enabled = False
