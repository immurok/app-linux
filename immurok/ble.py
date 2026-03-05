"""
immurok BLE 通信模块 — dbus-fast 直接访问 BlueZ GATT

设备作为 HID 键盘已由 BlueZ 管理连接，daemon 通过 D-Bus 直接访问
已连接设备的自定义 GATT 服务，无需 BleakClient.connect()。

协议严格匹配固件 ble_hid_kbd.c / immurok_security.c。
命令响应通过 write CMD + read RSP 获取；异步事件通过 RSP 通知到达。
"""

import asyncio
import logging
import os
import struct
from typing import Callable, Optional

from dbus_fast import BusType
from dbus_fast.aio import MessageBus

from .config import (
    BLE_AUTH_TIMEOUT,
    BLE_COMMAND_TIMEOUT,
    BLE_DEVICE_NAME_PREFIX,
    BLE_PAIR_MAX_RETRIES,
    BLE_PAIR_POLL_INTERVAL,
    BLE_RECONNECT_INTERVAL,
    BLE_SCAN_TIMEOUT,
    CHALLENGE_LEN,
    CHAR_CMD_UUID,
    CHAR_RSP_UUID,
    CMD_AUTH_REQUEST,
    CMD_DELETE_FP,
    CMD_ENROLL_START,
    CMD_ENROLL_STATUS,
    CMD_FACTORY_RESET,
    CMD_FP_LIST,
    CMD_FP_MATCHED,
    CMD_FP_MATCH_ACK,
    CMD_FP_MATCH_SIGNED,
    CMD_GET_CMD_CHALLENGE,
    CMD_GET_PAIR_STATUS,
    CMD_GET_STATUS,
    CMD_PAIR_CONFIRM,
    CMD_PAIR_INIT,
    DEVICE_ID_LEN,
    HMAC_FULL_LEN,
    HMAC_TRUNCATED_LEN,
    NONCE_LEN,
    RANDOM_LEN,
    SERVICE_UUID,
    STATUS_INVALID_STATE,
    STATUS_OK,
    STATUS_TIMEOUT,
    STATUS_WAIT_BUTTON,
    STATUS_WAIT_FP,
)
from .security import (
    PairingData,
    compute_cmd_hmac,
    derive_shared_key,
    get_host_id,
    verify_auth_response,
    verify_fp_match_signed,
)

log = logging.getLogger("immurok.ble")


class BLEError(Exception):
    """BLE 操作错误"""
    pass


class ImmurokBLE:
    """ESP32H2 immurok 设备 BLE 通信 — 通过 BlueZ D-Bus 直接访问 GATT"""

    def __init__(self) -> None:
        # D-Bus 连接与 GATT 接口
        self._bus: Optional[MessageBus] = None
        self._device_path: Optional[str] = None
        self._device_address: Optional[str] = None
        self._cmd_iface = None   # GattCharacteristic1 for CMD
        self._rsp_iface = None   # GattCharacteristic1 for RSP

        self._connected = False
        self._reconnect_enabled = True
        self._pairing: Optional[PairingData] = None

        # 异步事件：命令响应（通过通知接收）
        self._cmd_event = asyncio.Event()
        self._cmd_response: Optional[bytes] = None

        # 异步事件：AUTH_RESPONSE 通知
        self._auth_event = asyncio.Event()
        self._auth_result: Optional[tuple] = None  # (success, ...)
        self._auth_pending = False

        # 回调
        self.on_connected: Optional[Callable[[], None]] = None
        self.on_disconnected: Optional[Callable[[], None]] = None
        self.on_fp_match: Optional[Callable[[int, bool], None]] = None
        self.on_enroll_progress: Optional[Callable[[int, int, int], None]] = None

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

    def _on_notification(self, _sender: int, data: bytearray) -> None:
        """RSP 特征值通知路由"""
        length = len(data)
        if length == 0:
            return

        cmd = data[0]

        # 签名指纹匹配 (配对后) — 15 字节 (CH592F 无 counter)
        if cmd == CMD_FP_MATCH_SIGNED and length == 15:
            self._handle_fp_match_signed(data)
            return

        # 未签名指纹匹配 (未配对) — 3 字节
        if cmd == CMD_FP_MATCHED and length == 3:
            self._handle_fp_matched(data)
            return

        # 录入进度 — 4 字节
        if cmd == CMD_ENROLL_STATUS and length == 4:
            self._handle_enroll_status(data)
            return

        # AUTH_RESPONSE 成功 — 9 字节: [0x00][hmac:8] (CH592F 无 counter)
        if cmd == STATUS_OK and length == 9 and self._auth_pending:
            hmac_val = bytes(data[1:9])
            self._auth_result = (True, hmac_val)
            self._auth_event.set()
            return

        # AUTH 错误 (1 字节状态码，auth 进行中)
        if length == 1 and self._auth_pending and cmd != STATUS_OK:
            log.warning("AUTH 错误通知: 0x%02x", cmd)
            self._auth_result = (False, cmd)
            self._auth_event.set()
            return

        # 其他通知视为命令响应
        log.debug("命令响应通知: cmd=0x%02x len=%d data=%s",
                  cmd, length, data.hex())
        self._cmd_response = bytes(data)
        self._cmd_event.set()

    def _handle_fp_match_signed(self, data: bytearray) -> None:
        """处理签名指纹匹配通知 [0x21][page_id:2][ts:4][hmac:8] (CH592F 无 counter)"""
        page_id = struct.unpack_from("<H", data, 1)[0]
        timestamp = struct.unpack_from("<I", data, 3)[0]
        hmac_val = bytes(data[7:15])

        if self._pairing is None:
            log.warning("收到签名 FP 通知但未配对，忽略")
            return

        # HMAC 验证
        if not verify_fp_match_signed(
            self._pairing.shared_key, page_id, timestamp, hmac_val
        ):
            log.warning("FP 通知 HMAC 验证失败 (page_id=%d)", page_id)
            return

        log.info("指纹匹配 (签名): page_id=%d", page_id)
        # 发送 ACK 给固件
        try:
            asyncio.get_running_loop().create_task(self._send_fp_match_ack())
        except RuntimeError:
            pass  # 无 running loop (测试环境)
        if self.on_fp_match:
            self.on_fp_match(page_id, True)

    def _handle_fp_matched(self, data: bytearray) -> None:
        """处理未签名指纹匹配通知 [0x20][page_id:2 LE]"""
        if self._pairing is not None:
            log.warning("已配对但收到未签名 FP 通知，忽略")
            return
        page_id = struct.unpack_from("<H", data, 1)[0]
        log.info("指纹匹配 (未签名): page_id=%d", page_id)
        if self.on_fp_match:
            self.on_fp_match(page_id, False)

    def _handle_enroll_status(self, data: bytearray) -> None:
        """处理录入进度通知 [0x11][status:1][current:1][total:1]"""
        status, current, total = data[1], data[2], data[3]
        log.info("录入进度: status=%d, %d/%d", status, current, total)
        if self.on_enroll_progress:
            self.on_enroll_progress(status, current, total)

    # ── FP_MATCH_ACK ────────────────────────────────────────────

    async def _send_fp_match_ack(self) -> None:
        """发送 FP_MATCH_ACK [0x22][0x00] 确认收到签名指纹匹配。"""
        if not self._connected or not self._cmd_iface:
            log.warning("无法发送 FP_MATCH_ACK: 未连接")
            return
        try:
            data = bytes([CMD_FP_MATCH_ACK, 0x00])
            await self._cmd_iface.call_write_value(data, {})
            log.debug("FP_MATCH_ACK 已发送")
        except Exception:
            log.warning("FP_MATCH_ACK 发送失败", exc_info=True)

    # ── 命令发送 (write CMD + read RSP via D-Bus) ──────────────

    async def send_command(self, cmd: int, payload: bytes = b"",
                          timeout: float = BLE_COMMAND_TIMEOUT) -> bytes:
        """
        发送命令并等待响应通知。

        固件命令格式: [CMD:1][LEN:1][PAYLOAD:N]
        响应通过 RSP 特征值通知接收。
        """
        if not self._connected or not self._cmd_iface:
            raise BLEError("未连接")

        data = bytes([cmd, len(payload)]) + payload
        log.debug("发送命令: cmd=0x%02x payload=%s", cmd, payload.hex())

        # 清空命令响应状态
        self._cmd_event.clear()
        self._cmd_response = None

        await self._cmd_iface.call_write_value(data, {})

        # 等待通知带回响应
        try:
            await asyncio.wait_for(
                self._cmd_event.wait(), timeout=timeout
            )
        except asyncio.TimeoutError:
            raise BLEError(f"命令响应超时: cmd=0x{cmd:02x}")

        response = self._cmd_response
        log.debug("命令响应: %s", response.hex())
        return response

    # ── 命令认证 ───────────────────────────────────────────────

    async def get_cmd_challenge(self) -> bytes:
        """获取命令认证 challenge (8 字节)。"""
        rsp = await self.send_command(CMD_GET_CMD_CHALLENGE)
        if rsp[0] != STATUS_OK or len(rsp) < 1 + CHALLENGE_LEN:
            raise BLEError(f"GET_CMD_CHALLENGE 失败: 0x{rsp[0]:02x}")
        return bytes(rsp[1 : 1 + CHALLENGE_LEN])

    async def send_authenticated_command(
        self, cmd: int, payload: bytes = b""
    ) -> bytes:
        """
        发送需要命令认证的命令。

        流程: GET_CMD_CHALLENGE → HMAC(cmd||payload||challenge) → 发送
        认证后的 payload = original_payload + challenge(8) + hmac(8)
        """
        if self._pairing is None:
            raise BLEError("未配对，无法执行认证命令")

        challenge = await self.get_cmd_challenge()
        hmac_val = compute_cmd_hmac(
            self._pairing.shared_key, cmd, payload, challenge
        )

        auth_payload = payload + challenge + hmac_val
        return await self.send_command(cmd, auth_payload)

    # ── 高层命令 ───────────────────────────────────────────────

    async def get_status(self) -> int:
        rsp = await self.send_command(CMD_GET_STATUS)
        return rsp[0]

    async def get_pair_status(self) -> int:
        rsp = await self.send_command(CMD_GET_PAIR_STATUS)
        return rsp[0]

    async def fp_list(self) -> int:
        """获取指纹 bitmap。返回值每一位表示对应 slot 是否有指纹。"""
        rsp = await self.send_command(CMD_FP_LIST)
        if rsp[0] != STATUS_OK or len(rsp) < 2:
            return 0
        return rsp[1]

    async def enroll_start(self, slot_id: int) -> int:
        """开始指纹录入（需命令认证）。成功返回 0x00。"""
        rsp = await self.send_authenticated_command(
            CMD_ENROLL_START, bytes([slot_id])
        )
        return rsp[0]

    async def delete_fp(self, slot_id: int) -> int:
        """删除指纹（需命令认证）。"""
        rsp = await self.send_authenticated_command(
            CMD_DELETE_FP, bytes([slot_id])
        )
        return rsp[0]

    # ── 配对流程 ───────────────────────────────────────────────

    async def pair(self) -> PairingData:
        """
        执行完整配对流程。

        1. 发送 PAIR_INIT [0x30][host_id:16]
        2. 收到 [0x10][device_random:16]
        3. 循环发送 PAIR_CONFIRM [0x31][host_random:16]
           - 0x10/0xFD → 继续等待按钮
           - 0x00 + device_id → 成功
           - 0x06 → 超时
        4. HKDF 推导共享密钥，持久化
        """
        host_id = get_host_id()
        host_random = os.urandom(RANDOM_LEN)

        # Step 1: PAIR_INIT
        rsp = await self.send_command(CMD_PAIR_INIT, host_id)
        status = rsp[0]
        if status != STATUS_WAIT_BUTTON:
            raise PairingError(f"PAIR_INIT 失败: 0x{status:02x}")
        if len(rsp) < 1 + RANDOM_LEN:
            raise PairingError("PAIR_INIT 响应长度不足")
        device_random = rsp[1 : 1 + RANDOM_LEN]

        # Step 2: PAIR_CONFIRM 轮询 (等待用户按物理按钮)
        log.info("等待设备按钮确认...")
        device_id = None
        for _ in range(BLE_PAIR_MAX_RETRIES):
            await asyncio.sleep(BLE_PAIR_POLL_INTERVAL)

            rsp = await self.send_command(CMD_PAIR_CONFIRM, host_random)
            status = rsp[0]

            if status == STATUS_OK and len(rsp) >= 1 + DEVICE_ID_LEN:
                device_id = bytes(rsp[1 : 1 + DEVICE_ID_LEN])
                break
            elif status in (STATUS_WAIT_BUTTON, STATUS_INVALID_STATE):
                continue
            elif status == STATUS_TIMEOUT:
                raise PairingError("配对超时 (设备端)")
            else:
                raise PairingError(f"PAIR_CONFIRM 失败: 0x{status:02x}")

        if device_id is None:
            raise PairingError("配对超时 (未在限时内按下按钮)")

        # Step 3: 推导共享密钥 (Salt = host_id)
        shared_key = derive_shared_key(host_random, device_random, host_id)

        # Step 4: 持久化
        pairing = PairingData(
            device_id=device_id,
            shared_key=shared_key,
            host_id=host_id,
        )
        pairing.save()
        self._pairing = pairing
        log.info("配对成功: device_id=%s", device_id.hex())
        return pairing

    # ── AUTH_REQUEST 流程 ──────────────────────────────────────

    async def auth_request(self) -> bool:
        """
        执行认证请求。等待用户触摸指纹传感器，验证响应 HMAC。

        CH592F 流程 (无 counter):
        1. challenge = random(8)
        2. 发送 [0x33][0x08][challenge:8]
        3. 收到 [0x11][device_nonce:8]
        4. 等待 AUTH_RESPONSE 通知 (最长 60 秒)
        5. 收到 [0x00][hmac:8]
        6. 验证 HMAC(challenge || device_nonce || "auth-ok") → True/False
        """
        if self._pairing is None:
            raise AuthError("未配对")

        challenge = os.urandom(CHALLENGE_LEN)
        payload = challenge

        # 清空 auth 状态
        self._auth_event.clear()
        self._auth_result = None
        self._auth_pending = True

        try:
            # 发送 AUTH_REQUEST
            rsp = await self.send_command(CMD_AUTH_REQUEST, payload)
            status = rsp[0]
            if status != STATUS_WAIT_FP:
                raise AuthError(f"AUTH_REQUEST 失败: 0x{status:02x}")
            if len(rsp) < 1 + NONCE_LEN:
                raise AuthError("AUTH_REQUEST 响应长度不足")

            device_nonce = bytes(rsp[1 : 1 + NONCE_LEN])
            log.info("等待指纹验证...")

            # 等待 AUTH_RESPONSE 通知
            try:
                await asyncio.wait_for(
                    self._auth_event.wait(), timeout=BLE_AUTH_TIMEOUT
                )
            except asyncio.TimeoutError:
                raise AuthError("认证超时 (等待指纹)")

            result = self._auth_result
            if result is None or not result[0]:
                error = result[1] if result and len(result) > 1 else "unknown"
                log.warning("认证失败: %s", error)
                return False

            # 验证 HMAC (CH592F: 无 counter)
            _, resp_hmac = result
            if not verify_auth_response(
                self._pairing.shared_key,
                challenge,
                device_nonce,
                resp_hmac,
            ):
                log.warning("AUTH_RESPONSE HMAC 验证失败")
                return False

            log.info("认证成功")
            return True

        finally:
            self._auth_pending = False

    # ── 出厂重置 ───────────────────────────────────────────────

    async def factory_reset(self, hmac: bytes = b"") -> int:
        """
        出厂重置。已配对时需提供 32 字节 HMAC。
        返回状态码 (0x10=等待按钮确认)。
        """
        rsp = await self.send_command(CMD_FACTORY_RESET, hmac)
        return rsp[0]

    # ── 连接管理 (D-Bus 直接访问 BlueZ GATT) ────────────────────

    async def _attach_gatt(self, device_path: str, address: str) -> None:
        """
        通过 D-Bus 直接访问已连接设备的 GATT 服务。

        不调用 BleakClient.connect()（在已连接 HID 设备上会卡住），
        而是直接通过 BlueZ D-Bus API 访问 GattCharacteristic1 接口。
        """
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

        try:
            # 枚举 BlueZ 管理的所有对象，找到我们的 GATT 特征
            introspection = await bus.introspect("org.bluez", "/")
            obj = bus.get_proxy_object("org.bluez", "/", introspection)
            manager = obj.get_interface(
                "org.freedesktop.DBus.ObjectManager"
            )
            objects = await manager.call_get_managed_objects()

            cmd_path = None
            rsp_path = None
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

            if not cmd_path or not rsp_path:
                bus.disconnect()
                raise BLEError(
                    f"未找到 immurok GATT 特征 (CMD={cmd_path}, RSP={rsp_path})"
                )

            log.debug("GATT 特征: CMD=%s, RSP=%s", cmd_path, rsp_path)

            # 获取 CMD 特征接口
            cmd_intro = await bus.introspect("org.bluez", cmd_path)
            cmd_obj = bus.get_proxy_object("org.bluez", cmd_path, cmd_intro)
            self._cmd_iface = cmd_obj.get_interface(
                "org.bluez.GattCharacteristic1"
            )

            # 获取 RSP 特征接口 + 订阅通知
            rsp_intro = await bus.introspect("org.bluez", rsp_path)
            rsp_obj = bus.get_proxy_object("org.bluez", rsp_path, rsp_intro)
            self._rsp_iface = rsp_obj.get_interface(
                "org.bluez.GattCharacteristic1"
            )

            # RSP PropertiesChanged → 通知回调
            rsp_props = rsp_obj.get_interface(
                "org.freedesktop.DBus.Properties"
            )
            rsp_props.on_properties_changed(self._on_rsp_properties_changed)
            await self._rsp_iface.call_start_notify()

            # 设备 PropertiesChanged → 断线检测
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
        """RSP 特征值 PropertiesChanged → 通知路由"""
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
        """设备 PropertiesChanged → 断线检测"""
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
        """处理断线（D-Bus 通知或主动断开）"""
        if not self._connected:
            return
        self._connected = False
        self._cmd_iface = None
        self._rsp_iface = None
        self._device_path = None
        self._device_address = None
        # 关闭 D-Bus 连接
        if self._bus:
            self._bus.disconnect()
            self._bus = None
        log.info("连接断开")
        if self.on_disconnected:
            self.on_disconnected()
        # 唤醒等待中的 auth
        if self._auth_pending:
            self._auth_result = (False, "disconnected")
            self._auth_event.set()

    async def scan_and_connect(self) -> None:
        """
        查找并连接 immurok 设备，断线自动重连。

        设备作为 HID 键盘已由 BlueZ 管理连接，daemon 通过 D-Bus
        查找已连接的 immurok 设备并直接访问其 GATT 服务。
        """
        while self._reconnect_enabled:
            try:
                result = await self._find_connected_device()
                if result:
                    address, device_path = result
                    log.info(
                        "在 BlueZ 已连接设备中找到 immurok: %s", address
                    )
                    await self._attach_gatt(device_path, address)
                    # 保持连接直到断开
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
        """
        在 BlueZ 已连接设备中查找 immurok。

        返回 (address, dbus_device_path) 元组，未找到返回 None。
        """
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
                        log.debug(
                            "BlueZ 已连接设备: %s (%s) path=%s",
                            name, address, path,
                        )
                        return (address, path)
            finally:
                bus.disconnect()
        except Exception:
            log.debug("BlueZ D-Bus 查询失败", exc_info=True)

        return None

    async def disconnect(self) -> None:
        """主动断开 GATT 访问（不断开 HID 连接）。"""
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


# ── 异常 ───────────────────────────────────────────────────────

class PairingError(Exception):
    pass


class AuthError(Exception):
    pass
