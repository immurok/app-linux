"""
immurok.ble 单元测试

通过 mock D-Bus GATT 接口测试通知路由、命令编码、配对流程和认证流程。
不需要硬件设备。
"""

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from immurok.ble import AuthError, BLEError, ImmurokBLE, PairingError
from immurok.config import (
    CHAR_CMD_UUID,
    CHAR_RSP_UUID,
    CMD_AUTH_REQUEST,
    CMD_DELETE_FP,
    CMD_ENROLL_START,
    CMD_ENROLL_STATUS,
    CMD_FP_LIST,
    CMD_FP_MATCHED,
    CMD_FP_MATCH_SIGNED,
    CMD_GET_PAIR_STATUS,
    CMD_GET_STATUS,
    CMD_PAIR_CONFIRM,
    CMD_PAIR_INIT,
    DEVICE_ID_LEN,
    HMAC_TRUNCATED_LEN,
    NONCE_LEN,
    RANDOM_LEN,
    STATUS_INVALID_STATE,
    STATUS_NOT_PAIRED,
    STATUS_OK,
    STATUS_TIMEOUT,
    STATUS_WAIT_BUTTON,
    STATUS_WAIT_FP,
)
from immurok.security import PairingData, derive_shared_key, get_host_id

from .conftest import DEV_RANDOM_1, HOST_RANDOM_1, TEST_HOST_ID


# ── Fixtures ───────────────────────────────────────────────────


@pytest.fixture
def ble():
    """无配对数据的 ImmurokBLE 实例"""
    with patch.object(PairingData, "load", return_value=None):
        b = ImmurokBLE()
    return b


@pytest.fixture
def shared_key():
    return derive_shared_key(HOST_RANDOM_1, DEV_RANDOM_1, TEST_HOST_ID)


@pytest.fixture
def paired_ble(shared_key, tmp_path, monkeypatch):
    """带有模拟配对数据的 ImmurokBLE 实例"""
    pairing = PairingData(
        device_id=b"\xAA" * 16,
        shared_key=shared_key,
        host_id=TEST_HOST_ID,
        auth_counter=10,
        notify_counter=5,
    )
    monkeypatch.setattr(
        PairingData, "_pairing_path",
        staticmethod(lambda: tmp_path / "pairing.json"),
    )
    pairing.save()
    with patch.object(PairingData, "load", return_value=pairing):
        b = ImmurokBLE()
    return b


def _make_connected(ble: ImmurokBLE):
    """将 BLE 实例设置为已连接状态 (mock D-Bus GATT 接口)"""
    cmd_iface = AsyncMock()
    ble._cmd_iface = cmd_iface
    ble._connected = True
    ble._bus = MagicMock()
    return cmd_iface


def _set_cmd_response(ble: ImmurokBLE, response: bytes):
    """模拟命令响应通知：写命令后固件通过 RSP 通知返回响应"""
    original_write = ble._cmd_iface.call_write_value

    async def write_and_notify(*args, **kwargs):
        await original_write(*args, **kwargs)
        # 模拟固件通过通知返回响应
        ble._cmd_response = response
        ble._cmd_event.set()

    ble._cmd_iface.call_write_value = AsyncMock(side_effect=write_and_notify)


def _set_cmd_responses(ble: ImmurokBLE, responses: list[bytes]):
    """模拟多个命令响应通知（按顺序）"""
    original_write = ble._cmd_iface.call_write_value
    call_count = [0]

    async def write_and_notify(*args, **kwargs):
        await original_write(*args, **kwargs)
        idx = call_count[0]
        call_count[0] += 1
        if idx < len(responses):
            ble._cmd_response = responses[idx]
            ble._cmd_event.set()

    ble._cmd_iface.call_write_value = AsyncMock(side_effect=write_and_notify)


# ── 通知路由测试 ───────────────────────────────────────────────


class TestNotificationRouting:
    def test_signed_fp_match_15bytes(self, paired_ble, shared_key):
        """0x21 + 14 字节 → 签名 FP 匹配处理 (CH592F 无 counter)"""
        callback = MagicMock()
        paired_ble.on_fp_match = callback

        # 构造有效的签名通知
        page_id, ts = 1, 1000
        hmac_input = struct.pack("<HI", page_id, ts)
        import hashlib
        import hmac

        hmac_val = hmac.new(shared_key, hmac_input, hashlib.sha256).digest()[:8]

        data = bytearray([CMD_FP_MATCH_SIGNED])
        data += struct.pack("<HI", page_id, ts)
        data += hmac_val
        assert len(data) == 15

        paired_ble._on_notification(0, data)
        callback.assert_called_once_with(page_id, True)

    def test_signed_fp_bad_hmac_ignored(self, paired_ble):
        """HMAC 验证失败 → 不触发回调"""
        callback = MagicMock()
        paired_ble.on_fp_match = callback

        data = bytearray([CMD_FP_MATCH_SIGNED])
        data += struct.pack("<HI", 1, 1000)
        data += b"\xff" * 8  # 错误的 HMAC
        assert len(data) == 15

        paired_ble._on_notification(0, data)
        callback.assert_not_called()

    def test_unsigned_fp_match_3bytes(self, ble):
        """0x20 + 2 字节 → 未签名 FP 匹配 (未配对时)"""
        callback = MagicMock()
        ble.on_fp_match = callback

        data = bytearray([CMD_FP_MATCHED])
        data += struct.pack("<H", 2)
        assert len(data) == 3

        ble._on_notification(0, data)
        callback.assert_called_once_with(2, False)

    def test_unsigned_fp_ignored_when_paired(self, paired_ble):
        """已配对时不接受未签名通知"""
        callback = MagicMock()
        paired_ble.on_fp_match = callback

        data = bytearray([CMD_FP_MATCHED, 0x01, 0x00])
        paired_ble._on_notification(0, data)
        callback.assert_not_called()

    def test_enroll_status_4bytes(self, ble):
        """0x11 + 3 字节 → 录入进度"""
        callback = MagicMock()
        ble.on_enroll_progress = callback

        data = bytearray([CMD_ENROLL_STATUS, 0x01, 3, 6])
        assert len(data) == 4

        ble._on_notification(0, data)
        callback.assert_called_once_with(0x01, 3, 6)

    def test_auth_response_success_9bytes(self, paired_ble):
        """[0x00][hmac:8] = 9 字节 → AUTH_RESPONSE 成功 (CH592F 无 counter)"""
        paired_ble._auth_pending = True
        paired_ble._auth_event.clear()

        hmac_val = b"\xAB" * 8
        data = bytearray([STATUS_OK])
        data += hmac_val
        assert len(data) == 9

        paired_ble._on_notification(0, data)

        assert paired_ble._auth_event.is_set()
        assert paired_ble._auth_result == (True, hmac_val)

    def test_auth_response_ignored_when_not_pending(self, paired_ble):
        """没有 pending auth 时，9 字节通知作为命令响应"""
        paired_ble._auth_pending = False
        data = bytearray([STATUS_OK]) + b"\x00" * 8
        paired_ble._on_notification(0, data)
        # 不会设置 auth_event
        assert not paired_ble._auth_event.is_set()
        # 作为命令响应处理
        assert paired_ble._cmd_event.is_set()

    def test_auth_error_1byte(self, paired_ble):
        """auth 进行中收到 1 字节错误码"""
        paired_ble._auth_pending = True
        paired_ble._auth_event.clear()

        data = bytearray([0x07])  # FP_NOT_MATCH
        paired_ble._on_notification(0, data)

        assert paired_ble._auth_event.is_set()
        assert paired_ble._auth_result[0] is False

    def test_empty_notification_ignored(self, ble):
        """空通知不 crash"""
        ble._on_notification(0, bytearray())

    def test_cmd_response_via_notification(self, ble):
        """未知类型通知 → 作为命令响应"""
        ble._cmd_event.clear()
        data = bytearray([0x00, 0x05])  # e.g. GET_STATUS response
        ble._on_notification(0, data)
        assert ble._cmd_event.is_set()
        assert ble._cmd_response == bytes(data)


# ── 命令发送测试 ───────────────────────────────────────────────


class TestSendCommand:
    @pytest.mark.asyncio
    async def test_command_encoding(self, ble):
        """命令格式: [CMD:1][LEN:1][PAYLOAD:N]"""
        cmd_iface = _make_connected(ble)
        _set_cmd_response(ble, bytes([0x00]))

        await ble.send_command(CMD_GET_STATUS)

        cmd_iface.call_write_value.assert_called_once()
        args = cmd_iface.call_write_value.call_args
        written = args[0][0]  # first positional arg: data as bytes
        assert written == bytes([CMD_GET_STATUS, 0x00])  # cmd=0x01, len=0

    @pytest.mark.asyncio
    async def test_command_with_payload(self, ble):
        cmd_iface = _make_connected(ble)
        _set_cmd_response(ble, bytes([0x00]))

        await ble.send_command(CMD_ENROLL_START, bytes([3]))

        written = cmd_iface.call_write_value.call_args[0][0]
        assert written == bytes([CMD_ENROLL_START, 0x01, 0x03])  # cmd, len=1, slot=3

    @pytest.mark.asyncio
    async def test_read_response(self, ble):
        cmd_iface = _make_connected(ble)
        _set_cmd_response(ble, bytes([0x00, 0x05]))

        rsp = await ble.send_command(CMD_FP_LIST)
        assert rsp == bytes([0x00, 0x05])

    @pytest.mark.asyncio
    async def test_not_connected_raises(self, ble):
        with pytest.raises(BLEError):
            await ble.send_command(CMD_GET_STATUS)


# ── 高层命令测试 ───────────────────────────────────────────────


class TestHighLevelCommands:
    @pytest.mark.asyncio
    async def test_get_status(self, ble):
        _make_connected(ble)
        _set_cmd_response(ble, bytes([0x00]))
        assert await ble.get_status() == 0x00

    @pytest.mark.asyncio
    async def test_get_pair_status(self, ble):
        _make_connected(ble)
        _set_cmd_response(ble, bytes([STATUS_NOT_PAIRED]))
        assert await ble.get_pair_status() == STATUS_NOT_PAIRED

    @pytest.mark.asyncio
    async def test_fp_list_bitmap(self, ble):
        """FP_LIST 返回 bitmap (slot 0,1,2 有指纹 → 0b00111=7)"""
        _make_connected(ble)
        _set_cmd_response(ble, bytes([0x00, 0x07]))
        assert await ble.fp_list() == 0x07

    @pytest.mark.asyncio
    async def test_fp_list_not_paired(self, ble):
        _make_connected(ble)
        _set_cmd_response(ble, bytes([STATUS_NOT_PAIRED]))
        assert await ble.fp_list() == 0

    @pytest.mark.asyncio
    async def test_enroll_start_authenticated(self, paired_ble, shared_key):
        """enroll_start 需要命令认证: GET_CMD_CHALLENGE → ENROLL_START"""
        cmd_iface = _make_connected(paired_ble)
        challenge = b"\xCC" * 8
        challenge_rsp = bytes([STATUS_OK]) + challenge
        enroll_rsp = bytes([STATUS_OK])
        _set_cmd_responses(paired_ble, [challenge_rsp, enroll_rsp])

        assert await paired_ble.enroll_start(2) == 0x00

        # 第二次 write 是 ENROLL_START (认证后 payload = slotId + challenge + hmac)
        written = cmd_iface.call_write_value.call_args_list[1][0][0]
        assert written[0] == CMD_ENROLL_START
        assert written[1] == 17  # len = 1 + 8 + 8
        assert written[2] == 2   # slotId

    @pytest.mark.asyncio
    async def test_delete_fp_authenticated(self, paired_ble, shared_key):
        """delete_fp 需要命令认证"""
        cmd_iface = _make_connected(paired_ble)
        challenge = b"\xDD" * 8
        challenge_rsp = bytes([STATUS_OK]) + challenge
        delete_rsp = bytes([STATUS_OK])
        _set_cmd_responses(paired_ble, [challenge_rsp, delete_rsp])

        assert await paired_ble.delete_fp(1) == 0x00

        written = cmd_iface.call_write_value.call_args_list[1][0][0]
        assert written[0] == CMD_DELETE_FP
        assert written[1] == 17  # len = 1 + 8 + 8
        assert written[2] == 1   # slotId


# ── 配对流程测试 ───────────────────────────────────────────────


class TestPairing:
    @pytest.mark.asyncio
    async def test_pair_success(self, ble, tmp_path, monkeypatch):
        """完整配对流程: PAIR_INIT → PAIR_CONFIRM (一次成功)"""
        monkeypatch.setattr(
            PairingData, "_pairing_path",
            staticmethod(lambda: tmp_path / "pairing.json"),
        )
        cmd_iface = _make_connected(ble)

        device_random = DEV_RANDOM_1
        device_id = b"\xDD" * DEVICE_ID_LEN

        # PAIR_INIT → [WAIT_BUTTON][device_random:16]
        init_rsp = bytes([STATUS_WAIT_BUTTON]) + device_random
        # PAIR_CONFIRM → [OK][device_id:16]
        confirm_rsp = bytes([STATUS_OK]) + device_id

        _set_cmd_responses(ble, [init_rsp, confirm_rsp])

        with patch("immurok.ble.get_host_id", return_value=b"\x11" * 16), \
             patch("immurok.ble.os.urandom", return_value=HOST_RANDOM_1):
            pairing = await ble.pair()

        assert pairing.device_id == device_id
        assert pairing.shared_key == derive_shared_key(
            HOST_RANDOM_1, device_random, b"\x11" * 16
        )
        assert pairing.auth_counter == 0
        assert ble.paired

    @pytest.mark.asyncio
    async def test_pair_wait_button_retry(self, ble, tmp_path, monkeypatch):
        """配对确认需要重试 (等待按钮)"""
        monkeypatch.setattr(
            PairingData, "_pairing_path",
            staticmethod(lambda: tmp_path / "pairing.json"),
        )
        cmd_iface = _make_connected(ble)

        device_random = DEV_RANDOM_1
        device_id = b"\xDD" * DEVICE_ID_LEN
        init_rsp = bytes([STATUS_WAIT_BUTTON]) + device_random

        # 前两次返回 WAIT_BUTTON，第三次成功
        _set_cmd_responses(ble, [
            init_rsp,
            bytes([STATUS_WAIT_BUTTON]),
            bytes([STATUS_INVALID_STATE]),
            bytes([STATUS_OK]) + device_id,
        ])

        with patch("immurok.ble.get_host_id", return_value=b"\x11" * 16), \
             patch("immurok.ble.os.urandom", return_value=HOST_RANDOM_1), \
             patch("immurok.ble.asyncio.sleep", new_callable=AsyncMock):
            pairing = await ble.pair()

        assert pairing.device_id == device_id

    @pytest.mark.asyncio
    async def test_pair_init_already_paired(self, ble):
        """设备已配对 → PairingError"""
        _make_connected(ble)
        _set_cmd_response(ble, bytes([0x03]))  # ALREADY_PAIRED

        with patch("immurok.ble.get_host_id", return_value=b"\x11" * 16):
            with pytest.raises(PairingError, match="PAIR_INIT"):
                await ble.pair()

    @pytest.mark.asyncio
    async def test_pair_confirm_timeout(self, ble):
        """设备端超时 → PairingError"""
        _make_connected(ble)
        init_rsp = bytes([STATUS_WAIT_BUTTON]) + DEV_RANDOM_1
        _set_cmd_responses(ble, [
            init_rsp,
            bytes([STATUS_TIMEOUT]),
        ])

        with patch("immurok.ble.get_host_id", return_value=b"\x11" * 16), \
             patch("immurok.ble.os.urandom", return_value=HOST_RANDOM_1), \
             patch("immurok.ble.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(PairingError, match="超时"):
                await ble.pair()

    @pytest.mark.asyncio
    async def test_pair_init_command_format(self, ble):
        """PAIR_INIT 命令: [0x30][0x10][host_id:16]"""
        cmd_iface = _make_connected(ble)
        init_rsp = bytes([STATUS_WAIT_BUTTON]) + DEV_RANDOM_1
        confirm_rsp = bytes([STATUS_OK]) + b"\xDD" * DEVICE_ID_LEN
        _set_cmd_responses(ble, [init_rsp, confirm_rsp])

        host_id = b"\x11" * 16
        with patch("immurok.ble.get_host_id", return_value=host_id), \
             patch("immurok.ble.os.urandom", return_value=HOST_RANDOM_1), \
             patch("immurok.ble.asyncio.sleep", new_callable=AsyncMock), \
             patch.object(PairingData, "save"):
            await ble.pair()

        # 第一次 write 是 PAIR_INIT
        first_write = cmd_iface.call_write_value.call_args_list[0][0][0]
        assert first_write[0] == CMD_PAIR_INIT
        assert first_write[1] == 16  # len = 16
        assert bytes(first_write[2:]) == host_id


# ── AUTH_REQUEST 流程测试 ──────────────────────────────────────


class TestAuthRequest:
    @pytest.mark.asyncio
    async def test_auth_success(self, paired_ble, shared_key):
        """完整 AUTH 流程: 发送请求 → 等通知 → 验证 HMAC (CH592F 无 counter)"""
        cmd_iface = _make_connected(paired_ble)

        # 固定 challenge 和 nonce
        challenge = b"\x01" * NONCE_LEN
        device_nonce = b"\x02" * NONCE_LEN

        # AUTH_REQUEST → [WAIT_FP][device_nonce:8]
        rsp = bytes([STATUS_WAIT_FP]) + device_nonce
        _set_cmd_response(paired_ble, rsp)

        # 计算固件端应返回的 HMAC (CH592F: 无 counter)
        import hashlib
        import hmac

        hmac_input = challenge + device_nonce + b"auth-ok"
        expected_hmac = hmac.new(shared_key, hmac_input, hashlib.sha256).digest()[:8]

        # 模拟: 在 auth_request 等待时，异步注入 AUTH_RESPONSE 通知
        async def inject_auth_response():
            await asyncio.sleep(0.05)
            notify_data = bytearray([STATUS_OK])
            notify_data += expected_hmac
            paired_ble._on_notification(0, notify_data)

        with patch("immurok.ble.os.urandom", return_value=challenge):
            task = asyncio.create_task(inject_auth_response())
            result = await paired_ble.auth_request()
            await task

        assert result is True

    @pytest.mark.asyncio
    async def test_auth_bad_hmac(self, paired_ble, shared_key):
        """HMAC 验证失败 → 返回 False"""
        _make_connected(paired_ble)
        device_nonce = b"\x02" * NONCE_LEN
        rsp = bytes([STATUS_WAIT_FP]) + device_nonce
        _set_cmd_response(paired_ble, rsp)

        async def inject_bad_response():
            await asyncio.sleep(0.05)
            notify_data = bytearray([STATUS_OK])
            notify_data += b"\xFF" * 8  # 错误 HMAC
            paired_ble._on_notification(0, notify_data)

        with patch("immurok.ble.os.urandom", return_value=b"\x01" * 8):
            task = asyncio.create_task(inject_bad_response())
            result = await paired_ble.auth_request()
            await task

        assert result is False

    @pytest.mark.asyncio
    async def test_auth_fp_not_match(self, paired_ble):
        """指纹不匹配 → 返回 False"""
        _make_connected(paired_ble)
        device_nonce = b"\x02" * NONCE_LEN
        rsp = bytes([STATUS_WAIT_FP]) + device_nonce
        _set_cmd_response(paired_ble, rsp)

        async def inject_error():
            await asyncio.sleep(0.05)
            paired_ble._on_notification(0, bytearray([0x07]))  # FP_NOT_MATCH

        with patch("immurok.ble.os.urandom", return_value=b"\x01" * 8):
            task = asyncio.create_task(inject_error())
            result = await paired_ble.auth_request()
            await task

        assert result is False

    @pytest.mark.asyncio
    async def test_auth_not_paired(self, ble):
        """未配对 → AuthError"""
        _make_connected(ble)
        with pytest.raises(AuthError, match="未配对"):
            await ble.auth_request()

    @pytest.mark.asyncio
    async def test_auth_request_rejected(self, paired_ble):
        """设备拒绝 AUTH_REQUEST → AuthError"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([0x09]))  # COUNTER_REPLAY

        with patch("immurok.ble.os.urandom", return_value=b"\x01" * 8):
            with pytest.raises(AuthError, match="AUTH_REQUEST"):
                await paired_ble.auth_request()

    @pytest.mark.asyncio
    async def test_auth_command_format(self, paired_ble):
        """AUTH_REQUEST: [0x33][0x08][challenge:8] (CH592F 无 counter)"""
        cmd_iface = _make_connected(paired_ble)
        device_nonce = b"\x02" * NONCE_LEN
        rsp = bytes([STATUS_WAIT_FP]) + device_nonce
        _set_cmd_response(paired_ble, rsp)

        challenge = b"\xAA" * 8

        async def inject_ok():
            await asyncio.sleep(0.05)
            # 随便给个 auth result，反正我们只检查命令格式
            paired_ble._auth_result = (False, "test")
            paired_ble._auth_event.set()

        with patch("immurok.ble.os.urandom", return_value=challenge):
            task = asyncio.create_task(inject_ok())
            try:
                await paired_ble.auth_request()
            except Exception:
                pass
            await task

        written = cmd_iface.call_write_value.call_args[0][0]
        assert written[0] == CMD_AUTH_REQUEST
        assert written[1] == 8  # payload len = 8 (仅 challenge)
        assert bytes(written[2:10]) == challenge


# ── 连接管理测试 ───────────────────────────────────────────────


class TestConnection:
    def test_initial_state(self, ble):
        assert not ble.connected
        assert not ble.paired
        assert ble._reconnect_enabled

    def test_disconnect_wakes_auth(self, paired_ble):
        """断线时唤醒等待中的 auth"""
        _make_connected(paired_ble)
        paired_ble._auth_pending = True
        paired_ble._auth_event.clear()

        paired_ble._handle_disconnect()

        assert not paired_ble.connected
        assert paired_ble._auth_event.is_set()
        assert paired_ble._auth_result[0] is False

    def test_disconnect_callback_fires(self, ble):
        callback = MagicMock()
        ble.on_disconnected = callback
        _make_connected(ble)

        ble._handle_disconnect()
        callback.assert_called_once()

    def test_device_properties_disconnect(self, ble):
        """D-Bus Device1 Connected=False → 触发断线"""
        _make_connected(ble)
        callback = MagicMock()
        ble.on_disconnected = callback

        # 模拟 Variant 对象
        mock_variant = MagicMock()
        mock_variant.value = False

        ble._on_device_properties_changed(
            "org.bluez.Device1", {"Connected": mock_variant}, []
        )

        assert not ble.connected
        callback.assert_called_once()

    def test_rsp_properties_routes_notification(self, ble):
        """D-Bus RSP Value 变化 → 路由到 _on_notification"""
        callback = MagicMock()
        ble.on_fp_match = callback

        # 模拟 Variant 对象（未签名 FP 匹配）
        mock_variant = MagicMock()
        mock_variant.value = [CMD_FP_MATCHED, 0x03, 0x00]

        ble._on_rsp_properties_changed(
            "org.bluez.GattCharacteristic1", {"Value": mock_variant}, []
        )

        callback.assert_called_once_with(3, False)
