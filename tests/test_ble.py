"""
immurok.ble 单元测试

通过 mock D-Bus GATT 接口测试通知路由、命令编码、配对流程、
FP-gate 和 AUTH 流程。不需要硬件设备。
"""

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from immurok.ble import AuthError, BLEError, ImmurokBLE, PairingError
from immurok.config import (
    CHAR_CMD_UUID,
    CHAR_RSP_UUID,
    CMD_AUTH_REQUEST,
    CMD_DELETE_FP,
    CMD_ENROLL_START,
    CMD_ENROLL_STATUS,
    CMD_FP_LIST,
    CMD_FP_MATCH_SIGNED,
    CMD_GET_STATUS,
    CMD_PAIR_CONFIRM,
    CMD_PAIR_INIT,
    CMD_PAIR_STATUS,
    COMPRESSED_PUBKEY_LEN,
    STATUS_BUSY,
    STATUS_ERROR,
    STATUS_FP_GATE_APPROVED,
    STATUS_FP_NOT_MATCH,
    STATUS_OK,
    STATUS_TIMEOUT,
    STATUS_WAIT_FP,
)
from immurok.security import PairingData, derive_shared_key

from .conftest import TEST_ECDH_SECRET_1


# ── Fixtures ───────────────────────────────────────────────────


@pytest.fixture
def ble():
    """无配对数据的 ImmurokBLE 实例"""
    with patch.object(PairingData, "load", return_value=None):
        b = ImmurokBLE()
    return b


@pytest.fixture
def shared_key():
    return derive_shared_key(TEST_ECDH_SECRET_1)


@pytest.fixture
def paired_ble(shared_key, tmp_path, monkeypatch):
    """带有模拟配对数据的 ImmurokBLE 实例"""
    pairing = PairingData(shared_key=shared_key)
    monkeypatch.setattr(
        PairingData, "_pairing_path",
        staticmethod(lambda: tmp_path / "pairing.json"),
    )
    pairing.save()
    with patch.object(PairingData, "load", return_value=pairing):
        b = ImmurokBLE()
    return b


def _make_connected(ble: ImmurokBLE):
    """将 BLE 实例设置为已连接状态"""
    cmd_iface = AsyncMock()
    ble._cmd_iface = cmd_iface
    ble._connected = True
    ble._bus = MagicMock()
    return cmd_iface


def _set_cmd_response(ble: ImmurokBLE, response: bytes):
    """模拟命令响应通知"""
    original_write = ble._cmd_iface.call_write_value

    async def write_and_notify(*args, **kwargs):
        await original_write(*args, **kwargs)
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
    def test_signed_fp_match_11bytes(self, paired_ble, shared_key):
        """0x21 + page_id(2B) + hmac(8B) = 11 字节"""
        callback = MagicMock()
        paired_ble.on_fp_match = callback

        # 构造有效的签名通知
        page_id = 1
        import hashlib, hmac
        hmac_input = bytes([0x21]) + struct.pack("<H", page_id)
        hmac_val = hmac.new(shared_key, hmac_input, hashlib.sha256).digest()[:8]

        data = bytearray([CMD_FP_MATCH_SIGNED])
        data += struct.pack("<H", page_id)
        data += hmac_val
        assert len(data) == 11

        paired_ble._on_notification(0, data)
        callback.assert_called_once_with(page_id)

    def test_signed_fp_bad_hmac_ignored(self, paired_ble):
        """HMAC 验证失败 → 不触发回调"""
        callback = MagicMock()
        paired_ble.on_fp_match = callback

        data = bytearray([CMD_FP_MATCH_SIGNED])
        data += struct.pack("<H", 1)
        data += b"\xff" * 8
        assert len(data) == 11

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

    def test_fp_gate_approved_1byte(self, paired_ble):
        """0x10 (1 字节) → FP-gate 指纹通过，继续等待"""
        paired_ble._gate_pending = True
        paired_ble._on_notification(0, bytearray([STATUS_FP_GATE_APPROVED]))
        # 不应 set gate_event (操作仍在进行)
        assert not paired_ble._gate_event.is_set()

    def test_fp_not_match_gate(self, paired_ble):
        """0x07 (1 字节) + gate_pending → 指纹不匹配，计数"""
        paired_ble._gate_pending = True
        paired_ble._auth_failures = 0
        callback = MagicMock()
        paired_ble.on_fp_attempt_failed = callback

        # 第一次不匹配 → 剩余 2 次
        paired_ble._on_notification(0, bytearray([STATUS_FP_NOT_MATCH]))
        assert paired_ble._auth_failures == 1
        callback.assert_called_with(2)
        assert not paired_ble._gate_event.is_set()

    def test_fp_not_match_gate_max_failures(self, paired_ble):
        """3 次不匹配 → gate 失败"""
        paired_ble._gate_pending = True
        paired_ble._auth_failures = 2  # 已有 2 次

        paired_ble._on_notification(0, bytearray([STATUS_FP_NOT_MATCH]))
        assert paired_ble._gate_event.is_set()
        assert paired_ble._gate_result[0] is False

    def test_gate_success_1byte(self, paired_ble):
        """0x00 (1 字节) + gate_pending → 操作成功"""
        paired_ble._gate_pending = True
        paired_ble._gate_event.clear()

        paired_ble._on_notification(0, bytearray([STATUS_OK]))
        assert paired_ble._gate_event.is_set()
        assert paired_ble._gate_result == (True, None)

    def test_auth_success_1byte(self, paired_ble):
        """0x00 (1 字节) + auth_pending → AUTH 成功"""
        paired_ble._auth_pending = True
        paired_ble._auth_event.clear()

        paired_ble._on_notification(0, bytearray([STATUS_OK]))
        assert paired_ble._auth_event.is_set()
        assert paired_ble._auth_result is True

    def test_auth_fp_not_match(self, paired_ble):
        """0x07 + auth_pending → 指纹不匹配"""
        paired_ble._auth_pending = True
        paired_ble._auth_failures = 2

        paired_ble._on_notification(0, bytearray([STATUS_FP_NOT_MATCH]))
        assert paired_ble._auth_event.is_set()
        assert paired_ble._auth_result is False

    def test_empty_notification_ignored(self, ble):
        ble._on_notification(0, bytearray())

    def test_cmd_response_via_notification(self, ble):
        """未知类型通知 → 作为命令响应"""
        ble._cmd_event.clear()
        data = bytearray([0x00, 0x05])
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

        written = cmd_iface.call_write_value.call_args[0][0]
        assert written == bytes([CMD_GET_STATUS, 0x00])

    @pytest.mark.asyncio
    async def test_command_with_payload(self, ble):
        cmd_iface = _make_connected(ble)
        _set_cmd_response(ble, bytes([0x00]))

        await ble.send_command(CMD_ENROLL_START, bytes([3]))

        written = cmd_iface.call_write_value.call_args[0][0]
        assert written == bytes([CMD_ENROLL_START, 0x01, 0x03])

    @pytest.mark.asyncio
    async def test_read_response(self, ble):
        _make_connected(ble)
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
    async def test_get_status_with_battery(self, ble):
        """GET_STATUS 4 字节响应: [OK][bitmap][paired][battery]"""
        _make_connected(ble)
        _set_cmd_response(ble, bytes([STATUS_OK, 0x07, 0x01, 85]))
        bitmap, is_paired, battery = await ble.get_status()
        assert bitmap == 0x07
        assert is_paired is True
        assert battery == 85

    @pytest.mark.asyncio
    async def test_get_status_without_battery(self, ble):
        """GET_STATUS 3 字节响应（旧固件兼容）: [OK][bitmap][paired]"""
        _make_connected(ble)
        _set_cmd_response(ble, bytes([STATUS_OK, 0x03, 0x00]))
        bitmap, is_paired, battery = await ble.get_status()
        assert bitmap == 0x03
        assert is_paired is False
        assert battery is None

    @pytest.mark.asyncio
    async def test_get_pair_status(self, ble):
        _make_connected(ble)
        _set_cmd_response(ble, bytes([CMD_PAIR_STATUS, 0x01]))
        assert await ble.get_pair_status() == 0x01

    @pytest.mark.asyncio
    async def test_fp_list_bitmap(self, ble):
        _make_connected(ble)
        _set_cmd_response(ble, bytes([0x00, 0x07]))
        assert await ble.fp_list() == 0x07


# ── FP-gate 命令测试 ──────────────────────────────────────────


class TestFPGate:
    @pytest.mark.asyncio
    async def test_immediate_success(self, paired_ble):
        """FP cooldown 内直接成功 (0x00)"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_OK]))

        success, error = await paired_ble.send_fp_gated_command(CMD_DELETE_FP, bytes([0]))
        assert success is True
        assert error is None

    @pytest.mark.asyncio
    async def test_wait_fp_then_success(self, paired_ble):
        """WAIT_FP → 指纹匹配 → 操作成功"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_WAIT_FP]))

        async def inject_success():
            await asyncio.sleep(0.05)
            paired_ble._on_notification(0, bytearray([STATUS_OK]))

        task = asyncio.create_task(inject_success())
        success, error = await paired_ble.send_fp_gated_command(CMD_DELETE_FP, bytes([0]))
        await task

        assert success is True

    @pytest.mark.asyncio
    async def test_gate_rejected(self, paired_ble):
        """非 WAIT_FP 非 OK → 失败"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_ERROR]))

        success, error = await paired_ble.send_fp_gated_command(CMD_DELETE_FP, bytes([0]))
        assert success is False
        assert error == STATUS_ERROR


# ── 配对流程测试 ───────────────────────────────────────────────


class TestPairing:
    @pytest.mark.asyncio
    async def test_pair_success(self, ble, tmp_path, monkeypatch):
        """ECDH 配对: PAIR_INIT → 设备公钥, PAIR_CONFIRM → 成功"""
        monkeypatch.setattr(
            PairingData, "_pairing_path",
            staticmethod(lambda: tmp_path / "pairing.json"),
        )
        _make_connected(ble)

        # 生成一个模拟设备公钥
        from immurok.security import generate_p256_keypair
        _, device_pub = generate_p256_keypair()

        init_rsp = bytes([CMD_PAIR_INIT]) + device_pub
        confirm_rsp = bytes([CMD_PAIR_CONFIRM, STATUS_OK])
        _set_cmd_responses(ble, [init_rsp, confirm_rsp])

        pairing = await ble.pair()
        assert pairing.shared_key is not None
        assert len(pairing.shared_key) == 32
        assert ble.paired

    @pytest.mark.asyncio
    async def test_pair_init_too_short(self, ble):
        """PAIR_INIT 响应过短 → PairingError"""
        _make_connected(ble)
        _set_cmd_response(ble, bytes([CMD_PAIR_INIT, STATUS_ERROR]))

        with pytest.raises(PairingError, match="PAIR_INIT"):
            await ble.pair()

    @pytest.mark.asyncio
    async def test_pair_confirm_failed(self, ble, tmp_path, monkeypatch):
        """PAIR_CONFIRM 返回非 OK → PairingError"""
        monkeypatch.setattr(
            PairingData, "_pairing_path",
            staticmethod(lambda: tmp_path / "pairing.json"),
        )
        _make_connected(ble)

        from immurok.security import generate_p256_keypair
        _, device_pub = generate_p256_keypair()

        init_rsp = bytes([CMD_PAIR_INIT]) + device_pub
        confirm_rsp = bytes([CMD_PAIR_CONFIRM, STATUS_ERROR])
        _set_cmd_responses(ble, [init_rsp, confirm_rsp])

        with pytest.raises(PairingError, match="PAIR_CONFIRM"):
            await ble.pair()

    @pytest.mark.asyncio
    async def test_pair_init_command_format(self, ble, tmp_path, monkeypatch):
        """PAIR_INIT: [0x30][0x00]"""
        monkeypatch.setattr(
            PairingData, "_pairing_path",
            staticmethod(lambda: tmp_path / "pairing.json"),
        )
        cmd_iface = _make_connected(ble)

        from immurok.security import generate_p256_keypair
        _, device_pub = generate_p256_keypair()

        _set_cmd_responses(ble, [
            bytes([CMD_PAIR_INIT]) + device_pub,
            bytes([CMD_PAIR_CONFIRM, STATUS_OK]),
        ])

        await ble.pair()

        first_write = cmd_iface.call_write_value.call_args_list[0][0][0]
        assert first_write[0] == CMD_PAIR_INIT
        assert first_write[1] == 0x00  # 无 payload

    @pytest.mark.asyncio
    async def test_pair_confirm_sends_app_pubkey(self, ble, tmp_path, monkeypatch):
        """PAIR_CONFIRM 发送 App 33 字节压缩公钥"""
        monkeypatch.setattr(
            PairingData, "_pairing_path",
            staticmethod(lambda: tmp_path / "pairing.json"),
        )
        cmd_iface = _make_connected(ble)

        from immurok.security import generate_p256_keypair
        _, device_pub = generate_p256_keypair()

        _set_cmd_responses(ble, [
            bytes([CMD_PAIR_INIT]) + device_pub,
            bytes([CMD_PAIR_CONFIRM, STATUS_OK]),
        ])

        await ble.pair()

        confirm_write = cmd_iface.call_write_value.call_args_list[1][0][0]
        assert confirm_write[0] == CMD_PAIR_CONFIRM
        assert confirm_write[1] == COMPRESSED_PUBKEY_LEN  # len=33
        assert len(confirm_write) == 2 + COMPRESSED_PUBKEY_LEN


# ── AUTH_REQUEST 测试 ──────────────────────────────────────────


class TestAuthRequest:
    @pytest.mark.asyncio
    async def test_auth_success(self, paired_ble):
        """AUTH: 发送请求 → WAIT_FP → 0x00 成功"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_WAIT_FP]))

        async def inject_ok():
            await asyncio.sleep(0.05)
            paired_ble._on_notification(0, bytearray([STATUS_OK]))

        task = asyncio.create_task(inject_ok())
        result = await paired_ble.auth_request()
        await task

        assert result is True

    @pytest.mark.asyncio
    async def test_auth_fp_mismatch_then_ok(self, paired_ble):
        """指纹不匹配后成功"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_WAIT_FP]))

        async def inject_sequence():
            await asyncio.sleep(0.05)
            paired_ble._on_notification(0, bytearray([STATUS_FP_NOT_MATCH]))
            await asyncio.sleep(0.05)
            paired_ble._on_notification(0, bytearray([STATUS_OK]))

        task = asyncio.create_task(inject_sequence())
        result = await paired_ble.auth_request()
        await task

        assert result is True

    @pytest.mark.asyncio
    async def test_auth_max_failures(self, paired_ble):
        """3 次不匹配 → 认证失败"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_WAIT_FP]))

        async def inject_failures():
            for _ in range(3):
                await asyncio.sleep(0.03)
                paired_ble._on_notification(0, bytearray([STATUS_FP_NOT_MATCH]))

        task = asyncio.create_task(inject_failures())
        result = await paired_ble.auth_request()
        await task

        assert result is False

    @pytest.mark.asyncio
    async def test_auth_not_paired(self, ble):
        _make_connected(ble)
        with pytest.raises(AuthError, match="未配对"):
            await ble.auth_request()

    @pytest.mark.asyncio
    async def test_auth_rejected(self, paired_ble):
        """设备拒绝 AUTH_REQUEST"""
        _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_ERROR]))

        with pytest.raises(AuthError, match="AUTH_REQUEST"):
            await paired_ble.auth_request()

    @pytest.mark.asyncio
    async def test_auth_command_format(self, paired_ble):
        """AUTH_REQUEST: [0x33][0x00] (无 payload)"""
        cmd_iface = _make_connected(paired_ble)
        _set_cmd_response(paired_ble, bytes([STATUS_WAIT_FP]))

        async def inject_ok():
            await asyncio.sleep(0.05)
            paired_ble._auth_result = True
            paired_ble._auth_event.set()

        task = asyncio.create_task(inject_ok())
        await paired_ble.auth_request()
        await task

        written = cmd_iface.call_write_value.call_args[0][0]
        assert written[0] == CMD_AUTH_REQUEST
        assert written[1] == 0x00  # 无 payload


# ── 连接管理测试 ───────────────────────────────────────────────


class TestConnection:
    def test_initial_state(self, ble):
        assert not ble.connected
        assert not ble.paired
        assert ble._reconnect_enabled

    def test_disconnect_wakes_gate(self, paired_ble):
        _make_connected(paired_ble)
        paired_ble._gate_pending = True
        paired_ble._gate_event.clear()

        paired_ble._handle_disconnect()

        assert not paired_ble.connected
        assert paired_ble._gate_event.is_set()
        assert paired_ble._gate_result[0] is False

    def test_disconnect_wakes_auth(self, paired_ble):
        _make_connected(paired_ble)
        paired_ble._auth_pending = True
        paired_ble._auth_event.clear()

        paired_ble._handle_disconnect()

        assert paired_ble._auth_event.is_set()
        assert paired_ble._auth_result is False

    def test_disconnect_callback_fires(self, ble):
        callback = MagicMock()
        ble.on_disconnected = callback
        _make_connected(ble)

        ble._handle_disconnect()
        callback.assert_called_once()

    def test_device_properties_disconnect(self, ble):
        _make_connected(ble)
        callback = MagicMock()
        ble.on_disconnected = callback

        mock_variant = MagicMock()
        mock_variant.value = False

        ble._on_device_properties_changed(
            "org.bluez.Device1", {"Connected": mock_variant}, []
        )

        assert not ble.connected
        callback.assert_called_once()

    def test_rsp_properties_routes_notification(self, ble):
        callback = MagicMock()
        ble.on_enroll_progress = callback

        mock_variant = MagicMock()
        mock_variant.value = [CMD_ENROLL_STATUS, 0x01, 3, 6]

        ble._on_rsp_properties_changed(
            "org.bluez.GattCharacteristic1", {"Value": mock_variant}, []
        )

        callback.assert_called_once_with(0x01, 3, 6)
