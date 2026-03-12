"""
immurok.socket_server 单元测试

测试 Socket 服务器的命令处理、预授权、PAM 认证流程。
"""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import immurok.settings as _settings_mod
from immurok.ble import ImmurokBLE
from immurok.config import ENROLL_COMPLETE, STATUS_OK
from immurok.security import PairingData
from immurok.socket_server import SocketServer


@pytest.fixture(autouse=True)
def _isolate_settings(tmp_path, monkeypatch):
    """将设置和配对文件重定向到临时目录，避免测试间状态污染"""
    settings_path = str(tmp_path / "settings.json")
    monkeypatch.setattr(_settings_mod, "_SETTINGS_PATH", settings_path)
    # save() 使用 PAIRING_DIR 创建 tmpfile，必须在同一文件系统
    monkeypatch.setattr(_settings_mod, "PAIRING_DIR", str(tmp_path))
    # 隔离配对数据，避免读取真实 ~/.immurok/pairing.json
    pairing_file = tmp_path / "pairing.json"
    monkeypatch.setattr(
        PairingData, "_pairing_path", staticmethod(lambda: pairing_file)
    )


@pytest.fixture
def ble():
    with patch.object(PairingData, "load", return_value=None):
        b = ImmurokBLE()
    return b


@pytest.fixture
def server(ble):
    return SocketServer(ble)


@pytest.fixture
def connected_server(ble, server):
    ble._connected = True
    ble._cmd_iface = AsyncMock()
    ble._bus = MagicMock()
    return server


# ── STATUS ────────────────────────────────────────────────────


class TestStatus:
    def test_disconnected(self, server):
        rsp = server._handle_status()
        assert rsp == "STATUS:0::-1"

    def test_connected(self, connected_server):
        rsp = connected_server._handle_status()
        assert rsp == "STATUS:1:immurok:-1"

    def test_connected_with_battery(self, connected_server):
        connected_server._battery_level = 85
        rsp = connected_server._handle_status()
        assert rsp == "STATUS:1:immurok:85"


# ── 预授权 ────────────────────────────────────────────────────


class TestPreAuth:
    def test_set_and_consume(self, server):
        server.set_pre_auth(5.0)
        assert server.consume_pre_auth() is True

    def test_consume_without_set(self, server):
        assert server.consume_pre_auth() is False

    def test_consume_twice(self, server):
        server.set_pre_auth(5.0)
        assert server.consume_pre_auth() is True
        assert server.consume_pre_auth() is False


# ── 待处理 PAM 请求 ──────────────────────────────────────────


class TestPendingAuth:
    def test_no_pending(self, server):
        assert server.has_pending_auth() is False

    def test_approve_pending(self, server):
        server._pending_auth = asyncio.Event()
        server._pending_approved = False
        assert server.has_pending_auth() is True

        server.approve_pending()
        assert server._pending_approved is True
        assert server._pending_auth.is_set()


# ── 录入状态 ──────────────────────────────────────────────────


class TestEnrollStatus:
    def test_idle(self, server):
        assert server._handle_fp_status() == "OK:IDLE"

    def test_active(self, server):
        server.start_enrollment()
        assert server._enroll_active is True
        rsp = server._handle_fp_status()
        assert rsp == "OK:0:0:6"

    def test_update(self, server):
        server.start_enrollment()
        server.update_enroll_status(1, 2, 6)
        rsp = server._handle_fp_status()
        assert rsp == "OK:1:2:6"

    def test_complete_triggers_refresh(self, server):
        with patch.object(server, "_schedule_fp_bitmap_refresh") as mock:
            server.update_enroll_status(ENROLL_COMPLETE, 6, 6)
            mock.assert_called_once()


# ── FP 命令 ───────────────────────────────────────────────────


class TestFPCommands:
    @pytest.mark.asyncio
    async def test_fp_list_disconnected(self, server):
        rsp = await server._handle_fp_list()
        assert rsp == "ERROR:NOT_CONNECTED"

    @pytest.mark.asyncio
    async def test_fp_list_connected(self, connected_server):
        connected_server._fp_bitmap = 0x07
        rsp = await connected_server._handle_fp_list()
        assert rsp == "OK:7"

    @pytest.mark.asyncio
    async def test_fp_enroll_invalid_slot(self, server):
        rsp = await server._handle_fp_enroll(["FP", "ENROLL"])
        assert rsp == "ERROR:INVALID_SLOT"

    @pytest.mark.asyncio
    async def test_fp_enroll_slot_out_of_range(self, server):
        rsp = await server._handle_fp_enroll(["FP", "ENROLL", "99"])
        assert rsp == "ERROR:INVALID_SLOT"

    @pytest.mark.asyncio
    async def test_fp_delete_disconnected(self, server):
        rsp = await server._handle_fp_delete(["FP", "DELETE", "0"])
        assert rsp == "ERROR:NOT_CONNECTED"

    def test_fp_last_match_no_match(self, server):
        rsp = server._handle_fp_last_match()
        assert rsp == "OK:-1"

    def test_fp_last_match_consumes(self, server):
        server.notify_fp_match(2)
        rsp = server._handle_fp_last_match()
        assert rsp == "OK:2"
        rsp2 = server._handle_fp_last_match()
        assert rsp2 == "OK:-1"


# ── PAIR 命令 ──────────────────────────────────────────────────


class TestPairCommands:
    def test_pair_status_unpaired(self, server):
        rsp = server._handle_pair_status()
        assert rsp == "OK:UNPAIRED"

    @pytest.mark.asyncio
    async def test_pair_start_disconnected(self, server):
        rsp = await server._handle_pair_start()
        assert rsp == "ERROR:NOT_CONNECTED"


# ── SET/GET 设置 ──────────────────────────────────────────────


class TestSettings:
    def test_set_sudo(self, server):
        rsp = server._handle_set(["SET", "UNLOCK_SUDO", "0"])
        assert rsp == "OK"
        assert server.settings.unlock_sudo is False

    def test_set_polkit(self, server):
        rsp = server._handle_set(["SET", "UNLOCK_POLKIT", "0"])
        assert rsp == "OK"
        assert server.settings.unlock_polkit is False

    def test_set_screen(self, server):
        rsp = server._handle_set(["SET", "UNLOCK_SCREEN", "0"])
        assert rsp == "OK"
        assert server.settings.unlock_screen is False

    def test_set_unknown(self, server):
        rsp = server._handle_set(["SET", "UNKNOWN", "1"])
        assert rsp == "ERROR:UNKNOWN_KEY"

    def test_get_settings(self, server):
        rsp = server._handle_get_settings()
        assert rsp.startswith("OK:")
        assert "sudo=1" in rsp
        assert "polkit=1" in rsp
        assert "screen=1" in rsp

    def test_set_invalid_format(self, server):
        rsp = server._handle_set(["SET"])
        assert rsp == "ERROR:INVALID_FORMAT"


# ── AUTH 服务检查 ─────────────────────────────────────────────


class TestServiceAllowed:
    def test_sudo_allowed(self, server):
        assert server._is_service_allowed("sudo") is True

    def test_sudo_disabled(self, server):
        server._settings.unlock_sudo = False
        assert server._is_service_allowed("sudo") is False

    def test_polkit(self, server):
        assert server._is_service_allowed("polkit-1") is True
        server._settings.unlock_polkit = False
        assert server._is_service_allowed("polkit-1") is False

    def test_gdm(self, server):
        assert server._is_service_allowed("gdm-password") is True
        server._settings.unlock_screen = False
        assert server._is_service_allowed("gdm-password") is False

    def test_login_screen(self, server):
        server._settings.unlock_screen = False
        assert server._is_service_allowed("login") is False
