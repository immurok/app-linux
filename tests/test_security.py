"""
immurok.security 单元测试

所有测试向量由 Python hmac/hashlib 独立计算后硬编码，
确保 HKDF/HMAC 实现与固件 immurok_security.c 一致。
"""

import json
import struct
from pathlib import Path

import pytest

from immurok.config import HKDF_INFO, HMAC_FULL_LEN, HMAC_TRUNCATED_LEN
from immurok.security import (
    PairingData,
    compute_reset_hmac,
    derive_shared_key,
    get_host_id,
    hkdf_expand,
    hkdf_extract,
    verify_auth_response,
    verify_fp_match_signed,
)

from .conftest import DEV_RANDOM_1, DEV_RANDOM_2, HOST_RANDOM_1, HOST_RANDOM_2, TEST_HOST_ID


# ── HKDF 测试向量 ─────────────────────────────────────────────
# 独立计算: PRK = HMAC-SHA256(host_id, ikm)
#            OKM = HMAC-SHA256(PRK, "immurok-pairing" || 0x01)

TV1_PRK = bytes.fromhex(
    "ee5e7176b250c70e39e2ce1b1f8adc4a745ce2bee58a87dd28b62ff007bd7f58"
)
TV1_OKM = bytes.fromhex(
    "35d7fb8cdc4e15798b843fc74aa2c0569d06af53ebbf3166b044adc4090a2b06"
)

TV2_PRK = bytes.fromhex(
    "c0b18e36e474367b5ce5fd0ab04d9a623b407159b05864fe3b05049d5335f4c3"
)
TV2_OKM = bytes.fromhex(
    "4566a08acb88b35bb73373d0595b1b20d832ee07d381da4978a79e71abe5b870"
)


# ── HKDF ───────────────────────────────────────────────────────


class TestHKDF:
    def test_extract_tv1(self):
        ikm = HOST_RANDOM_1 + DEV_RANDOM_1
        assert hkdf_extract(TEST_HOST_ID, ikm) == TV1_PRK

    def test_extract_tv2(self):
        ikm = HOST_RANDOM_2 + DEV_RANDOM_2
        assert hkdf_extract(TEST_HOST_ID, ikm) == TV2_PRK

    def test_expand_tv1(self):
        assert hkdf_expand(TV1_PRK, HKDF_INFO, 32) == TV1_OKM

    def test_expand_tv2(self):
        assert hkdf_expand(TV2_PRK, HKDF_INFO, 32) == TV2_OKM

    def test_derive_shared_key_tv1(self):
        assert derive_shared_key(HOST_RANDOM_1, DEV_RANDOM_1, TEST_HOST_ID) == TV1_OKM

    def test_derive_shared_key_tv2(self):
        assert derive_shared_key(HOST_RANDOM_2, DEV_RANDOM_2, TEST_HOST_ID) == TV2_OKM

    def test_derive_key_length(self, shared_key_1):
        assert len(shared_key_1) == 32

    def test_extract_empty_salt_uses_zeros(self):
        """空 salt 应使用 32 字节零值 (匹配固件 default_salt)"""
        import hashlib
        import hmac

        ikm = b"test"
        result = hkdf_extract(b"", ikm)
        expected = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
        assert result == expected

    def test_expand_rejects_over_32(self):
        with pytest.raises(ValueError):
            hkdf_expand(b"\x00" * 32, b"info", 33)

    def test_derive_key_deterministic(self):
        """相同输入 → 相同输出"""
        k1 = derive_shared_key(HOST_RANDOM_1, DEV_RANDOM_1, TEST_HOST_ID)
        k2 = derive_shared_key(HOST_RANDOM_1, DEV_RANDOM_1, TEST_HOST_ID)
        assert k1 == k2

    def test_derive_key_different_input(self):
        """不同输入 → 不同输出"""
        k1 = derive_shared_key(HOST_RANDOM_1, DEV_RANDOM_1, TEST_HOST_ID)
        k2 = derive_shared_key(HOST_RANDOM_2, DEV_RANDOM_2, TEST_HOST_ID)
        assert k1 != k2


# ── 签名 FP 匹配 HMAC ─────────────────────────────────────────
# CH592F HMAC 输入: page_id(2 LE) || timestamp(4 LE) (无 counter)

TV_FP_HMAC = bytes.fromhex("1c6deffa14400633")  # key=TV1_OKM, pid=3, ts=0x12345678


class TestFPMatchSigned:
    def test_verify_known_vector(self, shared_key_1):
        assert verify_fp_match_signed(
            shared_key_1, page_id=3, timestamp=0x12345678,
            received_hmac=TV_FP_HMAC,
        )

    def test_wrong_page_id_fails(self, shared_key_1):
        assert not verify_fp_match_signed(
            shared_key_1, page_id=4, timestamp=0x12345678,
            received_hmac=TV_FP_HMAC,
        )

    def test_wrong_timestamp_fails(self, shared_key_1):
        assert not verify_fp_match_signed(
            shared_key_1, page_id=3, timestamp=0x12345679,
            received_hmac=TV_FP_HMAC,
        )

    def test_wrong_key_fails(self, shared_key_2):
        assert not verify_fp_match_signed(
            shared_key_2, page_id=3, timestamp=0x12345678,
            received_hmac=TV_FP_HMAC,
        )

    def test_hmac_input_layout(self, shared_key_1):
        """验证 HMAC 输入的字节布局: page_id(2 LE) || ts(4 LE) = 6 字节 (CH592F 无 counter)"""
        import hashlib
        import hmac

        data = struct.pack("<HI", 3, 0x12345678)
        assert len(data) == 6
        expected = hmac.new(shared_key_1, data, hashlib.sha256).digest()[:8]
        assert expected == TV_FP_HMAC


# ── AUTH_RESPONSE HMAC ─────────────────────────────────────────
# CH592F HMAC 输入: challenge(8) || nonce(8) || "auth-ok"(7) = 23 字节 (无 counter)

TV_AUTH_CHALLENGE = bytes.fromhex("0102030405060708")
TV_AUTH_NONCE = bytes.fromhex("a0b0c0d0e0f00010")
TV_AUTH_HMAC = bytes.fromhex("a9bb0c14a67cb815")  # key=TV1_OKM


class TestAuthResponse:
    def test_verify_known_vector(self, shared_key_1):
        assert verify_auth_response(
            shared_key_1, TV_AUTH_CHALLENGE, TV_AUTH_NONCE,
            TV_AUTH_HMAC,
        )

    def test_wrong_challenge_fails(self, shared_key_1):
        bad_challenge = b"\xff" * 8
        assert not verify_auth_response(
            shared_key_1, bad_challenge, TV_AUTH_NONCE,
            TV_AUTH_HMAC,
        )

    def test_wrong_nonce_fails(self, shared_key_1):
        bad_nonce = b"\xff" * 8
        assert not verify_auth_response(
            shared_key_1, TV_AUTH_CHALLENGE, bad_nonce,
            TV_AUTH_HMAC,
        )

    def test_wrong_key_fails(self, shared_key_2):
        assert not verify_auth_response(
            shared_key_2, TV_AUTH_CHALLENGE, TV_AUTH_NONCE,
            TV_AUTH_HMAC,
        )

    def test_hmac_input_layout(self, shared_key_1):
        """验证 23 字节 HMAC 输入布局 (CH592F 无 counter)"""
        import hashlib
        import hmac

        data = TV_AUTH_CHALLENGE + TV_AUTH_NONCE + b"auth-ok"
        assert len(data) == 23
        expected = hmac.new(shared_key_1, data, hashlib.sha256).digest()[:8]
        assert expected == TV_AUTH_HMAC


# ── 出厂重置 HMAC ─────────────────────────────────────────────

TV_RESET_HMAC = bytes.fromhex(
    "9b9c1ee5d985b1556b74c3cf4ce48813a3f39a7ba66f6cb75c3a14452206cc5c"
)


class TestResetHMAC:
    def test_known_vector(self, shared_key_1):
        assert compute_reset_hmac(shared_key_1) == TV_RESET_HMAC

    def test_full_32_bytes(self, shared_key_1):
        result = compute_reset_hmac(shared_key_1)
        assert len(result) == HMAC_FULL_LEN

    def test_different_key(self, shared_key_2):
        assert compute_reset_hmac(shared_key_2) != TV_RESET_HMAC


# ── Host ID ────────────────────────────────────────────────────


class TestHostID:
    def test_length(self):
        hid = get_host_id()
        assert len(hid) == 16

    def test_deterministic(self):
        assert get_host_id() == get_host_id()

    def test_from_machine_id(self):
        mid = Path("/etc/machine-id").read_text().strip()
        expected = bytes.fromhex(mid)[:16]
        assert get_host_id() == expected


# ── PairingData 持久化 ─────────────────────────────────────────


class TestPairingData:
    @pytest.fixture(autouse=True)
    def clean_pairing(self, tmp_path, monkeypatch):
        """将配对文件路径重定向到临时目录"""
        pairing_file = tmp_path / "pairing.json"
        monkeypatch.setattr(
            PairingData, "_pairing_path", staticmethod(lambda: pairing_file)
        )
        yield
        if pairing_file.exists():
            pairing_file.unlink()

    def test_save_and_load(self, shared_key_1):
        p = PairingData(
            device_id=b"\xAA" * 16,
            shared_key=shared_key_1,
            host_id=get_host_id(),
            auth_counter=10,
            notify_counter=5,
        )
        p.save()

        loaded = PairingData.load()
        assert loaded is not None
        assert loaded.device_id == b"\xAA" * 16
        assert loaded.shared_key == shared_key_1
        assert loaded.auth_counter == 10
        assert loaded.notify_counter == 5

    def test_load_nonexistent(self):
        assert PairingData.load() is None

    def test_delete(self, shared_key_1):
        p = PairingData(b"\xBB" * 16, shared_key_1, get_host_id())
        p.save()
        assert PairingData.load() is not None
        assert PairingData.delete() is True
        assert PairingData.load() is None

    def test_delete_nonexistent(self):
        assert PairingData.delete() is False

    def test_increment_auth_counter(self, shared_key_1):
        p = PairingData(b"\xCC" * 16, shared_key_1, get_host_id(), auth_counter=0)
        p.save()

        assert p.increment_auth_counter() == 1
        assert p.increment_auth_counter() == 2
        assert p.increment_auth_counter() == 3

        # 重新加载，确认持久化
        loaded = PairingData.load()
        assert loaded.auth_counter == 3

    def test_update_notify_counter(self, shared_key_1):
        p = PairingData(b"\xDD" * 16, shared_key_1, get_host_id(), notify_counter=0)
        p.save()

        p.update_notify_counter(5)
        assert p.notify_counter == 5

        # 不能倒退
        p.update_notify_counter(3)
        assert p.notify_counter == 5

        # 重新加载确认
        loaded = PairingData.load()
        assert loaded.notify_counter == 5

    def test_json_format(self, shared_key_1):
        p = PairingData(b"\xEE" * 16, shared_key_1, get_host_id())
        p.save()

        path = PairingData._pairing_path()
        data = json.loads(path.read_text())
        assert "device_id" in data
        assert "shared_key" in data
        assert "host_id" in data
        assert "auth_counter" in data
        assert "notify_counter" in data
        # 值是 hex 字符串
        assert data["device_id"] == "ee" * 16

    def test_load_corrupted_returns_none(self):
        path = PairingData._pairing_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json{{{")
        assert PairingData.load() is None

    def test_load_missing_field_returns_none(self):
        path = PairingData._pairing_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"device_id": "aa"}')  # 缺少 shared_key 等
        assert PairingData.load() is None
