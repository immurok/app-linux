"""
immurok.security 单元测试

测试 ECDH 配对、HKDF 密钥推导、HMAC 验证。
所有测试向量由 Python hmac/hashlib 独立计算后硬编码，
确保与固件 + docs/security.md 一致。
"""

import json
import struct
from pathlib import Path

import pytest

from immurok.config import HKDF_INFO, HKDF_SALT, HMAC_TRUNCATED_LEN
from immurok.security import (
    PairingData,
    compute_reset_hmac,
    derive_shared_key,
    generate_p256_keypair,
    ecdh_shared_secret,
    hkdf_expand,
    hkdf_extract,
    verify_fp_match_signed,
)

from .conftest import TEST_ECDH_SECRET_1, TEST_ECDH_SECRET_2


# ── HKDF 测试向量 ─────────────────────────────────────────────
# Salt = "immurok-pairing-salt", Info = "immurok-shared-key"
# PRK = HMAC-SHA256(salt, ikm)
# OKM = HMAC-SHA256(PRK, info || 0x01)

TV1_PRK = bytes.fromhex(
    "d7dac89591ecde1a0d19653b9e48460dfb75728be0bddad5b2c9e6846d082876"
)
TV1_OKM = bytes.fromhex(
    "8ce33b7eb7b369e488d58d05d5f5638c0442eaad226c9d837edeeff17f96a2b7"
)

TV2_PRK = bytes.fromhex(
    "faa2b9a1960da45cc55e4edc5bd8320fdbca0d5bfb52b9afa0a625a216ce26f8"
)
TV2_OKM = bytes.fromhex(
    "839da97831d5093fdc0c13f45867f2962a27e38c1b4b9be661e5846f4902349c"
)


# ── HKDF ───────────────────────────────────────────────────────


class TestHKDF:
    def test_extract_tv1(self):
        assert hkdf_extract(HKDF_SALT, TEST_ECDH_SECRET_1) == TV1_PRK

    def test_extract_tv2(self):
        assert hkdf_extract(HKDF_SALT, TEST_ECDH_SECRET_2) == TV2_PRK

    def test_expand_tv1(self):
        assert hkdf_expand(TV1_PRK, HKDF_INFO, 32) == TV1_OKM

    def test_expand_tv2(self):
        assert hkdf_expand(TV2_PRK, HKDF_INFO, 32) == TV2_OKM

    def test_derive_shared_key_tv1(self):
        assert derive_shared_key(TEST_ECDH_SECRET_1) == TV1_OKM

    def test_derive_shared_key_tv2(self):
        assert derive_shared_key(TEST_ECDH_SECRET_2) == TV2_OKM

    def test_derive_key_length(self, shared_key_1):
        assert len(shared_key_1) == 32

    def test_extract_empty_salt_uses_zeros(self):
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
        k1 = derive_shared_key(TEST_ECDH_SECRET_1)
        k2 = derive_shared_key(TEST_ECDH_SECRET_1)
        assert k1 == k2

    def test_derive_key_different_input(self):
        k1 = derive_shared_key(TEST_ECDH_SECRET_1)
        k2 = derive_shared_key(TEST_ECDH_SECRET_2)
        assert k1 != k2


# ── ECDH P-256 ─────────────────────────────────────────────────


class TestECDH:
    def test_generate_keypair(self):
        privkey, pubkey = generate_p256_keypair()
        assert len(pubkey) == 33  # compressed P-256 公钥
        assert pubkey[0] in (0x02, 0x03)  # 压缩前缀

    def test_ecdh_roundtrip(self):
        """两端各自生成密钥对，交换公钥后计算共享密钥应一致"""
        priv_a, pub_a = generate_p256_keypair()
        priv_b, pub_b = generate_p256_keypair()

        secret_a = ecdh_shared_secret(priv_a, pub_b)
        secret_b = ecdh_shared_secret(priv_b, pub_a)
        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_derive_from_ecdh(self):
        """ECDH + HKDF 推导共享密钥"""
        priv_a, pub_a = generate_p256_keypair()
        priv_b, pub_b = generate_p256_keypair()

        secret = ecdh_shared_secret(priv_a, pub_b)
        key = derive_shared_key(secret)
        assert len(key) == 32


# ── 签名 FP 匹配 HMAC ─────────────────────────────────────────
# docs/security.md:
#   message = 0x21 || page_id(2 LE)    (3 bytes)
#   hmac = HMAC-SHA256(shared_key, message)[0:8]

TV_FP_HMAC = bytes.fromhex("f40d525ac61aff04")  # key=TV1_OKM, pid=3


class TestFPMatchSigned:
    def test_verify_known_vector(self, shared_key_1):
        assert verify_fp_match_signed(
            shared_key_1, page_id=3,
            received_hmac=TV_FP_HMAC,
        )

    def test_wrong_page_id_fails(self, shared_key_1):
        assert not verify_fp_match_signed(
            shared_key_1, page_id=4,
            received_hmac=TV_FP_HMAC,
        )

    def test_wrong_key_fails(self, shared_key_2):
        assert not verify_fp_match_signed(
            shared_key_2, page_id=3,
            received_hmac=TV_FP_HMAC,
        )

    def test_hmac_input_layout(self, shared_key_1):
        """验证 HMAC 输入: 0x21 || page_id(2 LE) = 3 字节"""
        import hashlib
        import hmac

        data = bytes([0x21]) + struct.pack("<H", 3)
        assert len(data) == 3
        expected = hmac.new(shared_key_1, data, hashlib.sha256).digest()[:8]
        assert expected == TV_FP_HMAC


# ── 出厂重置 HMAC ─────────────────────────────────────────────

TV_RESET_HMAC = bytes.fromhex(
    "76d4ceed270272a5509ccc55b9a6585651f5405841fb5487f03da028ba2c44c8"
)


class TestResetHMAC:
    def test_known_vector(self, shared_key_1):
        assert compute_reset_hmac(shared_key_1) == TV_RESET_HMAC

    def test_full_32_bytes(self, shared_key_1):
        result = compute_reset_hmac(shared_key_1)
        assert len(result) == 32

    def test_different_key(self, shared_key_2):
        assert compute_reset_hmac(shared_key_2) != TV_RESET_HMAC


# ── PairingData 持久化 ─────────────────────────────────────────


class TestPairingData:
    @pytest.fixture(autouse=True)
    def clean_pairing(self, tmp_path, monkeypatch):
        pairing_file = tmp_path / "pairing.json"
        monkeypatch.setattr(
            PairingData, "_pairing_path", staticmethod(lambda: pairing_file)
        )
        yield
        if pairing_file.exists():
            pairing_file.unlink()

    def test_save_and_load(self, shared_key_1):
        p = PairingData(shared_key=shared_key_1)
        p.save()

        loaded = PairingData.load()
        assert loaded is not None
        assert loaded.shared_key == shared_key_1

    def test_load_nonexistent(self):
        assert PairingData.load() is None

    def test_delete(self, shared_key_1):
        p = PairingData(shared_key=shared_key_1)
        p.save()
        assert PairingData.load() is not None
        assert PairingData.delete() is True
        assert PairingData.load() is None

    def test_delete_nonexistent(self):
        assert PairingData.delete() is False

    def test_json_format(self, shared_key_1):
        p = PairingData(shared_key=shared_key_1)
        p.save()

        path = PairingData._pairing_path()
        data = json.loads(path.read_text())
        assert "shared_key" in data
        assert data["shared_key"] == shared_key_1.hex()

    def test_load_corrupted_returns_none(self):
        path = PairingData._pairing_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json{{{")
        assert PairingData.load() is None

    def test_load_missing_field_returns_none(self):
        path = PairingData._pairing_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"device_id": "aa"}')  # 缺少 shared_key
        assert PairingData.load() is None
