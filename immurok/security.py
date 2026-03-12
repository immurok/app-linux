"""
immurok 安全模块 — ECDH 配对 / HKDF / HMAC / 配对数据持久化

所有密码学参数严格匹配固件 + docs/security.md:
  - ECDH P-256 配对 (ephemeral keypair)
  - HKDF-SHA256 (Salt="immurok-pairing-salt", Info="immurok-shared-key")
  - HMAC-SHA256 (截断 8 字节) 用于 FP 通知验证
"""

import hashlib
import hmac as _hmac
import json
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .config import (
    COMPRESSED_PUBKEY_LEN,
    HKDF_INFO,
    HKDF_SALT,
    HMAC_TRUNCATED_LEN,
    PAIRING_DIR,
    PAIRING_FILE,
    SHARED_KEY_LEN,
)


# ── ECDH P-256 ────────────────────────────────────────────────

def generate_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """
    生成 P-256 临时密钥对。
    返回 (private_key, compressed_pubkey_33B)。
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    compressed = private_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint
    )
    return private_key, compressed


def ecdh_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_compressed_pubkey: bytes,
) -> bytes:
    """
    计算 ECDH 共享密钥 (32 字节 big-endian)。
    peer_compressed_pubkey 是 33 字节的压缩公钥。
    """
    peer_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_compressed_pubkey
    )
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    shared = private_key.exchange(ec.ECDH(), peer_pubkey)
    return shared  # 32 bytes


# ── HKDF-SHA256 (单 block, 匹配固件) ─────────────────────────

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """PRK = HMAC-SHA256(salt, IKM)。salt 为空时用 32 字节零值。"""
    if not salt:
        salt = b"\x00" * 32
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """OKM = HMAC-SHA256(PRK, info || 0x01)。仅支持单 block (≤32 字节)。"""
    if length > 32:
        raise ValueError("单 block HKDF 最多输出 32 字节")
    data = info + b"\x01"
    return _hmac.new(prk, data, hashlib.sha256).digest()[:length]


def derive_shared_key(ecdh_secret: bytes) -> bytes:
    """
    从 ECDH 共享密钥推导 shared_key (32 字节)。

    docs/security.md:
      IKM  = ECDH shared secret (32 bytes, big-endian)
      Salt = "immurok-pairing-salt" (20 bytes)
      Info = "immurok-shared-key" (18 bytes)
    """
    prk = hkdf_extract(HKDF_SALT, ecdh_secret)
    return hkdf_expand(prk, HKDF_INFO, SHARED_KEY_LEN)


# ── HMAC 工具 ─────────────────────────────────────────────────

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def _hmac_truncated(key: bytes, data: bytes) -> bytes:
    return _hmac_sha256(key, data)[:HMAC_TRUNCATED_LEN]


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(a, b)


# ── 签名 FP 匹配验证 (0x21 通知) ──────────────────────────────

def verify_fp_match_signed(
    key: bytes,
    page_id: int,
    received_hmac: bytes,
) -> bool:
    """
    验证固件发来的签名指纹匹配通知。

    docs/security.md:
      message = 0x21 || page_id(2 LE)    (3 bytes)
      hmac = HMAC-SHA256(shared_key, message)[0:8]
    """
    hmac_input = bytes([0x21]) + struct.pack("<H", page_id)
    expected = _hmac_truncated(key, hmac_input)
    return _constant_time_eq(expected, received_hmac)


# ── 出厂重置 HMAC ─────────────────────────────────────────────

def compute_reset_hmac(key: bytes) -> bytes:
    """
    计算出厂重置的完整 32 字节 HMAC。
    HMAC 输入: "factory-reset" (13 字节)
    """
    return _hmac_sha256(key, b"factory-reset")


# ── 配对数据持久化 ─────────────────────────────────────────────

class PairingData:
    """配对数据管理：ECDH 共享密钥持久化到 ~/.immurok/pairing.json"""

    def __init__(self, shared_key: bytes):
        self.shared_key = shared_key

    @staticmethod
    def _pairing_path() -> Path:
        return Path(PAIRING_DIR).expanduser() / PAIRING_FILE

    def save(self) -> None:
        path = self._pairing_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {"shared_key": self.shared_key.hex()}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(path)

    @classmethod
    def load(cls) -> "PairingData | None":
        path = cls._pairing_path()
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return cls(shared_key=bytes.fromhex(data["shared_key"]))
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    @classmethod
    def delete(cls) -> bool:
        path = cls._pairing_path()
        if path.exists():
            path.unlink()
            return True
        return False
