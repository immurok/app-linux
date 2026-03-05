"""
immurok 安全模块 — HKDF / HMAC / 配对数据持久化

所有密码学参数严格匹配固件 immurok_security.c，包含反重放 counter。
仅使用 Python 标准库 (hashlib, hmac)。
"""

import hashlib
import hmac as _hmac
import json
import os
import struct
from pathlib import Path

from .config import (
    CHALLENGE_LEN,
    HKDF_INFO,
    HMAC_FULL_LEN,
    HMAC_TRUNCATED_LEN,
    NONCE_LEN,
    PAIRING_DIR,
    PAIRING_FILE,
    RANDOM_LEN,
    SHARED_KEY_LEN,
)


# ── Host ID ────────────────────────────────────────────────────

def get_host_id() -> bytes:
    """从 /etc/machine-id 读取并截取前 16 字节作为 host_id。"""
    mid = Path("/etc/machine-id").read_text().strip()
    return bytes.fromhex(mid)[:16]


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


def derive_shared_key(host_random: bytes, device_random: bytes,
                      host_id: bytes) -> bytes:
    """
    从配对随机数推导共享密钥 (32 字节)。

    固件 immurok_security.c (CH592F):
      IKM  = host_random(16) || device_random(16)
      Salt = host_id (16 bytes)
      Info = "immurok-pairing" (15 bytes)
    """
    ikm = host_random[:RANDOM_LEN] + device_random[:RANDOM_LEN]
    prk = hkdf_extract(host_id, ikm)
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
    timestamp: int,
    received_hmac: bytes,
) -> bool:
    """
    验证固件发来的签名指纹匹配通知。

    HMAC 输入 (6 字节): page_id(2 LE) || timestamp(4 LE)
    固件 CH592F: immurok_security.c:667-682 (无 counter)
    """
    hmac_input = struct.pack("<HI", page_id, timestamp)
    expected = _hmac_truncated(key, hmac_input)
    return _constant_time_eq(expected, received_hmac)


# ── AUTH_RESPONSE 验证 ─────────────────────────────────────────

def verify_auth_response(
    key: bytes,
    challenge: bytes,
    device_nonce: bytes,
    received_hmac: bytes,
) -> bool:
    """
    验证固件返回的认证响应 HMAC。

    HMAC 输入 (23 字节):
      challenge(8) || device_nonce(8) || "auth-ok"(7)
    固件 CH592F: immurok_security.c:367-378
    """
    hmac_input = (
        challenge[:CHALLENGE_LEN]
        + device_nonce[:NONCE_LEN]
        + b"auth-ok"
    )
    expected = _hmac_truncated(key, hmac_input)
    return _constant_time_eq(expected, received_hmac)


# ── 出厂重置 HMAC ─────────────────────────────────────────────

def compute_reset_hmac(key: bytes) -> bytes:
    """
    计算出厂重置的完整 32 字节 HMAC。
    HMAC 输入: "factory-reset" (13 字节)
    固件: immurok_security.c:494-502
    """
    return _hmac_sha256(key, b"factory-reset")


# ── 命令认证 HMAC ─────────────────────────────────────────────

def compute_cmd_hmac(key: bytes, cmd: int, payload: bytes, challenge: bytes) -> bytes:
    """
    计算命令认证的截断 HMAC (8 字节)。

    HMAC 输入: cmd(1) || payload || challenge(8)
    固件: immurok_security.c:603-617 (verify_cmd)
    """
    hmac_input = bytes([cmd]) + payload + challenge[:CHALLENGE_LEN]
    return _hmac_truncated(key, hmac_input)


# ── 配对数据持久化 ─────────────────────────────────────────────

class PairingData:
    """配对数据管理：密钥、设备 ID、counter 持久化到 ~/.immurok/pairing.json"""

    def __init__(
        self,
        device_id: bytes,
        shared_key: bytes,
        host_id: bytes,
        auth_counter: int = 0,
        notify_counter: int = 0,
    ):
        self.device_id = device_id
        self.shared_key = shared_key
        self.host_id = host_id
        self.auth_counter = auth_counter
        self.notify_counter = notify_counter

    def increment_auth_counter(self) -> int:
        """递增并持久化 auth_counter，返回新值。"""
        self.auth_counter += 1
        self.save()
        return self.auth_counter

    def update_notify_counter(self, counter: int) -> None:
        """更新 notify_counter (从设备通知中获取)，持久化。"""
        if counter > self.notify_counter:
            self.notify_counter = counter
            self.save()

    @staticmethod
    def _pairing_path() -> Path:
        return Path(PAIRING_DIR).expanduser() / PAIRING_FILE

    def save(self) -> None:
        path = self._pairing_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "device_id": self.device_id.hex(),
            "shared_key": self.shared_key.hex(),
            "host_id": self.host_id.hex(),
            "auth_counter": self.auth_counter,
            "notify_counter": self.notify_counter,
        }
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
            return cls(
                device_id=bytes.fromhex(data["device_id"]),
                shared_key=bytes.fromhex(data["shared_key"]),
                host_id=bytes.fromhex(data["host_id"]),
                auth_counter=data.get("auth_counter", 0),
                notify_counter=data.get("notify_counter", 0),
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    @classmethod
    def delete(cls) -> bool:
        path = cls._pairing_path()
        if path.exists():
            path.unlink()
            return True
        return False
