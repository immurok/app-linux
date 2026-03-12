"""共享 fixture"""

import pytest

from immurok.security import derive_shared_key


# 固定 ECDH 共享密钥 (模拟 ECDH 输出)
TEST_ECDH_SECRET_1 = b"\x00" * 32
TEST_ECDH_SECRET_2 = bytes.fromhex(
    "a1b2c3d4e5f60718293a4b5c6d7e8f90" "1122334455667788aabbccddeeff0011"
)


@pytest.fixture
def shared_key_1():
    """从全零 ECDH secret 推导的共享密钥"""
    return derive_shared_key(TEST_ECDH_SECRET_1)


@pytest.fixture
def shared_key_2():
    """从固定 ECDH secret 推导的共享密钥"""
    return derive_shared_key(TEST_ECDH_SECRET_2)
