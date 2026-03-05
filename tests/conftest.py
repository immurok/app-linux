"""共享 fixture"""

import pytest

from immurok.security import derive_shared_key


# 固定随机数，用于可重现的测试
HOST_RANDOM_1 = b"\x00" * 16
DEV_RANDOM_1 = b"\x01" * 16
TEST_HOST_ID = b"\x11" * 16

HOST_RANDOM_2 = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
DEV_RANDOM_2 = bytes.fromhex("1122334455667788aabbccddeeff0011")


@pytest.fixture
def shared_key_1():
    """从全零/全一随机数推导的共享密钥"""
    return derive_shared_key(HOST_RANDOM_1, DEV_RANDOM_1, TEST_HOST_ID)


@pytest.fixture
def shared_key_2():
    """从固定随机数推导的共享密钥"""
    return derive_shared_key(HOST_RANDOM_2, DEV_RANDOM_2, TEST_HOST_ID)
