"""immurok 常量定义 — 以固件 + docs/protocol.md 为准"""

# ── BLE GATT UUID ──────────────────────────────────────────────
SERVICE_UUID = "12340010-0000-1000-8000-00805f9b34fb"
CHAR_CMD_UUID = "12340011-0000-1000-8000-00805f9b34fb"
CHAR_RSP_UUID = "12340012-0000-1000-8000-00805f9b34fb"

BLE_DEVICE_NAME_PREFIX = "immurok"

# ── BLE 时序 ───────────────────────────────────────────────────
BLE_RECONNECT_INTERVAL = 3.0    # 重连间隔 (秒)
BLE_COMMAND_TIMEOUT = 5.0       # 普通命令响应超时
BLE_PAIR_TIMEOUT = 30.0         # ECDH 配对整体超时（设备计算约 2s×2）
BLE_FP_GATE_TIMEOUT = 30.0      # FP-gate 等待指纹超时
BLE_AUTH_TIMEOUT = 30.0         # AUTH_REQUEST 等待指纹超时

# ── 命令码 ─────────────────────────────────────────────────────
CMD_GET_STATUS = 0x01
CMD_ENROLL_START = 0x10
CMD_ENROLL_STATUS = 0x11        # 通知方向: 设备 → 主机 (4 字节)
CMD_DELETE_FP = 0x12
CMD_FP_LIST = 0x13
CMD_FP_MATCH_SIGNED = 0x21      # 签名指纹匹配通知 (11 字节)
CMD_FP_MATCH_ACK = 0x22         # 确认收到签名指纹匹配
CMD_PAIR_INIT = 0x30
CMD_PAIR_CONFIRM = 0x31
CMD_PAIR_STATUS = 0x32
CMD_AUTH_REQUEST = 0x33
CMD_FACTORY_RESET = 0x36

# ── Key Storage 命令码 ─────────────────────────────────────────
CMD_KEY_COUNT = 0x60
CMD_KEY_READ = 0x61
CMD_KEY_WRITE = 0x62
CMD_KEY_DELETE = 0x63
CMD_KEY_COMMIT = 0x64
CMD_KEY_SIGN = 0x65
CMD_KEY_GETPUB = 0x66
CMD_KEY_GENERATE = 0x67
CMD_KEY_RESULT = 0x68
CMD_KEY_OTP_GET = 0x69

# ── 状态码 / 错误码 ───────────────────────────────────────────
STATUS_OK = 0x00
STATUS_TIMEOUT = 0x06
STATUS_FP_NOT_MATCH = 0x07
STATUS_FP_GATE_APPROVED = 0x10  # FP-gate: 指纹验证通过，操作进行中
STATUS_WAIT_FP = 0x11           # 设备等待指纹
STATUS_BUSY = 0xFD
STATUS_INVALID_PARAM = 0xFE
STATUS_ERROR = 0xFF

# ── 录入状态 ───────────────────────────────────────────────────
ENROLL_WAITING = 0x00
ENROLL_CAPTURED = 0x01
ENROLL_PROCESSING = 0x02
ENROLL_LIFT_FINGER = 0x03
ENROLL_COMPLETE = 0x04
ENROLL_FAILED = 0xFF

# ── 长度常量 ───────────────────────────────────────────────────
COMPRESSED_PUBKEY_LEN = 33
SHARED_KEY_LEN = 32
HMAC_TRUNCATED_LEN = 8

# ── HKDF 参数 (docs/security.md) ──────────────────────────────
HKDF_SALT = b"immurok-pairing-salt"   # 20 bytes
HKDF_INFO = b"immurok-shared-key"     # 18 bytes

# ── 路径 ─────────────────────────────────────────────────────
PAIRING_DIR = "~/.immurok"
PAIRING_FILE = "pairing.json"
SETTINGS_FILE = "settings.json"
SOCKET_PATH = "~/.immurok/pam.sock"

# ── 预授权 / PAM ─────────────────────────────────────────────
PRE_AUTH_DURATION = 10.0         # 预授权窗口 (秒)
PAM_TIMEOUT = 30                 # PAM 认证超时 (秒)

# ── FP Gate ───────────────────────────────────────────────────
FP_GATE_MAX_FAILURES = 3         # 最多 3 次指纹不匹配

# ── 最大指纹槽位 ─────────────────────────────────────────────
MAX_FINGERPRINT_SLOTS = 5        # 固件 FP_MAX_SLOTS (CH592F: 0-4)

# ── OTA BLE UUID ──────────────────────────────────────────────
OTA_CHAR_UUID = "0000fee1-0000-1000-8000-00805f9b34fb"

# ── OTA 常量 ─────────────────────────────────────────────────
IMAGE_B_BLOCKS = 54              # 216KB / 4KB
OTA_READ_POLL_INTERVAL = 0.2     # OTA 读取轮询间隔 (秒)
OTA_ERASE_TIMEOUT = 15.0         # 擦除超时 (秒)
OTA_SESSION_TIMEOUT = 30.0       # OTA 会话命令间超时 (秒)
