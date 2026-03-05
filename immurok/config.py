"""immurok 常量定义 — 以固件为准"""

# ── BLE GATT UUID ──────────────────────────────────────────────
SERVICE_UUID = "12340010-0000-1000-8000-00805f9b34fb"
CHAR_CMD_UUID = "12340011-0000-1000-8000-00805f9b34fb"
CHAR_RSP_UUID = "12340012-0000-1000-8000-00805f9b34fb"

BLE_DEVICE_NAME_PREFIX = "immurok"

# ── BLE 时序 ───────────────────────────────────────────────────
BLE_SCAN_TIMEOUT = 5.0          # 单次扫描超时 (秒)
BLE_RECONNECT_INTERVAL = 3.0    # 重连间隔 (秒)
BLE_COMMAND_TIMEOUT = 5.0       # 普通命令响应超时
BLE_AUTH_TIMEOUT = 60.0         # AUTH_REQUEST 等待指纹超时
BLE_PAIR_POLL_INTERVAL = 0.5    # 配对确认轮询间隔
BLE_PAIR_MAX_RETRIES = 60       # 配对确认最大重试次数 (30 秒)

# ── 命令码 ─────────────────────────────────────────────────────
CMD_GET_STATUS = 0x01
CMD_LOCK = 0x02
CMD_UNLOCK = 0x06
CMD_ENROLL_START = 0x10
CMD_ENROLL_STATUS = 0x11        # 通知方向: 设备 → 主机
CMD_DELETE_FP = 0x12
CMD_FP_LIST = 0x13
CMD_FP_MATCHED = 0x20           # 未签名指纹匹配 (未配对时)
CMD_FP_MATCH_SIGNED = 0x21      # 签名指纹匹配 (配对后)
CMD_FP_MATCH_ACK = 0x22          # 确认收到签名指纹匹配
CMD_PAIR_INIT = 0x30
CMD_PAIR_CONFIRM = 0x31
CMD_AUTH_REQUEST = 0x33
CMD_GET_PAIR_STATUS = 0x35
CMD_FACTORY_RESET = 0x36
CMD_GET_CMD_CHALLENGE = 0x40     # 获取命令认证挑战值

# ── 状态码 / 错误码 ───────────────────────────────────────────
STATUS_OK = 0x00
STATUS_NOT_PAIRED = 0x02
STATUS_ALREADY_PAIRED = 0x03
STATUS_TIMEOUT = 0x06
STATUS_FP_NOT_MATCH = 0x07
STATUS_INVALID_HMAC = 0x08
STATUS_COUNTER_REPLAY = 0x09
STATUS_WAIT_BUTTON = 0x10
STATUS_WAIT_FP = 0x11
STATUS_INVALID_STATE = 0xFD
STATUS_INVALID_PARAM = 0xFE
STATUS_UNKNOWN_CMD = 0xFF

# ── 录入状态 ───────────────────────────────────────────────────
ENROLL_WAITING = 0x00
ENROLL_CAPTURED = 0x01
ENROLL_PROCESSING = 0x02
ENROLL_LIFT_FINGER = 0x03
ENROLL_COMPLETE = 0x04
ENROLL_FAILED = 0xFF

# ── 长度常量 ───────────────────────────────────────────────────
HOST_ID_LEN = 16
DEVICE_ID_LEN = 16
RANDOM_LEN = 16
SHARED_KEY_LEN = 32
HMAC_FULL_LEN = 32
HMAC_TRUNCATED_LEN = 8
CHALLENGE_LEN = 8
NONCE_LEN = 8
TIMESTAMP_LEN = 4
COUNTER_LEN = 4

# ── HKDF 参数 (固件 immurok_security.c) ──────────────────────
# Salt = host_id (16 字节，运行时传入)
HKDF_INFO = b"immurok-pairing"

# ── AUTH_REQUEST payload 长度 ──────────────────────────────────
AUTH_REQUEST_PAYLOAD_LEN = CHALLENGE_LEN  # 8 (仅 challenge，无 counter)

# ── 路径 ─────────────────────────────────────────────────────
PAIRING_DIR = "~/.immurok"
PAIRING_FILE = "pairing.json"
SETTINGS_FILE = "settings.json"
SOCKET_PATH = "/tmp/immurok.sock"

# ── 预授权 / PAM ─────────────────────────────────────────────
PRE_AUTH_DURATION = 10.0         # 预授权窗口 (秒)
PAM_TIMEOUT = 30                 # PAM 认证超时 (秒)

# ── 最大指纹槽位 ─────────────────────────────────────────────
MAX_FINGERPRINT_SLOTS = 5        # 固件 FP_MAX_SLOTS (CH592F: 0-4)
