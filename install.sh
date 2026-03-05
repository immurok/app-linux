#!/bin/bash
#
# immurok Linux 安装脚本
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_BIN="$HOME/.local/bin"
SYSTEMD_DIR="$HOME/.config/systemd/user"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo "=== immurok Linux 安装 ==="
echo

# ── 检查依赖 ─────────────────────────────────────────────────

command -v python3 >/dev/null || error "需要 python3"

if ! python3 -c "import pip" 2>/dev/null; then
    if ! command -v pip3 >/dev/null; then
        warn "pip 未找到，尝试使用系统包管理器安装依赖"
    fi
fi

# ── 安装 Python 依赖 ─────────────────────────────────────────

info "安装 Python 依赖..."
if python3 -m pip install --user -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
    info "Python 依赖已安装"
elif pip3 install --user -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
    info "Python 依赖已安装"
else
    warn "自动安装依赖失败，请手动安装: pip install --user -r requirements.txt"
fi

# ── 编译 PAM 模块 ───────────────────────────────────────────

if command -v gcc >/dev/null; then
    info "编译 PAM 模块..."
    make -C "$SCRIPT_DIR" clean all
    info "PAM 模块编译成功"

    # 检查 pam-devel
    if [ -f /usr/include/security/pam_modules.h ]; then
        echo
        warn "PAM 模块需要 root 权限安装:"
        echo "  sudo make -C $SCRIPT_DIR install"
    else
        warn "pam-devel 未安装，PAM 模块编译可能失败"
        warn "Fedora: sudo dnf install pam-devel"
        warn "Ubuntu: sudo apt install libpam0g-dev"
    fi
else
    warn "gcc 未安装，跳过 PAM 模块编译"
    warn "Fedora: sudo dnf install gcc pam-devel"
    warn "Ubuntu: sudo apt install gcc libpam0g-dev"
fi

# ── 部署 Python 包和脚本 ────────────────────────────────────

info "部署文件..."
mkdir -p "$LOCAL_BIN"

# Python 包
SITE_DIR=$(python3 -c "import site; print(site.getusersitepackages())")
mkdir -p "$SITE_DIR/immurok"
cp "$SCRIPT_DIR"/immurok/*.py "$SITE_DIR/immurok/"
info "Python 包已部署到 $SITE_DIR/immurok/"

# 入口脚本
cp "$SCRIPT_DIR/immurok-daemon" "$LOCAL_BIN/immurok-daemon"
cp "$SCRIPT_DIR/immurok-cli" "$LOCAL_BIN/immurok-cli"
chmod +x "$LOCAL_BIN/immurok-daemon" "$LOCAL_BIN/immurok-cli"
info "脚本已部署到 $LOCAL_BIN/"

# ── 配置 systemd 服务 ───────────────────────────────────────

info "配置 systemd 服务..."
mkdir -p "$SYSTEMD_DIR"
cp "$SCRIPT_DIR/immurok-daemon.service" "$SYSTEMD_DIR/"
systemctl --user daemon-reload
systemctl --user enable immurok-daemon.service
info "systemd 服务已配置"

# ── 完成 ─────────────────────────────────────────────────────

echo
info "安装完成！"
echo
echo "下一步:"
echo "  1. 启动服务:  systemctl --user start immurok-daemon"
echo "  2. 查看状态:  immurok-cli status"
echo "  3. 配对设备:  immurok-cli pair"
echo "  4. 录入指纹:  immurok-cli enroll 0"
echo
echo "PAM 配置 (需要 root):"
echo "  sudo make -C $SCRIPT_DIR install"
echo "  然后编辑以下文件，在第一行 auth 之前添加:"
echo "    auth  sufficient  pam_immurok.so"
echo
echo "  /etc/pam.d/sudo          — sudo 指纹认证"
echo "  /etc/pam.d/gdm-password  — GNOME 锁屏解锁"
echo "  /etc/pam.d/polkit-1      — 系统权限弹窗"
