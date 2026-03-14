# immurok Linux — 编译 + 安装
#
# 用法:
#   make              编译 PAM 模块
#   make install      一键安装 (venv + PAM 模块 + 脚本 + systemd)
#   make uninstall    卸载
#   make clean        清理编译产物

CC ?= gcc
CFLAGS = -fPIC -Wall -Wextra -O2
LDFLAGS = -shared -lpam

TARGET = pam_immurok.so
SRC = pam_immurok.c
PY_SCRIPTS = immurok-daemon immurok-cli immurok-auth-dialog
SH_SCRIPTS = immurok-pam-helper

LOCAL_BIN = $(HOME)/.local/bin
SYSTEMD_DIR = $(HOME)/.config/systemd/user
VENV_DIR = $(HOME)/.local/share/immurok/venv
VENV_PYTHON = $(VENV_DIR)/bin/python3

# 自动检测 PAM 模块安装路径
PAM_DIR := $(shell \
    if [ -d /usr/lib64/security ]; then echo /usr/lib64/security; \
    elif [ -d /lib/aarch64-linux-gnu/security ]; then echo /lib/aarch64-linux-gnu/security; \
    elif [ -d /lib/x86_64-linux-gnu/security ]; then echo /lib/x86_64-linux-gnu/security; \
    elif [ -d /lib/security ]; then echo /lib/security; \
    else echo /usr/lib/security; fi)

# 颜色
G = \033[0;32m
Y = \033[1;33m
N = \033[0m

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# ── 一键安装 ───────────────────────────────────────────────────
install: $(TARGET)
	@if [ "$$(id -u)" = "0" ]; then \
		echo -e "$(R)请勿使用 sudo 运行 make install，直接运行 make install 即可$(N)"; \
		exit 1; \
	fi
	@echo "=== immurok Linux 安装 ==="
	@# ── venv + Python 依赖 ──
	@echo -e "$(G)[✓]$(N) 创建 venv..."
	@python3 -m venv $(VENV_DIR)
	@$(VENV_PYTHON) -m pip install --upgrade pip -q
	@$(VENV_PYTHON) -m pip install -r requirements.txt -q
	@echo -e "$(G)[✓]$(N) Python 依赖已安装到 $(VENV_DIR)"
	@# ── Python 包部署到 venv ──
	@PKGDIR=$$($(VENV_PYTHON) -c "import sysconfig;print(sysconfig.get_path('purelib'))") && \
		mkdir -p "$$PKGDIR/immurok" && \
		cp immurok/*.py "$$PKGDIR/immurok/"
	@# ── PAM 模块 (需要 sudo) ──
	@echo -e "$(G)[✓]$(N) 安装 PAM 模块到 $(PAM_DIR)/ ..."
	@sudo install -m 755 $(TARGET) $(PAM_DIR)/$(TARGET)
	@# ── 入口脚本 (改写 shebang 指向 venv python) ──
	@mkdir -p $(LOCAL_BIN)
	@for s in $(PY_SCRIPTS); do \
		sed "1s|.*|#!$(VENV_PYTHON)|" $$s > $(LOCAL_BIN)/$$s && chmod +x $(LOCAL_BIN)/$$s; \
	done
	@for s in $(SH_SCRIPTS); do \
		cp $$s $(LOCAL_BIN)/$$s && chmod +x $(LOCAL_BIN)/$$s; \
	done
	@echo -e "$(G)[✓]$(N) 脚本已部署到 $(LOCAL_BIN)/"
	@# ── systemd 服务 ──
	@mkdir -p $(SYSTEMD_DIR)
	@cp immurok-daemon.service $(SYSTEMD_DIR)/
	@systemctl --user daemon-reload
	@systemctl --user enable immurok-daemon.service
	@systemctl --user restart immurok-daemon.service
	@echo -e "$(G)[✓]$(N) daemon 已启动"
	@# ── 完成 ──
	@echo
	@echo -e "$(G)=== 安装完成 ===$(N)"
	@echo "下一步: immurok-cli"
	@echo "  [p] 配对  [e] 录入指纹  [s] 启用 sudo"

# ── 卸载 ───────────────────────────────────────────────────────
uninstall:
	@if [ "$$(id -u)" = "0" ]; then \
		echo -e "$(R)请勿使用 sudo 运行 make uninstall，直接运行 make uninstall 即可$(N)"; \
		exit 1; \
	fi
	@echo "=== immurok 卸载 ==="
	@-systemctl --user disable --now immurok-daemon.service 2>/dev/null
	@rm -f $(SYSTEMD_DIR)/immurok-daemon.service
	@-systemctl --user daemon-reload 2>/dev/null
	@for s in $(PY_SCRIPTS) $(SH_SCRIPTS); do rm -f $(LOCAL_BIN)/$$s; done
	@rm -rf $(VENV_DIR)
	@-sudo rm -f $(PAM_DIR)/$(TARGET) 2>/dev/null
	@rm -rf $(HOME)/.immurok
	@echo -e "$(G)[✓]$(N) 已卸载"

clean:
	rm -f $(TARGET)
