# immurok PAM 模块编译
#
# 自动检测发行版 PAM 安装路径
# 用法:
#   make              编译
#   sudo make install 安装到系统 PAM 目录
#   make clean        清理

CC ?= gcc
CFLAGS = -fPIC -Wall -Wextra -O2
LDFLAGS = -shared -lpam

TARGET = pam_immurok.so
SRC = pam_immurok.c

# 自动检测 PAM 模块安装路径
PAM_DIR := $(shell \
    if [ -d /usr/lib64/security ]; then echo /usr/lib64/security; \
    elif [ -d /lib/aarch64-linux-gnu/security ]; then echo /lib/aarch64-linux-gnu/security; \
    elif [ -d /lib/x86_64-linux-gnu/security ]; then echo /lib/x86_64-linux-gnu/security; \
    elif [ -d /lib/security ]; then echo /lib/security; \
    else echo /usr/lib/security; fi)

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) $(PAM_DIR)/$(TARGET)
	@echo "已安装到 $(PAM_DIR)/$(TARGET)"

uninstall:
	rm -f $(PAM_DIR)/$(TARGET)
	@echo "已卸载 $(PAM_DIR)/$(TARGET)"

clean:
	rm -f $(TARGET)
