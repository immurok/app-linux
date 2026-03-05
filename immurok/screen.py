"""
immurok 屏幕锁定检测 — D-Bus 信号监听

仅做锁屏状态监测（日志用途），不做键盘模拟。
屏幕解锁通过 fprintd 模式：PAM 直接认证。

支持 GNOME 和 KDE：
  - GNOME: org.gnome.ScreenSaver → ActiveChanged(bool)
  - KDE:   org.freedesktop.ScreenSaver → ActiveChanged(bool)
"""

import asyncio
import logging
from typing import Callable, Optional

log = logging.getLogger("immurok.screen")


class ScreenMonitor:
    """D-Bus 锁屏状态检测"""

    def __init__(self) -> None:
        self.screen_locked = False
        self.on_lock_changed: Optional[Callable[[bool], None]] = None
        self._bus = None
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """启动 D-Bus 信号监听"""
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import BusType, Message, MessageType

            self._bus = await MessageBus(bus_type=BusType.SESSION).connect()

            # 监听 GNOME ScreenSaver
            await self._bus.call(Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[
                    "type='signal',"
                    "interface='org.gnome.ScreenSaver',"
                    "member='ActiveChanged'"
                ],
            ))

            # 监听 KDE/freedesktop ScreenSaver
            await self._bus.call(Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[
                    "type='signal',"
                    "interface='org.freedesktop.ScreenSaver',"
                    "member='ActiveChanged'"
                ],
            ))

            self._bus.add_message_handler(self._on_message)
            log.info("屏幕锁定监测已启动")

            # 保持连接
            await self._bus.wait_for_disconnect()

        except ImportError:
            log.warning("dbus-fast 未安装，屏幕锁定检测不可用")
        except Exception:
            log.exception("D-Bus 连接失败")

    def _on_message(self, msg) -> None:
        from dbus_fast import MessageType

        if msg.message_type != MessageType.SIGNAL:
            return
        if msg.member != "ActiveChanged":
            return

        try:
            active = msg.body[0]
            self.screen_locked = bool(active)
            log.info("屏幕状态: %s", "已锁定" if self.screen_locked else "已解锁")
            if self.on_lock_changed:
                self.on_lock_changed(self.screen_locked)
        except (IndexError, TypeError):
            pass

    async def stop(self) -> None:
        if self._bus:
            self._bus.disconnect()
            self._bus = None
        log.info("屏幕锁定监测已停止")
