"""
immurok 守护进程 — 主 asyncio 事件循环

协调 BLE、Socket Server、Screen Monitor 三个模块。
日志输出到 stderr（journald 兼容）。
"""

import asyncio
import logging
import signal
import subprocess
import sys

from .ble import ImmurokBLE
from .screen import ScreenMonitor
from .security import PairingData
from .socket_server import SocketServer

log = logging.getLogger("immurok.daemon")


async def main() -> None:
    # 日志 → stderr (journald 自动收集)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    log.info("immurok daemon 启动中...")

    ble = ImmurokBLE()
    screen = ScreenMonitor()
    server = SocketServer(ble)

    # ── 指纹匹配回调 ─────────────────────────────────────────────

    def on_fp_match(page_id: int) -> None:
        log.info("指纹匹配: page_id=%d", page_id)

        # 通知指纹测试
        server.notify_fp_match(page_id)

        if server.has_pending_auth():
            server.approve_pending()
        elif screen.screen_locked:
            if not server.settings.unlock_screen:
                log.info("屏幕锁定但锁屏解锁已关闭，跳过")
                return
            server.set_pre_auth()
            log.info("屏幕锁定，正在解锁")
            try:
                subprocess.Popen(
                    ["loginctl", "unlock-session"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                log.warning("loginctl 未找到，无法解锁屏幕")
        else:
            server.set_pre_auth()

    ble.on_fp_match = on_fp_match

    # ── 录入进度回调 ─────────────────────────────────────────────

    def on_enroll_progress(event: int, current: int, total: int) -> None:
        server.update_enroll_status(event, current, total)

    ble.on_enroll_progress = on_enroll_progress

    # ── 连接状态回调 ─────────────────────────────────────────────

    async def on_connected_async() -> None:
        """连接后检查配对状态同步，刷新指纹缓存"""
        pairing = PairingData.load()
        if pairing is None:
            return
        try:
            device_pair_status = await ble.get_pair_status()
            if device_pair_status != 0x01:
                log.warning("设备未配对但本地有配对数据，清除本地数据")
                PairingData.delete()
                ble._pairing = None
        except Exception as e:
            log.debug("检查配对状态失败: %s", e)

        await server.refresh_fp_bitmap()

    def on_connected() -> None:
        log.info("BLE 已连接")
        asyncio.get_event_loop().create_task(on_connected_async())

    def on_disconnected() -> None:
        log.warning("BLE 已断开")

    ble.on_connected = on_connected
    ble.on_disconnected = on_disconnected

    # ── 信号处理 ─────────────────────────────────────────────────

    shutdown_event = asyncio.Event()

    def handle_signal() -> None:
        log.info("收到终止信号，正在关闭...")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    # ── 启动所有任务 ─────────────────────────────────────────────

    async def run_all() -> None:
        ble_task = asyncio.create_task(ble.scan_and_connect())
        screen_task = asyncio.create_task(screen.start())
        server_task = asyncio.create_task(server.start())

        await asyncio.sleep(0.1)
        log.info("immurok daemon 已就绪")

        await shutdown_event.wait()

        log.info("正在关闭...")
        await ble.disconnect()
        await server.stop()
        await screen.stop()

        ble_task.cancel()
        screen_task.cancel()

        for task in (ble_task, screen_task):
            try:
                await task
            except asyncio.CancelledError:
                pass

    await run_all()
    log.info("immurok daemon 已退出")
