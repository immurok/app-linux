"""
immurok Unix Socket 服务器 — PAM / CLI 通信

协议与 macOS PAMSocketServer.swift 完全一致。
文本协议，PAM 模块发送不带结尾符的原始文本。
"""

import asyncio
import logging
import os
import subprocess
import time
from typing import TYPE_CHECKING

from .config import (
    ENROLL_COMPLETE,
    MAX_FINGERPRINT_SLOTS,
    PAM_TIMEOUT,
    PRE_AUTH_DURATION,
    SOCKET_PATH,
    STATUS_OK,
)
from .settings import Settings

if TYPE_CHECKING:
    from .ble import ImmurokBLE

log = logging.getLogger("immurok.socket")


class SocketServer:
    """Unix Socket 服务器，处理 PAM 认证和 CLI 管理请求"""

    def __init__(self, ble: "ImmurokBLE") -> None:
        self._ble = ble
        self._server: asyncio.AbstractServer | None = None
        self._settings = Settings.load()

        # 预授权
        self._pre_auth_expiry: float = 0.0

        # 待处理 PAM 请求
        self._pending_auth: asyncio.Event | None = None
        self._pending_approved = False

        # 录入状态跟踪
        self._enroll_active = False
        self._enroll_event = 0
        self._enroll_current = 0
        self._enroll_total = 0

        # 指纹 bitmap 缓存 (避免每次轮询走 BLE)
        self._fp_bitmap: int = 0

        # 最近一次指纹匹配 (供 CLI 查询)
        self._last_match_page_id: int = -1

    @property
    def settings(self) -> Settings:
        return self._settings

    # ── 认证弹窗 ─────────────────────────────────────────────────

    @staticmethod
    def _show_auth_dialog() -> subprocess.Popen | None:
        """启动指纹认证弹窗，返回进程句柄。"""
        # 查找 immurok-auth-dialog 脚本
        pkg_dir = os.path.dirname(os.path.abspath(__file__))
        dialog = os.path.join(os.path.dirname(pkg_dir), "immurok-auth-dialog")
        if not os.path.isfile(dialog):
            import shutil
            dialog = shutil.which("immurok-auth-dialog")
        if not dialog:
            log.debug("immurok-auth-dialog 未找到")
            return None
        try:
            return subprocess.Popen(
                [dialog], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            return None

    @staticmethod
    def _close_auth_dialog(proc: subprocess.Popen | None) -> None:
        """关闭认证弹窗。"""
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ── 预授权 ───────────────────────────────────────────────────

    def set_pre_auth(self, duration: float = PRE_AUTH_DURATION) -> None:
        self._pre_auth_expiry = time.monotonic() + duration
        log.info("预授权已设置 (%.1f 秒)", duration)

    def consume_pre_auth(self) -> bool:
        if time.monotonic() < self._pre_auth_expiry:
            self._pre_auth_expiry = 0.0
            log.info("预授权已消费")
            return True
        self._pre_auth_expiry = 0.0
        return False

    # ── 待处理 PAM 请求 ──────────────────────────────────────────

    def has_pending_auth(self) -> bool:
        return self._pending_auth is not None

    def approve_pending(self) -> None:
        if self._pending_auth is not None:
            self._pending_approved = True
            self._pending_auth.set()
            log.info("待处理 PAM 请求已批准")

    # ── 录入状态 ─────────────────────────────────────────────────

    def update_enroll_status(self, event: int, current: int, total: int) -> None:
        self._enroll_event = event
        self._enroll_current = current
        self._enroll_total = total
        if event == ENROLL_COMPLETE:
            self._schedule_fp_bitmap_refresh()

    def start_enrollment(self) -> None:
        self._enroll_active = True
        self._enroll_event = 0
        self._enroll_current = 0
        self._enroll_total = 6

    def end_enrollment(self) -> None:
        self._enroll_active = False

    # ── 指纹 bitmap 缓存 ─────────────────────────────────────────────

    async def refresh_fp_bitmap(self) -> None:
        """从 BLE 设备刷新指纹 bitmap 缓存。"""
        if not self._ble.connected:
            return
        try:
            self._fp_bitmap = await self._ble.fp_list()
            log.debug("FP bitmap 已刷新: 0x%02x", self._fp_bitmap)
        except Exception as e:
            log.warning("刷新 FP bitmap 失败: %s", e)

    # ── 指纹测试 ───────────────────────────────────────────────────

    def notify_fp_match(self, page_id: int) -> None:
        """记录最近一次指纹匹配，供 CLI 轮询消费。"""
        self._last_match_page_id = page_id

    # ── 服务器生命周期 ───────────────────────────────────────────

    async def start(self) -> None:
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=SOCKET_PATH
        )
        os.chmod(SOCKET_PATH, 0o666)
        log.info("Socket 服务器已启动: %s", SOCKET_PATH)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
        log.info("Socket 服务器已停止")

    # ── 客户端处理 ───────────────────────────────────────────────

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=5.0)
            if not data:
                return

            request = data.decode("utf-8").strip("\x00\n\r ")
            log.debug("收到请求: %s", request)

            parts = request.split(":")
            cmd = parts[0]

            if cmd == "STATUS":
                response = self._handle_status()
            elif cmd == "AUTH":
                response = await self._handle_auth(parts, reader)
            elif cmd == "FP":
                response = await self._handle_fp(parts)
            elif cmd == "PAIR":
                response = await self._handle_pair(parts)
            elif cmd == "SET":
                response = self._handle_set(parts)
            elif cmd == "GET" and len(parts) >= 2 and parts[1] == "SETTINGS":
                response = self._handle_get_settings()
            else:
                response = "ERROR:UNKNOWN_COMMAND"

            writer.write(response.encode("utf-8"))
            await writer.drain()
        except asyncio.TimeoutError:
            log.debug("客户端读取超时")
        except Exception:
            log.exception("处理客户端请求异常")
        finally:
            writer.close()
            await writer.wait_closed()

    # ── STATUS ───────────────────────────────────────────────────

    def _handle_status(self) -> str:
        connected = self._ble.connected
        device_name = "immurok" if connected else ""
        return f"STATUS:{'1' if connected else '0'}:{device_name}"

    # ── AUTH ──────────────────────────────────────────────────────

    def _is_service_allowed(self, service: str) -> bool:
        """根据 service 名称检查对应功能开关。"""
        s = service.lower()
        if "gdm" in s or "login" in s:
            return self._settings.unlock_screen
        if s == "polkit-1":
            return self._settings.unlock_polkit
        if s == "sudo":
            return self._settings.unlock_sudo
        # 其他权限提升类，跟随 sudo 开关
        return self._settings.unlock_sudo

    async def _watch_client(self, reader: asyncio.StreamReader) -> None:
        """等待客户端断开连接 (PAM 模块超时关闭 socket)。"""
        try:
            await reader.read(1)
        except Exception:
            pass

    async def _watch_dialog(self, proc: subprocess.Popen | None) -> None:
        """等待弹窗进程退出 (用户点击取消)。"""
        if proc is None:
            await asyncio.Event().wait()  # 永不触发
            return
        while proc.poll() is None:
            await asyncio.sleep(0.2)

    async def _handle_auth(
        self, parts: list[str], reader: asyncio.StreamReader
    ) -> str:
        user = parts[1] if len(parts) >= 2 else "unknown"
        service = parts[2] if len(parts) >= 3 else "unknown"
        log.info("AUTH 请求: user=%s, service=%s", user, service)

        # 0. 检查功能开关
        if not self._is_service_allowed(service):
            log.info("AUTH 拒绝 (开关已关闭): service=%s", service)
            return "DENY"

        # 1. 检查预授权
        if self.consume_pre_auth():
            log.info("AUTH 通过预授权批准: %s", user)
            return "OK"

        # 2. 检查 BLE 连接
        if not self._ble.connected:
            log.warning("AUTH 失败: 设备未连接")
            return "DENY"

        # 3. 设置待处理请求，发送 AUTH_REQUEST 等待指纹
        self._pending_auth = asyncio.Event()
        self._pending_approved = False
        dialog_proc = self._show_auth_dialog()

        try:
            auth_task = asyncio.create_task(self._ble.auth_request())
            pending_task = asyncio.create_task(self._pending_auth.wait())
            client_task = asyncio.create_task(self._watch_client(reader))
            dialog_task = asyncio.create_task(self._watch_dialog(dialog_proc))

            all_tasks = [auth_task, pending_task, client_task, dialog_task]

            done, _ = await asyncio.wait(
                all_tasks,
                timeout=PAM_TIMEOUT,
                return_when=asyncio.FIRST_COMPLETED,
            )

            # 指纹主动批准 (on_fp_match 路径)
            if self._pending_approved:
                log.info("AUTH 通过主动指纹批准: %s", user)
                return "OK"

            # 客户端断开 (PAM 模块超时)
            if client_task in done:
                log.info("AUTH 客户端已断开: %s", user)
                return "DENY"

            # 用户取消弹窗
            if dialog_task in done:
                log.info("AUTH 用户取消: %s", user)
                return "DENY"

            # BLE auth_request 完成
            if auth_task in done:
                try:
                    success = auth_task.result()
                except Exception as e:
                    log.warning("AUTH_REQUEST 异常: %s", e)
                    success = False

                if success:
                    log.info("AUTH 通过设备认证: %s", user)
                    return "OK"

                # auth_request 失败，继续等待其他路径
                log.info("AUTH_REQUEST 失败，继续等待指纹匹配...")
                remaining = [pending_task, client_task, dialog_task]
                done2, _ = await asyncio.wait(
                    remaining,
                    timeout=PAM_TIMEOUT,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if self._pending_approved:
                    log.info("AUTH 通过主动指纹批准 (fallback): %s", user)
                    return "OK"

            log.warning("AUTH 超时: %s", user)
            return "TIMEOUT"

        finally:
            for t in [auth_task, pending_task, client_task, dialog_task]:
                t.cancel()
            self._close_auth_dialog(dialog_proc)
            self._pending_auth = None
            self._pending_approved = False

    # ── FP ────────────────────────────────────────────────────────

    async def _handle_fp(self, parts: list[str]) -> str:
        if len(parts) < 2:
            return "ERROR:INVALID_FORMAT"

        sub = parts[1]

        if sub == "LIST":
            return await self._handle_fp_list()
        elif sub == "ENROLL":
            return await self._handle_fp_enroll(parts)
        elif sub == "DELETE":
            return await self._handle_fp_delete(parts)
        elif sub == "STATUS":
            return self._handle_fp_status()
        elif sub == "LAST_MATCH":
            return self._handle_fp_last_match()
        else:
            return "ERROR:UNKNOWN_COMMAND"

    async def _handle_fp_list(self) -> str:
        if not self._ble.connected:
            return "ERROR:NOT_CONNECTED"
        return f"OK:{self._fp_bitmap}"

    async def _handle_fp_enroll(self, parts: list[str]) -> str:
        if len(parts) < 3:
            return "ERROR:INVALID_SLOT"
        try:
            slot = int(parts[2])
        except ValueError:
            return "ERROR:INVALID_SLOT"

        if slot < 0 or slot >= MAX_FINGERPRINT_SLOTS:
            return "ERROR:INVALID_SLOT"
        if not self._ble.connected:
            return "ERROR:NOT_CONNECTED"

        self.start_enrollment()
        try:
            status = await self._ble.enroll_start(slot)
            if status == STATUS_OK:
                return "OK:ENROLL_STARTED"
            self.end_enrollment()
            return f"ERROR:ENROLL_FAILED:0x{status:02x}"
        except Exception as e:
            self.end_enrollment()
            log.warning("FP:ENROLL 失败: %s", e)
            return "ERROR:ENROLL_FAILED"

    def _schedule_fp_bitmap_refresh(self) -> None:
        """安排异步刷新 fp_bitmap 缓存。"""
        try:
            asyncio.get_running_loop().create_task(self.refresh_fp_bitmap())
        except RuntimeError:
            pass

    async def _handle_fp_delete(self, parts: list[str]) -> str:
        if len(parts) < 3:
            return "ERROR:INVALID_SLOT"
        try:
            slot = int(parts[2])
        except ValueError:
            return "ERROR:INVALID_SLOT"

        if not self._ble.connected:
            return "ERROR:NOT_CONNECTED"

        try:
            status = await self._ble.delete_fp(slot)
            if status == STATUS_OK:
                await self.refresh_fp_bitmap()
                return "OK:DELETED"
            return f"ERROR:DELETE_FAILED:0x{status:02x}"
        except Exception as e:
            log.warning("FP:DELETE 失败: %s", e)
            return "ERROR:DELETE_FAILED"

    def _handle_fp_status(self) -> str:
        if not self._enroll_active:
            return "OK:IDLE"
        return f"OK:{self._enroll_event}:{self._enroll_current}:{self._enroll_total}"

    def _handle_fp_last_match(self) -> str:
        """返回并消费最近一次指纹匹配的 page_id，无匹配返回 -1。"""
        page_id = self._last_match_page_id
        self._last_match_page_id = -1
        return f"OK:{page_id}"

    # ── PAIR ──────────────────────────────────────────────────────

    async def _handle_pair(self, parts: list[str]) -> str:
        if len(parts) < 2:
            return "ERROR:INVALID_FORMAT"

        sub = parts[1]

        if sub == "STATUS":
            return self._handle_pair_status()
        elif sub == "START":
            return await self._handle_pair_start()
        elif sub == "RESET":
            return await self._handle_pair_reset()
        else:
            return "ERROR:UNKNOWN_COMMAND"

    def _handle_pair_status(self) -> str:
        from .security import PairingData

        pairing = PairingData.load()
        if pairing is not None:
            return f"OK:PAIRED:{pairing.device_id.hex()}"
        return "OK:UNPAIRED"

    async def _handle_pair_start(self) -> str:
        if not self._ble.connected:
            return "ERROR:NOT_CONNECTED"
        try:
            await self._ble.pair()
            return "OK:PAIRED"
        except Exception as e:
            log.warning("配对失败: %s", e, exc_info=True)
            return f"ERROR:PAIRING_FAILED:{e}"

    async def _handle_pair_reset(self) -> str:
        from .security import PairingData, compute_reset_hmac

        if self._ble.paired and self._ble.connected:
            try:
                hmac_val = compute_reset_hmac(self._ble.pairing.shared_key)
                await self._ble.factory_reset(hmac_val)
            except Exception as e:
                log.warning("工厂重置命令失败: %s", e)

        PairingData.delete()
        self._ble._pairing = None
        log.info("配对数据已清除")
        return "OK:RESET"

    # ── SET / GET ──────────────────────────────────────────────────

    def _handle_set(self, parts: list[str]) -> str:
        if len(parts) < 3:
            return "ERROR:INVALID_FORMAT"

        key = parts[1]
        val = parts[2]

        if key == "UNLOCK_SUDO":
            self._settings.unlock_sudo = val == "1"
            self._settings.save()
            log.info("设置 unlock_sudo=%s", self._settings.unlock_sudo)
            return "OK"
        elif key == "UNLOCK_POLKIT":
            self._settings.unlock_polkit = val == "1"
            self._settings.save()
            log.info("设置 unlock_polkit=%s", self._settings.unlock_polkit)
            return "OK"
        elif key == "UNLOCK_SCREEN":
            self._settings.unlock_screen = val == "1"
            self._settings.save()
            log.info("设置 unlock_screen=%s", self._settings.unlock_screen)
            return "OK"
        else:
            return "ERROR:UNKNOWN_KEY"

    def _handle_get_settings(self) -> str:
        s = self._settings
        return (
            f"OK:sudo={'1' if s.unlock_sudo else '0'}"
            f":polkit={'1' if s.unlock_polkit else '0'}"
            f":screen={'1' if s.unlock_screen else '0'}"
        )
