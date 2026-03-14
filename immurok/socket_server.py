"""
immurok Unix Socket 服务器 — PAM / CLI 通信

协议与 macOS PAMSocketServer.swift 完全一致。
文本协议，PAM 模块发送不带结尾符的原始文本。
"""

import asyncio
import base64
import logging
import os
import subprocess
import time
from typing import TYPE_CHECKING

from .config import (
    ENROLL_COMPLETE,
    IMAGE_B_BLOCKS,
    MAX_FINGERPRINT_SLOTS,
    OTA_ERASE_TIMEOUT,
    OTA_SESSION_TIMEOUT,
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

        # 指纹 bitmap 缓存
        self._fp_bitmap: int = 0

        # 最近一次指纹匹配
        self._last_match_page_id: int = -1

        # 电池电量 (0-100%, None = 未知)
        self._battery_level: int | None = None

    @property
    def settings(self) -> Settings:
        return self._settings

    # ── 认证弹窗 ─────────────────────────────────────────────────

    @staticmethod
    def _show_auth_dialog() -> subprocess.Popen | None:
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

    # ── 指纹 bitmap 缓存 ─────────────────────────────────────────

    async def refresh_device_status(self) -> None:
        """刷新设备状态（指纹位图 + 配对状态 + 电池电量）"""
        if not self._ble.connected:
            return
        try:
            bitmap, _, battery = await self._ble.get_status()
            self._fp_bitmap = bitmap
            self._battery_level = battery
            log.debug("设备状态已刷新: bitmap=0x%02x, battery=%s",
                      bitmap, f"{battery}%" if battery is not None else "n/a")
        except Exception as e:
            log.warning("刷新设备状态失败: %s", e)

    async def refresh_fp_bitmap(self) -> None:
        """刷新指纹位图（向后兼容，内部调用 refresh_device_status）"""
        await self.refresh_device_status()

    # ── 指纹匹配通知 ─────────────────────────────────────────────

    def notify_fp_match(self, page_id: int) -> None:
        self._last_match_page_id = page_id

    # ── 服务器生命周期 ───────────────────────────────────────────

    async def start(self) -> None:
        sock_path = os.path.expanduser(SOCKET_PATH)
        os.makedirs(os.path.dirname(sock_path), exist_ok=True)
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=sock_path
        )
        os.chmod(sock_path, 0o600)
        self._sock_path = sock_path
        log.info("Socket 服务器已启动: %s", sock_path)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        sock_path = getattr(self, "_sock_path", os.path.expanduser(SOCKET_PATH))
        try:
            os.unlink(sock_path)
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

            if cmd == "OTA":
                await self._handle_ota_session(reader, writer, parts)
                return
            elif cmd == "STATUS":
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
            elif cmd == "GET" and len(parts) >= 2 and parts[1] == "INFO":
                response = self._handle_get_info()
            else:
                response = "ERROR:UNKNOWN_COMMAND"

            writer.write(response.encode("utf-8"))
            await writer.drain()
        except asyncio.TimeoutError:
            log.debug("客户端读取超时")
        except Exception:
            log.exception("处理客户端请求异常")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    # ── STATUS ───────────────────────────────────────────────────

    def _handle_status(self) -> str:
        connected = self._ble.connected
        device_name = "immurok" if connected else ""
        batt = self._battery_level if self._battery_level is not None else -1
        return f"STATUS:{'1' if connected else '0'}:{device_name}:{batt}"

    # ── AUTH ──────────────────────────────────────────────────────

    def _is_service_allowed(self, service: str) -> bool:
        s = service.lower()
        if "gdm" in s or "login" in s:
            return self._settings.unlock_screen
        if s == "polkit-1":
            return self._settings.unlock_polkit
        if s == "sudo":
            return self._settings.unlock_sudo
        return self._settings.unlock_sudo

    async def _watch_client(self, reader: asyncio.StreamReader) -> None:
        try:
            await reader.read(1)
        except Exception:
            pass

    async def _watch_dialog(self, proc: subprocess.Popen | None) -> None:
        if proc is None:
            await asyncio.Event().wait()
            return
        while proc.poll() is None:
            await asyncio.sleep(0.2)

    async def _handle_auth(
        self, parts: list[str], reader: asyncio.StreamReader
    ) -> str:
        user = parts[1] if len(parts) >= 2 else "unknown"
        service = parts[2] if len(parts) >= 3 else "unknown"
        log.info("AUTH 请求: user=%s, service=%s", user, service)

        if not self._is_service_allowed(service):
            log.info("AUTH 拒绝 (开关已关闭): service=%s", service)
            return "DENY"

        if self.consume_pre_auth():
            log.info("AUTH 通过预授权批准: %s", user)
            return "OK"

        if not self._ble.connected:
            log.warning("AUTH 失败: 设备未连接")
            return "DENY"

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

            if self._pending_approved:
                log.info("AUTH 通过主动指纹批准: %s", user)
                return "OK"

            if client_task in done:
                log.info("AUTH 客户端已断开: %s", user)
                return "DENY"

            if dialog_task in done:
                log.info("AUTH 用户取消: %s", user)
                return "DENY"

            if auth_task in done:
                try:
                    success = auth_task.result()
                except Exception as e:
                    log.warning("AUTH_REQUEST 异常: %s", e)
                    success = False

                if success:
                    log.info("AUTH 通过设备认证: %s", user)
                    return "OK"

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
        elif sub == "VERIFY":
            return await self._handle_fp_verify()
        else:
            return "ERROR:UNKNOWN_COMMAND"

    async def _handle_fp_list(self) -> str:
        if not self._ble.connected:
            return "ERROR:NOT_CONNECTED"
        try:
            self._fp_bitmap = await self._ble.fp_list()
        except Exception:
            pass
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
            success, error = await self._ble.enroll_start(slot)
            if success:
                return "OK:ENROLL_STARTED"
            self.end_enrollment()
            return f"ERROR:ENROLL_FAILED:0x{error:02x}" if error else "ERROR:ENROLL_FAILED"
        except Exception as e:
            self.end_enrollment()
            log.warning("FP:ENROLL 失败: %s", e)
            return "ERROR:ENROLL_FAILED"

    def _schedule_fp_bitmap_refresh(self) -> None:
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
            success, error = await self._ble.delete_fp(slot)
            if success:
                await self.refresh_fp_bitmap()
                return "OK:DELETED"
            return f"ERROR:DELETE_FAILED:0x{error:02x}" if error else "ERROR:DELETE_FAILED"
        except Exception as e:
            log.warning("FP:DELETE 失败: %s", e)
            return "ERROR:DELETE_FAILED"

    def _handle_fp_status(self) -> str:
        if not self._enroll_active:
            return "OK:IDLE"
        return f"OK:{self._enroll_event}:{self._enroll_current}:{self._enroll_total}"

    def _handle_fp_last_match(self) -> str:
        page_id = self._last_match_page_id
        self._last_match_page_id = -1
        return f"OK:{page_id}"

    async def _handle_fp_verify(self) -> str:
        """发送 AUTH_REQUEST 验证指纹（用于测试）"""
        if not self._ble.connected:
            return "ERROR:NOT_CONNECTED"
        if not self._ble.paired:
            return "ERROR:NOT_PAIRED"
        try:
            success = await self._ble.auth_request()
            return "OK:MATCH" if success else "OK:NO_MATCH"
        except Exception as e:
            log.warning("FP:VERIFY 失败: %s", e)
            return f"ERROR:VERIFY_FAILED:{e}"

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
            return "OK:PAIRED"
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
                await self._ble.factory_reset()
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

    def _handle_get_info(self) -> str:
        ble = self._ble
        parts = ["OK"]
        parts.append(f"fw={ble._firmware_version or '-'}")
        parts.append(f"model=IK-1")
        parts.append(f"addr={ble._device_address or '-'}")
        parts.append(f"interval={ble._conn_interval}")
        parts.append(f"latency={ble._conn_latency}")
        parts.append(f"timeout={ble._conn_timeout}")
        batt = self._battery_level
        parts.append(f"battery={batt if batt is not None else -1}")
        return ":".join(parts)

    # ── OTA ────────────────────────────────────────────────────────

    async def _handle_ota_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_parts: list[str],
    ) -> None:
        """OTA 升级会话（持久连接，\n 分隔协议）"""
        log.info("OTA 会话开始")

        async def send_line(line: str) -> None:
            writer.write((line + "\n").encode())
            await writer.drain()

        # 处理第一个命令
        response = await self._process_ota_command(first_parts)
        await send_line(response)

        if len(first_parts) >= 2 and first_parts[1] == "END":
            log.info("OTA 会话结束")
            return

        # 持久连接：逐行读取后续命令
        while True:
            try:
                line_data = await asyncio.wait_for(
                    reader.readline(), timeout=OTA_SESSION_TIMEOUT
                )
            except asyncio.TimeoutError:
                log.warning("OTA 会话超时")
                break

            if not line_data:
                break

            request = line_data.decode().strip()
            if not request:
                continue

            parts = request.split(":")
            response = await self._process_ota_command(parts)
            await send_line(response)

            if len(parts) >= 2 and parts[1] == "END":
                break

        log.info("OTA 会话结束")

    async def _process_ota_command(self, parts: list[str]) -> str:
        """处理单个 OTA 命令，返回响应字符串"""
        if len(parts) < 2:
            return "ERROR:INVALID_FORMAT"

        sub = parts[1]
        if sub != "WRITE":
            log.info("OTA 命令: %s", sub)

        if sub == "VERSION":
            ver = self._ble._firmware_version or "unknown"
            return f"OK:{ver}"
        elif sub == "INFO":
            return await self._handle_ota_info()
        elif sub == "ERASE":
            return await self._handle_ota_erase()
        elif sub == "HEADER":
            return await self._handle_ota_header(parts)
        elif sub == "WRITE":
            return await self._handle_ota_write(parts)
        elif sub == "VERIFY":
            return await self._handle_ota_verify(parts)
        elif sub == "END":
            return await self._handle_ota_end()
        else:
            return "ERROR:UNKNOWN_OTA_CMD"

    async def _handle_ota_info(self) -> str:
        if not self._ble.ota_available:
            return "ERROR:OTA_NOT_AVAILABLE"

        # CMD_IAP_INFO: [0x84, 0x02, 0x00, 0x00]
        cmd = bytes([0x84, 0x02, 0x00, 0x00])
        resp = await self._ble.ota_write_and_read(cmd, timeout=5.0)

        if resp is None or len(resp) < 9:
            return "ERROR:NO_RESPONSE"

        image_flag = resp[0]
        image_size = (
            resp[1] | (resp[2] << 8) | (resp[3] << 16) | (resp[4] << 24)
        )
        block_size = resp[5] | (resp[6] << 8)
        chip_id = resp[7] | (resp[8] << 8)

        reply = (
            f"OK:{image_flag:02x}:{image_size:08x}"
            f":{block_size:04x}:{chip_id:04x}"
        )
        log.info("OTA INFO: %s", reply)
        return reply

    async def _handle_ota_erase(self) -> str:
        if not self._ble.ota_available:
            return "ERROR:OTA_NOT_AVAILABLE"

        # CMD_IAP_ERASE: [0x81, 0x04, addr_lo, addr_hi, blocks_lo, blocks_hi]
        cmd = bytes([
            0x81, 0x04,
            0x00, 0x00,
            IMAGE_B_BLOCKS & 0xFF, (IMAGE_B_BLOCKS >> 8) & 0xFF,
        ])
        resp = await self._ble.ota_write_and_read(
            cmd, timeout=OTA_ERASE_TIMEOUT
        )

        if resp is None or len(resp) < 1:
            return "ERROR:ERASE_TIMEOUT"

        if resp[0] == 0x00:
            log.info("OTA ERASE 成功")
            return "OK"

        log.warning("OTA ERASE 失败: 0x%02x", resp[0])
        return f"ERROR:ERASE_FAILED:{resp[0]:02x}"

    async def _handle_ota_header(self, parts: list[str]) -> str:
        if len(parts) < 3:
            return "ERROR:INVALID_FORMAT"
        if not self._ble.ota_available:
            return "ERROR:OTA_NOT_AVAILABLE"

        try:
            header_data = base64.b64decode(parts[2])
        except Exception:
            return "ERROR:INVALID_DATA"

        if len(header_data) != 96:
            return "ERROR:INVALID_HEADER_SIZE"

        # CMD_IAP_HEADER: [0x85, 0x60, header_data...]
        cmd = bytes([0x85, len(header_data)]) + header_data
        resp = await self._ble.ota_write_and_read(cmd, timeout=5.0)

        if resp is None or len(resp) < 1:
            return "ERROR:HEADER_TIMEOUT"

        if resp[0] == 0x00:
            log.info("OTA HEADER 已接受")
            return "OK"

        log.warning("OTA HEADER 被拒绝: 0x%02x", resp[0])
        return f"ERROR:HEADER_REJECTED:{resp[0]:02x}"

    async def _handle_ota_write(self, parts: list[str]) -> str:
        if len(parts) < 4:
            return "ERROR:INVALID_FORMAT"
        if not self._ble.ota_available:
            return "ERROR:OTA_NOT_AVAILABLE"

        try:
            offset = int(parts[2], 16)
        except ValueError:
            return "ERROR:INVALID_OFFSET"

        try:
            data = base64.b64decode(parts[3])
        except Exception:
            return "ERROR:INVALID_DATA"

        # 地址编码: encoded_addr = offset / 16
        encoded_addr = offset // 16

        # CMD_IAP_PROM: [0x80, data_len, addr_lo, addr_hi, data...]
        cmd = bytes([
            0x80,
            len(data),
            encoded_addr & 0xFF,
            (encoded_addr >> 8) & 0xFF,
        ]) + data

        ok = await self._ble.ota_write(cmd)
        return "OK" if ok else "ERROR:WRITE_FAILED"

    async def _handle_ota_verify(self, parts: list[str]) -> str:
        if len(parts) < 4:
            return "ERROR:INVALID_FORMAT"
        if not self._ble.ota_available:
            return "ERROR:OTA_NOT_AVAILABLE"

        try:
            offset = int(parts[2], 16)
        except ValueError:
            return "ERROR:INVALID_OFFSET"

        try:
            data = base64.b64decode(parts[3])
        except Exception:
            return "ERROR:INVALID_DATA"

        encoded_addr = offset // 16
        # CMD_IAP_VERIFY: [0x82, data_len, addr_lo, addr_hi, data...]
        cmd = bytes([
            0x82,
            len(data),
            encoded_addr & 0xFF,
            (encoded_addr >> 8) & 0xFF,
        ]) + data

        resp = await self._ble.ota_write_and_read(cmd, timeout=5.0)

        if resp is None or len(resp) < 1:
            return "ERROR:VERIFY_TIMEOUT"

        if resp[0] == 0x00:
            return "OK"

        return f"ERROR:VERIFY_FAILED:{resp[0]:02x}"

    async def _handle_ota_end(self) -> str:
        if not self._ble.ota_available:
            return "ERROR:OTA_NOT_AVAILABLE"

        # CMD_IAP_END: [0x83, 0x02, 0x00, 0x00]
        cmd = bytes([0x83, 0x02, 0x00, 0x00])
        try:
            resp = await self._ble.ota_write_and_read(cmd, timeout=5.0)
        except Exception:
            # 设备验证通过后立即重启，BLE 断连导致写入异常 — 视为成功
            log.info("OTA END: 设备已重启 (连接断开)")
            return "OK"

        if resp is not None and len(resp) >= 1:
            log.info("OTA END 响应: %s", resp.hex())
            if resp[0] == 0xF1:
                return "ERROR:SHA256_MISMATCH"
            if resp[0] == 0xF2:
                return "ERROR:HMAC_MISMATCH"

        # 无响应或成功（设备已重启）
        return "OK"
