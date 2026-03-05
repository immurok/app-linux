"""immurok 用户设置 — 功能开关持久化"""

import json
import logging
import os
import tempfile

from .config import PAIRING_DIR, SETTINGS_FILE

log = logging.getLogger("immurok.settings")

_SETTINGS_PATH = os.path.join(os.path.expanduser(PAIRING_DIR), SETTINGS_FILE)


class Settings:
    """用户功能开关，持久化到 ~/.immurok/settings.json"""

    def __init__(
        self,
        *,
        unlock_sudo: bool = True,
        unlock_polkit: bool = True,
        unlock_screen: bool = True,
    ) -> None:
        self.unlock_sudo = unlock_sudo
        self.unlock_polkit = unlock_polkit
        self.unlock_screen = unlock_screen

    @classmethod
    def load(cls) -> "Settings":
        """读取设置文件，缺失或损坏时返回默认值。"""
        try:
            with open(_SETTINGS_PATH) as f:
                data = json.load(f)
            return cls(
                unlock_sudo=bool(data.get("unlock_sudo", True)),
                unlock_polkit=bool(data.get("unlock_polkit", True)),
                unlock_screen=bool(data.get("unlock_screen", True)),
            )
        except (FileNotFoundError, json.JSONDecodeError, TypeError):
            return cls()

    def save(self) -> None:
        """原子写入设置文件 (tmp + replace)。"""
        directory = os.path.expanduser(PAIRING_DIR)
        os.makedirs(directory, exist_ok=True)

        data = {
            "unlock_sudo": self.unlock_sudo,
            "unlock_polkit": self.unlock_polkit,
            "unlock_screen": self.unlock_screen,
        }
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            os.replace(tmp_path, _SETTINGS_PATH)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def toggle_sudo(self) -> bool:
        """切换 sudo 开关，保存并返回新值。"""
        self.unlock_sudo = not self.unlock_sudo
        self.save()
        return self.unlock_sudo

    def toggle_polkit(self) -> bool:
        """切换 polkit 开关，保存并返回新值。"""
        self.unlock_polkit = not self.unlock_polkit
        self.save()
        return self.unlock_polkit

    def toggle_screen(self) -> bool:
        """切换锁屏开关，保存并返回新值。"""
        self.unlock_screen = not self.unlock_screen
        self.save()
        return self.unlock_screen
