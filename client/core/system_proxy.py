"""Temporary Windows system proxy configuration with restoration support."""

import ctypes


class WindowsSystemProxy:
    REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self, registry=None):
        self._registry = registry
        self._original_values = None

    def _winreg(self):
        if self._registry is None:
            import winreg
            self._registry = winreg
        return self._registry

    def enable(self, port):
        winreg = self._winreg()
        access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REGISTRY_PATH, 0, access) as key:
            if self._original_values is None:
                self._original_values = {}
                for name in ("ProxyEnable", "ProxyServer"):
                    try:
                        self._original_values[name] = winreg.QueryValueEx(key, name)
                    except FileNotFoundError:
                        self._original_values[name] = None
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(
                key, "ProxyServer", 0, winreg.REG_SZ,
                f"http=127.0.0.1:{port};https=127.0.0.1:{port}",
            )
        self._notify_change()

    def restore(self):
        if self._original_values is None:
            return
        winreg = self._winreg()
        access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REGISTRY_PATH, 0, access) as key:
            for name, value in self._original_values.items():
                if value is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
                else:
                    value_data, value_type = value
                    winreg.SetValueEx(key, name, 0, value_type, value_data)
        self._original_values = None
        self._notify_change()

    @staticmethod
    def _notify_change():
        try:
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except (AttributeError, OSError):
            pass
