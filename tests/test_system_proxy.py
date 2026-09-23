from client.core.system_proxy import WindowsSystemProxy


class _FakeRegistry:
    HKEY_CURRENT_USER = object()
    KEY_QUERY_VALUE = 1
    KEY_SET_VALUE = 2
    REG_DWORD = 4
    REG_SZ = 1

    def __init__(self, values=None):
        self.values = dict(values or {})

    def OpenKey(self, *_args):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def QueryValueEx(self, _key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name]

    def SetValueEx(self, _key, name, _reserved, value_type, value):
        self.values[name] = (value, value_type)

    def DeleteValue(self, _key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


def test_system_proxy_restores_existing_settings():
    original = {
        "ProxyEnable": (1, _FakeRegistry.REG_DWORD),
        "ProxyServer": ("proxy.corp:8080", _FakeRegistry.REG_SZ),
    }
    registry = _FakeRegistry(original)
    proxy = WindowsSystemProxy(registry)

    proxy.enable(1080)
    assert registry.values["ProxyEnable"] == (1, _FakeRegistry.REG_DWORD)
    assert registry.values["ProxyServer"] == (
        "http=127.0.0.1:1080;https=127.0.0.1:1080", _FakeRegistry.REG_SZ)

    proxy.restore()
    assert registry.values == original


def test_system_proxy_removes_values_that_were_initially_absent():
    registry = _FakeRegistry()
    proxy = WindowsSystemProxy(registry)

    proxy.enable(1080)
    proxy.restore()

    assert registry.values == {}
