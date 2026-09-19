import base64

import pytest

from phishguard_api.sandbox_manager import BrowserSandboxError, _capture_with_isolated_browser


def test_browser_capture_uses_hardened_isolated_container(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Containers:
        def run(self, image, **kwargs):
            captured["image"] = image
            captured.update(kwargs)
            class Container:
                def wait(self, timeout):
                    captured["timeout"] = timeout
                    return {"StatusCode": 0}
                def logs(self, **kwargs):
                    return ('{"html": "' + base64.b64encode(b"<html>ok</html>").decode() + '", "screenshot": "' + base64.b64encode(b"png").decode() + '"}').encode()
                def remove(self, force):
                    captured["removed"] = force
            return Container()

    class Client:
        containers = Containers()

    monkeypatch.setattr("phishguard_api.sandbox_manager.docker_client", Client())
    html, screenshot = _capture_with_isolated_browser("https://example.test/")
    assert html == b"<html>ok</html>"
    assert screenshot == b"png"
    assert captured["network"] == "phishguard_browser_internal"
    assert captured["read_only"] is True
    assert captured["cap_drop"] == ["ALL"]
    assert captured["pids_limit"] == 256
    assert captured["detach"] is True
    assert captured["removed"] is True
    assert captured["environment"]["HTTPS_PROXY"] == "http://egress-proxy:3128"


def test_browser_capture_rejects_empty_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    class Containers:
        def run(self, *args, **kwargs):
            class Container:
                def wait(self, timeout): return {"StatusCode": 0}
                def logs(self, **kwargs): return b'{"html": "", "screenshot": ""}'
                def remove(self, force): pass
            return Container()

    class Client:
        containers = Containers()

    monkeypatch.setattr("phishguard_api.sandbox_manager.docker_client", Client())
    with pytest.raises(BrowserSandboxError, match="empty"):
        _capture_with_isolated_browser("https://example.test/")
