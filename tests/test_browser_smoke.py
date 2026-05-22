from ctf_runner import browser_smoke


def test_browser_smoke_module_importable():
    assert browser_smoke.playwright_import_status()["playwright_import"] in {True, False}


def test_browser_smoke_missing_playwright_is_graceful(monkeypatch):
    def missing_import(name: str):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(browser_smoke.importlib, "import_module", missing_import)
    result = browser_smoke.run_browser_smoke()
    assert result["ok"] is False
    assert result["playwright_import"] is False
    assert result["chromium_launch"] is False
    assert result["reason"] == "playwright_missing"
