from ctf_runner.callback_smoke import LOCAL_CALLBACK_HOST, run_callback_smoke


def test_local_callback_smoke_ok():
    result = run_callback_smoke()
    assert result["ok"] is True
    assert result["host"] == LOCAL_CALLBACK_HOST
    assert result["host"] != "0.0.0.0"
    assert result["hit_count"] == 1
    assert isinstance(result["port"], int)


def test_local_callback_smoke_uses_loopback():
    result = run_callback_smoke()
    assert result["host"] == "127.0.0.1"
