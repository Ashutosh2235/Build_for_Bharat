from page_analysis import brand_hits, classify_forms, is_download_response, is_public_ip


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    for ip in ("127.0.0.1", "10.1.2.3", "172.20.0.5", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "nonsense"):
        assert not is_public_ip(ip), ip


def test_classify_forms_detects_credential_phishing():
    forms = [
        {"action": "https://collect.evil.top/p.php", "fields": [
            {"type": "text", "hint": "userid user id"}, {"type": "password", "hint": "password"},
            {"type": "hidden", "hint": "token"}]},
        {"action": "", "fields": [{"type": "tel", "hint": "otp enter otp"}]},
        {"action": "/pay", "fields": [{"type": "text", "hint": "card number cc-number"}, {"type": "text", "hint": "cvv"}]},
        {"action": "", "fields": [{"type": "submit", "hint": ""}]},
    ]
    out = classify_forms(forms, "bank-kyc.example.net")
    assert out[0] == {"action_host": "collect.evil.top", "password": True, "otp": False, "card": False,
                      "identity": False, "fields": 2}
    assert out[1]["otp"] and out[1]["action_host"] == "bank-kyc.example.net"
    assert out[2]["card"]
    assert len(out) == 3


def test_brand_hits():
    assert brand_hits("Welcome to Bharat Demo Bank net banking", "Login", {"DEMOBANK": ["bharat demo bank"],
                                                                             "SBI": ["sbi"]}) == ["DEMOBANK"]


def test_download_detection():
    assert is_download_response("application/vnd.android.package-archive", "https://x/a")
    assert is_download_response("text/html", "https://x/a", "attachment; filename=kyc.apk")
    assert is_download_response("application/octet-stream", "https://x/update.apk")
    assert not is_download_response("application/octet-stream", "https://x/font.woff2")
    assert not is_download_response("text/html", "https://x/a.apk.html")
