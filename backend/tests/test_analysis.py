import pytest
from app.services.content_rules import brands_mentioned, claims_brand, content_signals
from app.services.ruleset import get_ruleset
from app.services.scorer import score
from app.services.sender_intel import classify_sender, sender_signals
from app.services.url_intel import extract_urls, parse_url, registered_domain, static_url_signals

rs = get_ruleset()


def codes(signals):
    return {s.code for s in signals}


# ---------- sender ----------
@pytest.mark.parametrize(
    "raw,kind,norm,suffix",
    [
        ("VM-HDFCBK", "header", "HDR:HDFCBK", None),
        ("JD-HDFCBK-S", "header", "HDR:HDFCBK", "S"),
        ("ax-icicib-t", "header", "HDR:ICICIB", "T"),
        ("HDFCBK", "header", "HDR:HDFCBK", None),
        ("9876543210", "mobile", "+919876543210", None),
        ("+91 98765 43210", "mobile", "+919876543210", None),
        ("09876543210", "mobile", "+919876543210", None),
        ("+923001234567", "intl", "+923001234567", None),
        ("0092 300 1234567", "intl", "+923001234567", None),
        ("56161", "short", "SHORT:56161", None),
    ],
)
def test_classify_sender(raw, kind, norm, suffix):
    info = classify_sender(raw)
    assert (info.kind, info.norm, info.suffix) == (kind, norm, suffix)


def test_known_header_has_no_signals():
    info = classify_sender("VM-HDFCBK-T")
    sigs, imp = sender_signals(info, rs, brand_claimed=True, content_codes=set())
    assert sigs == [] and imp is None


def test_header_impersonation_by_edit_distance_and_token():
    sigs, imp = sender_signals(classify_sender("VM-HDFCBN"), rs, brand_claimed=True, content_codes=set())
    assert "HEADER_IMPERSONATION" in codes(sigs) and imp == "HDFC"
    sigs, imp = sender_signals(classify_sender("AD-SBIKYC-P"), rs, brand_claimed=True, content_codes={"KYC_BLOCK_THREAT"})
    assert codes(sigs) == {"HEADER_IMPERSONATION", "HEADER_SUFFIX_MISMATCH"} and imp == "SBI"


def test_mobile_claiming_bank():
    sigs, _ = sender_signals(classify_sender("9876543210"), rs, brand_claimed=True, content_codes=set())
    assert "MOBILE_BRAND_CLAIM" in codes(sigs)
    sigs, _ = sender_signals(classify_sender("9876543210"), rs, brand_claimed=True, content_codes=set(), in_contacts=True)
    assert codes(sigs) == {"IN_CONTACTS"}


# ---------- content ----------
@pytest.mark.parametrize(
    "text,expected",
    [
        ("Dear customer your SBI YONO account will be blocked today. Update PAN immediately", {"KYC_BLOCK_THREAT", "URGENCY"}),
        ("Please share the OTP sent to your mobile to complete verification", {"OTP_REQUEST"}),
        ("Congratulations! You won Rs 25,00,000 in KBC lucky draw. Claim now", {"PRIZE_LOTTERY"}),
        ("Dear consumer your electricity will be disconnected tonight at 9.30 pm as bill not updated", {"ELECTRICITY_CUTOFF", "URGENCY"}),
        ("India Post: your parcel is on hold due to incomplete address", {"PARCEL_CUSTOMS"}),
        ("Part time job: like YouTube videos and earn Rs 3000 per day", {"JOB_LOAN_FEE"}),
        ("आपका खाता आज बंद हो जाएगा, तुरंत केवाईसी अपडेट करें", {"KYC_BLOCK_THREAT", "URGENCY"}),
        ("CBI has registered a case against you, digital arrest warrant issued", {"DIGITAL_ARREST"}),
        ("Scan this QR code and enter UPI PIN to receive your refund", {"UPI_COLLECT", "REFUND_CASHBACK"}),
        ("Hi, are we meeting for lunch tomorrow?", set()),
        ("Your OTP for login is 482913. Do not share it with anyone. -HDFC Bank", set()),
    ],
)
def test_content_categories(text, expected):
    assert codes(content_signals(text, rs)) == expected


def test_brand_claim_and_mentions():
    assert claims_brand("Dear customer, your HDFC account…", rs)
    assert not claims_brand("see you at 6", rs)
    assert brands_mentioned("Your SBI YONO points expire", rs) == ["SBI"]


# ---------- URLs ----------
def test_extract_urls():
    text = ("Update KYC at https://hdfcbank-kyc-update.co/login, or visit sbi-kyc.in/abc. "
            "Mail me at a@gmail.com. Pay: upi://pay?pa=fraud@ybl&am=1 and bit.ly/x1y2!")
    urls = extract_urls(text, rs)
    assert urls == ["https://hdfcbank-kyc-update.co/login", "upi://pay?pa=fraud@ybl&am=1", "sbi-kyc.in/abc", "bit.ly/x1y2"] or \
        set(urls) == {"https://hdfcbank-kyc-update.co/login", "sbi-kyc.in/abc", "upi://pay?pa=fraud@ybl&am=1", "bit.ly/x1y2"}
    assert not any("gmail" in u for u in urls)


@pytest.mark.parametrize(
    "host,reg",
    [("www.sbi.co.in", "sbi.co.in"), ("a.b.hdfcbank.com", "hdfcbank.com"), ("evil.github.io", "evil.github.io"),
     ("x.y.evil.co.in", "evil.co.in"), ("hdfc.bank.in", "hdfc.bank.in")],
)
def test_registered_domain(host, reg):
    assert registered_domain(host, rs) == reg


@pytest.mark.parametrize(
    "url,expected,imitates",
    [
        ("https://hdfcbank-kyc-update.co/login", {"LOOKALIKE_DOMAIN"}, "HDFC"),
        ("http://hdfcbank.com.secure-login.xyz/a", {"LOOKALIKE_DOMAIN", "NO_HTTPS", "RISKY_TLD"}, "HDFC"),
        ("https://icicibnk.com/", {"LOOKALIKE_DOMAIN"}, "ICICI"),
        ("https://paytmkyc.in", {"LOOKALIKE_DOMAIN"}, "PAYTM"),
        ("https://www.hdfcbank.com/personal", {"OFFICIAL_DOMAIN"}, None),
        ("https://netbanking.hdfc.bank.in/", {"OFFICIAL_DOMAIN"}, None),
        ("http://192.168.0.5/login", {"IP_OR_PUNYCODE_URL", "NO_HTTPS"}, None),
        ("https://xn--hdfcbnk-0ta.com/", {"IP_OR_PUNYCODE_URL"}, None),
        ("https://example.com/files/update.apk", {"DOWNLOAD_LINK"}, None),
        ("bit.ly/x1y2", {"SHORTENER"}, None),
        ("https://wa.me/919999999999", {"MESSAGING_LINK"}, None),
        ("https://www.kodak.com/", set(), None),
    ],
)
def test_static_url(url, expected, imitates):
    res = static_url_signals(url, rs)
    assert codes(res.signals) == expected
    assert res.imitates == imitates


def test_unicode_host_is_punycoded():
    p = parse_url("https://hdfcbаnk.com/", rs)  # Cyrillic 'а'
    assert p.host.startswith("xn--")
    assert "IP_OR_PUNYCODE_URL" in codes(static_url_signals("https://hdfcbаnk.com/", rs).signals)


# ---------- scoring ----------
def _scan(sender, text):
    info = classify_sender(sender)
    cs = content_signals(text, rs)
    ss, _ = sender_signals(info, rs, brand_claimed=claims_brand(text, rs), content_codes=codes(cs))
    us = [s for u in extract_urls(text, rs) for s in static_url_signals(u, rs).signals]
    return score(cs + ss + us, rs)


def test_classic_kyc_scam_is_scam():
    # Static analysis alone: 30 mobile+brand, 15 KYC, 30 lookalike = 75 → SCAM, below the auto-report bar.
    r = _scan("9876543210", "Dear HDFC customer, your account will be blocked today. Update KYC: https://hdfcbank-kyc-update.co/login")
    assert r.verdict == "SCAM" and r.score == 75 and not r.auto_report
    # Adding an OTP request crosses the auto-report threshold.
    r = _scan("9876543210", "Dear HDFC customer, account blocked. Update KYC at https://hdfcbank-kyc-update.co and share OTP")
    assert r.score >= 80 and r.auto_report


def test_genuine_otp_is_safe():
    r = _scan("VM-HDFCBK-T", "482913 is your OTP for txn of Rs 500 at Amazon. Do not share it with anyone. -HDFC Bank")
    assert r.verdict == "SAFE"


def test_official_link_is_safe():
    r = _scan("JD-ICICIB-S", "Your statement is ready. Login at https://www.icicibank.com to view.")
    assert r.verdict == "SAFE" and r.score == 0


def test_financial_lure_group_does_not_stack():
    r = _scan("+923001234567", "Congratulations you won a lottery! Claim your cashback refund now, loan approved instantly")
    lure = [s for s in r.signals if s.group == "FINANCIAL_LURE"]
    assert len(lure) >= 2
    # INTL 10 + one lure 15 = 25, not 10 + 45
    assert r.score == 25
