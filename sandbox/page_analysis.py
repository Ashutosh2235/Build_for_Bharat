"""Pure helpers for the sandbox (no Playwright import, unit-testable)."""
from __future__ import annotations

import ipaddress
import re

# Runs inside the page. Returns plain JSON describing forms/inputs and page hints.
EXTRACT_JS = r"""
() => {
  const txt = (el) => ((el.getAttribute('name')||'') + ' ' + (el.id||'') + ' ' +
                       (el.getAttribute('placeholder')||'') + ' ' + (el.getAttribute('aria-label')||'') + ' ' +
                       (el.getAttribute('autocomplete')||'')).toLowerCase();
  const forms = [];
  const inputs = Array.from(document.querySelectorAll('input, select, textarea'));
  const seen = new Set();
  for (const f of Array.from(document.forms)) {
    const fields = Array.from(f.querySelectorAll('input, select, textarea'));
    fields.forEach(x => seen.add(x));
    forms.push({action: f.getAttribute('action') || '', method: (f.method||'get').toLowerCase(),
                fields: fields.map(x => ({type: (x.type||'').toLowerCase(), hint: txt(x)}))});
  }
  const loose = inputs.filter(x => !seen.has(x));
  if (loose.length) forms.push({action: '', method: 'js', fields: loose.map(x => ({type: (x.type||'').toLowerCase(), hint: txt(x)}))});
  const meta = document.querySelector('meta[http-equiv="refresh" i]');
  return {
    title: document.title || '',
    text: (document.body ? document.body.innerText : '').slice(0, 4000),
    forms,
    iframes: document.querySelectorAll('iframe').length,
    meta_refresh: meta ? (meta.getAttribute('content') || '') : '',
    script_hosts: Array.from(document.scripts).map(s => { try { return new URL(s.src).host } catch(e) { return '' } }).filter(Boolean),
  };
}
"""

OTP_HINT = re.compile(r"\b(otp|one.?time|verification code|mpin|upi.?pin|pin)\b")
CARD_HINT = re.compile(r"\b(card|cvv|cvc|expiry|exp.?date|cc-number|cc-csc|debit|credit)\b")
ID_HINT = re.compile(r"\b(aadhaa?r|pan|account.?(no|number)|ifsc|dob|date of birth|mother)\b")
PASSWORD_HINT = re.compile(r"\b(pass(word|code)?|pwd|login pin|net.?banking)\b")
DOWNLOAD_TYPES = ("application/vnd.android.package-archive", "application/x-msdownload", "application/java-archive",
                  "application/zip", "application/x-rar-compressed", "application/octet-stream")
DOWNLOAD_EXT = re.compile(r"\.(apk|apks|xapk|exe|msi|jar|zip|rar|7z|bat|scr)(\?|$)", re.I)


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
                or a.is_unspecified)


def classify_forms(forms: list[dict], page_host: str) -> list[dict]:
    """Summarise forms → [{action_host, password, otp, card, identity, fields}]."""
    from urllib.parse import urlsplit
    out = []
    for f in forms:
        fields = f.get("fields", [])
        if not fields:
            continue
        hints = " ".join(x.get("hint", "") for x in fields)
        types = {x.get("type", "") for x in fields}
        action = f.get("action") or ""
        action_host = urlsplit(action).hostname if "://" in action else page_host
        out.append({
            "action_host": action_host or page_host,
            "password": "password" in types or bool(PASSWORD_HINT.search(hints)),
            "otp": bool(OTP_HINT.search(hints)),
            "card": bool(CARD_HINT.search(hints)),
            "identity": bool(ID_HINT.search(hints)),
            "fields": len([x for x in fields if x.get("type") not in ("hidden", "submit", "button")]),
        })
    return [f for f in out if f["fields"] > 0]


def brand_hits(text: str, title: str, brand_words: dict[str, list[str]]) -> list[str]:
    blob = f"{title} {text}".lower()
    return sorted(b for b, words in brand_words.items() if any(re.search(rf"\b{re.escape(w)}\b", blob) for w in words))


def is_download_response(content_type: str, url: str, disposition: str = "") -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct in DOWNLOAD_TYPES and ct != "application/octet-stream":
        return True
    if "attachment" in (disposition or "").lower():
        return True
    return bool(DOWNLOAD_EXT.search(url)) and ct in DOWNLOAD_TYPES
