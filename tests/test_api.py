import pytest
from fastapi.testclient import TestClient

from app import ioc_store
from app.main import app

client = TestClient(app)

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_security_headers_present():
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" in r.headers


def test_docs_not_blocked_by_csp():
    r = client.get("/docs")
    assert r.status_code == 200
    assert "Content-Security-Policy" not in r.headers


def test_stats():
    body = client.get("/api/v1/stats").json()
    assert body["ips"] >= 3 and body["domains"] >= 2 and body["hashes"] >= 2
    assert "generated_at" in body["feed"]


def test_feed_is_merged_with_demo_data(monkeypatch, tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(
        '{"ips": {"45.9.148.108": {"threat": "Cobalt Strike"}}, "domains": {}, "hashes": {},'
        ' "_meta": {"source": "ThreatFox", "generated_at": "2026-11-05T05:00:00Z"}}'
    )
    monkeypatch.setattr(ioc_store, "FEED_FILE", feed)
    ioc_store.load_iocs.cache_clear()
    try:
        assert client.get("/api/v1/check/ip/45.9.148.108").json()["malicious"] is True
        assert client.get("/api/v1/check/ip/192.0.2.10").json()["malicious"] is True
        assert client.get("/api/v1/stats").json()["feed"]["source"] == "ThreatFox"
    finally:
        ioc_store.load_iocs.cache_clear()


def test_malicious_ip():
    body = client.get("/api/v1/check/ip/192.0.2.10").json()
    assert body["malicious"] is True
    assert body["details"]["threat"] == "C2 server"


def test_clean_private_ip():
    body = client.get("/api/v1/check/ip/10.0.0.1").json()
    assert body["malicious"] is False
    assert body["private"] is True


def test_documentation_range_is_not_local():
    assert client.get("/api/v1/check/ip/192.0.2.10").json()["private"] is False


def test_ipv6():
    body = client.get("/api/v1/check/ip/2001:db8::1").json()
    assert body["type"] == "ipv6"


@pytest.mark.parametrize("bad", ["999.1.1.1", "abc", "1.2.3"])
def test_invalid_ip(bad):
    r = client.get(f"/api/v1/check/ip/{bad}")
    assert r.status_code == 422


def test_malicious_subdomain():
    body = client.get("/api/v1/check/domain/login.MALICIOUS.example").json()
    assert body["malicious"] is True
    assert body["matched"] == "malicious.example"


def test_clean_domain():
    assert client.get("/api/v1/check/domain/utt.fr").json()["malicious"] is False


@pytest.mark.parametrize("bad", ["-bad.com", "no_tld", "<img src=x onerror=alert(1)>"])
def test_invalid_domain_is_rejected_without_reflection(bad):
    r = client.get(f"/api/v1/check/domain/{bad}")
    assert r.status_code == 422
    assert "<img" not in r.text


def test_hash_sha256_case_insensitive():
    body = client.get(f"/api/v1/check/hash/{EICAR_SHA256.upper()}").json()
    assert body["malicious"] is True
    assert body["type"] == "sha256"


def test_clean_sha1():
    body = client.get("/api/v1/check/hash/" + "a" * 40).json()
    assert body == {"indicator": "a" * 40, "type": "sha1", "malicious": False, "details": None}


@pytest.mark.parametrize("bad", ["123", "z" * 32])
def test_invalid_hash(bad):
    assert client.get(f"/api/v1/check/hash/{bad}").status_code == 422


def test_too_long_input_rejected():
    assert client.get("/api/v1/check/hash/" + "a" * 65).status_code == 422


# --- Interface web et détection automatique ---


def test_home_page_served_with_strict_csp():
    r = client.get("/")
    assert r.status_code == 200
    assert "SecureShip" in r.text
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp


def test_static_assets_served():
    for path in ("/static/app.js", "/static/style.css", "/static/flag.svg"):
        r = client.get(path)
        assert r.status_code == 200
        assert r.headers["Cache-Control"].startswith("public")


@pytest.mark.parametrize(
    ("value", "expected_type", "malicious"),
    [
        ("192.0.2.10", "ipv4", True),
        ("203.0.113.66:443", "ipv4", True),
        ("hxxps://login.phishing-login[.]example/compte", "domain", True),
        ("https://[2001:db8::1]:8443/x", "ipv6", False),
        ("malicious[.]example", "domain", True),
        (EICAR_SHA256, "sha256", True),
        ("  utt.fr  ", "domain", False),
    ],
)
def test_check_auto_detection(value, expected_type, malicious):
    body = client.get("/api/v1/check", params={"q": value}).json()
    assert body["type"] == expected_type
    assert body["malicious"] is malicious


def test_check_url_marks_extraction():
    body = client.get("/api/v1/check", params={"q": "http://192.0.2.10/payload"}).json()
    assert body["extracted_from"] == "url"


@pytest.mark.parametrize("bad", ["", "   ", "pas un indicateur", "http://", "a" * 2049])
def test_check_rejects_garbage(bad):
    r = client.get("/api/v1/check", params={"q": bad})
    assert r.status_code == 422


def test_bulk_mixed_results():
    payload = {"indicators": ["192.0.2.10", "utt.fr", "<img src=x>", "", EICAR_SHA256]}
    body = client.post("/api/v1/check/bulk", json=payload).json()
    assert body["count"] == 4
    assert body["malicious"] == 2
    invalid = body["results"][2]
    assert invalid["type"] == "invalid" and "error" in invalid


def test_bulk_limits():
    assert client.post("/api/v1/check/bulk", json={"indicators": []}).status_code == 422
    too_many = {"indicators": ["utt.fr"] * 101}
    assert client.post("/api/v1/check/bulk", json=too_many).status_code == 422
