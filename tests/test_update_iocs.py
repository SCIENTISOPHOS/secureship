import json

import pytest

from scripts import update_iocs

RAW = [
    {
        "ioc": "45.9.148.108:443",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "malware_printable": "Cobalt Strike",
        "confidence_level": 100,
        "first_seen": "2026-11-04 10:00:00 UTC",
    },
    {
        "ioc": "10.0.0.5:80",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "malware_printable": "X",
        "confidence_level": 50,
    },
    {
        "ioc": "Evil-C2.ru",
        "ioc_type": "domain",
        "threat_type": "botnet_cc",
        "malware_printable": "AsyncRAT",
        "confidence_level": 75,
    },
    {
        "ioc": "drive.google.com",
        "ioc_type": "domain",
        "threat_type": "payload_delivery",
        "malware_printable": "X",
        "confidence_level": 50,
    },
    {
        "ioc": "A" * 64,
        "ioc_type": "sha256_hash",
        "threat_type": "payload",
        "malware_printable": "Emotet",
        "confidence_level": 90,
    },
    {"ioc": "https://evil.example/payload.exe", "ioc_type": "url", "threat_type": "payload"},
    {"ioc": "<script>", "ioc_type": "domain", "threat_type": "x"},
    {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "confidence_level": None},
]
ALLOW = {"google.com"}


def test_normalization_and_filtering():
    data = update_iocs.normalize_entries(RAW, ALLOW)
    assert set(data["ips"]) == {"45.9.148.108", "1.2.3.4"}  # IP privée écartée
    assert set(data["domains"]) == {"evil-c2.ru"}  # liste blanche + entrée malformée écartées
    assert set(data["hashes"]) == {"a" * 64}
    assert data["ips"]["45.9.148.108"]["threat"] == "Cobalt Strike (botnet_cc)"
    assert data["ips"]["1.2.3.4"]["confidence"] == 0


def test_build_feed_has_metadata():
    feed = update_iocs.build_feed(RAW, {}, ALLOW)
    assert feed["_meta"]["counts"] == {"ips": 2, "domains": 1, "hashes": 1}
    assert feed["_meta"]["source"].startswith("ThreatFox")


def test_empty_feed_is_rejected():
    with pytest.raises(RuntimeError, match="vide"):
        update_iocs.build_feed([], {}, ALLOW)


def test_feed_collapse_is_rejected():
    previous = {"ips": {f"1.1.1.{i}": {} for i in range(100)}}
    with pytest.raises(RuntimeError, match="Chute"):
        update_iocs.build_feed(RAW, previous, ALLOW)


def test_oversized_feed_is_rejected(monkeypatch):
    monkeypatch.setattr(update_iocs, "MAX_ENTRIES", 2)
    with pytest.raises(RuntimeError, match="gros"):
        update_iocs.build_feed(RAW, {}, ALLOW)


def test_allowlist_file_is_loaded():
    assert "google.com" in update_iocs.load_allowlist()


def test_main_without_key(monkeypatch, tmp_path):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    out = tmp_path / "feed.json"
    assert update_iocs.main(["--optional", "--output", str(out)]) == 0
    assert update_iocs.main(["--output", str(out)]) == 1
    assert not out.exists()


def test_main_with_mocked_api(monkeypatch, tmp_path):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"query_status": "ok", "data": RAW}).encode()

    def fake_urlopen(request, timeout):
        captured["headers"] = dict(request.header_items())
        return FakeResponse()

    monkeypatch.setattr(update_iocs.urllib.request, "urlopen", fake_urlopen)
    out = tmp_path / "feed.json"
    assert update_iocs.main(["--days", "1", "--output", str(out)]) == 0
    assert captured["headers"]["Auth-key"] == "test-key"
    assert json.loads(out.read_text())["_meta"]["counts"]["ips"] == 2


def test_api_error_status(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"query_status": "unknown_auth_key"}'

    monkeypatch.setattr(update_iocs.urllib.request, "urlopen", lambda r, timeout: FakeResponse())
    with pytest.raises(RuntimeError, match="unknown_auth_key"):
        update_iocs.fetch_threatfox("bad", 1)
