"""Chargement et interrogation de la base d'indicateurs de compromission (IoC).

Deux sources sont fusionnées :
- data/iocs.json      : jeu de démonstration versionné dans Git (toujours présent) ;
- data/iocs_feed.json : flux Threat Intelligence réel, régénéré chaque jour par la
                        pipeline (scripts/update_iocs.py) et embarqué dans l'image.
"""

import ipaddress
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

DATA_DIR = Path(__file__).parent / "data"
DEMO_FILE = DATA_DIR / "iocs.json"
FEED_FILE = Path(os.getenv("IOC_FEED_FILE", DATA_DIR / "iocs_feed.json"))
KINDS = ("ips", "domains", "hashes")

# Nom de domaine : labels de 1 à 63 caractères, TLD alphabétique, 253 caractères max.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"^[a-f0-9]+$")


# Réseaux réellement internes (RFC 1918, CGNAT, boucle locale, lien local, ULA IPv6).
# ipaddress.is_private inclut aussi les plages de documentation, d'où cette liste explicite.
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


class InvalidIndicatorError(ValueError):
    """Indicateur au format invalide (entrée utilisateur ou flux rejeté)."""


# --- Normalisation / validation (partagée par l'API et le script de mise à jour) ---


def normalize_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise InvalidIndicatorError("Adresse IP invalide") from exc


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise InvalidIndicatorError("Nom de domaine invalide")
    return domain


def normalize_hash(value: str) -> tuple[str, str]:
    digest = value.strip().lower()
    algo = HASH_LENGTHS.get(len(digest))
    if algo is None or not HEX_RE.match(digest):
        raise InvalidIndicatorError("Hash invalide (MD5, SHA-1 ou SHA-256 attendu)")
    return digest, algo


# --- Chargement ---


def _read(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_iocs() -> dict:
    demo, feed = _read(DEMO_FILE), _read(FEED_FILE)
    # Le jeu de démonstration est prioritaire (valeurs stables pour les tests et la démo).
    return {kind: {**feed.get(kind, {}), **demo.get(kind, {})} for kind in KINDS}


def feed_metadata() -> dict:
    meta = _read(FEED_FILE).get("_meta")
    return meta or {"source": None, "generated_at": None}


# --- Requêtes ---


def check_ip(value: str) -> dict:
    ip = normalize_ip(value)
    normalized = str(ip)
    match = load_iocs()["ips"].get(normalized)
    return {
        "indicator": normalized,
        "type": f"ipv{ip.version}",
        "malicious": match is not None,
        "private": any(ip in net for net in LOCAL_NETWORKS if net.version == ip.version),
        "details": match,
    }


def check_domain(value: str) -> dict:
    domain = normalize_domain(value)
    store = load_iocs()["domains"]
    # Un sous-domaine d'un domaine malveillant est aussi signalé.
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in store:
            return {
                "indicator": domain,
                "type": "domain",
                "malicious": True,
                "matched": candidate,
                "details": store[candidate],
            }
    return {"indicator": domain, "type": "domain", "malicious": False, "details": None}


def check_hash(value: str) -> dict:
    digest, algo = normalize_hash(value)
    match = load_iocs()["hashes"].get(digest)
    return {"indicator": digest, "type": algo, "malicious": match is not None, "details": match}


# --- Détection automatique (interface web et vérification groupée) ---

MAX_INPUT_LENGTH = 2048
IP_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$")
REFANG = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("[:]", ":"),
)


def refang(value: str) -> str:
    """Rétablit un indicateur « désarmé » (ex. evil[.]com, hxxp://) tel qu'on le partage en CTI."""
    text = value.strip().strip("\"'<>")
    lowered = text.lower()
    for old, new in REFANG:
        lowered = lowered.replace(old, new)
    return lowered


def check_any(value: str) -> dict:
    """Détecte le type d'indicateur (IP, IP:port, URL, domaine, hash) puis le vérifie."""
    if len(value) > MAX_INPUT_LENGTH:
        raise InvalidIndicatorError("Entrée trop longue")
    text = refang(value)
    if not text:
        raise InvalidIndicatorError("Entrée vide")

    if "://" in text:
        host = urlsplit(text).hostname
        if not host:
            raise InvalidIndicatorError("URL invalide")
        result = _check_host(host)
        result["extracted_from"] = "url"
        return result

    port_match = IP_PORT_RE.match(text)
    if port_match:
        return check_ip(port_match.group(1))

    if len(text) in HASH_LENGTHS and HEX_RE.match(text):
        return check_hash(text)

    return _check_host(text)


def _check_host(host: str) -> dict:
    host = host.strip("[]")
    try:
        return check_ip(host)
    except InvalidIndicatorError:
        pass
    try:
        return check_domain(host)
    except InvalidIndicatorError as exc:
        raise InvalidIndicatorError(
            "Format non reconnu (IP, domaine, URL ou hash attendu)"
        ) from exc


def check_many(values: list[str]) -> list[dict]:
    results = []
    for value in values:
        if not value.strip():
            continue
        try:
            results.append(check_any(value))
        except InvalidIndicatorError as exc:
            # L'entrée est renvoyée tronquée, en JSON : l'interface l'affiche en texte brut.
            results.append({"indicator": value[:100], "type": "invalid", "error": str(exc)})
    return results


def stats() -> dict:
    data = load_iocs()
    counts = {kind: len(entries) for kind, entries in data.items()}
    return {**counts, "feed": feed_metadata()}
