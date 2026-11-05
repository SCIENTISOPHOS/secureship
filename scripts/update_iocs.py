"""Met à jour app/data/iocs_feed.json à partir du flux ThreatFox (abuse.ch).

Usage :
    ABUSECH_AUTH_KEY=xxxx python scripts/update_iocs.py [--days 7] [--optional]

Principes de sécurité :
- le flux est une donnée NON fiable : chaque indicateur est re-validé avant d'être gardé ;
- les IP privées/réservées et les domaines d'une liste blanche sont écartés (faux positifs) ;
- si le flux revient vide ou s'effondre par rapport à la version précédente, le script
  échoue au lieu de publier une base vide (protection contre une panne du fournisseur).
"""

import argparse
import json
import os
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.ioc_store import (  # noqa: E402
    FEED_FILE,
    InvalidIndicatorError,
    normalize_domain,
    normalize_hash,
    normalize_ip,
)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
ALLOWLIST_FILE = ROOT / "scripts" / "allowlist.txt"
MAX_ENTRIES = 50_000  # garde-fou de taille
MIN_RATIO = 0.2  # échec si on garde moins de 20 % des IoC de la version précédente
TIMEOUT = 30


def fetch_threatfox(auth_key: str, days: int) -> list[dict]:
    body = json.dumps({"query": "get_iocs", "days": days}).encode()
    request = urllib.request.Request(  # noqa: S310 - URL HTTPS constante
        API_URL,
        data=body,
        headers={"Auth-Key": auth_key, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310  # nosec B310
        payload = json.load(response)
    if payload.get("query_status") != "ok":
        raise RuntimeError(f"Réponse ThreatFox inattendue : {payload.get('query_status')}")
    return payload.get("data") or []


def load_allowlist() -> set[str]:
    if not ALLOWLIST_FILE.is_file():
        return set()
    lines = ALLOWLIST_FILE.read_text(encoding="utf-8").splitlines()
    return {line.strip().lower() for line in lines if line.strip() and not line.startswith("#")}


def is_allowlisted(domain: str, allowlist: set[str]) -> bool:
    parts = domain.split(".")
    return any(".".join(parts[i:]) in allowlist for i in range(len(parts) - 1))


def normalize_entries(raw: list[dict], allowlist: set[str]) -> dict:
    result = {"ips": {}, "domains": {}, "hashes": {}}
    for item in raw:
        ioc_type = str(item.get("ioc_type", ""))
        value = str(item.get("ioc", ""))
        details = {
            "threat": f"{item.get('malware_printable') or 'Unknown'} ({item.get('threat_type')})",
            "source": "ThreatFox (abuse.ch)",
            "confidence": int(item.get("confidence_level") or 0),
            "first_seen": item.get("first_seen"),
        }
        try:
            if ioc_type == "ip:port":
                ip = normalize_ip(value.rsplit(":", 1)[0].strip("[]"))
                if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast:
                    continue
                result["ips"][str(ip)] = details
            elif ioc_type == "domain":
                domain = normalize_domain(value)
                if not is_allowlisted(domain, allowlist):
                    result["domains"][domain] = details
            elif ioc_type.endswith("_hash"):
                digest, _ = normalize_hash(value)
                result["hashes"][digest] = details
            # Les URL sont ignorées : leur domaine est souvent un hébergeur légitime.
        except InvalidIndicatorError:
            continue  # entrée corrompue ou malformée : rejetée
    return result


def total(data: dict) -> int:
    return sum(len(data.get(kind, {})) for kind in ("ips", "domains", "hashes"))


def sanity_check(new: dict, previous: dict) -> None:
    count = total(new)
    if count == 0:
        raise RuntimeError("Flux vide : publication annulée")
    if count > MAX_ENTRIES:
        raise RuntimeError(f"Flux anormalement gros ({count} IoC) : publication annulée")
    old = total(previous)
    if old and count < old * MIN_RATIO:
        raise RuntimeError(f"Chute anormale du flux ({old} -> {count}) : publication annulée")


def build_feed(raw: list[dict], previous: dict, allowlist: set[str]) -> dict:
    data = normalize_entries(raw, allowlist)
    sanity_check(data, previous)
    # Tri pour des différences lisibles d'une version à l'autre.
    feed = {kind: dict(sorted(entries.items())) for kind, entries in data.items()}
    feed["_meta"] = {
        "source": "ThreatFox (abuse.ch)",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {kind: len(feed[kind]) for kind in ("ips", "domains", "hashes")},
    }
    return feed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=7, choices=range(1, 8))
    parser.add_argument(
        "--optional",
        action="store_true",
        help="ne pas échouer si la clé est absente (ex. Pull Request venant d'un fork)",
    )
    parser.add_argument("--output", type=Path, default=FEED_FILE)
    args = parser.parse_args(argv)

    auth_key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if not auth_key:
        print("ABUSECH_AUTH_KEY absente : flux non mis à jour (jeu de démonstration seul).")
        return 0 if args.optional else 1

    previous = json.loads(args.output.read_text(encoding="utf-8")) if args.output.is_file() else {}
    feed = build_feed(fetch_threatfox(auth_key, args.days), previous, load_allowlist())
    args.output.write_text(json.dumps(feed, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Flux mis à jour : {feed['_meta']['counts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
