"""SecureShip - IoC Checker API.

API REST et interface web qui indiquent si une IP, un domaine, une URL ou un hash
figure dans une base d'indicateurs de compromission (IoC).
"""

import os
from pathlib import Path as FsPath
from typing import Annotated

from fastapi import FastAPI, Path, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import ioc_store

APP_VERSION = os.getenv("APP_VERSION", "dev")
STATIC_DIR = FsPath(__file__).parent / "static"
MAX_BULK = 100

app = FastAPI(
    title="SecureShip - IoC Checker",
    version=APP_VERSION,
    description=(
        "Vérifie si une adresse IP, un domaine, une URL ou l'empreinte d'un fichier est connu "
        "comme malveillant. Données : jeu de démonstration + flux ThreatFox (abuse.ch) du jour."
    ),
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")
UI_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Ajoute des en-têtes de sécurité HTTP à chaque réponse (OWASP Secure Headers)."""
    response = await call_next(request)
    path = request.url.path
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-store"
    if path == "/" or path.startswith("/static/"):
        # Interface web : scripts et styles uniquement servis par l'application elle-même.
        response.headers["Content-Security-Policy"] = UI_CSP
    elif not path.startswith(DOCS_PATHS):
        # API pure : aucune ressource ne doit être chargée par un navigateur.
        response.headers["Content-Security-Policy"] = API_CSP
    return response


@app.exception_handler(ioc_store.InvalidIndicatorError)
async def invalid_indicator_handler(_: Request, exc: ioc_store.InvalidIndicatorError):
    # Message générique : on ne renvoie jamais l'entrée brute (évite les réflexions XSS).
    return JSONResponse(status_code=422, content={"error": str(exc)})


class BulkRequest(BaseModel):
    indicators: Annotated[
        list[Annotated[str, Field(max_length=ioc_store.MAX_INPUT_LENGTH)]],
        Field(min_length=1, max_length=MAX_BULK),
    ]


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@app.get("/health", tags=["monitoring"])
def health() -> dict:
    return {"status": "ok", "version": APP_VERSION}


@app.get("/api/v1/stats", tags=["ioc"], summary="Taille et fraîcheur de la base")
def get_stats() -> dict:
    return ioc_store.stats()


@app.get("/api/v1/check", tags=["ioc"], summary="Vérifier un indicateur (type détecté seul)")
def check(q: Annotated[str, Query(max_length=ioc_store.MAX_INPUT_LENGTH)]) -> dict:
    """IP, IP:port, domaine, URL (même désarmée : `hxxp://evil[.]com`) ou hash."""
    return ioc_store.check_any(q)


@app.post("/api/v1/check/bulk", tags=["ioc"], summary="Vérifier jusqu'à 100 indicateurs")
def check_bulk(body: BulkRequest) -> dict:
    results = ioc_store.check_many(body.indicators)
    return {
        "count": len(results),
        "malicious": sum(1 for r in results if r.get("malicious")),
        "results": results,
    }


@app.get("/api/v1/check/ip/{ip}", tags=["ioc"], summary="Vérifier une adresse IP")
def check_ip(ip: str = Path(max_length=45)) -> dict:
    return ioc_store.check_ip(ip)


@app.get("/api/v1/check/domain/{domain}", tags=["ioc"], summary="Vérifier un domaine")
def check_domain(domain: str = Path(max_length=253)) -> dict:
    return ioc_store.check_domain(domain)


@app.get("/api/v1/check/hash/{digest}", tags=["ioc"], summary="Vérifier un hash MD5/SHA-1/SHA-256")
def check_hash(digest: str = Path(max_length=64)) -> dict:
    return ioc_store.check_hash(digest)
