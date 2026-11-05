# ---- Étape 1 : construction des dépendances dans un environnement virtuel ----
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---- Étape 2 : image finale minimale, sans outils de build ----
FROM python:3.13-slim

LABEL org.opencontainers.image.title="secureship" \
      org.opencontainers.image.description="IoC Checker API - pipeline DevSecOps" \
      org.opencontainers.image.licenses="MIT"

# Mises à jour de sécurité du système de base + utilisateur non privilégié
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv
COPY --from=builder /opt/venv /opt/venv
COPY --chown=root:root app ./app

# Le processus ne tourne jamais en root
USER 10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--proxy-headers"]
