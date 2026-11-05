# Politique de sécurité

## Signaler une vulnérabilité

Merci de **ne pas ouvrir d'issue publique**. Utilisez l'onglet *Security > Report a vulnerability*
de ce dépôt (signalement privé GitHub). Une réponse est apportée sous 7 jours.

## Contrôles automatiques

Chaque modification de `main` passe par : SAST (Semgrep, Bandit), analyse des dépendances (pip-audit),
détection de secrets (Gitleaks), analyse Dockerfile/IaC (Hadolint, Checkov), scan d'image (Trivy),
signature Cosign et scan dynamique (OWASP ZAP). Les résultats sont visibles dans *Security > Code scanning*.

## Versions supportées

Seule la dernière version déployée depuis `main` est maintenue.
