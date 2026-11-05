# Guide de démarrage — SecureShip en 2 jours

Ce guide t'emmène du fichier zip jusqu'à un site web en ligne sur Azure, mis à jour automatiquement chaque jour.
Il est écrit pour qu'une personne qui n'a jamais utilisé GitHub Actions, Docker ou Terraform puisse le suivre.

| | Durée | Résultat |
|---|---|---|
| **Jour 1** | environ 4 h | Le projet tourne sur ton PC, il est sur GitHub, la pipeline de sécurité passe au vert |
| **Jour 2** | environ 4 h | Le site est en ligne sur Azure, avec un vrai flux de menaces mis à jour chaque matin |

> Conseil : lis chaque fichier avant de le pousser. En entretien, tu dois pouvoir expliquer chaque ligne.
> Si une étape bloque, copie-moi le message d'erreur complet.

---

## Sommaire

0. [Comprendre le projet en 5 minutes](#0-comprendre-le-projet-en-5-minutes)
1. [Installer les outils](#1-installer-les-outils-45-min)
2. [Lancer le site sur ton PC](#2-lancer-le-site-sur-ton-pc-20-min)
3. [Découvrir l'interface web](#3-découvrir-linterface-web-15-min)
4. [Mettre le projet sur GitHub](#4-mettre-le-projet-sur-github-20-min)
5. [Regarder la pipeline tourner](#5-regarder-la-pipeline-tourner-30-min)
6. [Prouver que la sécurité bloque vraiment](#6-prouver-que-la-sécurité-bloque-vraiment-45-min-)
7. [Préparer Azure](#7-préparer-azure-30-min)
8. [Créer l'infrastructure avec Terraform](#8-créer-linfrastructure-avec-terraform-45-min)
9. [Relier GitHub à Azure](#9-relier-github-à-azure-15-min)
10. [Déployer et ouvrir le site](#10-déployer-et-ouvrir-le-site-20-min)
11. [Activer le flux de menaces réel](#11-activer-le-flux-de-menaces-réel-20-min)
12. [Finaliser la vitrine](#12-finaliser-la-vitrine-1-h)
13. [Entretenir le projet](#13-entretenir-le-projet)
- [Dépannage](#dépannage) · [Glossaire](#glossaire) · [Pour le CV](#pour-le-cv) · [Questions d'entretien](#questions-dentretien)

---

## 0. Comprendre le projet en 5 minutes

**Ce que fait le site.** N'importe qui colle un lien, une adresse IP, un nom de domaine ou l'empreinte d'un fichier.
Le site répond s'il est connu comme malveillant, avec la menace, le niveau de confiance et le conseil adapté.

**Ce qui se passe à chaque modification du code** (et chaque matin automatiquement) :

```
Ton code ──► GitHub ──► Pipeline DevSecOps (GitHub Actions)
                          0. télécharge le flux de menaces ThreatFox
                          1. vérifie la qualité et lance 48 tests
                          2-5. cherche des failles : code, dépendances, secrets, Dockerfile, Terraform
                          6. construit l'image Docker et la scanne (bloque si faille grave)
                          7-8. publie l'image, génère son inventaire (SBOM), la signe
                          9. la déploie sur Azure (sans aucun mot de passe stocké)
                          10. attaque le site en ligne avec OWASP ZAP pour vérifier qu'il résiste
```

**Les dossiers du projet :**

| Dossier ou fichier | Rôle |
|---|---|
| `app/main.py` | Le serveur web : les routes de l'API et les en-têtes de sécurité |
| `app/ioc_store.py` | Le « cerveau » : détecte le type d'élément, le valide, le compare à la base |
| `app/data/iocs.json` | Les entrées de démonstration, sans danger (toujours présentes) |
| `app/static/` | L'interface web : `index.html` (page), `style.css` (apparence), `app.js` (comportement), polices |
| `scripts/update_iocs.py` | Télécharge et valide le flux ThreatFox |
| `scripts/allowlist.txt` | Les grands sites légitimes jamais signalés (anti fausses alertes) |
| `tests/` | Les 48 tests automatiques |
| `Dockerfile` | La recette de l'image Docker durcie |
| `infra/` | Terraform : tout ce qui est créé sur Azure |
| `.github/workflows/devsecops.yml` | La pipeline complète |
| `.github/dependabot.yml` | Mises à jour automatiques des dépendances |
| `.zap/rules.tsv` | Réglages du scan d'attaque OWASP ZAP |

---

# Jour 1 — Ton PC et GitHub

## 1. Installer les outils (45 min)

Installe dans cet ordre, puis **ferme et rouvre ton terminal** pour que les commandes soient reconnues.

| Outil | Où le trouver | Vérification dans le terminal |
|---|---|---|
| Git | git-scm.com | `git --version` |
| Python 3.12 ou plus | python.org (sous Windows : coche *Add python.exe to PATH*) | `python --version` |
| VS Code | code.visualstudio.com, avec les extensions Python, Terraform et GitHub Actions | — |
| GitHub CLI | cli.github.com | `gh --version` |
| Azure CLI | learn.microsoft.com, page « Install the Azure CLI » | `az --version` |
| Terraform 1.6 ou plus | developer.hashicorp.com/terraform/install | `terraform -version` |
| Docker Desktop (facultatif) | docker.com | `docker --version` |

**Sous Windows**, utilise le terminal *PowerShell*. Quand une commande diffère, elle est indiquée.

Configure Git une seule fois, avec l'adresse de ton compte GitHub :

```bash
git config --global user.name "Mahomed Arafat Anjoueneya Mouansie"
git config --global user.email "ton-adresse-github@exemple.com"
```

Connecte-toi à GitHub depuis le terminal (une page web s'ouvre pour valider) :

```bash
gh auth login        # choisis GitHub.com > HTTPS > Login with a web browser
```

## 2. Lancer le site sur ton PC (20 min)

Décompresse `secureship.zip`, puis ouvre un terminal **dans le dossier `secureship`** (dans VS Code : *Terminal > New Terminal*).

```bash
python -m venv .venv                 # crée un environnement Python isolé pour le projet
source .venv/bin/activate            # macOS / Linux
# Windows PowerShell : .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt  # installe FastAPI, pytest, ruff, bandit…
pytest                               # lance les 48 tests : tout doit être vert
uvicorn app.main:app --reload        # démarre le serveur
```

Sous Windows, si PowerShell refuse d'activer l'environnement, lance une fois
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, puis recommence.

Ouvre ton navigateur :
- **http://127.0.0.1:8000** → le site, pour tout le monde ;
- **http://127.0.0.1:8000/docs** → la documentation de l'API, pour les développeurs.

Pour arrêter le serveur : `Ctrl + C` dans le terminal.

Facultatif, avec Docker Desktop démarré, teste l'image exactement comme sur Azure :

```bash
docker build -t secureship .
docker run --rm -p 8000:8000 secureship
```

## 3. Découvrir l'interface web (15 min)

Sur http://127.0.0.1:8000, essaie chaque fonction. Elles serviront de démonstration en entretien.

| Essai | Ce que tu dois voir |
|---|---|
| Clique sur l'exemple *une adresse de serveur pirate* | Tampon rouge **Signalé**, menace « C2 server », confiance 90 % |
| Clique sur *un lien d'hameçonnage* | Le domaine est extrait du lien **désarmé** `hxxps://…[.]example` |
| Colle plusieurs lignes à la fois (jusqu'à 100) | Un résultat par ligne, numérotés, et un résumé en haut |
| Tape `10.0.0.1` | **Rien trouvé** et la mention « adresse de réseau local » |
| Tape `n'importe quoi` | Tampon gris **Non reconnu** avec un conseil de correction |
| Clique sur **EN** en haut à droite | Tout le site passe en anglais (pratique pour les offres à l'étranger) |
| Mets ton ordinateur en mode sombre | Le site s'adapte automatiquement |
| `Ctrl + Entrée` dans le champ | Lance la vérification sans la souris |

**Points de sécurité à savoir expliquer :**
- La page n'exécute que des scripts servis par le site lui-même : la *Content-Security-Policy* interdit tout script externe ou injecté.
- Les polices sont hébergées par le site : aucun visiteur n'est pisté par un service tiers.
- Les résultats sont affichés en texte brut (`textContent`), jamais comme du HTML : une entrée piégée comme `<img src=x onerror=alert(1)>` ne peut pas s'exécuter (essaie-la).
- Les recherches ne sont ni enregistrées ni transmises.

## 4. Mettre le projet sur GitHub (20 min)

1. Crée le dépôt **public** `secureship` (sans README, il existe déjà) :

```bash
gh repo create secureship --public --description "IoC Checker + pipeline DevSecOps sur Azure"
```

   Public est nécessaire : l'onglet *Security* est gratuit pour les dépôts publics, et c'est ta vitrine.

2. Envoie le code :

```bash
git init -b main
git add .
git commit -m "feat: SecureShip IoC Checker, interface web et pipeline DevSecOps"
git remote add origin https://github.com/SCIENTISOPHOS/secureship.git
git push -u origin main
```

3. Sur github.com, dans ton dépôt : **Settings > Environments > New environment**, nomme-le exactement `production`.

## 5. Regarder la pipeline tourner (30 min)

Ouvre l'onglet **Actions** du dépôt, puis le run *DevSecOps pipeline*.

| Étape | Résultat attendu aujourd'hui |
|---|---|
| 0 · Flux IoC | ✅ en mode démonstration : la clé ThreatFox arrive à l'étape 11 |
| 1 à 8 | ✅ tests, analyses de sécurité, image construite, scannée, publiée et signée |
| 9 · Déploiement Azure | ❌ **normal** : Azure n'est pas encore configuré (jour 2) |
| 10 · DAST | ⏭️ ignorée, car elle a besoin du site en ligne |

Ensuite, rends l'image publique pour qu'Azure puisse la télécharger :
ton profil GitHub > **Packages** > `secureship` > **Package settings** > *Change visibility* > **Public**.

Lire un échec : clique sur le job rouge, puis sur l'étape rouge. La dernière ligne en erreur explique presque toujours le problème.

## 6. Prouver que la sécurité bloque vraiment (45 min) ⭐

C'est la démonstration la plus parlante en entretien : tu introduis volontairement une faille, et la pipeline refuse le code.

```bash
git checkout -b test/faille-volontaire
```

Ajoute à la fin de `app/main.py` :

```python
@app.get("/debug")
def debug(cmd: str):
    import subprocess
    return {"out": subprocess.check_output(cmd, shell=True).decode()}
```

```bash
git commit -am "test: faille volontaire"
git push -u origin test/faille-volontaire
gh pr create --fill
```

Résultat attendu : ruff, Bandit et Semgrep détectent l'**injection de commande**, la Pull Request est rouge.
Fais une **capture d'écran** de la PR bloquée et de l'onglet *Security*, puis nettoie :

```bash
gh pr close --delete-branch
git checkout main
```

Pour verrouiller `main` : **Settings > Branches > Add branch ruleset** (ou *Add rule*) sur `main` →
*Require a pull request before merging* et *Require status checks to pass* (ajoute les jobs 1 à 6).
La pipeline quotidienne n'est pas gênée : elle ne pousse jamais de code.

---

# Jour 2 — Azure et mise en ligne

## 7. Préparer Azure (30 min)

```bash
az login                                     # avec ton compte UTT (Azure for Students)
az account show --query "{nom:name, id:id}" -o table
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
az provider register --namespace Microsoft.ManagedIdentity
az provider register --namespace Microsoft.Consumption
```

L'enregistrement des *providers* prend quelques minutes. Vérifie avec
`az provider show -n Microsoft.App --query registrationState` : il doit afficher `Registered`.

> Azure for Students limite parfois les régions autorisées. Si Terraform renvoie
> `RequestDisallowedByPolicy`, remplace `francecentral` par `westeurope` ou `swedencentral`.

## 8. Créer l'infrastructure avec Terraform (45 min)

Terraform lit les fichiers de `infra/` et crée exactement ce qu'ils décrivent.

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars      # Windows : copy terraform.tfvars.example terraform.tfvars
```

Ouvre `terraform.tfvars` et remplis :
- `subscription_id` : l'`id` affiché par `az account show` ;
- `github_repository` : `SCIENTISOPHOS/secureship` ;
- `budget_alert_email` : ton adresse e-mail.

Ce fichier n'est jamais envoyé sur GitHub (il est dans `.gitignore`).

```bash
terraform init      # télécharge le module Azure
terraform plan      # affiche ce qui va être créé : lis-le, 8 ressources
terraform apply     # tape "yes" pour confirmer
terraform output    # affiche les valeurs pour l'étape 9
```

**Ce qui est créé :**

| Ressource | Rôle |
|---|---|
| Groupe de ressources `rg-secureship` | Le « dossier » qui contient tout le projet |
| Log Analytics | Les journaux de l'application, plafonnés à 0,1 Go par jour |
| Environnement Container Apps | La plateforme qui exécute les conteneurs |
| Container App `ca-secureship` | Ton site, en HTTPS, qui s'éteint sans visiteur (coût proche de 0 €) |
| Identité managée + fédération OIDC | Permet à GitHub de déployer sans mot de passe |
| Rôle *Contributor* | Limité au seul groupe de ressources (moindre privilège) |
| Budget | Alerte e-mail à 80 % et 100 % de 10 € par mois |

> Si la ressource *budget* est refusée par ton abonnement, supprime le bloc
> `azurerm_consumption_budget_resource_group` dans `main.tf`, relance `terraform apply`,
> et crée l'alerte dans le portail Azure (*Cost Management > Budgets*).
> Si Terraform signale `parent_id` comme obsolète, c'est un simple avertissement.

## 9. Relier GitHub à Azure (15 min)

Sur GitHub : **Settings > Secrets and variables > Actions > onglet Variables** > *New repository variable*.
Crée ces 5 variables avec les valeurs de `terraform output` :

`AZURE_CLIENT_ID` · `AZURE_TENANT_ID` · `AZURE_SUBSCRIPTION_ID` · `AZURE_RESOURCE_GROUP` · `AZURE_CONTAINERAPP_NAME`

Ou en ligne de commande, depuis le dossier `infra` :

```bash
for v in AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID AZURE_RESOURCE_GROUP AZURE_CONTAINERAPP_NAME; do
  gh variable set "$v" --body "$(terraform output -raw $v)"
done
```

Ce sont des **variables**, pas des secrets : aucune n'est sensible, car l'authentification repose sur OIDC.
C'est un point fort à expliquer en entretien.

## 10. Déployer et ouvrir le site (20 min)

Onglet **Actions** > dernier run > **Re-run failed jobs**, ou en ligne de commande :

```bash
gh workflow run devsecops.yml
```

Quand tout est vert, l'adresse du site s'affiche dans le job *9 · Déploiement Azure*, étape *Smoke test*.
Tu peux aussi la retrouver avec `terraform output app_url`.

- **https://ton-adresse** → le site pour tout le monde ;
- **https://ton-adresse/docs** → l'API pour les recruteurs techniques.

Au premier accès après une période sans visite, le site met quelques secondes à se réveiller : c'est la mise à l'échelle à zéro qui économise ton crédit.

## 11. Activer le flux de menaces réel (20 min)

1. Crée un compte gratuit sur **auth.abuse.ch** (connexion possible avec GitHub) et copie ta clé *Auth-Key*.
   Lis au passage leurs conditions d'utilisation.
2. Sur GitHub : **Settings > Secrets and variables > Actions > onglet Secrets** > *New repository secret*,
   nom `ABUSECH_AUTH_KEY`, valeur : ta clé. Cette fois c'est bien un **secret** : la clé ne doit jamais apparaître.

```bash
gh secret set ABUSECH_AUTH_KEY        # colle la clé quand elle est demandée
gh workflow run devsecops.yml
```

3. Vérifie sur ton site : la section **D'où viennent les données** affiche des milliers d'entrées et la date du jour.
   Teste une IP récente trouvée sur threatfox.abuse.ch/browse : tampon rouge **Signalé**.

Tester le flux sur ton PC :

```bash
export ABUSECH_AUTH_KEY=ta_cle        # Windows PowerShell : $env:ABUSECH_AUTH_KEY="ta_cle"
python scripts/update_iocs.py --days 1
uvicorn app.main:app --reload
```

Le fichier généré `app/data/iocs_feed.json` n'est jamais envoyé sur GitHub.

Désormais, **chaque jour à 06:17 (heure de Paris)**, la pipeline rafraîchit le flux, re-scanne l'image contre les nouvelles failles et redéploie le site.

## 12. Finaliser la vitrine (1 h)

- **README** : ajoute 4 captures (page d'accueil, résultat signalé, pipeline verte, PR bloquée).
  Crée un dossier `docs/` et insère-les avec `![Accueil](docs/accueil.png)`.
- **Dépôt** : dans *About* (roue dentée à droite), colle l'adresse du site et ajoute les sujets
  `devsecops`, `azure`, `terraform`, `github-actions`, `threat-intelligence`, `fastapi`.
- **Profil GitHub** : épingle le dépôt (*Customize your pins*).
- **LinkedIn** : un court post avec une capture et ce que tu as appris (je peux le rédiger avec toi).

## 13. Entretenir le projet

| Événement | Quoi faire |
|---|---|
| Dependabot ouvre une Pull Request | Attends que la pipeline soit verte, puis *Merge* |
| La pipeline du matin échoue à l'étape 6 (Trivy) | Une nouvelle faille touche l'image : relance le lendemain ou fusionne la PR Dependabot de l'image de base |
| L'étape 0 échoue (« Chute anormale » ou « Flux vide ») | Le garde-fou a fonctionné : ThreatFox a eu un problème. Le site garde la version précédente ; relance plus tard |
| Le crédit Azure baisse | `az consumption usage list` ou le portail *Cost Management*. Pour tout supprimer : `terraform destroy` |
| Tu veux modifier le site | Branche, modification, Pull Request : la pipeline vérifie tout avant la fusion |

---

## Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| `python` introuvable (Windows) | Python pas dans le PATH | Réinstalle en cochant *Add python.exe to PATH*, ou utilise `py` |
| `pytest` échoue sur ton PC | Environnement virtuel non activé | Réactive `.venv` (étape 2) |
| Étape 0 : `ABUSECH_AUTH_KEY absente` | Secret non créé | Étape 11 |
| Étape 0 : `unknown_auth_key` | Clé mal copiée | Recrée le secret sans espace autour |
| Étape 2 : Semgrep ou Bandit rouge | Vraie alerte dans ton code | Lis la règle et corrige ; ne désactive jamais un contrôle sans le justifier |
| Étape 4 : Gitleaks rouge | Un secret a été commité | Révoque le secret, puis retire-le de l'historique |
| Étape 6 : Trivy rouge sans changement de code | Nouvelle faille dans l'image de base | Reconstruis plus tard ou applique la PR Dependabot |
| Étape 9 : `AADSTS700213` ou *No matching federated identity* | Nom du dépôt ou de l'environnement différent | Vérifie `github_repository` et l'environnement `production`, puis `terraform apply` |
| Étape 9 : l'image ne se télécharge pas | Package GHCR privé | Rends-le public (étape 5) |
| `RequestDisallowedByPolicy` | Région non autorisée | Change `location` dans `terraform.tfvars` |
| Le site affiche « Mode démonstration » | Flux pas encore généré | Étape 11, puis relance la pipeline |
| Étape 10 (ZAP) rouge | Une alerte de sécurité réelle sur le site | Ouvre le rapport du job, corrige l'en-tête ou la page concernée |

---

## Glossaire

| Terme | En une phrase |
|---|---|
| **IoC** | Indicateur de compromission : une trace technique (IP, domaine, hash) laissée par une attaque |
| **CI/CD** | Intégration et déploiement continus : chaque modification est testée puis mise en ligne automatiquement |
| **DevSecOps** | DevOps où la sécurité est vérifiée à chaque étape, pas seulement à la fin |
| **SAST** | Analyse du code source sans l'exécuter (Semgrep, Bandit) |
| **SCA** | Analyse des bibliothèques tierces utilisées (pip-audit) |
| **DAST** | Test de l'application en fonctionnement, comme un attaquant (OWASP ZAP) |
| **SBOM** | Liste de tous les composants d'une image, pour savoir vite si une nouvelle faille te concerne |
| **OIDC** | Échange de jetons temporaires qui remplace les mots de passe entre GitHub et Azure |
| **Infrastructure as Code** | Décrire les serveurs dans des fichiers (Terraform) plutôt que de cliquer dans un portail |
| **Digest** | Empreinte unique d'une image Docker ; contrairement à un tag, elle ne peut pas être déplacée |
| **CSP** | En-tête qui dit au navigateur quels scripts et styles il a le droit de charger |
| **Désarmer (defang)** | Écrire `hxxp://site[.]com` pour qu'un lien dangereux ne soit pas cliquable |

---

## Pour le CV

> **SecureShip — Plateforme de Threat Intelligence et pipeline DevSecOps sur Azure** · *Projet personnel · Nov. 2026*
> *GitHub Actions, Docker, Terraform, Azure Container Apps, FastAPI, Trivy, Semgrep, Cosign, OWASP ZAP*
> — Chaîne CI/CD sécurisée en 10 étapes (SAST, SCA, secrets, scan d'image, DAST) bloquant tout déploiement vulnérable.
> — Infrastructure Azure en Terraform, déploiement GitHub → Azure par OIDC, sans secret stocké.
> — Mise à jour quotidienne automatisée d'une base d'IoC depuis ThreatFox (abuse.ch), avec validation et garde-fous.
> — Interface web bilingue et accessible (CSP stricte, protection XSS), vérification groupée et détection automatique du type d'indicateur.

## Questions d'entretien

1. **Pourquoi OIDC plutôt qu'un secret client ?** Jeton court, émis à chaque exécution, limité à un dépôt et un environnement : rien à voler ni à faire tourner.
2. **Différence SAST / SCA / DAST ?** Code source / dépendances tierces / application en fonctionnement.
3. **Pourquoi déployer par digest et non par tag ?** Un tag peut être déplacé ; un digest désigne une image unique et signée.
4. **À quoi sert un SBOM ?** Savoir en quelques minutes si une nouvelle CVE touche tes applications.
5. **Pourquoi épingler les actions GitHub ?** En 2026, des versions de `trivy-action` ont été compromises : une action non épinglée peut exécuter du code malveillant dans ta pipeline.
6. **Pourquoi valider le flux ThreatFox alors qu'il vient d'une source reconnue ?** Toute donnée externe est non fiable : un flux compromis ou corrompu ne doit ni casser le site ni vider sa base.
7. **Comment ton interface résiste-t-elle au XSS ?** CSP sans script inline, affichage en `textContent`, messages d'erreur qui ne renvoient jamais l'entrée brute.
8. **Pourquoi la pipeline tourne-t-elle chaque jour même sans changement de code ?** Pour rafraîchir les IoC et re-scanner l'image : une image saine hier peut être vulnérable aujourd'hui.
9. **Que ferais-tu ensuite ?** État Terraform distant, vérification de signature avant déploiement, Kubernetes avec ArgoCD et Kyverno, limitation de débit sur l'API.
