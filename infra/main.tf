locals {
  tags = {
    project    = var.project
    managed_by = "terraform"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.project}"
  location = var.location
  tags     = local.tags
}

# Journaux de la Container App (30 jours, minimum facturé)
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${var.project}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = 0.1 # plafond pour protéger le crédit étudiant
  tags                = local.tags
}

resource "azurerm_container_app_environment" "main" {
  name                       = "cae-${var.project}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  tags                       = local.tags
}

resource "azurerm_container_app" "api" {
  name                         = "ca-${var.project}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  tags                         = local.tags

  template {
    min_replicas = 0 # mise à l'échelle à zéro : aucun coût sans trafic
    max_replicas = 1

    container {
      name = "api"
      # Image publiée par la pipeline (jour 1) ; ensuite la pipeline la remplace
      # à chaque déploiement par l'image signée, référencée par son digest.
      image  = "ghcr.io/${lower(var.github_repository)}:latest"
      cpu    = 0.25
      memory = "0.5Gi"

      liveness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/health"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"
    # HTTPS uniquement : les requêtes HTTP sont redirigées
    allow_insecure_connections = false

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  lifecycle {
    # L'image et les variables sont gérées par la pipeline CI/CD, pas par Terraform.
    ignore_changes = [template[0].container[0].image, template[0].container[0].env]
  }
}

# ---------------------------------------------------------------------------
# Identité de déploiement GitHub Actions -> Azure (OIDC, sans aucun secret)
# Une identité managée évite d'avoir besoin des droits "App Registration"
# dans le tenant de l'université.
# ---------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "github" {
  name                = "id-${var.project}-github"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "github_production" {
  name                      = "github-${var.project}-production"
  user_assigned_identity_id = azurerm_user_assigned_identity.github.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = "https://token.actions.githubusercontent.com"
  # Seul le job utilisant l'environnement GitHub "production" de CE dépôt peut se connecter.
  # Les nouveaux dépôts GitHub incluent les identifiants numériques du compte et du dépôt
  # dans le "subject" (immuable : un dépôt supprimé puis recréé sous le même nom est refusé).
  subject = coalesce(
    var.github_oidc_subject,
    "repo:${var.github_repository}:environment:production",
  )
}

# Moindre privilège : droits limités au seul groupe de ressources du projet.
resource "azurerm_role_assignment" "github_deploy" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.github.principal_id
}

# Garde-fou financier : alerte e-mail à 80 % puis 100 % du budget mensuel.
resource "azurerm_consumption_budget_resource_group" "main" {
  name              = "budget-${var.project}"
  resource_group_id = azurerm_resource_group.main.id
  amount            = var.monthly_budget_eur
  time_grain        = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", plantimestamp())
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    contact_emails = [var.budget_alert_email]
  }

  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThan"
    contact_emails = [var.budget_alert_email]
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}
