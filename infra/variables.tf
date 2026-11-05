variable "subscription_id" {
  description = "ID de l'abonnement Azure for Students (az account show --query id -o tsv)"
  type        = string
}

variable "github_repository" {
  description = "Dépôt GitHub autorisé à déployer, au format owner/repo"
  type        = string
}

variable "github_oidc_subject" {
  description = <<-EOT
    Subject OIDC exact envoyé par GitHub, si le dépôt utilise le format avec identifiants,
    ex. "repo:OWNER@123/REPO@456:environment:production" (visible dans l'erreur AADSTS700213).
  EOT
  type        = string
  default     = null
}

variable "location" {
  description = "Région Azure (Azure for Students limite parfois les régions autorisées)"
  type        = string
  default     = "francecentral"
}

variable "project" {
  description = "Préfixe des ressources"
  type        = string
  default     = "secureship"
}

variable "budget_alert_email" {
  description = "Adresse qui reçoit les alertes de budget"
  type        = string
}

variable "monthly_budget_eur" {
  description = "Budget mensuel maximum avant alerte"
  type        = number
  default     = 10
}
