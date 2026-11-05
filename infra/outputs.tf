# Valeurs à recopier dans GitHub : Settings > Secrets and variables > Actions > Variables
output "AZURE_CLIENT_ID" {
  value = azurerm_user_assigned_identity.github.client_id
}

output "AZURE_TENANT_ID" {
  value = azurerm_user_assigned_identity.github.tenant_id
}

output "AZURE_SUBSCRIPTION_ID" {
  value = var.subscription_id
}

output "AZURE_RESOURCE_GROUP" {
  value = azurerm_resource_group.main.name
}

output "AZURE_CONTAINERAPP_NAME" {
  value = azurerm_container_app.api.name
}

output "app_url" {
  value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}
