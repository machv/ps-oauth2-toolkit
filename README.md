# Azure AD OAuth2 toolkit

This module provides some helper functions to work with Azure AD OAuth2 endpoint without the need to construct URL manually.

## Installation

The easiest way to use this module is to download it from PowerShell Gallery:

```powershell
Install-Module -Name Oauth2Toolkit
```

## Supported Grant Type Flows

| OAuth 2 Flow | Function | Notes |
| ------------- | ------------- | ----- |
| Authorization Code Grant | `Invoke-CodeGrantFlow` |  |
| Device Code  | `Invoke-DeviceCodeFlow` |  |
| Password | `Invoke-ResourceOwnerPasswordGrantFlow` |  |
| On behalf of | `Invoke-OnBehalfOfFlow` |  https://docs.microsoft.com/cs-cz/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow |


## Example use

Obtain access token for the application:
```powershell
$response = Invoke-CodeGrantFlow -RedirectUrl "http://localhost:8080/auth" -ClientId "<AppId>" -ClientSecret "<AppSecret>" -Tenant "tenant.onmicrosoft.com" -Resource "<AppId>" -AlwaysPrompt $true
```

And use the returned Access Token to get resource specific Access Tokens for multiple services on behalf of the user:

```powershell
$graphAuthenticationHeaders = Invoke-OnBehalfOfFlow -Tenant "tenant.onmicrosoft.com" -ClientId "<AppId>" -ClientSecret "<AppSecret>" -AccessToken $response.access_token -Resource "https://graph.microsoft.com" | ConvertTo-AuthorizationHeaders

Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me" -Headers $graphAuthenticationHeaders
```
