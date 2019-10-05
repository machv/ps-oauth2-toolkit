function ConvertFrom-Timestamp
{
    param(
        [Parameter(Mandatory = $true)]
        [int]$Timestamp
    )

    $utc = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($Timestamp))
    $datetime = [datetime]::SpecifyKind($utc, 'Utc').ToLocalTime()

    $datetime
}

function New-AccessToken
{
    param(
        [string]$Tenant,
        [Parameter(ParameterSetName='ClientCredential')]
        [pscredential]$Client,
        [Parameter(ParameterSetName='ClientExplicit')]
        [string]$ClientId,
        [Parameter(ParameterSetName='ClientExplicit')]
        [string]$ClientSecret,
        [string]$RefreshToken
    )

    $authUrl = "https://login.microsoftonline.com/{0}/oauth2/token" -f $Tenant
    $parameters = @{
        grant_type = "refresh_token"
        client_secret= $ClientSecret
        refresh_token = $RefreshToken
        client_id = $ClientId
    }

    $response = Invoke-RestMethod -Uri $authUrl -Method Post -Body $parameters
    $expires = ConvertFrom-Timestamp -Timestamp $response.expires_on
    
    $result = [PSCustomObject]@{
        Expires = $expires
        AccessToken = $response.access_token
    }

    $result
}

function Invoke-OnBehalfOfFlow
{
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-oauth2-on-behalf-of-flow
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$clientSecret,
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        [Parameter()]
        [string]$Resource = "https://graph.microsoft.com"
    )    

    $payload = @{
        grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        requested_token_use = "on_behalf_of"
        scope = "openid"
        assertion = $AccessToken
        resource = $Resource
        client_id = $ClientId
        client_secret = $clientSecret
        
    }
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" -Body $payload

    $response
}

function ConvertTo-AuthorizationHeaders
{
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        $response
    )

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer " + $response.access_token
        'ExpiresOn'     = (ConvertFrom-Timestamp -Timestamp $response.expires_on)
    }

    $headers
}

function Add-AdalAssemblies
{
    $assemblyPath = Join-path $PSScriptRoot "NetCoreAssemblies\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    Add-Type -path $assemblyPath

    $assemblyPath = Join-path $PSScriptRoot "NetCoreAssemblies\Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    Add-Type -path $assemblyPath
}

function New-OnBehalfOfAccessToken 
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$clientSecret,
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        [Parameter()]
        [string]$ResourcePrincial = "https://graph.microsoft.com"
    )

    Add-AdalAssemblies

    $authority = "https://login.microsoftonline.com/$Tenant"
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $clientCredentials = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList ($ClientId, $ClientSecret)
    $userAssertion  = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserAssertion" -ArgumentList ($AccessToken)
    $authResult = $authContext.AcquireTokenAsync($ResourcePrincial, $clientCredentials, $userAssertion)
    
    if ($authResult.Result.AccessToken) {
        # Creating header for Authorization token
        $authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = "Bearer " + $authResult.Result.AccessToken
            'ExpiresOn'     = $authResult.Result.ExpiresOn
        }
    
        $authHeader
    }
    elseif ($authResult.Exception) {
        throw "An error occured getting access token: $($authResult.Exception.InnerException)"
    }
}

# Oauth password flow

function Add-Win32HelperType
{
    $nativeHelperTypeDefinition =
    @"
    using System;
    using System.Runtime.InteropServices;
    public static class WinApi
        {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);
        public static bool SetForeground(IntPtr windowHandle)
        {
           return SetForegroundWindow(windowHandle);
        }

        [DllImport("user32.dll", SetLastError=true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        public static void KillProcess(IntPtr windowHandle) 
        {
            uint pid;
            GetWindowThreadProcessId(windowHandle, out pid);

            System.Diagnostics.Process p = System.Diagnostics.Process.GetProcessById((int)pid); 
            if(p != null) p.Kill();
        }
    }
"@
    if(-not ([System.Management.Automation.PSTypeName] "WinApi").Type)
    {
        Add-Type -TypeDefinition $nativeHelperTypeDefinition
    }
}

function Invoke-BrowserLogin
{
    param
    (
        [Parameter(HelpMessage='Authorization URL', Mandatory = $true)]
        [ValidateNotNull()]
        [string]$AuthorizationUrl,
        [Parameter(HelpMessage='Redirect URI', Mandatory = $true)]
        [ValidateNotNull()]
        $RedirectUrl,
        $ExpectedSuccessParameter = "code"
    )

    Add-Type -AssemblyName System.Web
    Add-Win32HelperType

    # Create an Internet Explorer Window for the Login Experience
    $ie = New-Object -ComObject InternetExplorer.Application
    $ie.Width = 550
    $ie.Height = 600
    $ie.AddressBar = $false
    $ie.ToolBar = $false
    $ie.StatusBar = $false
    $ie.visible = $true
    $ie.navigate($authorizationUrl)
    $handle = $ie.HWND
    $winForeground = [WinApi]::SetForeground($handle)
    # Grab the window
    $wind = (New-Object -ComObject Shell.Application).Windows() | Where-Object { $_.HWND -eq $handle }
    $sleepCounter = 0

    while ($ie.Busy)
    {
        Start-Sleep -Milliseconds 50
        $sleepCounter++

        if ($sleepCounter -eq 100)
        {
            throw "Unable to connect to $authorizationUrl, timed out waiting for page."
        }
    }

    try
    {
        while($true)
        {
            $urls = @()
            $urls += $wind.LocationUrl | Where-Object { $_ -and $_ -match "(^https?://.+)|(^ftp://)" }
            if (-not $urls) 
            {
                # "No urls found, refreshing window"
                $wind = (New-Object -ComObject Shell.Application).Windows() | Where-Object { $_.HWND -eq $handle }
                if (-not $wind)
                {
                    throw "Could not find IE window with handle: $handle"
                }
            }
            
            foreach ($url in $urls)
            {
                $urlPrefix = "{0}?{1}=" -f $RedirectUrl, $ExpectedSuccessParameter
                if (($url).StartsWith($urlPrefix))
                {
                    $code = $url -replace (".*$($ExpectedSuccessParameter)=") -replace ("&.*") #  | Out-File $outputAuth

                    return $code
                }
                elseif (($url).StartsWith($RedirectUrl + "?error="))
                {
                    $error = [System.Web.HttpUtility]::UrlDecode(($a.LocationUrl) -replace (".*error="))

                    throw $error
                }
            }
        }
    }
    finally
    {
        [WinApi]::KillProcess($handle)
    }
}

function Invoke-CodeGrantFlow
{
    param(
        [Parameter(HelpMessage='Redirect Uri', Mandatory = $true)]
        [ValidateNotNull()]
        [string]$RedirectUrl,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [Parameter(Mandatory = $true)]
        [string]$Resource,
        [bool]$AlwaysPrompt = $false
    )
    
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code

    $authorizationUrl = ("https://login.microsoftonline.com/{0}/oauth2/authorize?response_type=code&client_id={1}&redirect_uri={2}&resource={3}" -f $Tenant, $ClientId, $RedirectUrl, $Resource)
    if($AlwaysPrompt)
    {
        $authorizationUrl += "&prompt=select_account"
    }

    $code = Invoke-BrowserLogin -AuthorizationUrl $authorizationUrl -RedirectUrl $RedirectUrl

    if(-not $code)
    {
        throw "Code Grant Flow failed"
    }

    $url = "https://login.microsoftonline.com/{0}/oauth2/token" -f $Tenant
    $fields = @{
        grant_type = "authorization_code"
        client_id = $clientId
        code = $code
        redirect_uri = $RedirectUrl
        resource = $Resource
        client_secret = $clientSecret
    }
    $response = Invoke-RestMethod -Method Post -Uri $url -Body $fields

    $response
}

function Invoke-DeviceCodeFlow
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [Parameter(Mandatory = $true)]
        [string]$Resource
    )

    $postParams = @{
        resource = $Resource
        client_id = $ClientId
    }
    $url = "https://login.microsoftonline.com/{0}/oauth2/devicecode" -f $Tenant
    $response = Invoke-RestMethod -Method Post -Uri $url -Body $postParams

    if(-not $response.device_code)
    {
        throw "Device Code Flow failed"
    }

    $tokenResponse = $null
    $maxDate = (Get-Date).AddSeconds($response.expires_in)

    $url = "https://login.microsoftonline.com/{0}/oauth2/token" -f $Tenant
    $tokenParams = @{
        grant_type = "device_code"
        resource = $Resource
        client_id = "$ClientId"
        code = $response.device_code
    }
    while (!$tokenResponse -and (Get-Date) -lt $maxDate)
    {
        try
        {
            $tokenResponse = Invoke-RestMethod -Method Post -Uri $url -Body $tokenParams
        } 
        catch [System.Net.WebException], [Microsoft.PowerShell.Commands.HttpResponseException]
        {
            if ($_.Exception.Response -eq $null)
            {
                throw
            }
        
            $errBody = $null
            if($PSEdition -eq "Core") 
            {
                $errBody = ConvertFrom-Json ($_.ErrorDetails | Select-Object -ExpandProperty Message)
            }
            else
            {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $errBody = ConvertFrom-Json $reader.ReadToEnd();
            }
        
            if(-not $errBody -or $errBody.Error -ne "authorization_pending")
            {
                throw
            }

            Start-Sleep($response.interval)
            Write-Host -NoNewline "."
        }
    }

    $tokenResponse
}

function Invoke-ResourceOwnerPasswordGrantFlow
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [pscredential]$UserCredentials,
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [Parameter(Mandatory = $true)]
        [string]$Resource
    )

    $btsr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserCredentials.Password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($btsr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($btsr)

    $payload = @{
        grant_type = "password"
        client_id = $ClientId
        resource = $Resource
        username = $UserCredentials.UserName
        password = $plainPassword
        
    }
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" -Body $payload

    $response
}

function Invoke-AdminConsentForApplication
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [Parameter(Mandatory = $true)]
        [string]$RedirectUrl
    )
    # https://docs.microsoft.com/cs-cz/azure/active-directory/develop/v2-permissions-and-consent#using-the-admin-consent-endpoint

    $consentUrl = "https://login.microsoftonline.com/{0}/adminconsent?client_id={1}&state=12345&redirect_uri={2}" -f $Tenant, $ClientId, $RedirectUrl
    
    $response = Invoke-BrowserLogin -AuthorizationUrl $consentUrl -RedirectUrl $RedirectUrl -ExpectedSuccessParameter "admin_consent"

    if($response -ne "True")
    {
        throw "Admin consent failed"
    }
}
