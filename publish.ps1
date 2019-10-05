$certs = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
$moduleName = "OAuth2Toolkit"
$nugetKey = Read-Host -Prompt "Please provide API Key"

$parent = [System.IO.Path]::GetTempPath()
$name = [System.IO.Path]::GetRandomFileName()
$tmp = New-Item -ItemType Directory -Path (Join-Path $parent $name)
New-Item -ItemType Directory -Path $tmp.FullName -Name $moduleName
$destinationDir = Join-Path $tmp.FullName $moduleName
Copy-Item ".\src\*" $destinationDir -Recurse

Set-AuthenticodeSignature -Certificate $certs -TimestampServer "http://timestamp.digicert.com" -IncludeChain All -FilePath "$($destinationDir)\Oauth2Toolkit.psm1"

Publish-Module -Path $destinationDir -NuGetApiKey $nugetKey
