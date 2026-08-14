[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [switch]$DownloadCss
)

$forbiddenProperties = @(
    'position'
    'margin'
    'transform'
    'opacity'
    'overflow'
    'filter'
    'pointer-events'
    'clip-path'
    'mix-blend-mode'
    'translate'
)
Write-Host "Checking custom CSS for tenant: $TenantId" -ForegroundColor Cyan
Write-Host "Forbidden CSS properties to check: $($forbiddenProperties -join ', ')" -ForegroundColor Cyan
Write-Host "Based on information from Microsoft documentation, these properties are not supported in custom CSS for Microsoft 365 branding. See https://techcommunity.microsoft.com/blog/microsoft-entra-blog/microsoft-entra-id-enhances-security-of-branded-sign-ins/4537471" -ForegroundColor Cyan

$authstatus = Get-mgcontext
if (-not $authstatus) {
    Write-Host "Not authenticated to Microsoft Graph."
    Connect-MgGraph -Scopes "Organization.Read.All" -TenantId $TenantId -erroraction Stop
}elseif ($authstatus.TenantId -ne $TenantId) {
    Write-Host "Authenticated to a different tenant. Please authenticate to the correct tenant."
    Connect-MgGraph -Scopes "Organization.Read.All" -TenantId $TenantId -erroraction Stop
}

$brandingUrl = "https://graph.microsoft.com/v1.0/organization/$TenantId/branding"
$branding = Invoke-MgGraphRequest -Method GET -Uri $brandingUrl

if (-not $branding.customCSSRelativeUrl) {
    Write-Host "No custom CSS configured for this tenant." -ForegroundColor Yellow
    return
}

$cssUrl = "https://" + $branding.cdnList[0] + "/" + $branding.customCSSRelativeUrl
Write-Host "Downloading CSS from: $cssUrl"

$css = Invoke-RestMethod -Uri $cssUrl -erroraction Stop
if ($css) {
    Write-Host "CSS downloaded successfully. Showing first 5 lines:" -ForegroundColor Green
    # Display the first 5 lines of the CSS for verification
    $cssLines = $css -split "`n"
    $cssLines[0..4] | ForEach-Object { Write-Host $_ }  
}

if ($DownloadCss) {
    $outputFile = Join-Path $PWD "custom-branding.css"
    $css | Out-File -FilePath $outputFile -Encoding utf8
    Write-Host "`nCSS saved to: $outputFile" -ForegroundColor Green
    return
}

$found = @()
$cssLines = $css -split "`n"
foreach ($prop in $forbiddenProperties) {
    $pattern = "(?i)(^|[{;}\s])$([regex]::Escape($prop))\s*:"
    for ($i = 0; $i -lt $cssLines.Count; $i++) {
        if ($cssLines[$i] -match $pattern) {
            $found += [PSCustomObject]@{ Property = $prop; Line = $i + 1; Content = $cssLines[$i].Trim() }
        }
    }
}

if ($found.Count -gt 0) {
    Write-Host "`nForbidden CSS properties found:" -ForegroundColor Red
    $found | ForEach-Object { Write-Host "  - Line $($_.Line): $($_.Property)  [$($_.Content)]" -ForegroundColor Red }
    exit 1
}
else {
    Write-Host "`nNo forbidden CSS properties found. CSS is compliant." -ForegroundColor Green
}
