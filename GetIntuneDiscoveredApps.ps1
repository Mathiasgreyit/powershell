<#
    Get Intune Discovered Apps
    Requires Powershell 7

    Returns methods see
    https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview?view=graph-rest-beta

    Work in progress. Only looks for Windows apps (not Andorid or Ios)

    Permissions.
    DeviceManagementManagedDevices.Read.All

#>

param (
    # Parameter help description
    [Parameter(Mandatory=$false,HelpMessage="Enter the Directory")]
    [ValidateScript({
        if(Test-Path -Path $_ -PathType Container){
            return $true # Found directory
        }else{
            throw "$_ directory does not exist. Must be a valid directory" # didnt find directory
        }
    })]
    [System.IO.FileInfo]$Path = $env:HOMEPATH,
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    [Parameter(Mandatory=$false)]
    [string]$AppDisplayName, 
    [Parameter(Mandatory=$false)]
    [ValidateSet('All','WindowsRt','Android','Ios')]
    [string]$DeviceType = 'All',
    [Parameter(Mandatory=$false)]
    [ValidateSet('Excel','Csv')]
    [string]$Output,
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,1000)]
    [int]$First,
    [Parameter(Mandatory=$false)]
    [switch]
    $TabellFormatering
)

# Check if Ps 7
if ($PSVersionTable.PSEdition -ne 'Core') {
    Write-Output "Must be run in Powershell Core (7.x)! Aborting."
    Break
}

# Load required modules (missing any Install-Module -Name nameofmodule). All is hosted on PSGallery
Import-Module Microsoft.Graph.Authentication -MinimumVersion 1.27.0 -ErrorAction Stop


if ($Output -eq 'Excel') {
    Import-Module ImportExcel -ErrorAction Stop
}

# Setup connection
$resp = Get-MgContext -ErrorAction Stop
if (-not($resp)) {
    Throw "Make sure you have signed in to Graph! Connect-MgGraph -Scopes 'Directory.AccessAsUser.All,DeviceManagementManagedDevices.Read.All'"; Break
}
if ($TenantId -and $resp.TenantId -ne $TenantId) {
    Throw "Make sure you have signed in to the correct tenant!"; Break
}
if ($resp.scopes -notcontains 'Directory.AccessAsUser.All' -or $resp.scopes -notcontains 'DeviceManagementManagedDevices.Read.All') {
    Throw "Make sure you have the right permissions/scope in Graph! Connect-MgGraph -Scopes 'Directory.AccessAsUser.All,DeviceManagementManagedDevices.Read.All' "; Break
}

Select-MgProfile -Name beta

# Script start

# Get current date and create filename
$date = Get-Date -Format "yyyy-MM-dd"
$filename = "IntuneDiscoveredapps_$date.xlsx"

# Get all Intune managed devices
$devices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
do {
    $result = Invoke-MgGraphRequest -Method get -Uri $uri
    if ($result.value) {
        $devices += $result.value
    }else{
        $devices = $result
    }
    $uri = $result.'@odata.nextLink'
}until (!($uri))

# Select choosen devicetype 
if ($DeviceType -eq 'All') {
    $deviceselected = $devices 
}else{
    $deviceselected = $devices | Where-Object {$_.deviceType -eq $DeviceType}
}

# Iterate over all Intune managed devices
$retarr = @(); $count = 1
foreach ($d in $deviceselected) {
    if ($First -gt 0 -and $count -gt $First) {continue} # Skip if reached First counter
    if ($First -eq 0) {
        [Int32]$status = $($count/$deviceselected.Count)*100 # Calculate procent done
    }else{
        [Int32]$status = $($count/$First)*100 # Calculate procent done
    }
    Write-Progress -Activity "Iterating devices.." -Status "Working : $status %" -PercentComplete $status
    $count++

    $allapps = Invoke-MgGraphRequest -Method get -Uri "https://graph.microsoft.com/beta/deviceManagement/manageddevices('$($d.id)')?`$expand=detectedApps"
    $selectedapps = $allapps.detectedApps | Where-Object {$_.displayName -like "*$AppDisplayName*"}
    
    foreach ($app in $selectedapps) {
        $myobj = New-Object -TypeName PSObject
        Add-Member -InputObject $myobj -MemberType NoteProperty -Name ApplicationName -Value $app.displayName
        Add-Member -InputObject $myobj -MemberType NoteProperty -Name ApplicationID -Value $app.id
        Add-Member -InputObject $myobj -MemberType NoteProperty -Name DeviceName -Value $d.deviceName
        Add-Member -InputObject $myobj -MemberType NoteProperty -name Version -Value $app.version
        $retarr += $myobj
    }
}

# Returns output based on selection, but always Out-Gridview and to output stream.
if ($Output -eq 'Excel') {
    if ($TabellFormatering) {  # Wants Table formatting
        $retarr | Export-Excel -Path (Join-Path $Path $filename) -TableName TestTabell -FreezeTopRow # What the hell does TestTabell do?
    }else{
        $retarr | Export-Excel -Path (Join-Path $Path $filename)
    }
    Write-Output "$filename created in directory $Path"
}
if ($Output -eq 'Csv') {
    $retarr | Export-Csv -Path (Join-Path $Path $filename) -Encoding UTF8
}
$retarr