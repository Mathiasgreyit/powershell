#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Finds usage of the "memberOf" operator in dynamic membership rules across Entra ID.
.DESCRIPTION
    Scans dynamic groups, dynamic administrative units, and entitlement management
    auto-assignment policies for rules containing the "memberOf" operator.
    Requires Microsoft.Graph.Authentication module and appropriate read permissions.
#>

[CmdletBinding()]
param(
    [switch]$ConnectGraph
)

$ErrorActionPreference = 'Stop'

$requiredScopes = @(
    'Group.Read.All',
    'AdministrativeUnit.Read.All',
    'EntitlementManagement.Read.All'
)

if ($ConnectGraph) {
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
}

$context = Get-MgContext
if (-not $context) {
    Write-Error "Not connected to Microsoft Graph. Run with -ConnectGraph or call Connect-MgGraph first."
    return
}

Write-Host "Connected as: $($context.Account)" -ForegroundColor Cyan
Write-Host ""

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# --- Dynamic Membership Groups ---
$allGroups = [System.Collections.Generic.List[hashtable]]::new()
$groupsUri = 'https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(g:g eq ''DynamicMembership'')&$select=id,displayName,membershipRule,membershipRuleProcessingState&$top=999'

Write-Progress -Activity 'Scanning for memberOf usage' -Status 'Fetching dynamic groups...' -PercentComplete 0
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $groupsUri
    foreach ($g in $response.value) { $allGroups.Add($g) }
    $groupsUri = $response.'@odata.nextLink'
} while ($groupsUri)

for ($i = 0; $i -lt $allGroups.Count; $i++) {
    $group = $allGroups[$i]
    Write-Progress -Activity 'Scanning for memberOf usage' -Status "Checking group $($i + 1) of $($allGroups.Count)" -PercentComplete (($i + 1) / $allGroups.Count * 33)
    if ($group.membershipRule -and $group.membershipRule -match '\bmemberOf\b') {
        $results.Add([PSCustomObject]@{
            Type           = 'Dynamic Group'
            Id             = $group.id
            DisplayName    = $group.displayName
            ProcessingState = $group.membershipRuleProcessingState
            MembershipRule = $group.membershipRule
        })
    }
}

# --- Dynamic Administrative Units ---
$allAUs = [System.Collections.Generic.List[hashtable]]::new()
$auUri = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName,membershipRule,membershipRuleProcessingState,membershipType&$top=999'

Write-Progress -Activity 'Scanning for memberOf usage' -Status 'Fetching administrative units...' -PercentComplete 33
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $auUri
    foreach ($a in $response.value) { $allAUs.Add($a) }
    $auUri = $response.'@odata.nextLink'
} while ($auUri)

for ($i = 0; $i -lt $allAUs.Count; $i++) {
    $au = $allAUs[$i]
    Write-Progress -Activity 'Scanning for memberOf usage' -Status "Checking AU $($i + 1) of $($allAUs.Count)" -PercentComplete (33 + ($i + 1) / [Math]::Max($allAUs.Count, 1) * 17)
    if ($au.membershipType -eq 'Dynamic' -and $au.membershipRule -and $au.membershipRule -match '\bmemberOf\b') {
        $results.Add([PSCustomObject]@{
            Type           = 'Dynamic Administrative Unit'
            Id             = $au.id
            DisplayName    = $au.displayName
            ProcessingState = $au.membershipRuleProcessingState
            MembershipRule = $au.membershipRule
        })
    }
}

# --- Entitlement Management Auto-Assignment Policies ---
$allPolicies = [System.Collections.Generic.List[hashtable]]::new()
$policiesUri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies?$select=id,displayName&$top=999'

Write-Progress -Activity 'Scanning for memberOf usage' -Status 'Fetching assignment policies...' -PercentComplete 50
do {
    $polListResponse = Invoke-MgGraphRequest -Method GET -Uri $policiesUri
    foreach ($p in $polListResponse.value) { $allPolicies.Add($p) }
    $policiesUri = $polListResponse.'@odata.nextLink'
} while ($policiesUri)

for ($i = 0; $i -lt $allPolicies.Count; $i++) {
    $polSummary = $allPolicies[$i]
    Write-Progress -Activity 'Scanning for memberOf usage' -Status "Checking policy $($i + 1) of $($allPolicies.Count)" -PercentComplete (50 + ($i + 1) / [Math]::Max($allPolicies.Count, 1) * 50)
    try {
        $policyUri = "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/$($polSummary.id)"
        $policy = Invoke-MgGraphRequest -Method GET -Uri $policyUri

        if (-not $policy.specificAllowedTargets) { continue }

        foreach ($target in $policy.specificAllowedTargets) {
            if ($target.'@odata.type' -eq '#microsoft.graph.attributeRuleMembers' -and
                $target.membershipRule -and
                $target.membershipRule -match '\bmemberOf\b') {

                $results.Add([PSCustomObject]@{
                    Type           = 'Auto-Assignment Policy'
                    Id             = $policy.id
                    DisplayName    = $policy.displayName
                    ProcessingState = 'N/A'
                    MembershipRule = $target.membershipRule
                })
            }
        }
    }
    catch {
        Write-Warning "Could not read assignment policy '$($polSummary.id)': $_"
    }
}

Write-Progress -Activity 'Scanning for memberOf usage' -Completed

# --- Output ---
Write-Host ""
if ($results.Count -eq 0) {
    Write-Host "No usage of 'memberOf' operator found." -ForegroundColor Green
}
else {
    Write-Host "Found $($results.Count) rule(s) using 'memberOf':" -ForegroundColor Red
}

$results
