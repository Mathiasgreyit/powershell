<#
.SYNOPSIS
    Restores Exchange Online management role permissions for a specified user.

.DESCRIPTION
    This script is used to restore Exchange Online management role permissions by creating or using 
    an Azure AD application with the necessary Graph API permissions, and then assigning the 
    "Role Management" role to a specified user in Exchange Online. This is particularly useful 
    for emergency access scenarios where Exchange admin roles need to be restored.

    The script operates in two phases:
    1. If no ApplicationName is provided, it creates a new Azure AD application with required permissions
    2. If ApplicationName is provided, it uses the existing application to assign the role

.PARAMETER UserID
    The Object ID of the user who should receive the Exchange management role permissions.

.PARAMETER TenantId
    The Entra Tenant ID where the operations should be performed.

.PARAMETER ApplicationName
    Optional. The name of an existing Azure AD application to use. If not provided, a new application will be created.
    This is also use to rerun the script after giving admin consent to the application in Entra portal.

.PARAMETER Secret
    Optional. The client secret for the application. If not provided, a new secret will be generated.
    Sometimes the call using the newly created secret fails, then it can be rerun with the secret already generated

.EXAMPLE
    .\Set-ExchManageRoleGroup.ps1 -UserID "user-object-id" -TenantId "tenant-id"
    Creates a new application and prompts for admin consent.

.EXAMPLE
    .\Set-ExchManageRoleGroup.ps1 -UserID "user-object-id" -TenantId "tenant-id" -ApplicationName "RecoverExchangeAdminRole guid"
    Uses an existing application to assign the role.

.NOTES
    Requires the Microsoft.Graph PowerShell module and appropriate permissions.
    Admin consent is required for the created application before role assignment can proceed.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    $UserID,
    [Parameter(Mandatory = $true)]
    $TenantId,
    [Parameter()]
    $ApplicationName,
    [Parameter()]
    $secret
)

Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -tenantId $TenantId

if (-not $ApplicationName) {
    $ApplicationName = "RecoverExchangeAdminRole $(New-Guid)"
    try {
        $user = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$UserID" -Method Get -errorAction Stop
        if (-not $user) {
            Write-Error "User with ID $UserID not found."
            Throw "User not found with ID: $UserID"
        }
    }
    catch {
        Write-Error "Failed to retrieve user with ID $UserID. Error: $_"
        Throw "Failed to retrieve user with ID: $UserID"
    }

    Write-Output "Trying to create application with name: $ApplicationName ..."
    $app = New-MgApplication -DisplayName $ApplicationName -SignInAudience "AzureADMyOrg" -RequiredResourceAccess @{
        ResourceAppId  = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        ResourceAccess = @(
            @{
                Id   = "025d3225-3f02-4882-b4c0-cd5b541a4e80" # RoleManagement.ReadWrite.Exchange
                Type = "Role"
            }
        )
    }
    Write-Output "Application created with ID: $($app.Id)"
    Write-Output "Applicationname is: $ApplicationName"
    Write-Output "Manually grant admin consent to the application in Azure AD portal."
    Write-Output "After that, rerun this script with the paramaeter -ApplicationName '$ApplicationName' to continue."
    Break
}
else {

    Write-Output "Looking for existing application with name: $ApplicationName ..."
    try {
        # Query for the application by display name
        $filter = "displayName eq '$ApplicationName'"
        $appResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$filter" -Method Get -ErrorAction Stop
    
        # Check if any applications were found
        if ($appResponse.value.Count -eq 0) {
            Write-Error "Application with name '$ApplicationName' not found."
            Throw "Application not found with name: $ApplicationName"
        }
        elseif ($appResponse.value.Count -gt 1) {
            Write-Warning "Multiple applications found with name '$ApplicationName'. Using the first one."
        }
    
        # Get the first application from the results
        $app = $appResponse.value[0]
        Write-Output "Found existing application with ID: $($app.id)"
    }
    catch {
        Write-Error "Failed to retrieve application with name '$ApplicationName'. Error: $_"
        Throw "Failed to retrieve application: $_"
    }
    if ($secret) {
        Write-Output "Using provided secret for application: $ApplicationName ..."
        $passwordCredential = @{
            SecretText = $secret
        }
    }
    else {
        Write-Output "No secret provided, generating new secret for application: $ApplicationName ..."
        Write-Output "Trying to generate client secret for application: $ApplicationName ..."
        $requestBody = @{
            passwordCredential = @{
                displayName = "ClientSecret"
                endDateTime = (Get-Date).AddDays(1).ToUniversalTime().ToString("o")
            }
        } | ConvertTo-Json

        $passwordCredential = Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/addPassword" `
            -Body $requestBody -ErrorAction Stop
        Write-Host "Secret generated: $($passwordCredential.SecretText)"
        Start-Sleep -Seconds 3
    }

    # Get accesstoken for the application
    Write-Output "Getting access token for application: $ApplicationName ..."
    $payload = @{
        grant_type    = 'client_credentials'  # Replace with actual principal ID
        client_id     = $app.appID #$app.AppId       # Replace with actual role definition ID
        client_secret = $passwordCredential.SecretText # $passwordCredential.SecretText          # Replace with actual scope
        scope         = "https://graph.microsoft.com/.default"
    }
    $uri = "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token"
    try {
        $accesstoken = Invoke-RestMethod -Uri $uri -Method Post -Body $payload -ErrorAction Stop
    }
    catch {
        Write-Output "Failed to retrieve access token. Try rerunning the script with a the parameter -Secret and supply the secret generated."
        Throw "Failed to retrieve access token: $_"
    }
    Write-Output "Access token retrieved successfully."

    # Set up headers for API calls with the appplication token
    $headers = @{
        "Authorization" = "Bearer $($accesstoken.access_token)"
        "Content-Type"  = "application/json"
    }

    # Get all role definitions for Exchange
    try {
        $definitions = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/roleManagement/exchange/roleDefinitions" `
            -Method Get -Headers $headers -ErrorAction Stop
    }
    catch {
        Write-Output "Failed to retrieve role definitions. Make sure you have given adminconsent to application $($app.DisplayName)."
        Throw "Failed to retrieve role definitions: $_"
    }
    # Get correct role definition ID
    foreach ($definition in $definitions.value) {
        if ($definition.description -like "This role enables administrators to manage management role groups*") {
            $roleDefinitionId = $definition.id
            Write-Output "Found role definition ID: $roleDefinitionId"
            break
        }
    }

    # Create payload for role assignment
    $payload = @{
        principalId      = "/Users/$UserID"  # Replace with actual principal ID
        roleDefinitionId = $roleDefinitionId       # Replace with actual role definition ID
        directoryScopeId = "/"           # Replace with actual scope
    } | ConvertTo-Json

    # Assign Role Management role to the user
    $assignmentResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/roleManagement/exchange/roleAssignments" `
        -Method Post -Headers $headers -Body $payload

    # Give some helpful insights to the user
    Write-Output "Role assignment created with ID: $($assignmentResponse.id)"
    Write-Output "Script completed successfully."
    Write-Output "You can view and remove this role using ExchangeOnlineManagement module and command Get-ManagementRoleAssignment -Role 'Role Management'"
    Write-Output "and remve with Remove-ManagementRoleAssignment"
}
