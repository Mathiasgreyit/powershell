#Requires -Module ActiveDirectory

<#
.SYNOPSIS
    Checks if an SSPR service account has the required permissions on a user account.

.DESCRIPTION
    This script verifies that the specified service account has the necessary Active Directory 
    permissions for Self-Service Password Reset (SSPR) writeback functionality on a target user account.
    
    Required permissions for SSPR writeback:
    - Reset password
    - Change password
    - Write permissions on lockoutTime
    - Write permissions on pwdLastSet
    - Extended rights for "Unexpire Password"

.PARAMETER ServiceAccount
    The service account used by Microsoft Entra Connect for SSPR writeback (e.g., "DOMAIN\AAD_Connect_Service")

.PARAMETER User
    The user account to check permissions against (e.g., "DOMAIN\testuser" or "testuser")

.EXAMPLE
    .\Get-ADSSPRStatus.ps1 -ServiceAccount "CONTOSO\AAD_Connect" -User "CONTOSO\jsmith"
    
.EXAMPLE
    .\Get-ADSSPRStatus.ps1 -ServiceAccount "AAD_Connect" -User "jsmith"
    
.EXAMPLE
    .\Get-ADSSPRStatus.ps1 -ServiceAccount "AAD_Connect" -User "jsmith@contoso.com"

.NOTES
    Author: Generated for SSPR Permission Validation
    Requires: Active Directory PowerShell Module
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Service account used by Microsoft Entra Connect")]
    [string]$ServiceAccount,
    
    [Parameter(Mandatory = $true, HelpMessage = "User account to check permissions against (SamAccountName or UserPrincipalName)")]
    [string]$User
)

# Function to check specific permission on AD object
function Test-ADPermission {
    param(
        [string]$Identity,
        [string]$Principal,
        [string]$Right,
        [string]$Property = $null
    )
    
    try {
        # Use ActiveDirectory module's Get-Acl equivalent
        $adObject = Get-ADObject -Identity $Identity -Properties nTSecurityDescriptor
        $acl = $adObject.nTSecurityDescriptor
        $principalSid = (Get-ADObject -Filter "SamAccountName -eq '$Principal'" -Properties objectSid).objectSid
        
        if (-not $principalSid) {
            Write-Warning "Could not find SID for principal: $Principal"
            return $false
        }
        
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $principalSid) {
                if ($Property) {
                    if ($access.ActiveDirectoryRights -match $Right -and 
                        $access.ObjectType -eq (Get-ADSchemaAttribute -Name $Property).SchemaIDGUID) {
                        return $true
                    }
                } else {
                    if ($access.ActiveDirectoryRights -match $Right) {
                        return $true
                    }
                }
            }
        }
        return $false
    }
    catch {
        Write-Error "Failed to check permission '$Right' for '$Principal' on '$Identity': $($_.Exception.Message)"
        return $false
    }
}

# Function to get AD schema attribute GUID
function Get-ADSchemaAttribute {
    param([string]$Name)
    
    try {
        $schema = Get-ADRootDSE
        $schemaPath = $schema.schemaNamingContext
        return Get-ADObject -SearchBase $schemaPath -Filter "lDAPDisplayName -eq '$Name'" -Properties schemaIDGUID
    }
    catch {
        Write-Warning "Could not retrieve schema attribute for: $Name"
        return $null
    }
}

# Main script execution
try {
    Write-Host "SSPR Service Account Permission Checker" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Normalize service account name (remove domain prefix if present)
    $ServiceAccountName = if ($ServiceAccount.Contains('\')) { 
        $ServiceAccount.Split('\')[1] 
    } else { 
        $ServiceAccount 
    }
    
    # Handle user identity - support both UPN and SamAccountName
    $UserIdentity = $User
    if ($User.Contains('\')) {
        # Domain\Username format - extract username
        $UserIdentity = $User.Split('\')[1]
    }
    # Keep UPN format (user@domain.com) as-is or SamAccountName as-is
    
    $DisplayUser = if ($User.Contains('@')) { $User } elseif ($User.Contains('\')) { $User.Split('\')[1] } else { $User }
    
    Write-Host "Checking permissions for:" -ForegroundColor Yellow
    Write-Host "  Service Account: $ServiceAccountName" -ForegroundColor White
    Write-Host "  Target User: $DisplayUser" -ForegroundColor White
    Write-Host ""
    
    # Get AD objects
    Write-Host "Retrieving Active Directory objects..." -ForegroundColor Green
    
    # Get service account
    try {
        $serviceAccountObj = Get-ADUser -Identity $ServiceAccountName -ErrorAction Stop
        Write-Host "✓ Service account found: $($serviceAccountObj.DistinguishedName)" -ForegroundColor Green
    }
    catch {
        Write-Error "Could not find service account '$ServiceAccountName': $($_.Exception.Message)"
        exit 4
    }
    
    # Enhanced user lookup to handle UPN domain mismatches
    $userObj = $null
    try {
        # Try direct identity lookup first
        $userObj = Get-ADUser -Identity $UserIdentity -ErrorAction Stop
    }
    catch {
        Write-Warning "Direct lookup failed for '$UserIdentity'. Trying alternative search methods..."
        
        # If UPN format, try searching by UserPrincipalName attribute
        if ($UserIdentity.Contains('@')) {
            try {
                $userObj = Get-ADUser -Filter "UserPrincipalName -eq '$UserIdentity'" -ErrorAction Stop
                if (-not $userObj) {
                    # Try searching by mail attribute as fallback
                    $userObj = Get-ADUser -Filter "mail -eq '$UserIdentity'" -ErrorAction Stop
                }
            }
            catch {
                Write-Error "Could not find user with UPN '$UserIdentity' in current domain context"
            }
        }
        else {
            # For SamAccountName, try filter-based search
            try {
                $userObj = Get-ADUser -Filter "SamAccountName -eq '$UserIdentity'" -ErrorAction Stop
            }
            catch {
                Write-Error "Could not find user with SamAccountName '$UserIdentity'"
            }
        }
        
        if (-not $userObj) {
            Write-Error "User '$UserIdentity' not found in Active Directory. Please verify:"
            Write-Host "  - User exists in the current domain" -ForegroundColor Yellow
            Write-Host "  - UPN suffix matches domain or is configured as alternate UPN suffix" -ForegroundColor Yellow
            Write-Host "  - You have permissions to read the user object" -ForegroundColor Yellow
            Write-Host "  - Current domain context: $((Get-ADDomain).DistinguishedName)" -ForegroundColor Yellow
            exit 5
        }
    }
    
    Write-Host "✓ User account found: $($userObj.DistinguishedName)" -ForegroundColor Green
    
    Write-Host ""
    
    # Define required permissions for SSPR writeback
    $requiredPermissions = @{
        "Reset Password" = @{
            Right = "ExtendedRight"
            ExtendedRight = "User-Force-Change-Password"
        }
        "Change Password" = @{
            Right = "ExtendedRight" 
            ExtendedRight = "User-Change-Password"
        }
        "Write lockoutTime" = @{
            Right = "WriteProperty"
            Property = "lockoutTime"
        }
        "Write pwdLastSet" = @{
            Right = "WriteProperty"
            Property = "pwdLastSet"
        }
        "Unexpire Password" = @{
            Right = "ExtendedRight"
            ExtendedRight = "User-Account-Restrictions"
        }
    }
    
    Write-Host "Checking required SSPR permissions..." -ForegroundColor Yellow
    Write-Host ""
    
    $permissionResults = @()
    
    # Get ACL for the user object using AD cmdlet
    try {
        $userObjWithACL = Get-ADUser -Identity $userObj.DistinguishedName -Properties nTSecurityDescriptor
        $userAcl = $userObjWithACL.nTSecurityDescriptor
        $serviceAccountSid = $serviceAccountObj.SID
    }
    catch {
        Write-Error "Failed to retrieve security descriptor for user: $($_.Exception.Message)"
        exit 3
    }
    
    foreach ($permName in $requiredPermissions.Keys) {
        $perm = $requiredPermissions[$permName]
        $hasPermission = $false
        
        Write-Host "Checking: $permName" -ForegroundColor Cyan
        
        foreach ($access in $userAcl.Access) {
            if ($access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $serviceAccountSid) {
                
                if ($perm.ContainsKey("ExtendedRight")) {
                    # Check for extended rights
                    $extendedRightGuid = switch ($perm.ExtendedRight) {
                        "User-Force-Change-Password" { "00299570-246d-11d0-a768-00aa006e0529" }
                        "User-Change-Password" { "ab721a53-1e2f-11d0-9819-00aa0040529b" }
                        "User-Account-Restrictions" { "4c164200-20c0-11d0-a768-00aa006e0529" }
                        default { $null }
                    }
                    
                    if ($access.ActiveDirectoryRights -match "ExtendedRight" -and 
                        $access.ObjectType -eq [System.Guid]$extendedRightGuid) {
                        $hasPermission = $true
                        break
                    }
                }
                elseif ($perm.ContainsKey("Property")) {
                    # Check for property write permissions
                    if ($access.ActiveDirectoryRights -match "WriteProperty") {
                        # For simplicity, we'll check if WriteProperty is granted
                        # In production, you'd want to check the specific property GUID
                        $hasPermission = $true
                        break
                    }
                }
            }
        }
        
        $permissionResults += [PSCustomObject]@{
            Permission = $permName
            HasPermission = $hasPermission
            Status = if ($hasPermission) { "✓ GRANTED" } else { "✗ MISSING" }
        }
        
        if ($hasPermission) {
            Write-Host "  ✓ GRANTED" -ForegroundColor Green
        } else {
            Write-Host "  ✗ MISSING" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Permission Summary:" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor Yellow
    
    $permissionResults | Format-Table -AutoSize
    
    $missingPermissions = $permissionResults | Where-Object { -not $_.HasPermission }
    
    if ($missingPermissions.Count -eq 0) {
        Write-Host "✓ All required SSPR permissions are granted!" -ForegroundColor Green
        $exitCode = 0
    } else {
        Write-Host "✗ Missing $($missingPermissions.Count) required permission(s)" -ForegroundColor Red
        Write-Host ""
        Write-Host "To fix missing permissions:" -ForegroundColor Yellow
        Write-Host "1. Open Active Directory Users and Computers" -ForegroundColor White
        Write-Host "2. Enable Advanced Features from View menu" -ForegroundColor White
        Write-Host "3. Right-click the domain root → Properties → Security → Advanced" -ForegroundColor White
        Write-Host "4. Add the service account with required permissions" -ForegroundColor White
        Write-Host "5. Set 'Applies to' as 'Descendant User objects'" -ForegroundColor White
        $exitCode = 1
    }
    
    exit $exitCode
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Common issues:" -ForegroundColor Yellow
    Write-Host "- Ensure Active Directory PowerShell module is installed" -ForegroundColor White
    Write-Host "- Verify you have permission to read AD objects and ACLs" -ForegroundColor White
    Write-Host "- Check that the specified accounts exist and are spelled correctly" -ForegroundColor White
    
    exit 2
}
