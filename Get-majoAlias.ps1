[CmdletBinding()]
param (
    [Parameter(Position = 0, Mandatory = $true)]
    [mailaddress]
    $EmailAddress
)

Begin {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "Importing required Powershell modules ..."
    Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
    $coninfo = Get-ConnectionInformation
    Write-Verbose "Check if authentication to Exchange is ok ..."
    if ($coninfo.State -ne 'Connected') { 
        Throw "Sign in to Exchange before running this script. Connect-ExchangeOnline"
    }
    Write-Verbose "Using account $($coninfo.UserPrincipalName) to tenant $($coninfo.TenantID)"
}
Process {

    $retobj = New-Object -TypeName PSObject
    $emailfound = $null
    if (-not($emailfound)) {
        Write-Verbose "Searching Unifiedgroups (Microsoft 365 groups including Teams) ..."
        $emailfound = Get-UnifiedGroup -ResultSize Unlimited -Filter "EmailAddresses -like '*$emailaddress*'"
        if ($emailfound) {
            Add-Member -InputObject $retobj -MemberType NoteProperty -Name "Type" -Value "UnifiedGroup"
            Add-Member -InputObject $retobj -MemberType NoteProperty -Name "Data" -Value $emailfound
        }
    }
    if (-not($emailfound)) {
        Write-Verbose "Searching distributiongroups ..."
        $emailfound = Get-DistributionGroup -ResultSize Unlimited -Filter "EmailAddresses -like '*$emailaddress*'"
        if ($emailfound) {
            Add-Member -InputObject $retobj -MemberType NoteProperty -Name "Type" -Value "DistributionsGroup"
            Add-Member -InputObject $retobj -MemberType NoteProperty -Name "Data" -Value $emailfound
        }
    }
    if (-not($emailfound)) {
        Write-Verbose "Searching all user and shared mailboxes ..."
        $emailfound = Get-EXOMailbox -ResultSize Unlimited -Filter "EmailAddresses -like '*$emailaddress*'"
        if ($emailfound) {
            Add-Member -InputObject $retobj -MemberType NoteProperty -Name "Type" -Value "Mailbox"
            Add-Member -InputObject $retobj -MemberType NoteProperty -Name "Data" -Value $emailfound
        }
    }
    $stopwatch.Stop()
    
}
End {
    Write-Verbose "Elapsed time $($stopwatch.Elapsed)"
    $retobj
}