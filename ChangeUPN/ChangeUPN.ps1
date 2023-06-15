[CmdletBinding()]
    param (
        [Parameter(Position=0,Mandatory=$true)]
        [psobject]
        $UserObject,
        [Parameter(Position=1,Mandatory=$true)]
        [String]
        $OldDomainSuffix,
        [Parameter(Position=2,Mandatory=$true)]
        [String]
        $NewDomainSuffix,
        [Parameter(Position=3,Mandatory=$false)]
        [Switch]
        $OverrideNullProxyaddresses # If proxyAddresses are null, then use this switch
    )

begin {
    try {
        Import-Module -Name ActiveDirectory -ErrorAction Stop
    }
    catch {
        <#Do this if a terminating exception happens#>
        Break
    }

    # Validating OldDomainSuffix and NewDomainSuffix
    $UPNSuffixes = @()
    $UPNSuffixes += ((Get-ADForest).Name)
    foreach ($suffix in ((Get-ADForest).UPNSuffixes)){
        $UPNSuffixes += $suffix
    }
    if ($UPNSuffixes.Count -eq 0) {
        Throw "Couldnt find any UPNSuffixes in domain"; Break
    }
    if ($UPNSuffixes -contains $NewDomainSuffix -and $UPNSuffixes -contains $OldDomainSuffix) {
        # All good
    }else{
        Throw "Either $OldDomainSuffix or $NewDomainSuffix does not exists in the AD DS Forest. Check this with Get-ADForest (name and UPNSuffix)."
    }
}     

process {
    if ($UserObject.GetType().name -ne 'ADUser') {
        Throw "Must be a ADUser object"  
        Write-Error "ERROR: Must be a ADUser object"; Break
    }
    if (-not($OverrideNullProxyaddresses)) {
    # Validating that property proxyAddresses is supplied
        if ($UserObject.PropertyNames -notcontains 'proxyAddresses') {
            Throw "User $($UserObject.UserPrincipalName) must have proxyAddress! Do this by specifying Get-ADUser -Property proxyAddresses. It can also be that the user has null as proxyAddresses, use OverrideNullProxyaddresses"; Break
        }
    }

    $shouldChangeproxy = $false
    if (($UserObject.UserPrincipalName).Split('@')[1] -eq $OldDomainSuffix ) {
        Write-Output "User $($UserObject.UserPrincipalName) has the old UPN. Changing..."
        $newuserupn = "$(($UserObject.UserPrincipalName).Split('@')[0])@$NewDomainSuffix"
        Set-ADUser -Identity $UserObject -UserPrincipalName $newuserupn -ErrorAction Stop
        $shouldChangeproxy = $true # If we change UPN then also change proxyAddress
    }else{
        Write-Output "User $($UserObject.UserPrincipalName) doesnt match the OldDomainSuffix. Skipping..."
    }

    # manipulating proxyAddresses
    if ($UserObject.proxyAddresses -and $shouldChangeproxy) {
        $newproxy = $null; $oldproxy = $null
        foreach ($m in $UserObject.proxyAddresses) {
            $oldproxy = $oldproxy + "$m,"
            if ($m -clike 'SMTP:*' -and $m -ne "SMTP:$newuserupn") {
                $newproxy = $newproxy + "$($m.ToLower()),"
            }else{
                if ($m -ne "smtp:$newuserupn") { # Avoiding getting double mail adresses
                    $newproxy = $newproxy + "$m,"
                }
            }
        }
        if ($UserObject.proxyAddresses -cnotcontains "SMTP:$newuserupn") {
            
            $newproxy = $newproxy + "SMTP:$newuserupn"    
        }
        $newproxy = $newproxy.trimend(','); $oldproxy = $oldproxy.trimend(',')
        Write-Output "Modifying proxyAddresses for user $($UserObject.UserPrincipalName)."
        Write-Output "User $($UserObject.UserPrincipalName) Old proxyAddresses: $oldproxy"
        Write-Output "New $($UserObject.UserPrincipalName) proxyAddresses: $newproxy"
        Set-ADUser -Identity $UserObject -replace @{ProxyAddresses=$newproxy -split ","}
        Set-ADUser -Identity $UserObject -replace @{mail=$newuserupn}
    }else{
        Write-Output "Either the user has no proxyAddresses or OldDomainSuffix doesnt match. Skipping..."
    }

}

end {
    
}