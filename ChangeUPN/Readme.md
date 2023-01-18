# Change UPN

## Script ChangeUPN.ps1

This script purpose is to change UPN on AD DS on-prem users. It also changes proxyAddresses

Example (to change 1 user)

Get-ADUser -Identity User1 -Properties proxyAddresses | % {.\ChangeUPN.ps1 -UserObject $_ -OldDomainx 'olddomain.com' -NewDomainSuffix 'newdomain.com'}

Example (to change for multiple users)

Get-ADUser -filter * -SearchBase "OU=TestUPNChange,OU=Users,OU=AD,DC=ad,DC=langeben,DC=se" -Properties proxyAddresses | % {.\ChangeUPN.ps1 -UserObject $_ -OldDomainx 'olddomain.com' -NewDomainSuffix 'newdomain.com'}