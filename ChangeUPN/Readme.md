# Change UPN

## Script ChangeUPN.ps1

This script purpose is to change UPN on AD DS on-prem users. It also changes proxyAddresses

Example (to change 1 user)

*Get-ADUser -Identity User1 -Properties proxyAddresses | ForEach-Object {.\ChangeUPN.ps1 -UserObject $_ -OldDomainSuffix 'olddomain.com' -NewDomainSuffix 'newdomain.com'}*

Example (to change for multiple users)

*Get-ADUser -filter * -SearchBase "OU=TestUPNChange,OU=Users,DC=contoso,DC=com" -Properties proxyAddresses | ForEach-Object {.\ChangeUPN.ps1 -UserObject $_ -OldDomainSuffix 'olddomain.com' -NewDomainSuffix 'newdomain.com'}*  

Example changing users UPN for users that has no proxyAddresses (ie proxyAddresses equals null)

*Get-ADUser -filter * -SearchBase "OU=TestUPNChange,OU=Users,DC=contoso,DC=com" -Properties proxyAddresses | ForEach-Object {.\ChangeUPN.ps1 -UserObject $_ -OldDomainSuffix 'olddomain.com' -NewDomainSuffix 'newdomain.com' -OverrideNullProxyaddresses}*  

Example changing user when you want to exclude a sub OU under your ldap searchbase. You might have a searchbase 

*Get-ADUser -filter * -SearchBase "OU=TestUPNChange,OU=Users,DC=contoso,DC=com" -Properties proxyAddresses | Where-Object {$_.DistinguishedName -notlike "\*OU=DontIncludeThisOne\*"} | ForEach-Object {.\ChangeUPN.ps1 -UserObject $_ -OldDomainSuffix 'olddomain.com' -NewDomainSuffix 'newdomain.com'}*  