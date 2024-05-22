# PowerShell Scripts

This repository contains PowerShell scripts for managing outbound connectors in Exchange Online.

## Scripts

### Add-majoOutboundConnectorTLS.ps1

This script adds or updates an outbound connector in Exchange Online with TLS settings for specified external domains. If an outbound connector with the specified name already exists, the script updates the recipient domains of the connector. If the outbound connector does not exist, a new outbound connector is created.

#### Parameters

- `Domains`: Specifies an array of external domains for which TLS settings should be applied.
- `Identity`: Specifies the name of the outbound connector. Default value is 'External TLS 1'.
- `Comment`: Specifies a comment for the outbound connector. Default value is 'Outbound connector with force TLS settings for external domains.'

#### Example

```powershell
Add-majoOutboundConnectorTLS.ps1 -Domains "example.com", "contoso.com" -Identity "External TLS 2" -Comment "Outbound connector for TLS 2"
```
### Get-majoOutBoundConnectorTLS.ps1

This script retrieves outbound connectors with TLS settings and their recipient domains. It provides the option to filter by duplicate domains and specific connector identities or domains.

#### Parameters

- `OnlyDuplicateDomains`: Specifies whether to only return duplicate recipient domains. By default, all recipient domains are returned.
- `Identity`: Specifies the identity of the outbound connector to retrieve. If not specified, all outbound connectors are retrieved.
- `Domain`: Specifies the recipient domains to filter by. Only outbound connectors with matching recipient domains are returned.

#### Example

```powershell
Get-majoOutBoundConnectorTLS.ps1 -OnlyDuplicateDomains $true -Identity "Connector1" -Domain "example.com"