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