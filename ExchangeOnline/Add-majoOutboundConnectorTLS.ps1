<#
.SYNOPSIS
    Adds or updates an outbound connector with TLS settings for specified external domains.

.DESCRIPTION
    This script adds or updates an outbound connector in Exchange Online with TLS settings for specified external domains. 
    If an outbound connector with the specified name already exists, the script updates the recipient domains of the connector.
    If the outbound connector does not exist, a new outbound connector is created.

.PARAMETER Domains
    Specifies an array of external domains for which TLS settings should be applied.

.PARAMETER Identity
    Specifies the name of the outbound connector. Default value is 'External TLS 1'.

.PARAMETER Comment
    Specifies a comment for the outbound connector. Default value is 'Outbound connector with force TLS settings for external domains.'

.EXAMPLE
    Add-majoOutboundConnectorTLS.ps1 -Domains "example.com", "contoso.com" -Identity "External TLS 2" -Comment "Outbound connector for TLS 2"

.NOTES
    This script requires the Exchange Online PowerShell module.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string[]]$Domains,
    [Parameter(Mandatory = $false)]
    [string]$Identity = 'External TLS 1',
    [Parameter(Mandatory = $false)]
    [string]$Comment = 'Outbound connector with force TLS settings for external domains.'
)

begin {
    # Check if we have name Outboundconnector with force TLS on
    $tlsconnector = Get-OutboundConnector | Where-Object { $_.Name -eq $Identity }
}

process {
    if ($tlsconnector) {
        $tlsconnector.RecipientDomains += $Domains
        try {
            Set-OutboundConnector -Identity $Identity -TlsSettings 'CertificateValidation' -RecipientDomains $tlsconnector.RecipientDomains -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match "is already present in the collection") {
                throw "Recipient domain $domains already present in the outbound connector."
            }
            else {
                throw $_
            }
        }
            
    }
    else {
        New-OutboundConnector -Name $Identity -TlsSettings 'CertificateValidation' -RecipientDomains $Domains `
            -ConnectorType Partner -IsTransportRuleScoped $false -Comment $Comment | Out-Null
    }
}
