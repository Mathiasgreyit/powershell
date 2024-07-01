<#
.SYNOPSIS
    Retrieves outbound connectors with TLS settings and their recipient domains.

.DESCRIPTION
    This script retrieves outbound connectors with TLS settings and their recipient domains. 
    It provides the option to filter by duplicate domains and specific connector identities or domains.

.PARAMETER OnlyDuplicateDomains
    Specifies whether to only return duplicate recipient domains.
    By default, all recipient domains are returned.

.PARAMETER Identity
    Specifies the identity of the outbound connector to retrieve.
    If not specified, all outbound connectors are retrieved.

.PARAMETER Domain
    Specifies the recipient domains to filter by.
    Only outbound connectors with matching recipient domains are returned.

.EXAMPLE
    Get-majoOutBoundConnectorTLS.ps1 -OnlyDuplicateDomains
    Retrieves outbound connectors with duplicate recipient domains.

.EXAMPLE
    Get-majoOutBoundConnectorTLS.ps1 -Identity "Connector1"
    Retrieves the outbound connector with the specified identity.

.EXAMPLE
    Get-majoOutBoundConnectorTLS.ps1 -Domain "example.com", "contoso.com"
    Retrieves outbound connectors with the specified recipient domains.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$OnlyDuplicateDomains,
    [Parameter(Mandatory = $false)]
    [string]$Identity,
    [Parameter(Mandatory = $false)]
    [string[]]$Domain
)
begin {
    # Check if we have name Outboundconnector with force TLS on
    $tlsconnectors = Get-OutboundConnector | Where-Object {$_.Smarthosts.count -eq 0 -and ($_.TlsSettings -eq 'CertificateValidation' -or $_.TlsSettings -eq 'EncryptionOnly')}

}
process {
    $recdom = @()   
    foreach ($connector in $tlsconnectors) {
        foreach ($dom in $connector.RecipientDomains) {
            if ($Domain -and $Domain -notcontains $dom) { continue }
            $myobj = New-Object -TypeName PSObject -Property @{
                'ConnectorId'     = $connector.Identity
                'RecipientDomain' = $dom
                'Enabled'         = $connector.Enabled
            }
            $recdom += $myobj
        }
    }
}
end {
    if ($OnlyDuplicateDomains) {
        $recdom | Group-Object -Property RecipientDomain | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Group
    }
    else {
        $recdom
    }
}