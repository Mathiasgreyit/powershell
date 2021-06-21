function Get-majoAzKeyVaultCertificate {
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        Script based on information on https://docs.microsoft.com/sv-se/azure/key-vault/certificates/how-to-export-certificate?tabs=azure-powershell
    #>
    
    [CmdletBinding()]
    param (
        [String]$CertificateName,
        [String]$VaultName,
        [String]$Password,
        [String]$Path
    )
    
    begin {
        try {
            $azcontext = Get-AzContext -ErrorAction Stop  
        }
        catch {
            Write-Error
        }
        try {
            # Try loading required modules
            Import-Module -Name Az.KeyVault -ErrorAction Stop
        }
        catch {
            
        }
    }
    
    process {
        $cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
        $secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $cert.Name   
        
        $secretValueText = '';
        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
        try {
            $secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
        }
        $secretByte = [Convert]::FromBase64String($secretValueText)
        $x509Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($secretByte,
            "", "Exportable,PersistKeySet")
        $type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
        $pfxFileByte = $x509Cert.Export($type, $password)

        [System.IO.File]::WriteAllBytes($Path, $pfxFileByte)
    }
    
    end {
        
    }
}