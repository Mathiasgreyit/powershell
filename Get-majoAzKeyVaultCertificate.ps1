function Get-majoAzKeyVaultCertificate {
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