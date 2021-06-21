function Get-majoAzKeyVaultCertificate {
    <#
    .SYNOPSIS
        Creates a pfx file including private key from Azure KeyVault certificate.
    .DESCRIPTION
        The purpose of this script is to simplify downloading and generate a pfx file from a Azure Keyvault.
    .EXAMPLE
        PS C:\> Get-majoAzKeyVaultCertificate -CertificateName 'mycert' -VaultName myazurekeyvault
        Searches after a AzureKey vault containing a cert with name mycert. Creates a pfx file including private with a random password and save it as a random named pfx file in current directory
    .INPUTS
        [String]CertificateName, certificatename.
        [String]VaultName, name of Azure Keyvault where certificate is located.
    .OUTPUTS
        [String]Password, yes password in cleartext for pfx file.
        [String]Fullname, fullname of pfx file including path.
    .NOTES
        Script based on information on https://docs.microsoft.com/sv-se/azure/key-vault/certificates/how-to-export-certificate?tabs=azure-powershell
    .LINK
        This script and resides on Githud in my repository https://github.com/Mathiasgreyit/powershell  
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            HelpMessage = 'Certificate friendly name',
            Position = 0)]
        [String]$CertificateName,
        [Parameter(Mandatory = $true,
            HelpMessage = 'Azure Keyvault name',
            Position = 3)]
        [String]$VaultName,
        [Parameter(Mandatory = $false,
            HelpMessage = 'Azure subscription i where Keyvault exists',
            Position = 4)]
        [String]$Subscription,   
        [Parameter(Mandatory = $false,
            HelpMessage = 'Password for pfx in Securestring',
            Position = 1)]
        [String]$Password,
        [Parameter(Mandatory = $false,
            HelpMessage = 'Path and name with file ending pfx',
            Position = 2)]
        [String]$Fullpath    
    )
    
    begin {
        $ErrorActionPreference = "Stop"
        Import-Module -Name Az.KeyVault
        Import-Module -Name Az.Accounts

        $azcontext = Get-AzContext  

        if ($Subscription -ne '' -and $Subscription -ne $azcontext.Subscription) {
            Select-AzSubscription -Subscription $Subscription
        }elseif (-not ($azcontext.Subscription)) {
            Throw "Run Connect-AzAccount to login."
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
        if (-not($Password)) {# If no Password is supplied, generate one
            $Password = "Pass"+(Get-Random -Maximum 9999 -Minimum 1000)    
        }
        if (-not($Fullpath)) {# If no Path is supplied generate random filename
            do {
                $filename = $CertificateName+(Get-Random -Minimum 10 -Maximum 999)+".pfx"
                $Fullpath = (Get-Location).Path+"\"+$filename    
            } until ((Test-Path $Fullpath) -eq $false) # Make sure random file not already exist    
        }
        $pfxFileByte = $x509Cert.Export($type, $Password)
        
        [System.IO.File]::WriteAllBytes($Fullpath, $pfxFileByte)
        Write-Output "Succesfully created pfx file with private key."
        Write-Output "Path: $Fullpath"
        Write-Output "Password: $Password"
    }
    
    end {
        
    }
}