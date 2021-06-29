function Get-majoWindowsOriginialProductKey {
    <#
    .SYNOPSIS
        On Windows 10 diplays OEM Windows Product key
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
        General notes
    #>
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        
    }
    
    process {
        (Get-WmiObject -Class SoftwareLicensingService).OA3xOriginalProductKey
    }
    
    end {
        
    }
}