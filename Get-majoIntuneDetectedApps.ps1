function Get-majoIntuneDetectedApps {
    [CmdletBinding()]
    param (
        $Search, # https://docs.microsoft.com/en-us/graph/search-query-parameter#using-search-on-person-collections
        $FilterStartsWith # https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter
    )
    
    begin {
        <#
         #  DeviceManagementApps.Read.All
            DeviceManagementConfiguration.Read.All
            DeviceManagementManagedDevices.Read.All
            DeviceManagementServiceConfig.Read.All

        Get Intune id of devices with that app
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/detectedApps/731F6BAA-A986-45A4-8936-7C3AAAAA760B/managedDevices"  

         #>
        #Connect-MgGraph -TenantId 936252be-3425-4a13-9412-779c8d88951a -Scopes "DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All"
        if ($Search) {
            $nexturi = 'https://graph.microsoft.com/beta/deviceManagement/detectedApps?$search="' + $Search + '"'
        }
        elseif ($FilterStartsWith) {
            $nexturi = 'https://graph.microsoft.com/beta/deviceManagement/detectedApps?$filter=startsWith('+$FilterStartsWith+')'
        }else{
            $nexturi = 'https://graph.microsoft.com/beta/deviceManagement/detectedApps'
        }

    }
    
    process {

        
        do {
            $sv = Invoke-MgGraphRequest -Method GET -Uri $nexturi
            foreach ($a in $sv.Value) {
                $a  
            }       
            $nexturi = $sv["@odata.nextLink"]
        } until ($nexturi -eq $null)
        
    
    }
    
    end {
        #Disconnect-MgGraph    
    }
}