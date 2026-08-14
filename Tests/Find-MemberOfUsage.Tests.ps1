BeforeAll {
    # Load script content without #Requires so tests run without the Graph module
    $originalPath = Join-Path $PSScriptRoot '..' 'Find-MemberOfUsage.ps1'
    $content = Get-Content -Path $originalPath -Raw
    $content = $content -replace '#Requires\s+-Modules\s+\S+', ''
    $script:TestScriptPath = Join-Path $TestDrive 'Find-MemberOfUsage.ps1'
    Set-Content -Path $script:TestScriptPath -Value $content

    # Stub Graph SDK commands so Pester can mock them
    function script:Invoke-MgGraphRequest { param([string]$Method, [string]$Uri) }
    function script:Get-MgContext { }
    function script:Connect-MgGraph { param([string[]]$Scopes, [switch]$NoWelcome) }
}

Describe 'Find-MemberOfUsage' {
    BeforeEach {
        Mock Write-Progress
        Mock Write-Host
        Mock Write-Warning
        Mock Get-MgContext { [PSCustomObject]@{ Account = 'test@contoso.com' } }
    }

    Context 'Connection handling' {
        It 'Errors when not connected to Graph' {
            Mock Get-MgContext { $null }

            { & $script:TestScriptPath } | Should-Throw
            Should-Invoke -CommandName Get-MgContext -Times 1
        }

        It 'Calls Connect-MgGraph when -ConnectGraph is specified' {
            Mock Connect-MgGraph
            Mock Invoke-MgGraphRequest { @{ value = @() } }

            & $script:TestScriptPath -ConnectGraph | Out-Null

            Should-Invoke -CommandName Connect-MgGraph -Times 1
        }
    }

    Context 'Dynamic groups' {
        BeforeEach {
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*administrativeUnits*' }
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*assignmentPolicies*' }
        }

        It 'Detects memberOf in dynamic group rules' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{
                            id = 'g1'
                            displayName = 'MemberOfGroup'
                            membershipRule = '(user.memberOf -any (group.objectId -in ["abc-123"]))'
                            membershipRuleProcessingState = 'On'
                        }
                    )
                }
            } -ParameterFilter { $Uri -like '*groups*' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 1
            $results[0].Type | Should-Be 'Dynamic Group'
            $results[0].Id | Should-Be 'g1'
            $results[0].DisplayName | Should-Be 'MemberOfGroup'
            $results[0].ProcessingState | Should-Be 'On'
        }

        It 'Skips groups without memberOf in their rule' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{
                            id = 'g2'
                            displayName = 'DeptGroup'
                            membershipRule = '(user.department -eq "IT")'
                            membershipRuleProcessingState = 'On'
                        }
                    )
                }
            } -ParameterFilter { $Uri -like '*groups*' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 0
        }

        It 'Handles pagination across multiple pages of groups' {
            $script:groupPageCount = 0

            Mock Invoke-MgGraphRequest {
                $script:groupPageCount++
                if ($script:groupPageCount -eq 1) {
                    return @{
                        value          = @(
                            @{ id = 'g-page1'; displayName = 'Page1Group'; membershipRule = 'user.memberOf -any (group.objectId -in ["x"])'; membershipRuleProcessingState = 'On' }
                        )
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/groups?$skiptoken=page2'
                    }
                }
                return @{
                    value = @(
                        @{ id = 'g-page2'; displayName = 'Page2Group'; membershipRule = 'user.memberOf -any (group.objectId -in ["y"])'; membershipRuleProcessingState = 'On' }
                    )
                }
            } -ParameterFilter { $Uri -like '*groups*' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 2
            $results[0].Id | Should-Be 'g-page1'
            $results[1].Id | Should-Be 'g-page2'
            Should-Invoke -CommandName Invoke-MgGraphRequest -Times 2 -ParameterFilter { $Uri -like '*groups*' }
        }
    }

    Context 'Dynamic administrative units' {
        BeforeEach {
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*groups*' }
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*assignmentPolicies*' }
        }

        It 'Detects memberOf in dynamic AU rules' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{
                            id = 'au1'
                            displayName = 'DynamicAU'
                            membershipType = 'Dynamic'
                            membershipRule = '(user.memberOf -any (group.objectId -in ["au-group"]))'
                            membershipRuleProcessingState = 'On'
                        }
                    )
                }
            } -ParameterFilter { $Uri -like '*administrativeUnits*' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 1
            $results[0].Type | Should-Be 'Dynamic Administrative Unit'
            $results[0].DisplayName | Should-Be 'DynamicAU'
        }

        It 'Skips AUs that are not Dynamic membershipType' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{
                            id = 'au2'
                            displayName = 'AssignedAU'
                            membershipType = 'Assigned'
                            membershipRule = $null
                            membershipRuleProcessingState = $null
                        }
                    )
                }
            } -ParameterFilter { $Uri -like '*administrativeUnits*' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 0
        }

        It 'Handles pagination across multiple pages of AUs' {
            $script:auPageCount = 0

            Mock Invoke-MgGraphRequest {
                $script:auPageCount++
                if ($script:auPageCount -eq 1) {
                    return @{
                        value          = @(
                            @{ id = 'au-p1'; displayName = 'AU-Page1'; membershipType = 'Dynamic'; membershipRule = 'user.memberOf -any (group.objectId -in ["z"])'; membershipRuleProcessingState = 'On' }
                        )
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$skiptoken=page2'
                    }
                }
                return @{
                    value = @(
                        @{ id = 'au-p2'; displayName = 'AU-Page2'; membershipType = 'Dynamic'; membershipRule = 'user.memberOf -any (group.objectId -in ["w"])'; membershipRuleProcessingState = 'On' }
                    )
                }
            } -ParameterFilter { $Uri -like '*administrativeUnits*' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 2
            $results[0].Id | Should-Be 'au-p1'
            $results[1].Id | Should-Be 'au-p2'
            Should-Invoke -CommandName Invoke-MgGraphRequest -Times 2 -ParameterFilter { $Uri -like '*administrativeUnits*' }
        }
    }

    Context 'Assignment policies' {
        BeforeEach {
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*groups*' }
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*administrativeUnits*' }
        }

        It 'Detects memberOf in policy specificAllowedTargets' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'pol1'; displayName = 'AutoPolicy1' }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies?*' }

            Mock Invoke-MgGraphRequest {
                @{
                    id                     = 'pol1'
                    displayName            = 'AutoPolicy1'
                    specificAllowedTargets = @(
                        @{
                            '@odata.type'  = '#microsoft.graph.attributeRuleMembers'
                            membershipRule = '(user.memberOf -any (group.objectId -in ["policy-grp"]))'
                        }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies/pol1' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 1
            $results[0].Type | Should-Be 'Auto-Assignment Policy'
            $results[0].Id | Should-Be 'pol1'
            $results[0].DisplayName | Should-Be 'AutoPolicy1'
        }

        It 'Skips policies without specificAllowedTargets' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'pol2'; displayName = 'ManualPolicy' }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies?*' }

            Mock Invoke-MgGraphRequest {
                @{
                    id                     = 'pol2'
                    displayName            = 'ManualPolicy'
                    specificAllowedTargets = $null
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies/pol2' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 0
        }

        It 'Skips targets that are not attributeRuleMembers' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'pol3'; displayName = 'DirectPolicy' }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies?*' }

            Mock Invoke-MgGraphRequest {
                @{
                    id                     = 'pol3'
                    displayName            = 'DirectPolicy'
                    specificAllowedTargets = @(
                        @{
                            '@odata.type' = '#microsoft.graph.groupMembers'
                            groupId       = 'some-group-id'
                        }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies/pol3' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 0
        }

        It 'Handles errors fetching individual policies gracefully' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'pol-err'; displayName = 'ErrorPolicy' }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies?*' }

            Mock Invoke-MgGraphRequest {
                throw 'Forbidden'
            } -ParameterFilter { $Uri -like '*assignmentPolicies/pol-err' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 0
            Should-Invoke -CommandName Write-Warning -Times 1
        }

        It 'Handles pagination across multiple pages of policies' {
            $script:polPageCount = 0

            Mock Invoke-MgGraphRequest {
                $script:polPageCount++
                if ($script:polPageCount -eq 1) {
                    return @{
                        value          = @(
                            @{ id = 'pol-p1'; displayName = 'PolicyPage1' }
                        )
                        '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies?$skiptoken=page2'
                    }
                }
                return @{
                    value = @(
                        @{ id = 'pol-p2'; displayName = 'PolicyPage2' }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies?*' -or $Uri -like '*skiptoken*' }

            Mock Invoke-MgGraphRequest {
                @{
                    id                     = $Uri.Split('/')[-1]
                    displayName            = 'MatchingPolicy'
                    specificAllowedTargets = @(
                        @{
                            '@odata.type'  = '#microsoft.graph.attributeRuleMembers'
                            membershipRule = 'user.memberOf -any (group.objectId -in ["grp"])'
                        }
                    )
                }
            } -ParameterFilter { $Uri -match 'assignmentPolicies/pol-p[12]$' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 2
            $results[0].Id | Should-Be 'pol-p1'
            $results[1].Id | Should-Be 'pol-p2'
        }
    }

    Context 'Mixed results across all sources' {
        It 'Returns results from groups, AUs, and policies combined' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'g1'; displayName = 'DynGroup'; membershipRule = 'user.memberOf -any (group.objectId -in ["a"])'; membershipRuleProcessingState = 'On' }
                    )
                }
            } -ParameterFilter { $Uri -like '*groups*' }

            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'au1'; displayName = 'DynAU'; membershipType = 'Dynamic'; membershipRule = 'user.memberOf -any (group.objectId -in ["b"])'; membershipRuleProcessingState = 'On' }
                    )
                }
            } -ParameterFilter { $Uri -like '*administrativeUnits*' }

            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'pol1'; displayName = 'AutoPol' }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies?*' }

            Mock Invoke-MgGraphRequest {
                @{
                    id                     = 'pol1'
                    displayName            = 'AutoPol'
                    specificAllowedTargets = @(
                        @{
                            '@odata.type'  = '#microsoft.graph.attributeRuleMembers'
                            membershipRule = 'user.memberOf -any (group.objectId -in ["c"])'
                        }
                    )
                }
            } -ParameterFilter { $Uri -like '*assignmentPolicies/pol1' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 3
            @($results | Where-Object Type -EQ 'Dynamic Group').Count | Should-Be 1
            @($results | Where-Object Type -EQ 'Dynamic Administrative Unit').Count | Should-Be 1
            @($results | Where-Object Type -EQ 'Auto-Assignment Policy').Count | Should-Be 1
        }

        It 'Returns empty when nothing uses memberOf' {
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*groups*' }
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*administrativeUnits*' }
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*assignmentPolicies*' }

            $results = @(& $script:TestScriptPath)

            $results.Count | Should-Be 0
        }
    }

    Context 'MemberOf pattern matching' {
        BeforeEach {
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*administrativeUnits*' }
            Mock Invoke-MgGraphRequest { @{ value = @() } } -ParameterFilter { $Uri -like '*assignmentPolicies*' }
        }

        It 'Matches memberOf as a whole word only' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'g-false'; displayName = 'FalsePositive'; membershipRule = '(user.customMemberOfAttribute -eq "yes")'; membershipRuleProcessingState = 'On' }
                    )
                }
            } -ParameterFilter { $Uri -like '*groups*' }

            $results = @(& $script:TestScriptPath)

            # "customMemberOfAttribute" should not match \bmemberOf\b
            $results.Count | Should-Be 0
        }

        It 'Matches memberOf regardless of case in the rule' {
            Mock Invoke-MgGraphRequest {
                @{
                    value = @(
                        @{ id = 'g-upper'; displayName = 'UpperCase'; membershipRule = '(user.MEMBEROF -any (group.objectId -in ["x"]))'; membershipRuleProcessingState = 'On' }
                    )
                }
            } -ParameterFilter { $Uri -like '*groups*' }

            $results = @(& $script:TestScriptPath)

            # PowerShell -match is case-insensitive by default
            $results.Count | Should-Be 1
        }
    }
}
