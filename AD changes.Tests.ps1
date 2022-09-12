#Requires -Modules Pester
#Requires -Version 5.1

BeforeAll {
    $testOutParams = @{
        FilePath = (New-Item 'TestDrive:/Test.json' -ItemType File).FullName
        Encoding = 'utf8'
    }

    $testInputFile = @{
        AD       = @{
            PropertyToMonitor = @('Office')
            PropertyInReport  = @('SamAccountName', 'Office', 'Title')
            OU                = @('OU=BEL,OU=EU,DC=contoso,DC=com')
        }
        SendMail = @{
            When = 'Always'
            To   = 'bob@contoso.com'
        }
    }

    $testScript = $PSCommandPath.Replace('.Tests.ps1', '.ps1')
    $testParams = @{
        ScriptName = 'Test (Brecht)'
        ImportFile = $testOutParams.FilePath
        LogFolder  = 'TestDrive:/log'
    }

    Mock Send-MailHC
    Mock Write-EventLog
    Mock Get-ADDisplayNameHC
    Mock Get-ADUser
    Mock Get-ADTSProfileHC
}

Describe 'the mandatory parameters are' {
    It '<_>' -ForEach 'ScriptName', 'ImportFile' {
        (Get-Command $testScript).Parameters[$_].Attributes.Mandatory | 
        Should -BeTrue
    }
}
Describe 'send an e-mail to the admin when' {
    BeforeAll {
        $MailAdminParams = {
            ($To -eq $ScriptAdmin) -and ($Priority -eq 'High') -and 
            ($Subject -eq 'FAILURE')
        }    
    }
    It 'the log folder cannot be created' {
        $testNewParams = $testParams.clone()
        $testNewParams.LogFolder = 'xxx::\notExistingLocation'

        .$testScript @testNewParams -EA ignore

        Should -Invoke Send-MailHC -Exactly 1 -ParameterFilter {
            (&$MailAdminParams) -and 
            ($Message -like '*Failed creating the log folder*')
        }
    }
    Context 'the ImportFile' {
        It 'is not found' {
            $testNewParams = $testParams.clone()
            $testNewParams.ImportFile = 'nonExisting.json'
    
            .$testScript @testNewParams
    
            Should -Invoke Send-MailHC -Exactly 1 -ParameterFilter {
                (&$MailAdminParams) -and 
                ($Message -like "*Cannot find path*nonExisting.json*")
            }
            Should -Invoke Write-EventLog -Exactly 1 -ParameterFilter {
                $EntryType -eq 'Error'
            }
        }
        It 'is missing property <_>' -ForEach @(
            'AD.OU', 
            'AD.PropertyToMonitor',
            'AD.PropertyInReport',
            'SendMail.To',
            'SendMail.When'
        ) {
            $testJsonFile = @{
                AD       = @{
                    PropertyToMonitor = @('Office')
                    PropertyInReport  = @('SamAccountName', 'Office', 'Title')
                    OU                = @('OU=BEL,OU=EU,DC=contoso,DC=com')
                }
                SendMail = @{
                    When = 'Always'
                    To   = 'bob@contoso.com'
                }
            }

            if ($_ -match '.') {
                $keys = $_ -split '\.', 2
                $testJsonFile[$keys[0]].Remove($keys[1])
            }
            else {
                $testJsonFile.Remove($_)
            }

            $testJsonFile | ConvertTo-Json -Depth 3 | Out-File @testOutParams

            .$testScript @testParams
                        
            Should -Invoke Send-MailHC -Exactly 1 -ParameterFilter {
                (&$MailAdminParams) -and 
                ($Message -like "*Property '$_' not found*")
            }
            Should -Invoke Write-EventLog -Exactly 1 -ParameterFilter {
                $EntryType -eq 'Error'
            }
        }
        It 'AD.PropertyInReport contains an unknown AD property' {
            $testJsonFile = @{
                AD       = @{
                    PropertyToMonitor = @('Office')
                    PropertyInReport  = @('SamAccountName', 'Office', 'foobar')
                    OU                = @('OU=BEL,OU=EU,DC=contoso,DC=com')
                }
                SendMail = @{
                    When = 'Always'
                    To   = 'bob@contoso.com'
                }
            }
            $testJsonFile | ConvertTo-Json -Depth 3 | Out-File @testOutParams

            .$testScript @testParams
                        
            Should -Invoke Send-MailHC -Exactly 1 -ParameterFilter {
                (&$MailAdminParams) -and 
                ($Message -like "*Property 'foobar' defined in 'AD.PropertyInReport' is not a valid AD property. Valid AD properties are*")
            }
            Should -Invoke Write-EventLog -Exactly 1 -ParameterFilter {
                $EntryType -eq 'Error'
            }
        }
        It 'AD.PropertyToMonitor contains an unknown AD property' {
            $testJsonFile = @{
                AD       = @{
                    PropertyToMonitor = @('foobar')
                    PropertyInReport  = @('SamAccountName', 'Office', 'Title')
                    OU                = @('OU=BEL,OU=EU,DC=contoso,DC=com')
                }
                SendMail = @{
                    When = 'Always'
                    To   = 'bob@contoso.com'
                }
            }
            $testJsonFile | ConvertTo-Json -Depth 3 | Out-File @testOutParams

            .$testScript @testParams
                        
            Should -Invoke Send-MailHC -Exactly 1 -ParameterFilter {
                (&$MailAdminParams) -and 
                ($Message -like "*Property 'foobar' defined in 'AD.PropertyToMonitor' is not a valid AD property. Valid AD properties are*")
            }
            Should -Invoke Write-EventLog -Exactly 1 -ParameterFilter {
                $EntryType -eq 'Error'
            }
        }
    }
}