#Requires -Modules Pester
#Requires -Version 5.1

BeforeAll {
    $testOutParams = @{
        FilePath = (New-Item 'TestDrive:/Test.json' -ItemType File).FullName
        Encoding = 'utf8'
    }

    $testScript = $PSCommandPath.Replace('.Tests.ps1', '.ps1')
    $testParams = @{
        ScriptName = 'Test (Brecht)'
        ImportFile = $testOutParams.FilePath
        LogFolder  = 'TestDrive:/log'
    }

    Mock Get-ADDisplayNameHC
    Mock Get-ADUser
    Mock Get-ADTSProfileHC
    Mock Send-MailHC
    Mock Write-EventLog
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
Describe 'when all tests pass' {
    BeforeAll {
        Mock Get-ADDisplayNameHC {
            'manager chuck'
        } -ParameterFilter {
            $Name -eq 'President'
        }
        Mock Get-ADDisplayNameHC {
            'manager bob'
        } -ParameterFilter {
            $Name -eq 'US President'
        }
        Mock Get-ADTsProfileHC {
            "TS AllowLogon chuck"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis chuck') -and
            ($Property -eq 'AllowLogon')
        }
        Mock Get-ADTsProfileHC {
            "TS AllowLogon bob"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bob') -and
            ($Property -eq 'AllowLogon')
        }
        Mock Get-ADTsProfileHC {
            "TS HomeDirectory chuck"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis chuck') -and
            ($Property -eq 'HomeDirectory')
        }
        Mock Get-ADTsProfileHC {
            "TS HomeDirectory bob"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bob') -and
            ($Property -eq 'HomeDirectory')
        }
        Mock Get-ADTsProfileHC {
            "TS HomeDrive chuck"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis chuck') -and
            ($Property -eq 'HomeDrive')
        }
        Mock Get-ADTsProfileHC {
            "TS HomeDrive bob"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bob') -and
            ($Property -eq 'HomeDrive')
        }
        Mock Get-ADTsProfileHC {
            "TS UserProfile chuck"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis chuck') -and
            ($Property -eq 'UserProfile')
        }
        Mock Get-ADTsProfileHC {
            "TS UserProfile bob"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bob') -and
            ($Property -eq 'UserProfile')
        }
        Mock ConvertTo-OuNameHC {
            'OU chuck'
        } -ParameterFilter {
            $Name -eq 'OU=Texas,OU=USA,DC=contoso,DC=net'
        }
        Mock ConvertTo-OuNameHC {
            'OU bob'
        } -ParameterFilter {
            $Name -eq 'OU=Tennessee,OU=USA,DC=contoso,DC=net'
        }

        Mock Get-ADUser {
            [PSCustomObject]@{
                AccountExpirationDate = (Get-Date).AddYears(1)
                CanonicalName         = 'OU=Texas,OU=USA,DC=contoso,DC=net'
                Co                    = 'USA'
                Company               = 'US Government'
                Department            = 'Texas rangers'
                Description           = 'Ranger'
                DisplayName           = 'Chuck Norris'
                DistinguishedName     = 'dis chuck'
                EmailAddress          = 'gmail@chuck.norris'
                EmployeeID            = '1'
                EmployeeType          = 'Special'
                Enabled               = $true
                ExtensionAttribute8   = '3'
                Fax                   = '2'
                GivenName             = 'Chuck'
                HomePhone             = '4'
                HomeDirectory         = 'c:\chuck'
                Info                  = "best`nguy`never"
                IpPhone               = '5'
                Surname               = 'Norris'
                LastLogonDate         = (Get-Date)
                LockedOut             = $false
                Manager               = 'President'
                MobilePhone           = '6'
                Name                  = 'Chuck Norris'
                Office                = 'Texas'
                OfficePhone           = '7'
                Pager                 = '9'
                PasswordExpired       = $false
                PasswordNeverExpires  = $true
                SamAccountName        = 'cnorris'
                ScriptPath            = 'c:\cnorris\script.ps1'
                Title                 = 'Texas lead ranger'
                UserPrincipalName     = 'norris@world'
                WhenChanged           = (Get-Date).AddDays(-5)
                WhenCreated           = (Get-Date).AddYears(-3)
            }
            [PSCustomObject]@{
                AccountExpirationDate = (Get-Date).AddYears(2)
                CanonicalName         = 'OU=Tennessee,OU=USA,DC=contoso,DC=net'
                Co                    = 'America'
                Company               = 'Retired'
                Department            = 'US Army snipers'
                Description           = 'Sniper'
                DisplayName           = 'Bob Lee Swagger'
                DistinguishedName     = 'dis bob'
                EmailAddress          = 'bl@tenessee.com'
                EmployeeID            = '9'
                EmployeeType          = 'Sniper'
                Enabled               = $true
                ExtensionAttribute8   = '11'
                Fax                   = '10'
                GivenName             = 'Bob Lee'
                HomePhone             = '12'
                HomeDirectory         = 'c:\swagger'
                Info                  = "best`nsniper`nin`nthe`nworld"
                IpPhone               = '13'
                Surname               = 'Swagger'
                LastLogonDate         = (Get-Date)
                LockedOut             = $false
                Manager               = 'US President'
                MobilePhone           = '14'
                Name                  = 'Bob Lee Swagger'
                Office                = 'Tennessee'
                OfficePhone           = '15'
                Pager                 = '16'
                PasswordExpired       = $false
                PasswordNeverExpires  = $true
                SamAccountName        = 'lswagger'
                ScriptPath            = 'c:\swagger\script.ps1'
                Title                 = 'Corporal'
                UserPrincipalName     = 'swagger@world'
                WhenChanged           = (Get-Date).AddDays(-7)
                WhenCreated           = (Get-Date).AddYears(-30)
            }
        }

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
        $testJsonFile | ConvertTo-Json -Depth 3 | Out-File @testOutParams

        .$testScript @testParams
    }
    Context 'Get-AdUser' {
        It 'is called with the correct arguments' {
            Should -Invoke Get-AdUser -Scope Describe -Times 1 -Exactly -ParameterFilter {
                ($SearchBase -eq $testJsonFile.AD.OU)
            }
        }
    }
    Context 'export an Excel file with all AD user accounts' {
        BeforeAll {
            $testExportedExcelRows = @(
                @{
                    AccountExpirationDate     = (Get-Date).AddYears(1)
                    Country                   = 'USA'
                    Company                   = 'US Government'
                    Department                = 'Texas rangers'
                    Description               = 'Ranger'
                    DisplayName               = 'Chuck Norris'
                    EmailAddress              = 'gmail@chuck.norris'
                    EmployeeID                = '1'
                    EmployeeType              = 'Special'
                    Enabled                   = $true
                    Fax                       = '2'
                    FirstName                 = 'Chuck'
                    HeidelbergCementBillingID = '3'
                    HomePhone                 = '4'
                    HomeDirectory             = 'c:\chuck'
                    IpPhone                   = '5'
                    LastName                  = 'Norris'
                    LastLogonDate             = (Get-Date)
                    LockedOut                 = $false
                    Manager                   = 'manager chuck'
                    MobilePhone               = '6'
                    Name                      = 'Chuck Norris'
                    Notes                     = 'best guy ever'
                    Office                    = 'Texas'
                    OfficePhone               = '7'
                    OU                        = 'OU chuck'
                    Pager                     = '9'
                    PasswordExpired           = $false
                    PasswordNeverExpires      = $true
                    SamAccountName            = 'cnorris'
                    LogonScript               = 'c:\cnorris\script.ps1'
                    Title                     = 'Texas lead ranger'
                    TSAllowLogon              = 'TS AllowLogon chuck'
                    TSHomeDirectory           = 'TS HomeDirectory chuck'
                    TSHomeDrive               = 'TS HomeDrive chuck'
                    TSUserProfile             = 'TS UserProfile chuck'
                    UserPrincipalName         = 'norris@world'
                    WhenChanged               = (Get-Date).AddDays(-5)
                    WhenCreated               = (Get-Date).AddYears(-3)
                }
                @{
                    AccountExpirationDate     = (Get-Date).AddYears(2)
                    Country                   = 'America'
                    Company                   = 'Retired'
                    Department                = 'US Army snipers'
                    Description               = 'Sniper'
                    DisplayName               = 'Bob Lee Swagger'
                    EmailAddress              = 'bl@tenessee.com'
                    EmployeeID                = '9'
                    EmployeeType              = 'Sniper'
                    Enabled                   = $true
                    Fax                       = '10'
                    FirstName                 = 'Bob Lee'
                    HeidelbergCementBillingID = '11'
                    HomePhone                 = '12'
                    HomeDirectory             = 'c:\swagger'
                    IpPhone                   = '13'
                    LastName                  = 'Swagger'
                    LastLogonDate             = (Get-Date)
                    LockedOut                 = $false
                    Manager                   = 'manager bob'
                    MobilePhone               = '14'
                    Name                      = 'Bob Lee Swagger'
                    Notes                     = 'best sniper in the world'
                    Office                    = 'Tennessee'
                    OfficePhone               = '15'
                    OU                        = 'OU bob'
                    Pager                     = '16'
                    PasswordExpired           = $false
                    PasswordNeverExpires      = $true
                    SamAccountName            = 'lswagger'
                    LogonScript               = 'c:\swagger\script.ps1'
                    Title                     = 'Corporal'
                    TSAllowLogon              = 'TS AllowLogon bob'
                    TSHomeDirectory           = 'TS HomeDirectory bob'
                    TSHomeDrive               = 'TS HomeDrive bob'
                    TSUserProfile             = 'TS UserProfile bob'
                    UserPrincipalName         = 'swagger@world'
                    WhenChanged               = (Get-Date).AddDays(-7)
                    WhenCreated               = (Get-Date).AddYears(-30)
                }
            )

            $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - State.xlsx'

            $actual = Import-Excel -Path $testExcelLogFile.FullName -WorksheetName 'AllUsers'
        }
        It 'to the log folder' {
            $testExcelLogFile | Should -Not -BeNullOrEmpty
        }
        It 'with the correct total rows' {
            $actual | Should -HaveCount $testExportedExcelRows.Count
        }
        It 'with the correct data in the rows' {
            foreach ($testRow in $testExportedExcelRows) {
                $actualRow = $actual | Where-Object {
                    $_.SamAccountName -eq $testRow.SamAccountName
                }
                $actualRow.AccountExpirationDate.ToString('yyyyMMdd HHmm') | 
                Should -Be $testRow.AccountExpirationDate.ToString('yyyyMMdd HHmm')
                $actualRow.DisplayName | Should -Be $testRow.DisplayName
                $actualRow.Country | Should -Be $testRow.Country
                $actualRow.Company | Should -Be $testRow.Company
                $actualRow.Department | Should -Be $testRow.Department
                $actualRow.Description | Should -Be $testRow.Description
                $actualRow.DisplayName | Should -Be $testRow.DisplayName
                $actualRow.EmailAddress | Should -Be $testRow.EmailAddress
                $actualRow.EmployeeID | Should -Be $testRow.EmployeeID
                $actualRow.EmployeeType | Should -Be $testRow.EmployeeType
                $actualRow.Enabled | Should -Be $testRow.Enabled
                $actualRow.Fax | Should -Be $testRow.Fax
                $actualRow.FirstName | Should -Be $testRow.FirstName
                $actualRow.HeidelbergCementBillingID | 
                Should -Be $testRow.HeidelbergCementBillingID
                $actualRow.HomePhone | Should -Be $testRow.HomePhone
                $actualRow.HomeDirectory | Should -Be $testRow.HomeDirectory
                $actualRow.IpPhone | Should -Be $testRow.IpPhone
                $actualRow.LastName | Should -Be $testRow.LastName
                $actualRow.LogonScript | Should -Be $testRow.LogonScript
                $actualRow.LastLogonDate.ToString('yyyyMMdd HHmm') | 
                Should -Be $testRow.LastLogonDate.ToString('yyyyMMdd HHmm')
                $actualRow.LockedOut | Should -Be $testRow.LockedOut
                $actualRow.Manager | Should -Be $testRow.Manager
                $actualRow.MobilePhone | Should -Be $testRow.MobilePhone
                $actualRow.Name | Should -Be $testRow.Name
                $actualRow.Notes | Should -Be $testRow.Notes
                $actualRow.Office | Should -Be $testRow.Office
                $actualRow.OfficePhone | Should -Be $testRow.OfficePhone
                $actualRow.OU | Should -Be $testRow.OU
                $actualRow.Pager | Should -Be $testRow.Pager
                $actualRow.PasswordExpired | Should -Be $testRow.PasswordExpired
                $actualRow.PasswordNeverExpires | 
                Should -Be $testRow.PasswordNeverExpires
                $actualRow.SamAccountName | Should -Be $testRow.SamAccountName
                $actualRow.Title | Should -Be $testRow.Title
                $actualRow.TSAllowLogon | Should -Be $testRow.TSAllowLogon
                $actualRow.TSHomeDirectory | Should -Be $testRow.TSHomeDirectory
                $actualRow.TSHomeDrive | Should -Be $testRow.TSHomeDrive
                $actualRow.TSUserProfile | Should -Be $testRow.TSUserProfile
                $actualRow.UserPrincipalName | 
                Should -Be $testRow.UserPrincipalName
                $actualRow.WhenChanged.ToString('yyyyMMdd HHmm') | 
                Should -Be $testRow.WhenChanged.ToString('yyyyMMdd HHmm')
                $actualRow.WhenCreated.ToString('yyyyMMdd HHmm') | 
                Should -Be $testRow.WhenCreated.ToString('yyyyMMdd HHmm')
            }
        }
    }
    Context 'send a mail to the user when SendMail.When is Always' {
        BeforeAll {
            $testMail = @{
                To          = 'bob@contoso.com'
                Bcc         = $ScriptAdmin
                Priority    = 'Normal'
                Subject     = '3 files found'
                Message     = "*Found a total of <b>3 files</b>*$env:COMPUTERNAME*$testFolderPath*Filter*Files found**kiwi*3*Check the attachment for details*"
                Attachments = '* - 0 - Log.xlsx'
            }
        }
        It 'Send-MailHC has the correct arguments' {
            $mailParams.To | Should -Be $testMail.To
            $mailParams.Bcc | Should -Be $testMail.Bcc
            $mailParams.Priority | Should -Be $testMail.Priority
            $mailParams.Subject | Should -Be $testMail.Subject
            $mailParams.Message | Should -BeLike $testMail.Message
            $mailParams.Attachments | Should -BeLike $testMail.Attachments
        }
        It 'Send-MailHC is called' {
            Should -Invoke Send-MailHC -Exactly 1 -Scope Describe -ParameterFilter {
                ($To -eq $testMail.To) -and
                ($Bcc -eq $testMail.Bcc) -and
                ($Priority -eq $testMail.Priority) -and
                ($Subject -eq $testMail.Subject) -and
                ($Attachments -like $testMail.Attachments) -and
                ($Message -like $testMail.Message)
            }
        }
    } -Skip
} -Tag Test