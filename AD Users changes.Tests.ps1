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
        Should -Invoke Write-EventLog -Exactly 1 -ParameterFilter {
            $EntryType -eq 'Error'
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
    It 'no AD user accounts were found' {
        Mock Get-AdUser
        
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

        . $testScript @testParams

        Should -Invoke Send-MailHC -Exactly 1 -ParameterFilter {
            (&$MailAdminParams) -and 
            ($Message -like '*No AD user accounts found*')
        }
        Should -Invoke Write-EventLog -Exactly 1 -ParameterFilter {
            $EntryType -eq 'Error'
        }
    }
}
Describe 'when the script runs for the first time' {
    BeforeAll {
        #region Create mocks
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
        #endregion

        $testAdUser = @(
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
        )
        Mock Get-ADUser {
            $testAdUser
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
    Context 'collect all AD user accounts' {
        It 'call Get-AdUser with the correct arguments' {
            Should -Invoke Get-AdUser -Scope Describe -Times 1 -Exactly -ParameterFilter {
                ($SearchBase -eq $testJsonFile.AD.OU)
            }
        }
    }
    Context 'export an Excel file with all AD user accounts' {
        BeforeAll {
            $testExportedExcelRows = @(
                @{
                    AccountExpirationDate     = $testAdUser[0].AccountExpirationDate
                    Country                   = $testAdUser[0].Co
                    Company                   = $testAdUser[0].Company
                    Department                = $testAdUser[0].Department
                    Description               = $testAdUser[0].Description
                    DisplayName               = $testAdUser[0].DisplayName
                    EmailAddress              = $testAdUser[0].EmailAddress
                    EmployeeID                = $testAdUser[0].EmployeeID
                    EmployeeType              = $testAdUser[0].EmployeeType
                    Enabled                   = $testAdUser[0].Enabled
                    Fax                       = $testAdUser[0].Fax
                    FirstName                 = $testAdUser[0].GivenName
                    HeidelbergCementBillingID = $testAdUser[0].extensionAttribute8
                    HomePhone                 = $testAdUser[0].HomePhone
                    HomeDirectory             = $testAdUser[0].HomeDirectory
                    IpPhone                   = $testAdUser[0].IpPhone
                    LastName                  = $testAdUser[0].Surname
                    LastLogonDate             = $testAdUser[0].LastLogonDate
                    LockedOut                 = $testAdUser[0].LockedOut
                    Manager                   = 'manager chuck'
                    MobilePhone               = $testAdUser[0].MobilePhone
                    Name                      = $testAdUser[0].Name
                    Notes                     = 'best guy ever'
                    Office                    = $testAdUser[0].Office
                    OfficePhone               = $testAdUser[0].OfficePhone
                    OU                        = 'OU chuck'
                    Pager                     = $testAdUser[0].Pager
                    PasswordExpired           = $testAdUser[0].PasswordExpired
                    PasswordNeverExpires      = $testAdUser[0].PasswordNeverExpires
                    SamAccountName            = $testAdUser[0].SamAccountName
                    LogonScript               = $testAdUser[0].scriptPath
                    Title                     = $testAdUser[0].Title
                    TSAllowLogon              = 'TS AllowLogon chuck'
                    TSHomeDirectory           = 'TS HomeDirectory chuck'
                    TSHomeDrive               = 'TS HomeDrive chuck'
                    TSUserProfile             = 'TS UserProfile chuck'
                    UserPrincipalName         = $testAdUser[0].UserPrincipalName
                    WhenChanged               = $testAdUser[0].WhenChanged
                    WhenCreated               = $testAdUser[0].WhenCreated
                }
                @{
                    AccountExpirationDate     = $testAdUser[1].AccountExpirationDate
                    Country                   = $testAdUser[1].Co
                    Company                   = $testAdUser[1].Company
                    Department                = $testAdUser[1].Department
                    Description               = $testAdUser[1].Description
                    DisplayName               = $testAdUser[1].DisplayName
                    EmailAddress              = $testAdUser[1].EmailAddress
                    EmployeeID                = $testAdUser[1].EmployeeID
                    EmployeeType              = $testAdUser[1].EmployeeType
                    Enabled                   = $testAdUser[1].Enabled
                    Fax                       = $testAdUser[1].Fax
                    FirstName                 = $testAdUser[1].GivenName
                    HeidelbergCementBillingID = $testAdUser[1].extensionAttribute8
                    HomePhone                 = $testAdUser[1].HomePhone
                    HomeDirectory             = $testAdUser[1].HomeDirectory
                    IpPhone                   = $testAdUser[1].IpPhone
                    LastName                  = $testAdUser[1].Surname
                    LastLogonDate             = $testAdUser[1].LastLogonDate
                    LockedOut                 = $testAdUser[1].LockedOut
                    Manager                   = 'manager bob'
                    MobilePhone               = $testAdUser[1].MobilePhone
                    Name                      = $testAdUser[1].Name
                    Notes                     = 'best sniper in the world'
                    Office                    = $testAdUser[1].Office
                    OfficePhone               = $testAdUser[1].OfficePhone
                    OU                        = 'OU bob'
                    Pager                     = $testAdUser[1].Pager
                    PasswordExpired           = $testAdUser[1].PasswordExpired
                    PasswordNeverExpires      = $testAdUser[1].PasswordNeverExpires
                    SamAccountName            = $testAdUser[1].SamAccountName
                    LogonScript               = $testAdUser[1].scriptPath
                    Title                     = $testAdUser[1].Title
                    TSAllowLogon              = 'TS AllowLogon bob'
                    TSHomeDirectory           = 'TS HomeDirectory bob'
                    TSHomeDrive               = 'TS HomeDrive bob'
                    TSUserProfile             = 'TS UserProfile bob'
                    UserPrincipalName         = $testAdUser[1].UserPrincipalName
                    WhenChanged               = $testAdUser[1].WhenChanged
                    WhenCreated               = $testAdUser[1].WhenCreated
                }
            )

            $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - State{*}.xlsx'

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
    Context 'no e-mail or further action is taken' {
        It 'because there are no previous AD user accounts available in a previously exported Excel file' {
            Should -Not -Invoke Send-MailHC -Scope Describe 
            Should -Invoke Write-EventLog -Scope Describe -Times 1 -Exactly -ParameterFilter {
                $Message -like '*No comparison possible*'
            }
        }
    }
}
Describe 'when the script runs after a snapshot was created' {
    BeforeAll {
        #region Create mocks
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
        Mock Get-ADDisplayNameHC {
            'manager bond'
        } -ParameterFilter {
            $Name -eq 'M'
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
            "TS AllowLogon bond"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bond') -and
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
            "TS HomeDirectory bond"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bond') -and
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
            "TS HomeDrive bond"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bond') -and
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
        Mock Get-ADTsProfileHC {
            "TS UserProfile bond"
        } -ParameterFilter {
            ($DistinguishedName -eq 'dis bond') -and
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
        Mock ConvertTo-OuNameHC {
            'OU bond'
        } -ParameterFilter {
            $Name -eq 'OU=London,OU=GBR,DC=contoso,DC=net'
        }
        #endregion

        $testAdUser = @(
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
            [PSCustomObject]@{
                AccountExpirationDate = (Get-Date).AddYears(2)
                CanonicalName         = 'OU=London,OU=GBR,DC=contoso,DC=net'
                Co                    = 'United Kingdom'
                Company               = 'MI6'
                Department            = 'Special agent'
                Description           = 'agent 007'
                DisplayName           = 'James Bond'
                DistinguishedName     = 'dis bond'
                EmailAddress          = '007@mi6.com'
                EmployeeID            = '17'
                EmployeeType          = 'Agent'
                Enabled               = $true
                ExtensionAttribute8   = '18'
                Fax                   = '19'
                GivenName             = 'James'
                HomePhone             = '20'
                HomeDirectory         = 'c:\bond'
                Info                  = "best agent"
                IpPhone               = '21'
                Surname               = 'Bond'
                LastLogonDate         = (Get-Date)
                LockedOut             = $false
                Manager               = 'M'
                MobilePhone           = '22'
                Name                  = 'James Bond'
                Office                = 'London'
                OfficePhone           = '23'
                Pager                 = '24'
                PasswordExpired       = $false
                PasswordNeverExpires  = $true
                SamAccountName        = 'jbond'
                ScriptPath            = 'c:\bond\script.ps1'
                Title                 = 'Commander at sea'
                UserPrincipalName     = 'bond@world'
                WhenChanged           = (Get-Date).AddDays(-90)
                WhenCreated           = (Get-Date).AddYears(-10)
            }
        )
        Mock Get-ADUser {
            $testAdUser[0..1]
        }

        $testJsonFile = @{
            AD       = @{
                PropertyToMonitor = @('Description', 'Title')
                PropertyInReport  = @('*')
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
    Context 'and a user account is removed from AD' {
        BeforeAll {
            Mock Get-ADUser {
                $testAdUser[0]
            }

            .$testScript @testParams
        }
        Context 'export an Excel file with all current AD user accounts' {
            BeforeAll {
                $testExportedExcelRows = @(
                    @{
                        AccountExpirationDate     = $testAdUser[0].AccountExpirationDate
                        Country                   = $testAdUser[0].Co
                        Company                   = $testAdUser[0].Company
                        Department                = $testAdUser[0].Department
                        Description               = $testAdUser[0].Description
                        DisplayName               = $testAdUser[0].DisplayName
                        EmailAddress              = $testAdUser[0].EmailAddress
                        EmployeeID                = $testAdUser[0].EmployeeID
                        EmployeeType              = $testAdUser[0].EmployeeType
                        Enabled                   = $testAdUser[0].Enabled
                        Fax                       = $testAdUser[0].Fax
                        FirstName                 = $testAdUser[0].GivenName
                        HeidelbergCementBillingID = $testAdUser[0].extensionAttribute8
                        HomePhone                 = $testAdUser[0].HomePhone
                        HomeDirectory             = $testAdUser[0].HomeDirectory
                        IpPhone                   = $testAdUser[0].IpPhone
                        LastName                  = $testAdUser[0].Surname
                        LastLogonDate             = $testAdUser[0].LastLogonDate
                        LockedOut                 = $testAdUser[0].LockedOut
                        Manager                   = 'manager chuck'
                        MobilePhone               = $testAdUser[0].MobilePhone
                        Name                      = $testAdUser[0].Name
                        Notes                     = 'best guy ever'
                        Office                    = $testAdUser[0].Office
                        OfficePhone               = $testAdUser[0].OfficePhone
                        OU                        = 'OU chuck'
                        Pager                     = $testAdUser[0].Pager
                        PasswordExpired           = $testAdUser[0].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[0].PasswordNeverExpires
                        SamAccountName            = $testAdUser[0].SamAccountName
                        LogonScript               = $testAdUser[0].scriptPath
                        Title                     = $testAdUser[0].Title
                        TSAllowLogon              = 'TS AllowLogon chuck'
                        TSHomeDirectory           = 'TS HomeDirectory chuck'
                        TSHomeDrive               = 'TS HomeDrive chuck'
                        TSUserProfile             = 'TS UserProfile chuck'
                        UserPrincipalName         = $testAdUser[0].UserPrincipalName
                        WhenChanged               = $testAdUser[0].WhenChanged
                        WhenCreated               = $testAdUser[0].WhenCreated
                    }
                )
    
                $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - State{*}.xlsx' | 
                Sort-Object 'CreationTime' | Select-Object -Last 1
    
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
        Context 'export an Excel file with the differences' {
            BeforeAll {
                $testExportedExcelRows = @(
                    @{
                        Status                    = 'REMOVED'
                        UpdatedFields             = ''
                        AccountExpirationDate     = $testAdUser[1].AccountExpirationDate
                        Country                   = $testAdUser[1].Co
                        Company                   = $testAdUser[1].Company
                        Department                = $testAdUser[1].Department
                        Description               = $testAdUser[1].Description
                        DisplayName               = $testAdUser[1].DisplayName
                        EmailAddress              = $testAdUser[1].EmailAddress
                        EmployeeID                = $testAdUser[1].EmployeeID
                        EmployeeType              = $testAdUser[1].EmployeeType
                        Enabled                   = $testAdUser[1].Enabled
                        Fax                       = $testAdUser[1].Fax
                        FirstName                 = $testAdUser[1].GivenName
                        HeidelbergCementBillingID = $testAdUser[1].extensionAttribute8
                        HomePhone                 = $testAdUser[1].HomePhone
                        HomeDirectory             = $testAdUser[1].HomeDirectory
                        IpPhone                   = $testAdUser[1].IpPhone
                        LastName                  = $testAdUser[1].Surname
                        LastLogonDate             = $testAdUser[1].LastLogonDate
                        LockedOut                 = $testAdUser[1].LockedOut
                        Manager                   = 'manager bob'
                        MobilePhone               = $testAdUser[1].MobilePhone
                        Name                      = $testAdUser[1].Name
                        Notes                     = 'best sniper in the world'
                        Office                    = $testAdUser[1].Office
                        OfficePhone               = $testAdUser[1].OfficePhone
                        OU                        = 'OU bob'
                        Pager                     = $testAdUser[1].Pager
                        PasswordExpired           = $testAdUser[1].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[1].PasswordNeverExpires
                        SamAccountName            = $testAdUser[1].SamAccountName
                        LogonScript               = $testAdUser[1].scriptPath
                        Title                     = $testAdUser[1].Title
                        TSAllowLogon              = 'TS AllowLogon bob'
                        TSHomeDirectory           = 'TS HomeDirectory bob'
                        TSHomeDrive               = 'TS HomeDrive bob'
                        TSUserProfile             = 'TS UserProfile bob'
                        UserPrincipalName         = $testAdUser[1].UserPrincipalName
                        WhenChanged               = $testAdUser[1].WhenChanged
                        WhenCreated               = $testAdUser[1].WhenCreated
                    }
                )
    
                $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - Differences{*}.xlsx'
    
                $actual = Import-Excel -Path $testExcelLogFile.FullName -WorksheetName 'Differences'
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
                    $actualRow.Status | Should -Be $testRow.Status
                    $actualRow.UpdatedFields | Should -Be $testRow.UpdatedFields
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
    }
    Context 'and a user account is added to AD' {
        BeforeAll {
            Mock Get-ADUser {
                $testAdUser[0..2]
            }

            .$testScript @testParams
        }
        Context 'export an Excel file with all current AD user accounts' {
            BeforeAll {
                $testExportedExcelRows = @(
                    @{
                        AccountExpirationDate     = $testAdUser[0].AccountExpirationDate
                        Country                   = $testAdUser[0].Co
                        Company                   = $testAdUser[0].Company
                        Department                = $testAdUser[0].Department
                        Description               = $testAdUser[0].Description
                        DisplayName               = $testAdUser[0].DisplayName
                        EmailAddress              = $testAdUser[0].EmailAddress
                        EmployeeID                = $testAdUser[0].EmployeeID
                        EmployeeType              = $testAdUser[0].EmployeeType
                        Enabled                   = $testAdUser[0].Enabled
                        Fax                       = $testAdUser[0].Fax
                        FirstName                 = $testAdUser[0].GivenName
                        HeidelbergCementBillingID = $testAdUser[0].extensionAttribute8
                        HomePhone                 = $testAdUser[0].HomePhone
                        HomeDirectory             = $testAdUser[0].HomeDirectory
                        IpPhone                   = $testAdUser[0].IpPhone
                        LastName                  = $testAdUser[0].Surname
                        LastLogonDate             = $testAdUser[0].LastLogonDate
                        LockedOut                 = $testAdUser[0].LockedOut
                        Manager                   = 'manager chuck'
                        MobilePhone               = $testAdUser[0].MobilePhone
                        Name                      = $testAdUser[0].Name
                        Notes                     = 'best guy ever'
                        Office                    = $testAdUser[0].Office
                        OfficePhone               = $testAdUser[0].OfficePhone
                        OU                        = 'OU chuck'
                        Pager                     = $testAdUser[0].Pager
                        PasswordExpired           = $testAdUser[0].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[0].PasswordNeverExpires
                        SamAccountName            = $testAdUser[0].SamAccountName
                        LogonScript               = $testAdUser[0].scriptPath
                        Title                     = $testAdUser[0].Title
                        TSAllowLogon              = 'TS AllowLogon chuck'
                        TSHomeDirectory           = 'TS HomeDirectory chuck'
                        TSHomeDrive               = 'TS HomeDrive chuck'
                        TSUserProfile             = 'TS UserProfile chuck'
                        UserPrincipalName         = $testAdUser[0].UserPrincipalName
                        WhenChanged               = $testAdUser[0].WhenChanged
                        WhenCreated               = $testAdUser[0].WhenCreated
                    }
                    @{
                        AccountExpirationDate     = $testAdUser[1].AccountExpirationDate
                        Country                   = $testAdUser[1].Co
                        Company                   = $testAdUser[1].Company
                        Department                = $testAdUser[1].Department
                        Description               = $testAdUser[1].Description
                        DisplayName               = $testAdUser[1].DisplayName
                        EmailAddress              = $testAdUser[1].EmailAddress
                        EmployeeID                = $testAdUser[1].EmployeeID
                        EmployeeType              = $testAdUser[1].EmployeeType
                        Enabled                   = $testAdUser[1].Enabled
                        Fax                       = $testAdUser[1].Fax
                        FirstName                 = $testAdUser[1].GivenName
                        HeidelbergCementBillingID = $testAdUser[1].extensionAttribute8
                        HomePhone                 = $testAdUser[1].HomePhone
                        HomeDirectory             = $testAdUser[1].HomeDirectory
                        IpPhone                   = $testAdUser[1].IpPhone
                        LastName                  = $testAdUser[1].Surname
                        LastLogonDate             = $testAdUser[1].LastLogonDate
                        LockedOut                 = $testAdUser[1].LockedOut
                        Manager                   = 'manager bob'
                        MobilePhone               = $testAdUser[1].MobilePhone
                        Name                      = $testAdUser[1].Name
                        Notes                     = 'best sniper in the world'
                        Office                    = $testAdUser[1].Office
                        OfficePhone               = $testAdUser[1].OfficePhone
                        OU                        = 'OU bob'
                        Pager                     = $testAdUser[1].Pager
                        PasswordExpired           = $testAdUser[1].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[1].PasswordNeverExpires
                        SamAccountName            = $testAdUser[1].SamAccountName
                        LogonScript               = $testAdUser[1].scriptPath
                        Title                     = $testAdUser[1].Title
                        TSAllowLogon              = 'TS AllowLogon bob'
                        TSHomeDirectory           = 'TS HomeDirectory bob'
                        TSHomeDrive               = 'TS HomeDrive bob'
                        TSUserProfile             = 'TS UserProfile bob'
                        UserPrincipalName         = $testAdUser[1].UserPrincipalName
                        WhenChanged               = $testAdUser[1].WhenChanged
                        WhenCreated               = $testAdUser[1].WhenCreated
                    }
                    @{
                        AccountExpirationDate     = $testAdUser[2].AccountExpirationDate
                        Country                   = $testAdUser[2].Co
                        Company                   = $testAdUser[2].Company
                        Department                = $testAdUser[2].Department
                        Description               = $testAdUser[2].Description
                        DisplayName               = $testAdUser[2].DisplayName
                        EmailAddress              = $testAdUser[2].EmailAddress
                        EmployeeID                = $testAdUser[2].EmployeeID
                        EmployeeType              = $testAdUser[2].EmployeeType
                        Enabled                   = $testAdUser[2].Enabled
                        Fax                       = $testAdUser[2].Fax
                        FirstName                 = $testAdUser[2].GivenName
                        HeidelbergCementBillingID = $testAdUser[2].extensionAttribute8
                        HomePhone                 = $testAdUser[2].HomePhone
                        HomeDirectory             = $testAdUser[2].HomeDirectory
                        IpPhone                   = $testAdUser[2].IpPhone
                        LastName                  = $testAdUser[2].Surname
                        LastLogonDate             = $testAdUser[2].LastLogonDate
                        LockedOut                 = $testAdUser[2].LockedOut
                        Manager                   = 'manager bond'
                        MobilePhone               = $testAdUser[2].MobilePhone
                        Name                      = $testAdUser[2].Name
                        Notes                     = 'best agent'
                        Office                    = $testAdUser[2].Office
                        OfficePhone               = $testAdUser[2].OfficePhone
                        OU                        = 'OU bond'
                        Pager                     = $testAdUser[2].Pager
                        PasswordExpired           = $testAdUser[2].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[2].PasswordNeverExpires
                        SamAccountName            = $testAdUser[2].SamAccountName
                        LogonScript               = $testAdUser[2].scriptPath
                        Title                     = $testAdUser[2].Title
                        TSAllowLogon              = 'TS AllowLogon bond'
                        TSHomeDirectory           = 'TS HomeDirectory bond'
                        TSHomeDrive               = 'TS HomeDrive bond'
                        TSUserProfile             = 'TS UserProfile bond'
                        UserPrincipalName         = $testAdUser[2].UserPrincipalName
                        WhenChanged               = $testAdUser[2].WhenChanged
                        WhenCreated               = $testAdUser[2].WhenCreated
                    }
                )    
    
                $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - State{*}.xlsx' | 
                Sort-Object 'CreationTime' | Select-Object -Last 1
    
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
        Context 'export an Excel file with the differences' {
            BeforeAll {
                $testExportedExcelRows = @(
                    @{
                        Status                    = 'ADDED'
                        UpdatedFields             = ''
                        AccountExpirationDate     = $testAdUser[2].AccountExpirationDate
                        Country                   = $testAdUser[2].Co
                        Company                   = $testAdUser[2].Company
                        Department                = $testAdUser[2].Department
                        Description               = $testAdUser[2].Description
                        DisplayName               = $testAdUser[2].DisplayName
                        EmailAddress              = $testAdUser[2].EmailAddress
                        EmployeeID                = $testAdUser[2].EmployeeID
                        EmployeeType              = $testAdUser[2].EmployeeType
                        Enabled                   = $testAdUser[2].Enabled
                        Fax                       = $testAdUser[2].Fax
                        FirstName                 = $testAdUser[2].GivenName
                        HeidelbergCementBillingID = $testAdUser[2].extensionAttribute8
                        HomePhone                 = $testAdUser[2].HomePhone
                        HomeDirectory             = $testAdUser[2].HomeDirectory
                        IpPhone                   = $testAdUser[2].IpPhone
                        LastName                  = $testAdUser[2].Surname
                        LastLogonDate             = $testAdUser[2].LastLogonDate
                        LockedOut                 = $testAdUser[2].LockedOut
                        Manager                   = 'manager bond'
                        MobilePhone               = $testAdUser[2].MobilePhone
                        Name                      = $testAdUser[2].Name
                        Notes                     = 'best agent'
                        Office                    = $testAdUser[2].Office
                        OfficePhone               = $testAdUser[2].OfficePhone
                        OU                        = 'OU bond'
                        Pager                     = $testAdUser[2].Pager
                        PasswordExpired           = $testAdUser[2].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[2].PasswordNeverExpires
                        SamAccountName            = $testAdUser[2].SamAccountName
                        LogonScript               = $testAdUser[2].scriptPath
                        Title                     = $testAdUser[2].Title
                        TSAllowLogon              = 'TS AllowLogon bond'
                        TSHomeDirectory           = 'TS HomeDirectory bond'
                        TSHomeDrive               = 'TS HomeDrive bond'
                        TSUserProfile             = 'TS UserProfile bond'
                        UserPrincipalName         = $testAdUser[2].UserPrincipalName
                        WhenChanged               = $testAdUser[2].WhenChanged
                        WhenCreated               = $testAdUser[2].WhenCreated
                    }
                )
    
                $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - Differences{*}.xlsx'
    
                $actual = Import-Excel -Path $testExcelLogFile.FullName -WorksheetName 'Differences'
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
                    $actualRow.Status | Should -Be $testRow.Status
                    $actualRow.UpdatedFields | Should -Be $testRow.UpdatedFields
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
    }
    Context 'and a user account is updated in AD' {
        BeforeAll {
            $testOriginalValue = @{
                Description = $testAdUser[0].Description
                Title       = $testAdUser[0].Title
            }

            $testAdUser[0].Description = 'changed description'
            $testAdUser[0].Title = 'changed title'

            Mock Get-ADUser {
                $testAdUser[0..1]
            }

            .$testScript @testParams
        }
        Context 'export an Excel file with all current AD user accounts' {
            BeforeAll {
                $testExportedExcelRows = @(
                    @{
                        AccountExpirationDate     = $testAdUser[0].AccountExpirationDate
                        Country                   = $testAdUser[0].Co
                        Company                   = $testAdUser[0].Company
                        Department                = $testAdUser[0].Department
                        Description               = $testAdUser[0].Description
                        DisplayName               = $testAdUser[0].DisplayName
                        EmailAddress              = $testAdUser[0].EmailAddress
                        EmployeeID                = $testAdUser[0].EmployeeID
                        EmployeeType              = $testAdUser[0].EmployeeType
                        Enabled                   = $testAdUser[0].Enabled
                        Fax                       = $testAdUser[0].Fax
                        FirstName                 = $testAdUser[0].GivenName
                        HeidelbergCementBillingID = $testAdUser[0].extensionAttribute8
                        HomePhone                 = $testAdUser[0].HomePhone
                        HomeDirectory             = $testAdUser[0].HomeDirectory
                        IpPhone                   = $testAdUser[0].IpPhone
                        LastName                  = $testAdUser[0].Surname
                        LastLogonDate             = $testAdUser[0].LastLogonDate
                        LockedOut                 = $testAdUser[0].LockedOut
                        Manager                   = 'manager chuck'
                        MobilePhone               = $testAdUser[0].MobilePhone
                        Name                      = $testAdUser[0].Name
                        Notes                     = 'best guy ever'
                        Office                    = $testAdUser[0].Office
                        OfficePhone               = $testAdUser[0].OfficePhone
                        OU                        = 'OU chuck'
                        Pager                     = $testAdUser[0].Pager
                        PasswordExpired           = $testAdUser[0].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[0].PasswordNeverExpires
                        SamAccountName            = $testAdUser[0].SamAccountName
                        LogonScript               = $testAdUser[0].scriptPath
                        Title                     = $testAdUser[0].Title
                        TSAllowLogon              = 'TS AllowLogon chuck'
                        TSHomeDirectory           = 'TS HomeDirectory chuck'
                        TSHomeDrive               = 'TS HomeDrive chuck'
                        TSUserProfile             = 'TS UserProfile chuck'
                        UserPrincipalName         = $testAdUser[0].UserPrincipalName
                        WhenChanged               = $testAdUser[0].WhenChanged
                        WhenCreated               = $testAdUser[0].WhenCreated
                    }
                    @{
                        AccountExpirationDate     = $testAdUser[1].AccountExpirationDate
                        Country                   = $testAdUser[1].Co
                        Company                   = $testAdUser[1].Company
                        Department                = $testAdUser[1].Department
                        Description               = $testAdUser[1].Description
                        DisplayName               = $testAdUser[1].DisplayName
                        EmailAddress              = $testAdUser[1].EmailAddress
                        EmployeeID                = $testAdUser[1].EmployeeID
                        EmployeeType              = $testAdUser[1].EmployeeType
                        Enabled                   = $testAdUser[1].Enabled
                        Fax                       = $testAdUser[1].Fax
                        FirstName                 = $testAdUser[1].GivenName
                        HeidelbergCementBillingID = $testAdUser[1].extensionAttribute8
                        HomePhone                 = $testAdUser[1].HomePhone
                        HomeDirectory             = $testAdUser[1].HomeDirectory
                        IpPhone                   = $testAdUser[1].IpPhone
                        LastName                  = $testAdUser[1].Surname
                        LastLogonDate             = $testAdUser[1].LastLogonDate
                        LockedOut                 = $testAdUser[1].LockedOut
                        Manager                   = 'manager bob'
                        MobilePhone               = $testAdUser[1].MobilePhone
                        Name                      = $testAdUser[1].Name
                        Notes                     = 'best sniper in the world'
                        Office                    = $testAdUser[1].Office
                        OfficePhone               = $testAdUser[1].OfficePhone
                        OU                        = 'OU bob'
                        Pager                     = $testAdUser[1].Pager
                        PasswordExpired           = $testAdUser[1].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[1].PasswordNeverExpires
                        SamAccountName            = $testAdUser[1].SamAccountName
                        LogonScript               = $testAdUser[1].scriptPath
                        Title                     = $testAdUser[1].Title
                        TSAllowLogon              = 'TS AllowLogon bob'
                        TSHomeDirectory           = 'TS HomeDirectory bob'
                        TSHomeDrive               = 'TS HomeDrive bob'
                        TSUserProfile             = 'TS UserProfile bob'
                        UserPrincipalName         = $testAdUser[1].UserPrincipalName
                        WhenChanged               = $testAdUser[1].WhenChanged
                        WhenCreated               = $testAdUser[1].WhenCreated
                    }
                )    
    
                $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - State{*}.xlsx' | 
                Sort-Object 'CreationTime' | Select-Object -Last 1
    
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
        Context 'export an Excel file with the differences' {
            BeforeAll {
                $testExportedExcelRows = @(
                    @{
                        Status                    = 'AFTER_UPDATE'
                        UpdatedFields             = 'Description, Title'
                        AccountExpirationDate     = $testAdUser[0].AccountExpirationDate
                        Country                   = $testAdUser[0].Co
                        Company                   = $testAdUser[0].Company
                        Department                = $testAdUser[0].Department
                        Description               = $testAdUser[0].Description
                        DisplayName               = $testAdUser[0].DisplayName
                        EmailAddress              = $testAdUser[0].EmailAddress
                        EmployeeID                = $testAdUser[0].EmployeeID
                        EmployeeType              = $testAdUser[0].EmployeeType
                        Enabled                   = $testAdUser[0].Enabled
                        Fax                       = $testAdUser[0].Fax
                        FirstName                 = $testAdUser[0].GivenName
                        HeidelbergCementBillingID = $testAdUser[0].extensionAttribute8
                        HomePhone                 = $testAdUser[0].HomePhone
                        HomeDirectory             = $testAdUser[0].HomeDirectory
                        IpPhone                   = $testAdUser[0].IpPhone
                        LastName                  = $testAdUser[0].Surname
                        LastLogonDate             = $testAdUser[0].LastLogonDate
                        LockedOut                 = $testAdUser[0].LockedOut
                        Manager                   = 'manager chuck'
                        MobilePhone               = $testAdUser[0].MobilePhone
                        Name                      = $testAdUser[0].Name
                        Notes                     = 'best guy ever'
                        Office                    = $testAdUser[0].Office
                        OfficePhone               = $testAdUser[0].OfficePhone
                        OU                        = 'OU chuck'
                        Pager                     = $testAdUser[0].Pager
                        PasswordExpired           = $testAdUser[0].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[0].PasswordNeverExpires
                        SamAccountName            = $testAdUser[0].SamAccountName
                        LogonScript               = $testAdUser[0].scriptPath
                        Title                     = $testAdUser[0].Title
                        TSAllowLogon              = 'TS AllowLogon chuck'
                        TSHomeDirectory           = 'TS HomeDirectory chuck'
                        TSHomeDrive               = 'TS HomeDrive chuck'
                        TSUserProfile             = 'TS UserProfile chuck'
                        UserPrincipalName         = $testAdUser[0].UserPrincipalName
                        WhenChanged               = $testAdUser[0].WhenChanged
                        WhenCreated               = $testAdUser[0].WhenCreated
                    }
                    @{
                        Status                    = 'BEFORE_UPDATE'
                        UpdatedFields             = 'Description, Title'
                        AccountExpirationDate     = $testAdUser[0].AccountExpirationDate
                        Country                   = $testAdUser[0].Co
                        Company                   = $testAdUser[0].Company
                        Department                = $testAdUser[0].Department
                        Description               = $testOriginalValue.Description
                        DisplayName               = $testAdUser[0].DisplayName
                        EmailAddress              = $testAdUser[0].EmailAddress
                        EmployeeID                = $testAdUser[0].EmployeeID
                        EmployeeType              = $testAdUser[0].EmployeeType
                        Enabled                   = $testAdUser[0].Enabled
                        Fax                       = $testAdUser[0].Fax
                        FirstName                 = $testAdUser[0].GivenName
                        HeidelbergCementBillingID = $testAdUser[0].extensionAttribute8
                        HomePhone                 = $testAdUser[0].HomePhone
                        HomeDirectory             = $testAdUser[0].HomeDirectory
                        IpPhone                   = $testAdUser[0].IpPhone
                        LastName                  = $testAdUser[0].Surname
                        LastLogonDate             = $testAdUser[0].LastLogonDate
                        LockedOut                 = $testAdUser[0].LockedOut
                        Manager                   = 'manager chuck'
                        MobilePhone               = $testAdUser[0].MobilePhone
                        Name                      = $testAdUser[0].Name
                        Notes                     = 'best guy ever'
                        Office                    = $testAdUser[0].Office
                        OfficePhone               = $testAdUser[0].OfficePhone
                        OU                        = 'OU chuck'
                        Pager                     = $testAdUser[0].Pager
                        PasswordExpired           = $testAdUser[0].PasswordExpired
                        PasswordNeverExpires      = $testAdUser[0].PasswordNeverExpires
                        SamAccountName            = $testAdUser[0].SamAccountName
                        LogonScript               = $testAdUser[0].scriptPath
                        Title                     = $testOriginalValue.Title
                        TSAllowLogon              = 'TS AllowLogon chuck'
                        TSHomeDirectory           = 'TS HomeDirectory chuck'
                        TSHomeDrive               = 'TS HomeDrive chuck'
                        TSUserProfile             = 'TS UserProfile chuck'
                        UserPrincipalName         = $testAdUser[0].UserPrincipalName
                        WhenChanged               = $testAdUser[0].WhenChanged
                        WhenCreated               = $testAdUser[0].WhenCreated
                    }
                )
    
                $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - Differences{*}.xlsx'
    
                $actual = Import-Excel -Path $testExcelLogFile.FullName -WorksheetName 'Differences'
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
                        $_.Status -eq $testRow.Status
                    }
                    $actualRow.SamAccountName | 
                    Should -Be $testRow.SamAccountName
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
    }
}
Describe 'monitor only the requested AD properties' {
    BeforeAll {
        $testAdUser = @(
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
        )
        
        Mock Get-ADUser {
            $testAdUser
        }

        $testJsonFile = @{
            AD       = @{
                PropertyToMonitor = @('Description')
                PropertyInReport  = @('Office', 'Title')
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
    Context 'to the Excel file with the differences' {
        BeforeAll {
            $testOriginalValue = @{
                Description = $testAdUser[0].Description
            }

            $testAdUser[0].Description = 'changed description'
            $testAdUser[1].Title = 'changed title'

            Mock Get-ADUser {
                $testAdUser
            }

            .$testScript @testParams

            $testExportedExcelRows = @(
                @{
                    Status         = 'AFTER_UPDATE'
                    UpdatedFields  = 'Description'
                    Description    = $testAdUser[0].Description
                    Office         = $testAdUser[0].Office
                    SamAccountName = $testAdUser[0].SamAccountName
                    Title          = $testAdUser[0].Title
                }
                @{
                    Status         = 'BEFORE_UPDATE'
                    UpdatedFields  = 'Description'
                    Description    = $testOriginalValue.Description
                    Office         = $testAdUser[0].Office
                    SamAccountName = $testAdUser[0].SamAccountName
                    Title          = $testAdUser[0].Title
                }
            )

            $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - Differences{*}.xlsx'

            $actual = Import-Excel -Path $testExcelLogFile.FullName -WorksheetName 'Differences'
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
                    $_.Status -eq $testRow.Status
                }
                $actualRow.SamAccountName | 
                Should -Be $testRow.SamAccountName
                $actualRow.Description | Should -Be $testRow.Description
                $actualRow.Office | Should -Be $testRow.Office
                $actualRow.Title | Should -Be $testRow.Title
                $actualRow.UpdatedFields | Should -Be $testRow.UpdatedFields

                foreach (
                    $testProp in 
                    $actualRow.PSObject.Properties.Name 
                ) {
                    @(
                        'SamAccountName', 'Status', 'UpdatedFields',
                        'Description', 'Title', 'Office'
                    ) | 
                    Should -Contain $testProp
                }
            }
        }
    }
}
Describe 'export only the requested AD properties' {
    BeforeAll {
        $testAdUser = @(
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
        )
        
        Mock Get-ADUser {
            $testAdUser
        }

        $testJsonFile = @{
            AD       = @{
                PropertyToMonitor = @('Description', 'Title')
                PropertyInReport  = @('Office')
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
    Context 'to the Excel file with the differences' {
        BeforeAll {
            $testOriginalValue = @{
                Description = $testAdUser[0].Description
                Title       = $testAdUser[0].Title
            }

            $testAdUser[0].Description = 'changed description'
            $testAdUser[0].Title = 'changed title'

            Mock Get-ADUser {
                $testAdUser
            }

            .$testScript @testParams

            $testExportedExcelRows = @(
                @{
                    Status         = 'AFTER_UPDATE'
                    UpdatedFields  = 'Description, Title'
                    Description    = $testAdUser[0].Description
                    Office         = $testAdUser[0].Office
                    SamAccountName = $testAdUser[0].SamAccountName
                    Title          = $testAdUser[0].Title
                }
                @{
                    Status         = 'BEFORE_UPDATE'
                    UpdatedFields  = 'Description, Title'
                    Description    = $testOriginalValue.Description
                    Office         = $testAdUser[0].Office
                    SamAccountName = $testAdUser[0].SamAccountName
                    Title          = $testOriginalValue.Title
                }
            )

            $testExcelLogFile = Get-ChildItem $testParams.LogFolder -File -Recurse -Filter '* - Differences{*}.xlsx'

            $actual = Import-Excel -Path $testExcelLogFile.FullName -WorksheetName 'Differences'
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
                    $_.Status -eq $testRow.Status
                }
                $actualRow.SamAccountName | 
                Should -Be $testRow.SamAccountName
                $actualRow.Description | Should -Be $testRow.Description
                $actualRow.Office | Should -Be $testRow.Office
                $actualRow.Title | Should -Be $testRow.Title
                $actualRow.UpdatedFields | Should -Be $testRow.UpdatedFields

                foreach (
                    $testProp in 
                    $actualRow.PSObject.Properties.Name 
                ) {
                    @(
                        'SamAccountName', 'Status', 'UpdatedFields',
                        'Description', 'Title', 'Office'
                    ) | 
                    Should -Contain $testProp
                }
            }
        }
    }
}
Describe 'send a mail with SendMail.When set to Always when' {
    BeforeAll {
        $testAdUser = @(
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
        )
        
        Mock Get-ADUser {
            $testAdUser[0]
        }

        $testJsonFile = @{
            AD       = @{
                PropertyToMonitor = @('Description', 'Title')
                PropertyInReport  = @('Office')
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
    Context 'no changes are detected' {
        BeforeAll {
            .$testScript @testParams

            $testMail = @{
                To       = $testJsonFile.SendMail.To
                Bcc      = $ScriptAdmin
                Priority = 'Normal'
                Subject  = 'No changes detected'
                Message  = "*<p>AD user accounts:*"
            }
        }
        It 'Send-MailHC has the correct arguments' {
            $mailParams.To | Should -Be $testMail.To
            $mailParams.Bcc | Should -Be $testMail.Bcc
            $mailParams.Priority | Should -Be $testMail.Priority
            $mailParams.Subject | Should -Be $testMail.Subject
            $mailParams.Message | Should -BeLike $testMail.Message
            $mailParams.Attachments | Should -BeNullOrEmpty
        }
        It 'Send-MailHC is called' {
            Should -Invoke Send-MailHC -Exactly 1 -Scope Context -ParameterFilter {
            ($To -eq $testMail.To) -and
            ($Bcc -eq $testMail.Bcc) -and
            ($Priority -eq $testMail.Priority) -and
            ($Subject -eq $testMail.Subject) -and
            (-not $Attachments) -and
            ($Message -like $testMail.Message)
            }
        }
    }
    Context 'changes are detected' {
        BeforeAll {
            Mock Get-ADUser {
                $testAdUser[0..1]
            }

            .$testScript @testParams
            
            $currentAdUsers | Should -HaveCount 2
            $previousAdUsers | Should -HaveCount 1

            $testMail = @{
                To          = $testJsonFile.SendMail.To
                Bcc         = $ScriptAdmin
                Priority    = 'Normal'
                Subject     = '1 added, 0 updated, 0 removed'
                Message     = "*<p>AD user accounts:</p>*Check the attachment for details*"
                Attachments = '* - Differences{*}.xlsx'
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
            Should -Invoke Send-MailHC -Exactly 1 -Scope Context -ParameterFilter {
            ($To -eq $testMail.To) -and
            ($Bcc -eq $testMail.Bcc) -and
            ($Priority -eq $testMail.Priority) -and
            ($Subject -eq $testMail.Subject) -and
            ($Attachments -like $testMail.Attachments) -and
            ($Message -like $testMail.Message)
            }
        }
    }
}
Describe 'with SendMail.When set to OnlyWhenChangesAreFound' {
    BeforeAll {
        $testAdUser = @(
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
        )
        
        Mock Get-ADUser {
            $testAdUser[0]
        }

        $testJsonFile = @{
            AD       = @{
                PropertyToMonitor = @('Description', 'Title')
                PropertyInReport  = @('Office')
                OU                = @('OU=BEL,OU=EU,DC=contoso,DC=com')
            }
            SendMail = @{
                When = 'OnlyWhenChangesAreFound'
                To   = 'bob@contoso.com'
            }
        }
        $testJsonFile | ConvertTo-Json -Depth 3 | Out-File @testOutParams

        .$testScript @testParams
    }
    Context 'send no mail when there are no changes' {
        BeforeAll {
            .$testScript @testParams
        }
        It 'Send-MailHC is not called' {
            Should -Not -Invoke Send-MailHC  -Scope Context
        }
    }
    Context 'send a mail when there are changes' {
        BeforeAll {
            Mock Get-ADUser {
                $testAdUser[0..1]
            }

            .$testScript @testParams

            $testMail = @{
                To          = $testJsonFile.SendMail.To
                Bcc         = $ScriptAdmin
                Priority    = 'Normal'
                Subject     = '1 added, 0 updated, 0 removed'
                Message     = "*<p>AD user accounts:</p>*Check the attachment for details*"
                Attachments = '* - Differences{*}.xlsx'
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
            Should -Invoke Send-MailHC -Exactly 1 -Scope Context -ParameterFilter {
            ($To -eq $testMail.To) -and
            ($Bcc -eq $testMail.Bcc) -and
            ($Priority -eq $testMail.Priority) -and
            ($Subject -eq $testMail.Subject) -and
            ($Attachments -like $testMail.Attachments) -and
            ($Message -like $testMail.Message)
            }
        }
    }
}