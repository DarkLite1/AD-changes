#Requires -Version 5.1
#Requires -Modules ActiveDirectory, ImportExcel
#Requires -Modules Toolbox.HTML, Toolbox.EventLog

<#
    .SYNOPSIS
        Monitor changes in AD and send an e-mail when changes have been found.

    .DESCRIPTION
        When the script runs it always creates a single Excel file containing 
        all the active directory user accounts with their current state.
        - Ex. 2022-09-31 AD State.xlsx

        The second step for the script is to compare the latest Excel file 
        (not the one from today) with the current AD user accounts and report
        the differences in a second Excel file.
        - Ex. 2022-09-31 AD Changes.xlsx

    .PARAMETER OU
        Collection of organizational units in AD where to search for user 
        accounts.

    .PARAMETER AD.PropertyToMonitor
        Collection of AD fields where to look for changes. All other fields are 
        disregarded.

    .PARAMETER AD.PropertyInReport
        Collection of AD fields to export to the Excel file where the changes
        are reported.

    .PARAMETER SendMail.Header
        The header to use in the e-mail sent to the end user.

    .PARAMETER SendMail.To
        List of e-mail addresses where to send the e-mail too.

    .PARAMETER SendMail.When
        When an e-mail will be sent to the end user.
        Valid options:
        - OnlyWhenChangesAreFound : when no changes are found not e-mail is sent
        - Always                  : always sent an e-mail, even when no changes 
                                    are found
#>

Param (
    [Parameter(Mandatory)]
    [String]$ScriptName,
    [Parameter(Mandatory)]
    [String]$ImportFile,
    [String]$LogFolder = "$env:POWERSHELL_LOG_FOLDER\AD Reports\AD changes\$ScriptName",
    [String[]]$ScriptAdmin = $env:POWERSHELL_SCRIPT_ADMIN
)

Begin {
    Try {
        $now = Get-ScriptRuntimeHC -Start
        Import-EventLogParamsHC -Source $ScriptName
        Write-EventLog @EventStartParams

        #region Logging
        try {
            $logParams = @{
                LogFolder    = New-Item -Path $LogFolder -ItemType 'Directory' -Force -ErrorAction 'Stop'
                Name         = $ScriptName
                Date         = 'ScriptStartTime'
                NoFormatting = $true
            }
            $logFile = New-LogFileNameHC @LogParams
        }
        Catch {
            throw "Failed creating the log folder '$LogFolder': $_"
        }
        #endregion

        try {
            #region Import .json file
            $M = "Import .json file '$ImportFile'"
            Write-Verbose $M; Write-EventLog @EventVerboseParams -Message $M

            $file = Get-Content $ImportFile -Raw -EA Stop | ConvertFrom-Json
            #endregion

            #region Test .json file
            if (-not ($adPropertyToMonitor = $file.AD.PropertyToMonitor)) {
                throw "Property 'AD.PropertyToMonitor' not found."
            }
            if (-not ($adPropertyInReport = $file.AD.PropertyInReport)) {
                throw "Property 'AD.PropertyInReport' not found."
            }
            if (-not ($adOU = $file.AD.OU)) {
                throw "Property 'AD.OU' not found."
            }
            if (-not ($mailTo = $file.SendMail.To)) {
                throw "Property 'SendMail.To' not found."
            }
            if (-not ($mailWhen = $file.SendMail.When)) {
                throw "Property 'SendMail.When' not found."
            }
            if (
                $mailWhen -notMatch '^Always$|^OnlyWhenChangesAreFound$'
            ) {
                throw "The value '$mailWhen' in 'SendMail.When' is not supported. Only the value 'Always' or 'OnlyWhenChangesAreFound' can be used."
            }

            $adProperties = @(
                @{
                    Name       = 'AccountExpirationDate'
                    Expression = { $_.AccountExpirationDate } 
                },
                @{
                    Name       = 'Country'
                    Expression = { $_.co } 
                },
                @{
                    Name       = 'Company'
                    Expression = { $_.Company } 
                },
                @{
                    Name       = 'Department'
                    Expression = { $_.Department } 
                },
                @{
                    Name       = 'Description'
                    Expression = { $_.Description } 
                },
                @{
                    Name       = 'DisplayName'
                    Expression = { $_.DisplayName } 
                },
                @{
                    Name       = 'EmailAddress'
                    Expression = { $_.EmailAddress } 
                },
                @{
                    Name       = 'EmployeeID'
                    Expression = { $_.EmployeeID } 
                },
                @{
                    Name       = 'EmployeeType'
                    Expression = { $_.EmployeeType } 
                },
                @{
                    Name       = 'Enabled'
                    Expression = { $_.Enabled } 
                },
                @{
                    Name       = 'Fax'
                    Expression = { $_.Fax } 
                },
                @{
                    Name       = 'FirstName'
                    Expression = { $_.GivenName } 
                }, 
                @{
                    Name       = 'HeidelbergCementBillingID'
                    Expression = { $_.extensionAttribute8 } 
                },
                @{
                    Name       = 'HomePhone'
                    Expression = { $_.HomePhone } 
                },
                @{
                    Name       = 'HomeDirectory'
                    Expression = { $_.HomeDirectory } 
                },
                @{
                    Name       = 'IpPhone'
                    Expression = { $_.IpPhone } 
                },
                @{
                    Name       = 'LastName'
                    Expression = { $_.Surname } 
                }, 
                @{
                    Name       = 'LastLogonDate'
                    Expression = { $_.LastLogonDate } 
                }, 
                @{
                    Name       = 'LockedOut'
                    Expression = { $_.LockedOut } 
                }, 
                @{
                    Name       = 'Manager'
                    Expression = { 
                        if ($_.manager) { Get-ADDisplayNameHC $_.manager }
                    }
                }, 
                @{
                    Name       = 'MobilePhone'
                    Expression = { $_.MobilePhone } 
                }, 
                @{
                    Name       = 'Name'
                    Expression = { $_.Name } 
                }, 
                @{
                    Name       = 'Notes'
                    Expression = { $_.info -replace "`n", ' ' } 
                },
                @{
                    Name       = 'Office'
                    Expression = { $_.Office } 
                }, 
                @{
                    Name       = 'OfficePhone'
                    Expression = { $_.OfficePhone } 
                }, 
                @{
                    Name       = 'OU'
                    Expression = {
                        ConvertTo-OuNameHC $_.CanonicalName
                    }
                },
                @{
                    Name       = 'Pager'
                    Expression = { $_.Pager } 
                }, 
                @{
                    Name       = 'PasswordExpired'
                    Expression = { $_.PasswordExpired } 
                }, 
                @{
                    Name       = 'PasswordNeverExpires'
                    Expression = { $_.PasswordNeverExpires } 
                }, 
                @{
                    Name       = 'SamAccountName'
                    Expression = { $_.SamAccountName } 
                }, 
                @{
                    Name       = 'LogonScript'
                    Expression = { $_.scriptPath } 
                }, 
                @{
                    Name       = 'Title'
                    Expression = { $_.Title } 
                }, 
                @{
                    Name       = 'TSAllowLogon'
                    Expression = {
                        Get-ADTsProfileHC $_.DistinguishedName 'AllowLogon'
                    }
                },
                @{
                    Name       = 'TSHomeDirectory'
                    Expression = { 
                        Get-ADTsProfileHC $_.DistinguishedName 'HomeDirectory' 
                    }
                }, 
                @{
                    Name       = 'TSHomeDrive'
                    Expression = {
                        Get-ADTsProfileHC $_.DistinguishedName 'HomeDrive'
                    }
                }, 
                @{
                    Name       = 'TSUserProfile'
                    Expression = {
                        Get-ADTsProfileHC $_.DistinguishedName 'UserProfile' 
                    } 
                },
                @{
                    Name       = 'UserPrincipalName'
                    Expression = { $_.UserPrincipalName } 
                }, 
                @{
                    Name       = 'WhenChanged'
                    Expression = { $_.WhenChanged } 
                }, 
                @{
                    Name       = 'WhenCreated'
                    Expression = { $_.WhenCreated } 
                }
            )

            $adPropertyToMonitor | Where-Object { 
                $adProperties.Name -notContains $_ 
            } | ForEach-Object {
                throw "Property '$_' defined in 'AD.PropertyToMonitor' is not a valid AD property. Valid AD properties are: $($adProperties.Name)"
            }
            $adPropertyInReport | Where-Object { 
                $adProperties.Name -notContains $_ 
            } | ForEach-Object {
                throw "Property '$_' defined in 'AD.PropertyInReport' is not a valid AD property. Valid AD properties are: $($adProperties.Name)"
            }
            #endregion
        }
        catch {
            throw "Failed to import file '$ImportFile': $_"
        }
    }
    Catch {
        Write-Warning $_
        Send-MailHC -To $ScriptAdmin -Subject 'FAILURE' -Priority 'High' -Message $_ -Header $ScriptName
        Write-EventLog @EventErrorParams -Message "FAILURE:`n`n- $_"
        Write-EventLog @EventEndParams; Exit 1
    }
}
Process {
    Try {
        #region Get current AD users
        $currentAdUsers = foreach ($ou in $adOU) {
            $M = "Get user accounts in OU '$ou'"
            Write-Verbose $M; Write-EventLog @EventVerboseParams -Message $M

            Get-ADUser -SearchBase $ou -Filter '*' -Properties @(
                'AccountExpirationDate', 'CanonicalName', 'Co', 'Company', 
                'Department', 'Description', 'DisplayName', 
                'DistinguishedName', 'EmailAddress', 'EmployeeID', 
                'EmployeeType', 'Enabled', 'ExtensionAttribute8', 'Fax', 
                'GivenName', 'HomePhone', 'HomeDirectory', 'Info', 'IpPhone', 
                'Surname', 'LastLogonDate', 'LockedOut', 'Manager', 
                'MobilePhone', 'Name', 'Office', 'OfficePhone', 'Pager', 
                'PasswordExpired', 'PasswordNeverExpires', 'SamAccountName', 
                'ScriptPath', 'Title', 'UserPrincipalName', 'WhenChanged' , 
                'WhenCreated'
            ) |
            Select-Object -Property $adProperties
        }

        if (-not $currentAdUsers) {
            throw 'No AD user accounts found'
        }
        #endregion

        #region Export all AD users to Excel file
        $excelParams = @{
            Path          = "$logFile - State.xlsx"
            WorksheetName = 'AllUsers'
            TableName     = 'AllUsers'
            AutoSize      = $true
            FreezeTopRow  = $true
            Verbose       = $false
        }

        $M = "Export all AD users to Excel file '{0}'" -f $excelParams.Path
        Write-Verbose $M; Write-EventLog @EventOutParams -Message $M

        $currentAdUsers | Export-Excel @excelParams
        #endregion

        #region Get previously exported AD users
        $M = "Get previously exported AD users from the latest Excel file in folder '{0}'" -f $logParams.LogFolder
        Write-Verbose $M; Write-EventLog @EventOutParams -Message $M

        $params = @{
            LiteralPath = $logParams.LogFolder
            Filter      = '* - State.xlsx'
            File        = $true
        }
        $lastExcelFile = Get-ChildItem @params | Where-Object {
            $_.CreationTime -lt $now
        } | Sort-Object 'CreationTime' | Select-Object -Last 1

        $M = "Last Excel file containing AD users accounts is '{0}'" -f $lastExcelFile.FullName
        Write-Verbose $M; Write-EventLog @EventOutParams -Message $M

        if (-not $lastExcelFile) {
            $M = 'No comparison possible because there is no previously exported Excel file with AD user accounts yet. The next run will not have this issue because a snapshot of the current AD users has just been created and exported to Excel. This file will then be used for comparison on the next run.'
            Write-Verbose $M; Write-EventLog @EventVerboseParams -Message $M
            Exit
        }
        
        $params = @{
            Path          = $lastExcelFile.FullName
            WorksheetName = $excelParams.WorksheetName
            ErrorAction   = 'Stop'
        }
        $previousAdUsers = Import-Excel @params

        if (-not $previousAdUsers) {
            throw 'No previously exported AD user accounts found'
        }
        #endregion
    }
    Catch {
        Write-Warning $_
        Send-MailHC -To $ScriptAdmin -Subject 'FAILURE' -Priority 'High' -Message $_ -Header $ScriptName
        Write-EventLog @EventErrorParams -Message "FAILURE:`n`n- $_"; Exit 1
    }
    Finally {
        Write-EventLog @EventEndParams
    }
}