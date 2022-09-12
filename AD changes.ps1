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
        Get-ScriptRuntimeHC -Start
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
                'AccountExpirationDate', 'department', 'description',
                'displayName', 'CanonicalName', 'co', 'company',
                'EmailAddress', 'EmployeeID', 'extensionAttribute8',
                'employeeType', 'Fax', 'homeDirectory', 'info', 'ipPhone',
                'manager', 'Office', 'OfficePhone', 'HomePhone', 'MobilePhone',
                'pager', 'PasswordNeverExpires', 'SamAccountName', 'scriptPath',
                'title', 'UserPrincipalName', 'whenChanged', 'whenCreated'
            )
            $adPropertyToMonitor | Where-Object { 
                $adProperties -notContains $_ 
            } | ForEach-Object {
                throw "Property '$_' defined in 'AD.PropertyToMonitor' is not a valid AD property. Valid AD properties are: $adProperties"
            }
            $adPropertyInReport | Where-Object { 
                $adProperties -notContains $_ 
            } | ForEach-Object {
                throw "Property '$_' defined in 'AD.PropertyInReport' is not a valid AD property. Valid AD properties are: $adProperties"
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
        

        #region Get AD users
        [array]$adUsers = foreach ($ou in $adOU) {
            $M = "Get user accounts in OU '$ou'"
            Write-Verbose $M; Write-EventLog @EventVerboseParams -Message $M

            Get-ADUser -OU $ou -Properties $adProperties |
            Select-Object -Property @{
                Name       = 'CreationDate'
                Expression = { $_.whenCreated } 
            }, 
            DisplayName, Name, SamAccountName,
            @{
                Name       = 'LastName'
                Expression = { $_.Surname } 
            }, 
            @{
                Name       = 'FirstName'
                Expression = { $_.GivenName } 
            }, 
            Title, Department, Company,
            @{
                Name       = 'Manager'
                Expression = { 
                    if ($_.manager) { Get-ADDisplayNameHC $_.manager }
                }
            }, 
            EmployeeID,
            @{
                Name       = 'HeidelbergCementBillingID'
                Expression = { $_.extensionAttribute8 } 
            },
            employeeType,
            @{
                Name       = 'OU'
                Expression = {
                    ConvertTo-OuNameHC $_.CanonicalName
                }
            },
            Description,
            @{
                Name       = 'Country'
                Expression = { $_.co } 
            },
            Office, OfficePhone, HomePhone, MobilePhone, ipPhone, Fax, pager,
            @{
                Name       = 'Notes'
                Expression = { $_.info -replace "`n", ' ' } 
            },
            EmailAddress,
            @{
                Name       = 'LogonScript'
                Expression = { $_.scriptPath } 
            }, 
            @{
                Name       = 'TSUserProfile'
                Expression = {
                    Get-ADTsProfileHC $_.DistinguishedName 'UserProfile' 
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
                Name       = 'TSAllowLogon'
                Expression = {
                    Get-ADTsProfileHC $_.DistinguishedName 'AllowLogon'
                }
            },
            HomeDirectory, AccountExpirationDate, LastLogonDate, PasswordExpired, 
            PasswordNeverExpires, LockedOut, Enabled
        }
        #endregion

        #region Export users to Excel file

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