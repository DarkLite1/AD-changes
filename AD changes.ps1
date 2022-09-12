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
        $adUsers = foreach ($ou in $adOU) {
            Get-ADUser -OU $ou
        }
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