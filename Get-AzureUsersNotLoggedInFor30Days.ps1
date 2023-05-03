<#
.SYNOPSIS
AzureAD typically keeps login data for 30 days by default (2023).
If no login data is found for an Azure user, this script assumes the user has not logged in for 30 days.
If the user is found without Azure login data and their AD-synced conterpart's last login date is > 30 days, the user is included in end results.
.DESCRIPTION
Get Users Not Logged In For 30 Days - Correlating AD & AzureAD
.EXAMPLE
PS C:\> Get-AzureUsersNotLoggedInFor30Days.ps1 -Server CyberCondor.local
## Input
ADUsers
- Contains list of all users and their properties of interest
AzureAdAuditSigninLogs
- Sign-in logs from Azure
## Output
.\EnabledAzureAccountsWhereLastLoginGT30Days-$($Server)_$($CurrentDate).csv
#>
param(
    [Parameter(mandatory=$True, Position=0, ValueFromPipeline=$false)]
    [system.String]$Server
)

try{Import-Module AzureADPreview -ErrorAction Stop
}
catch{$errMsg = $_.Exception.message
    if($errMsg -like "*not loaded*"){
        Write-Warning "`t $_.Exception"
        Write-Output "AzureADPreview is missing -> install via 'Install-Module AzureADPreview -AllowClobber"
    }
    break
}

Write-Host "`n`t`tAttempting to query Active Directory.'n" -BackgroundColor Black -ForegroundColor Yellow
try{Get-ADUser -server $Server -filter 'Title -like "*Admin*"' > $null -ErrorAction stop
}
catch{$errMsg = $_.Exception.message
    if($errMsg -like "*is not recognized as the name of a cmdlet*"){
        Write-Warning "`t $_.Exception"
        Write-Output "Ensure 'RSAT Active Directory DS-LDS Tools' are installed through 'Windows Features' & ActiveDirectory PS Module is installed"
    }
    elseif($errMsg -like "*Unable to contact the server*"){
        Write-Warning "`t $_.Exception"
        Write-Output "Check server name and that server is reachable, then try again."
    }
    else{Write-Warning "`t $_.Exception"}
    break
}

Write-Host "`n`t`tAttempting to query AZURE Active Directory." -BackgroundColor Black -ForegroundColor Yellow
try{Get-AzureADUser -All $true > $null -ErrorAction stop
}
catch{$errMsg = $_.Exception.message
    if($errMsg -like "*is not recognized as the name of a cmdlet*"){
        Write-Warning "`t $_.Exception"
        Write-Output "Ensure 'AzureAD PS Module is installed. 'Install-Module AzureAD'"
        break
    }
    elseif($_.Exception -like "*Connect-AzureAD*"){
        Write-Warning "`t $_.Exception"
        Write-Output "Calling Connect-AzureAD"
        try{Connect-AzureAD -ErrorAction stop
        }
        catch{$errMsg = $_.Exception.message
            Write-Warning "`t $_.Exception"
            break
        }
    }
    else{Write-Warning "`t $_.Exception" ; break}
}

function Get-ExistingUsers_AD($Properties_AD){
    try{$ExistingUsers = Get-ADUser -Server $Server -Filter * -Properties $Properties_AD | where{$_.Enabled -eq $true} | Select $Properties_AD -ErrorAction Stop
        return $ExistingUsers
    }
    catch{$errMsg = $_.Exception.message
        Write-Warning "`t $_.Exception"
        return $null
    }
}
function Get-UserRunningThisProgram($ExistingUsers_AD){
    foreach($ExistingUser in $ExistingUsers_AD){
        if($ExistingUser.SamAccountName -eq $env:UserName){return $ExistingUser}
    }
    Write-Warning "User Running this program not found."
    return $null
}
function SanitizeManagerPropertyFormat($ExistingUsers_AD){
    foreach($ExistingUser in $ExistingUsers_AD){
        [string]$UnsanitizedName = $ExistingUser.Manager
        $NameSanitized = $false
        if(($UnsanitizedName -ne $null) -and ($UnsanitizedName -ne "") -and ($UnsanitizedName -ne "`n") -and ($UnsanitizedName -match '[a-zA-Z]') -and ($UnsanitizedName.Length -ne 1)){
            $index = 0
            while($NameSanitized -eq $false){
                $SanitizedName = $ExistingUser.Manager.Substring(3,$index++)
                if($ExistingUser.Manager[$index] -eq ','){
                    $ExistingUser.Manager = $SanitizedName.Substring(0,$SanitizedName.Length - 2)
                    $NameSanitized = $true
                }
            }
        }
        else{$ExistingUser.Manager = "NULL"}
    }
}
function Add-AzureADLastLoginTimestampPropertyTo($ExistingUsers){
    $TotalAccounts = ($ExistingUsers).count
    $ProgressCount = 1
    foreach($ExistingUser in $ExistingUsers){ 
        $FoundLastLogin = $false
        $LastLogin = @()
        Write-Progress -Activity "Finding Last Login Timestamp for Accounts - $ProgressCount/$TotalAccounts" -Status "$(($ProgressCount++/$TotalAccounts).ToString("P")) Complete"
        if($ExistingUser.UserPrincipalName){
            sleep 1
            try{$LastLogin = Get-AzureAdAuditSigninLogs -top 1 -filter "UserPrincipalName eq '$($ExistingUser.UserPrincipalName)'" | Select CreatedDateTime -ErrorAction stop}
            catch{$errMsg = $_.Exception.message
                if($errMsg -like "*is not recognized as the name of a cmdlet*"){
                    Write-Warning "`t $_.Exception"
                    Write-Output "Open up a fresh shell and try again. Blame AzureADPreview."
                    break
                }
                else{Write-Warning "`t $_.Exception -> $($ExistingUser.UserPrincipalName)"}
            }
            if(($LastLogin -eq $null) -and ($ExistingUser.Name)){sleep 1
                try{$LastLogin = Get-AzureAdAuditSigninLogs -top 1 -filter "UserDisplayName eq '$($ExistingUser.Name)'" | Select CreatedDateTime -ErrorAction Stop}
                catch{$errMsg = $_.Exception.message
                    if($errMsg -like "*is not recognized as the name of a cmdlet*"){
                        Write-Warning "`t $_.Exception"
                        Write-Output "Open up a fresh shell and try again. Blame AzureADPreview."
                        break
                    }
                    else{Write-Warning "`t $_.Exception -> $($ExistingUser.Name)"}
                }
            }
            if($LastLogin -ne $null){$ExistingUser | Add-Member -NotePropertyMembers @{AzureLastLoginTimestamp="$($LastLogin.CreatedDateTime)"}}
            else{$ExistingUser | Add-Member -NotePropertyMembers @{AzureLastLoginTimestamp="NULL"}}
        }
        else{Write-Host "UPN is null -> $($ExistingUser)"}
    }
}

$Properties_AD = @("Name",
                   "Office",
                   "Title",
                   "Department",
                   "Manager",
                   "UserPrincipalName",
                   "SamAccountName",
                   "Enabled",
                   "whenCreated",
                   "whenChanged",
                   "PasswordLastSet",
                   "PasswordExpired",
                   "AccountExpirationDate",
                   "logonCount",
                   "LastLogonDate",
                   "LastBadPasswordAttempt",
                   "Description")

$CurrentDate = get-date -format yyy-MM-dd
$ExistingUsers = Get-ExistingUsers_AD $Properties_AD
if($ExistingUsers -eq $null){break}
Get-UserRunningThisProgram $ExistingUsers

SanitizeManagerPropertyFormat $ExistingUsers
Add-AzureADLastLoginTimestampPropertyTo $ExistingUsers

$Properties_AD += "AzureLastLoginTimestamp"

$ExportedFileName = "EnabledAzureAccountsWhereLastLoginGT30Days-$($Server)_$($CurrentDate).csv"

$ExistingUsers | 
    where{($_.AzureLastLoginTimestamp -eq "NULL") -and ($_.LastLogonDate -lt [datetime]::Now.AddDays(-30))} | 
    select $Properties_AD |
    sort PasswordExpired,AccountExpirationDate,Office,Title,Department,Manager,Description,LastLogonDate |
    Export-Csv $ExportedFileName -NoTypeInformation

Write-Host "`nSummary of Accounts Where AzureAD Last Login Timestamp is NULL is available @ '$($ExportedFileName)'"