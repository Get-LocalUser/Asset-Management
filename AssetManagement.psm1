<# 
.SYNOPSIS
    This Module is a collection of common things I need to lookup relating to devices in Intune and Entra as well as creating TAP codes.

.AUTHOR
    Get-LocalUser

.REQUIREMENTS
    - PowerShell 7
    - RSAT: Active Directory
    - Microsoft.Graph.Beta PowerShell module
#>


function Initialize-Modules {
    # Active Directory
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "ActiveDirectory module not found. Please install RSAT: Active Directory." -ForegroundColor Red
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "ActiveDirectory module imported successfully." -ForegroundColor Yellow

    # Microsoft Graph Beta
    if (-not (Get-InstalledModule -Name Microsoft.Graph.Beta -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Graph module. This will take a few minutes..." -ForegroundColor Yellow
        Install-Module -Name Microsoft.Graph.Beta -Scope CurrentUser -Force -Verbose
    }
    Import-Module Microsoft.Graph.Beta -ErrorAction Ignore
    Write-Host "Graph module imported successfully." -ForegroundColor Yellow
}

function Search-SingleComputer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome

    # Define the PSCustomObject for output
    $deviceresult = [PSCustomObject]@{
        InputName = $ComputerName

        # Active Directory
        AD_ComputerFound        = $false
        AD_ComputerName         = $null

        # Intune
        Intune_ComputerFound    = $false
        Intune_ComputerName     = $null
        Intune_SerialNumber     = $null

        # Autopilot
        Autopilot_ComputerFound = $false
        Autopilot_SerialNumber  = $null
    }

    Write-Host "Searching for computer.." -ForegroundColor Yellow

    # Get AD Computer
    try {
        $Compresults = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
    }
    catch {
        $Compresults = $null
    }

    if ($Compresults.Count -gt 1) {
        Write-Host "Multiple computers found in AD. Verify entries before deleting" -ForegroundColor Red
        $Compresults | ForEach-Object { Write-Host "Active Directory:$($_.Name)" }
    }
    elseif ($Compresults) {
        $deviceresult.AD_ComputerFound = $true
        $deviceresult.AD_ComputerName  = $Compresults.Name
    }

    # Get Intune computer
    $Compresults = Get-MgBetaDeviceManagementManagedDevice -Filter "deviceName eq '$ComputerName'"
    if ($Compresults.Count -gt 1) {
        Write-Host "Multiple Intune computers found. Verify entries before deleting" -ForegroundColor Red
        $compresults | ForEach-Object {Write-Host "Intune: $($_.DeviceName)"} 
    } elseif ($Compresults) {
        $deviceresult.Intune_ComputerFound   = $true
        $deviceresult.Intune_ComputerName    = $Compresults.DeviceName
        $deviceresult.Intune_SerialNumber    = $Compresults.SerialNumber
    }

    # Get Autopilot enrollment
    if ($deviceresult.Intune_SerialNumber) {
        $Compresults = Get-MgBetaDeviceManagementWindowsAutopilotDeviceIdentity -ErrorAction SilentlyContinue | Where-Object { $_.SerialNumber -eq $deviceresult.Intune_SerialNumber }
    }
    
    if ($Compresults.Count -gt 1) {
        Write-Host "Multiple Autopilot devices found. Verify entries before deleting" -ForegroundColor Red
        $compresults | ForEach-Object {Write-Host "Autopilot: $($_.DisplayName)"} 
    } elseif ($Compresults) {
        $deviceresult.Autopilot_ComputerFound = $true
        $deviceresult.Autopilot_SerialNumber  = $Compresults.SerialNumber
    }


    # Display results of previous checks
    if ($deviceresult.AD_ComputerFound -or $deviceresult.Intune_ComputerFound -or $deviceresult.Autopilot_ComputerFound) {
        Write-Host "Device found in one or more systems." -ForegroundColor Yellow
    } else { 
        Write-Host "No devices found in any system." -ForegroundColor Red
    }

    $Check = "✓"
    $output = [PSCustomObject]@{
        ComputerName    = $deviceresult.InputName
        ActiveDirectory = if ($deviceresult.AD_ComputerFound)       { $Check } else { "False" }
        Intune          = if ($deviceresult.Intune_ComputerFound)   { $Check } else { "False" }
        Autopilot       = if ($deviceresult.Autopilot_ComputerFound){ $Check } else { "False" }
    }

    $output | Format-Table -AutoSize

    return $deviceresult
}

function Search-BulkComputers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [switch]$Transcript
    )

    if ($Transcript) {
    $logpath = "$($env:USERPROFILE)\Downloads"
    $logname = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_search_bulk_computer_script.log"
    Start-Transcript -Path "$logpath\$logname" -Verbose
    }

    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome

    if (-not (Test-Path $CsvPath)) {
        Write-Host "CSV file not found: $CsvPath" -ForegroundColor Red
        return
    }

    try {
        $computers = Import-Csv $CsvPath
        Write-Host "`nProcessing $($computers.Count) computers from CSV..." -ForegroundColor Yellow

        $results = @()
        $counter = 0

        foreach ($row in $computers) {
            $counter++
            $ComputerName = $row.'Asset Tag'

            if ([string]::IsNullOrWhiteSpace($computerName)) {
                Write-Host "[$counter/$($computers.Count)] Skipping empty computer name" -ForegroundColor Yellow
                continue
        }

        # Show progress
        Write-Host "[$counter/$($computers.Count)] $computerName" -ForegroundColor Cyan
`
        $deviceInfo = Search-SingleComputer -ComputerName $computerName

        $Check = "✓"
        $result = [PSCustomObject]@{
            ComputerName     = $computerName
            ActiveDirectory  = if ($deviceInfo.AD_ComputerFound)       { $check } else { "False" }
            Intune           = if ($deviceInfo.Intune_ComputerFound)   { $check } else { "False" }
            Autopilot        = if ($deviceInfo.Autopilot_ComputerFound){ $check } else { "False" }
        }

            $results += $result
        }

    }
    catch {
        Write-Host "Error processing CSV: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Print results and export to a CSV in the user's Downloads folder
    $Pathway = "C:\Users\$env:USERNAME\Downloads\"
    $ExportFile = Join-Path -Path $Pathway -ChildPath "Computersfound.csv"

    if ($results) { 
        $Utf8WithBom = New-Object System.Text.UTF8Encoding $true
        $csvContent = $results | ConvertTo-Csv -NoTypeInformation | Out-String
        [System.IO.File]::WriteAllText($ExportFile, $csvContent, $Utf8WithBom)
        Write-Host "`nResults exported to: $ExportFile" -ForegroundColor Yellow
        Write-Host "`nOpen in Excel for best visual." -ForegroundColor Magenta
    }
    else {
        Write-Host "Not exported" -ForegroundColor Yellow
    }

    if ($Transcript) {
        Stop-Transcript
    }

    return $results
    Write-Host "`nOpen in Excel for best visual." -ForegroundColor Magenta
}

function Remove-SingleComputer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Type in the P number/hostname of the computer")]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [switch]$Transcript
    )
    
    if ($Transcript) {
    $logpath = "$($env:USERPROFILE)\Downloads"
    $logname = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_remove_single_computer_script.log"
    Start-Transcript -Path "$logpath\$logname" -Verbose
    }

    Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All", "DeviceManagementServiceConfig.ReadWrite.All" -NoWelcome

    # --- Active Directory ---
    Write-Host "Checking Active Directory for $ComputerName..." -ForegroundColor Yellow
    try {
        $adComputer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
    } catch {
        $adComputer = $null
    }
    
    if (-not $adComputer) {
        Write-Host "$ComputerName NOT found in Active Directory" -ForegroundColor Red
    } else {
        Write-Host "$ComputerName found in Active Directory" -ForegroundColor Yellow
        try {
            Remove-ADObject -Identity $adComputer.DistinguishedName -Recursive -Confirm:$true -ErrorAction Stop
            Write-Host "$ComputerName Deleted from AD" -ForegroundColor Green
        } catch {
            Write-Host "Failed to delete $ComputerName from AD" -ForegroundColor Red
        }
    }
    
    # --- Intune ---
    Write-Host "Checking Intune for $ComputerName..." -ForegroundColor Yellow
    try {
        $matchedDevice = Get-MgBetaDeviceManagementManagedDevice -Filter "deviceName eq '$ComputerName'" -ErrorAction Stop
    } catch {
        $matchedDevice = $null
    }
    
    if (-not $matchedDevice) {
        Write-Host "$ComputerName NOT found in Intune" -ForegroundColor Red
        return  # Early exit since no device found
    }
    
    # Device found in Intune
    Write-Host "$ComputerName found in Intune" -ForegroundColor Yellow
    try {
        Remove-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $matchedDevice.Id -ErrorAction Stop
        Write-Host "$ComputerName removed from Intune." -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove $ComputerName from Intune: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # --- Autopilot ---
    if (-not $matchedDevice.SerialNumber) {
        Write-Host "No serial number found for device in Intune." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Checking Autopilot for serial number $($matchedDevice.SerialNumber)..." -ForegroundColor Yellow
    try {
        $autopilotDevice = Get-MgBetaDeviceManagementWindowsAutopilotDeviceIdentity | Where-Object {$_.SerialNumber -eq $matchedDevice.SerialNumber} #Get-MgBetaDeviceManagementWindowsAutopilotDeviceIdentity -Filter "SerialNumber eq '$($matchedDevice.SerialNumber)'" -ErrorAction Stop
    } catch {
        $autopilotDevice = $null
    }
    
    if (-not $autopilotDevice) {
        Write-Host "No Autopilot record found for serial $($matchedDevice.SerialNumber)" -ForegroundColor Red
        return
    }
    
    # Autopilot device found - try to delete
    try {
        Remove-MgBetaDeviceManagementWindowsAutopilotDeviceIdentity -WindowsAutopilotDeviceIdentityId $autopilotDevice.Id -ErrorAction Stop
        Write-Host "Autopilot record for $($matchedDevice.SerialNumber) deleted." -ForegroundColor Green
    } catch {
        Write-Host "Failed to delete from Autopilot: $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($Transcript) {
    Stop-Transcript
    }
}

function Remove-BulkComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [switch]$Transcript
    )

    if ($Transcript) {
        $logpath = "$($env:USERPROFILE)\Downloads"
        $logname = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_remove_bulk_computer_script.log"
        Start-Transcript -Path "$logpath\$logname" -Verbose
    }

    Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All", "DeviceManagementServiceConfig.ReadWrite.All" -NoWelcome

    # --- File Picker UI if path not provided ---
    if (-not $CsvPath) {
        Add-Type -AssemblyName System.Windows.Forms

        # Create hidden topmost form so dialog appears in foreground
        $form = New-Object System.Windows.Forms.Form
        $form.TopMost = $true
        $form.WindowState = 'Minimized'
        $form.ShowInTaskbar = $false

        $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $fileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        $fileDialog.Title = "Select the CSV file with computers to delete"
        $fileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")

        if ($fileDialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            $CsvPath = $fileDialog.FileName
        } else {
            Write-Host "No file selected. Exiting bulk delete." -ForegroundColor Red
            $form.Dispose()
            return
        }

        $form.Dispose()
    }

    # --- Import CSV and initialize ---
    $ImportedCSV = Import-Csv $CsvPath
    $counter = 0
    $results = @()

    foreach ($row in $ImportedCSV) {
        $counter++
        $ComputerName = $row.'Asset Tag'
        $result = [PSCustomObject]@{
            ComputerName    = $ComputerName
            ADStatus        = "Not Attempted"
            IntuneStatus    = "Not Attempted"
            AutopilotStatus = "Not Attempted"
        }

        if ([string]::IsNullOrWhiteSpace($ComputerName)) {
            Write-Host "[$counter/$($ImportedCSV.Count)] Skipping empty computer name" -ForegroundColor Yellow
            $result.ADStatus = "Skipped - Empty"
            $results += $result
            continue
        }

        Write-Host "[$counter/$($ImportedCSV.Count)] Processing '$ComputerName'" -ForegroundColor Cyan

        # --- Active Directory ---
        Write-Host "[$counter] Checking Active Directory for $ComputerName..." -ForegroundColor Yellow
        try {
            $adComputer = Get-ADComputer -Identity $ComputerName -ErrorAction SilentlyContinue
        } catch {
            $adComputer = $null
        }
        
        if (-not $adComputer) {
            Write-Host "[$counter] $ComputerName NOT found in Active Directory" -ForegroundColor Red
            $result.ADStatus = "Not Found"
        } else {
            try {
                Remove-ADObject -Identity $adComputer.DistinguishedName -Recursive -Confirm:$false -ErrorAction SilentlyContinue
                Write-Host "[$counter] $ComputerName Deleted from AD" -ForegroundColor Green
                $result.ADStatus = "Deleted"
            } catch {
                Write-Host "[$counter] Failed to delete $ComputerName from AD: $($_.Exception.Message)" -ForegroundColor Red
                $result.ADStatus = "Error: $($_.Exception.Message)"
            }
        }

        # --- Intune ---
        Write-Host "[$counter] Checking Intune for $ComputerName..." -ForegroundColor Yellow
        try {
            $matchedDevice = Get-MgBetaDeviceManagementManagedDevice -Filter "deviceName eq '$ComputerName'" -ErrorAction SilentlyContinue
        } catch {
            $matchedDevice = $null
        }
        
        if (-not $matchedDevice) {
            Write-Host "[$counter] $ComputerName NOT found in Intune" -ForegroundColor Red
            $result.IntuneStatus = "Not Found"
            $results += $result
            continue
        }

        try {
            Remove-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $matchedDevice.Id -ErrorAction SilentlyContinue
            Write-Host "[$counter] $ComputerName removed from Intune." -ForegroundColor Green
            $result.IntuneStatus = "Deleted"
        } catch {
            Write-Host "[$counter] Failed to remove $ComputerName from Intune: $($_.Exception.Message)" -ForegroundColor Red
            $result.IntuneStatus = "Error: $($_.Exception.Message)"
            $results += $result
            continue
        }

        # --- Autopilot ---
        if (-not $matchedDevice.SerialNumber) {
            Write-Host "[$counter] No serial number found for device in Intune." -ForegroundColor Yellow
            $result.AutopilotStatus = "No Serial Number"
            $results += $result
            continue
        }

        Write-Host "[$counter] Checking Autopilot for serial number $($matchedDevice.SerialNumber)..." -ForegroundColor Yellow
        try {
            $autopilotDevice = Get-MgBetaDeviceManagementWindowsAutopilotDeviceIdentity -ErrorAction SilentlyContinue |
                Where-Object { $_.SerialNumber -eq $matchedDevice.SerialNumber }
        } catch {
            $autopilotDevice = $null
        }

        if (-not $autopilotDevice) {
            Write-Host "[$counter] No Autopilot record found for serial $($matchedDevice.SerialNumber)" -ForegroundColor Red
            $result.AutopilotStatus = "Not Found"
            $results += $result
            continue
        }

        try {
            Remove-MgBetaDeviceManagementWindowsAutopilotDeviceIdentity -WindowsAutopilotDeviceIdentityId $autopilotDevice.Id -ErrorAction SilentlyContinue
            Write-Host "[$counter] Autopilot record for $($matchedDevice.SerialNumber) deleted." -ForegroundColor Green
            $result.AutopilotStatus = "Deleted"
        } catch {
            Write-Host "[$counter] Failed to delete from Autopilot: $($_.Exception.Message)" -ForegroundColor Red
            $result.AutopilotStatus = "Error: $($_.Exception.Message)"
        }

        $results += $result
    }

    # --- Export Results to CSV ---
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $exportPath = Join-Path $env:USERPROFILE "Downloads\BulkDeletionResults_$timestamp.csv"
    $results | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $exportPath" -ForegroundColor Cyan

    if ($Transcript) {
        Stop-Transcript
    }

}

function Get-LastLoggedInUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Connect-MgGraph -Scopes "User.Read.All", "DeviceManagementManagedDevices.Read.All" -NoWelcome

    try {
        $device = Get-MgBetaDeviceManagementManagedDevice -Filter "contains(deviceName,'$ComputerName')"
    }
    catch {
        Write-Error "Error retrieving device: $_"
    }

    if (-not $device) {
    Write-Host "No device found for $ComputerName." -ForegroundColor Yellow
    return
    }

    if ($device) {
        $lastusers = $device.UsersLoggedOn

        $usersList = @()

        foreach ($user in $lastusers) {
            $lastlogon = $user.LastLogOnDateTime
            $userobject = [PSCustomObject]@{
                UserID = $user.userid
                PrimaryUser = $device.UserPrincipalName
                DisplayName = (Get-MgBetaUser -UserId $user.UserId).DisplayName
                LastLoggedOnDateTime = $lastLogon
            }
            $usersList += $userObject
        }
        $usersList | Format-List
    } else {
        Write-Output "Device not found."
    }
}

function Get-AllUserEntraRegisteredDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $false)]
        [string]$ExportPath

    )

    Connect-MgGraph -Scopes "Directory.Read.All" -NoWelcome

    try {
        $devices = Get-MgBetaUserRegisteredDevice -UserId $UserPrincipalName

    } catch {
        Write-Error "Error retrieving registered devices: $_"
        return
    }

    if (-not $devices) {
        Write-Host "No Entra registered devices found for $UserPrincipalName." -ForegroundColor Yellow
        return
    }

    $results = $devices | ForEach-Object {
        $props = $_.AdditionalProperties
        [PSCustomObject]@{
            UserName           = $UserPrincipalName
            DisplayName        = $props.displayName
            DeviceId           = $props.deviceId
            OS                 = $props.operatingSystem
            OSVersion          = $props.operatingSystemVersion
            TrustType          = $props.trustType
            ProfileType        = $props.profileType
            CreatedDate        = $props.createdDateTime 
            RegistrationDate   = $props.registrationDateTime
            LastSignIn         = $props.approximateLastSignInDateTime
            AccountEnabled     = $props.accountEnabled
        }
    }

    if ($ExportPath) {
    $results | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "Results exported to $ExportPath" -ForegroundColor Green
}

$results | Format-Table -AutoSize

}

function Get-AllUserMDMManagedDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    Connect-MgGraph -Scopes "Device.Read.All" -NoWelcome

    try {
        $devices = Get-MgBetaDeviceManagementManagedDevice -Filter "userPrincipalName eq '$UserPrincipalName'"
    } catch {
        Write-Error "Error retrieving devices: $_"
        return
    }

    if (-not $devices) {
        Write-Host "No devices found for $UserPrincipalName." -ForegroundColor Yellow
        return
    }

    $results = $devices | ForEach-Object {
        [PSCustomObject]@{
            UserName = $_.UserDisplayName
            DeviceName = $_.DeviceName
            ID = $_.Id
            Type = $_.DeviceType
            Model = $_.Model
            Compliant = $_.ComplianceState
            EnrolledDate = $_.EnrolledDateTime
            EnrolledBy = $_.EnrolledByUserPrincipalName
        }
    } 

    if ($ExportPath) {
    $results | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "Results exported to $ExportPath" -ForegroundColor Green

}

$results | Format-Table -AutoSize

}

function New-TAP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All" -NoWelcome

    # Define the time you want TAp to take affect
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Create a Temporary Access Pass for a user that can be used more than once
    $properties = @{}
    $properties.isUsableOnce = $false
    $properties.startDateTime = $time
    $propertiesJSON = $properties | ConvertTo-Json

    $tap = New-MgBetaUserAuthenticationTemporaryAccessPassMethod -UserID $UserPrincipalName -BodyParameter $propertiesJSON | Out-Host
    Write-Host "MFA Setup Link:`nhttps://aka.ms/mfasetup" -ForegroundColor Magenta

    try {
        $question = Read-Host "Do you want to remove the current TAP?"
        if ($question -like "y") {
            $existingtap = (Get-MgBetaUserAuthenticationTemporaryAccessPassMethod -UserId $UserPrincipalName).Id
            Remove-MgBetaUserAuthenticationTemporaryAccessPassMethod -UserId $UserPrincipalName -TemporaryAccessPassAuthenticationMethodId $existingtap
            Write-Host "TAP with ID $existingtap removed" -ForegroundColor Green
        } else {
            Write-Host "You declined. TAP will remain active for 60 minutes from the time it was created."
        }
    }
    catch {
        Write-Host "Failed to remove TAP. Manually remove from the Entra Admin Center" -ForegroundColor Red
        "Error: $($_.Exception.Message)"
    }
}

function Get-RemainingE5Licenses {
    [CmdletBinding()]

$skus = Get-MgBetaSubscribedSku -SubscribedSkuId "bfecfed6-9541-432f-878e-cba66795ff4d_06ebc4ee-1bb5-47dd-8120-11324bc54e06" | Select-Object SkuId, SkuPartNumber, ConsumedUnits,
    @{Name="ActiveUnits"; Expression={$_.PrepaidUnits.Enabled}},
    @{Name="WarningUnits"; Expression={$_.PrepaidUnits.Warning}},
    @{Name="SuspendedUnits"; Expression={$_.PrepaidUnits.Suspended}}

if ($skus.ConsumedUnits -ge $skus.ActiveUnits) {
    Write-Host "License count met or exceeded."
} else {
    $skus
}
}

Export-ModuleMember -Function Initialize-Modules
Export-ModuleMember -Function Search-SingleComputer
Export-ModuleMember -Function Search-BulkComputers
Export-ModuleMember -Function Remove-SingleComputer
Export-ModuleMember -Function Remove-BulkComputers
Export-ModuleMember -Function Get-LastLoggedInUser
Export-ModuleMember -Function Get-AllUserMDMManagedDevices
Export-ModuleMember -Function Get-AllUserEntraRegisteredDevices
Export-ModuleMember -Function New-TAP
Export-ModuleMember -Function Get-RemainingE5Licenses