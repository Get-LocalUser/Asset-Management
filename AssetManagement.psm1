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

    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All", "Device.Read.All" -NoWelcome

    # Define the PSCustomObject for output
    $deviceresult = [PSCustomObject]@{
        InputName = $ComputerName

        # Active Directory
        AD_ComputerFound        = $false
        AD_ComputerName         = $null

        # Entra ID
        EntraID_ComputerFound   = $false
        EntraID_ComputerName    = $null

        # Intune
        Intune_ComputerFound    = $false
        Intune_ComputerName     = $null
        Intune_SerialNumber     = $null
        Intune_AzureADDeviceId  = $null

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
        Write-Host "`nMultiple Intune computers found. Verify entries before deleting`n" -ForegroundColor Red
        $compresults | ForEach-Object {Write-Host "Intune: $($_.DeviceName)"}
    } elseif ($Compresults) {
        $deviceresult.Intune_ComputerFound   = $true
        $deviceresult.Intune_ComputerName    = $Compresults.DeviceName
        $deviceresult.Intune_SerialNumber    = $Compresults.SerialNumber
        $deviceresult.Intune_AzureADDeviceId = $Compresults.AzureADDeviceId
    }

    # Get Entra ID device — matched by AzureADDeviceId attribute from Intune to avoid name duplicates. If no Entra device tied to the Intune AzureADDeviceId attribute is found this will result in nothing.
    if ($deviceresult.Intune_AzureADDeviceId) {
        try {
            $EntraResults = Get-MgBetaDevice -Filter "deviceId eq '$($deviceresult.Intune_AzureADDeviceId)'" -ErrorAction Stop
        }
        catch {
            $EntraResults = $null
        }

        if ($EntraResults) {
            $deviceresult.EntraID_ComputerFound = $true
            $deviceresult.EntraID_ComputerName  = $EntraResults.DisplayName
        }
    }

    # Get Autopilot enrollment
    $Compresults = $null
    if ($deviceresult.Intune_SerialNumber) {
        $Compresults = Get-MgBetaDeviceManagementWindowsAutopilotDeviceIdentity -ErrorAction SilentlyContinue | Where-Object { $_.SerialNumber -eq $deviceresult.Intune_SerialNumber }
    }

    if ($Compresults.Count -gt 1) {
        Write-Host "`nMultiple Autopilot devices found. Verify entries before deleting" -ForegroundColor Red
        $compresults | ForEach-Object {Write-Host "Autopilot: $($_.DisplayName)"}
    } elseif ($Compresults) {
        $deviceresult.Autopilot_ComputerFound = $true
        $deviceresult.Autopilot_SerialNumber  = $Compresults.SerialNumber
    }


    # Display results of previous checks
    if ($deviceresult.AD_ComputerFound -or $deviceresult.EntraID_ComputerFound -or $deviceresult.Intune_ComputerFound -or $deviceresult.Autopilot_ComputerFound) {
        Write-Host "Device found in one or more systems." -ForegroundColor Yellow
    } else {
        Write-Host "No devices found in any system." -ForegroundColor Red
    }

    $Check = "✓"
    $output = [PSCustomObject]@{
        ComputerName    = $deviceresult.InputName
        ActiveDirectory = if ($deviceresult.AD_ComputerFound)       { $Check } else { "False" }
        Intune          = if ($deviceresult.Intune_ComputerFound)   { $Check } else { "False" }
        EntraID         = if ($deviceresult.EntraID_ComputerFound)  { $Check } else { "False" }
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

        $deviceInfo = Search-SingleComputer -ComputerName $computerName

        $Check = "✓"
        $result = [PSCustomObject]@{
            ComputerName     = $computerName
            ActiveDirectory  = if ($deviceInfo.AD_ComputerFound)       { $check } else { "False" }
            Intune           = if ($deviceInfo.Intune_ComputerFound)   { $check } else { "False" }
            EntraID          = if ($deviceInfo.EntraID_ComputerFound)  { $check } else { "False" }
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
        Write-Host "`nNote: An Entra ID object is returned only when a matching Intune object with the same AzureADDeviceId attribute exists." -ForegroundColor Blue
        Write-Host "If no matching Intune object exists, the result is null. This avoids conflicts when names are duplicated." -ForegroundColor Blue
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

function Search-SingleiOSDevice {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Serial
    )

    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All", "Device.Read.All" -NoWelcome

    $Serial = $Serial.Trim()
    $DeviceName = "iPhone-$Serial-NamedUser"

    $deviceresult = [PSCustomObject]@{
        InputSerial     = $Serial
        ConstructedName = $DeviceName

        # Intune
        Intune_DeviceFound      = $false
        Intune_DeviceName       = $null
        Intune_SerialNumber     = $null
        Intune_AzureADDeviceId  = $null

        # Entra ID
        EntraID_DeviceFound     = $false
        EntraID_DeviceName      = $null
    }

    Write-Host "Searching for: $DeviceName" -ForegroundColor Yellow

    # Get Intune device by constructed name
    $IntuneResults = Get-MgBetaDeviceManagementManagedDevice -Filter "deviceName eq '$DeviceName'"

    if ($IntuneResults.Count -gt 1) {
        Write-Host "`nMultiple Intune devices found for serial '$Serial'. Verify entries before deleting.`n" -ForegroundColor Red
        $IntuneResults | ForEach-Object { Write-Host "Intune: $($_.DeviceName)" }
    }
    elseif ($IntuneResults) {
        $deviceresult.Intune_DeviceFound     = $true
        $deviceresult.Intune_DeviceName      = $IntuneResults.DeviceName
        $deviceresult.Intune_SerialNumber    = $IntuneResults.SerialNumber
        $deviceresult.Intune_AzureADDeviceId = $IntuneResults.AzureADDeviceId
    }

    # Get Entra ID device matched by AzureADDeviceId from Intune
    if ($deviceresult.Intune_AzureADDeviceId) {
        try {
            $EntraResults = Get-MgBetaDevice -Filter "deviceId eq '$($deviceresult.Intune_AzureADDeviceId)'" -ErrorAction Stop
        }
        catch {
            $EntraResults = $null
        }

        if ($EntraResults) {
            $deviceresult.EntraID_DeviceFound = $true
            $deviceresult.EntraID_DeviceName  = $EntraResults.DisplayName
        }
    }

    # Display results
    if ($deviceresult.Intune_DeviceFound -or $deviceresult.EntraID_DeviceFound) {
        Write-Host "Device found in one or more systems." -ForegroundColor Yellow
    }
    else {
        Write-Host "No devices found for serial: $Serial" -ForegroundColor Red
    }

    $Check = "✓"
    $output = [PSCustomObject]@{
        Serial          = $deviceresult.InputSerial
        ConstructedName = $deviceresult.ConstructedName
        Intune          = if ($deviceresult.Intune_DeviceFound)  { $Check } else { "False" }
        EntraID         = if ($deviceresult.EntraID_DeviceFound) { $Check } else { "False" }
    }

    $output | Format-Table -AutoSize

    return $deviceresult
}

function Search-BulkiOSDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [switch]$Transcript
    )

    if ($Transcript) {
        $logpath = "$($env:USERPROFILE)\Downloads"
        $logname = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_search_bulk_ios_devices_script.log"
        Start-Transcript -Path "$logpath\$logname" -Verbose
    }

    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All", "Device.Read.All" -NoWelcome

    if (-not (Test-Path $CsvPath)) {
        Write-Host "CSV file not found: $CsvPath" -ForegroundColor Red
        return
    }

    try {
        $devices = Import-Csv $CsvPath
        Write-Host "`nProcessing $($devices.Count) devices from CSV..." -ForegroundColor Yellow

        $results = @()
        $counter = 0

        foreach ($row in $devices) {
            $counter++
            $Serial = $row.'Serial'

            if ([string]::IsNullOrWhiteSpace($Serial)) {
                Write-Host "[$counter/$($devices.Count)] Skipping empty serial number" -ForegroundColor Yellow
                continue
            }

            Write-Host "[$counter/$($devices.Count)] $Serial" -ForegroundColor Cyan

            $deviceInfo = Search-SingleiOSDevice -Serial $Serial

            $Check = "✓"
            $result = [PSCustomObject]@{
                Serial          = $Serial
                ConstructedName = $deviceInfo.ConstructedName
                Intune          = if ($deviceInfo.Intune_DeviceFound)  { $Check } else { "False" }
                EntraID         = if ($deviceInfo.EntraID_DeviceFound) { $Check } else { "False" }
            }

            $results += $result
        }
    }
    catch {
        Write-Host "Error processing CSV: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Print results and export to a CSV in the user's Downloads folder
    $Pathway = "C:\Users\$env:USERNAME\Downloads\"
    $ExportFile = Join-Path -Path $Pathway -ChildPath "iOSDevicesFound.csv"

    if ($results) {
        $Utf8WithBom = New-Object System.Text.UTF8Encoding $true
        $csvContent = $results | ConvertTo-Csv -NoTypeInformation | Out-String
        [System.IO.File]::WriteAllText($ExportFile, $csvContent, $Utf8WithBom)
        Write-Host "`nResults exported to: $ExportFile" -ForegroundColor Yellow
        Write-Host "`nOpen in Excel for best visual." -ForegroundColor Magenta
        Write-Host "`nNote: Entra ID is only returned when a matching Intune object with the same AzureADDeviceId attribute exists." -ForegroundColor Blue
    }
    else {
        Write-Host "Not exported — no results." -ForegroundColor Yellow
    }

    if ($Transcript) {
        Stop-Transcript
    }

    return $results
}

function Remove-SingleiOSDevice {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Serial
    )

    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All", "Device.Read.All", "Device.ReadWrite.All" -NoWelcome

    $Serial = $Serial.Trim()
    $DeviceName = "iPhone-$Serial-NamedUser"

    $deviceresult = [PSCustomObject]@{
        InputSerial     = $Serial
        ConstructedName = $DeviceName

        # Intune
        Intune_DeviceFound     = $false
        Intune_DeviceName      = $null
        Intune_DeviceId        = $null
        Intune_AzureADDeviceId = $null
        Intune_Deleted         = $false

        # Entra ID
        EntraID_DeviceFound = $false
        EntraID_DeviceName  = $null
        EntraID_Deleted     = $false
    }

    Write-Host "Processing: $DeviceName" -ForegroundColor Yellow

    # --- Intune ---
    Write-Host "Checking Intune for $DeviceName..." -ForegroundColor Yellow
    $IntuneResults = Get-MgBetaDeviceManagementManagedDevice -Filter "deviceName eq '$DeviceName'" -ErrorAction SilentlyContinue

    if ($IntuneResults.Count -gt 1) {
        Write-Host "`nMultiple Intune devices found for serial '$Serial'. Verify entries before deleting.`n" -ForegroundColor Red
        $IntuneResults | ForEach-Object { Write-Host "Intune: $($_.DeviceName)" }
    }
    elseif ($IntuneResults) {
        $deviceresult.Intune_DeviceFound     = $true
        $deviceresult.Intune_DeviceName      = $IntuneResults.DeviceName
        $deviceresult.Intune_DeviceId        = $IntuneResults.Id
        $deviceresult.Intune_AzureADDeviceId = $IntuneResults.AzureADDeviceId

        Write-Host "$DeviceName found in Intune." -ForegroundColor Yellow
        try {
            Remove-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $IntuneResults.Id -ErrorAction Stop
            Write-Host "$DeviceName removed from Intune." -ForegroundColor Green
            $deviceresult.Intune_Deleted = $true
        } catch {
            Write-Host "Failed to remove $DeviceName from Intune: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "$DeviceName NOT found in Intune." -ForegroundColor Red
    }

    # --- Entra ID ---
    Write-Host "Checking Entra ID for $DeviceName..." -ForegroundColor Yellow
    if ($deviceresult.Intune_AzureADDeviceId) {
        try {
            $EntraResults = Get-MgBetaDevice -Filter "deviceId eq '$($deviceresult.Intune_AzureADDeviceId)'" -ErrorAction Stop
        }
        catch {
            $EntraResults = $null
        }

        if ($EntraResults) {
            $deviceresult.EntraID_DeviceFound = $true
            $deviceresult.EntraID_DeviceName  = $EntraResults.DisplayName

            Write-Host "$DeviceName found in Entra ID." -ForegroundColor Yellow
            try {
                Remove-MgBetaDevice -DeviceId $EntraResults.Id -ErrorAction Stop
                Write-Host "$DeviceName removed from Entra ID." -ForegroundColor Green
                $deviceresult.EntraID_Deleted = $true
            } catch {
                Write-Host "Failed to remove $DeviceName from Entra ID: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "$DeviceName NOT found in Entra ID." -ForegroundColor Red
        }
    }
    else {
        Write-Host "No AzureADDeviceId found for $DeviceName in Intune. Cannot search Entra ID." -ForegroundColor Yellow
    }

    # Display results
    $Check = "✓"
    $output = [PSCustomObject]@{
        Serial          = $deviceresult.InputSerial
        ConstructedName = $deviceresult.ConstructedName
        Intune          = if ($deviceresult.Intune_Deleted)  { $Check } elseif ($deviceresult.Intune_DeviceFound)  { "Found - Not Deleted" } else { "Not Found" }
        EntraID         = if ($deviceresult.EntraID_Deleted) { $Check } elseif ($deviceresult.EntraID_DeviceFound) { "Found - Not Deleted" } else { "Not Found" }
    }

    $output | Format-Table -AutoSize

    return $deviceresult
}

function Remove-BulkiOSDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [switch]$Transcript
    )

    if ($Transcript) {
        $logpath = "$($env:USERPROFILE)\Downloads"
        $logname = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_remove_bulk_ios_devices_script.log"
        Start-Transcript -Path "$logpath\$logname" -Verbose
    }

    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All", "Device.Read.All", "Device.ReadWrite.All" -NoWelcome

    if (-not (Test-Path $CsvPath)) {
        Write-Host "CSV file not found: $CsvPath" -ForegroundColor Red
        return
    }

    try {
        $devices = Import-Csv $CsvPath
        Write-Host "`nProcessing $($devices.Count) devices from CSV..." -ForegroundColor Yellow

        $results = @()
        $counter = 0

        foreach ($row in $devices) {
            $counter++
            $Serial = $row.'Serial'

            if ([string]::IsNullOrWhiteSpace($Serial)) {
                Write-Host "[$counter/$($devices.Count)] Skipping empty serial number" -ForegroundColor Yellow
                continue
            }

            Write-Host "[$counter/$($devices.Count)] $Serial" -ForegroundColor Cyan

            $deviceInfo = Remove-SingleiOSDevice -Serial $Serial

            $Check = "✓"
            $result = [PSCustomObject]@{
                Serial          = $Serial
                ConstructedName = $deviceInfo.ConstructedName
                IntuneStatus    = if ($deviceInfo.Intune_Deleted)  { $Check } elseif ($deviceInfo.Intune_DeviceFound)  { "Found - Not Deleted" } else { "Not Found" }
                EntraIDStatus   = if ($deviceInfo.EntraID_Deleted) { $Check } elseif ($deviceInfo.EntraID_DeviceFound) { "Found - Not Deleted" } else { "Not Found" }
            }

            $results += $result
        }
    }
    catch {
        Write-Host "Error processing CSV: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Print results and export to a CSV in the user's Downloads folder
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $Pathway = "C:\Users\$env:USERNAME\Downloads\"
    $ExportFile = Join-Path -Path $Pathway -ChildPath "iOSDevicesRemoved_$timestamp.csv"

    if ($results) {
        $Utf8WithBom = New-Object System.Text.UTF8Encoding $true
        $csvContent = $results | ConvertTo-Csv -NoTypeInformation | Out-String
        [System.IO.File]::WriteAllText($ExportFile, $csvContent, $Utf8WithBom)
        Write-Host "`nResults exported to: $ExportFile" -ForegroundColor Yellow
        Write-Host "`nOpen in Excel for best visual." -ForegroundColor Magenta
        Write-Host "`nNote: Entra ID is only removed when a matching Intune object with the same AzureADDeviceId attribute exists." -ForegroundColor Blue
    }
    else {
        Write-Host "Not exported — no results." -ForegroundColor Yellow
    }

    if ($Transcript) {
        Stop-Transcript
    }

    return $results
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

    Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All", "DeviceManagementServiceConfig.ReadWrite.All", "Device.Read.All", "Device.ReadWrite.All" -NoWelcome

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

    # --- Entra ID ---
    Write-Host "Checking Entra ID for $ComputerName..." -ForegroundColor Yellow
    if ($matchedDevice.AzureADDeviceId) {
        try {
            $EntraIDDevice = Get-MgBetaDevice -Filter "deviceId eq '$($matchedDevice.AzureADDeviceId)'" -ErrorAction Stop
        } catch {
            $EntraIDDevice = $null
        }

        if ($EntraIDDevice) {
            Write-Host "$ComputerName found in Entra ID" -ForegroundColor Yellow
            try {
                Remove-MgBetaDevice -DeviceId $EntraIDDevice.Id -ErrorAction Stop
                Write-Host "$ComputerName removed from Entra ID." -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove $ComputerName from Entra ID: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "$ComputerName NOT found in Entra ID" -ForegroundColor Red
        }
    } else {
        Write-Host "No AzureADDeviceId found for $ComputerName in Intune. Cannot search Entra ID." -ForegroundColor Yellow
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

    Connect-MgGraph -Scopes "DeviceManagementServiceConfig.Read.All", "DeviceManagementServiceConfig.ReadWrite.All", "Device.Read.All", "Device.ReadWrite.All" -NoWelcome

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
            EntraIDStatus   = "Not Attempted"
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

        # --- Entra ID ---
        Write-Host "[$counter] Checking Entra ID for $ComputerName..." -ForegroundColor Yellow
        if ($matchedDevice.AzureADDeviceId) {
            try {
                $EntraIDDevice = Get-MgBetaDevice -Filter "deviceId eq '$($matchedDevice.AzureADDeviceId)'" -ErrorAction SilentlyContinue
            } catch {
                $EntraIDDevice = $null
            }

            if ($EntraIDDevice) {
                Write-Host "[$counter] $ComputerName found in Entra ID" -ForegroundColor Yellow
                try {
                    Remove-MgBetaDevice -DeviceId $EntraIDDevice.Id -ErrorAction SilentlyContinue
                    Write-Host "[$counter] $ComputerName removed from Entra ID." -ForegroundColor Green
                    $result.EntraIDStatus = "Deleted"
                } catch {
                    Write-Host "[$counter] Failed to remove $ComputerName from Entra ID: $($_.Exception.Message)" -ForegroundColor Red
                    $result.EntraIDStatus = "Error: $($_.Exception.Message)"
                }
            } else {
                Write-Host "[$counter] $ComputerName NOT found in Entra ID" -ForegroundColor Red
                $result.EntraIDStatus = "Not Found"
            }
        } else {
            Write-Host "[$counter] No AzureADDeviceId found for $ComputerName in Intune. Cannot search Entra ID." -ForegroundColor Yellow
            $result.EntraIDStatus = "No AzureADDeviceId"
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
Export-ModuleMember -Function Search-SingleiOSDevice
Export-ModuleMember -Function Search-BulkiOSDevices
Export-ModuleMember -Function Remove-SingleiOSDevice
Export-ModuleMember -Function Remove-BulkiOSDevices
Export-ModuleMember -Function Remove-SingleComputer
Export-ModuleMember -Function Remove-BulkComputers
Export-ModuleMember -Function Get-LastLoggedInUser
Export-ModuleMember -Function Get-AllUserMDMManagedDevices
Export-ModuleMember -Function Get-AllUserEntraRegisteredDevices
Export-ModuleMember -Function New-TAP
Export-ModuleMember -Function Get-RemainingE5Licenses