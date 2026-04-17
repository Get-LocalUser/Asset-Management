#
# Module manifest for module 'AssetManagement'
#

@{
    # Module file associated with this manifest
    RootModule        = 'AssetManagement.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # Unique ID for this module
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'

    # Author
    Author            = 'Get-LocalUser'

    # Description
    Description       = 'A collection of PowerShell functions for managing devices in Active Directory, Intune, and Entra ID. Includes tools for searching, removing, and reporting on computers and users, as well as creating Temporary Access Passes (TAP).'

    # Minimum PowerShell version required
    PowerShellVersion = '7.0'

    # Modules that must be imported into the global environment prior to this module
    RequiredModules   = @(
        'ActiveDirectory',
        'Microsoft.Graph.Beta'
    )

    # Functions to export from this module
    FunctionsToExport = @(
        'Initialize-Modules',
        'Search-SingleComputer',
        'Search-BulkComputers',
        'Remove-SingleComputer',
        'Remove-BulkComputers',
        'Get-LastLoggedInUser',
        'Get-AllUserMDMManagedDevices',
        'Get-AllUserEntraRegisteredDevices',
        'New-TAP',
        'Get-RemainingE5Licenses'
    )

    # Cmdlets to export — none defined in this module
    CmdletsToExport   = @()

    # Variables to export — none
    VariablesToExport = @()

    # Aliases to export — none
    AliasesToExport   = @()

    # Private data / PSGallery metadata
    PrivateData       = @{
        PSData = @{
            # Tags for discoverability on PSGallery (if published)
            Tags         = @('Intune', 'Entra', 'ActiveDirectory', 'MicrosoftGraph', 'Autopilot', 'TAP', 'DeviceManagement')

            # Project URI (your GitHub repo)
            ProjectUri   = 'https://github.com/Get-LocalUser/Asset-Management'

            # Release notes
            ReleaseNotes = 'Initial release.'
        }
    }
}
