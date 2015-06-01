#
# Module manifest for module 'fmg.powershell.dsc'
#
# Generated by: Matt Hatch
#
# Generated on: 3/27/2015
#
<#
    Summary
    =======
    DSC Commands to manage meta.MOF files and update server LCM configurations

    Revision History
    ================
    7/30/2014 - Initial Version (Matt Hatch)
    8/13/2014 - Updated the Cmdlet names
    8/14/2014 - Added the New-ServerManifest function (Matt Hatch)
    8/14/2014 - Added the Update-ServerManifest function (Matt Hatch)
    8/15/2014 - Cleaned up Update-ServerManifest Comments
    8/21/2014 - Update New-ServerManifest to accept array of ComputerNames
    8/26/2014 - Added Get-ServerConfiguration and Updated New-MetaMOF to Accept Get-ServerConfiguration Pipeline data
    8/27/2014 - Added Get-DSCServer to return all servers in the configuration database
    8/31/2014 - Added Get-DSCGuid to return all GUID and associated information including collection of Servers associated (Matt Hatch)
    9/3/2014 - Added Get-DSCConfigurationType (Matt Hatch)
    9/3/2014 - Added Get-DSCEnvironment (Matt Hatch)
    9/3/2014 - Refactored setting up SQL Connection to __connect-sql (Matt Hatch)
    9/3/2014 - Refactored getting data from sql to __get-SQLData (Matt Hatch)
    10/1/2014 - Added two parameters to New-MetaMof allowing a user to Override the ConfigurationMode and RefreshMode (Matt Hatch)
    10/22/2014 - Added New Cmdlet Test-DesiredState
    12/04/2014 - Added Remove-MetaMof, Removed depricated Cmdlets (Matt Hatch)
    12/09/2014 - Added Invoke-DSCBuild (Matt Hatch)
    12/11/2014 - Added Update-ServerConfiguration
    03/27/2015 - Added Environment Parameter to Get-ServerConfigurationData to allow for an envionment override

    TODO: Add New-ServerConfiguration
#>

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\fmg.powershell.dsc.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = '63471fb3-02bd-46da-8250-ec9501963188'

# Author of this module
Author = 'Matt Hatch'

# Company or vendor of this module
CompanyName = 'FM Global'

# Copyright statement for this module
Copyright = '(c) 2015 Matt Hatch. All rights reserved.'

# Description of the functionality provided by this module
Description = 'FM Global implemtation of DSC implemetation'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess
# PrivateData = ''

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

