<#
.SYNOPSIS
    Prepares, executes, and validates the migration of Windows servers to Azure Local (Stack HCI) with comprehensive automation and monitoring.

.DESCRIPTION
    This comprehensive script automates the end-to-end process of migrating Windows servers from VMware to Azure Local (Azure Stack HCI).
    Version 2.4 removes all Active Directory OU management functionality and implements forced StaticIP migration preparation
    by copying Prepare-MigratedVM.zip from NETLOGON and executing the StaticIPMigration process.

    Key Features:
    - Automated pre-migration validation and configuration
    - Real-time migration monitoring and cutover handling
    - Post-migration verification and optional server reboot
    - SCOM maintenance mode management with conflict resolution
    - Comprehensive logging to file and console
    - Support for bypass mode when server is unreachable
    - VMware connection cleanup for sequential migrations

    Pre-Migration:
    - Validates server connectivity and DNS resolution
    - Determines datacenter location (DC1/DC2) from VMware if not specified
    - Creates PSSession for server information gathering (OS, disk count)
    - Forcibly copies Prepare-MigratedVM.zip from NETLOGON to c:\StaticIP
    - Extracts zip file and runs Prepare-MigratedVM.ps1 -StaticIPMigration
    - Ensures all disks are online and properly configured
    - Checks for pending SCCM updates
    - Creates migration documentation and CRQ (change request) records
    - Places server in SCOM maintenance mode

    Migration:
    - Initiates the Azure Migrate migration job
    - Monitors migration progress in real-time with status updates
    - Handles the cutover process to Azure Local
    - Validates VM appearance in the target Azure Local cluster
    - Waits for VM to become fully active before proceeding

    Post-Migration:
    - Verifies network connectivity to migrated server
    - Confirms all disks are online on the new Azure Local VM
    - Renames source VMware VM with ONSTACK prefix
    - Disconnects from VMware vCenter (prevents connection conflicts)
    - Restarts SCOM agent (healthservice) on migrated server
    - Prompts for optional server reboot with two-stage verification:
      * Ping connectivity check (6 attempts, 10-second intervals)
      * WinRM availability verification (6 attempts, 10-second intervals)
    - Archives StaticIP folder from server to desktop
    - Sends notification emails to Teams channel
    - Performs cleanup operations

    BypassChecks Mode:
    When -bypassChecks is enabled, the script skips all operations requiring direct server connectivity.
    Use this mode when the server is not reachable for remote PowerShell operations but migration needs to proceed.

    Operations Skipped with -bypassChecks:
    - PSSession creation and server information gathering
    - Pre-migration checks (connectivity, StaticIP preparation, updates, disk verification)
    - Post-migration disk confirmation
    - SCOM agent restart
    - Final reboot prompt
    - StaticIP folder archiving via network path

    Operations Still Performed with -bypassChecks:
    - Datacenter determination from VMware
    - Azure migration job initiation and monitoring
    - VMware VM renaming (ONSTACK prefix)
    - Email notifications
    - Log file operations

    User Responsibilities with -bypassChecks:
    - Monitor migration progress via Azure portal
    - Manually archive StaticIP folder if needed
    - Manually restart SCOM agent if needed
    - Manually reboot server if needed

.PARAMETER whatIf
    Switch parameter to simulate the script execution without making any changes.
    Currently not fully implemented throughout the script.

.PARAMETER serverName
    The name of the Windows server to be migrated.
    If not provided, the script will prompt for input.

.PARAMETER SQL
    Switch parameter to indicate if the server is running SQL Server.
    When specified, uses SQL-specific clusters (e.g., DC1-SQL-CL01, DC2-SQL-CL02).

.PARAMETER datacenter
    The target datacenter location (DC1 or DC2).
    If not provided, the script will automatically determine the datacenter from VMware.

.PARAMETER clusterID
    The target cluster ID (C1 or C2). Required parameter to specify which cluster to use.
    C1 = Cluster 01, C2 = Cluster 02

.PARAMETER bypassChecks
    Switch parameter to skip all pre-migration and post-migration validation checks and remote server connections.
    Use with caution - this mode assumes the server is not reachable and skips all direct connectivity operations.
    When enabled, user must manually handle post-migration tasks (SCOM agent restart, etc.).
    Ideal for offline migrations or when server is unreachable for remote PowerShell operations.

.EXAMPLE
    .\Start-AzureLocalMigrationV2.ps1 -serverName "SERVER01" -datacenter "DC1" -clusterID "C1"

    Migrates SERVER01 to DC1 cluster 01 with full pre and post-migration checks.

.EXAMPLE
    .\Start-AzureLocalMigrationV2.ps1 -serverName "SQLSERVER01" -SQL -datacenter "DC2" -clusterID "C2"

    Migrates SQL server SQLSERVER01 to DC2 SQL cluster 02 with full checks.

.EXAMPLE
    .\Start-AzureLocalMigrationV2.ps1 -serverName "SERVER02" -clusterID "C1" -bypassChecks

    Migrates SERVER02 to cluster 01 with all checks bypassed. Datacenter determined automatically.
    User must manually handle post-migration tasks.

.NOTES
    Version:        2.4
    Author:         <AUTHOR>
    Creation Date:  <CREATION_DATE>
    Last Modified:  <LAST_MODIFIED_DATE>

    Prerequisites:
    - VMware PowerCLI module must be installed
      Install-Module -Name VMware.VimAutomation.Core -Verbose -Force -AllowClobber
      Install-Module -Name VMware.VimAutomation.Vds -Verbose -Force -AllowClobber
      Install-Module -Name Az.ResourceGraph
    - Active Directory PowerShell module must be installed
    - Appropriate permissions in Azure, VMware, Active Directory, and SCOM
    - Network connectivity to vCenter servers and target servers (unless using -bypassChecks)

    Known Limitations:
    - Brief window during SCOM maintenance mode removal/re-add where alerts may trigger
    - 2-minute initial wait for server reboot may be insufficient for slower hardware
    - Force restart during optional reboot does not wait for running applications
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param (
    [Switch]$whatIf,
    [Switch]$SQL,
    [string]$serverName = "",
    [Switch]$bypassChecks,
    [Parameter(Mandatory = $false)]
    [ValidateSet('DC1', 'DC2')]
    [string]$datacenter = $null,
    [Parameter(Mandatory = $true)]
    [ValidateSet('C1', 'C2')]
    [string]$clusterID
)

# ============================================================
# ENVIRONMENT CONFIGURATION - Update these values for your org
# ============================================================

# Azure Subscription ID for the target environment
$targetSubscriptionId = "<AZURE_SUBSCRIPTION_ID>"

# Domain FQDN used for NETLOGON and UNC paths
$domainFQDN = "<DOMAIN_FQDN>"                     # e.g. "contoso.com"

# vCenter server hostnames
$vCenter1 = "<DC1_VCENTER_FQDN>"                  # e.g. "dc1-vmw-vcsa-01.contoso.com"
$vCenter2 = "<DC2_VCENTER_FQDN>"                  # e.g. "dc2-vmw-vcsa-01.contoso.com"

# SCOM management server hostnames
$scomServer1 = "<DC1_SCOM_SERVER_FQDN>"           # e.g. "dc1-scom-msm-01.contoso.com"
$scomServer2 = "<DC2_SCOM_SERVER_FQDN>"           # e.g. "dc2-scom-msm-01.contoso.com"

# NETLOGON path for Prepare-MigratedVM.zip
$netlogonZipPath = "\\$domainFQDN\NETLOGON\Software\IP\Prepare-MigratedVM.zip"

# CRQ file share path
$CRQfileshare = "<CRQ_FILESHARE_PATH>"            # e.g. "\\fileserver\share\AzureLocalCRQ"

# Email notification settings
$emailFrom       = "<EMAIL_FROM>"                 # e.g. "azuremigrate@contoso.com"
$emailTo         = "<EMAIL_TO>"                   # e.g. "teamschannel@contoso.onmicrosoft.com@amer.teams.ms"
$emailSmtpServer = "<SMTP_SERVER>"                # e.g. "smtp.contoso.com"

# ============================================================

$ScriptVersion = "2.4"
$VMDisplayName = $serverName
$SourceMachineType = "VMware"
$currentUser = whoami
$totalSteps = 8
$currentStep = 0
$destination = "$env:USERPROFILE\Desktop"
$destinationFolderPath = Join-Path -Path $destination -ChildPath $serverName
$logPath = Join-Path $destinationFolderPath "$serverName-migrate.log"

if ("" -eq $serverName) {
    $serverName = Read-Host "Enter Server Name (to be checked for migration)"
}

# ============================================================
# Logging Functions
# ============================================================

function logH1($msg) {
    $pattern = '0-' * 40
    $spaces = ' ' * (40 - $msg.length / 2)
    $nl = [Environment]::NewLine
    $msgFull = "$nl $nl $pattern $nl $spaces $msg $nl $pattern $nl"
    Write-Host -ForegroundColor Green $msgFull
}

function logH2($msg) {
    $msgFull = "==> $msg"
    Write-Host -ForegroundColor Magenta $msgFull
    Add-Content -Value "$msgFull" -Path $logPath
}

function logH3($msg) {
    $msgFull = "==> $msg"
    Write-Host -ForegroundColor Red $msgFull
    Add-Content -Value "$msgFull" -Path $logPath
}

function logH4($msg) { Write-Host -ForegroundColor Magenta $msg }
function logH5($msg) { Write-Host -ForegroundColor Green $msg }
function logH6($msg) { Write-Host -ForegroundColor Yellow $msg }
function logH7($msg) { Write-Host -ForegroundColor Red $msg }
function logH8($msg) { Write-Host -ForegroundColor Blue $msg }

# ============================================================
# Azure Local Cluster Variables
# ============================================================

$clusterSuffix = if ($clusterID -eq "C1") { "01" } else { "02" }
$DC1cluster = "DC1-AZL-CL$clusterSuffix"
$DC2cluster = "DC2-AZL-CL$clusterSuffix"
$whatIf = $false

# ============================================================
# Setup Output Directory and Log
# ============================================================

if (-not (Test-Path -Path $destinationFolderPath -PathType Container)) {
    Write-Output "Creating destination folder: $destinationFolderPath"
    New-Item -Path $destinationFolderPath -ItemType Directory | Out-Null
}

if (Test-Path -Path $logPath) {
    Write-Output "Log file already exists. Deleting..."
    Remove-Item -Path $logPath -Force
}

$versionMessage = "Start-AzureLocalMigrationV2.ps1 - Version $ScriptVersion"
Write-Host -ForegroundColor Cyan $versionMessage
Add-Content -Path $logPath -Value $versionMessage
Add-Content -Path $logPath -Value "Script started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Content -Path $logPath -Value "----------------------------------------"

# ============================================================
# VMware Module Check
# ============================================================

function CheckVMwareModule {
    param (
        [string]$logPath
    )

    $modules = @("VMware.VimAutomation.Core", "VMware.VimAutomation.vds")

    foreach ($module in $modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Add-Content -Path $logPath -Value "Module $module is not installed."
            Write-Error "Module $module is not installed. Exiting script."
            exit
        }
    }
}

CheckVMwareModule -logPath $logPath

# ============================================================
# Datacenter Determination
# ============================================================

if (-not $datacenter) {
    $vm = $null
    logH1 "Determining Datacenter and Domain Information for $($serverName.ToUpper())"

    Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

    try {
        Connect-VIServer -Server $vCenter1 -ErrorAction Stop | Out-Null
        $vm = Get-VM -Name $serverName -ErrorAction SilentlyContinue
        if ($vm) {
            $datacenter = 'DC1'
            Disconnect-VIServer -Server $vCenter1 -Confirm:$false
        }
        else {
            Disconnect-VIServer -Server $vCenter1 -Confirm:$false

            Connect-VIServer -Server $vCenter2 -ErrorAction Stop | Out-Null
            $vm = Get-VM -Name $serverName -ErrorAction Stop
            if ($vm) {
                $datacenter = 'DC2'
            }
            Disconnect-VIServer -Server $vCenter2 -Confirm:$false
        }

        if ($datacenter) {
            logH2 "Datacenter: $datacenter"
        }
        else {
            throw "Server $serverName not found in either vCenter"
        }
    }
    catch {
        throw "Failed to determine datacenter: $_"
    }
}

if ($SQL) {
    $DC1cluster = "DC1-SQL-CL$clusterSuffix"
    $DC2cluster = "DC2-SQL-CL$clusterSuffix"
    logH3 "SQL Server specific steps will be executed since the SQL parameter was specified."
}

switch ($datacenter) {
    "DC1" {
        $stackCluster = $DC1cluster
        if ($SQL) {
            $ProjectName      = "dc1-vmware-to-dc1-sql-cl$clusterSuffix"
            $ResourceGroupName = "dc1-vmware-to-dc1-sql-cl$clusterSuffix"
        }
        else {
            if ($clusterSuffix -eq "02") {
                $ProjectName      = "dc1-vmware-to-dc1-azl-cl$clusterSuffix"
                $ResourceGroupName = "dc1-vmware-to-dc1-azl-cl$clusterSuffix-rg"
            }
            else {
                $ProjectName      = "dc1-vmware-to-dc1-azl-cl$clusterSuffix"
                $ResourceGroupName = "dc1-vmware-to-dc1-azl-cl$clusterSuffix"
            }
        }
        $vCenter = $vCenter1
    }
    "DC2" {
        $stackCluster = $DC2cluster
        if ($SQL) {
            $ProjectName      = "dc2-vmware-to-dc2-sql-cl$clusterSuffix"
            $ResourceGroupName = "dc2-vmware-to-dc2-sql-cl$clusterSuffix-rg"
        }
        else {
            $ProjectName      = "dc2-vmware-to-dc2-azl-cl$clusterSuffix"
            $ResourceGroupName = "dc2-vmware-to-dc2-azl-cl$clusterSuffix-rg"
        }
        $vCenter = $vCenter2
    }
}

logH2 "Target Cluster: $stackCluster"

# ============================================================
# Domain Detection
# ============================================================

function Get-DomainSetting {
    param (
        [Parameter(Mandatory = $true)]
        [string]$serverName
    )

    try {
        $dnsInfo = Resolve-DnsName -Name $serverName -ErrorAction Stop | Select-Object -First 1
        if (-not $dnsInfo) {
            throw "Could not resolve DNS for $serverName"
        }

        $fqdn = $dnsInfo.Name
        $domainName = ($fqdn -split '\.', 2)[1]
        if (-not $domainName) {
            throw "Could not extract domain name from FQDN: $fqdn"
        }

        $domainParts = $domainName -split '\.'
        $domainBase  = "DC=" + ($domainParts -join ",DC=")

        $dc = Get-ADDomainController -DomainName $domainName -Discover -ForceDiscover | Select-Object -First 1
        if (-not $dc) {
            throw "Could not find domain controller for domain: $domainName"
        }
        $domainDC = $dc.HostName

        $settings = @{
            DomainName   = $domainName
            DomainBase   = $domainBase
            DomainDC     = $domainDC
            DomainSuffix = ".$domainName"
            FQDN         = $fqdn
        }

        logH2 "Domain Name: $($settings.DomainName)"
        logH2 "Domain Base: $($settings.DomainBase)"
        logH2 "Domain Controller: $($settings.DomainDC)"
        logH2 "Domain Suffix: $($settings.DomainSuffix)"
        logH2 "Server FQDN: $($settings.FQDN)"

        do {
            $confirm = Read-Host "Are these domain settings correct? (y/n)"
            if ($confirm -notin @('y', 'n')) {
                logH7 "Invalid input. Please enter 'y' for yes or 'n' for no."
            }
        } while ($confirm -notin @('y', 'n'))

        if ($confirm -eq 'n') {
            logH3 "Domain settings were not confirmed by user. Exiting script."
            throw "Domain settings were not confirmed by user"
        }

        return $settings
    }
    catch {
        Write-Error "Error detecting domain settings: $_"
        exit 1
    }
}

$domainSettings = Get-DomainSetting -serverName $serverName
$domainName     = $domainSettings.DomainName
$domainBase     = $domainSettings.DomainBase
$domainDC       = $domainSettings.DomainDC
$fqdn           = $domainSettings.FQDN

# ============================================================
# Azure Authentication
# ============================================================

$loginPrompt = Read-Host "Do you need to login to Azure? (y/n)"
if ($loginPrompt -eq 'y') {
    Connect-AzAccount -UseDeviceAuthentication
    $currentContext = Get-AzContext
    if (-Not $currentContext) {
        logH3 "Azure authentication failed. No context available after login attempt. Exiting script."
        exit 1
    }
}
else {
    logH2 "Skipping Azure login. Current context:"
    $currentContext = Get-AzContext
    if ($currentContext) {
        logH2 "Subscription: $($currentContext.Subscription.Name) ($($currentContext.Subscription.Id))"
        logH2 "Account: $($currentContext.Account)"
        logH2 "Tenant: $($currentContext.Tenant.Id)"
    }
    else {
        logH3 "No Azure context available. Some operations may fail."
    }
}

if ($currentContext.Subscription.Id -ne $targetSubscriptionId) {
    logH2 "Switching to required subscription..."
    Set-AzContext -SubscriptionId $targetSubscriptionId
}
else {
    logH2 "Azure Subscription Check: Passed"
}

# ============================================================
# DNS Resolution and Connectivity Check
# ============================================================

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script" -Status "Azure Migrate Pre-Check Starting..." -PercentComplete (($currentStep / $totalSteps) * 100)
logH1 "Checking DNS Resolution and Network Connectivity"

try {
    $dnsResult = Resolve-DnsName -Name $serverName -ErrorAction Stop
    if ($dnsResult.IPAddress) {
        if ($dnsResult.IPAddress -is [array]) {
            $serverIP = $dnsResult.IPAddress -join ", "
        }
        else {
            $serverIP = $dnsResult.IPAddress
        }
        logH2 "Successfully resolved DNS name to IP address: $serverIP"
    }
    else {
        Write-Error "DNS resolution failed - no IP address returned for $serverName"
        exit 1
    }
}
catch {
    Write-Error "Failed to resolve DNS for $serverName : $_"
    exit 1
}

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path $logPath -Value "Precheck started at $currentDateTime"
Add-Content -Path $logPath -Value "User: $currentUser"
Add-Content -Path $logPath -Value "Server: $serverName"
Add-Content -Path $logPath -Value "IP Address: $serverIP"
Add-Content -Path $logPath -Value "Datacenter: $datacenter"
Add-Content -Path $logPath -Value "Cluster: $stackCluster"

$connection = Test-Connection -ComputerName $serverName -Count 1 -Quiet
if (-not $connection) {
    Write-Warning "Server $serverName is not online. Trying with domain suffix..."
    $connection = Test-Connection -ComputerName $fqdn -Count 1 -Quiet
    if (-not $connection) {
        Write-Error "Server $serverName is not online. Exiting script."
        exit
    }
}

if ($null -eq $serverIP) {
    Write-Error "Could not resolve IP for server $serverName. Exiting script."
    exit
}

Write-Verbose "Found $serverName online at: $serverIP"

# ============================================================
# SCOM Maintenance Mode
# ============================================================

function PlaceServerInSCOMMaintenanceMode {
    param (
        [Parameter(Mandatory = $true)]
        [string]$serverName,

        [Parameter(Mandatory = $false)]
        [int]$durationMinutes = 120,

        [Parameter(Mandatory = $false)]
        [string]$reason = "Azure Local Migration in Progress",

        [Parameter(Mandatory = $false)]
        [string]$comment = "Server placed in maintenance mode during migration to Azure Local"
    )

    try {
        logH6 "Attempting to place $serverName into SCOM maintenance mode for $durationMinutes minutes..."

        $scomServers = @(
            $scomServer1,
            $scomServer2
        )

        $connectedScomServer = $null

        foreach ($server in $scomServers) {
            try {
                $testConnection = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
                if ($testConnection) {
                    logH6 "Successfully connected to SCOM management server: $server"
                    $connectedScomServer = $server
                    break
                }
            }
            catch {
                logH7 "Could not connect to SCOM server $server. Trying next server..."
                continue
            }
        }

        if (-not $connectedScomServer) {
            logH7 "Warning: Could not connect to any SCOM management server. SCOM maintenance mode will be skipped."
            logH7 "Available SCOM servers: $($scomServers -join ', ')"
            return $false
        }

        $scriptBlock = {
            param($targetServerName, $durationMin, $maintenanceReason, $maintenanceComment)

            try {
                Import-Module OperationsManager -ErrorAction Stop

                $managementServer = Get-SCOMManagementServer -ErrorAction Stop | Select-Object -First 1
                if (-not $managementServer) {
                    throw "Could not connect to SCOM management server"
                }

                $scomAgent = Get-SCOMAgent -Name "$targetServerName*" -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $scomAgent) {
                    Write-Warning "Server $targetServerName not found in SCOM."
                    return @{ Success = $false; Message = "Server not found in SCOM monitoring" }
                }

                $monitoringObject = $scomAgent.HostComputer
                if (-not $monitoringObject) {
                    Write-Warning "Monitoring object for $targetServerName not found in SCOM."
                    return @{ Success = $false; Message = "Monitoring object not found in SCOM" }
                }

                $startTime = [DateTime]::Now
                $endTime   = $startTime.AddMinutes($durationMin)

                $inMaintenance = Get-SCOMMaintenanceMode -Instance $monitoringObject -ErrorAction SilentlyContinue
                if ($inMaintenance) {
                    Write-Host "Server $targetServerName is already in maintenance mode. Attempting to extend to $durationMin minutes..."
                }

                Start-SCOMMaintenanceMode -Instance $monitoringObject -EndTime $endTime -Reason $maintenanceReason -Comment $maintenanceComment -ErrorAction Stop

                return @{
                    Success   = $true
                    Message   = "Successfully placed $targetServerName in maintenance mode until $endTime"
                    StartTime = $startTime
                    EndTime   = $endTime
                }
            }
            catch {
                return @{
                    Success = $false
                    Message = "Error: $($_.Exception.Message)"
                    Error   = $_
                }
            }
        }

        logH6 "Executing SCOM maintenance mode command on $connectedScomServer..."
        $result = Invoke-Command -ComputerName $connectedScomServer -ScriptBlock $scriptBlock -ArgumentList $serverName, $durationMinutes, $reason, $comment -ErrorAction Stop

        if ($result.Success) {
            logH2 "SUCCESS: $($result.Message)"
            Add-Content -Value "SCOM Maintenance Mode: $($result.Message)" -Path $logPath
            return $true
        }
        else {
            logH7 "WARNING: $($result.Message)"
            Add-Content -Value "SCOM Maintenance Mode Warning: $($result.Message)" -Path $logPath
            return $false
        }
    }
    catch {
        logH7 "Error placing server in SCOM maintenance mode: $($_.Exception.Message)"
        logH7 "The migration will continue, but the server may generate alerts in SCOM."
        Add-Content -Value "SCOM Maintenance Mode Error: $($_.Exception.Message)" -Path $logPath
        return $false
    }
}

# ============================================================
# Static IP Migration Preparation
# ============================================================

function Test-StaticIP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$serverName,

        [Parameter(Mandatory = $true)]
        [string]$fqdn
    )

    try {
        $destinationPath = "\\$fqdn\c$\StaticIP"
        $zipDestination  = Join-Path $destinationPath "Prepare-MigratedVM.zip"

        if (-not (Test-Path $destinationPath -PathType Container)) {
            logH2 "Creating c:\StaticIP directory on $serverName..."
            New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
            logH2 "Created c:\StaticIP directory on $serverName"
        }
        else {
            logH2 "c:\StaticIP directory already exists on $serverName"
        }

        logH2 "Copying Prepare-MigratedVM.zip from NETLOGON to $serverName..."
        Copy-Item -Path $netlogonZipPath -Destination $zipDestination -Force -ErrorAction Stop
        logH2 "Successfully copied Prepare-MigratedVM.zip to $serverName"

        logH2 "Extracting Prepare-MigratedVM.zip on $serverName..."
        $zipPath     = "c:\StaticIP\Prepare-MigratedVM.zip"
        $extractPath = "c:\StaticIP"

        Invoke-Command -ComputerName $fqdn -ScriptBlock {
            try {
                $windowsFolder = Join-Path $using:extractPath "Windows"
                if (Test-Path $windowsFolder) {
                    Remove-Item -Path $windowsFolder -Recurse -Force
                }
                Expand-Archive -Path $using:zipPath -DestinationPath $using:extractPath -Force
                Write-Output "Successfully extracted Prepare-MigratedVM.zip"
            }
            catch {
                Write-Error "Failed to extract zip file: $_"
                throw
            }
        }

        logH2 "Successfully extracted Prepare-MigratedVM.zip on $serverName"

        logH2 "Running Prepare-MigratedVM.ps1 -StaticIPMigration on $serverName..."
        Invoke-Command -ComputerName $fqdn -ScriptBlock {
            try {
                $scriptPath = "c:\StaticIP\Windows\Prepare-MigratedVM.ps1"
                if (Test-Path $scriptPath) {
                    & $scriptPath -StaticIPMigration
                    Write-Output "Successfully executed Prepare-MigratedVM.ps1 -StaticIPMigration"
                }
                else {
                    Write-Error "Prepare-MigratedVM.ps1 not found at $scriptPath"
                    throw "Prepare-MigratedVM.ps1 not found"
                }
            }
            catch {
                Write-Error "Failed to execute Prepare-MigratedVM.ps1: $_"
                throw
            }
        }

        logH2 "Successfully completed StaticIP migration preparation on $serverName"
    }
    catch {
        logH3 "Failed to setup StaticIP migration: $_"
        Write-Error "Failed to setup StaticIP migration: $_"
        exit 1
    }
}

# ============================================================
# SCCM Update Check
# ============================================================

function CheckTargetServerForUpdates {
    param (
        [string]$serverName
    )

    logH2 "Checking for pending SCCM updates on server: $serverName..."

    try {
        $cimSession = New-CimSession -ComputerName $serverName -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to create CIM session with $serverName. Exiting script."
        exit
    }

    $scriptBlock = {
        Get-CimInstance -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_SoftwareUpdate | Where-Object { $_.ComplianceState -ne 1 }
    }

    try {
        $updates = Invoke-Command -ComputerName $serverName -ScriptBlock $scriptBlock -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match "Generic failure|0x80041001") {
            logH7 "Note: Unable to query SCCM updates (Generic failure - this is normal if SCCM client is busy or initializing)."
            logH7 "Continuing with migration. Please verify updates manually if needed."
            $updates = $null
        }
        else {
            Write-Warning "Error checking SCCM updates: $($_.Exception.Message)"
            logH7 "Continuing with migration despite SCCM check error."
            $updates = $null
        }
    }

    if ($updates) {
        Write-Warning "Available SCCM updates found on server: $serverName!"
        $updates | ForEach-Object {
            logH3 "Update: $($_.ArticleID) - $($_.Name)"
        }

        $confirmation = Read-Host "Do you want to continue anyway despite pending updates? (y/n)"
        if ($confirmation -eq "n") {
            Remove-CimSession -CimSession $cimSession
            Write-Error "Please install pending SCCM updates. Exiting script."
            exit
        }
        elseif ($confirmation -eq "y") {
            logH2 "Continuing with migration despite pending SCCM updates."
        }
    }
    else {
        logH2 "No available SCCM updates found on server: $serverName"
    }

    Remove-CimSession -CimSession $cimSession
}

# ============================================================
# Disk Online Check
# ============================================================

function MakeSureDisksAreOnline {
    param (
        [string]$serverName
    )

    $diskPartCommand = @"
san policy=OnlineAll
exit
"@

    Invoke-Command -ComputerName $serverName -ScriptBlock {
        $diskPartCommand = $using:diskPartCommand
        $null = $diskPartCommand | diskpart
    }

    logH2 "SAN Policy - OnlineAll: Passed"
}

# ============================================================
# Pre-Migration Checks
# ============================================================

if (-not $bypassChecks) {
    logH2 "Checking for c:\temp directory on $serverName..."
    $tempPath  = "\\$serverName\c$\temp"
    $createPath = "C:\temp"
    if (-not (Test-Path $tempPath -PathType Container)) {
        try {
            New-Item -Path $createPath -ItemType Directory -Force | Out-Null
            logH2 "Created c:\temp directory on $serverName"
        }
        catch {
            Write-Warning "Failed to create c:\temp directory on $serverName : $_"
            logH3 "Failed to create c:\temp directory on $serverName : $_"
            throw "Failed to create c:\temp directory on $serverName. Cannot continue migration."
        }
    }
    else {
        logH2 "c:\temp directory already exists on $serverName"
    }

    Test-StaticIP -serverName $serverName -fqdn $fqdn
    CheckTargetServerForUpdates -serverName $fqdn
    MakeSureDisksAreOnline -serverName $fqdn
}
else {
    logH3 "Bypassing pre-checks as -bypassChecks was specified."
    logH8 "WARNING: PLEASE MAKE SURE SERVER IS ONLINE MANUALLY.  CHECK FOR C:\STATICIP\WINDOWS FOLDER!"
    Read-Host -Prompt "Press any key to continue"
}

# ============================================================
# PSSession and Server Info Gathering
# ============================================================

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script" -Status "Checking PSSession...." -PercentComplete (($currentStep / $totalSteps) * 100)

if (-not $bypassChecks) {
    try {
        $session = New-PSSession -ComputerName $fqdn -ErrorAction Stop
    }
    catch {
        try {
            $session = New-PSSession -ComputerName $serverName -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to create PSSession with FQDN $fqdn. Exiting script."
            exit
        }
    }

    $eventLogParams = @{
        LogName   = 'Application'
        Source    = 'Azure Migrate PreCheck'
        EntryType = 'Warning'
        EventId   = 1000
        Message   = "Azure Migrate PreCheck was started by $($currentUser)"
    }

    $eventLogBlock = {
        $currentUser = $using:currentUser
        if (-not [System.Diagnostics.EventLog]::SourceExists($using:eventLogParams.Source)) {
            New-EventLog -LogName $using:eventLogParams.LogName -Source $using:eventLogParams.Source
        }
        Write-EventLog @using:eventLogParams
    }

    $serverInfo = Invoke-Command -Session $session -ScriptBlock {
        $osName   = (Get-CimInstance -ClassName CIM_OperatingSystem).Caption
        $diskCount = (Get-CimInstance -ClassName CIM_DiskDrive).Count
        return @{
            OSName    = $osName
            DiskCount = $diskCount
        }
    }

    $osName    = $serverInfo.OSName
    $diskCount = $serverInfo.DiskCount
    logH2 "Operating System: $osName"
    logH2 "VMware Disks: $diskCount"

    $eventLogParams = @{
        LogName   = 'Application'
        Source    = 'Azure Migrate PreCheck'
        EntryType = 'Warning'
        EventId   = 1916
        Message   = "Azure Migrate PreCheck was completed by $($currentUser)"
    }

    Invoke-Command -Session $session -ScriptBlock $eventLogBlock
    Remove-PSSession -Session $session
}
else {
    logH3 "Bypassing PSSession checks as -bypassChecks was specified."
    logH3 "Migration will proceed without verifying OS details or disk count."
}

# ============================================================
# Helper Functions
# ============================================================

function GetVMStatus {
    param ([string]$serverName)

    $vmStatus = "OFFLINE"
    $connectionTest = Test-Connection -ComputerName $serverName -Count 1 -Quiet
    if ($connectionTest) { $vmStatus = "ONLINE" }
    return $vmStatus
}

function CreateCRQFile {
    param (
        [Parameter(Mandatory = $true)][string]$serverName,
        [Parameter(Mandatory = $true)][string]$username,
        [Parameter(Mandatory = $true)][string]$ipAddress,
        [Parameter(Mandatory = $true)][string]$domain,
        [Parameter(Mandatory = $true)][string]$datacenter,
        [Parameter(Mandatory = $true)][string]$fileShare
    )

    try {
        if (-not (Test-Path -Path $fileShare -PathType Container)) {
            Write-Output "File share path $fileShare does not exist. Creating it..."
            New-Item -Path $fileShare -ItemType Directory -Force | Out-Null
        }

        $crqFilePath = Join-Path -Path $fileShare -ChildPath "$serverName.log"

        $crqContent = @"
User: $username
Server: $serverName
IP Address: $ipAddress
Domain: $domain
Datacenter: $datacenter
Cluster: $stackCluster
"@

        $crqContent | Out-File -FilePath $crqFilePath -Encoding UTF8 -Force
        logH6 "CRQ file created successfully at $crqFilePath"
    }
    catch {
        Write-Error "Failed to create CRQ file. Error: $_"
    }
}

function SendEmailToTeams {
    param (
        [string]$logPath,
        [string]$serverName
    )

    $emailParams = @{
        From       = $emailFrom
        To         = $emailTo
        Subject    = "Azure Stack Migration started for $serverName"
        Body       = (Get-Content -Path $logPath) -join "`n"
        SmtpServer = $emailSmtpServer
    }

    Send-MailMessage @emailParams
    # Log the action
    logH2 "Migration notification email sent for $serverName"
}