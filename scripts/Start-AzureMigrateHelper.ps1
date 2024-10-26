<#
.SYNOPSIS
    This script assists with migrating a SQL server to Azure Stack HCI.

.DESCRIPTION
This script automates several tasks related to Azure migration:

1. Prompts the user for the server name to be migrated.
2. Checks if the server is online and resolves its name to an IP address. Also checks for pending SCCM updates.
3. Connects to vCenter to identify the datacenter hosting the server.
4. Establishes a PowerShell session with the server to collect network information.
5. Generates a log file and a network information file on the user's desktop.
6. If the SQL parameter is specified, it carries out SQL Server specific operations.
7. If the diskSize parameter is not provided, it prompts the user to input the SQL disk size.
8. Connects to the Hyper-V cluster to create a 4K SQL disk.
9. Monitors the migration process until completion and attaches the VHDX to the VM.
10. Waits for the VM to power on and adds a SCSI controller and disk to the VM.
11. Connects to the offline VM via Hyper-V Direct and brings it online.
12. Renames the old server in VMware


.PARAMETER serverName
    Specifies the name of the server to be migrated. If not provided, the script will prompt for it.

.PARAMETER whatIf
    A switch parameter. If provided, the script will run in debug mode.

.PARAMETER SQL
    A switch parameter. If provided, SQL Server specific steps will be executed.

.PARAMETER diskSize
    Specifies the SQL disk size. If not provided, the script will prompt for it.

.EXAMPLE
    .\Start-AzureMigrateHelper.ps1 -serverName "Server1" -SQL -diskSize 256
    This example shows how to run the script with the serverName, SQL, and diskSize parameters.

.INPUTS
    serverName: You can provide the server name as a parameter when running the script.
    whatIf: You can provide this switch to run the script in debug mode.
    SQL: You can provide this switch to execute SQL Server specific steps.
    diskSize: You can provide the SQL disk size as a parameter when running the script.
    datacenter: You can provide the datacenter name as a parameter when running the script.

.OUTPUTS
    Log files and network information files are created on the user's desktop. The script also outputs the progress of the migration process to the console.

.NOTES
    Version:        1.1
    Author:         Jon McCabe
    Creation Date:  2024-06-01
    Purpose/Change: Azure Migrate Pre-Check script for SQL Server migration to Azure Stack HCI.
    Prerequistes: This script requires VMware PowerCLI and Hyper-V PowerShell modules to be installed on the machine running the script.
    PowerShell install commands:
    Install-Module -Name VMware.VimAutomation.Core -verbose -Force -AllowClobber
    Install-Module -Name VMware.VimAutomation.Vds
#>

# Define parameters
param (
    [Switch]$whatIf,
    [Switch]$SQL,
    [int]$diskSize = 0,
    [string]$serverName = "",
    [Parameter(Mandatory = $true)]
    [ValidateSet('RDC', 'BDC')]
    [string]$datacenter
)

# Set debug variable
$debug = $false
if ($whatIf) {
    $debug = $true
}

$currentUser = whoami
$totalSteps = 13 #total steps in the script
$currentStep = 0
$RDCcluster = "AZURE STACK CLUSTER NAME1"
$BDCcluster = "AZURE STACK CLUSTER NAME2"
$vCenter1 = "[FQDN OF VCENTER1]"
$vCenter2 = "[FQDN OF VCENTER2]"
$domainName = "AD DOMAIN SUFFIX"
$Hashtable = ""
$sourceFolderPath = "UNC FILE SHARE PATH"
$destination = "$env:USERPROFILE\Desktop"
$destinationFolderPath = Join-Path -Path $destination -ChildPath $servername
$filePath = Join-Path $destinationFolderPath "$serverName.txt"
$logPath = Join-Path $destinationFolderPath "$serverName-migrate.log"

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script" -Status "Azure Migrate Pre-Check Starting..." -PercentComplete (($currentStep / $totalSteps) * 100)
Write-Warning "THIS SCRIPT IS FOR THE TEST ONLY. DO NOT USE IN PRODUCTION."
Write-Output "Running Azure Migrate Helper Script"
Write-Output "."
Write-Output "."
Write-Output "."
Write-Output "."


if ("" -eq $serverName) {
    $serverName = Read-Host "Enter Server Name (to be checked for migration)"
}
$fqdn = $serverName + $domainName

$connection = Test-Connection -ComputerName $serverName -Count 1 -Quiet
if (-not $connection) {
    Write-Warning "Server $serverName is not online. Trying with domain suffix..."

    $connection = Test-Connection -ComputerName $fqdn -Count 1 -Quiet
    if (-not $connection) {
        Write-Error "Server $serverName is not online. Exiting script."
        exit
    }
}

$serverIP = (Resolve-DnsName -Name $serverName).IPAddress
Write-Output "Precheck: Successfully resolved DNS name to IP address."

if ($null -eq $serverIP) {
    Write-Error "Could not resolve IP for server $serverName. Exiting script."
    exit
}
Write-Verbose "Found $serverName online at: $serverip"

#Setup Logging
if (-not (Test-Path -Path $destinationFolderPath)) {
    New-Item -Path $destinationFolderPath -ItemType Directory
}
# Check if the source folder exists
if (Test-Path -Path $sourceFolderPath -PathType Container) {
    # Copy the source folder to the destination and rename it to $servername
    Copy-Item -Path $sourceFolderPath -Destination $destinationFolderPath -Recurse -Force
}
else {
    Write-Error "Folder does not exist at $sourceFolderPath."
}
if (Test-Path -Path $logPath) {
    Remove-Item -Path $logPath -Force
}
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path $logPath -Value "Precheck started at $currentDateTime"
Add-Content -Path $logPath -Value "User: $currentUser"
Add-Content -Path $logPath -Value "Server: $serverName"
Add-Content -path $logPath -Value "IP Address: $serverIP"

function CheckTagetServerForUpdates {
    param (
        [string]$serverName
    )

    Write-Output "Checking for pending SCCM updates on server: $serverName"

    $scriptBlock = {
        Get-CimInstance -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_SoftwareUpdate | Where-Object { $_.ComplianceState -ne 1 }
    }

    $updates = Invoke-Command -ComputerName $serverName -ScriptBlock $scriptBlock

    if ($updates) {
        Write-Warning "Available SCCM updates found on server: $serverName! Please remediate."
        $updates | ForEach-Object {
            Write-Output "Update: $($_.ArticleID) - $($_.Name)"
            Write-Error "PENDING_UPDATE - No pending software updates allowed during migrations."
            exit
        }
    } else {
        Write-Output "No available SCCM updates found on server: $serverName."
        return
    }
}

CheckTagetServerForUpdates -serverName $serverName

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
        else {
            Add-Content -Path $logPath -Value "Module $module is installed."

        }
    }


}

CheckVMwareModule -logPath $logPath

function CreateLocalAdmin {
    param (
        [string]$serverName,
        [string]$logPath,
        [pscredential]$passwordcred
    )
    # $passwordcred = Get-Credential -Message "Enter a password for the new local admin account" -UserName "tempadmin"
    # Create a new PSSession
    $session = New-PSSession -ComputerName $serverName


    # Define the script block
    $scriptBlock = {
        param (
            [PSCredential]$passwordcred
        )
        # Check if the tempadmin user already exists
        $userExists = Get-LocalUser -Name "tempadmin" -ErrorAction SilentlyContinue

        if ($null -ne $userExists) {
            Write-Output "User tempadmin already exists."

            # Reset the password
            $userExists | Set-LocalUser -Password $passwordcred.Password
            # Add the new user to the local administrators group
            try {
                Add-LocalGroupMember -Group "Administrators" -Member $passwordcred.UserName -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Failed to add user to Administrators group."
            }
        }
        else {
            # Create a new local user
            New-LocalUser -Name $passwordcred.UserName -Password $passwordcred.Password -FullName "Temporary Administrator" -Description "Temporary admin account"

            # Add the new user to the local administrators group
            Add-LocalGroupMember -Group "Administrators" -Member $passwordcred.UserName
        }
    }

    # Invoke the command
    Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $passwordcred


    Add-Content -Path $logPath -Value "Local admin account created on $serverName"
    # Close the PSSession
    Remove-PSSession -Session $session

    # Return the password credential
    return $passwordcred

}

if ($debug -eq $true) {
    Write-Warning "This would create a local administrator but the -whatIf parameter was used."
}
else {
    $passwordcred = (Get-Credential -Message "Enter a password for the new local admin account" -UserName "tempadmin")
    CreateLocalAdmin -serverName $fqdn -logPath $logPath -passwordcred $passwordcred
}


#SQL Server specific steps

if ($SQL) {
    Write-Verbose "SQL Server specific steps will be executed since the SQL parameter was specified."
    Add-Content -Path $logPath -Value "SQL Server specific steps will be executed."

    if (0 -eq $diskSize) {
        $diskSize = Read-Host "Enter SQL disk size (in GB)"
    }
    $diskSizeString = $diskSize.ToString() + "GB"
    $diskSize = [int]$diskSize
}

Add-Content -Path $logPath -Value "Log file created at $logPath."
Add-Content -Path $logPath -Value "Network information file created at $filePath."

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script" -Status "Connecting to VMware for VLAN...." -PercentComplete (($currentStep / $totalSteps) * 100)


# Set vCenter and stackCluster based on datacenter
if ($datacenter -eq "RDC") {
    $vCenter = $vCenter1
    $stackCluster = $RDCcluster
    Add-Content -Path $logPath -Value "Datacenter set to RDC."
}
else {
    $vCenter = $vCenter2
    $stackCluster = $BDCcluster
    Add-Content -Path $logPath -Value "Datacenter set to BDC."
}

# Connect to vCenter
Connect-VIServer -Server $vCenter | Out-Null

# Get the host of the VM
$vm = Get-VM -Name $serverName
$vmHost = $vm.VMHost

# If the VM host is null, throw an error
if ($null -eq $vmHost) {
    throw "VM host is null"
}
$Networkname = Get-NetworkAdapter -VM $serverName | Select-Object Name -ExpandProperty NetworkName
$VLANID = Get-VDPortgroup -Name $Networkname | Select-Object Name -ExpandProperty VlanConfiguration
$VLANID = $VLANID.ToString()
$VLANID = $VLANID.Replace("VLAN ", "")

Add-Content -Value "VLAN ID: $VLANID" -Path $logPath

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script" -Status "Checking PSSession...." -PercentComplete (($currentStep / $totalSteps) * 100)


try {
    $session = New-PSSession -ComputerName $fqdn -ErrorAction Stop
}
catch {
    #Write-Warning "Failed to create PSSession with server name $serverName. Trying with FQDN..."
    try {
        $session = New-PSSession -ComputerName $serverName -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to create PSSession with FQDN $fqdn. Exiting script."
        exit
    }
}

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script" -Status "Step 3: Connecting to $serverName for network information..." -PercentComplete (($currentStep / $totalSteps) * 100)

# Write to the server's event log
$eventLogParams = @{
    LogName   = 'Application' # or any other log name
    Source    = 'Azure Migrate PreCheck' # the source of the event
    EntryType = 'Warning' # or 'Error', 'Warning', 'SuccessAudit', 'FailureAudit'
    EventId   = 1000 # a unique identifier for the event
    Message   = "Azure Migrate PreCheck was started by $($currentUser)"  # the message to write to the event log
}
$eventLogBlock = {
    # Check if the source exists
    $currentUser = $using:currentUser
    if (-not [System.Diagnostics.EventLog]::SourceExists($using:eventLogParams.Source)) {
        # Create the source
        New-EventLog -LogName $using:eventLogParams.LogName -Source $using:eventLogParams.Source
    }

    # Write to the event log
    Write-EventLog @using:eventLogParams
}

# Get the network interfaces on the server that have the same IP address as the server
Invoke-Command -Session $session -ScriptBlock $eventLogBlock

$networkInterfaces = Invoke-Command -Session $session -ScriptBlock {
    Get-NetAdapter | ForEach-Object {
        $ifIndex = $_.ifIndex
        $ipAddress = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
        if ($ipAddress -eq $using:serverIP) {
            $_ | Select-Object Name, InterfaceDescription, ifIndex
        }
    }
} -ArgumentList $serverip, $serverName


$networkInterfaces | ForEach-Object {

    $ifIndex = $_.ifIndex

    # Get the IP address and prefix length of the network interface
    $networkConfig = Invoke-Command -Session $session -ScriptBlock {
        Get-NetIPAddress -InterfaceIndex $using:ifIndex -AddressFamily IPv4 | Select-Object IPAddress, PrefixLength
    }

    # Get the gateway of the network interface
    $gateway = Invoke-Command -Session $session -ScriptBlock {
        Get-NetRoute -InterfaceIndex $using:ifIndex -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object NextHop
    }

    # Get the DNS servers of the network interface
    $dnsServers = Invoke-Command -Session $session -ScriptBlock {
        Get-DnsClientServerAddress -InterfaceIndex $using:ifIndex | Select-Object ServerAddresses
    }

    # Get the IP address from the network configuration
    $ipAddress = $networkConfig.IPAddress

    # If the IP address does not match the server IP, exit the script
    if ($ipAddress -ne $serverIP) {
        Write-Error "IP Address $ipAddress does not match Server IP $serverIP. Exiting script."
        exit
    }
    $prefixLength = $networkConfig.PrefixLength
    $gatewayAddress = $gateway.NextHop
    $dnsAddresses = $dnsServers.ServerAddresses

    $content = "vlan = $VLANID`ngateway = $gatewayAddress`nprefix = $prefixLength`ndns1 = $($dnsAddresses[0])`ndns2 = $($dnsAddresses[1])`ndns3 = $($dnsAddresses[2])`n$serverName = $serverIP`n"

    if (Test-Path -Path $filepath) {
        Remove-Item -Path $filepath -Force
    }

    Add-Content -Path $filepath -Value $content -Force
}

# Write the network information to a file
Write-Output "Network Information file created: $filePath"
$destinationPath = Join-Path -Path $destinationFolderPath -ChildPath "scripts\vm-network-details.txt"
Copy-Item -Path $filePath -Destination $destinationPath

$serverInfo = Invoke-Command -Session $session -ScriptBlock {
    # Get the operating system name
    $osName = (Get-CimInstance -ClassName CIM_OperatingSystem).Caption

    # Get the number of disks
    $diskCount = (Get-CimInstance -ClassName CIM_DiskDrive).Count

    # Return the OS name and disk count
    return @{
        OSName    = $osName
        DiskCount = $diskCount
    }
}

# Extract the OS name and disk count from the result
$osName = $serverInfo.OSName
$diskCount = $serverInfo.DiskCount
Add-Content -Path $logPath -Value $osName
Add-Content -Path $logPath -Value "VMware Disks: $diskCount"

# Write to the server's event log
$eventLogParams = @{
    LogName   = 'Application' # or any other log name
    Source    = 'Azure Migrate PreCheck' # the source of the event
    EntryType = 'Warning' # or 'Error', 'Warning', 'SuccessAudit', 'FailureAudit'
    EventId   = 1916 # a unique identifier for the event
    Message   = "Azure Migrate PreCheck was completed by $($currentUser)"  # the message to write to the event log
}

Invoke-Command -Session $session -ScriptBlock $eventLogBlock

Remove-PSSession -Session $session

disconnect-viserver -confirm:$false


$currentStep++
Write-Progress -Activity "Running SQL Specific Steps" -Status "Step 4:Creating 4K SQL Server disks..." -PercentComplete (($currentStep / $totalSteps) * 100)


if ($SQL) {
    write-Output "SQL Server specific steps will be executed because the SQL parameter was specified."
    $4kscriptblock = {

        $clusterStoragePath = "C:\ClusterStorage"

        $firstFolder = Get-ChildItem -Path $clusterStoragePath | Select-Object -First 1

        function Get-RandomNumber {
            return Get-Random -Minimum 1 -Maximum 5
        }

        $storagenumber = Get-RandomNumber
        $folder = "UserStorage_" + $storagenumber

        # Change directory to the selected folder
        if ($folder) {
            $UserFolder = Join-Path -Path $clusterStoragePath -ChildPath $folder

        }

        if ($Userfolder) {

            $firstFolder = Get-ChildItem -Path $UserFolder | Select-Object -First 1
            $DiskPath = Join-Path -Path $UserFolder -ChildPath $firstFolder

        }

        # Prompt for disk size

        $diskpath = $diskpath.ToString()
        $diskPath = $diskpath + "\" + "$args" + "-4k-SQL-Disk1.vhdx"
        return $DiskPath
    }

    if ($datacenter -eq "BDC") {
        Add-Content -Path $logPath -Value "Creating 4K SQL disk on BDC cluster."
        $clustersession = New-PSSession -ComputerName $BDCcluster
    }
    else {
        Add-Content -Path $logPath -Value "Creating 4K SQL disk on RDC cluster."
        $clustersession = New-PSSession -ComputerName $RDCcluster
    }

    $diskpath = Invoke-Command -Session $clustersession -ArgumentList $serverName -ScriptBlock $4kscriptblock


    Add-Content -Path $logPath -Value "Disk will be created at the following location: $diskPath"


    $currentStep++
    Write-Progress -Activity "Running SQL Specific Steps: Disk Operations" -Status "Step 4:Confirming creation of disks..." -PercentComplete (($currentStep / $totalSteps) * 100)

    Write-Output "Press Y to create new 4K VHDX at path $diskPath with size $diskSizeString"
    $confirmation = Read-Host "Confirm disk creation (Y/N)"
    if ($confirmation -ieq "Y") {
        # Proceed with disk creation
        Write-Output "Disk creation confirmed."
        # Create new fixed VHD
        if ($debug -eq $true) {
            Write-Warning "This would create $diskPath with size $diskSizeString but the -whatIf parameter was used."
        }
        else {

            Invoke-Command -Session $clustersession -ScriptBlock {
                New-VHD -Path $using:diskPath -LogicalSectorSizeBytes 4KB -SizeBytes ($using:diskSize * 1GB) -Dynamic -Verbose
            }
        }

    }
    else {
        Write-Output "Disk creation cancelled."
    }


}

function GetVMStatus {
    param (
        [string]$serverName
    )

    # Initialize vmStatus
    $vmStatus = "OFFLINE"

    # Test the network connection
    $connectionTest = Test-Connection -ComputerName $serverName -Count 1 -Quiet

    if ($connectionTest) {
        $vmStatus = "ONLINE"
    }

    return $vmStatus
}


function SendEmailToTeams {
    param (
        [string]$logPath,
        [string]$serverName
    )

    # Define email parameters
    $emailParams = @{
        From       = "AzureMigrateScript@DOMAIN.com"  # replace with your sender email address
        To         = "###.DOMAIN.onmicrosoft.com@amer.teams.ms"
        Subject    = "Azure Stack Migration started for $serverName"
        Body       = (Get-Content -Path $logPath) -join "`n"
        SmtpServer = "smtp.DOMAIN.com"  # replace with your SMTP server address
    }

    # Send the email
    Send-MailMessage @emailParams

    # Log the action
    Add-Content -Value "Sent email to Teams for server: $serverName" -Path $logPath
}

SendEmailToTeams -logPath $logPath -serverName $serverName

function WaitForVMInCluster {
    param (
        [string]$serverName,
        [string]$stackCluster
    )

    # Import the FailoverClusters module
    Import-Module FailoverClusters

    # Get the current time
    $startTime = Get-Date

    # Wait for the VM to show up and be powered on
    while ($true) {
        # Get the cluster group corresponding to the VM
        $clusterGroup = Get-ClusterGroup -Cluster $stackCluster | Where-Object { $_.Name -eq $serverName }

        if ($null -ne $clusterGroup) {
            # Check if the VM is powered on
            if ($clusterGroup.State -eq 'Online') {
                Write-Output "VM named $serverName found and is powered on in cluster $stackCluster."
                Write-Output "Waiting 2 minutes for boot up before proceeding..."
                # Wait for 2 minutes
                Start-Sleep -Seconds 120
                break
            }
            else {
                Write-Output "VM named $serverName found but is not powered on in cluster $stackCluster. Waiting..."
            }
        }
        else {
            $vmStatus = GetVMStatus -serverName $serverName
            Write-Output "$serverName is $vmStatus. Waiting for VM named $serverName in cluster $stackCluster..."
        }
        # Calculate the elapsed time
        $elapsedTime = (Get-Date) - $startTime
        Write-Output "Time elapsed: $($elapsedTime.TotalMinutes.ToString('N2')) minutes"

        Start-Sleep -Seconds 30
    }
}

$currentStep++
Write-Progress -Activity "PAUSED:Refeshing every 30 seconds" -Status "Go to Azure Portal and initiate migration. Waiting for migration to complete..." -PercentComplete (($currentStep / $totalSteps) * 100)
WaitForVMInCluster -serverName $serverName -stackCluster $stackCluster


Remove-PSSession -Session $clustersession
Write-Output "PreCheck and migration completed. Continuing to next step..."


#### Add VHDX to VM
$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script: Disk Operations" -Status "Adding SCSI and Disk to $serverName.  This takes a few minutes..." -PercentComplete (($currentStep / $totalSteps) * 100)

function StartUpVM {
    param (
        [string]$serverName,
        [string]$clusterName
    )
    $ClusterNode = (Get-ClusterResource -Cluster $clusterName | Where-Object { $_.ResourceType -like "Virtual Machine" -and $_.OwnerGroup -eq "$serverName" }).OwnerNode

    hyper-v\Start-VM $serverName -ComputerName $ClusterNode -Confirm:$false

}

function ShutdownVM {
    param (
        [string]$serverName,
        [string]$clusterName
    )
    $ClusterNode = (Get-ClusterResource -Cluster $clusterName | Where-Object { $_.ResourceType -like "Virtual Machine" -and $_.OwnerGroup -eq "$serverName" }).OwnerNode

    hyper-v\Stop-VM $serverName -ComputerName $ClusterNode -Confirm:$false

}

function AddScsiAndHardDisk {
    param (
        [string]$serverName,
        [string]$clusterName,
        [string]$vhdPath
    )

    ShutdownVM -serverName $serverName -clusterName $clusterName

    # Wait for the server to shut down

    Start-Sleep -Seconds 20
    $ClusterNode = (Get-ClusterResource -Cluster $clusterName | Where-Object { $_.ResourceType -like "Virtual Machine" -and $_.OwnerGroup -ieq "$serverName" }).OwnerNode
    $cimSession = New-CimSession -ComputerName $ClusterNode


    # Add a new SCSI controller
    Add-VMScsiController -VMName $serverName -CimSession $cimSession

    # Add a new hard disk to the SCSI controller
    Add-VMHardDiskDrive -VMName $serverName -ControllerType SCSI -ControllerNumber 1 -Path $vhdPath -CimSession $cimSession
    Write-Output "Added 4K SQL disk to VM named $serverName."


    # Power on the VM
    StartUpVM -serverName $serverName -clusterName $clusterName
    Write-Output "Powered on VM named $serverName.  Wait for boot up..."
    # Wait for 2 minutes
    $currentStep++
    Write-Progress -Activity "Azure Migrate Helper Script: Boot Operations" -Status "Waiting for $serverName to boot..." -PercentComplete (($currentStep / $totalSteps) * 100)
    Start-Sleep -Seconds 120
    Write-Output "Wait for the VM to boot up and then use Hyper-V Console to connect to the VM with account created earlier"

}

AddScsiAndHardDisk -serverName $serverName -clusterName $stackCluster -vhdPath $diskPath


$currentStep++
Write-Progress -Activity "PAUSED: Azure Migrate Helper Script" -Status "Use Hyper-V console to connect to $serverName.  Waiting for input." -PercentComplete (($currentStep / $totalSteps) * 100)

do {
    Write-Output "Script paused.  Please connect to VM and setup disks as needed.  Once complete, return here and type Y to re-IP the server and bring it online."
    $proceed = Read-Host -Prompt "Proceed with re-IP and bring server online? (Y/N)"
} while ($proceed -ine "Y")

# Proceed with disk creation
Write-Output "Proceeding with re-IP and bringing server online."

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script" -Status "Trying to connect to offline VM via Hyper-V Direct and bring it online..." -PercentComplete (($currentStep / $totalSteps) * 100)

try {
    $Hashtable = Get-Content -Raw $filePath -ErrorAction Stop | ConvertFrom-StringData
}
catch {
    Add-Content -Path $logPath -Value "Error:"$_.Exception.Message
}


$UserName = $serverName + "\tempadmin"
$credential = New-Object System.Management.Automation.PsCredential("$UserName", $passwordcred.Password)

Start-Transcript -Path "$((Get-Location).Path)\update-vm-ips_$(Get-date -Format "yyyyMMdd-hhmmss").log" -NoClobber


#Check cluster exists
function CheckForCluster {
    param (
        [string]$Cluster,
        [string]$logPath
    )

    $CheckForCluster = Get-ClusterResource -Cluster $Cluster -ErrorAction Ignore
    if ($null -eq $CheckForCluster) {
        Add-Content -Path $logPath -Value  "No cluster found for name $Cluster, please check the spelling and rerun the script!"
        Exit
    }
}
CheckForCluster $stackCluster -logPath $logPath

#Filter out network variables from hash table
$VMNames = $Hashtable.GetEnumerator() | Where-Object { $_.Key -ne "vlan" -and $_.Key -ne "gateway" -and $_.Key -ne "prefix" -and $_.Key -notlike 'dns*' }
foreach ($VMName in $VMNames.name) {
    #Check VMName exists
    $CheckForVM = Get-ClusterResource -Cluster $stackCluster | Where-Object { $_.ResourceType -like "Virtual Machine" -and $_.OwnerGroup -eq "$VMName" } -ErrorAction Ignore
    if ($CheckForVM) {
        Add-Content -Path $logPath -Value "Checking network settings for VM: $VMname"

        #Get the values in the hash table to pass on
        $PassIPAddress = $Hashtable.Get_item("$VMName")
        $PassGateway = $Hashtable.Get_item("gateway")
        $PassPrefix = $Hashtable.Get_item("prefix")
        $PassDNS1 = $Hashtable.Get_item("dns1")
        $PassDNS2 = $Hashtable.Get_item("dns2")
        $PassDNS3 = $Hashtable.Get_item("dns3")
        $PassVLAN = $Hashtable.Get_item("vlan")

        #Get  host name where VM is running
        $ClusterNode = (Get-ClusterResource -Cluster $stackCluster | Where-Object { $_.ResourceType -like "Virtual Machine" -and $_.OwnerGroup -eq "$VMName" }).OwnerNode

        #Connect to host where VM is running
        Invoke-Command -ComputerName $ClusterNode -ScriptBlock {

            #Get the values in the hash table to pass on
            $PassIPAddress = $args[0]
            $PassGateway = $args[1]
            $PassPrefix = $args[2]
            $PassDNS1 = $args[3]
            $PassDNS2 = $args[4]
            $PassDNS3 = $args[5]
            $VLAN = $args[6]
            $credential = $args[7]

            #Check and set the VLAN tag
            #Add-Content -Path $logPath -Value  "Checking VLAN against ID specified in config file: $VLAN"
            $VMAdapters = Get-VM -VMName $using:VMName | Get-VMNetworkAdapter
            $VMAdapterOperationMode = ($VMAdapters[0] | Get-VMNetworkAdapterVlan).OperationMode
            $VMAdapterVlan = ($VMAdapters[0] | Get-VMNetworkAdapterVlan).VlanList
            if ($VMAdapterOperationMode -eq "Untagged" -and $VLAN -eq '0') {
                #Add-Content -Path $logPath -Value  "VLAN is correctly untagged (0)"
            }
            else {
                if ($VLAN -eq '0') {
                    #Add-Content -Path $logPath -Value "Removing VLAN Tag as VLAN should be untagged (0)"
                    $VMAdapters[0] | Set-VMNetworkAdapterVlan -Untagged
                }
                elseif ($VMAdapterVlan -eq $VLAN) {
                    #Add-Content -Path $logPath -Value "VLAN is correct: $VLAN"
                }
                else {
                    #Add-Content -Path $logPath -Value "Setting correct VLAN Tag: $VLAN"
                    $VMAdapters[0] | Set-VMNetworkAdapterVlan -Access -VlanId $VLAN
                }
            }

            #Connect to VM
            Invoke-Command -VMName $using:VMName -Credential $using:credential -ScriptBlock {
                get-service -DisplayName SQL* | stop-service -force
                Get-disk | Where-Object PartitionStyle -ne 'raw' | Set-Disk -IsOffline:$false
                $newDisk = Get-Disk | Where-Object PartitionStyle -eq 'raw' | Initialize-Disk -PartitionStyle GPT -PassThru
                New-Partition -DiskNumber $newDisk.Number -UseMaximumSize -DriveLetter Q | Format-volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "SQL"
                function CheckForMountPoints {
                    param (
                        [string]$sourceDrive = 'S:\',
                        [string]$destinationDrive = 'Q:\'
                    )
                
                    # Check for mount points
                    $mountPoints = ((Get-CimInstance -classname win32_volume).name) | Where-Object { $_ -match "S:" } | Where-Object { $_.split("\").count -gt 2 }
                
                    if ($mountPoints) {
                        Write-Output "Mount points found on $sourceDrive. Using robocopy."
                
                        # Run the robocopy command
                        robocopy S:\ Q:\ /mir /e /copy:DTSO /XD /TEE "$RECYCLE.BIN" "System Volume Information" /XF DESKTOP.INI /mt:16 /R:0 /log+:C:\temp\robocopy.log
                        $mountPoints = ((Get-CimInstance -classname win32_volume).name) | Where-Object { $_ -match "S:" -and $_.split("\").count -gt 2 }
                        foreach ($mountPoint in $mountPoints) {
                            attrib -h -s $mountPoint.replace("S:", "Q:").substring(0, $mountpoint.length - 1)
                        }
                        return
                    }
                    else {
                        Write-Output "No mount points found on $sourceDrive."
                        return
                    }
                }
                CheckForMountPoints
                
                function ChangeDriveLetter {
                    param (
                        [string]$newDriveLetter = 'S:',
                        [string]$oldDriveLetter = 'Q:'
                    )
                
                    # Get the disk numbers of all mount points on S: drive
                    $drivesToOffline = (get-partition | Where-Object { $_.accesspaths -match "S:" })
                
                    # Get the partition of the old drive
                    $oldPartition = Get-Partition -DriveLetter $newDriveLetter.TrimEnd(':')
                    $oldPartition | Remove-PartitionAccessPath -AccessPath "$newDriveLetter\"
                    $newPartition = Get-Partition -DriveLetter $oldDriveLetter.TrimEnd(':')
    
                    # Change the drive letter of the old drive to the new drive letter
                    Set-Partition -InputObject $newPartition -NewDriveLetter $newDriveLetter.TrimEnd(':')
                    Write-Output "Drive letter of $oldDriveLetter has been changed to $newDriveLetter."
                
                    foreach ($drive in $drivesToOffline) {
                        Set-Disk -number $drive.disknumber -isoffline $true
                        Write-Output "Drive $($drive.accesspaths | Where-object {$_ -match "S:"}) is now offline."
                    }
                }
                
                ChangeDriveLetter
    

                #Get Adapter Index
                $vmlogpath = "c:\temp\update-vm-ips.log"
                #First check if there is a default gw configured and get the related Adapter index
                $CheckGW = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue
                if (!$CheckGW) {
                    $MgmtAdapterIndex = (Get-NetAdapter).ifIndex
                }
                else {
                    $MgmtAdapterIndex = (Get-NetRoute -DestinationPrefix 0.0.0.0/0).ifIndex
                }
                #Get network details
                $CurrentIPAddress = (Get-NetIPAddress -InterfaceIndex $MgmtAdapterIndex -AddressFamily IPv4).IPAddress
                $CorrectIPAddress = $args[0]
                $Gateway = $args[1]
                $Prefix = $args[2]
                $DNS1 = $args[3]
                $DNS2 = $args[4]
                $DNS3 = $args[5]
                #Check if IP is correct and set it if not
                if ($CurrentIPAddress -eq $CorrectIPAddress) {
                    Add-Content -Path $vmlogPath -Value  "IP Address is already correct: $CurrentIPAddress"
                }
                else {
                    try {
                        Add-Content -Path $vmlogPath -Value "Updating network settings to: $CorrectIPAddress, Gateway: $Gateway, Prefix: $Prefix, DNS Servers: $DNS1,$DNS2,$DNS3"
                        Remove-NetIPAddress -InterfaceIndex $MgmtAdapterIndex -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                        Remove-NetRoute -InterfaceIndex $MgmtAdapterIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                        New-NetIPAddress -InterfaceIndex $MgmtAdapterIndex -IPAddress $CorrectIPAddress -DefaultGateway $Gateway -PrefixLength $Prefix -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                        Get-DnsClientServerAddress | Set-DnsClientServerAddress -ResetServerAddresses -Confirm:$false | Out-Null
                        Set-DnsClientServerAddress -InterfaceIndex $MgmtAdapterIndex -ServerAddresses "$DNS1", "$DNS2", "$DNS3" -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                    }
                    catch { Add-Content -Path $vmlogPath -Value  -f Yellow "Error:"$_.Exception.Message }
                }

            } -ArgumentList $PassIPAddress, $PassGateway, $PassPrefix, $PassDNS1, $PassDNS2, $PassDNS3

        } -ArgumentList $PassIPAddress, $PassGateway, $PassPrefix, $PassDNS1, $PassDNS2, $PassDNS3, $PassVLAN, $credential
    }
    Else {
        Add-Content -Path $logPath -Value  "No VM found with name $VMname, please check the spelling and rerun the script!"
    }
}

Stop-transcript

function RemoveLocalAdmin {
    param (
        [string]$serverName,
        [string]$logPath
    )

    # Create a new PSSession
    try {
        $session = New-PSSession -ComputerName $serverName -ErrorAction Stop
    }
    catch {
        Write-Output "Failed to create PSSession to $serverName. Exiting function."
        Write-Warning "TEMPADMIN ACCOUNT NOT REMOVED! Please remove manually."
        return
    }

    # Define the script block
    $scriptBlock = {
        # Remove the local user
        Remove-LocalUser -Name "tempadmin"
    }

    # Invoke the command
    Invoke-Command -Session $session -ScriptBlock $scriptBlock

    # Log the removal of the local admin account
    Add-Content -Path $logPath -Value "Local admin account removed on $serverName."
    Write-Output "Local admin account removed on $serverName."

    # Close the PSSession
    Remove-PSSession -Session $session
}

RemoveLocalAdmin -serverName $fqdn -logPath $logPath

function Rename-VM {
    param (
        [string]$vCenter,
        [string]$serverName
    )

    # Connect to the vCenter server
    Connect-VIServer -Server $vCenter | Out-Null

    if ($null -ne $vm) {
        # Rename the VM
        $newName = "ONSTACK" + $serverName
        $vm | VMware.VimAutomation.Core\Get-NetworkAdapter | VMware.VimAutomation.Core\Set-NetworkAdapter -StartConnected:$false -Confirm:$false
        VMware.VimAutomation.Core\Set-VM -VM $vm -Name $newName -Confirm:$false
        Write-Output "Renamed VM to $newName."
    }
    else {
        Write-Output "VM named $serverName not found. Unable to rename."
    }
}
Rename-VM -vCenter $vCenter -serverName $serverName

$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script: Post Migration Checks" -Status "Setting SAN policy to online disks..." -PercentComplete (($currentStep / $totalSteps) * 100)

do {
    Write-Output "Script paused.  Server should be online and disks should be setup."
    $proceed = Read-Host -Prompt "Remove any offline disks from VM and type Y to proceed with reboot and disk checks. (Y/N)"
} while ($proceed -ine "Y")

function MakeSureDisksAreOnline {
    param (
        [string]$logPath,
        [string]$serverName
    )

    # Define the diskpart command to set the SAN policy to OnlineAll
    $diskPartCommand = @"
san policy=OnlineAll
exit
"@

    # Remotely execute the diskpart command
    Invoke-Command -ComputerName $serverName -ScriptBlock {
        $diskPartCommand = $using:diskPartCommand
        $diskPartCommand | diskpart
    }
    # Log the action
    Add-Content -Path $logPath -Value "Made sure all disks are online on server: $serverName"
}

# Call the function
MakeSureDisksAreOnline -logPath $logPath -serverName $serverName

function Restart-Server {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [string]$logPath,
        [string]$serverName
    )

    if ($PSCmdlet.ShouldProcess("Reboot the server $serverName")) {
        # Remotely reboot the server
        Restart-Computer -ComputerName $serverName -Force
        Start-Sleep -Seconds 30
        # Log the action
        Add-Content -Path $logPath -Value "Remotely rebooted server: $serverName"
    }
    else {
        Write-Output "Reboot cancelled by user."
    }
}
# Call the function
Restart-Server -logPath $logPath -serverName $serverName
Start-Sleep -Seconds 30
$currentStep++
Write-Progress -Activity "Running Azure Migrate Helper Script: Post Migration Checks" -Status "Rebooting $serverName and checking disks..." -PercentComplete (($currentStep / $totalSteps) * 100)

function ConfirmDisksCameOnline {
    param (
        [string]$logPath,
        [string]$serverName
    )

    # Wait for the server to be network available
    while (-not (Test-Connection -ComputerName $serverName -Count 1 -Quiet)) {
        Start-Sleep -Seconds 10
    }

    # Remotely check for any offline disks
    $offlineDisks = Invoke-Command -ComputerName $serverName -ScriptBlock {
        Get-Disk | Where-Object { $_.OperationalStatus -eq 'Offline' } | Select-Object Number, Size, PartitionStyle
    }

    # If there are any offline disks, report them as a warning
    if ($offlineDisks) {
        $offlineDisks | ForEach-Object {
            Write-Warning "Disk $($_.Number) is offline on server $serverName."
            Add-Content -Path $logPath -Value "Disk $($_.Number) is offline on server $serverName."
        }
    }
    else {
        Add-Content -Path $logPath -Value "All disks are online on server $serverName."
    }
}

# Call the function
ConfirmDisksCameOnline -logPath $logPath -serverName $serverName
Add-Content -Path $logPath -Value "Migration completed. Log file created at $logPath."
Write-Output "Migration completed. Log file created at $logPath."
