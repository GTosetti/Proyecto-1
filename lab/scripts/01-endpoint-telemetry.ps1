<#
    01-endpoint-telemetry.ps1
    ---------------------------------------------------------------------------
    WHAT IT DOES
      Turns a freshly installed Windows 11 endpoint into something worth
      collecting logs from. Out of the box Windows records almost nothing a SOC
      can use: no command line inside Event ID 4688, no PowerShell script
      blocks, and a 20 MB Security channel that wraps within hours once Sysmon
      is running.

    WHY IT EXISTS
      Telemetry has to be configured BEFORE the agent is installed. An agent
      deployed onto an unconfigured endpoint ships an empty stream very
      reliably: the SIEM looks healthy and contains nothing readable. This
      script is the "generation" layer of the generate / collect / detect model
      used throughout this repository.

    ORDER OF OPERATIONS
      1. Static IP and Private network profile
      2. Advanced audit policy (10 subcategories)
      3. Command line inside 4688 + PowerShell 4103/4104 logging
      4. Event log channel size raised to 256 MB
      5. Firewall: inbound ICMP, SMB and RDP (deliberate - see note)
      6. Sysmon with the SwiftOnSecurity configuration
      7. Verification of its own work

    RUN AS ADMINISTRATOR, once, on the endpoint:
      powershell -ExecutionPolicy Bypass -File .\01-endpoint-telemetry.ps1

    DO NOT wrap this script in `*>&1 | Tee-Object`. Under PowerShell 5.1 that
    converts a native executable's stderr into an ErrorRecord; combined with
    $ErrorActionPreference = 'Stop' it aborted this script at step 6 during the
    original build - steps 1-5 applied and Sysmon was never installed, with no
    obvious error. Use Start-Transcript if you need a log of the run.

    NOTE ON THE FIREWALL RULES
      Opening 445 and 3389 inbound is not "turning off security". A real
      corporate endpoint has both open to the internal network. Closed, there is
      no logon type 3 and no logon type 10, and most of the detection exercises
      in this repository cannot be run at all.

    NOTE ON LANGUAGE
      auditpol addresses subcategories by their LOCALISED display name. The
      names below are the English ones, which is why this lab installs Windows
      in English. On a non-English install this step fails silently per item.

    No credential appears in this file.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    # Lab defaults. Override for a different segment.
    [string]   $IpAddress  = '10.10.10.20',
    [string]   $Gateway    = '10.10.10.1',
    [string[]] $DnsServers = @('8.8.8.8', '1.1.1.1'),

    # 256 MB. The Security channel defaults to 20 MB.
    [int]      $ChannelSizeBytes = 268435456,

    [string]   $SysmonDir  = 'C:\Sysmon',
    [string]   $SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',

    [switch]   $SkipNetwork,
    [switch]   $SkipRdp
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest is far faster without the progress bar

function Write-Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Write-Ok($text)   { Write-Host "  [ok] $text"    -ForegroundColor Green }
function Write-Warn($text) { Write-Host "  [!]  $text"    -ForegroundColor Yellow }

# --- Privilege check -------------------------------------------------------
# Note: a process launched through `VBoxManage guestcontrol run` will FAIL this
# check even when the account is in Administrators, because UAC hands it a
# filtered token (Medium Mandatory Level). That is expected; run this from an
# elevated interactive session.
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run as Administrator.'
}

# ===========================================================================
# 1 - Network
# ===========================================================================
if (-not $SkipNetwork) {
    Write-Step "1/7  Network: static $IpAddress"

    $adapter = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    if ($null -eq $adapter) { throw 'No active network adapter found. Check the VM NIC.' }

    $alreadySet = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.IPAddress -eq $IpAddress }

    if ($null -eq $alreadySet) {
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' `
            -Confirm:$false -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Dhcp Disabled
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $IpAddress -PrefixLength 24 `
            -DefaultGateway $Gateway | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DnsServers
        Write-Ok "$IpAddress/24 - gw $Gateway - dns $($DnsServers -join ', ')"
    } else {
        Write-Ok "Already had $IpAddress, left alone"
    }

    # Private profile matters: under the Public profile the firewall blocks
    # discovery and the rules set in step 5 do not apply.
    Set-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -NetworkCategory Private -ErrorAction SilentlyContinue
    Write-Ok 'Network profile = Private'
} else {
    Write-Warn 'Network step skipped (-SkipNetwork)'
}

# ===========================================================================
# 2 - Advanced audit policy
# ===========================================================================
Write-Step '2/7  Advanced audit policy'

$auditSubcategories = @(
    @{ Name = 'Process Creation';          Success = 'enable'; Failure = 'enable'  }  # 4688
    @{ Name = 'Process Termination';       Success = 'enable'; Failure = 'disable' }  # 4689
    @{ Name = 'Logon';                     Success = 'enable'; Failure = 'enable'  }  # 4624 / 4625
    @{ Name = 'Logoff';                    Success = 'enable'; Failure = 'disable' }  # 4634 / 4647
    @{ Name = 'Special Logon';             Success = 'enable'; Failure = 'enable'  }  # 4672
    @{ Name = 'Account Lockout';           Success = 'enable'; Failure = 'enable'  }  # 4740
    @{ Name = 'User Account Management';   Success = 'enable'; Failure = 'enable'  }  # 4720 / 4726 / 4738
    @{ Name = 'Security Group Management'; Success = 'enable'; Failure = 'enable'  }  # 4732 / 4733
    @{ Name = 'Audit Policy Change';       Success = 'enable'; Failure = 'enable'  }  # 4719
    @{ Name = 'Security System Extension'; Success = 'enable'; Failure = 'enable'  }  # 4697 (service installed)
)

foreach ($sub in $auditSubcategories) {
    $out = auditpol /set /subcategory:"$($sub.Name)" /success:$($sub.Success) /failure:$($sub.Failure) 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Ok $sub.Name } else { Write-Warn "$($sub.Name) -> $out" }
}

# ===========================================================================
# 3 - Command line in 4688, and PowerShell logging
# ===========================================================================
Write-Step '3/7  Command line in 4688 and PowerShell logging'

# Without this, a 4688 tells you "powershell.exe started" and nothing else.
# With it, it tells you exactly what was run. Highest value-per-byte registry
# setting on a Windows endpoint for detection purposes.
$key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
Write-Ok '4688 now includes the command line'

# Script Block Logging -> Microsoft-Windows-PowerShell/Operational, Event ID 4104.
# Records the code that ACTUALLY executed, already de-obfuscated. This is what
# exposes -EncodedCommand / FromBase64String one-liners.
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'EnableScriptBlockLogging' -Value 1 -PropertyType DWord -Force | Out-Null
Write-Ok 'Script Block Logging (4104)'

# Module Logging -> Event ID 4103: every command with its parameters.
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'EnableModuleLogging' -Value 1 -PropertyType DWord -Force | Out-Null
New-Item -Path "$key\ModuleNames" -Force | Out-Null
New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
Write-Ok 'Module Logging (4103)'

# ===========================================================================
# 4 - Event log channel size
# ===========================================================================
# The Security channel defaults to 20 MB. In a lab with Sysmon running that
# wraps within hours, and the evidence disappears on exactly the day you need it.
Write-Step "4/7  Event log channel size -> $ChannelSizeBytes bytes"

$channels = @(
    'Security',
    'System',
    'Application',
    'Microsoft-Windows-PowerShell/Operational'
)
foreach ($channel in $channels) {
    wevtutil sl "$channel" /ms:$ChannelSizeBytes 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "$channel resized" } else { Write-Warn "$channel could not be resized" }
}

# ===========================================================================
# 5 - Firewall and RDP
# ===========================================================================
Write-Step '5/7  Lab firewall rules'

# -Name is language independent; -DisplayGroup is not (this lab runs Windows in English).
Enable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction SilentlyContinue
Write-Ok 'Inbound ICMP echo (so ping from the attacker VM answers)'

Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue
Write-Ok 'Inbound SMB (445) -> enables logon type 3 from the attacker VM'

if (-not $SkipRdp) {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
        -Name 'fDenyTSConnections' -Value 0
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
    Write-Ok 'Inbound RDP (3389) -> enables logon type 10'
    Write-Warn 'RDP server requires Windows 11 PRO. On Home this step does nothing.'
} else {
    Write-Warn 'RDP skipped (-SkipRdp)'
}

# ===========================================================================
# 6 - Sysmon
# ===========================================================================
# Sysmon is installed IN ADDITION TO native auditing, not instead of it.
# Measured on the same process event in this lab: Security 4688 has no
# ParentCommandLine, no hashes, no OriginalFileName, no file metadata, no
# CurrentDirectory and no stable process identifier - Sysmon Event ID 1 has all
# of them. Conversely 4688 uniquely carries TokenElevationType. Neither source
# is a superset of the other.
Write-Step '6/7  Sysmon + SwiftOnSecurity configuration'

New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null

Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' `
    -OutFile "$SysmonDir\Sysmon.zip" -UseBasicParsing
Expand-Archive -Path "$SysmonDir\Sysmon.zip" -DestinationPath $SysmonDir -Force
Write-Ok 'Sysmon downloaded'

Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile "$SysmonDir\sysmonconfig.xml" -UseBasicParsing
Write-Ok 'SwiftOnSecurity configuration downloaded'

$svc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if ($null -eq $svc) { $svc = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue }

if ($null -eq $svc) {
    & "$SysmonDir\Sysmon64.exe" -accepteula -i "$SysmonDir\sysmonconfig.xml"
    Write-Ok 'Sysmon installed'
} else {
    & "$SysmonDir\Sysmon64.exe" -c "$SysmonDir\sysmonconfig.xml"
    Write-Ok 'Sysmon already present: configuration updated only'
}

wevtutil sl 'Microsoft-Windows-Sysmon/Operational' /ms:$ChannelSizeBytes 2>&1 | Out-Null
Write-Ok 'Sysmon channel resized'

# ===========================================================================
# 7 - Verification
# ===========================================================================
# Verify the END STATE, never the fact that the script appeared to run. A
# partially applied telemetry baseline is worse than none, because you then
# believe Sysmon is running when it is not.
Write-Step '7/7  Verification'

Write-Host "`n-- Effective audit policy --" -ForegroundColor White
auditpol /get /category:* | Select-String -Pattern 'Process Creation|Logon|Logoff|Special Logon|Account Lockout'

Write-Host "`n-- Registry values --" -ForegroundColor White
[PSCustomObject]@{
    'CmdLine in 4688'    = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    'ScriptBlockLogging' = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging
    'ModuleLogging'      = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -EA SilentlyContinue).EnableModuleLogging
} | Format-List

Write-Host "-- Sysmon service --" -ForegroundColor White
Get-Service -Name 'Sysmon*' | Format-Table Name, Status, StartType -AutoSize

Write-Host "-- Last 5 Sysmon events --" -ForegroundColor White
try {
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 |
        Format-Table TimeCreated, Id, @{n='Message';e={($_.Message -split "`n")[0]}} -AutoSize
} catch {
    Write-Warn 'Sysmon has not written anything yet. Open an application and look again.'
}

Write-Host "`nDone. Next: 02-wazuh-agent.ps1" -ForegroundColor Cyan
