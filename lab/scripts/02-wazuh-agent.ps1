<#
    02-wazuh-agent.ps1
    ---------------------------------------------------------------------------
    WHAT IT DOES
      Installs the Wazuh agent on the endpoint, enrols it against the manager,
      and adds the two event channels the agent does NOT collect by default:
      Sysmon and PowerShell.

    WHY IT EXISTS
      This is the "collect" layer of the generate / collect / detect model. Two
      things go wrong here for almost everyone:

      1. The agent is installed before the manager exists, so enrolment has
         nowhere to go, the agent sits in 'pending', and hours are spent
         debugging the agent when the real problem is that the server was never
         built. Run this AFTER the manager is up and answering on 1514/1515 -
         which is why step 1 below is a reachability test, not a courtesy.

      2. The agent collects Application, Security and System out of the box.
         Sysmon and PowerShell/Operational have to be requested explicitly. Skip
         step 3 and you get a SIEM that cannot show you a process tree.

    RUN AS ADMINISTRATOR on the endpoint, after 01-endpoint-telemetry.ps1:
      powershell -ExecutionPolicy Bypass -File .\02-wazuh-agent.ps1 -ManagerIp <IP>

    WATCH THE MSI URL. Wazuh's download paths follow OPPOSITE conventions for
    the two artefacts. Verified 2026-08-07:
        https://packages.wazuh.com/4.x/windows/wazuh-agent-<ver>.msi   -> 200 OK
        https://packages.wazuh.com/4.14/windows/wazuh-agent-<ver>.msi  -> 403
    For the MANAGER installer it is the other way round: 4.x/ returns 403 and
    the version-specific path is the one that works. Test the URL, do not deduce
    it from the other one.

    No credential appears in this file. Enrolment here uses the manager's
    default registration service on 1515; if your manager requires a
    pre-shared key, pass it in at run time and do not commit it.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    # Address of the Wazuh manager. Lab default shown; override for your own.
    [string] $ManagerIp = '10.10.10.10',

    # Name this agent registers under, as it will appear in the dashboard.
    [string] $AgentName = $env:COMPUTERNAME,

    [string] $MsiUrl    = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi',

    # Channels the agent does not collect unless told to.
    [string[]] $ExtraChannels = @(
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-PowerShell/Operational'
    ),

    [string] $AgentDir = 'C:\Program Files (x86)\ossec-agent'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Write-Step($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Write-Ok($t)   { Write-Host "  [ok] $t"    -ForegroundColor Green }
function Write-Warn($t) { Write-Host "  [!]  $t"    -ForegroundColor Yellow }

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run as Administrator.'
}

# ===========================================================================
# 1 - Can we actually reach the manager?
# ===========================================================================
# 1514 = where the agent sends events. 1515 = where it enrols the first time.
# Testing both before installing turns "the agent is broken" into "the server
# is not up", which is a completely different afternoon.
Write-Step "1/5  Connectivity to the manager $ManagerIp"

foreach ($port in 1514, 1515) {
    $r = Test-NetConnection -ComputerName $ManagerIp -Port $port -WarningAction SilentlyContinue
    if ($r.TcpTestSucceeded) {
        Write-Ok "$ManagerIp`:$port answers"
    } else {
        throw "$ManagerIp`:$port does NOT answer. Start the SIEM VM before continuing."
    }
}

# ===========================================================================
# 2 - Install
# ===========================================================================
Write-Step '2/5  Installing the agent'

$msi = Join-Path $env:TEMP 'wazuh-agent.msi'
Invoke-WebRequest -Uri $MsiUrl -OutFile $msi -UseBasicParsing
Write-Ok "MSI downloaded ($([math]::Round((Get-Item $msi).Length / 1MB, 1)) MB)"

$msiArgs = "/i `"$msi`" /q " +
           "WAZUH_MANAGER=$ManagerIp " +
           "WAZUH_REGISTRATION_SERVER=$ManagerIp " +
           "WAZUH_AGENT_NAME=$AgentName"

$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "msiexec returned $($p.ExitCode)" }
Write-Ok 'Agent installed and enrolled'

# ===========================================================================
# 3 - Collect Sysmon and PowerShell
# ===========================================================================
Write-Step '3/5  ossec.conf: add the Sysmon and PowerShell channels'

$conf = Join-Path $AgentDir 'ossec.conf'
if (-not (Test-Path $conf)) { throw "Cannot find $conf" }

Copy-Item $conf "$conf.bak" -Force
Write-Ok "Backup written to $conf.bak"

$content = Get-Content $conf -Raw
$blocks  = ''

foreach ($channel in $ExtraChannels) {
    if ($content -like "*$channel*") {
        Write-Warn "$channel was already in ossec.conf"
    } else {
        $blocks += "`n  <localfile>`n    <location>$channel</location>`n    <log_format>eventchannel</log_format>`n  </localfile>`n"
        Write-Ok "$channel added"
    }
}

if ($blocks -ne '') {
    # Inserted immediately before the final </ossec_config>.
    $idx = $content.LastIndexOf('</ossec_config>')
    if ($idx -lt 0) { throw 'ossec.conf has no </ossec_config>. Inspect it by hand.' }
    $new = $content.Substring(0, $idx) + $blocks + $content.Substring($idx)
    Set-Content -Path $conf -Value $new -Encoding UTF8
}

# ===========================================================================
# 4 - Start the service
# ===========================================================================
Write-Step '4/5  Starting the service'

Restart-Service -Name 'WazuhSvc' -Force -ErrorAction SilentlyContinue
Set-Service    -Name 'WazuhSvc' -StartupType Automatic
Start-Service  -Name 'WazuhSvc' -ErrorAction SilentlyContinue
Start-Sleep -Seconds 10
Write-Ok "Service state: $((Get-Service WazuhSvc).Status)"

# ===========================================================================
# 5 - Verification
# ===========================================================================
Write-Step '5/5  Verification'

$stateFile = Join-Path $AgentDir 'wazuh-agent.state'
if (Test-Path $stateFile) {
    Write-Host "`n-- wazuh-agent.state --" -ForegroundColor White
    Get-Content $stateFile
} else {
    Write-Warn 'No wazuh-agent.state yet. Wait a few seconds and look again.'
}

Write-Host "`n-- Tail of ossec.log --" -ForegroundColor White
Get-Content (Join-Path $AgentDir 'ossec.log') -Tail 20

Write-Host @"

WHAT A HEALTHY AGENT LOOKS LIKE
  - wazuh-agent.state  ->  status='connected'
  - ossec.log          ->  "Connected to the server"
  - dashboard          ->  Agents -> this host, state Active

IF IT SAYS 'disconnected' OR STAYS 'pending'
  1. Confirm the SIEM VM is running and 1514/1515 answer (step 1 above).
  2. On the manager:  sudo tail -f /var/ossec/logs/ossec.log
  3. Fallback: dashboard -> Agents -> Deploy new agent, which generates the
     enrolment command with the key already embedded.

READING THESE FILES FROM THE HOST
  Anything under the agent directory needs administrator rights, so
  `VBoxManage guestcontrol copyfrom` returns Access denied. Copy the files to a
  world-readable directory (e.g. C:\lab) from an elevated session first. Also
  note that `cmd /c type` breaks on paths containing spaces - use the 8.3 form.

Next: 03-generate-known-events.ps1
"@ -ForegroundColor Cyan
