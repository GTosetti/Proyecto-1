<#
    04-process-tree-generate.ps1
    ---------------------------------------------------------------------------
    WHAT IT DOES
      Launches ONE known process tree, carrying a unique marker string in the
      command line of the cmd.exe and powershell.exe links, and writes the exact
      UTC window to a JSON file so the collector scripts know what to look for.

      The leaf is the exception and it matters: whoami.exe is launched with no
      arguments, because whoami takes none that would carry a marker. So the
      process the exercise cares about most is the one the marker search will
      not return. Find it by image name inside the recorded window - which is
      what 06-collect-evidence.ps1 does, with `-match 'whoami\.exe'` alongside
      the marker match. Changing the leaf to something that could carry the
      marker would change the telemetry the published counts describe, so it
      has been left alone and documented instead.

    WHY IT EXISTS
      The point of the exercise is to take a single, fully understood event and
      chase it through three sources that all claim to describe it:

          1. Security Event ID 4688   (Windows audit)
          2. Sysmon Event ID 1        (Sysinternals)
          3. The alert the SIEM does - or does not - produce

      They do not say the same thing. Finding out which field each source
      contributes, and which ones it silently lacks, is the whole exercise. Two
      results from running it in this lab: `ProcessId` means the CREATED process
      in Sysmon (decimal) and the PARENT in 4688 (hexadecimal), so correlating
      on the shared field name inverts the tree; and 16 of 16 process-creation
      events alerted through a catch-all rule while only 1 of 11 Sysmon events
      did - and that one fired on a parent/child PATTERN, not on process
      creation.

    WHY THE MARKER
      Searching a SIEM for "powershell.exe" returns hundreds of results.
      Searching for a marker that exists nowhere else returns exactly yours.
      Note that a free-text search may still fail: in this lab a query_string
      search for the marker returned 0 results while the string sat in
      data.win.eventdata.commandLine. Target the field directly.

    RUN WITHOUT ELEVATION, as an ordinary user. That is deliberate: the process
    then carries Medium integrity and a real user account, which is the normal
    case and the one worth learning to read.

      powershell -ExecutionPolicy Bypass -File .\04-process-tree-generate.ps1

    No credential appears in this file.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $LabDir      = 'C:\lab',
    [string] $ChildScript = '',          # defaults to <LabDir>\05-process-tree-child.ps1

    # Where the child opens a TCP connection, to produce a Sysmon network event.
    # Lab default is the SIEM's dashboard port; any reachable host works.
    [string] $TcpTarget   = '10.10.10.10',
    [int]    $TcpPort     = 443,

    # A name under a domain the IANA reserves for documentation, so the query
    # cannot accidentally reach anyone's infrastructure.
    [string] $DnsName     = 'labmarker.example.com'
)

$ErrorActionPreference = 'Continue'

if (-not $ChildScript) { $ChildScript = Join-Path $LabDir '05-process-tree-child.ps1' }
if (-not (Test-Path $ChildScript)) { throw "Child script not found: $ChildScript" }

# --- The marker ------------------------------------------------------------
$marker = 'LABMARK' + (Get-Date -Format 'yyyyMMddHHmmss')

# --- Time window -----------------------------------------------------------
# Recorded in UTC because the SIEM indexes in UTC while Windows displays local
# time. Also worth knowing before you query: the manager's own @timestamp ran
# about 1.8 s behind the endpoint in this lab, so filter on the endpoint's
# systemTime field, not on the index's default time axis.
$startLocal = Get-Date
$startUtc   = $startLocal.ToUniversalTime()

Write-Host "=============================================================="
Write-Host " Process tree generator"
Write-Host "=============================================================="
Write-Host " Marker    : $marker"
Write-Host " Start UTC : $($startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Host " User      : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host ""

# --- The tree --------------------------------------------------------------
#  powershell.exe (this script)
#     |__ cmd.exe                      <- the classic intermediate link
#           |__ powershell.exe         <- runs the child script
#                 |__ DNS query        -> Sysmon 22
#                 |__ TCP connection   -> Sysmon 3
#                 |__ whoami.exe       -> Sysmon 1 + Security 4688
#
#  The SHAPE imitates a real intrusion (a parent spawns cmd, cmd spawns
#  powershell, powershell talks to the network) while doing nothing harmful.

$cmdArgs = "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ChildScript $marker $TcpTarget $TcpPort $DnsName"

Write-Host " Launching: cmd.exe $cmdArgs"
$p = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
                   -ArgumentList $cmdArgs `
                   -Wait -PassThru -WindowStyle Hidden
Write-Host " cmd.exe exited with code $($p.ExitCode)"

# Sysmon writes network (3) and DNS (22) events to the channel several seconds
# after they occur - 3.2 s and 4.0 s respectively when measured here. Without
# this pause the collector runs before they exist.
Start-Sleep -Seconds 5

$endUtc = (Get-Date).ToUniversalTime()

# --- Run record ------------------------------------------------------------
# Written to disk so the collector knows what to search for, and so the window
# is recorded. Without a recorded window you cannot search a SIEM honestly:
# widening or narrowing the range after the fact is how false coverage gaps get
# reported.
$record = [ordered]@{
    marker      = $marker
    start_utc   = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    end_utc     = $endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    start_local = $startLocal.ToString('yyyy-MM-dd HH:mm:ss')
    computer    = $env:COMPUTERNAME
    user        = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    dns_name    = $DnsName
    tcp_target  = "$TcpTarget`:$TcpPort"
}
$recordPath = Join-Path $LabDir 'process-tree-run.json'
$record | ConvertTo-Json | Set-Content -Path $recordPath -Encoding UTF8

Write-Host ""
Write-Host " End UTC   : $($endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Host " Record    : $recordPath"
Write-Host ""
Write-Host " WHAT TO LOOK FOR NOW"
Write-Host " ----------------------------------------------------------"
Write-Host " Security 4688   CommandLine        contains $marker"
Write-Host "                 (Wazuh: data.win.eventdata.commandLine - 4688 has no"
Write-Host "                  field called ProcessCommandLine)"
Write-Host " Sysmon   1      CommandLine        contains $marker"
Write-Host " Security 4688   NewProcessName     ends with whoami.exe   <- the leaf"
Write-Host "                 carries no marker; it is launched with no arguments"
Write-Host " Sysmon   22     QueryName          = $DnsName"
Write-Host " Sysmon   3      DestinationIp      = $TcpTarget port $TcpPort"
Write-Host " SIEM            search the UTC window above, on the endpoint's"
Write-Host "                 own timestamp field - not the index default"
Write-Host "=============================================================="
Write-Host ""
Write-Host " If you see TWO powershell.exe where you expected one, and this was"
Write-Host " launched through VBoxManage guestcontrol run --, that is the known"
Write-Host " argv[0] duplication, not a finding. See lab/README.md."
