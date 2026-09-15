<#
    06-collect-evidence.ps1
    ---------------------------------------------------------------------------
    WHAT IT DOES
      Takes the process tree produced by 04-process-tree-generate.ps1 and pulls
      the SAME facts out of two independent sources on the endpoint, then prints
      them side by side:

          Security  4688   "A new process has been created"   (Windows audit)
          Sysmon       1   "Process Create"                   (Sysinternals)

      It also dumps Sysmon 3 (network connection) and 22 (DNS query), for which
      the Windows Security log has no equivalent at all, and finishes with a
      volume count.

      Output is written to a text file so it can be copied off the VM and
      attached to a writeup.

    WHY IT EXISTS
      "Deploy Sysmon" is advice everyone repeats and few justify. This script
      produces the justification as data: the field-by-field difference between
      the two sources for one identical event. What it showed in this lab:

        - 4688 has no ParentCommandLine, no hashes, no OriginalFileName, no file
          metadata, no CurrentDirectory and no stable process identifier.
        - Sysmon 1 has all of those, including a ProcessGuid that never recycles
          and is what ties a process to its own network and DNS events.
        - Without OriginalFileName, a renamed system binary cannot be detected
          from the Security log at all.
        - 4688 does uniquely carry TokenElevationType. Neither source is a
          superset of the other.
        - The field called ProcessId means opposite things in the two sources
          (created process vs parent) and in different number bases (decimal vs
          hexadecimal). Joining on the shared name inverts the tree silently.

    WHY IT READS XML AND NOT .Message
      Get-WinEvent hands you a nicely formatted Message string, but the
      structured FIELDS live in the event XML - and a SIEM ingests the XML, not
      the message. Reading the message teaches you to look for things a SIEM
      cannot search on.

    PREREQUISITE - and it needs a reboot
      Reading the Security and Sysmon channels requires the token to carry
      BUILTIN\Event Log Readers:

          net localgroup "Event Log Readers" <LAB_USER> /add

      run once from an ELEVATED terminal, AND THEN A REBOOT. Without the reboot
      the membership is in the SAM (Get-LocalGroupMember shows it) but not in
      the token, and reads keep failing with "Attempted to perform an
      unauthorized operation". This is group-membership caching, not UAC
      filtering - Event Log Readers survives a filtered token fine. Closing
      guest control sessions does not refresh it. The Sysmon channel already
      ships the matching ACE, so its SDDL needs no change.

    USAGE (on the endpoint):
      powershell -ExecutionPolicy Bypass -File .\06-collect-evidence.ps1

    No credential appears in this file.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $Marker  = '',
    [string] $LabDir  = 'C:\lab',
    [string] $OutFile = ''
)

$ErrorActionPreference = 'Continue'

if (-not $OutFile) { $OutFile = Join-Path $LabDir 'process-tree-evidence.txt' }
$recordPath = Join-Path $LabDir 'process-tree-run.json'

# --- Run record ------------------------------------------------------------
$record = $null
if (Test-Path $recordPath) {
    $record = Get-Content $recordPath -Raw | ConvertFrom-Json
    if (-not $Marker) { $Marker = $record.marker }
}
if (-not $Marker) { throw "No marker available. Run 04-process-tree-generate.ps1 first." }

# Two minutes of slack before the recorded start. Deliberate: in this lab an
# apparent coverage gap turned out to be a window-edge artefact - each remote
# invocation produced a PAIR of logon events and the pair was being cut in half
# by a tight boundary. Widen the window before declaring anything missing.
$since = if ($record) { [datetime]::Parse($record.start_local).AddMinutes(-2) } else { (Get-Date).AddHours(-1) }

$lines = New-Object System.Collections.Generic.List[string]
function W([string]$t = '') { $lines.Add($t) }

# --- Turn an event's XML into name = value pairs ---------------------------
function Get-EventFields($ev) {
    $x = [xml]$ev.ToXml()
    $h = [ordered]@{}
    foreach ($d in $x.Event.EventData.Data) {
        $n = $d.Name; if (-not $n) { $n = '(unnamed)' }
        $h[$n] = [string]$d.'#text'
    }
    return $h
}

function Write-EventDetail($title, $ev) {
    W "  --- $title ---"
    W "  TimeCreated (local) : $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
    W "  TimeCreated (UTC)   : $($ev.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
    W "  RecordId            : $($ev.RecordId)"
    W "  Provider            : $($ev.ProviderName)"
    W "  Level               : $($ev.LevelDisplayName)"
    W "  XML fields:"
    $fields = Get-EventFields $ev
    foreach ($k in $fields.Keys) { W ("    {0,-28} = {1}" -f $k, $fields[$k]) }
    W ""
    return $fields
}

W "=============================================================================="
W " PROCESS TREE - RAW EVIDENCE"
W " Marker     : $Marker"
if ($record) {
    W " UTC window : $($record.start_utc)  ->  $($record.end_utc)"
    W " Computer   : $($record.computer)   User: $($record.user)"
}
W " Collected  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (local)"
W "=============================================================================="
W ""

# ===========================================================================
#  1. SECURITY 4688
# ===========================================================================
W "##############################################################################"
W "# 1. WINDOWS SECURITY LOG - Event ID 4688 (A new process has been created)"
W "##############################################################################"
W ""

$sec4688 = @()
try {
    $sec4688 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$since} -ErrorAction Stop |
               Where-Object { $_.Message -match [regex]::Escape($Marker) -or $_.Message -match 'whoami\.exe' } |
               Sort-Object TimeCreated
} catch {
    W "  ERROR reading Security: $($_.Exception.Message)"
    W "  If this says 'unauthorized operation', see the Event Log Readers note in"
    W "  the header of this script - it needs a reboot, not just the group add."
}

W "  Found: $($sec4688.Count)"
W ""
$fields4688 = $null
foreach ($e in $sec4688) {
    $f = Write-EventDetail "4688  RecordId $($e.RecordId)" $e
    if (-not $fields4688 -and $f['NewProcessName'] -match 'powershell\.exe$') { $fields4688 = $f }
}

# ===========================================================================
#  2. SYSMON 1
# ===========================================================================
W "##############################################################################"
W "# 2. SYSMON CHANNEL - Event ID 1 (Process Create)"
W "##############################################################################"
W ""

$sys1 = @()
try {
    $sys1 = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$since} -ErrorAction Stop |
            Where-Object { $_.Message -match [regex]::Escape($Marker) -or $_.Message -match 'whoami\.exe' } |
            Sort-Object TimeCreated
} catch { W "  ERROR reading Sysmon: $($_.Exception.Message)" }

W "  Found: $($sys1.Count)"
W ""
$fieldsSys1 = $null
foreach ($e in $sys1) {
    $f = Write-EventDetail "Sysmon 1  RecordId $($e.RecordId)" $e
    if (-not $fieldsSys1 -and $f['Image'] -match 'powershell\.exe$') { $fieldsSys1 = $f }
}

# ===========================================================================
#  3. SYSMON 3 and 22 - what 4688 cannot tell you
# ===========================================================================
W "##############################################################################"
W "# 3. SYSMON 3 (network connection) and 22 (DNS query)"
W "#    The Windows Security log has NO equivalent for either."
W "#    Read the UtcTime FIELD of these two, not the channel's TimeCreated:"
W "#    they are written to the channel 3-4 s after they actually happen, and"
W "#    sorting by TimeCreated reverses cause and effect."
W "##############################################################################"
W ""

$dnsName   = if ($record) { $record.dns_name }   else { 'example.com' }
$tcpTarget = if ($record) { ($record.tcp_target -split ':')[0] } else { '' }

foreach ($id in 3, 22) {
    $events = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=$id; StartTime=$since} -ErrorAction Stop |
                  Where-Object {
                      ($dnsName   -and $_.Message -match [regex]::Escape($dnsName)) -or
                      ($tcpTarget -and $_.Message -match [regex]::Escape($tcpTarget))
                  } |
                  Sort-Object TimeCreated
    } catch { W "  ERROR Sysmon $id : $($_.Exception.Message)" }

    W "  Sysmon $id -> found: $($events.Count)"
    foreach ($e in $events) { [void](Write-EventDetail "Sysmon $id  RecordId $($e.RecordId)" $e) }
    W ""
}

# ===========================================================================
#  4. FIELD-BY-FIELD COMPARISON
# ===========================================================================
W "##############################################################################"
W "# 4. THE SAME PROCESS, THE TWO SOURCES, FIELD BY FIELD"
W "#    Watch for fields that share a NAME but not a meaning. ProcessId is the"
W "#    known trap: created process in Sysmon (decimal), parent in 4688 (hex)."
W "##############################################################################"
W ""

if ($fields4688 -and $fieldsSys1) {
    W "  Fields ONLY in Security 4688:"
    foreach ($k in $fields4688.Keys) {
        if (-not $fieldsSys1.Contains($k)) { W ("    - {0,-26} = {1}" -f $k, $fields4688[$k]) }
    }
    W ""
    W "  Fields ONLY in Sysmon 1:"
    foreach ($k in $fieldsSys1.Keys) {
        if (-not $fields4688.Contains($k)) { W ("    - {0,-26} = {1}" -f $k, $fieldsSys1[$k]) }
    }
    W ""
    W "  Fields with the SAME NAME in both - compare the values before trusting them:"
    foreach ($k in $fields4688.Keys) {
        if ($fieldsSys1.Contains($k)) {
            W ("    = {0,-26} | 4688: {1} | Sysmon: {2}" -f $k, $fields4688[$k], $fieldsSys1[$k])
        }
    }
} else {
    W "  Could not pair a powershell.exe across both sources."
    W "  4688 paired: $([bool]$fields4688)   Sysmon 1 paired: $([bool]$fieldsSys1)"
}
W ""

# ===========================================================================
#  5. VOLUME - why this matters operationally
# ===========================================================================
W "##############################################################################"
W "# 5. VOLUME"
W "##############################################################################"
W ""
try {
    $count4688 = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue).Count
    $countSys1 = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue).Count
    W "  Last hour, on ONE idle machine:"
    W "    Security 4688 : $count4688 events"
    W "    Sysmon 1      : $countSys1 events"
    W "  Multiply by the endpoint count of any real organisation. That number is"
    W "  the reason detection is a filtering problem and not a collection problem."
} catch { W "  ERROR counting: $($_.Exception.Message)" }
W ""

$lines -join "`r`n" | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Evidence written to $OutFile  ($($lines.Count) lines)"
