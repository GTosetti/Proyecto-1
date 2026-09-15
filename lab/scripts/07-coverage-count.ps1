<#
    07-coverage-count.ps1
    ---------------------------------------------------------------------------
    WHAT IT DOES
      Counts, for a fixed time window, how many events the endpoint GENERATED,
      broken down by channel and by Event ID.

    WHY IT EXISTS
      It produces the denominator. On its own the number is not interesting;
      compared against how many ALERTS the SIEM raised for the same window, it
      measures the three layers of detection coverage:

          1. generate    - Windows and Sysmon write the event
          2. collect     - the agent ships it (the <localfile> entries in
                           ossec.conf)
          3. detect      - a rule on the manager matches it

      A hole in layer 1 or 2 eventually announces itself. A hole in layer 3 does
      not: there is no error, no missing-alert indicator, and nothing to search
      for. It is invisible from the dashboard. The only way to find one is to
      cause an event deliberately and check whether it ever became an alert.

      Measured this way in this lab: 172 events generated produced 36 alerts.
      (A first pass over a narrower window reported 167 and 27; it clipped
      paired events at the boundary. Always widen the window and recount.)
      Process-creation events alerted 16 of 16 through a catch-all rule at the
      lowest level, while Sysmon process events alerted 1 of 11 - and that one
      matched a parent/child pattern rather than process creation itself.
      Several channels that were being ingested correctly produced zero alerts.

    A METHOD WARNING WORTH KEEPING
      Before reporting a coverage gap, WIDEN THE WINDOW. An apparent gap in
      logon events here turned out to be a boundary artefact: each remote
      invocation produced a pair of events and the pair was being cut in half by
      the window edge. A false gap in a coverage report is as damaging as a
      false positive in a queue.

    USAGE (on the endpoint, after 04-process-tree-generate.ps1):
      powershell -ExecutionPolicy Bypass -File .\07-coverage-count.ps1
      powershell -ExecutionPolicy Bypass -File .\07-coverage-count.ps1 -WindowSeconds 60

    Reading the Security channel needs BUILTIN\Event Log Readers in the token -
    see the note in 06-collect-evidence.ps1; it requires a reboot after the
    group is added.

    No credential appears in this file.
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    # Local start time, 'yyyy-MM-dd HH:mm:ss'. Read from the run record if omitted.
    [string]   $StartLocal    = '',
    [int]      $WindowSeconds = 20,
    [string]   $LabDir        = 'C:\lab',
    [string[]] $Channels      = @(
        'Security',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-PowerShell/Operational'
    )
)

$ErrorActionPreference = 'Continue'

$recordPath = Join-Path $LabDir 'process-tree-run.json'
if (-not $StartLocal -and (Test-Path $recordPath)) {
    $record     = Get-Content $recordPath -Raw | ConvertFrom-Json
    $StartLocal = $record.start_local
}
if (-not $StartLocal) {
    throw "No window given. Run 04-process-tree-generate.ps1 first, or pass -StartLocal."
}

$start = [datetime]::Parse($StartLocal)
$end   = $start.AddSeconds($WindowSeconds)

# Both are printed because the endpoint records local time and the SIEM indexes
# in UTC. You need the UTC pair to build the matching query on the alert side.
"Window (local) : $($start.ToString('HH:mm:ss')) -> $($end.ToString('HH:mm:ss'))"
"Window (UTC)   : $($start.ToUniversalTime().ToString('HH:mm:ss'))Z -> $($end.ToUniversalTime().ToString('HH:mm:ss'))Z"
""

$grandTotal = 0

foreach ($channel in $Channels) {
    "=== $channel ==="
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName=$channel; StartTime=$start; EndTime=$end} -ErrorAction Stop
        $grandTotal += $events.Count
        "  TOTAL events generated: $($events.Count)"
        $events | Group-Object Id | Sort-Object { [int]$_.Name } |
            ForEach-Object { "    Event ID {0,-6} x{1}" -f $_.Name, $_.Count }
    } catch {
        "  (none, or error: $($_.Exception.Message))"
    }
    ""
}

"=============================================================================="
"  GENERATED in this window, all channels: $grandTotal"
""
"  Now count ALERTS for the same UTC window in the SIEM and compare. The"
"  difference is your layer-3 coverage. For each Event ID you generated, you"
"  should be able to say whether it alerted and which rule matched it."
""
"  Absence of an alert is not evidence of absence of activity."
"=============================================================================="
