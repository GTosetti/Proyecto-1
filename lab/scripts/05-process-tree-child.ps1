<#
    05-process-tree-child.ps1
    ---------------------------------------------------------------------------
    WHAT IT DOES
      Three harmless actions, each chosen because it produces a different Sysmon
      Event ID:
          - a DNS query              -> Sysmon 22
          - an outbound TCP connect  -> Sysmon 3
          - a child process          -> Sysmon 1 + Security 4688

    WHY IT EXISTS
      It is the leaf of the tree launched by 04-process-tree-generate.ps1 and is
      not meant to be run on its own. Sysmon 3 and Sysmon 22 are included
      because neither has an equivalent in the Security channel AS THIS LAB IS
      CONFIGURED. Be precise about that, because it is the kind of sentence an
      interviewer tests: Windows can record an outbound connection with the
      process image and PID, in 5156, but that is the Filtering Platform
      Connection subcategory and it is deliberately off here for volume. A DNS
      query has no Security-channel equivalent at all - the native record is in
      Microsoft-Windows-DNS-Client/Operational, a channel this lab does not
      collect. Both Sysmon IDs were also found to have zero detection coverage
      in the default ruleset used here, despite being ingested - which is
      exactly the kind of gap this exercise is designed to surface.

    No credential appears in this file.
#>

param(
    [string] $Marker    = 'NOMARKER',
    [string] $TcpTarget = '10.10.10.10',
    [int]    $TcpPort   = 443,
    [string] $DnsName   = 'labmarker.example.com'
)

Write-Host "  [child] marker received: $Marker"

# --- 1. DNS query  ->  Sysmon Event ID 22 ----------------------------------
# example.com is reserved by the IANA for documentation: it belongs to nobody
# and cannot be visited by accident.
try {
    Resolve-DnsName -Name $DnsName -ErrorAction Stop | Out-Null
    Write-Host "  [child] DNS resolved: $DnsName"
} catch {
    # Success or failure is irrelevant - the QUERY happened, so Sysmon 22 is
    # written either way. A failed lookup is in fact the more interesting case:
    # repeated NXDOMAIN from one process is the shape of DGA behaviour.
    Write-Host "  [child] DNS lookup failed (event 22 was still generated): $($_.Exception.Message)"
}

# --- 2. TCP connection  ->  Sysmon Event ID 3 ------------------------------
# Raw TcpClient rather than Test-NetConnection: the latter spawns helper
# processes and pollutes the very process tree this exercise exists to read.
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($TcpTarget, $TcpPort)
    Write-Host "  [child] TCP $TcpTarget`:$TcpPort connected = $($client.Connected)"
    $client.Close()
} catch {
    Write-Host "  [child] TCP connect failed: $($_.Exception.Message)"
}

# --- 3. Child process  ->  Security 4688 + Sysmon 1 ------------------------
# whoami.exe is the first thing most intruders run. Worth noting what it
# produces here: in this lab it generated a process-creation event matched by a
# catch-all rule at the lowest alert level, identical to the alert produced by a
# routine system service.
#
# It is launched with no arguments, so its command line carries no marker. That
# is why the collector searches for this one by image name as well as by marker.
$who = & "$env:SystemRoot\System32\whoami.exe"
Write-Host "  [child] whoami -> $who"

Write-Host "  [child] finished"
