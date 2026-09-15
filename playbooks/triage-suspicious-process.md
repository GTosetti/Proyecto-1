# Playbook: suspicious process creation

Covers alerts raised on a process being created: interpreter chains, encoded commands,
dropped executables and discovery commands. Measured on `WIN11-VICTIMA` (10.10.10.20), which
runs Sysmon64 with the SwiftOnSecurity configuration alongside Windows advanced audit policy,
with command line included in 4688 and PowerShell ScriptBlock (4104) and Module (4103) logging
enabled.

ATT&CK: T1059.001, T1059.003, T1033, T1036.003, T1105.

---

## 1. Trigger

| Rule | Level | Fires on | Lab observation |
|---|---|---|---|
| 92057 | 12 | PowerShell spawning PowerShell with a base64-encoded command | Fired on 2026-08-08 — on a **Sysmon Event ID 1**, not on the 4104 the exercise had predicted; the 4104 existed but the alert came from the other source |
| 92004 | 4 | PowerShell process spawned a Windows command shell | The only Sysmon 1 alert out of 11 Sysmon 1 events in the 2026-08-11 exercise; it matched the parent→child **pattern**, not process creation |
| 92213 | 15 | Executable file dropped in a folder commonly used by malware (Sysmon 11) | False positive every single time so far: 1x on 2026-08-08, 5x on 2026-08-11, 12x on 2026-09-07, always on `__PSScriptPolicyTest_<random>.ps1` |
| 67027 | 3 | Any process creation (Security 4688) — catch-all | 16 of 16 process creations alerted in the 2026-08-11 exercise |

Read that table before you read the alert. Rule 92213 at level 15 is currently the loudest
rule in the lab and has never once been right; rule 67027 at level 3 is the only reason some
processes are searchable at all. Level tells you nothing about which is which.

---

## 2. Required context

| Question | How to answer |
|---|---|
| Which sensor raised it — Security 4688 or Sysmon 1? | Determines which fields exist at all (section 4) |
| Is the image path under `C:\Windows\System32`, `C:\Program Files*`, or somewhere a user can write? | `Image` / `NewProcessName` |
| Which session is it in? | `SubjectLogonId` (4688) / `LogonId` (Sysmon 1) — the pivot for everything else |
| Was an interactive session open at that moment? | 4624 for the same LogonId; if the session is 0x3e7 it is SYSTEM, not a person |
| Is this host currently running lab automation? | Processes launched from the host through VirtualBox appear as ordinary local activity — see the `Advapi` note in the README |

---

## 3. The trap: `ProcessId` means opposite things in the two sources

Measured on 2026-08-11 on a single `powershell.exe` process, reported by both sensors:

| Field | Security 4688 | Sysmon Event ID 1 |
|---|---|---|
| The process that was **created** | `NewProcessId` = `0x1250` | `ProcessId` = `4688` |
| Its **parent** | `ProcessId` = `0xdb4` | `ParentProcessId` = `3508` |
| Number base | Hexadecimal | Decimal |

`0x1250` = 4688 decimal and `0xdb4` = 3508 decimal: these are the same two processes described
twice. The field literally named `ProcessId` refers to the **child** in Sysmon and to the
**parent** in 4688.

Joining the two sources on the shared field name — without converting the base and without
checking the semantics — inverts the process tree, silently, producing a wrong report built
from correct data. There is no error message for this.

Two further hazards in the same area:

- In this measurement the created process had PID **4688**, which is also the Event ID of
  process creation. If a number like that turns up in a note, say which it is.
- PIDs are recycled by Windows. Sysmon's `ProcessGuid`
  (measured example shape: `{2bfc577d-5a5c-6a7b-0901-...}`) never is, and it is what ties a
  process to its network (Sysmon 3) and DNS (Sysmon 22) events — all three carried the same
  GUID segment in the 2026-08-11 exercise. **Build trees on ProcessGuid, verify with PID,
  never the other way round.**

Conversion, when you must compare the two:

```powershell
[Convert]::ToInt64('0x1250'.Replace('0x',''), 16)   # 4688
'0x{0:x}' -f 3508                                   # 0xdb4
```

---

## 4. What each source can and cannot tell you

Field-by-field comparison, measured on the same process event on 2026-08-11.

| Field | Security 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Yes — **only because** `ProcessCreationIncludeCmdLine_Enabled` was set to 1 by hand | Yes |
| ParentCommandLine | **No** | Yes |
| Hashes (MD5 / SHA256 / IMPHASH) | No | Yes |
| OriginalFileName | **No** | Yes (`PowerShell.EXE`) |
| File metadata (FileVersion, Description, Product, Company) | No | Yes |
| CurrentDirectory | No | Yes |
| Stable process identifier | No — PID only, and PIDs recycle | `ProcessGuid` |
| Integrity level | As the SID `MandatoryLabel S-1-16-8192` | `IntegrityLevel = Medium`, in words |
| TokenElevationType | **Yes** (`%%1938` = Limited) — unique to 4688 | No |
| Session | `SubjectLogonId` `0x10cce5` | `LogonId` `0x10cce5` — identical, so they join cleanly |

Consequences that change how you triage:

- **With only 4688 you know the parent's name but not what the parent was doing.** Missing
  `ParentCommandLine` is the most expensive omission, because the interesting question about
  `cmd.exe` is almost never "was cmd.exe running" but "what was it told to do".
- **Renamed system binaries are undetectable from the Security log alone.** If
  `powershell.exe` is copied to `C:\Users\Public\svchost.exe`, both Sysmon's `Image` and
  4688's `NewProcessName` report the lie. `OriginalFileName` still reports `PowerShell.EXE`,
  and 4688 has no equivalent field. That is T1036.003, and it is the concrete reason this lab
  runs Sysmon *in addition to* native auditing rather than instead of it.
- **4672 does not mean the process ran elevated.** Every remote invocation in this lab
  produced a *pair* of 4624 events — one with `elevatedToken %%1842` (Yes) plus a 4672, one
  with `%%1843` (No) and no 4672 — 8 times out of 8. The process that actually launched
  carried the second LogonId and `TokenElevationType %%1938` (Limited). That is the UAC linked
  token visible in the log. Codes: `%%1936` Default (UAC does not apply, e.g. SYSTEM),
  `%%1937` Full (elevated), `%%1938` Limited (filtered).

---

## 5. Decision tree

```
Process-creation alert
│
├─ Q1. Is it rule 92213 on __PSScriptPolicyTest_*.ps1 written by the signed system PowerShell?
│     ──► FALSE POSITIVE. Close with a tuning note. Do not spend the shift here.
│         (18 occurrences across three exercises, zero true.)
│
├─ Q2. Reconstruct the tree (query A). Walk UP from the alerting process to a root you trust.
│   Trusted roots: services.exe, explorer.exe under a real interactive LogonId, winlogon.exe.
│   Untrusted roots: an Office application, a browser, wscript/mshta, an unknown service.
│   │
│   ├─ Cannot reach a trusted root (parent already exited, PID recycled)
│   │     ──► say so in the ticket. Do not invent the chain.
│   └─ Reached a root ──► continue
│
├─ Q3. Is the image what it claims to be? (query B)
│     Compare Image / NewProcessName against OriginalFileName, and check the path.
│     ├─ OriginalFileName ≠ the file name on disk ──► renamed binary. TRUE POSITIVE, T1036.003.
│     └─ System binary in a user-writable path ──► TRUE POSITIVE until proven otherwise.
│
├─ Q4. Read the command line — both the process's and, from Sysmon, its parent's.
│     ├─ -EncodedCommand / -enc / FromBase64String / -w hidden / IEX / DownloadString
│     │     ──► decode it (query C) and read the script block from 4104 on the endpoint.
│     │         The SIEM will not have it: 110 PowerShell events produced 0 alerts on 2026-08-11.
│     ├─ Three or more discovery commands under the same parent inside ~60 s
│     │     (whoami, net user, net localgroup, nltest, systeminfo, ipconfig /all, arp -a, quser)
│     │     ──► discovery sequence. Single commands are invisible here; the sequence is the signal.
│     └─ Nothing unusual ──► continue to Q5 before closing.
│
├─ Q5. What did the process touch? (query D, joined on ProcessGuid)
│     Sysmon 11 files written · Sysmon 3 network · Sysmon 22 DNS · Sysmon 13 registry
│     Read Sysmon 3 and 22 by their own UtcTime field, NOT by TimeCreated.
│     Neither 3 nor 22 has any detection rule in this lab — if you do not look, nobody does.
│
└─ Q6. Whose session was it? (query E)
      Pivot on LogonId to the 4624 that opened it and the 4634 that closed it.
      A process in a session that was opened from a remote address is an intrusion ticket,
      not a process ticket ──► triage-remote-access.md.
```

---

## 6. Queries

### Query A — reconstruct the tree from Sysmon (endpoint)

Sysmon is the source to build the tree from, because it carries `ParentCommandLine` and a
non-recycling GUID. Save as `C:\lab\q-tree.ps1`, run with `-File`.

```powershell
$start = (Get-Date).AddMinutes(-15)
$procs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$start} |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime       = $d['UtcTime']          # authoritative time for Sysmon events
      Guid          = $d['ProcessGuid']
      Pid           = [int]$d['ProcessId']   # DECIMAL, and this is the CHILD
      ParentGuid    = $d['ParentProcessGuid']
      ParentPid     = [int]$d['ParentProcessId']
      Image         = $d['Image']
      OriginalName  = $d['OriginalFileName'] # survives a rename; 4688 has no equivalent
      CommandLine   = $d['CommandLine']
      ParentImage   = $d['ParentImage']
      ParentCmdLine = $d['ParentCommandLine']
      User          = $d['User']
      LogonId       = $d['LogonId']
      Integrity     = $d['IntegrityLevel']
      Sha256        = ($d['Hashes'] -split ',' | Where-Object { $_ -like 'SHA256=*' })
    }
  }

# walk up from one process
function Get-Chain($guid) {
  while ($guid) {
    $p = $procs | Where-Object Guid -eq $guid | Select-Object -First 1
    if (-not $p) { "  (parent $guid not in window — chain incomplete)"; break }
    "  {0}  {1}  [{2}]  {3}" -f $p.UtcTime, $p.Image, $p.Pid, $p.CommandLine
    $guid = $p.ParentGuid
  }
}
$procs | Sort-Object UtcTime | Format-Table UtcTime, Image, Pid, ParentImage, ParentPid -AutoSize
# Get-Chain '{PUT-THE-ProcessGuid-HERE}'
```

Anomalies in the tree are worth chasing even when they look like your own tooling. On
2026-08-11 the captured tree showed **two** `powershell.exe` where one was expected: the outer
one with `-File C:\lab\04-b4-generar.ps1` spawning an inner one with the same arguments. The
cause was a defect in how the script was launched from the host (a duplicated `argv[0]` made
PowerShell treat its own name as `-Command` and relaunch itself). The command's output looked
perfectly normal; only the process tree showed it.

### Query B — the same process from the Security log, for the fields Sysmon lacks

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddMinutes(-15)} |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      Time        = $_.TimeCreated.ToString('o')
      RecordId    = $_.RecordId
      NewProcess  = $d['NewProcessName']
      NewPidHex   = $d['NewProcessId']        # HEX, the CHILD
      ParentPidHex= $d['ProcessId']           # HEX, the PARENT — note the name
      ParentImage = $d['ParentProcessName']
      CommandLine = $d['CommandLine']
      LogonId     = $d['SubjectLogonId']
      Elevation   = $d['TokenElevationType']  # %%1936 Default / %%1937 Full / %%1938 Limited
    }
  } | Format-Table -AutoSize
```

### Query C — PowerShell script content (endpoint only)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-15)} |
  Select-Object TimeCreated, @{n='Script';e={$_.Message}} | Format-List

# decode an -EncodedCommand argument found in a command line
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<BASE64 FROM THE COMMAND LINE>'))
```

The SIEM is not an option for this step: in the 2026-08-11 exercise the PowerShell channel
produced 110 events and 0 alerts, so none of it is in `wazuh-alerts-*`.

### Query D — what the process did, joined on ProcessGuid (endpoint)

```powershell
$guid = '{PUT-THE-ProcessGuid-HERE}'
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3,11,12,13,22; StartTime=(Get-Date).AddMinutes(-15)} |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    if ($d['ProcessGuid'] -eq $guid) {
      [pscustomobject]@{
        EventId   = [int]$x.Event.System.EventID
        UtcTime   = $d['UtcTime']                 # use this, not TimeCreated
        File      = $d['TargetFilename']          # Sysmon 11
        DestIp    = $d['DestinationIp']           # Sysmon 3
        DestPort  = $d['DestinationPort']         # Sysmon 3
        Initiated = $d['Initiated']               # Sysmon 3: false = inbound
        DnsQuery  = $d['QueryName']               # Sysmon 22
        RegKey    = $d['TargetObject']            # Sysmon 12/13
      }
    }
  } | Sort-Object UtcTime | Format-Table -AutoSize
```

Why `UtcTime` and not `TimeCreated`: measured on 2026-08-11, Sysmon 22 (DNS) was written to
the channel 3.2 s after the event and Sysmon 3 (network) 4.0 s after. Sorting by
`TimeCreated` placed a DNS query *after* the `whoami.exe` that followed it — a timeline with
cause and effect reversed.

### Query E — everything in the session (SIEM)

Same shape as query C in `triage-failed-authentication.md`: filter `subjectLogonId`,
`targetLogonId` and `logonId` for the session value, sorted by `data.win.system.systemTime`.

---

## 7. Verdict criteria

**True positive**
Any one of: `OriginalFileName` disagreeing with the name on disk; a system binary running from
a user-writable path; an encoded or obfuscated command line whose decoded content downloads,
encodes or executes something; an interpreter chain rooted in a document handler or browser;
three or more discovery commands under one parent inside about a minute; a process in a
session opened from an address that should not be authenticating to the host.

**True, authorised**
The chain resolves to a known administrative task, a software installer, or lab automation you
launched, and the command line matches what that task actually does. Record which task, and
the `ProcessGuid`, so the same chain can be recognised next time without repeating the work.

**False positive**
The rule matched something other than what its name claims. The standing example in this lab
is rule 92213 on `__PSScriptPolicyTest_*.ps1` — a file the signed system `powershell.exe`
writes into `%TEMP%` to test its own execution policy. 18 occurrences, 18 false positives.
Close it, and record the tuning: exclude that filename pattern when the writing image is the
signed system PowerShell. Until that is done, level 15 carries no information here.

**Needs escalation / undecided**
The parent exited before the window opened and the chain cannot be closed; or the command line
is encoded and the 4104 content is unavailable; or the binary's hash is unknown to you and you
have no reputation source. Escalate with the hash and the incomplete chain rather than
guessing at intent.

---

## 8. Collect this before escalating

A tier 2 analyst should not have to ask for any of these.

1. `eventRecordID` of the alerting event and the channel it came from.
2. `ProcessGuid` of the subject process, and of its parent.
3. Full command line **and** parent command line (the second only exists in Sysmon 1).
4. `Image`, `OriginalFileName`, and the SHA256 from Sysmon's `Hashes`.
5. The process chain, written as a chain, with times from `UtcTime`/`systemTime` — each line
   `time · image · pid · command line`, and an explicit marker where the chain breaks.
6. `LogonId`, plus the 4624 that opened that session (type, source address, logon process).
7. `TokenElevationType` from 4688, with the reminder that a 4672 nearby refers to the
   account's other token and not to this process.
8. Child activity joined on `ProcessGuid`: files written (Sysmon 11), network (Sysmon 3,
   with `Initiated`), DNS (Sysmon 22), registry (Sysmon 12/13).
9. Whether the endpoint has been contained or not, and what you did — in this lab the only
   containment is the `base-limpia` snapshot, and restoring it destroys the evidence, so it is
   the last step, never the first.
10. The blind spots relevant to this ticket: no network sensor, PowerShell content not in the
    SIEM, Sysmon 3/22 with no rule coverage.

---

## 9. Known gaps this playbook works around

| Gap | Evidence | Consequence |
|---|---|---|
| Discovery commands are indistinguishable from noise | `whoami.exe` produced a 4688 matched by catch-all rule 67027 at level 3 — byte for byte the same treatment as `sppsvc.exe` | Detect the sequence, not the command |
| 4798 / 4799 (local group membership enumeration — literally what SharpHound does) never alert | 2 events generated, 0 alerts on 2026-08-11, confirmed against a widened window | Must be queried manually |
| 4648 (logon with explicit credentials) never alerts | 1 event, 0 alerts on 2026-08-11 | The `runas` / lateral-movement signature is invisible in the queue |
| Sysmon 3 and 22 have zero rule coverage | 1 network event and 1 DNS event in the 2026-08-11 window, 0 alerts each; 2 inbound Sysmon 3 events on 2026-09-07, 0 alerts | Query D is not optional |
| PowerShell 4103/4104 has zero rule coverage | 110 events, 0 alerts on 2026-08-11 | Script content only exists on the endpoint |
| 4689 (process termination) never alerts | 12 events, 0 alerts on 2026-08-11 | Cannot bound a process's lifetime from the SIEM alone |
