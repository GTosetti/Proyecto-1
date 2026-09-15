# 002 - One process tree, three telemetry sources: Security 4688, Sysmon EID 1 and Wazuh

| | |
|---|---|
| Date of exercise | 2026-08-11 |
| Type | Visibility exercise, not an incident. A benign process tree, launched on purpose and then tracked. |
| Environment | Self-built home lab, NAT network `SOCLAB` `10.10.10.0/24` |
| Endpoint | `WIN11-VICTIMA`, Windows 11 Pro 25H2 build 10.0.26200, `10.10.10.20` |
| Detection stack | Wazuh 4.14.7 all-in-one on Ubuntu Server 24.04.4 (`10.10.10.10`), Windows advanced audit policy with command line in 4688, Sysmon64 with the SwiftOnSecurity configuration |
| Channels forwarded | Security, System, Application, Sysmon/Operational, PowerShell/Operational |
| ATT&CK techniques | T1059.001, T1059.003, T1033, T1036.003 (present by *absence* of a field), T1087 |
| Observation window | 17:22:36Z - 17:22:56Z, widened to 17:22:20Z - 17:23:00Z during verification (section 5) |

## 1. Starting point

There is no alert here and nothing malicious happened. The question the exercise answers is one an
analyst relies on every shift without testing it:

> When the SIEM shows me "a process was created", what is it *not* showing me?

A known process tree was launched from a script, carrying a unique marker in the command line so
that these processes, and no others, could be located in three independent places afterwards.

```
powershell.exe   (04-b4-generar.ps1)
  └── cmd.exe    /c powershell.exe ... -File 05-b4-hijo.ps1 B4MARCA202608111422
        └── powershell.exe  (05-b4-hijo.ps1)
              ├── DNS query   b4marca.example.com          -> Sysmon EID 22
              ├── TCP 10.10.10.20:49686 -> 10.10.10.10:443 -> Sysmon EID 3
              └── whoami.exe                               -> Security 4688 + Sysmon EID 1
```

The marker `B4MARCA202608111422` is the anchor. It travels in `CommandLine`, so the same process can
be identified in the Windows Security log, in the Sysmon channel and in the SIEM index without
guessing.

## 2. Hypotheses, written before looking at the data

| # | Hypothesis | Result |
|---|---|---|
| 1 | Sysmon EID 1 and Security 4688 say the same thing, Sysmon just with more fields | **False** |
| 2 | Fields that carry the same name mean the same thing | **False** |
| 3 | Anything the endpoint generates and the agent collects ends up visible in Wazuh | **False** |
| 4 | The timestamps from the three sources agree | **False** |

All four were wrong. That is the content of this writeup.

## 3. Evidence collected

### 3.1 How each source was read

Endpoint, from inside the VM (PowerShell 5.1):

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$from } |
    Where-Object { $_.Message -match 'B4MARCA202608111422' }

# The rendered .Message is presentation only. The XML is what the agent ships:
([xml]$ev.ToXml()).Event.EventData.Data
```

SIEM, from the host. The Wazuh indexer listens on 9200 **only on localhost inside the SIEM VM**, so
a VirtualBox NAT port forward to 9200 fails (curl error 35, TLS). The path that works is the
dashboard's console proxy, already exposed on 8443, which accepts basic auth:

```bash
curl -k -u admin:<REDACTED> -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d '{"query":{"terms":{"data.win.system.eventRecordID":["31476","31478","31479"]}}}'
```

One method note that cost time: a `query_string` search for the marker `B4MARCA202608111422`
returned **0 results** while the string was sitting in `data.win.eventdata.commandLine` of indexed
documents. Searching a SIEM is not `grep`. Field names and index analysis decide what is findable.
The query that worked targeted the field directly, here a `terms` filter on
`data.win.system.eventRecordID`.

### 3.2 Field mapping across the three sources

Measured on one process: `powershell.exe` running `05-b4-hijo.ps1`, decimal PID 4688. (The PID
happening to equal the Event ID number 4688 is coincidence, but it is confusing to read, so it is
flagged here.)

| What it is | Security 4688 | Sysmon EID 1 | As indexed by Wazuh |
|---|---|---|---|
| Identity of the created process | `NewProcessId` = `0x1250` (**hex**) | `ProcessId` = `4688` (**decimal**) | `data.win.eventdata.newProcessId` / `data.win.eventdata.processId`, verbatim as the source wrote them |
| Identity of the **parent** | `ProcessId` = `0xdb4` (**hex**) | `ParentProcessId` = `3508` (**decimal**) | same field names as above, the collision survives into the index |
| Binary path | `NewProcessName` | `Image` | two different field names for the same fact |
| Parent binary path | `ParentProcessName` | `ParentImage` | - |
| Command line | `CommandLine` (only because `ProcessCreationIncludeCmdLine_Enabled` was set to 1 by hand) | `CommandLine` | `data.win.eventdata.commandLine` |
| **Parent command line** | not present | `ParentCommandLine` | only available from the Sysmon document |
| File hashes | not present | `Hashes` (MD5, SHA256, IMPHASH) | present only on Sysmon documents |
| Original file name (survives a rename) | not present | `OriginalFileName` = `PowerShell.EXE` | present only on Sysmon documents |
| File metadata | not present | `FileVersion`, `Description`, `Product`, `Company` | present only on Sysmon documents |
| Working directory | not present | `CurrentDirectory` | present only on Sysmon documents |
| Integrity level | `MandatoryLabel` = `S-1-16-8192` (a SID) | `IntegrityLevel` = `Medium` (plain word) | same fact, two representations; a rule written against one will not match the other |
| Token elevation | `TokenElevationType` = `%%1938` (Limited) | not present | present only on 4688 documents |
| Stable process identifier | not present, only the PID, which is recycled | `ProcessGuid` = `{2bfc577d-5a5c-6a7b-0901-...}` | the only non-recycling join key available |
| User | `SubjectUserSid` + `SubjectUserName` | `User` = `WIN11-VICTIMA\<LAB_USER>` | - |
| Logon session | `SubjectLogonId` = `0x10cce5` | `LogonId` = `0x10cce5` + `LogonGuid` + `TerminalSessionId` | **identical value in both sources**, the one field that joins cleanly |
| Detection metadata | none, the raw event | none, the raw event | `rule.id`, `rule.level`, `rule.mitre.id`, `@timestamp` exist only here |

Reading of the table:

- **`ProcessId` is the single most dangerous field name in Windows telemetry.** In 4688 it is the
  **parent**; in Sysmon EID 1 it is the **created process**. Joining the two sources on a field with
  the same name inverts the process tree, silently, and produces a wrong report built on correct
  data.
- The values do reconcile once you convert the base: `0x1250` = 4688 and `0xdb4` = 3508, which are
  exactly the decimal `ProcessId` and `ParentProcessId` Sysmon reported for the same process. The
  correlation is possible; it just is not the one the field names suggest.
- **`LogonId` is the join key that behaves.** `0x10cce5` appeared identically in the 4688
  (`SubjectLogonId`) and the Sysmon EID 1 (`LogonId`), and the same value tied the session's opening
  4624 and closing 4634 to every process launched inside it.
- **`ProcessGuid` is the join key for anything beyond process creation.** The Sysmon EID 3 (network)
  and EID 22 (DNS) events produced in this exercise carried the same GUID segment as the process
  that caused them. Security 4688 has no equivalent, so with the Security log alone the network
  activity cannot be attributed to a process except by PID, and PIDs are reused.
- **`OriginalFileName` is the field whose absence has a named consequence.** Copy `powershell.exe`
  to `C:\Users\Public\svchost.exe` and both Sysmon's `Image` and 4688's `NewProcessName` report the
  lie; `OriginalFileName` still reports `PowerShell.EXE`. Security 4688 has no equivalent field, so
  **T1036.003 is not detectable from the Windows Security log alone**. This is the concrete argument
  for deploying Sysmon *in addition to* native auditing rather than instead of it.

## 4. Worked timeline: the answer changes with the timestamp field you sort by

Three clocks were measured, on the same events.

**Clock 1, endpoint versus manager.** For the creation of `cmd.exe` (`eventRecordID` 31476), the
endpoint's `TimeCreated` / `data.win.system.systemTime` read `17:22:36.6840621Z` while Wazuh's
`@timestamp` read `17:22:34.930Z`: a delta of **-1.754 s**. Measured across three consecutive event
records the deltas were -1.754 s, -1.821 s and -1.757 s. Consistent, so it is an offset, not jitter.

**Clock 2, Sysmon channel write versus event occurrence.** Sysmon writes network and DNS events to
the channel seconds after they happen, and each event carries its own `UtcTime` recording when it
actually occurred:

| Event | `TimeCreated` (written to the channel) | `UtcTime` (when it happened) | Gap |
|---|---|---|---|
| Sysmon EID 22 · DNS query | 17:22:40.464 | 17:22:37.222 | 3.2 s |
| Sysmon EID 3 · network connection | 17:22:41.163 | 17:22:37.162 | 4.0 s |

**The same four events, sorted three ways:**

| Order | By `systemTime` / `UtcTime` (endpoint truth) | By channel `TimeCreated` | By Wazuh `@timestamp` (dashboard default) |
|---|---|---|---|
| 1 | 17:22:36.684, `cmd.exe` created | 17:22:36.684, `cmd.exe` created | 17:22:34.930, `cmd.exe` created |
| 2 | 17:22:37.162, outbound TCP to 10.10.10.10:443 | 17:22:38.7, `whoami.exe` created | ~17:22:36.9, `whoami.exe` created |
| 3 | 17:22:37.222, DNS query `b4marca.example.com` | 17:22:40.464, DNS query | *(absent)* |
| 4 | 17:22:38.7, `whoami.exe` created | 17:22:41.163, outbound TCP | *(absent)* |

Three separate failures are visible in that table:

1. **Sorting by channel `TimeCreated` reverses cause and effect.** It places the DNS query and the
   network connection *after* `whoami.exe`, which is false: they happened roughly 1.5 s before it.
   For Sysmon EID 3 and EID 22 the field to read is `UtcTime`, never the channel's `TimeCreated`.
2. **Sorting by `@timestamp` shifts everything about 1.8 s earlier**, because `@timestamp` is the
   manager's processing clock, not the endpoint's. Filtering the dashboard for "what happened at
   17:22:36" returns events Windows recorded at 17:22:38. The field to pin queries to is
   `data.win.system.systemTime`.
3. **Two of the four rows do not exist at all in the `@timestamp` column**, because the Sysmon EID 3
   and EID 22 events produced zero alerts (section 5). The dashboard timeline is not a quiet
   timeline here. It is a timeline with no row for the network activity whatsoever.

The relative order of rows 2 and 3 in the first column rests on a 60 ms difference, which is too
fine to lean on. What the measurement does support firmly is that both preceded `whoami.exe` by over
a second, and that only one of the three sort orders shows that.

Fix, for the record: this is not a rule to write, it is NTP on both VMs plus the discipline of
pinning every query to `data.win.system.systemTime`, and to `UtcTime` for Sysmon 3 and 22. It gets
materially more important once a domain controller joins the lab, since Kerberos rejects skew above
five minutes.

## 5. The collection funnel: 172 events generated, 36 alerts

Counted per channel. The first pass counted over the narrow window, 17:22:36Z - 17:22:56Z, and was
wrong. The table below is the corrected count over the widened window, 17:22:20Z - 17:23:00Z, with
the first-pass figures kept in place for the two rows that changed. How the count was wrong is the
more useful half of this section, so it is shown rather than quietly fixed.

| Channel | Event | Generated | Alerts | Rule / level |
|---|---|---|---|---|
| Security | 4688 process created | 16 | 16 | 67027 · level 3 |
| Security | 4689 process terminated | 12 | 0 | - |
| Security | 4624 logon | **8** (4 in the first pass) | **8** (2 in the first pass) | 60118 · level 3 |
| Security | 4634 logoff | 2 | 2 | 67023 · level 3 |
| Security | 4672 special privileges assigned | **4** (3 in the first pass) | **4** (1 in the first pass) | 67028 · level 3 |
| Security | 4648 logon with explicit credentials | 1 | **0** | - |
| Security | 4798 + 4799 group membership enumeration | 2 | **0** | - |
| Sysmon | EID 1 process create | 11 | **1** | 92004 · level 4 |
| Sysmon | EID 3 network connection | 1 | **0** | - |
| Sysmon | EID 11 file created | 4 (first pass only, never recounted) | 5 | 92213 · **level 15** |
| Sysmon | EID 22 DNS query | 1 | **0** | - |
| PowerShell | 4103 / 4104 / other | 110 | **0** | - |
| | **Total** | **172** | **36** | |

**The correction, shown because it is the method and not an erratum.** The first pass showed 4 x
4624 generated against 2 alerted, and 3 x 4672 against 1. That reads like the SIEM dropping events,
and that is what I wrote down: a coverage gap. It was not one. Widening the window to 17:22:20Z -
17:23:00Z showed 8 x 4624 and 4 x 4672, every one of them alerting individually. The exercise made
**4** remote invocations, and each one produces a **pair** of 4624 events plus a single 4672, so the
pairs were being cut in half by my window boundary. The rule I took from it: **before declaring a
coverage gap, widen the window.** A false gap in a coverage report is as damaging as a false
positive in a queue. Only the gaps that survived the widened window, 4648, 4798/4799, Sysmon 3 and
Sysmon 22, are reported below as real.

**One row is still not trustworthy, and it is left visible rather than tidied away.** Sysmon EID 11
shows 4 generated against 5 alerts. Rule 92213 is a single-event rule, so it cannot alert more often
than the channel wrote events: the 5 alerts were counted over the widened window and the 4 was never
recounted there. The generated total of 172 is therefore a lower bound, understated by at least one
event. Recounting that one channel is a short job I have not done, and publishing 172 with the flaw
named is worth more than publishing a total that adds up cleanly.

**The alerting distribution is the inverse of what I predicted.**

- Security 4688 alerted 16 out of 16, through rule 67027, a catch-all that fires at level 3 on every
  process creation. 4688 therefore delivers **coverage plus noise**: `whoami.exe`, usually the first
  thing an intruder runs, produced an alert byte for byte identical to the one produced by
  `sppsvc.exe`.
- Sysmon EID 1 alerted **1 out of 11**, through rule 92004, *"Powershell process spawned Windows
  command shell instance"*. It fired on the **pattern** `powershell -> cmd`, not on the act of
  creating a process. Sysmon delivers **signal, but only where a rule is looking for it**.
- The only level 15 of the exercise was rule 92213, *"Executable file dropped in folder commonly
  used by malware"* (mapped to T1105), firing five times on the `__PSScriptPolicyTest_<random>.ps1`
  files that signed system PowerShell writes into `%TEMP%` to test its own execution policy. It is a
  false positive, and it is the same false positive recorded in the previous exercise. Severity is
  not priority: rule level measures how bad the event would be if real, not the probability that it
  is real.

**The three-layer model this makes concrete.** Between a fact and an alert there are three
independent layers: *generation* (does the OS log it), *collection* (does the agent ship it),
*detection* (does a rule match it). Every event in the table above was generated, so layer 1 is
doing its job; layer 2 is not separately observable from the alert index, since Wazuh indexes only
what matched a rule, so "the agent shipped it" is an inference here and not a measurement. What is
measured is layer 3, and layer 3 has holes. A hole in layer 3 produces no error, no missing-alert
indicator and nothing to search for. **It is invisible from the dashboard, because a
detection gap generates no evidence.** The only way to find one is to cause the event deliberately
and check whether it arrives.

## 6. Artefacts observed

No threat indicators. The activity was benign and self-generated. These are the artefacts an analyst
would extract from the same events:

| Type | Value |
|---|---|
| Command-line marker | `B4MARCA202608111422` |
| Domain queried | `b4marca.example.com` (`QueryStatus` 9501, no records) |
| Network connection | 10.10.10.20:49686 -> 10.10.10.10:443 |
| Pivot process `ProcessGuid` | `{2bfc577d-5a5c-6a7b-0901-...}` (truncated) |
| Session `LogonId` | `0x10cce5` |
| File hashes | 3 distinct SHA256 values captured from Sysmon EID 1 (`powershell.exe`, `cmd.exe`, `whoami.exe`), all signed system binaries. Values held in the lab evidence file, not reproduced here |

## 7. Detection gaps identified, and what would close them

Writing these rules is later work. Identifying and evidencing the gap is the point of this exercise.

| Gap | Evidence | What would close it |
|---|---|---|
| Sysmon EID 3 has zero coverage despite being ingested | 1 event generated, 0 alerts | Alert on EID 3 where `Image` is an interpreter (`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`) and `DestinationIp` is outside the local subnet, reading the event's `UtcTime`, not `TimeCreated` |
| Sysmon EID 22 has zero coverage despite being ingested | 1 event generated (`QueryStatus` 9501), 0 alerts | Alert on `QueryName` against a threat-intel or newly-registered-domain list, and on repeated NXDOMAIN from the same `ProcessGuid`. Correlate to the process by `ProcessGuid`, never by PID |
| Security 4648 produces no alert | 1 generated, 0 alerted, confirmed against the widened window | Alert at level 5 or above where `SubjectUserName` differs from `TargetUserName` and the calling process is not a known administrative tool, the runas / lateral-movement signature |
| Security 4798 / 4799 produce no alert | 2 generated, 0 alerted, confirmed against the widened window | Alert when several 4798/4799 occur under the same `SubjectLogonId` in a short window, the local group enumeration signature (T1087) |
| Discovery commands are indistinguishable from noise | `whoami.exe` produced the same level-3 4688 alert as `sppsvc.exe`; no Sysmon rule fired on it | A sequence rule, not a single-event rule: three or more of {`whoami`, `net user`, `net localgroup`, `nltest`, `systeminfo`, `ipconfig /all`, `arp -a`, `quser`} created under the same `ParentProcessGuid` or `SubjectLogonId` within 60 seconds |
| Rule 92213 fires at level 15 on benign PowerShell behaviour | 5 occurrences in this window, all on `__PSScriptPolicyTest_*.ps1` | Exclude `TargetFilename` matching `__PSScriptPolicyTest_*.ps1` where `Image` is signed system PowerShell. Until that is done, level 15 carries no information in this lab |
| No time synchronisation between endpoint and SIEM | -1.8 s offset across three consecutive records, plus the 3 to 4 s Sysmon channel-write lag | Not a rule: NTP on both VMs, and pin every dashboard query to `data.win.system.systemTime` / `UtcTime` |

## 8. What I learned, including the part that was my own mistake

- The three sources are not one truth at three levels of detail. They use **the same name for
  different things** (`ProcessId`) and **different representations of the same thing** (integrity
  level as a SID versus as a word). Correlating without first verifying what a field means is the
  fastest way to produce a confident, wrong report from entirely correct data.
- **A coverage table is a claim, and the window it was counted over is part of the claim.** The
  first version of section 5 reported 167 events and 27 alerts, and two of its rows were artefacts
  of where I put the window boundary rather than facts about the endpoint. The corrected figures are
  172 and 36. I found it by re-running the count rather than by re-reading the table, which is the
  only way this class of error surfaces.
- **The process tree caught a defect in my own tooling that was invisible from the command's
  output.** The captured tree showed two `powershell.exe` where one was expected: the first with
  argv `powershell.exe -NoProfile ... -File C:\lab\04-b4-generar.ps1`, spawning a second with
  `"powershell.exe" -NoProfile ... -File C:\lab\04-b4-generar.ps1`. Cause: `VBoxManage guestcontrol
  run --` adds its own `argv[0]`, so PowerShell received `powershell.exe` as its first argument,
  treated it as `-Command`, and relaunched itself. The command returned correct output and nothing
  was visible from outside. It was visible only in the process tree. That is precisely what reading
  a process tree is for.
- **Absence of an alert is not evidence of absence of activity.** 172 events became 36 alerts here,
  and in the previous exercise roughly 2,100 events reported to the manager left 835 alerts indexed
  for the endpoint. Any coverage claim based on searching the alert index is bounded by the ruleset,
  not by what the endpoint produced.
- What still needs work: I can now state which field to trust and why, but I have not yet written
  the rules that would close the four real gaps above, and the Sysmon EID 3 / 22 correlation by
  `ProcessGuid` has been reasoned about rather than implemented. Those are the next tasks, not
  claims I can make yet.
