# Lessons learned

Engineering and analysis lessons from building and instrumenting a three-VM home SOC lab
(Windows 11 endpoint with Sysmon, Wazuh 4.14.7 all-in-one on Ubuntu Server 24.04.4, Kali as
the attacker, VirtualBox NAT network `SOCLAB` 10.10.10.0/24).

Every lesson below follows the same shape: **what was expected**, **what actually happened**,
**the evidence** (how it was measured), and **the takeaway**. Nothing here is second-hand: each
number comes from an event, a query or a command run on this lab, on the dates given.

Credentials are referred to as `<LAB_USER>` / `<REDACTED>` and never appear in this repository.

---

## Theme 1 — Windows process and logon telemetry does not mean what its field names suggest

### L-01. The field called `ProcessId` means the opposite thing in 4688 and in Sysmon Event ID 1

**Expected.** Two sources describing the same process creation, both with a field named
`ProcessId`, should be joinable on that field.

**What happened.** They are not joinable. They refer to different processes and are written in
different number bases.

**Evidence** (2026-08-11, same process: `powershell.exe` running `05-b4-hijo.ps1`, captured
from the Security and Sysmon channels with `Get-WinEvent -FilterHashtable` and
`[xml]$_.ToXml()`):

| Source | Field | Value | Refers to | Base |
|---|---|---|---|---|
| Security 4688 | `NewProcessId` | `0x1250` | the created process | hex |
| Security 4688 | `ProcessId` | `0xdb4` | the **parent** | hex |
| Sysmon 1 | `ProcessId` | `4688` | the **created** process | decimal |
| Sysmon 1 | `ParentProcessId` | `3508` | the parent | decimal |

**Takeaway.** Correlating the two sources on name similarity inverts the process tree, and does
it silently: the data is correct, the report built on it is wrong, and nothing errors. Map
fields by semantics and by base before joining sources. Where both are available, the safest
join key is not a PID at all but Sysmon's `ProcessGuid`, which is never recycled.

---

### L-02. Security 4688 is missing seven things Sysmon Event ID 1 provides, and `ParentCommandLine` is the expensive one

**Expected.** With `ProcessCreationIncludeCmdLine_Enabled = 1` set by hand, native 4688 auditing
would be close enough to Sysmon for process telemetry.

**What happened.** Measured field by field on the same event, 4688 lacks: `ParentCommandLine`,
file hashes, `OriginalFileName`, the file metadata block (FileVersion / Description / Product /
Company), `CurrentDirectory`, a stable process identifier, and a readable integrity level — it
expresses integrity as the SID `MandatoryLabel S-1-16-8192`. Sysmon 1 supplied all of those,
including `OriginalFileName = PowerShell.EXE`, MD5/SHA256/IMPHASH, `ProcessGuid` and
`IntegrityLevel = Medium` in words. The traffic is not one-way: 4688 uniquely carries
`TokenElevationType` (`%%1938` = Limited). Both carry the session — 4688 `SubjectLogonId`
`0x10cce5` equals Sysmon `LogonId` `0x10cce5`.

**Evidence.** 2026-08-11 visibility exercise, a benign process tree launched with a unique
marker in the command line and then chased through both channels and the Wazuh alert index.

**Takeaway.** With only 4688 the analyst knows the parent was `cmd.exe` but not what that
`cmd.exe` was doing, and has to rebuild the chain by joining on PIDs that Windows recycles.
Sysmon's `ProcessGuid` is what ties a process to its network (Sysmon 3) and DNS (Sysmon 22)
events — in this exercise all three carried the same GUID segment. This is the concrete
argument for deploying Sysmon **in addition to** native auditing, not instead of it.

---

### L-03. Renamed system binaries are undetectable from the Security log alone

**Expected.** A renamed `powershell.exe` would be catchable by looking at the image path.

**What happened.** Both `Image` (Sysmon) and `NewProcessName` (4688) report whatever the file is
called on disk — they repeat the lie. Only Sysmon's `OriginalFileName` survives the rename: it
reported `PowerShell.EXE` for the process regardless of the file name. Security 4688 has no
equivalent field at all.

**Evidence.** 2026-08-11, `OriginalFileName = PowerShell.EXE` observed alongside `Image` in
Sysmon Event ID 1. Negative evidence for 4688: the field does not exist in the event schema.

**Takeaway.** T1036.003 (Rename System Utility) is not detectable from native Windows auditing.
This is one of the few coverage questions with a binary answer, and it is a deployment decision,
not a rule-writing decision.

---

### L-04. Event ID 4672 says the *account* is privileged, not that the *process* is elevated

**Expected.** A 4672 ("special privileges assigned to new logon") next to a logon means the
session that follows runs with administrative rights.

**What happened.** Every single `VBoxManage guestcontrol run` produced **two** 4624 events with
two different LogonIds: one with `elevatedToken %%1842` (Yes) accompanied by a 4672, and one with
`%%1843` (No) and no 4672. The processes that actually launched carried the *second* LogonId
(`0x10cce5`) and their 4688 recorded `TokenElevationType %%1938` (Limited).

**Evidence.** The pattern held on 4 out of 4 invocations with no exception, which is what the
widened window of L-19 counted as 8 × 4624 and 4 × 4672 — one pair and one 4672 each. Elevation
codes seen: `%%1936` Default (UAC does not apply, e.g. SYSTEM), `%%1937` Full, `%%1938` Limited.

**Takeaway.** This is the UAC linked token made visible in the log: Windows mints a full token
and a stripped copy for an administrator account, interactive programs start with the stripped
one, and the 4672 attaches to the full one. Reading "4672 present, therefore this activity ran
elevated" is a triage error. It also explained a real lab failure: `guestcontrol`-launched
processes carry the stripped token, so any script that checks for elevation rebounds (L-25). The
related failure to read the Security log had a different cause again — group-membership caching
in the token, which `Event Log Readers` survives perfectly well (L-24).

---

### L-05. The same sentence — "someone failed a password" — is two different stories, separable only by field

**Expected.** Ten 4625 events in one window, all with the same description, are one event type
to be counted.

**What happened.** The ten split cleanly into two groups of five that had nothing to do with
each other.

**Evidence** (2026-08-08 exercise):

| | Group A | Group B |
|---|---|---|
| `logonType` | 2 (interactive) | 3 (network) |
| `logonProcessName` | `seclogo` (the runas service) | `NtLmSsp` |
| `authenticationPackage` | Negotiate | NTLM |
| `ipAddress` | `::1` | `10.10.10.5` |
| `workstationName` | `WIN11-VICTIMA` | `KALI` |
| Target account | `usuario-fantasma` | `fantasma` |
| Actually was | local `runas` attempts | `smbclient` from the attacker VM |

All ten carried `subStatus 0xC0000064`.

**Takeaway.** If you are not reading `logonType`, `ipAddress` and `logonProcessName`, you are
counting alerts rather than triaging them. A type 3 from an address that should never
authenticate is an indicator; a type 2 is usually a user mistyping.

---

### L-06. `LogonId` is the thread that turns one alert into an investigation

**Expected.** Answering "what did they do after getting in" would require correlating on user
name and time.

**What happened.** There is a mechanical answer: the LogonId is stamped on the session and on
everything the session does.

**Evidence** (traced end to end on lab data, 2026-08-11): 4624 `TargetLogonId = 0x10cce5`
(session created) → 4688 `SubjectLogonId = 0x10cce5` for `cmd.exe`, `powershell.exe` and
`whoami.exe` → Sysmon 1 `LogonId = 0x10cce5` on the same processes → 4634 `TargetLogonId =
0x10cce5` (session closed). Fixed values worth memorising: `0x3e7` SYSTEM, `0x3e4` NETWORK
SERVICE, `0x3e5` LOCAL SERVICE.

**Takeaway.** Take the LogonId from the suspicious 4624 and filter every event carrying it. That
single pivot is the difference between reporting an alert and reporting a session.

---

### L-07. A logon type 2 does not imply a human at the keyboard; `logonProcessName` is the field that says so

**Expected.** Type 2 = Interactive = someone physically logged on.

**What happened.** The lab produced type 2 logons with nobody at the keyboard, generated by
commands issued from the host through VirtualBox.

**Evidence.** 4624 with `targetUserName = <LAB_USER>`, `logonType = 2`, `logonProcessName =
Advapi`, `authenticationPackageName = MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, `processName =
C:\Windows\System32\VBoxService.exe`, `subjectUserName = WIN11-VICTIMA$` with
`subjectLogonId 0x3e7` (SYSTEM). A genuine console logon shows `logonProcessName` `User32` /
`Winlogon`.

**Takeaway.** `Advapi` means a program called `LogonUser()` on its own behalf. Legitimate agents
do it; so do offensive tools. On an end-user workstation, `Advapi` inside a type 2 deserves a
question. It also explains why `LocalAccountTokenFilterPolicy=1` changed nothing here: that key
only affects network (type 3) logons.

---

## Theme 2 — Authentication telemetry: the fields that separate noise from an attack

### L-08. `SubStatus` is where blind spraying becomes a targeted attack, and lockout policy is blind to the first half

**Expected.** Failed-logon volume plus account lockout policy would be enough to characterise a
password attack.

**What happened.** The volume told one story and the `SubStatus` field told a much more precise
one.

**Evidence** (2026-09-07, 18 authentication attempts from 10.10.10.5, all with
`Status 0xC000006D`):

| Phase | Count | SubStatus | Meaning | Window |
|---|---|---|---|---|
| Enumeration | 15 × 4625 | `0xC0000064` | account does not exist | 18:30:10–18:30:43 |
| Targeted | 3 × 4625 | `0xC000006A` | account exists, wrong password | 18:31:13–18:31:16 |

The account names tried in the first phase were generic (`admin`, `administrador`, `backup`,
`sqlsvc`, `helpdesk`). The local lockout threshold is 10 attempts / 10 minutes, so those 15
attempts were free: lockout only counts failures against accounts that exist.
`WorkstationName` was empty (`-`) on all 18 — which distinguishes `netexec` from `smbclient`,
not Linux from Windows: L-05 above records `smbclient`, on the same Kali VM against the same
endpoint, filling that field with `KALI`. An empty `WorkstationName` is a tool fingerprint worth
chasing, not an attribution.

**Takeaway.** The transition `0xC0000064` → `0xC000006A` is the moment the attacker stops
shooting blind, and it is the more serious of the two events even though it is the quieter one.
Any brute-force correlation rule that ignores `SubStatus` cannot tell fifteen guesses at five
imaginary users from one employee who forgot their password.

---

### L-09. With NLA enabled, a failed RDP login is logon type 3, not type 10

**Expected.** "RDP brute force = 4625 with logon type 10" — the rule of thumb in most tutorials.

**What happened.** Four failed RDP attempts produced 4625 events with **logon type 3**. Two
authentication-only connections produced 4624 type 3 plus TS-RemoteConnectionManager EID 1149,
still no type 10. The only type 10 in the whole exercise appeared when a full graphical session
actually established.

**Evidence** (2026-09-07): failures at 18:33:28–18:33:29 (type 3); `+auth-only` connections at
18:33:30–18:33:31 (4624 type 3 + 1149); the real session at 18:35:09 — 4624 type 10,
`AuthenticationPackage Negotiate`, `LogonProcessName User32`, accompanied by
TerminalServices-LocalSessionManager 41 → 42 → 21 (session logon) → 22 (shell start
notification). The 24 and 40 of that exercise came later, at 18:36:49, when the session was
disconnected: they are the teardown pair, not part of the establishment. EID 22 is not a
reconnection, whatever the tutorials say — reconnection is EID 25, and this lab has never
produced one. Forcing a type 10 headlessly
required `timeout 90 xvfb-run -a xfreerdp /v:... /cert:ignore /w:1280 /h:800`; under roughly 60
seconds the session is cut before logon completes and only EID 1149 plus a disconnect 40 remain.

**Takeaway.** Network Level Authentication moves authentication in front of session creation, so
an RDP failure is indistinguishable from an SMB failure by logon type alone — and NLA is the
default. A detection keyed on type 10 misses exactly the hosts that are configured correctly.
The fix is corroboration: correlate 4625 type 3 with the TerminalServices channels, which do
carry the RDP context (`Source Network Address 10.10.10.5`).

---

### L-10. A mitigation working correctly can look like a network fault to the attacker and like attacker tempo to the analyst

**Expected.** A wrong password over SMB returns a wrong-password error.

**What happened.** The attacker tool reported *"The NETBIOS connection with the remote host
timed out"* — which reads like a routing or firewall problem, not a failed credential. On the
defender side the failures arrived spaced roughly 2 seconds apart.

**Evidence** (2026-09-07). `Get-SmbServerConfiguration` on the endpoint returned
`EnableAuthRateLimiter = True` and `InvalidAuthenticationDelayTimeInMs = 2000`, both defaults on
Windows 11 24H2 and later. All 4625 events were still generated normally; only the pacing
changed.

**Takeaway.** Two lessons in one. Offensively, a timeout is not proof that a service is
unreachable. Defensively, the ~2 s spacing in the timeline is a fingerprint of *the mitigation*,
not of the attacker's tooling — reading it as attacker behaviour builds a wrong profile. And the
control only slows the attack: one attempt per hour evades it entirely, which is why 4625 events
must also be grouped by source IP over long windows (24 h), not only over the five-minute
windows that correlation rules default to.

---

## Theme 3 — Three clocks, and none of them is the one the dashboard shows

### L-11. The Wazuh `@timestamp` is the manager's clock and lags the endpoint by about 1.8 seconds

**Expected.** The dashboard's time axis is when the event happened.

**What happened.** It is when the manager processed it.

**Evidence.** Measured on the same `eventRecordID` (31476, `cmd.exe` creation): endpoint
`TimeCreated` / `data.win.system.systemTime` = `17:22:36.6840621Z`, Wazuh `@timestamp` =
`17:22:34.930Z`. Delta −1.754 s. Across three consecutive records: −1.754 s / −1.821 s /
−1.757 s — consistent, so it is a clock offset, not jitter.

**Takeaway.** Filtering for "what happened at 17:22:36" on the default axis returns events
Windows recorded at 17:22:38. In a multi-source investigation that silently reorders the facts.
Pin queries to `data.win.system.systemTime`. And configure NTP — this stops being a nuisance and
becomes a failure the moment a domain controller joins the lab, since Kerberos rejects skew above
5 minutes.

---

### L-12. Inside Sysmon, network and DNS events are written to the channel seconds after they occur

**Expected.** An event's `TimeCreated` is when the thing happened.

**What happened.** For Sysmon Event IDs 3 and 22 it is when the record was written, which is
3–4 seconds later.

**Evidence** (2026-08-11): Sysmon 22 (DNS) `TimeCreated 17:22:40.464` vs its own `UtcTime` field
`17:22:37.222` — a 3.2 s gap. Sysmon 3 (network) `TimeCreated 17:22:41.163` vs `UtcTime
17:22:37.162` — 4.0 s. Sorting by `TimeCreated` placed the DNS query *after* `whoami.exe`
(17:22:38.7), which is false; the query came first.

**Takeaway.** For Sysmon 3 and 22, read the event's own `UtcTime`. A timeline built on the
channel timestamp reverses cause and effect, and cause and effect is the entire output of an
investigation.

---

## Theme 4 — Coverage: a SIEM stores what its rules recognise, not what happened

### L-13. Coverage has three layers, and a hole in the third one is invisible

**Expected.** If an event is audited and the agent ships the channel, the event is searchable.

**What happened.** Security Event ID 4697 ("a service was installed") is generated, is expected
to be collected, and never becomes an alert, because no default rule matches it.

**Evidence** (2026-08-08). `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697}`
returned the event at 21:44:56 local, inside the exercise window; the Security channel is
declared in the agent's `ossec.conf` and the agent reported `connected`; a query of
`wazuh-alerts-*` returned **0** documents with Event ID 4697. The same real-world fact — a
service was installed — did alert, via Event ID 7045 from the System channel.

**The limit of that evidence.** Layer 2 here is inferred, not counted. Wazuh indexes only what
matched a rule, so an empty alert index looks identical whether the agent never shipped the event
or shipped it to a ruleset that ignored it. Settling that takes a manager-side count of arriving
events — `logall_json` archives, or the agent's own send counter — and this lab has not produced
one for that channel. The conclusion below survives either way (nothing is searchable), but a
claim that the failure is specifically at layer 3 is a claim this evidence does not carry on its
own.

**Takeaway.** Generation / collection / detection are three independent layers. A failure in
generation or collection tends to show up eventually as an error somewhere; a failure in
detection produces no error, no missing-data indicator and nothing to search for. The only way to
find it is to cause the event deliberately and check whether it arrives. That is the argument for
adversary emulation as routine maintenance rather than as a one-off exercise.

---

### L-14. The funnel is lossy, and absence of an alert is not absence of activity

**Expected.** Searching the alert index answers "did this happen on the endpoint".

**What happened.** It answers "did a rule fire on this", which is a much smaller question.

**Evidence.** 2026-08-08 exercise: the agent reported roughly 2,100 events to the manager (the
B2 verification counted 2,098 sent) and 835 alerts for that endpoint remained in the index —
more than half of the telemetry never became queryable, because it matched no rule at
level ≥ 3. The 2026-08-11 exercise measured the same shape at smaller scale: **167 events
generated → 27 alerts** over the narrow observation window, or **172 → 36** once the two rows
that window cut in half are recounted (L-19). Neither total is settled — the Sysmon 11 row inside
both is 4 generated against 5 alerted, which a single-event rule cannot produce and which has not
been recounted.

**Takeaway.** Any coverage claim based on searching the alert index is bounded by the ruleset,
not by what the endpoint produced. When a question really matters, go to the channel on the
endpoint, not only to the SIEM.

---

### L-15. Native auditing gave coverage plus noise; Sysmon gave signal only where a rule was looking

**Expected.** Sysmon, being richer, would produce more alerts than the Security log.

**What happened.** The inverse, and for structural reasons.

**Evidence** (2026-08-11, per channel — generated / alerted). The counts are given on the narrow
observation window first, because that is the window the original tables were built on, with the
widened 17:22:20–17:23:00 figures beside them where the two differ:

| Source | Generated | Alerted | Rule |
|---|---|---|---|
| Security 4688 process created | 16 | 16 | 67027, level 3 (catch-all) |
| Security 4689 process terminated | 12 | 0 | — |
| Security 4624 logon | 4 → **8** | 2 → **8** | 60118, level 3 (narrow window halved the pairs — L-19) |
| Security 4634 logoff | 2 | 2 | 67023, level 3 |
| Security 4672 special privileges | 3 → **4** | 1 → **4** | 67028, level 3 (same window artefact) |
| Security 4648 explicit credentials | 1 | 0 | — |
| Security 4798 + 4799 group enumeration | 2 | 0 | — |
| Sysmon 1 process create | 11 | 1 | 92004, level 4 |
| Sysmon 3 network connection | 1 | 0 | — |
| Sysmon 11 file created | 4 | 5 (?) | 92213, level 15 — see the note below the table |
| Sysmon 22 DNS query | 1 | 0 | — |
| PowerShell 4103 / 4104 / other | 110 | 0 | — |

**Note on the Sysmon 11 row.** 4 events generated and 5 alerts is arithmetically impossible for a
single-event rule like 92213, which fires once per Sysmon 11. Something in that row is miscounted
and it has not been recounted. It is left visible rather than quietly corrected, because a table
that hides its own bad cell is worse than one that flags it.

**Takeaway.** Rule 67027 alerts on every process creation at level 3 — coverage bought with
noise. The single Sysmon 1 alert fired on a *pattern* (`powershell` → `cmd`, rule 92004
"Powershell process spawned Windows command shell instance"), not on process creation itself.
Richer telemetry does not detect anything by existing; 110 PowerShell script-block events sat in
the index with zero rules pointed at them.

---

### L-16. Severity is an opinion held by whoever wrote the rule; it is not a priority

**Expected.** Working a queue from the highest severity down is a reasonable triage strategy.

**What happened.** The top of the queue was consistently the least interesting thing in it.

**Evidence.** The 2026-08-08 verification produced 82 alerts across its three phases
(00:44:48Z–00:49:14Z: an 8-second generator script, an 88-second port scan, then five SMB logon
failures), level distribution 3→53, 4→7, 5→13, 8→5, 12→3, 15→1. The single level 15 was rule
92213 ("Executable file dropped in folder commonly used by malware", mapped to T1105) firing on
`C:\Users\<LAB_USER>\AppData\Local\Temp\__PSScriptPolicyTest_<random>.ps1` — a file written by a
signed `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` to test its own execution
policy. Reproduced ×5 on 2026-08-11 and ×12 on 2026-09-07. Meanwhile the simulated intrusion
that mattered — a local user created, added to Administrators and deleted inside 8 seconds
(4720 → 4732 → 4726) — surfaced at levels 8 and 12, below the noise. In the 2026-09-07 exercise
the single most informative alert of the reconnaissance phase was the ANONYMOUS LOGON SMB null
session at **level 6** (rule 92652), while twelve level 15s in the same window were the same
false positive.

**Takeaway.** Severity measures how bad the event would be if it were real, not the probability
that it is real. An untuned level-15 rule that fires 12 times on legitimate behaviour teaches
analysts to ignore level 15, which is precisely the failure mode that lets a real incident
through. Tuning is not cosmetic work.

---

### L-17. Discovery commands cannot be detected one at a time

**Expected.** `whoami` — usually the first thing an intruder runs — would stand out.

**What happened.** It produced a 4688 matched by catch-all rule 67027 at level 3, byte for byte
the same treatment as `sppsvc.exe`. No Sysmon rule fired on it either. Events 4648
(explicit-credential logon) and 4798/4799 (enumeration of a user's local group membership —
literally what SharpHound does) produced no alert at all, despite existing in the log and
reaching the SIEM.

**Evidence.** 2026-08-11 counts above; the 4648 and 4798/4799 zeros were re-confirmed against a
widened time window before being reported.

**Takeaway.** A single discovery command is genuinely indistinguishable from background noise,
and no amount of rule tuning changes that. It has to be detected as a sequence — several
discovery binaries under the same parent or the same `SubjectLogonId` inside a short interval.
Knowing *which* gaps are single-event gaps and which are sequence gaps decides whether the fix
is a rule or a correlation.

---

### L-18. A scan left no host record — and the reason is the audit configuration, not Windows

**Expected.** A full port scan against a monitored endpoint would produce something.

**What happened.** `nmap -sS -p- -T4 10.10.10.20` ran 88 seconds (00:47:17Z–00:48:45Z), found 8
open ports and 65,527 filtered, and produced **zero** attributable alerts. Six alerts fell inside
the window and all six were unrelated background 4688 events.

**Evidence.** Repeated on 2026-09-07 at smaller scale: an `-sS -sV` scan of 7 ports left 2 Sysmon
Event ID 3 records (inbound to `:3389` from 10.10.10.5, `Initiated=false`) and 0 Security 5156
events, because the Filtering Platform Connection subcategory is deliberately not audited — it is
very high volume.

**Correcting my own conclusion.** I first wrote this lesson as "Windows does not log a SYN to a
closed port anywhere". That is wrong, and it was the weakest sentence in this repository. The
65,527 ports nmap reported *filtered* are packets the host
firewall dropped, and Windows does have a subcategory for exactly that: *Audit Filtering Platform
Packet Drop*, Security **5152** / 5153. It is one of the ones this endpoint leaves off — the
baseline enables ten subcategories and Packet Drop is not among them, for volume. So the measured
fact is narrower than the claim: *with the subcategories this endpoint enables*, nothing recorded
the scan. What Packet Drop would have produced under an 88-second full-port sweep has never been
measured here, because it has never been enabled. Note too that 5156 — which I originally named
as the fix — is *a connection was permitted*; it covers the 8 open ports, never the 65,527
filtered ones.

**Takeaway.** A gap caused by a switch that is off is a **configuration** gap, and calling it
structural hides a fix that costs one `auditpol` line. Only the part a host agent genuinely
cannot see — payloads, sessions, every host that is not this one — is the architecture gap that
needs a network sensor on the segment. The broader lesson is about how the claim was phrased: an
absolute about what an operating system "does not log" is a statement about a product, and it
should never be written from what one lab happened to have turned on. Recognising which layer a
gap lives in is what keeps a remediation plan from being a list of rules that can never work, and
that only works if the layer is read off the configuration instead of assumed.

---

## Theme 5 — Analytical discipline

### L-19. Before declaring a coverage gap, widen the window

**Expected.** 4 × 4624 generated with 2 alerted, and 3 × 4672 with 1 alerted, looked like a
filtering gap worth reporting.

**What happened.** It was an artefact of the analyst's own time range. Widening to
17:22:20–17:23:00 showed 8 × 4624 and 4 × 4672, every one of them alerting individually. Each
`guestcontrol` invocation produces a *pair* of 4624 events (see L-04) and the pairs were being
cut in half by the window boundary.

**Evidence.** Re-run of the same OpenSearch query with only the range clause changed.

**Takeaway.** A false gap in a coverage report costs as much credibility as a false positive
costs an analyst's shift. The method rule extracted from this: widen the window before writing
anything down. Only the gaps that survived the widened window (4648, 4798/4799, Sysmon 3,
Sysmon 22) were reported as real.

---

### L-20. Searching a SIEM is not `grep`

**Expected.** A free-text search for a unique marker string would find the documents containing
it.

**What happened.** A `query_string` search for the marker `B4MARCA202608111422` returned 0
results, while the string was sitting in `data.win.eventdata.commandLine` in indexed documents.
The query that worked targeted the field directly (for example a `terms` filter on
`data.win.system.eventRecordID`).

**Evidence.** 2026-08-11, both queries run through the dashboard console proxy against
`wazuh-alerts-*`.

**Takeaway.** Field names and index analysis decide what is findable. An analyst who assumes
free-text search works will conclude the evidence does not exist when it is in front of them —
the same failure mode as L-13, one layer up.

---

### L-21. Reading the process tree exposed a defect in my own tooling that the command output hid

**Expected.** One script launched from the host, one `powershell.exe` in the tree.

**What happened.** The captured tree showed **two**: `powershell.exe -NoProfile ... -File
C:\lab\04-b4-generar.ps1` spawning `"powershell.exe" -NoProfile ... -File
C:\lab\04-b4-generar.ps1`. Cause: `VBoxManage guestcontrol run --` adds its own `argv[0]`, so
PowerShell received `powershell.exe` as its first argument, treated it as `-Command`, and
relaunched itself. The command returned correct output; nothing was visible from outside.

**Evidence.** 2026-08-11 process tree reconstruction. Follow-up measurement (2026-09-07, VBox
7.2.6): the behaviour is not the same across guest operating systems — on Windows the binary
name must be repeated after `--`, on Linux it must not, or bash receives `/usr/bin/bash` as a
script name and answers *"cannot execute binary file"*.

**Takeaway.** This is what a process tree is *for*, demonstrated on my own infrastructure: the
output was right and the execution was wrong. Platform-specific invocation behaviour has to be
tested with a trivial script that prints its arguments, never assumed from documentation.

---

### L-22. Writing the explanation out found the gaps before the exam did

**Expected.** Reading and understanding the Security+ Domain 1 material was enough to sit a
diagnostic.

**What happened.** The first SY0-701 diagnostic (ExamCompass Practice Test 1, objectives 1.1 and
1.2, 2026-08-08) scored **52 % real (13/25)**, not the 74.58 % the site displayed — CompTIA
scores multiple-response items all-or-nothing and there is no partial credit. The split was 82 %
on definitions and 29 % on classifying examples, which is what the exam actually asks. Root
cause: control *category* and control *type* were being held as one flat list instead of two
independent axes.

**Evidence.** All 5 blanks left unfilled in my own Domain 1 notes corresponded to 5 failed
questions — 5 for 5.

**Takeaway.** An unfinished explanation in your own words is a located knowledge gap, and it
shows up later as a wrong answer with perfect reliability. The same method is what the lab
writeups use: state the prediction in writing *before* looking at the data, because a falsified
prediction points at exactly what you did not understand. In the 2026-08-11 exercise all four
stated hypotheses were falsified, which is why that exercise produced anything worth writing down.

---

### L-23. Before concluding the data is wrong, check the tool's defaults

**Expected.** 213 self-authored Anki cards — objective 1.1, the seven videos of 1.2, and 1.3 as
far as Change Management — would present as the full spread of topics once imported.

**What happened.** Only the first 20 cards surfaced, all from objective 1.1, which looked like a
content error. Anki's default is 20 new cards per day per deck. Fix: split into one sub-deck per
video — ten of them across the two files (55 cards for 1.1, 158 in nine sub-decks for the rest).

**Takeaway.** Trivial in itself, but the same shape as L-13: the data was present and the
presentation layer made it invisible, and the reasonable-looking conclusion ("content is
missing") was wrong. The identical reflex belongs in front of a SIEM dashboard — default time
range, default index pattern, default result limit.

---

## Theme 6 — Building and automating the lab

### L-24. Group membership needed to read the Security log lives in the token, not in the SAM

**Expected.** Adding the lab account to `Event Log Readers` would immediately let host-launched
processes read the Security and Sysmon channels without making the account an administrator.

**What happened.** `net localgroup "Event Log Readers" <LAB_USER> /add`, run from an elevated
terminal, made `Get-LocalGroupMember` show the membership instantly — while
`guestcontrol`-launched processes kept failing with *"Attempted to perform an unauthorized
operation"*. `VBoxManage guestcontrol closesession --all` did not refresh it. Only rebooting the
VM did.

**Evidence.** Resolved 2026-08-11. This is group-membership caching in the token, not UAC
filtering: `Event Log Readers` survives the filtered token fine. The Sysmon channel already ships
the ACE `(A;;0x1;;;S-1-5-32-573)` from the factory, so no SDDL change was needed. After the
reboot the collection scripts ran end to end over `guestcontrol`.

**Takeaway.** Group-based log access on Windows takes effect only when the token is reissued.
Directly relevant outside a lab: granting a service account read access to Security without
making it an administrator is the right design, and it will appear not to work until the next
logon.

---

### L-25. `guestcontrol run` does not hand out an elevated token, and the registry workaround everyone reaches for addresses a different logon type

**Expected.** Since `<LAB_USER>` is in the local Administrators group, host-launched commands
would run elevated.

**What happened.** `whoami /groups` inside a `guestcontrol`-launched process showed
`BUILTIN\Administrators` as *"Group used for deny only"* and `Medium Mandatory Level`. Setting
`LocalAccountTokenFilterPolicy=1` changed nothing (tested and reverted): that key applies only to
network logons, and VirtualBox performs an interactive logon.

**Evidence.** Verified 2026-08-08. The path that worked was to open a single elevated terminal by
injecting scancodes (`Win+X` = `e0 5b 2d ad e0 db`, then `A` = `1e 9e`, then `Alt+Y` =
`38 15 95 b8` at the UAC prompt, because the default UAC button is **No**) and drive it with
`keyboardputstring`, capturing output with `Start-Transcript` to a world-readable file in
`C:\lab` retrieved afterwards with `guestcontrol copyfrom`.

**Takeaway.** The same mechanism that stops an attacker elevating silently (L-04) stops
legitimate automation, and the first workaround the internet offers solves a different problem.
Read what a setting actually applies to before concluding it is broken.

---

### L-26. A logging-configuration script that appears to run is not a logging configuration

**Expected.** Wrapping the telemetry baseline script as `script *>&1 | Tee-Object` would capture
its output.

**What happened.** In PowerShell 5.1 that construction turns any *native executable's* stderr
into an `ErrorRecord`. With `$ErrorActionPreference='Stop'`, `01-telemetria-win11.ps1` aborted at
step 6: steps 1–5 applied, and `Sysmon64.exe -i` never installed the service — with no obvious
error.

**Evidence.** Reproduced and fixed by replacing the wrapper with `Start-Transcript`.

**Takeaway.** A partially applied telemetry baseline is worse than none, because the analyst
believes Sysmon is running when it is not — a silent blind spot that looks like a quiet endpoint.
Any script that configures logging must be verified by its **end state** (`Get-Service Sysmon64`
= Running, events actually present in the channel), never by the fact that it appeared to run.

---

### L-27. `curl -sO` will save the error page as the installer

**Expected.** Vendor download paths follow a predictable pattern, and a download either works or
fails loudly.

**What happened.** Neither. The Wazuh manager installer lives at
`packages.wazuh.com/4.14/wazuh-install.sh` — the generic `4.x/` path returns 403 — while the
Windows agent MSI lives at `packages.wazuh.com/4.x/windows/...` and the `4.14/windows/` path
returns 403. Exactly opposite conventions on the same site (verified 2026-07-31 and 2026-08-07).
Separately, `curl -sO` stored an HTTP 403 XML body under the script's filename, and bash then
failed with *"syntax error near unexpected token `newline`"* on a line reading
`<?xml version="1.0"...>`.

**Takeaway.** The symptom (a shell syntax error inside a vendor script) pointed nowhere near the
cause (an HTTP 403 saved to disk). `curl -fsSLO` fails on HTTP errors instead of writing them to
a file, which converts a silent corruption into a loud failure. Test the path; do not deduce it.

---

### L-28. A port that completes a TCP handshake is not a service

**Expected.** The reported symptom — "the SSH password is wrong" on `127.0.0.1:2222` — was a
credentials problem.

**What happened.** OpenSSH had never been installed on the SIEM. The connection still completed
because the VirtualBox NAT proxy, not the VM, answers on the forwarded port; the session hung
without ever prompting. Behind that, the VM had no address at all: `ip -4 a` showed only `lo`,
and `ip link` showed `enp0s3` enslaved to a `bond0` that the Ubuntu installer had created
silently around a single NIC and that never obtained an address.

**Evidence.** 2026-07-29. Fix: rewrite `/etc/netplan/50-cloud-init.yaml` with `enp0s3` and static
`10.10.10.10/24`, disable cloud-init network regeneration via `99-disable-network-config.cfg`,
`netplan apply`, then `apt install -y openssh-server && systemctl enable --now ssh`.

**Takeaway.** The reported symptom sat two layers away from the cause. Checking for the
`SSH-2.0-OpenSSH` banner rather than for "port open" is the difference between a scan that
informs and a scan that lies — and that is the same reasoning applied to reading `nmap` output
during triage, where "open" means a handshake completed and nothing more.

---

### L-29. The Wazuh indexer cannot be reached by port forwarding; the dashboard console proxy can

**Expected.** Adding a NAT port-forward to 9200 would allow scripted queries from the host.

**What happened.** It fails with `curl` error 35 (TLS), because the indexer listens on 9200 only
on `localhost` inside the SIEM VM. The working path is the dashboard's console proxy, already
exposed on 8443, which accepts basic auth:

```bash
curl -k -u admin:<REDACTED> -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query.json
```

**Takeaway.** Small operational detail with a large effect on method: it made SIEM queries
scripted, repeatable and diffable between exercises instead of manual dashboard clicking. Every
count in this repository comes from a saved JSON query rather than from a screenshot.

---

## Theme 7 — Reading ATT&CK from the mitigation side

### L-30. The number of mitigations a technique carries is itself a signal

**Expected.** Detection is where ATT&CK is useful; mitigations are somebody else's column.

**What happened.** Reading five techniques through their mitigations (2026-07-31, ATT&CK v18)
turned out to predict how much work lands on the SOC.

**Evidence.** Mitigation counts: T1036.004 Masquerade Task or Service = **0** (the page states
the technique cannot easily be mitigated with preventive controls because it abuses legitimate
system features); T1659 Content Injection = 2; T1684.002 Email Spoofing = 3; T1548.002 Bypass
UAC = 4; T1059 Command and Scripting Interpreter = **11**. Fourteen distinct `M####` mitigations
were catalogued from these five and classified as *eliminates* / *reduces* / *visibility only*.

**Takeaway.** Zero mitigations means "this is detected, not prevented" — the whole problem lands
on the analyst. Eleven mitigations is not the opposite of well defended: it means the attack
surface is large enough to need eleven angles and still leaves a gap. And M1047 *Audit* is not a
control at all; it is an instruction to go and look, which is work assigned to the SOC.

---

### L-31. The strongest mitigation available fails for organisational reasons, and that gap is the job description

**Expected.** A technique with a mitigation that eliminates it is a solved problem.

**What happened.** For T1548.002 (Bypass UAC) the four mitigations are M1047 Audit, M1026
Privileged Account Management, M1051 Update Software and M1052 User Account Control. M1026 closes
the technique outright — every UAC bypass presupposes the account is already in local
Administrators, so removing it eliminates the attack — and it is the one organisations resist
most. Microsoft's own position is that UAC is not a security boundary, which makes M1051 an
unending patch race. Contrast T1659, where M1041 (encrypt traffic end to end) eliminates the
technique architecturally and leaves nothing to detect.

**Takeaway.** Sorting techniques by whether the fix is architectural (encrypt it and forget it),
organisational (remove local admin, which people push back on) or purely detective (T1036.004,
zero mitigations) is what decides whether a problem belongs to engineering or to operations. The
space between "the control exists" and "the control is applied" is where a SOC works — and in
this lab it was measurable: the UAC linked-token mechanism T1548.002 abuses is exactly what L-04
captured in the logs.

---

## What these lessons changed in the lab

| Lesson | Change made or queued |
|---|---|
| L-01, L-02 | Correlation keyed on `ProcessGuid` / `LogonId`, never on a bare PID |
| L-08, L-09, L-10 | Brute-force detection must read `SubStatus`, corroborate RDP with the TerminalServices channels, and include a 24 h window grouped by source IP |
| L-11, L-12 | Every query pinned to `data.win.system.systemTime`, and to `UtcTime` for Sysmon 3 and 22; NTP on both VMs is queued before the domain controller is built |
| L-13, L-14, L-18 | Gaps classified by layer (generation / collection / detection) before any remediation is proposed, and a gap traced to a disabled audit subcategory recorded as configuration rather than as structure — see [03-detection-gap-analysis.md](03-detection-gap-analysis.md) |
| L-18 | Two audit subcategories queued for a measured trial: *Filtering Platform Packet Drop* (5152/5153) against a repeat of the 88-second scan, and *Credential Validation* (4776) against a repeat of the NTLM run |
| L-16 | Rule 92213 marked for tuning; until then, level 15 carries no information in this lab |
| L-19 | Widen the window before reporting any gap |
| L-24, L-25, L-26 | Telemetry scripts verified by end state; log access granted by group plus a reboot, not by elevation |
