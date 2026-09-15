# Detection gap analysis

Every gap below was found by generating the activity on purpose in my own lab and then checking
whether it survived to the alert index. None of them is theoretical, and none was taken from a
vendor coverage matrix.

**The three layers.** A gap is only useful if you know which layer it lives in, because the fix
is different at each one:

| Layer | Question it answers | Symptom when it fails |
|---|---|---|
| **Generation** | Does the operating system write the event at all? | Nothing in the channel. Findable with `Get-WinEvent` on the endpoint. |
| **Collection** | Does the agent ship that channel to the SIEM? | Event on the endpoint, nothing in the index — which is also the symptom of a detection failure. |
| **Detection** | Does a rule match it once it arrives? | **No symptom at all.** No error, no missing-data indicator, nothing to search for. |

The third layer is the dangerous one. A detection gap is invisible from the dashboard by
definition: the only way to find it is to cause the event deliberately and go looking for the
alert that never came.

One limitation of that table, stated up front. Wazuh indexes only what matched a rule, so an
empty alert index cannot by itself separate layer 2 from layer 3. Everything called a detection
gap below rests on the channel being declared in the agent's `ossec.conf` and the agent reporting
`connected`: collection is expected, not independently counted. Separating the two layers
properly needs something the alert index does not hold — a count of events arriving at the
manager. That measurement is not in this repository.

Lab under measurement: Windows 11 Pro build 10.0.26200 endpoint (`10.10.10.20`) with advanced
audit policy, command line in 4688, PowerShell ScriptBlockLogging and ModuleLogging, and Sysmon
with the SwiftOnSecurity configuration; Wazuh 4.14.7 all-in-one on Ubuntu Server 24.04.4
(`10.10.10.10`); Kali as attacker (`10.10.10.5`) on the VirtualBox NAT network `SOCLAB`
(10.10.10.0/24). Credentials are referred to as `<LAB_USER>` and never appear in this repository.

---

## Summary

| ID | Gap | Layer | Measured evidence | Fix belongs to | Sigma rule in this repo |
|---|---|---|---|---|---|
| G-01 | Security 4697 (service installed) never becomes an alert | Detection | 4697 present in the Security log, 0 documents in `wazuh-alerts-*` | A rule | [`win_security_susp_service_installation.yml`](../detections/sigma/win_security_susp_service_installation.yml) |
| G-02 | Sysmon Event ID 3 (network connection) has zero coverage | Detection | 1 generated / 0 alerted (B4); 2 generated / 0 alerted (2026-09-07) | A rule | [`net_connection_win_script_interpreter_external_dest.yml`](../detections/sigma/net_connection_win_script_interpreter_external_dest.yml) |
| G-03 | Sysmon Event ID 22 (DNS query) has zero coverage | Detection | 1 generated / 0 alerted (B4) | A rule | [`dns_query_win_unexpected_process.yml`](../detections/sigma/dns_query_win_unexpected_process.yml) |
| G-04 | Security 4648 (explicit credentials) produces no alert | Detection | 1 generated / 0 alerted, confirmed on a widened window | A rule | — (proposed logic below) |
| G-05 | Security 4798 / 4799 (local group enumeration) produce no alert | Detection | 2 generated / 0 alerted, confirmed on a widened window | A correlation | — (proposed logic below) |
| G-06 | Discovery commands are swept up by a catch-all 4688 rule at level 3 | Detection | `whoami.exe` treated identically to `sppsvc.exe` (rule 67027, level 3) | A correlation | [`proc_creation_win_lolbin_discovery_burst.yml`](../detections/sigma/proc_creation_win_lolbin_discovery_burst.yml) |
| G-07 | Port scans leave no record with the audit subcategories this endpoint has enabled | Generation (by configuration) | 65,535-port scan, 88 s, **0** attributable alerts | Audit configuration, then architecture (network sensor) | — (no rule can close it as configured) |
| G-08 | Password spraying is not separable from ordinary failed logons | Detection | Rule 60204 accumulates 60122 events but never reads `SubStatus` | A rule | [`win_security_password_spray_nonexistent_accounts.yml`](../detections/sigma/win_security_password_spray_nonexistent_accounts.yml), [`win_security_targeted_password_guessing_valid_account.yml`](../detections/sigma/win_security_targeted_password_guessing_valid_account.yml) |
| G-09 | Rule 92213 fires at level 15 on benign PowerShell behaviour | Detection | Same false positive ×1, ×5 and ×12 on three separate dates | Tuning | [`file_event_win_executable_dropped_excluding_psscriptpolicytest.yml`](../detections/sigma/file_event_win_executable_dropped_excluding_psscriptpolicytest.yml) |
| G-10 | Security 1102 (audit log cleared) has never been generated, so its path is untested | Generation | The only one of twelve priority Event IDs with no lab data | A lab exercise | — (test first, then rule) |
| G-11 | RDP failure detection has no listener-side corroboration | Detection | 4 failed RDP logins arrived as 4625 **type 3**, not type 10 | A correlation | [`win_security_rdp_bruteforce_behind_nla.yml`](../detections/sigma/win_security_rdp_bruteforce_behind_nla.yml), [`win_security_successful_interactive_rdp_session.yml`](../detections/sigma/win_security_successful_interactive_rdp_session.yml) |
| G-12 | No time synchronisation between endpoint and SIEM | Collection | −1.8 s manager offset; 3–4 s channel-write lag inside Sysmon 3 and 22 | Configuration (NTP) | — (not a rule) |

Three further rules in `detections/sigma/` do not close a gap listed here. One reproduces a
detection that already worked but was carried by an unexpected source
([`proc_creation_win_encoded_powershell.yml`](../detections/sigma/proc_creation_win_encoded_powershell.yml)).
One covers an ancestry pattern the default ruleset only partially reaches
([`proc_creation_win_office_browser_spawning_shell.yml`](../detections/sigma/proc_creation_win_office_browser_spawning_shell.yml)).
One reimplements, as portable Sigma, the single most informative alert of the 2026-09-07
reconnaissance phase
([`win_security_anonymous_logon_smb_null_session.yml`](../detections/sigma/win_security_anonymous_logon_smb_null_session.yml)) —
see G-07.

That is 12 files holding 21 rule documents, 7 of them correlations. Read the "Sigma rule in this
repo" column above as *drafted*: all 21 parse cleanly under `sigma check` and convert under at
least one backend, and none has been deployed to the lab manager, so none has ever matched a live
event. A rule listed against a gap is a proposed answer to it, not a closed gap.

---

## G-01 — Security Event ID 4697 is generated, collected, and matched by nothing

**Layer:** detection.

**Evidence.** `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697}` returned
*"4697 A service was installed in the system"* at 2026-08-08 21:44:56 local, inside the exercise
window. The Security channel is declared in the agent's `ossec.conf` and the agent reported
`connected`, so collection is expected — though it was not counted independently, for the reason
given under the three layers above.
A query of `wazuh-alerts-*` returned **0 documents** with Event ID 4697. The same real-world fact
— a service was installed — *did* alert, through Event ID 7045 from the System channel.

**Operational impact.** Service installation is a persistence and privilege-escalation primitive
(T1543.003) and the anchor of T1036.004, which ATT&CK lists with **zero** mitigations — meaning
the entire burden falls on detection. Here the endpoint did its job, the agent did its job, and
the SIEM silently dropped the record because no rule was pointed at it. Coverage looked complete
from the dashboard. The only reason this was found is that the service installation was performed
deliberately and the alert was then looked for.

**Remediation.** [`win_security_susp_service_installation.yml`](../detections/sigma/win_security_susp_service_installation.yml)
— alerts on Security 4697 when the service image sits outside the system binary directories, when
the service name imitates a Windows service, or when the service runs a script interpreter. The
existing 7045 rule stays: the two events describe the same fact with different fields, and 4697 is
the one that carries `SubjectUserName` and `SubjectLogonId` — the account that installed the
service, and the pivot that joins the installation to everything else that session did.

---

## G-02 — Sysmon Event ID 3 (network connection) has zero detection coverage

**Layer:** detection. The channel is ingested; nothing reads it.

**Evidence.** 2026-08-11 visibility exercise: 1 Sysmon 3 event generated, 0 alerts. 2026-09-07
attack exercise: a service scan from the attacker VM left 2 Sysmon 3 events (inbound to
`10.10.10.20:3389` from `10.10.10.5`, `Initiated=false`) and again 0 alerts.

**Operational impact.** Sysmon 3 is the only host-side record of a process talking to the
network, and it is the record that ties a suspicious process to a destination. With no rule on
it, an interpreter beaconing outbound is invisible unless some *other* event happens to fire.

**Remediation.** [`net_connection_win_script_interpreter_external_dest.yml`](../detections/sigma/net_connection_win_script_interpreter_external_dest.yml)
— alerts on a shell or scripting interpreter (`powershell.exe`, `cmd.exe`, `wscript.exe`,
`mshta.exe` and similar) connecting to a destination outside private, loopback, link-local and
multicast ranges. A secondary rule for repeated inbound `Initiated=false` connections from one
source inside a short window is not yet written. Both must read the event's own `UtcTime`, not
the channel `TimeCreated` — see G-12.

---

## G-03 — Sysmon Event ID 22 (DNS query) has zero detection coverage

**Layer:** detection.

**Evidence.** 2026-08-11: 1 Sysmon 22 event generated (`b4marca.example.com`, `QueryStatus 9501`
= no records), 0 alerts.

**Operational impact.** DNS is where command-and-control, DGA behaviour and exfiltration
staging are visible earliest and cheapest. The channel is being ingested and paid for in storage
while contributing nothing.

**Remediation.** [`dns_query_win_unexpected_process.yml`](../detections/sigma/dns_query_win_unexpected_process.yml)
— alerts when a process with no reason to resolve names issues a DNS query. Threat-intel and
newly-registered-domain matching, and NXDOMAIN-burst logic per `ProcessGuid` (DGA shape), are the
natural extensions and are not yet written. Correlation back to the process must use
`ProcessGuid`, never the PID: Sysmon and 4688 disagree about what `ProcessId` means and in which
base (see [04-lessons-learned.md](04-lessons-learned.md), L-01).

---

## G-04 — Security Event ID 4648 (logon with explicit credentials) produces no alert

**Layer:** detection.

**Evidence.** 2026-08-11: 1 × 4648 generated, 0 alerts. Re-confirmed against a widened time
window before being reported, because an earlier apparent gap in 4624/4672 turned out to be a
window-edge artefact (see G-05 note and L-19).

**Operational impact.** 4648 is the `runas` / "use these other credentials" event: it is the
native signature of credential reuse and of the first step of lateral movement. Zero coverage
means an operator switching to another account leaves a log entry nobody will ever see.

**Remediation.** Alert at level 5 or above on 4648 where `SubjectUserName` differs from
`TargetUserName` and the calling process is not a known administrative tool. Not yet written as a
Sigma rule here. Deliberately scoped narrow: on this single-endpoint lab, legitimate 4648 volume
is near zero, but on a real estate this rule needs a baseline period before it is enabled.

---

## G-05 — Security Event IDs 4798 and 4799 (local group enumeration) produce no alert

**Layer:** detection.

**Evidence.** 2026-08-11: 2 events across 4798/4799 generated, 0 alerts, confirmed against a
widened window.

**Operational impact.** 4798 (a user's local group membership was enumerated) and 4799 (a
security-enabled local group membership was enumerated) are, almost literally, what SharpHound
does when it maps a host. This is the highest-value discovery telemetry Windows produces for
free, and it is being discarded.

**Remediation.** A correlation rather than a single-event rule: alert when several 4798/4799
events occur under the same `SubjectLogonId` inside a short window. Not yet written here. The
`SubjectLogonId` pivot is the same one verified end to end in the lab — 4624 → 4688 → Sysmon 1 →
4634 all carried `0x10cce5` for one session.

---

## G-06 — Discovery commands are indistinguishable from background noise

**Layer:** detection.

**Evidence.** 2026-08-11: `whoami.exe` produced a Security 4688 matched by catch-all rule 67027
at level 3 — byte for byte the same alert `sppsvc.exe` produces. No Sysmon rule fired on it
either. In the same window, 16 of 16 4688 events alerted through that same catch-all rule, while
only 1 of 11 Sysmon Event ID 1 events alerted (rule 92004, level 4, on the `powershell` → `cmd`
pattern).

**Operational impact.** `whoami` is one of the first things an intruder runs, and it is also
something a support engineer runs. Alerting on each one individually produces coverage without
discrimination — the analyst gets 16 identical level-3 rows and no way to tell which of them
belongs to an intrusion.

**Remediation.** [`proc_creation_win_lolbin_discovery_burst.yml`](../detections/sigma/proc_creation_win_lolbin_discovery_burst.yml)
— a base rule that is informational on its own plus a correlation that fires when three or more
of `{whoami, net user, net localgroup, nltest, systeminfo, ipconfig /all, arp -a, quser}` are
created under the same parent or the same `SubjectLogonId` within 60 seconds. The single-event
rule deliberately carries informational severity: it exists to be counted, not triaged.

---

## G-07 — Port scans leave no record with the audit subcategories this endpoint has enabled

**Layer:** generation — nothing is written on the host, so there is nothing for the agent to
collect and nothing for a rule to match. It is a generation gap *by configuration*, not by
structure, and the distinction matters: Windows can record this, and this endpoint is not asking
it to.

**Evidence.** `nmap -sS -p- -T4 10.10.10.20` from Kali ran 88 seconds (00:47:17Z–00:48:45Z) and
found 8 open ports (135, 139, 445, 3389, 5040, 5357, 7680, 49668) with 65,527 filtered. Wazuh
raised 6 alerts in those 88 seconds and all 6 were unrelated background 4688 process-creation
events: **zero** attributable to the scan. Repeated at smaller scale on 2026-09-07, an
`nmap -sS -sV` against 7 ports left 2 Sysmon Event ID 3 records and **0** Security 5156 events,
because the Filtering Platform Connection subcategory is not audited — a deliberate choice, since
it is very high volume.

**What Windows could have written, and why it did not.** Those 65,527 filtered ports are packets
the host firewall dropped, and the subcategory that records a dropped packet is *Audit Filtering
Platform Packet Drop* (**5152** — the Windows Filtering Platform blocked a packet — and 5153).
It is one of the subcategories this lab leaves off: the endpoint baseline enables ten, and Packet
Drop is not among them, again for volume. So the correct statement is not that Windows records
nothing about a scan, but that **this** endpoint records nothing about a scan. Nothing in this
lab has ever measured what Packet Drop produces under an 88-second full-port scan, because it
has never been switched on; the count is unknown, not zero. Note also that 5156 is *a connection
was permitted* — it would have covered the 8 open ports, never the 65,527 filtered ones, so it
was never the right subcategory for this measurement.

**Operational impact.** As this endpoint is configured, reconnaissance against it is free and
silent. Any claim that
the lab "detects reconnaissance" would be false: what it detected on 2026-09-07 was not the scan
but the **SMB null session** that followed it — Security 4624 for ANONYMOUS LOGON, type 3, NTLM,
from `10.10.10.5`, flagged by Wazuh rule 92652 at level 6. That level-6 alert was the single most
informative event of the reconnaissance phase, in the same exercise where twelve level-15 alerts
were all the same false positive. It is reimplemented as a portable rule in
[`win_security_anonymous_logon_smb_null_session.yml`](../detections/sigma/win_security_anonymous_logon_smb_null_session.yml),
which is a compensating detection for the phase *after* the scan — not a detection of the scan
itself.

**Remediation.** Two options, and the second is still the answer:
1. Enable *Audit Filtering Platform Packet Drop* (5152/5153) — the subcategory that actually
   records a dropped inbound packet — and write a rule for many distinct destination ports from
   one source IP in a short window, accepting the log volume on every endpoint. *Filtering
   Platform Connection* (5156/5157) is the wrong subcategory for this: it describes connections
   permitted and blocked at the ALE layer, not packets dropped at the filter. The volume cost of
   Packet Drop on this endpoint is unmeasured and has to be measured before it is recommended.
2. Put a network sensor (Suricata or Zeek) on the segment, which is where this telemetry belongs
   and which also sees everything option 1 cannot — payloads, sessions, hosts other than this one.

Neither is deployed yet. Option 2 is constrained by lab hardware: three VMs already use 20 GB of
48 GB RAM, and the host disk was down to 46 GB free (96 % used) as of 2026-09-07. Option 1 is one
`auditpol` line and a re-run of the 88-second scan; that is new lab work, not a rewrite of this
document, and until it is done the host-side half of this gap stays a hypothesis.

---

## G-08 — Password spraying cannot be separated from ordinary failed logons

**Layer:** detection.

**Evidence.** On 2026-09-07 the existing correlation rule 60204 ("Multiple Windows Logon
Failures", level 10, mapped to T1110) fired twice by accumulating rule 60122 events. It works on
volume alone: it never reads `SubStatus`. The 60122 count for the exercise was 20 at level 5,
aggregated across the whole run rather than per phase — and the run produced 22 × 4625 in total
(15 + 3 over SMB, then 4 over RDP). 60122 fires once per 4625, so two failures are unaccounted
for. That discrepancy has not been chased down, and it is itself a small coverage observation:
nothing in the dashboard would have told me the two were missing. The 18 SMB attempts from
`10.10.10.5` split into two very different phases:

| Phase | Count | Status | SubStatus | Meaning | Window |
|---|---|---|---|---|---|
| Enumeration | 15 × 4625 | `0xC000006D` | `0xC0000064` | account does not exist | 18:30:10–18:30:43 |
| Targeted | 3 × 4625 | `0xC000006D` | `0xC000006A` | account exists, wrong password | 18:31:13–18:31:16 |

The local lockout threshold is 10 attempts / 10 minutes, so the 15 attempts against non-existent
accounts were never subject to it — lockout only counts failures against accounts that exist.
`WorkstationName` was empty (`-`) on all 18. That is a fingerprint of *this tool*, not of
non-Windows tooling as a class: on 2026-08-08, `smbclient` — Linux, same Kali VM, same endpoint —
filled the same field with `KALI`. Treat an empty `WorkstationName` as something to identify, not
as evidence that the client was not Windows.

**Operational impact.** The alert that reaches the analyst says "multiple logon failures" and
cannot distinguish fifteen guesses at five imaginary users from one employee who forgot a
password. It also cannot see the transition between the two phases, which is the exact moment
enumeration becomes a targeted attack. Compounding it: the endpoint runs Windows 11 24H2+ with
`EnableAuthRateLimiter = True` and `InvalidAuthenticationDelayTimeInMs = 2000`, which spaced the
failures ~2 s apart — a mitigation that also guarantees a patient attacker stays under any
short-window threshold.

**Remediation.** Two rules, because the two phases are different events:

- [`win_security_password_spray_nonexistent_accounts.yml`](../detections/sigma/win_security_password_spray_nonexistent_accounts.yml)
  — a burst of 4625 with `SubStatus 0xC0000064` across several distinct `TargetUserName` values
  from one source `IpAddress`: enumeration, still shooting blind, and invisible to lockout policy.
- [`win_security_targeted_password_guessing_valid_account.yml`](../detections/sigma/win_security_targeted_password_guessing_valid_account.yml)
  — 4625 with `SubStatus 0xC000006A`: the attacker has found a real account and is now aiming at
  it. Lower volume, higher meaning.

The long-window variant (24 h, grouped by source `IpAddress`, five distinct `TargetUserName`
values) is the piece that is not optional, because with the 2 s rate limiter in place a
short-window threshold alone is defeated by an attacker doing one attempt per hour. It is drafted
as the third document inside
[`win_security_password_spray_nonexistent_accounts.yml`](../detections/sigma/win_security_password_spray_nonexistent_accounts.yml)
— drafted, not deployed: like every rule in that folder it has never run against the lab manager.

---

## G-09 — The only level-15 rule in the lab is an untuned false positive

**Layer:** detection (tuning).

**Evidence.** Rule 92213 ("Executable file dropped in folder commonly used by malware", mapped to
T1105) fires on Sysmon Event ID 11 for
`C:\Users\<LAB_USER>\AppData\Local\Temp\__PSScriptPolicyTest_<random>.ps1` — a file that a signed
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` writes to test its own execution
policy. Reproduced on 2026-08-08 (×1), 2026-08-11 (×5) and 2026-09-07 (×12). The 2026-08-08
verification produced 82 alerts across its three phases (00:44:48Z–00:49:14Z: an 8-second
generator script, an 88-second port scan, then five SMB logon failures), distributed by rule
level 3→53, 4→7, 5→13, 8→5, 12→3, 15→1. That false positive was the single highest-severity
alert in the whole set, while the simulated intrusion that mattered — a local user created,
added to Administrators and deleted inside the 8-second script (4720 → 4732 → 4726) — surfaced at
levels 8 and 12, below it.

**Operational impact.** Severity measures how bad an event would be if real, not how likely it is
to be real. A level-15 rule that fires repeatedly on legitimate behaviour trains analysts to
ignore level 15 — the failure mode that lets a real incident through. Until it is tuned, level 15
carries no information in this lab and the queue cannot be worked top-down.

**Remediation.** An exclusion for `TargetFilename` matching `__PSScriptPolicyTest_*.ps1` where
`Image` is the signed system PowerShell, written as
[`file_event_win_executable_dropped_excluding_psscriptpolicytest.yml`](../detections/sigma/file_event_win_executable_dropped_excluding_psscriptpolicytest.yml).
The equivalent tuning has **not** yet been applied to the Wazuh ruleset itself, so the false
positive is still firing in the lab today — which is why its count is reported here rather than
quietly dropped.

---

## G-10 — Security Event ID 1102 (audit log cleared) has never been generated

**Layer:** generation — in the sense that the lab has never produced the event, so the whole path
is untested.

**Evidence.** 1102 is on my list of twelve priority Event IDs and is explicitly recorded as the
only one of the twelve with **no data from this lab**: never generated, therefore never
collected, therefore never tested against a rule.

**Operational impact.** 1102 is one of the very few Windows events that is close to being an
indicator on its own — a cleared Security log on a workstation has almost no benign explanation.
Claiming coverage for T1685.005 (numbered T1070.001 before the v18 regrouping) without ever having produced the event would be exactly the kind
of unverified claim the rest of this repository exists to avoid.

**Remediation.** Two steps in order: (1) trigger it deliberately and confirm the full path
endpoint → agent → index → alert; (2) only then write the rule, unconditional and high severity.
The `base-limpia` snapshots exist on both VMs precisely so destructive tests like this can be
rolled back — restoration was tested and verified (after restore: Sysmon64 running, the Wazuh
service running, `10.10.10.20` intact).

---

## G-11 — RDP failure detection has no listener-side corroboration

**Layer:** detection.

**Evidence.** On 2026-09-07, four failed RDP logins produced 4625 events with **logon type 3**,
not type 10, because Network Level Authentication moves authentication in front of session
creation. Two authentication-only connections produced 4624 type 3 plus
TerminalServices-RemoteConnectionManager EID 1149, still no type 10. The only logon type 10 of
the entire exercise appeared at 18:35:09, when a full graphical session actually established:
4624 type 10, `AuthenticationPackage Negotiate`, `LogonProcessName User32`, with
TerminalServices-LocalSessionManager 41 → 42 → **21** (session logon) → **22** (shell start
notification). The session was then disconnected at 18:36:49, which is where the 24 and 40 of
that exercise come from — they belong to the teardown, not to the establishment. Worth being
exact about, because 22 is routinely described as a reconnection and is not: reconnection is
EID 25, which this lab has never produced. The RDP context — including
`Source Network Address 10.10.10.5` — lives in those TerminalServices channels, not in the 4625.

**Operational impact.** Any detection built on "RDP brute force = 4625 logon type 10" misses every
NLA-protected target, and NLA is the default. Worse, the failed RDP attempts are byte-for-byte
indistinguishable by logon type from the SMB attempts earlier in the same exercise, so the
analyst cannot tell which service was attacked from the Security log alone.

**Remediation.** [`win_security_rdp_bruteforce_behind_nla.yml`](../detections/sigma/win_security_rdp_bruteforce_behind_nla.yml)
catches the volume of 4625 logon type 3 from one source, which is what is detectable from the
Security log alone, and
[`win_security_successful_interactive_rdp_session.yml`](../detections/sigma/win_security_successful_interactive_rdp_session.yml)
catches the other end of the chain — the 4624 logon type 10 that only appears once a graphical
session really establishes, which is the event that turns an attempt into an intrusion. The piece
that is still missing is the reclassification: correlating those 4625s with
TerminalServices-RemoteConnectionManager EID 261/1149 in the same window to say *which service*
was attacked. Prerequisite:
those TerminalServices channels are not currently forwarded by the agent — the forwarded set is
Security, System, Application, `Microsoft-Windows-Sysmon/Operational` and
`Microsoft-Windows-PowerShell/Operational` — so this is a collection change first and a rule
second.

---

## G-12 — No time synchronisation between endpoint and SIEM

**Layer:** collection.

**Evidence.** Measured on the same `eventRecordID` (31476): endpoint
`data.win.system.systemTime` = `17:22:36.6840621Z`, Wazuh `@timestamp` = `17:22:34.930Z` — a
delta of −1.754 s. Across three consecutive records: −1.754 / −1.821 / −1.757 s, consistently
negative, so it is an offset and not jitter. Separately, inside Sysmon, events 3 and 22 are
written to the channel after the fact: EID 22 `TimeCreated 17:22:40.464` vs its own `UtcTime`
`17:22:37.222` (3.2 s), EID 3 `TimeCreated 17:22:41.163` vs `UtcTime 17:22:37.162` (4.0 s).
Sorting by `TimeCreated` placed a DNS query after a `whoami.exe` that in fact came later.

**Operational impact.** `@timestamp` — the manager's processing clock — is the dashboard's
default time axis. Filtering for "what happened at 17:22:36" returns events Windows recorded at
17:22:38, which silently reorders a multi-source timeline. Cause and effect is the output of an
investigation; a timeline built on the wrong field inverts it.

**Remediation.** Not a rule: configure NTP on both VMs, and pin every dashboard query and saved
search to `data.win.system.systemTime`, and to `UtcTime` for Sysmon 3 and 22. This becomes a hard
requirement rather than a nuisance once a domain controller joins the lab, since Kerberos rejects
clock skew above 5 minutes.

---

## Other measured zero-coverage channels

Not written up as individual gaps, but measured in the same 2026-08-11 window and recorded here
so the coverage picture is complete:

| Channel | Generated | Alerted |
|---|---|---|
| PowerShell 4103 / 4104 / other | 110 | 0 |
| Security 4689 (process terminated) | 12 | 0 |

PowerShell ScriptBlockLogging is enabled, forwarded, and read by nothing in the default ruleset.
It is the richest untapped source on this endpoint, and closing it is the next detection-writing
task after the gaps above. 4689 is lower value on its own, but it is what bounds a process's
lifetime when reconstructing a timeline.

One further method note belongs here. An apparent gap in 4624/4672 (4 generated / 2 alerted and
3 / 1) was **withdrawn** after widening the query range to 17:22:20–17:23:00 revealed 8 × 4624
and 4 × 4672, every one alerting individually: the four host-driven invocations in that window
each produce a *pair* of 4624 events plus one 4672, and the pairs were being cut in half by the
window boundary. Only gaps that survived
a widened window — 4648, 4798/4799, Sysmon 3, Sysmon 22 — are reported above. A false gap in a
coverage report costs as much credibility as a false positive costs an analyst's shift.

---

## Known blind spots: what this lab cannot see at all

The gaps above are things that could be fixed with a rule, a correlation or a configuration
change. The following are not gaps in the ruleset — they are things this lab has no telemetry for
whatsoever. Listing them precisely is more useful than a coverage claim.

**1. Network traffic analysis — nothing.** There is no IDS, no packet capture, no flow data and
no TLS metadata anywhere in the lab. Everything in this repository is host telemetry read from
Windows event channels. The measured consequence is G-07: a 65,535-port scan over 88 seconds
produced zero attributable alerts, and a 7-port service scan left 2 Sysmon Event ID 3 records.
I also have **0** malware-traffic-analysis pcaps solved, so packet-level analysis is a skill this
repository does not yet evidence at all. Any question about beaconing intervals, JA3/JA4, DNS
tunnelling seen on the wire, or C2 protocol behaviour is outside what I have measured.

**2. No domain controller, therefore no Kerberos or directory telemetry.** `DC01` is planned
(Windows Server, 4 GB / 2 vCPU, `10.10.10.5`) and **has not been created**. Everything measured
here is local-account authentication on a workgroup endpoint. That means no 4768 / 4769 / 4771,
no Kerberoasting or AS-REP roasting, no Golden/Silver Ticket activity, no DCSync, no delegation
abuse, no Group Policy telemetry, no cross-host lateral movement inside a domain, and no
directory-level account management events. A practical detail already waiting: DHCP handed the
attacker VM `10.10.10.5`, the address reserved in the plan for the domain controller — a
documented collision to resolve before stage 2.

One event usually listed alongside those does **not** belong in this blind spot: **4776**, *the
computer attempted to validate the credentials for an account*. That is the NTLM
credential-validation record, and for local accounts it is written by the local machine's MSV1_0
package, not by a domain controller. It is missing here for a much cheaper reason — *Audit
Credential Validation* is not one of the ten subcategories this endpoint enables. It is the
cheapest addition this lab could make to the attack path it actually measured: every NTLM logon
of 2026-09-07 — the 18 SMB attempts of G-08, and the valid credential supplied after them — ran
straight through the check 4776 describes. The same correction applies to any
query written against 4776 on this endpoint: it will return nothing today, and that is
configuration, not absence of the event class.

**3. No email or phishing telemetry.** There is no mail server, no gateway and no mailbox in the
lab, so the most common real-world initial-access vector produces nothing to detect here.
T1684.002 (Email Spoofing) was studied through its mitigations — two of its three depend on
parties the defender does not control — but it is not reproducible on this infrastructure, and
nothing in this repository should be read as experience triaging phishing.

**4. A single endpoint, a single user, a single OS build.** One Windows 11 Pro 25H2 host
(10.0.26200), one lab account, one Sysmon configuration. Consequences: no cross-host correlation,
no pivot from workstation to server, no baseline of "normal" built from a population, and no
exposure to the volume problems that appear when the same rule runs against hundreds of hosts.
Several findings here — for example that 4648 volume is effectively zero — hold only because the
population is one.

**5. No Linux or macOS endpoint telemetry.** The Ubuntu VM runs the SIEM; it is not itself
instrumented as a monitored endpoint, and there is no auditd or eBPF telemetry in the index.
Kali is the attacker and is not monitored either.

**6. No cloud, identity-provider or SaaS telemetry.** No Entra ID or M365 sign-in logs, no cloud
audit trail, no proxy or web-gateway logs. A large share of real SOC L1 work happens in exactly
those sources, and none of it is represented here.

**7. No EDR and no malware detonation.** Detection is Sysmon plus native Windows auditing
forwarded to Wazuh. There is no behavioural EDR, no memory analysis, no sandbox and no sample
detonation. The three SHA256 hashes captured from Sysmon Event ID 1 in the visibility exercise
belong to `powershell.exe`, `cmd.exe` and `whoami.exe` — legitimate signed system binaries from a
benign exercise.

**8. Everything here is emulation, not incident response.** In the 2026-09-07 exercise I executed
the attack and then investigated it, so I knew the answer in advance. It is a controlled
adversary-emulation exercise and should be read as one. It is not an unscripted investigation,
and no writeup in this repository claims to be.

**9. The SIEM only shows what its rules recognise.** Measured as a funnel: in the 2026-08-08
exercise the agent reported roughly 2,100 events to the manager (2,098 counted at verification)
and 835 alerts remained in the index for that endpoint — more than half the telemetry never
became queryable, because it matched no rule at level ≥ 3. In the 2026-08-11 exercise the same
shape appeared at smaller scale: 167 events generated → 27 alerts on the narrow observation
window, which becomes **172 → 36** once the two rows the same exercise retracted (4624 and 4672,
halved by the window boundary — see the method note above) are recounted over
17:22:20–17:23:00. The narrow pair is kept here only because it is the one the per-channel tables
were originally built on; the widened pair supersedes it. Neither is settled: one row inside both
totals (Sysmon 11, 4 generated / 5 alerted) is arithmetically impossible for a single-event rule
and has not been recounted. Every coverage statement in
this document is therefore bounded by the ruleset, not by what the endpoint produced. Absence of
an alert is not evidence of absence of activity.

**10. Hardware limits what can be added next.** The three running VMs use 20 GB of 48 GB RAM, and
the single host disk was down to 46 GB free of 952 GB (96 % used) as of 2026-09-07. Adding a
domain controller and a network sensor is constrained by disk before it is constrained by
anything else — worth stating plainly, because "why haven't you added a Zeek sensor yet" has a
concrete answer rather than an excuse.

---

Related: [04-lessons-learned.md](04-lessons-learned.md) for the instrumentation lessons behind
several of these gaps, and [`detections/sigma/`](../detections/sigma/) for the rules that close
the ones a rule can close.
