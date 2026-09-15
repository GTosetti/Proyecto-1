# ATT&CK coverage matrix

Every row is a technique this lab has touched, and every mark comes from a measurement taken on the
lab described in [`../docs/01-lab-architecture.md`](../docs/01-lab-architecture.md). Nothing here is
filled in from an ATT&CK mapping table, a vendor datasheet or an assumption. Where a column is
partial, the reason is written next to it.

The matrix exists to keep three things apart that are usually collapsed into one tick: activity that
was **generated**, telemetry that was **collected**, and events that a rule actually **detected**. On
2026-08-08 those three came apart on a single event — Security 4697 was in the endpoint log, the
Security channel was being forwarded, and a `wazuh-alerts-*` query returned 0 documents for it. That
failure is silent, and a binary coverage table would have shown it as covered.

ATT&CK v18 nomenclature is used throughout: tactic **TA0005 is named Stealth**, not Defense Evasion,
and the former T1656/T1672 are regrouped as T1684.001/.002. Most third-party material still uses the
old names.

---

## How to read it

Markers, per column:

| Mark | Simulated | Telemetry generated | Telemetry collected | Rule matched |
|---|---|---|---|---|
| ● | Executed deliberately in a lab exercise | Events for the technique were confirmed in the endpoint log | The events were confirmed present in the SIEM index | A rule fired on it, observed in `wazuh-alerts-*` |
| ◐ | Only an adjacent or benign proxy of it was executed | Only partial or adjacent events exist | The channel is forwarded but no event for this technique was confirmed in it | A rule fired, but it is a catch-all or every firing was a false positive |
| ○ | Never executed | No events | Not collected, or nothing to collect | No rule matched |

Score (the same value used in [`attack-navigator-layer.json`](attack-navigator-layer.json)):

| Score | Meaning |
|---|---|
| 3 | A rule fired on this technique's activity in this lab |
| 2 | The mapped telemetry was generated **and** confirmed collected, and no rule matched it — a measured detection gap |
| 1 | The mapped telemetry exists on the endpoint, but only partially or only as an adjacent mechanism, and detection is untested |
| 0 | Nothing: the technique was never exercised and no mapped telemetry exists in this lab |

---

## The matrix

| Technique | Name | Tactic (v18) | Sim. | Gen. | Coll. | Rule | Score | Evidence |
|---|---|---|:--:|:--:|:--:|:--:|:--:|---|
| T1059 | Command and Scripting Interpreter | Execution | ● | ● | ● | ● | 3 | Telemetry configured and verified: 4104, 4103, 4688 with command line, Sysmon 1. Detection evidenced through its sub-techniques below. [001](../investigations/001-first-alert-triage.md), [002](../investigations/002-process-telemetry-correlation.md) |
| T1059.001 | PowerShell | Execution | ● | ● | ● | ● | 3 | Rule `92057`, level 12, fired on a **Sysmon Event ID 1** — not on the 4104 the exercise had predicted, although the 4104 was generated. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1059.003 | Windows Command Shell | Execution | ● | ● | ● | ● | 3 | Rule `92004`, level 4, on the `powershell → cmd` ancestry pattern: the only alert out of 11 Sysmon EID 1 events in the window. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1098 | Account Manipulation | Persistence / Priv. Esc. | ● | ● | ● | ● | 3 | Rules `60109` (4720/4722), `60110` (4738 ×2), `60111` (4726), all level 8. Single-event rules — nothing correlates the three into one sequence. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence / Priv. Esc. | ● | ● | ● | ◐ | 3 | A test service install alerted through **7045** (System channel). **4697** (Security channel) reached the SIEM and produced 0 alert documents. Detection rests on one of the two sources. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Priv. Esc. / Stealth | ○ | ◐ | ● | ○ | 1 | Never simulated. The UAC linked-token mechanism it abuses was measured: 8 of 8 remote invocations produced a 4624 pair (`elevatedToken %%1842` with a 4672, `%%1843` without), and launched processes carried `TokenElevationType %%1938` (Limited). No bypass path exercised. ATT&CK study 2026-07-31 (4 mitigations) + [002](../investigations/002-process-telemetry-correlation.md) |
| T1110 | Brute Force | Credential Access | ● | ● | ● | ● | 3 | Correlation rule `60204`, level 10, fired twice by accumulating 20 × rule `60122` (level 5) in a short window. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1110.001 | Brute Force: Password Guessing | Credential Access | ● | ● | ● | ◐ | 3 | 18 attempts from 10.10.10.5: 15 × 4625 `SubStatus 0xC0000064` then 3 × `0xC000006A`, then a successful 4624. Alerts fired, but rule 60204 never reads `SubStatus`, so enumeration and targeted guessing are indistinguishable to it. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1016 | System Network Configuration Discovery | Discovery | ● | ● | ● | ◐ | 2 | `ipconfig /all` and `systeminfo` produced only generic level-3 4688 alerts from catch-all rule `67027`. No rule reads the command line. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1033 | System Owner/User Discovery | Discovery | ● | ● | ● | ◐ | 2 | `whoami.exe` produced a 4688 matched by rule `67027` at level 3 — byte for byte the same treatment as `sppsvc.exe`. No Sysmon rule fired on it either. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1046 | Network Service Discovery | Discovery | ● | ◐ | ◐ | ○ | 1 | `nmap -sS -p-`: 65,535 ports in 88 s, 8 open / 65,527 filtered, **0** attributable alerts. A 7-port `-sS -sV` scan left 2 Sysmon EID 3 events and 0 Security 5156, because Filtering Platform Connection auditing is deliberately off. Structural: host agent, no network sensor. [001](../investigations/001-first-alert-triage.md), [003](../investigations/003-smb-rdp-attack-chain.md) |
| T1087 | Account Discovery | Discovery | ● | ● | ● | ○ | 2 | Security 4798/4799 (local group membership enumeration — the SharpHound signature): 2 events generated, 0 alerts, confirmed against a widened window. `net user` / `net localgroup` produced only level-3 4688s. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1135 | Network Share Discovery | Discovery | ● | ● | ● | ● | 3 | The SMB null session preceding the enumeration produced 4624 ANONYMOUS LOGON, type 3, NTLM, from 10.10.10.5 → rule `92652`, level 6 — the only reliable trace of the whole reconnaissance phase. The authenticated `--shares` listing of ADMIN$/C$/IPC$ left no distinct event of its own. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | ● | ● | ● | ● | 3 | Rule `92657` fired 3 times at level 6. With NLA active the 4 failed logons appeared as 4625 **type 3**; only the completed graphical session produced 4624 type 10 (Negotiate / User32) with TS-LocalSessionManager 41→42→21→22→24. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access / Persistence / Priv. Esc. / Stealth | ● | ● | ● | ◐ | 3 | A guessed local credential was accepted over SMB (4624 type 3, NTLM, rule `92657`) and later over RDP (4624 type 10). The account is a local administrator, so ADMIN$ and C$ access implies full control. Nothing in the alert separates it from a legitimate admin logon. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1659 | Content Injection | Initial Access / Command and Control | ○ | ○ | ◐ | ○ | 0 | Studied only. Assessed as reproducible in this lab without any exploit, and not executed. The channels its detection strategy needs (Sysmon 11 → 1 → 3) are ingested; no event for the technique exists. ATT&CK study, 2026-07-31 (2 mitigations; M1041 eliminates it outright) |
| T1105 | Ingress Tool Transfer | Command and Control | ○ | ● | ● | ◐ | 3 | Rule `92213` (level 15) carries this mapping and fired **18 times** — 1 on 2026-08-08, 5 on 2026-08-11, 12 on 2026-09-07 — and all 18 were false positives on `__PSScriptPolicyTest_*.ps1` written by the signed system `powershell.exe`. No real transfer was ever staged, so the true-positive path is unvalidated. [001](../investigations/001-first-alert-triage.md) |
| T1531 | Account Access Removal | Impact | ● | ● | ● | ● | 3 | Co-mapped with T1098 on rule `60111`, level 8, firing on Security 4726 — the deletion of the account created eight seconds earlier. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1036.003 | Masquerading: Rename System Utility | Stealth | ○ | ● | ● | ○ | 2 | Found by **negative** evidence: Sysmon EID 1 carries `OriginalFileName` (`PowerShell.EXE`), which survives a rename and is collected; Security 4688 has no equivalent field, so the technique is undetectable from the Security log alone. No rule reads the field. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1036.004 | Masquerading: Masquerade Task or Service | Stealth | ◐ | ● | ● | ○ | 2 | Not simulated; its mapped telemetry was. Security 4697 confirmed in the log with `Get-WinEvent`, Security channel forwarded, `wazuh-alerts-*` returned 0 documents for 4697. ATT&CK lists **zero** mitigations for this technique — it is a detection problem by definition. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Stealth | ○ | ○ | ○ | ○ | 0 | Security 1102 has **never been generated** in this lab — the only one of the twelve priority Event IDs with no measured data, so its detection path is untested. Planned exercise; the `base-limpia` snapshot exists for rollback. |
| T1484 | Domain or Tenant Policy Modification | Stealth / Priv. Esc. | ● | ● | ● | ● | 3 | Rule `60154` ("Administrators Group Changed"), level 12, on Security 4732 and 4733 inside the create-user → add-to-Administrators → delete sequence. The ATT&CK mapping is Wazuh's, attached to the rule, and 4732 arguably belongs to T1098. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1684.002 | Social Engineering: Email Spoofing | Stealth | ○ | ○ | ○ | ○ | 0 | Theory only. Not reproducible here: there is no mail server in the lab. Two of its three mitigations depend on parties the defender does not control. Numbered T1672 before the v18 regrouping. ATT&CK study, 2026-07-31 |

---

## What the matrix adds up to

**13 of 23 techniques (57%) had a rule fire on them.** That is the generous number. The useful numbers
are smaller, and each one is a subtraction that can be checked against the rows above:

| Reading | Count | Why |
|---|---|---|
| Techniques with measured evidence in this lab | 23 | The whole population of this matrix — a small fraction of ATT&CK Enterprise, and only what the lab has actually touched |
| A rule fired on it | 13 (57%) | Score 3 |
| …with at least one true positive | 12 (52%) | T1105 removed: 18 firings, 18 false positives |
| …fired by a rule reading a **pattern** rather than a single event | 3 | `92057` (powershell → base64), `92004` (powershell → cmd), `60204` (accumulated logon failures). Everything else alerts because one event exists |
| Detected by a rule written by me | **0** | Two Sigma rules are drafted, neither deployed. See [`README.md`](README.md) |
| Measured detection gaps — generated, collected, no rule | 5 | T1016, T1033, T1036.003, T1036.004, T1087 |
| Never exercised at all | 3 | T1659, T1070.001, T1684.002 |

The repository's own progress counter applies a stricter definition still — the technique was
simulated by me *and* a rule fired on that simulation — and records **3**, against a target of 10.

One caveat applies to every row, and it is measurable: a coverage claim built by searching the alert
index is bounded by the ruleset, not by what the endpoint produced. In the 2026-08-08 exercise the
agent reported roughly 2,100 events to the manager and 835 alerts were left in the index; in the
2026-08-11 exercise, 167 events generated produced 27 alerts. More than half the telemetry never
became queryable. **Absence of an alert is not evidence of absence of activity.**

### Coverage by tactic

Each technique is counted once, under the tactic shown in its matrix row.

| Tactic (v18) | Techniques | Score 3 | Uncovered |
|---|:--:|:--:|:--:|
| Execution | 3 | 3 | 0 |
| Persistence / Priv. Esc. | 2 | 2 | 0 |
| Privilege Escalation / Stealth | 1 | 0 | 1 |
| Credential Access | 2 | 2 | 0 |
| **Discovery** | 5 | 1 | **4** |
| Lateral Movement | 1 | 1 | 0 |
| Initial Access (incl. multi-tactic) | 2 | 1 | 1 |
| Command and Control | 1 | 1 | 0 (but the only firings were false positives) |
| Impact | 1 | 1 | 0 |
| **Stealth** | 5 | 1 | **4** |

**The largest uncovered tactic is Stealth (TA0005 — called Defense Evasion before ATT&CK v18):**
4 of its 5 techniques have no rule, and counting T1548.002 under Stealth as well as Privilege
Escalation makes it 5 of 6.

Discovery is level with it at 4 of 5 and is the more actionable of the two, because every one of its
gaps is a real layer-3 hole: all five Discovery techniques were executed, their telemetry was
generated, and all of it reached the SIEM — it simply matched no rule that distinguishes it from
noise. Two of the four Stealth gaps, by contrast, are gaps because the activity was never produced
(T1684.002 needs a mail server this lab does not have; T1070.001 has never been triggered).

That points the backlog in one direction, and it is the direction the measurements already argued
for: discovery activity cannot be detected one command at a time — `whoami.exe` produced the same
alert as `sppsvc.exe` — so it has to be detected as a **sequence** under one parent or one logon
session. That rule is the first item in the backlog in [`README.md`](README.md).
