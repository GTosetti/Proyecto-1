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
the former T1656/T1672 are regrouped as T1684.001/.002, and T1070.001 (clearing Windows event logs)
is renumbered **T1685.005**. Most third-party material still uses the old names and the old IDs.

---

## How to read it

Markers, per column:

| Mark | Simulated | Telemetry generated | Telemetry collected | Rule matched |
|---|---|---|---|---|
| ● | Executed deliberately in a lab exercise | Events for the technique were confirmed in the endpoint log | The channel is forwarded — proven by an alert document where a rule matched, inferred from the agent's configuration where none did | A rule fired on it, observed in `wazuh-alerts-*` |
| ◐ | Only an adjacent or benign proxy of it was executed | Only partial or adjacent events exist | The channel is forwarded but no event for this technique was confirmed in it | A rule fired, but it is a catch-all or every firing was a false positive |
| ○ | Never executed | No events | Not collected, or nothing to collect | No rule matched |

That distinction is the weak point of this matrix and it is stated rather than buried. An event that
matched no rule is never indexed, so wherever a ● sits in the Collected column with an ○ or a gap in
the Rule column — T1087, T1036.003, T1036.004, and the 4697 half of T1543.003 — collection is
**inferred** from the channel being declared in the agent's `ossec.conf` and the agent reporting
`connected`. It was not observed, and this evidence cannot separate a layer-2 failure from a layer-3
one. Verifying it needs `logall_json` on the manager and a query against `wazuh-archives-*`, which
this lab has not done. Same caveat, longer, in [`README.md`](README.md) step 3.

Score (the same value used in [`attack-navigator-layer.json`](attack-navigator-layer.json)):

| Score | Meaning |
|---|---|
| 3 | A rule fired on **this technique's own** activity in this lab, and the firing was usable — even if it covers only part of the technique |
| 2 | The mapped telemetry was generated and collected, and nothing actionable matched it: either no rule fired at all, or the only match was a catch-all that treats the activity exactly like background noise — a measured detection gap |
| 1 | The mapped telemetry exists on the endpoint, but only partially or only as an adjacent mechanism, and detection is untested |
| 0 | Nothing: the technique was never exercised and no mapped telemetry exists in this lab |

The Rule column and the score answer different questions, which is why a ◐ can land on either 3 or 2.
◐ scores **3** when a real rule fired on the technique's own activity and the gap is in what it covers
(T1543.003, T1110.001, T1078.003). It scores **2** when the only thing that matched was catch-all rule
`67027`, which fires on every 4688 at level 3 (T1016, T1033). It scores **1** when the rule never saw
the technique at all and fired only on an adjacent artefact (T1105).

---

## The matrix

| Technique | Name | Tactic (v18) | Sim. | Gen. | Coll. | Rule | Score | Evidence |
|---|---|---|:--:|:--:|:--:|:--:|:--:|---|
| T1059 | Command and Scripting Interpreter | Execution | ● | ● | ● | ● | 3 | Telemetry configured and verified: 4104, 4103, 4688 with command line, Sysmon 1. Detection evidenced through its sub-techniques below. [001](../investigations/001-first-alert-triage.md), [002](../investigations/002-process-telemetry-correlation.md) |
| T1059.001 | PowerShell | Execution | ● | ● | ● | ● | 3 | Rule `92057`, level 12, fired on a **Sysmon Event ID 1** — not on the 4104 the exercise had predicted, although the 4104 was generated. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1059.003 | Windows Command Shell | Execution | ● | ● | ● | ● | 3 | Rule `92004`, level 4, on the `powershell → cmd` ancestry pattern: the only alert out of 11 Sysmon EID 1 events in the window. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1098 | Account Manipulation | Persistence / Priv. Esc. | ● | ● | ● | ● | 3 | Rules `60109` (4720/4722), `60110` (4738 ×2), `60111` (4726), all level 8. Single-event rules — nothing correlates the three into one sequence. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence / Priv. Esc. | ● | ● | ● | ◐ | 3 | A test service install alerted through **7045** (System channel). **4697** (Security channel) was confirmed in the endpoint log, sits on a channel the agent forwards, and produced 0 alert documents. Detection rests on one of the two sources. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Priv. Esc. / Stealth | ○ | ◐ | ● | ○ | 1 | Never simulated. The UAC linked-token mechanism it abuses was measured: 4 of 4 remote invocations produced a 4624 pair — 8 × 4624 and 4 × 4672 in all (`elevatedToken %%1842` with a 4672, `%%1843` without) — and launched processes carried `TokenElevationType %%1938` (Limited). No bypass path exercised. ATT&CK study 2026-07-31 (4 mitigations) + [002](../investigations/002-process-telemetry-correlation.md) |
| T1110 | Brute Force | Credential Access | ● | ● | ● | ● | 3 | Correlation rule `60204`, level 10, fired twice by accumulating 20 × rule `60122` (level 5) in a short window. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1110.001 | Brute Force: Password Guessing | Credential Access | ● | ● | ● | ◐ | 3 | 18 attempts from 10.10.10.5: 15 × 4625 `SubStatus 0xC0000064` then 3 × `0xC000006A`. None of them guessed the password — the successful 4624 that follows came from a known-valid credential supplied on purpose. Alerts fired, but rule 60204 never reads `SubStatus`, so enumeration and targeted guessing are indistinguishable to it. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1016 | System Network Configuration Discovery | Discovery | ● | ● | ● | ◐ | 2 | `ipconfig /all` and `systeminfo` produced only generic level-3 4688 alerts from catch-all rule `67027`. No rule reads the command line. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1033 | System Owner/User Discovery | Discovery | ● | ● | ● | ◐ | 2 | `whoami.exe` produced a 4688 matched by rule `67027` at level 3 — byte for byte the same treatment as `sppsvc.exe`. No Sysmon rule fired on it either. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1046 | Network Service Discovery | Discovery | ● | ◐ | ◐ | ○ | 1 | `nmap -sS -p-`: 65,535 ports in 88 s, 8 open / 65,527 filtered, **0** attributable alerts. A 7-port `-sS -sV` scan left 2 Sysmon EID 3 events and 0 Security 5156, because Filtering Platform Connection auditing is deliberately off — and enabled it would have logged only the 8 permitted connections. The subcategory that records a dropped packet is *Audit Filtering Platform Packet Drop* (5152/5153); it is off too and was never measured here. Structural: host agent, no network sensor. [001](../investigations/001-first-alert-triage.md), [003](../investigations/003-smb-rdp-attack-chain.md) |
| T1087 | Account Discovery | Discovery | ● | ● | ● | ○ | 2 | Security 4798/4799 (local group membership enumeration — the SharpHound signature): 2 events generated, 0 alerts, confirmed against a widened window. `net user` / `net localgroup` produced only level-3 4688s. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1135 | Network Share Discovery | Discovery | ● | ● | ● | ● | 3 | The SMB null session preceding the enumeration produced 4624 ANONYMOUS LOGON, type 3, NTLM, from 10.10.10.5 → rule `92652`, level 6 — the only reliable trace of the whole reconnaissance phase. The alert fired on the logon that carried the enumeration, not on the enumeration itself: the authenticated `--shares` listing of ADMIN$/C$/IPC$ left no distinct event of its own, because *Audit Object Access → File Share* (5140/5145, and a 5145 on IPC$ with relative target `srvsvc` is the canonical record of `NetShareEnum`) is deliberately off in this lab. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | ● | ● | ● | ● | 3 | Rule `92657` fired 3 times at level 6. With NLA active the 4 failed logons appeared as 4625 **type 3**; only the completed graphical session produced 4624 type 10 (Negotiate / User32) with TS-LocalSessionManager 41→42→21→22→24. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1078.003 | Valid Accounts: Local Accounts | Initial Access / Persistence / Priv. Esc. / Stealth | ● | ● | ● | ◐ | 3 | The guessing phase never succeeded; a known-valid local credential was then supplied deliberately, to generate the post-authentication telemetry. It was accepted over SMB (4624 type 3, NTLM, rule `92657`) and later over RDP (4624 type 10). The account is a local administrator, so ADMIN$ and C$ access implies full control. Nothing in the alert separates it from a legitimate admin logon. [003](../investigations/003-smb-rdp-attack-chain.md), 2026-09-07 |
| T1659 | Content Injection | Initial Access / Command and Control | ○ | ○ | ◐ | ○ | 0 | Studied only. Assessed as reproducible in this lab without any exploit, and not executed. The channels its detection strategy needs (Sysmon 11 → 1 → 3) are ingested; no event for the technique exists. ATT&CK study, 2026-07-31 (2 mitigations; M1041 eliminates it outright) |
| T1105 | Ingress Tool Transfer | Command and Control | ○ | ◐ | ● | ◐ | 1 | Rule `92213` (level 15) carries this mapping and fired **21 times** — 1 on 2026-08-08, 5 on 2026-08-11, 12 on 2026-09-07, 3 on 2026-09-17 — and all 21 were false positives on `__PSScriptPolicyTest_*.ps1` written by the signed system `powershell.exe`. No transfer was ever staged, so the events that exist are the adjacent file-create mechanism, not the technique, and the true-positive path is untested. Scored 1, not 3: a rule that has only ever fired on something else has not detected this. [001](../investigations/001-first-alert-triage.md) |
| T1531 | Account Access Removal | Impact | ● | ● | ● | ● | 3 | Co-mapped with T1098 on rule `60111`, level 8, firing on Security 4726 — the deletion of the account created eight seconds earlier. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1036.003 | Masquerading: Rename System Utility | Stealth | ○ | ● | ● | ○ | 2 | Found by **negative** evidence: Sysmon EID 1 carries `OriginalFileName` (`PowerShell.EXE`), which survives a rename and is collected; Security 4688 has no equivalent field, so the technique is undetectable from the Security log alone. No rule reads the field. [002](../investigations/002-process-telemetry-correlation.md), 2026-08-11 |
| T1036.004 | Masquerading: Masquerade Task or Service | Stealth | ◐ | ● | ● | ○ | 2 | Not simulated; its mapped telemetry was. Security 4697 confirmed in the log with `Get-WinEvent`, Security channel forwarded, `wazuh-alerts-*` returned 0 documents for 4697. ATT&CK lists **zero** mitigations for this technique — it is a detection problem by definition. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1685.005 | Indicator Removal: Clear Windows Event Logs | Stealth | ○ | ○ | ○ | ○ | 0 | Security 1102 has **never been generated** in this lab and no query has ever been run against it, so its detection path is untested — the gap here is the missing exercise, not a query that came back empty. Planned; the `base-limpia` snapshot exists for rollback. Numbered T1070.001 before the v18 regrouping. |
| T1484 | Domain or Tenant Policy Modification | Stealth / Priv. Esc. | ● | ● | ● | ● | 3 | Rule `60154` ("Administrators Group Changed"), level 12, on Security 4732 and 4733 inside the create-user → add-to-Administrators → delete sequence. The ATT&CK mapping is Wazuh's, attached to the rule, and 4732 arguably belongs to T1098. [001](../investigations/001-first-alert-triage.md), 2026-08-08 |
| T1684.002 | Social Engineering: Email Spoofing | Stealth | ○ | ○ | ○ | ○ | 0 | Theory only. Not reproducible here: there is no mail server in the lab. Two of its three mitigations depend on parties the defender does not control. Numbered T1672 before the v18 regrouping. ATT&CK study, 2026-07-31 |

---

## What the matrix adds up to

**12 of 23 techniques (52%) had a rule fire on their own activity.** That is the generous number, and
the percentage deserves less weight than the count: the denominator is the 23 techniques this lab has
touched, not ATT&CK Enterprise, so it measures the lab against itself. The useful readings are
smaller, and each is a subtraction that can be checked against the rows above:

| Reading | Count | Why |
|---|---|---|
| Techniques with measured evidence in this lab | 23 | The whole population of this matrix — a small fraction of ATT&CK Enterprise, and only what the lab has actually touched |
| A rule fired on the technique's own activity | 12 (52%) | Score 3. T1105 is **not** in this count: rule `92213` carries the mapping and fired 21 times, all 21 on an adjacent PowerShell temp file, so it scores 1 |
| …fired by a rule reading a **pattern** rather than a single event | 3 | `92057` (powershell → base64), `92004` (powershell → cmd), `60204` (accumulated logon failures). Everything else alerts because one event exists |
| Detected by a rule written by me | **0** | 25 Sigma rule documents across 15 files are drafted; none is deployed to the manager, so none has produced a detection. See [`README.md`](README.md) |
| Measured gaps where **no rule matched at all** | 3 | T1087, T1036.003, T1036.004 |
| Measured gaps where **only a catch-all matched** | 2 | T1016 and T1033: rule `67027` fires on every 4688 at level 3, so `whoami.exe` and `sppsvc.exe` arrive in the queue identically. A match that carries no discrimination is not coverage, which is why both score 2 rather than 3 |
| Never exercised, and no mapped telemetry either | 3 | T1659, T1685.005, T1684.002 — the score-0 rows |
| Never exercised, but mapped or adjacent telemetry exists | 3 | T1548.002, T1036.003, T1105 — measured through the mechanism, not through the attack |

The repository's own progress counter applies a stricter definition still — the technique was
simulated by me *and* a rule fired on that simulation — and records **3**, against a target of 10.

One caveat applies to every row, and it is measurable: a coverage claim built by searching the alert
index is bounded by the ruleset, not by what the endpoint produced. In the 2026-08-08 exercise the
agent reported roughly 2,100 events to the manager and 835 alerts were left in the index; in the
2026-08-11 exercise, 172 events generated produced 36 alerts - four events in five never became
queryable. (A first pass reported 167 and 27; the window clipped events at its boundary and the
recount is in `../investigations/002-process-telemetry-correlation.md`.) **Absence of an alert is not evidence of absence of activity.**

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
| Command and Control | 1 | 0 | 1 (a rule carries the mapping, but all 18 firings were false positives) |
| Impact | 1 | 1 | 0 |
| **Stealth** | 5 | 1 | **4** |

**The largest uncovered tactic is Stealth (TA0005 — called Defense Evasion before ATT&CK v18):**
4 of its 5 techniques have no rule, and counting T1548.002 under Stealth as well as Privilege
Escalation makes it 5 of 6.

Discovery is level with it at 4 of 5 and is the more actionable of the two, though not uniformly:
**three of its four gaps are layer-3 holes — T1016, T1033 and T1087.** All three were executed, their
telemetry was generated, and their channels are forwarded. Nothing actionable matched: T1016 and
T1033 only through the level-3 catch-all `67027`, and T1087's two 4798/4799 events not at all. The
fourth,
T1046, is not a rule backlog item at all: its own row scores Generation ◐ and Collection ◐, because a
host agent cannot see a SYN to a filtered port with the subcategories this endpoint enables. It needs
a sensor, and counting it as a rule to write is exactly the mistake the method in
[`../docs/02-detection-methodology.md`](../docs/02-detection-methodology.md) exists to prevent.

Two of the four Stealth gaps, by contrast, are gaps because the activity was never produced
(T1684.002 needs a mail server this lab does not have; T1685.005 has never been triggered).

That points the work in one direction, and it is the direction the measurements already argued for:
discovery activity cannot be detected one command at a time — `whoami.exe` produced the same alert as
`sppsvc.exe` — so it has to be detected as a **sequence** under one parent or one logon session. That
rule is written: `proc_creation_win_lolbin_discovery_burst.yml`, a `value_count` correlation over
three or more distinct discovery utilities under one `ParentProcessGuid` in 60 s. It is drafted and
undeployed, like the other eleven files, so none of the three Discovery gaps has closed yet. The
inventory and the remaining backlog are in [`README.md`](README.md).
