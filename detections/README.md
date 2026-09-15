# Detections

Rules live here only when a gap was **measured** first. Nothing in this folder was added because a
framework lists the technique, because a blog post recommended it, or to make the list longer.

Every claim below that came from the lab names the date it was measured and the command or query
that produced it. The lab itself is described in [`../docs/01-lab-architecture.md`](../docs/01-lab-architecture.md).
Credentials never appear in this repository: the lab account is written `<LAB_USER>` and passwords
`<REDACTED>`. The `10.10.10.0/24` addresses are private lab addresses.

---

## 1. Why a rule exists here

Coverage is not one thing. It is three layers, and they fail independently:

| Layer | Question | How it fails |
|---|---|---|
| Generation | Does the operating system write the event at all? | Loudly — the event simply is not in the log, and `Get-WinEvent` says so. |
| Collection | Does the agent forward that channel to the SIEM? | Loudly — the channel is missing from `ossec.conf`. |
| Detection | Does any rule match the event once it arrives? | **Silently.** No error, no missing-alert indicator, nothing to search for. |

That third row is the whole reason this folder exists. It was measured on 2026-08-08: Event ID 4697
("a service was installed") was confirmed in the endpoint's Security log with
`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697}`, the Security channel is declared in
the agent's `ossec.conf`, and a `wazuh-alerts-*` query returned **0 documents** containing Event ID
4697. The same real-world fact — a service was installed — did alert, through Event ID 7045 from the
System channel. Nothing on the dashboard indicated that half the evidence had been dropped.
([`../investigations/001-first-alert-triage.md`](../investigations/001-first-alert-triage.md))

So the rule for rules here is:

> A rule is written to close a layer-3 hole that has been demonstrated with a query. If the hole is
> in layer 1 or layer 2, a rule cannot fix it, and pretending otherwise is worse than leaving the
> gap open — it puts a green tick over a blind spot.

Two consequences, both visible in this folder: it is small, and it contains a section for gaps that
are deliberately **not** being closed with a rule.

---

## 2. From observation to validated detection

The pipeline used in this lab. Steps 1–6 have been carried out for the rules listed in section 3.
Step 7 has **not** been carried out for any rule in this folder yet — see the status note under the
inventory table.

1. **Generate the activity on purpose** and record the exact UTC window. Either from the attacker VM
   (Kali, `10.10.10.5`) or with a script on the endpoint. Nothing is investigated that was not first
   caused deliberately, and the writeups say so.
2. **Confirm generation on the endpoint.** `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=<id>}`,
   and `[xml]$_.ToXml()` to read the fields rather than the rendered description — the description
   text is the same for events that mean different things. Measured example: ten 4625 events on
   2026-08-08 read identically and split cleanly into five logon type 2 (local `runas`, `seclogo`,
   `::1`) and five logon type 3 (SMB from Kali, `NtLmSsp`, NTLM, `10.10.10.5`).
3. **Confirm collection.** The channel must be listed in the agent's `ossec.conf`. This lab forwards
   Security, System, Application, `Microsoft-Windows-Sysmon/Operational` and
   `Microsoft-Windows-PowerShell/Operational`.
4. **Query the SIEM for the event.** The indexer listens on 9200 on localhost only inside the SIEM VM,
   so a NAT port-forward to it fails with `curl` error 35. The path that works from the host is the
   dashboard console proxy already exposed on 8443:

   ```bash
   curl -k -u admin:<REDACTED> -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
     -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
     -d @query.json
   ```

   Two measured traps in that query. Search **by field**, not free text: a `query_string` search for
   the unique marker string used on 2026-08-11 returned 0 results while the string sat in
   `data.win.eventdata.commandLine` of indexed documents. And pin the time range to
   `data.win.system.systemTime`, not `@timestamp`: the Wazuh `@timestamp` is the manager's clock and
   ran 1.754 s / 1.821 s / 1.757 s behind the endpoint across three consecutive `eventRecordID`s.
   For Sysmon Events 3 and 22, read the event's own `UtcTime` — the channel wrote them 4.0 s and 3.2 s
   after they happened, which is enough to reverse cause and effect in a timeline.
5. **Widen the window before declaring a gap.** On 2026-08-11 an apparent gap (4 × 4624 generated,
   2 alerted) disappeared when the range was widened by twenty seconds: there were 8 × 4624 and all
   eight alerted. Each remote invocation produces a *pair* of 4624 events and the pairs were being cut
   in half by the window boundary. A false gap in a coverage report is as damaging as a false positive
   in a queue. Only gaps that survived a widened window were reported as real.
6. **Check what already fires before writing anything.** Some events are already covered, badly:
   rule `67027` matches *every* Security 4688 at level 3, so 16 of 16 process creations alerted in the
   2026-08-11 window — coverage without discrimination. A new rule there must add a discriminator
   (ancestry, command line, sequence), not another level-3 line.
7. **Deploy and validate.** Re-run the exact activity from step 1, then query the alert index for the
   new rule ID inside the new window. A rule is `validated` only when that query returns the document,
   and the entry records the date and the query.
8. **Measure false positives before trusting the level.** Rule `92213` fires at level 15 —
   the maximum — and produced 18 firings in this lab (1 on 2026-08-08, 5 on 2026-08-11, 12 on
   2026-09-07), every one of them a false positive on a file PowerShell writes to test its own
   execution policy. Severity measures how bad the event would be if real, not how likely it is to be
   real. The level a rule ships with is an opinion held by whoever wrote it.

---

## 3. Rule inventory

Validation status vocabulary — used strictly:

| Status | Meaning |
|---|---|
| `planned` | The gap is measured and written down. The rule file does not exist. |
| `drafted` | The rule file exists and its logic was derived from lab measurement, but it has never been run against this lab's data. |
| `validated` | The rule was deployed, the source activity was re-run, and a query returned the alert. The entry records the date and the query. |
| `tuning` | Deployed and firing, but its false-positive rate has not been measured yet, so its level is not trusted. |

| File | What it detects | ATT&CK | Validation status |
|---|---|---|---|
| [`sigma/proc_creation_win_encoded_powershell.yml`](sigma/proc_creation_win_encoded_powershell.yml) | `powershell.exe` / `pwsh.exe` started with `-EncodedCommand` or its abbreviations, matched from Security 4688 or Sysmon Event ID 1, with an `OriginalFileName` branch so a renamed binary still matches | T1059.001, T1027 | `drafted` |
| [`sigma/proc_creation_win_office_browser_spawning_shell.yml`](sigma/proc_creation_win_office_browser_spawning_shell.yml) | A document application or browser creating a shell or scripting interpreter as a child process | T1059.001, T1059.003, T1566.001 | `drafted` |

**Status, stated plainly:** no rule in this folder has been deployed to the lab manager, so nothing
here is `validated` yet. Both rules were derived from measurements in this lab, and both describe the
measurement in their own `description` block. The second one cannot be validated in this lab at all
in its current form: Office is not installed on the endpoint and no browser has ever been observed
spawning a child process in a measured window, which is recorded in its `falsepositives` section
rather than hidden.

### Backlog — measured gaps with no rule yet

Each row is a hole that was demonstrated with a query, not a suspicion. None has a file yet, so none
has a filename.

| Gap (measured) | Evidence | Proposed detection | ATT&CK |
|---|---|---|---|
| Security 4697 (service installed) is generated and collected and matches no rule | 4697 present in the log 2026-08-08; 0 documents in `wazuh-alerts-*` | Match 4697 and alert when `ServiceFileName` points outside `System32`, or when `ServiceName` resembles but does not equal a real system service | T1543.003, T1036.004 |
| Discovery commands are indistinguishable from background noise | `whoami.exe` produced the same level-3 alert as `sppsvc.exe` (rule 67027), 2026-08-11 | A **sequence** rule, not a single-event rule: three or more of `whoami`, `net user`, `net localgroup`, `nltest`, `systeminfo`, `ipconfig /all`, `arp -a`, `quser` under one `ParentProcessGuid` or `SubjectLogonId` inside 60 s | T1033, T1087, T1016 |
| Security 4798/4799 (local group membership enumeration) produce no alert | 2 events generated, 0 alerts, confirmed against a widened window, 2026-08-11 | Several 4798/4799 under the same `SubjectLogonId` in a short window — the local enumeration signature | T1087 |
| Security 4648 (logon with explicit credentials) produces no alert | 1 event generated, 0 alerts, confirmed against a widened window, 2026-08-11 | Alert where `SubjectUserName` differs from `TargetUserName` and the calling process is not a known administrative tool | T1078.003 |
| Password spraying cannot be separated from one user mistyping a password | Rule 60204 accumulates 60122 events but never reads `SubStatus`; 2026-09-07 saw 15 × `0xC0000064` then 3 × `0xC000006A` | Burst of 4625 with `SubStatus 0xC0000064` across three or more distinct `TargetUserName` values from one source IP; plus a 24 h variant grouped by source IP, because the 2 s SMB rate limiter lets a slow attacker under any short window | T1110.001 |
| An RDP failure is indistinguishable from an SMB failure by logon type | With NLA active, 4 failed RDP logons appeared as 4625 **type 3**; only the completed graphical session produced type 10, 2026-09-07 | Correlate 4625 type 3 with TerminalServices-RemoteConnectionManager 1149 / 261 in the same window to reclassify the failure as RDP | T1021.001 |
| Sysmon Event ID 3 (network connection) is ingested with zero detection coverage | 1 event / 0 alerts on 2026-08-11; 2 inbound `Initiated=false` events to `:3389` / 0 alerts on 2026-09-07 | Interpreter process (`powershell`, `cmd`, `wscript`, `mshta`) connecting outside the local subnet, read from the event's `UtcTime`; plus repeated inbound `Initiated=false` from one source | T1059.001 |
| Sysmon Event ID 22 (DNS query) is ingested with zero detection coverage | 1 event / 0 alerts, 2026-08-11 | Query name on an intel or newly-registered-domain list, or repeated NXDOMAIN from one `ProcessGuid`; correlate by `ProcessGuid`, never by PID | Not mapped yet |
| Security 1102 (audit log cleared) has never been generated, so its detection path is untested | The only one of the author's twelve priority Event IDs with no measured data | Alert on 1102 unconditionally at high severity. The task is first a **lab** task: trigger it deliberately and confirm the path end to end. The `base-limpia` snapshot exists for the rollback | T1070.001 |

---

## 4. Gaps a rule cannot close

Recorded here rather than converted into a rule that would not work.

| Gap | Layer | Why a rule does not fix it |
|---|---|---|
| Port scans are invisible | Collection | A 65,535-port SYN scan lasting 88 s produced **0** attributable alerts; a 7-port `-sS -sV` scan left 2 Sysmon Event ID 3 events and 0 Security 5156, because the Filtering Platform Connection subcategory is deliberately not audited (very high volume). A Wazuh agent reads Windows event logs and Windows does not record a SYN to a closed port anywhere. The options are to enable 5156/5157 auditing and accept the volume, or to put a network sensor on the segment. The honest answer is the second. |
| No time synchronisation | Collection | A consistent ~1.8 s offset between the endpoint clock and the manager clock, plus a 3–4 s channel-write lag inside Sysmon 3 and 22. Fixed by configuring NTP on both VMs and pinning queries to `data.win.system.systemTime`, not by a rule. It becomes materially more important once a domain controller joins the lab, since Kerberos rejects a skew above 5 minutes. |
| Rule 92213 fires at level 15 on benign PowerShell behaviour | Tuning debt | Not a missing rule — an existing rule that needs an exclusion for `__PSScriptPolicyTest_*.ps1` written by the signed system `powershell.exe`. Until that is done, level 15 carries no information in this lab, and sorting the queue by severity is actively harmful. |

---

## 5. Deploying to Wazuh

Nothing below has been executed against this lab's manager yet. It is written from the Wazuh
documentation and from how the lab is already wired, and it is flagged as such so that the difference
between "this works" and "this is the plan" stays visible.

**Sigma is the source of truth in this repository; the Wazuh XML is a translation of it.** There is no
pySigma backend for Wazuh that has been tested here, so the intended path is manual translation, with
the Sigma rule `id` carried into the XML `<description>` so the two never drift apart silently.

Field names matter and were measured: the Wazuh decoder exposes Windows event data as
`data.win.system.*` and `data.win.eventdata.*`, with a lowercase first letter —
`data.win.eventdata.commandLine`, not `CommandLine`. A Sigma rule that is translated without checking
this produces a rule that never matches and never errors.

Steps:

1. Write the rule into `/var/ossec/etc/rules/local_rules.xml` on `WAZUH-SIEM`. Custom rules use IDs
   from 100000 upward, per the Wazuh documentation, so they cannot collide with the shipped ruleset
   (`60xxx`, `67xxx`, `92xxx` in the alerts measured here).
2. Test the rule against a sample event **before** restarting anything:
   `/var/ossec/bin/wazuh-logtest`.
3. Apply: `sudo systemctl restart wazuh-manager`.
4. Re-run the activity from step 1 of the pipeline and query `wazuh-alerts-*` for the new rule ID,
   filtering on `data.win.system.systemTime`.
5. Record the result in the inventory table — date, query, and outcome — and move the row to
   `validated` or `tuning`.

Shape of a custom rule for the 4697 gap, as a draft and not as a tested artefact:

```xml
<group name="windows,sysmon,local,">
  <rule id="100001" level="8">
    <if_sid>60009</if_sid>
    <field name="win.system.eventID">^4697$</field>
    <description>Service installed (Security 4697) - not covered by the default ruleset</description>
    <mitre><id>T1543.003</id></mitre>
  </rule>
</group>
```

The `if_sid` parent, the exact level and the field spelling are precisely what step 2 exists to check.
Publishing the draft before testing it would be the same mistake as publishing a coverage matrix
built from a framework list instead of from queries.

**Level discipline.** Pick the level from the action the alert should trigger, not from how alarming
the technique sounds. In this lab the most informative alert of an entire reconnaissance phase was a
level 6 (rule 92652, anonymous SMB session), while the only level 15 was noise 18 times out of 18.

---

## 6. Related files

| File | What it holds |
|---|---|
| [`coverage-matrix.md`](coverage-matrix.md) | Every ATT&CK technique with measured evidence in this lab, scored across the three layers, with the honest coverage number |
| [`attack-navigator-layer.json`](attack-navigator-layer.json) | The same data as an ATT&CK Navigator layer (layer format 4.5, ATT&CK v18) |
| [`../investigations/001-first-alert-triage.md`](../investigations/001-first-alert-triage.md) | The 2026-08-08 end-to-end verification: 82 alerts, the level-15 false positive, the invisible 4697 gap |
| [`../investigations/002-process-telemetry-correlation.md`](../investigations/002-process-telemetry-correlation.md) | The 2026-08-11 visibility exercise: 4688 vs Sysmon 1 vs Wazuh, 167 events to 27 alerts |
| [`../investigations/003-smb-rdp-attack-chain.md`](../investigations/003-smb-rdp-attack-chain.md) | The 2026-09-07 controlled SMB/RDP chain: `SubStatus` codes, NLA and logon types, the SMB rate limiter |
| [`../docs/01-lab-architecture.md`](../docs/01-lab-architecture.md) | The lab the measurements were taken on |
