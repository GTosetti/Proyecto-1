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

One caveat travels with that result everywhere it is used in this folder. Collection was confirmed by
reading the agent's `ossec.conf`, not by watching the event arrive: the manager indexes what matched a
rule, so an event that matched nothing leaves nothing to query. From the alert index alone, a layer-2
failure and a layer-3 failure look identical. What narrows it here is circumstantial and worth stating
as such: other Security-channel events from the same window did alert — 4720/4722 through rule 60109,
4738 through 60110, 4726 through 60111, 4732/4733 through 60154 — so the channel was reaching the
manager while 4697 produced nothing. That makes layer 3 the likely explanation, not a proven one. Step 3 below says what would
prove it.

So the rule for rules here is:

> A rule is written to close a layer-3 hole that has been demonstrated with a query. If the hole is
> in layer 1 or layer 2, a rule cannot fix it, and pretending otherwise is worse than leaving the
> gap open — it puts a green tick over a blind spot.

Two consequences, both visible in this folder: it is small — 25 rule documents, each traceable to a
dated measurement — and it contains a section for gaps that are deliberately **not** being closed
with a rule.

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
3. **Confirm collection, and know how weak this step is.** The channel must be listed in the agent's
   `ossec.conf`. This lab forwards Security, System, Application,
   `Microsoft-Windows-Sysmon/Operational` and `Microsoft-Windows-PowerShell/Operational`, and the
   agent reports `connected`. That is a declaration plus a heartbeat, not a measurement of the event
   itself. Wazuh indexes only what matched a rule, so an event that matched nothing cannot be found
   in the index whether it arrived or not. Collection is therefore **inferred** everywhere in this
   repository and was never independently verified, and no layer-3 conclusion drawn this way can rule
   out a layer-2 cause. Measuring it needs `<logall_json>yes</logall_json>` on the manager and a query
   against `wazuh-archives-*`. That has not been done here.
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
   2 alerted) disappeared when the range was widened by twenty seconds: the four remote invocations in
   the window had produced 8 × 4624 and 4 × 4672, and every one of them alerted. Each invocation
   produces a *pair* of 4624 events and the pairs were being cut in half by the window boundary. A false gap in a coverage report is as damaging as a false positive
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

`detections/sigma/` holds **15 files containing 25 rule documents**, eight of which are correlation
rules. A file holds more than one document when a correlation needs its base events declared
alongside it; the `Docs` column gives the count, and the base documents ship at level
`informational` because they exist to be counted, not triaged.

| File | Docs | What it detects | ATT&CK | Validation status |
|---|:--:|---|---|---|
| [`sigma/proc_creation_win_encoded_powershell.yml`](sigma/proc_creation_win_encoded_powershell.yml) | 1 | `powershell.exe` / `pwsh.exe` started with `-EncodedCommand` or its abbreviations, matched from Security 4688 or Sysmon Event ID 1, with an `OriginalFileName` branch so a renamed binary still matches | T1059.001, T1027 | `drafted` |
| [`sigma/proc_creation_win_office_browser_spawning_shell.yml`](sigma/proc_creation_win_office_browser_spawning_shell.yml) | 1 | A document application or browser creating a shell or scripting interpreter as a child process | T1059.001, T1059.003, T1566.001 | `drafted` |
| [`sigma/proc_creation_win_lolbin_discovery_burst.yml`](sigma/proc_creation_win_lolbin_discovery_burst.yml) | 2 (1 correlation) | A single built-in discovery utility (`whoami`, `net user`, `nltest`, `systeminfo`, `ipconfig`, `arp`, `quser`, `tasklist`) as an informational base event, plus a `value_count` correlation on three or more distinct utilities under one `ParentProcessGuid` inside 60 s | T1033, T1087.001, T1016, T1082 | `drafted` |
| [`sigma/win_security_susp_service_installation.yml`](sigma/win_security_susp_service_installation.yml) | 1 | Security 4697 where the service image sits outside `System32`/`SysWOW64`, the service name imitates a Windows service, or the service runs a script interpreter | T1543.003, T1036.004 | `drafted` |
| [`sigma/win_security_password_spray_nonexistent_accounts.yml`](sigma/win_security_password_spray_nonexistent_accounts.yml) | 3 (2 correlations) | 4625 with `SubStatus 0xC0000064` as the base event, then a short-window spray correlation across distinct non-existent usernames from one source, and a 24 h variant for a slow attacker under any short window | T1110.001, T1110.003, T1087.001 | `drafted` |
| [`sigma/win_security_targeted_password_guessing_valid_account.yml`](sigma/win_security_targeted_password_guessing_valid_account.yml) | 2 (1 correlation) | 4625 with `SubStatus 0xC000006A` as the base event, then repeated wrong passwords against one existing account from one source — the moment enumeration becomes targeted | T1110.001 | `drafted` |
| [`sigma/win_security_anonymous_logon_smb_null_session.yml`](sigma/win_security_anonymous_logon_smb_null_session.yml) | 1 | 4624 `ANONYMOUS LOGON`, logon type 3, from a non-local address: the SMB null session that precedes share and account enumeration | T1135, T1087.001 | `drafted` |
| [`sigma/win_security_rdp_bruteforce_behind_nla.yml`](sigma/win_security_rdp_bruteforce_behind_nla.yml) | 4 (2 correlations) | Failed type-3 logons and RDP listener activity as base events, a burst correlation over 4625 type 3 from one source, and a temporal correlation that reclassifies that burst as RDP when the listener channel corroborates it | T1110.001, T1021.001 | `drafted` |
| [`sigma/win_security_successful_interactive_rdp_session.yml`](sigma/win_security_successful_interactive_rdp_session.yml) | 3 (1 correlation) | 4624 logon type 10 and TerminalServices-LocalSessionManager session events as base documents, correlated into "an interactive RDP session was actually established" rather than "someone authenticated" | T1021.001, T1078.003 | `drafted` |
| [`sigma/net_connection_win_script_interpreter_external_dest.yml`](sigma/net_connection_win_script_interpreter_external_dest.yml) | 1 | Sysmon Event ID 3: a shell or scripting interpreter opening an outbound connection to an address outside the private, loopback, link-local and multicast ranges | T1071.001, T1059.001 | `drafted` |
| [`sigma/dns_query_win_unexpected_process.yml`](sigma/dns_query_win_unexpected_process.yml) | 1 | Sysmon Event ID 22: a DNS query issued by a discovery binary or a simple desktop application, neither of which has a reason to resolve a name | T1071.004, T1036.003 | `drafted` |
| [`sigma/file_event_win_executable_dropped_excluding_psscriptpolicytest.yml`](sigma/file_event_win_executable_dropped_excluding_psscriptpolicytest.yml) | 1 | Sysmon Event ID 11: an executable or script written to a user-writable folder, with the one false positive this lab measured four times (`__PSScriptPolicyTest_*.ps1`) excluded by writer path, prefix and extension together | T1105 | `drafted` |

| [`sigma/proc_creation_win_lolbin_remote_download.yml`](sigma/proc_creation_win_lolbin_remote_download.yml) | 1 | `certutil`, `bitsadmin` or `regsvr32` pulling a file from an `http`/`https` URL — the LOLBin download. Written because Defender caught the `certutil` and `regsvr32` command lines on 2026-09-17 but its verdict never reached the SIEM | T1105, T1218.010 | `drafted` |
| [`sigma/dns_query_win_high_entropy_subdomain.yml`](sigma/dns_query_win_high_entropy_subdomain.yml) | 1 | Sysmon Event ID 22: a DNS query whose leftmost label is 20+ chars of base32/base64 alphabet, the shape of data over DNS, with a CDN allowlist. Closes the Sysmon 22 gap re-measured on 2026-09-17 (5 beacons, 0 alerts) | T1071.004, T1048 | `drafted` |
| [`sigma/win_security_local_group_enumeration_burst.yml`](sigma/win_security_local_group_enumeration_burst.yml) | 2 (1 correlation) | Security 4798/4799 as an informational base event filtered of the system SIDs, plus a `event_count` correlation of 10+ under one `SubjectLogonId` in 60 s — the SharpHound-shaped enumeration. Closes the 4798/4799 gap (7 events, 0 alerts, 2026-09-17) | T1069.001, T1087.001 | `drafted` |

**Status, stated plainly:** all 25 documents pass `sigma check` with 0 errors, and they convert — 9
files under the `opensearch_lucene` backend, the 5 files carrying `stats` correlations under `esql`,
and the temporal RDP rule under `open_search_ppl` once field aliases are applied. **None of them has
been deployed to the lab manager, so none is `validated` in the sense defined above, and the count of
techniques detected by a rule of mine stays at 0.** Every rule derives its log source, fields and
thresholds from a measurement recorded in its own `description` block. One of them cannot be validated
in this lab at all in its current form: Office is not installed on the endpoint and no browser has
ever been observed spawning a child process in a measured window, which is recorded in that rule's
`falsepositives` section rather than hidden.

Provenance and per-rule detail — naming convention, the multi-document file layout, conversion
commands and the measurement behind each rule — are in
[`sigma/README.md`](sigma/README.md).

### Backlog — measured gaps with no rule yet

Each row is a hole that was demonstrated with a query, not a suspicion. These two are what is left
after the fifteen files above; every other measured gap now has a drafted rule.

| Gap (measured) | Evidence | Proposed detection | ATT&CK |
|---|---|---|---|
| Security 4648 (logon with explicit credentials) produces no alert | 1 event generated, 0 alerts, confirmed against a widened window, 2026-08-11 | Alert where `SubjectUserName` differs from `TargetUserName` and the calling process is not a known administrative tool | T1078.003 |
| Security 1102 (audit log cleared) has never been generated, so its detection path is untested | No 1102 has ever been produced in this lab and no query has been run against it — the gap is the absence of the exercise, not the absence of a query result | Alert on 1102 unconditionally at high severity. The task is first a **lab** task: trigger it deliberately and confirm the path end to end. The `base-limpia` snapshot exists for the rollback | T1685.005 (numbered T1070.001 before the v18 regrouping) |

---

## 4. Gaps a rule cannot close

Recorded here rather than converted into a rule that would not work.

| Gap | Layer | Why a rule does not fix it |
|---|---|---|
| Port scans are invisible | Collection | A 65,535-port SYN scan lasting 88 s produced **0** attributable alerts; a 7-port `-sS -sV` scan left 2 Sysmon Event ID 3 events and 0 Security 5156. With the audit subcategories enabled on this endpoint, nothing recorded the scan. The subcategory that would is *Audit Filtering Platform Packet Drop* (5152/5153), which is off here and was never measured; *Audit Filtering Platform Connection* (5156/5157) is also off, and even enabled it would only have recorded the 8 permitted connections, not the 65,527 filtered ones. So the host-side option is 5152/5153 and its volume, and the alternative is a network sensor on the segment. The answer here is the sensor. |
| No time synchronisation | Collection | A consistent ~1.8 s offset between the endpoint clock and the manager clock, plus a 3–4 s channel-write lag inside Sysmon 3 and 22. Fixed by configuring NTP on both VMs and pinning queries to `data.win.system.systemTime`, not by a rule. It becomes materially more important once a domain controller joins the lab, since Kerberos rejects a skew above 5 minutes. |
| Rule 92213 fires at level 15 on benign PowerShell behaviour | Tuning debt | Not a missing rule — an existing rule that needs an exclusion for `__PSScriptPolicyTest_*.ps1` written by the signed system `powershell.exe`. The replacement is drafted (`file_event_win_executable_dropped_excluding_psscriptpolicytest.yml`) and, like everything else here, not deployed: the stock rule is still what fires on this endpoint. Until that changes, level 15 carries no information in this lab, and sorting the queue by severity is actively harmful. |

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
<group name="windows,windows_security,local,">
  <rule id="100001" level="8">
    <if_sid>60009</if_sid>
    <field name="win.system.eventID">^4697$</field>
    <description>Service installed (Security 4697) - not covered by the default ruleset</description>
    <mitre><id>T1543.003</id></mitre>
  </rule>
</group>
```

The group name is `windows_security`, not `sysmon`: 4697 comes from the Security channel, and a rule
filed under the wrong group is mis-sorted by every dashboard pivot that reads `rule.groups`. The
`if_sid` parent, the exact level, the group list and the field spelling are precisely what step 2
exists to check.
Publishing the draft before testing it would be the same mistake as publishing a coverage matrix
built from a framework list instead of from queries.

**Level discipline.** Pick the level from the action the alert should trigger, not from how alarming
the technique sounds. In this lab the most informative alert of an entire reconnaissance phase was a
level 6 (rule 92652, anonymous SMB session), while the only level 15 was noise 18 times out of 18.

---

## 6. Related files

| File | What it holds |
|---|---|
| [`sigma/README.md`](sigma/README.md) | The ruleset itself: naming convention, why several documents share a file, the `sigma convert` commands and their backend limits, and the lab measurement behind each rule |
| [`coverage-matrix.md`](coverage-matrix.md) | Every ATT&CK technique with measured evidence in this lab, scored across the three layers, with the honest coverage number |
| [`attack-navigator-layer.json`](attack-navigator-layer.json) | The same data as an ATT&CK Navigator layer (layer format 4.5, ATT&CK v18) |
| [`../investigations/001-first-alert-triage.md`](../investigations/001-first-alert-triage.md) | The 2026-08-08 end-to-end verification: 82 alerts, the level-15 false positive, the invisible 4697 gap |
| [`../investigations/002-process-telemetry-correlation.md`](../investigations/002-process-telemetry-correlation.md) | The 2026-08-11 visibility exercise: 4688 vs Sysmon 1 vs Wazuh, 172 events to 36 alerts |
| [`../investigations/003-smb-rdp-attack-chain.md`](../investigations/003-smb-rdp-attack-chain.md) | The 2026-09-07 controlled SMB/RDP chain: `SubStatus` codes, NLA and logon types, the SMB rate limiter |
| [`../docs/01-lab-architecture.md`](../docs/01-lab-architecture.md) | The lab the measurements were taken on |
