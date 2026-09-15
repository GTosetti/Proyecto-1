# 001 — First alert triage: 82 alerts, and the three that taught something

**Date of exercise:** 2026-08-08 · **Environment:** self-built home lab (`WIN11-VICTIMA` 10.10.10.20 → `WAZUH-SIEM` 10.10.10.10, attacker VM on the `SOCLAB` NAT network) · **Analyst:** me · **Role played by the same person:** attacker (see disclosure below)

---

## Findings first

Three results came out of triaging this batch, and all three are worth more than the lab build that produced them.

| # | Finding | Measurement behind it |
|---|---|---|
| 1 | **The only maximum-severity alert in the batch was a false positive.** Level 15, rule `92213` ("Executable file dropped in folder commonly used by malware", T1105), fired on `__PSScriptPolicyTest_<random>.ps1` — a file PowerShell writes into `%TEMP%` to test its own execution policy, written by the signed system `powershell.exe`. The simulated intrusion that actually mattered (local user created → added to Administrators → deleted, in 8 seconds) surfaced at levels 8 and 12, below the noise. | 82 alerts, level distribution 3→53, 4→7, 5→13, 8→5, 12→3, 15→1. The same false positive reproduced 5 times on 2026-08-11 and 12 times on 2026-09-07. |
| 2 | **A full 65,535-port TCP SYN scan produced zero alerts.** Not a misconfiguration — a structural limit. A Wazuh agent reads Windows event logs, and Windows does not log a SYN to a closed port anywhere. | `nmap -sS -p- -T4` ran 88 s and found 8 open ports / 65,527 filtered. Six alerts fell inside that window and all six were unrelated background `4688` process-creation events. |
| 3 | **Event ID 4697 reaches the Windows Security log, is forwarded by the agent, and never becomes an alert**, because no rule in the default ruleset matches it. It fails silently: no error, no missing-alert indicator, nothing to search for. | `Get-WinEvent` confirmed `4697` in the Security log inside the exercise window; a `wazuh-alerts-*` query returned 0 documents with that Event ID. The same real-world fact — a service was installed — did alert, via `7045` from the System channel. |

The single sentence that carries finding 1: **rule severity measures how bad the event would be if it were real, not the probability that it is real.** A level-15 rule that fires repeatedly on legitimate activity trains an analyst to ignore level 15, which is the exact failure mode that lets a real incident through.

Finding 3 generalises into a model used in every later exercise in this repository — coverage has three independent layers, and only the third one fails invisibly:

| Layer | Question | Result for 4697 |
|---|---|---|
| 1 · Generation | Does the OS write it? | Yes — `4697` present in the Security log |
| 2 · Collection | Does the agent ship it? | Yes — the Security channel is declared in the agent's `ossec.conf` |
| 3 · Detection | Does any rule match it? | **No. This is where it is lost.** |

---

## Disclosure

**I executed the activity I then investigated, and I knew what I had run before I opened the dashboard.** A reader would assume it anyway, and hiding it would cost more credibility than admitting it. Concretely, that means:

- This is a **controlled generation-and-verification exercise**, not an unscripted investigation. It does not demonstrate that I can work an alert of unknown origin.
- The triage conclusions about *detection coverage* survive that caveat, because they are negative results — the SIEM either produced an alert or it did not, and knowing the answer in advance cannot manufacture an alert that was never raised.
- The conclusions about *analyst judgement under uncertainty* do not survive it, and I do not claim them.

A second honesty note, on method: the writeup template I used starts with a written prediction table, to be filled in **before** looking at the data. **In this run I left it blank** and executed and observed almost simultaneously, which cost me the most valuable part of the exercise — a failed prediction is a precisely located knowledge gap, and I threw away the chance to locate any. The section below reconstructs what I actually expected, and labels it as a reconstruction. The correction was applied in the following two exercises, both of which state their hypotheses up front and record which ones were falsified.

---

## Scenario and scope

**Scenario.** The lab had just been finished: a Windows 11 Pro endpoint with advanced audit policy, command line recorded inside `4688`, PowerShell ScriptBlock and Module logging, Sysmon (SwiftOnSecurity configuration) and a Wazuh agent in `connected` state forwarding the Security, System, Application, Sysmon/Operational and PowerShell/Operational channels to a Wazuh 4.14 all-in-one manager. Nothing had ever been verified end to end.

The question the exercise had to answer was not "does the lab work" but the harder version of it: **when I deliberately cause a known set of events, which of them come out the other side as alerts, at what severity, and which do not come out at all?**

**In scope.** Alerts indexed in `wazuh-alerts-*` for the endpoint `WIN11-VICTIMA` during three consecutive windows on 2026-08-08; the Windows Security, System, PowerShell/Operational and Sysmon/Operational channels on the endpoint; correlation between the two.

**Out of scope.** Network-level telemetry — there is no IDS and no packet capture on the segment, which is itself one of the findings. Malware analysis: nothing malicious was executed, only benign binaries and account-management commands. The domain controller did not exist yet, so nothing about Kerberos, domain accounts or group policy is covered.

**Timezone note.** The endpoint clock runs at UTC−3. The same service-installation event appears as `21:44:56` local on 2026-08-08 and `00:44:56Z`. Every timestamp in this document is **UTC** unless it says "local".

---

## Hypothesis stated before looking at data

Stated honestly: **these were not written down before observation.** They are the expectations encoded in the event-generation script I wrote beforehand, reconstructed here so the comparison in the Analysis section is meaningful rather than retrofitted. Treat them as "what the script's own documentation predicted", which is verifiable, rather than "what I predicted", which is not.

| # | Activity generated | Expected detection path | Outcome |
|---|---|---|---|
| H1 | 5 failed logons with a non-existent user | Security `4625`, alerting | Confirmed — 10 `4625` in total, see split below |
| H2 | Process tree `cmd.exe → powershell.exe → whoami.exe` | Security `4688` and Sysmon 1 | Confirmed, but only as generic level-3 alerts |
| H3 | `powershell -EncodedCommand` (base64) | **PowerShell `4104`**, Script Block Logging | **Falsified** — the level-12 alert came from Sysmon Event 1, not from `4104` |
| H4 | Reconnaissance batch (`whoami /priv`, `net user`, `net localgroup administrators`, `ipconfig /all`, `systeminfo`) | `4688` per command | Confirmed, and that is the problem — level 3, indistinguishable from background |
| H5 | Local user created, added to Administrators, deleted | `4720` / `4732` / `4726`, alerting at high level | Partially falsified — it alerted, but at levels 8 and 12, below the level-15 noise |
| H6 | Test service installed | `4697` **and** `7045` | **Falsified** — `7045` alerted, `4697` never became an alert |
| H7 | `nmap -sS -p-` from the attacker VM | Some form of alerting | **Falsified** — zero alerts |
| H8 | 5 SMB attempts with false credentials from the attacker VM | `4625` logon type 3 | Confirmed |

Three of eight expectations were wrong, and the three wrong ones are the three findings.

---

## Evidence collected

### Access path to the SIEM, and why it is not the obvious one

The Wazuh indexer listens on `9200` **only on localhost inside the SIEM VM**, so a VirtualBox NAT port-forward to `9200` fails (`curl` error 35, TLS). The path that works from the host is the **dashboard console proxy**, already exposed on the forwarded port and accepting basic auth. Every query below was issued this way, which made them scripted and repeatable instead of clicked:

```bash
curl -k -u <WAZUH_USER>:<REDACTED> \
  -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query.json
```

**Q1 — alert volume and severity distribution over the generation window** (`query.json`):

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term":  { "agent.name": "WIN11-VICTIMA" } },
        { "range": { "@timestamp": { "gte": "2026-08-09T00:44:40Z",
                                     "lte": "2026-08-09T00:45:10Z" } } }
      ]
    }
  },
  "aggs": {
    "by_level":    { "terms": { "field": "rule.level", "size": 20 } },
    "by_event_id": { "terms": { "field": "data.win.system.eventID", "size": 50 } },
    "by_rule":     { "terms": { "field": "rule.id", "size": 50 } }
  }
}
```

**Q2 — does Event ID 4697 exist anywhere in the alert index?** (the query behind finding 3):

```json
{
  "size": 5,
  "query": {
    "bool": {
      "filter": [
        { "term": { "agent.name": "WIN11-VICTIMA" } },
        { "term": { "data.win.system.eventID": "4697" } }
      ]
    }
  }
}
```

Result: `hits.total.value = 0`.

**Q3 — the endpoint-side half of the same question**, run on the endpoint in PowerShell 5.1:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4697 }
# 8/8/2026 9:44:56 PM   4697   A service was installed in the system
```

Two queries against two different layers, asking the same question, disagreeing. That disagreement is the finding.

**Method caveat worth recording:** a later exercise (2026-08-11) established that a `query_string` free-text search for a string that was demonstrably present in the index returned zero results, while a query targeting the field directly returned it. Field-targeted queries are not a stylistic preference here; free-text search is not reliable against this index, and an analyst who assumes otherwise will conclude that evidence does not exist when it is sitting in front of them.

### Evidence table

| Source | Artefact | What it proves |
|---|---|---|
| `wazuh-alerts-*` via Q1 | 82 alerts for the endpoint in the 8-second generation window, across 19 distinct Event IDs | The collection and detection pipeline is alive end to end |
| `wazuh-alerts-*` via Q1, `by_level` aggregation | 3→53, 4→7, 5→13, 8→5, 12→3, **15→1** | The severity profile of the batch; sets up finding 1 |
| `wazuh-alerts-*` via Q1, `by_rule` aggregation | Rule `92213`, level 15, Sysmon Event 11, T1105, on `C:\Users\<LAB_USER>\AppData\Local\Temp\__PSScriptPolicyTest_<random>.ps1`, image `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | The single highest-severity alert is a signed system process writing a file for its own use — a false positive |
| `wazuh-alerts-*` via Q1 | Rule `60154` level 12 on `4732` and again on `4733` (T1484); rule `60109` level 8 on `4720`/`4722`, rule `60110` level 8 on `4738` ×2, rule `60111` level 8 on `4726` (T1098, T1531) | The account-manipulation sequence was detected, but three levels below the false positive |
| `wazuh-alerts-*` via Q1 | Rule `92057` level 12, T1059.001, firing on **Sysmon Event 1** | The base64 command was caught by the process-creation source, not by the PowerShell channel that was expected to catch it |
| Security channel, `4625` field breakdown | 10 events splitting cleanly 5 / 5 by `logonType`; all 10 carrying `subStatus 0xC0000064` | Same Event ID, same description text, two different stories — see Analysis |
| Attacker VM, `nmap -sS -p- -T4 10.10.10.20` | 65,535 ports in 88 s; 8 open (135, 139, 445, 3389, 5040, 5357, 7680, 49668), 65,527 filtered | A loud, unambiguous network event took place |
| `wazuh-alerts-*`, same 88-second window | 6 alerts, all unrelated background `4688` | The loud network event left no trace in the alert index — host visibility, no network visibility |
| Endpoint Security log via Q3 vs alert index via Q2 | `4697` present on the endpoint, absent from the index; `7045` from the System channel alerted | A layer-3 (detection) coverage gap, invisible from the dashboard |
| Agent statistics vs index count | ~2,100 events reported to the manager (the agent-verification step counted 2,098 sent) → 835 alerts indexed for this endpoint | More than half the telemetry never became queryable, because it matched no rule at level ≥ 3 |

Per-Event-ID breakdown of the 82 alerts, as recorded at the time:

| Event ID | Count | What it is |
|---|---|---|
| 4688 | 38 | Process created (Security) |
| Sysmon 1 | 15 | Process created (Sysmon) |
| **4625** | **10** | **Failed logon** |
| 4624 / 4634 | 2 / 2 | Successful logon / logoff |
| 4738 | 2 | User account changed |
| 4720 / 4722 / 4726 | 1 / 1 / 1 | User created / enabled / deleted |
| 4728 / 4729 / 4732 / 4733 | 1 each | Added to and removed from groups (global and local) |
| 4104 | 1 | Script Block Logging — the base64 already decoded |
| 7045 | 1 | Service installed (System) |
| Sysmon 11 / 13 | 1 / 1 | File created / registry value set |
| 4672 | 1 | Special privileges assigned |

This tabulation accounts for 81 of the 82 alerts; one alert is not represented in the per-Event-ID counts I recorded, and I am not going to reconstruct it after the fact.

---

## Timeline

All times UTC. The batch straddles local midnight in Argentina (UTC−3), so the UTC date is 2026-08-09 while the exercise is dated by its local date, 2026-08-08.

| Time (UTC) | Origin | Event |
|---|---|---|
| 00:44:48 | Endpoint, local | Generation script starts: 5 failed console logons against a non-existent user |
| 00:44:48–00:44:56 | Endpoint, local | Process tree `cmd.exe → powershell.exe → whoami.exe`; `powershell -EncodedCommand`; reconnaissance batch (`whoami /priv`, `net user`, `net localgroup administrators`, `ipconfig /all`, `systeminfo`) |
| 00:44:48–00:44:56 | Endpoint, local | Local user created (`4720`/`4722`), added to Administrators (`4732`), test service installed (`4697` + `7045`), user deleted (`4726`) — the whole account sequence inside 8 seconds |
| 00:44:56 | Endpoint | `4697` "A service was installed in the system" written to the Security log (21:44:56 local) |
| 00:44:48–00:44:56 | SIEM | 82 alerts indexed for this endpoint, one of them at level 15 |
| 00:47:17–00:48:45 | Attacker VM | `nmap -sS -p- -T4 10.10.10.20` — 65,535 ports, 88 seconds, 8 open |
| 00:47:17–00:48:45 | SIEM | 6 alerts, all unrelated background `4688`. **Zero attributable to the scan** |
| 00:49:03–00:49:14 | Attacker VM | `smbclient -L //10.10.10.20 -U <fake-user>%<fake-pass>` ×5 |
| 00:49:03–00:49:14 | Endpoint / SIEM | 5 × `4625` logon type 3, `NtLmSsp` / NTLM, source 10.10.10.5, workstation `KALI` |

**Timeline caveat.** The axis above is the endpoint clock. A later measurement (2026-08-11) found that Wazuh's `@timestamp` — the dashboard's default time axis — is the **manager's** processing clock and runs about 1.8 s behind the endpoint (−1.754 s / −1.821 s / −1.757 s across three consecutive event records). The field to build a timeline on is `data.win.system.systemTime`. For an 8-second window that is not cosmetic, and I did not know it when I built this one.

---

## Analysis

### 1. Why the level-15 alert is noise and the level-8 alerts are the incident

Rule `92213` is correct about what it saw: an executable-extension file appeared in a directory malware commonly uses. What it cannot see is context — the writing process is the signed system PowerShell binary, the directory is that process's own `%TEMP%`, and the filename matches a fixed, documented pattern that PowerShell generates every time it checks its own execution policy before running a script. My own generation script caused it, simply by starting.

The inverse case is in the same batch. `4720 → 4732 → 4726` — an account created, granted local administrator, and deleted — completed in **8 seconds**. On a real endpoint that sequence is a textbook intrusion with cleanup. Wazuh rated it 8 and 12.

So an analyst who sorts the queue by severity and starts at the top spends the first minutes of the shift on PowerShell talking to itself, and reaches the actual intrusion later, if at all. That is not a Wazuh defect; it is what severity *means*. **Severity is a statement about impact if real. Priority requires probability, and probability comes from context the rule does not have.** The operational consequence is that an untuned ruleset must be tuned before its severity field is usable as a sort key — and that a known-false-positive list for your own environment is one of the highest-value artefacts a junior analyst can build, because it is what makes fast triage possible.

Reinforcing evidence for the tuning point: the same `92213` false positive reproduced **5 times** on 2026-08-11 and **12 times** on 2026-09-07. In a later exercise the highest-value alert of a real reconnaissance phase was a **level 6** (an ANONYMOUS LOGON over SMB), while twelve level 15s in the same window were this same noise. Rule level is an opinion held by whoever wrote the rule, not a fact about the event.

### 2. Why the port scan was invisible, and why that is an architecture answer rather than a rule answer

The scan was as loud as a scan gets: every TCP port on the host, in 88 seconds. Nothing.

The reason is the shape of the sensor. A Wazuh agent on a Windows endpoint is a **log forwarder**. It can only report what some Windows subsystem has already written down. Windows does not write a log entry for a SYN packet to a closed port — the TCP/IP stack answers or drops it and that is the end of it. The only Windows source that would see this is Filtering Platform Connection auditing (`5156`/`5157`), which is not enabled, deliberately, because its volume is very high. A follow-up exercise confirmed the shape of the residue: a 7-port service scan left exactly **2 Sysmon Event ID 3 records** (inbound to 3389, `Initiated=false`) and **0 `5156` events**.

Therefore: writing more Wazuh rules cannot close this. The honest options are to enable Filtering Platform auditing and accept the volume, or to put a network sensor (Suricata or Zeek) on the segment. **I have host visibility and no network visibility**, and any coverage claim I make has to say so.

### 3. Why the 4697 gap is the most dangerous kind

A missing alert produces no error. There is no red indicator, no failed-ingest counter, nothing in the dashboard that says "an event class is being discarded". The Wazuh analysis engine received `4697`, found no rule that matched, and dropped it — which is normal, intended behaviour. From the console, a dropped event and an event that never happened are identical.

The only way I found this was by **causing the event on purpose and then checking whether it appeared.** That is a method, and it generalises: a coverage matrix cannot be built by reading the ruleset, only by generating events and verifying arrival.

The gap was partially masked by luck. A service installation writes `7045` to the System channel as well as `4697` to Security, and `7045` does have a rule. The fact of the world was detected — through the other door. If I had only asked "was the service installation detected?" I would have answered yes and never found the hole. The question that found it was narrower: "which of the two Event IDs this action generates became alerts?"

### 4. The 4625 split — the field that turns counting into triage

Ten failed logons, one Event ID, one description string, two completely different stories:

| Group | Count | logonType | logonProcessName | Auth package | Source | Target user |
|---|---|---|---|---|---|---|
| A | 5 | **2** (interactive) | `seclogo` (the runas service) | Negotiate | `::1` (local) | a non-existent local user |
| B | 5 | **3** (network) | `NtLmSsp` | NTLM | 10.10.10.5 | a non-existent local user |

All ten carried `subStatus 0xC0000064` — "the account does not exist".

Group A is a user mistyping, or a script using `runas`. Group B is authentication arriving over the network from a host that has no business authenticating to this endpoint. The alert count is identical; the meaning is not. **If you are not reading `logonType`, you are counting alerts, not triaging them.**

The `subStatus` field carries the other half of the story and I did not exploit it in this exercise. A later run made the point sharply: `0xC0000064` means "that account does not exist" — the attacker is still enumerating, shooting blind — while `0xC000006A` means "that account exists, wrong password" — the attacker now knows where to aim. The transition between those two values is the moment enumeration becomes a targeted attack, and account lockout policy is blind to the first phase entirely.

### 5. The funnel

~2,100 events reported by the agent → **835 alerts indexed** for this endpoint. More than half of the telemetry is not queryable, because it matched no rule at level ≥ 3. A separate, tightly-controlled exercise measured the same funnel at 167 events generated → 27 alerts.

The consequence for any statement I make about coverage: **absence of an alert is not evidence of absence of activity.** A search of the alert index is bounded by the ruleset, not by what the endpoint produced. To answer "did X happen", the question has to go to the endpoint log, not to the SIEM.

---

## Conclusion

1. **The pipeline works end to end.** An event caused on the endpoint arrives at the SIEM as an alert with its ATT&CK technique attached, at the expected latency.
2. **Severity is not priority.** The only level-15 alert in the batch was PowerShell testing its own execution policy. The simulated intrusion surfaced at levels 8 and 12.
3. **`logonType` is the field that turns a `4625` into information.** Ten identical-looking events, two different stories.
4. **I have host visibility and no network visibility.** A 65,535-port scan passed without a trace, and no additional Wazuh rule can change that.
5. **A detection gap does not raise an error.** `4697` was lost in silence, and I only found it because I caused the event knowing in advance what to look for.

Mapped to ATT&CK, what this exercise actually demonstrated as *detected*: T1059.001 (PowerShell, rule `92057`, level 12, on Sysmon 1), T1098 / T1531 (account manipulation and removal, rules `60109`/`60110`/`60111`, level 8), T1484 (rule `60154`, level 12), T1543.003 (service installation — detected via `7045`, *not* via `4697`), T1110.001 (password guessing, 10 × `4625`). What it demonstrated as *not detected*: T1046 (network service discovery, zero alerts), T1033 and T1087 (discovery commands, generic level-3 only), and T1105 as a mapping that produced only false positives.

---

## Detection gaps identified

| # | Gap | Failing layer | Evidence | What would close it |
|---|---|---|---|---|
| G-01 | Security `4697` (service installed) is generated and collected but matched by no rule, so it is never indexed | Detection | `Get-WinEvent` shows it on the endpoint at 00:44:56Z; `wazuh-alerts-*` returns 0 documents for it | A rule on Security `4697` alerting when `ServiceFileName` points outside `C:\Windows\System32`, or when `ServiceName` closely resembles but does not equal a known system service name. Requires baseline exclusions for installers and monitoring agents |
| G-02 | Port scans are structurally invisible to a host-agent-only architecture | Collection | 65,535-port scan over 88 s → 0 attributable alerts; a later 7-port `-sS -sV` scan → 2 Sysmon Event 3 records and 0 `5156` | Either enable Filtering Platform auditing (`5156`/`5157`) and write a many-distinct-ports-from-one-source rule, accepting the volume, or place a network IDS on the segment. This is an architecture gap, not a rule gap, and the second answer is the honest one |
| G-03 | Rule `92213` fires at level 15 on benign PowerShell behaviour and is untuned | Detection | Reproduced 2026-08-08 ×1, 2026-08-11 ×5, 2026-09-07 ×12, always on `__PSScriptPolicyTest_*.ps1` written by signed system PowerShell | An exclusion for `TargetFilename` matching `__PSScriptPolicyTest_*.ps1` where the image is the signed system PowerShell. Until that exists, level 15 carries no information in this environment |
| G-04 | Discovery commands are indistinguishable from background noise | Detection | The reconnaissance batch produced only generic `4688` alerts at level 3 — `whoami.exe` received byte-for-byte the same treatment as a routine system process | A sequence rule rather than a single-event rule: alert when three or more of `{whoami, net user, net localgroup, nltest, systeminfo, ipconfig /all, arp -a, quser}` are created under the same parent or the same `SubjectLogonId` within 60 seconds |
| G-05 | Security `1102` (audit log cleared) has never been generated, so its detection path is untested | Generation | Recorded as the only one of my twelve priority Event IDs with no data from this lab | Trigger it deliberately — the `base-limpia` snapshot exists precisely so this is safe to do — and confirm the alert path end to end. `1102` is one of the very few Windows events close to being an indicator on its own |
| G-06 | No time synchronisation between endpoint and SIEM | Collection | A consistent ≈1.8 s offset between the endpoint `systemTime` and the Wazuh `@timestamp`, measured across three consecutive event records | Not a rule: configure NTP on both VMs, and pin every dashboard query to `data.win.system.systemTime`. This matters more once a domain controller exists, since Kerberos rejects clock skew above 5 minutes |

---

## What I would do differently

1. **Write the prediction down before looking.** This is the concrete failure of this run. I executed and observed nearly simultaneously and lost the diagnostic value of the exercise: a prediction that survives contact with the data teaches nothing, a prediction that fails locates a knowledge gap exactly. Applied from the next exercise onward, where four hypotheses were stated up front and all four were falsified — which is the outcome you want.
2. **Ask the narrower question.** "Was the service installation detected?" answers yes and hides G-01. "Which of the Event IDs this action generates became alerts?" finds it. Every coverage check should enumerate the expected artefacts individually rather than asking whether the *activity* was caught.
3. **Widen the window before declaring a gap.** In the follow-up exercise an apparent `4624`/`4672` coverage hole turned out to be an artefact of my own time-range boundary cutting event pairs in half. A false gap in a coverage report is as damaging as a false positive in a queue, and the fix costs one re-query.
4. **Build the false-positive list as a deliverable, not as a memory.** `92213` on `__PSScriptPolicyTest_*.ps1` should have been written down the first time. It has now cost triage attention three times.
5. **Read `subStatus`, not only `logonType`, on every `4625`.** I split the ten failures by logon type and stopped there. `0xC0000064` versus `0xC000006A` is the difference between enumeration and a targeted attempt, and it is a free field on an event I was already reading.
6. **Add a network source before making any coverage claim that involves the network.** Without it, half of any coverage matrix is blank by construction rather than by finding, and saying so is more useful than filling it in with assumptions.
7. **Do one exercise where I do not know the answer.** Everything above is bounded by the fact that I wrote the attack. The next step that actually raises the ceiling is an alert whose cause I have to reconstruct rather than recall.

---

*Lab, tooling and full build detail: see the lab documentation in this repository. All credentials are redacted; `10.10.10.0/24` is a private lab range.*
