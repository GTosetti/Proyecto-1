# Triage playbooks

These are the runbooks I follow when an alert fires in my home SOC lab. They are written for
one analyst working a queue, not for a team, and every threshold, field name, rule ID and
timing quirk in them was measured on the lab described in `../lab/` — not copied from a
vendor document.

The point of this folder is the part of the L1 job that is not building anything: taking an
alert you did not choose, deciding whether it is real, deciding how far it reached, and then
either closing it with a reason or handing it upward in a form somebody can act on.

## Contents

| File | Covers | Anchored on |
|---|---|---|
| `triage-failed-authentication.md` | 4625 floods, spraying, user enumeration | SubStatus branching, lockout policy limits |
| `triage-suspicious-process.md` | Process-creation alerts, tree reconstruction | 4688 vs Sysmon 1 field semantics |
| `triage-remote-access.md` | RDP and SMB alerts, anonymous sessions | NLA logon-type behaviour |
| `escalation-template.md` | The hand-off note to tier 2 | Worked example from investigation 003 |

## The triage loop

Every playbook here is a specialisation of the same four steps. Do them in order. Do not
start collecting evidence before step 1 is answered, and do not decide a verdict before
step 3.

| Step | Question | What ends the step |
|---|---|---|
| 1. What fired | Which rule, on which event, from which sensor, on which asset | You can state the rule ID, its level, the source channel and the event ID without looking again |
| 2. Is it true | Does the underlying event actually mean what the rule name says | A verdict of true / false / undecided, with the field that decided it |
| 3. Blast radius | What else carries the same session, host, process or source address | A bounded list of affected accounts, hosts and sessions — or an explicit "unknown, and here is why" |
| 4. Escalate or close | Does this need someone with more authority than me | Either a closed ticket with a written reason, or an escalation note using the ten-line template |

Step 2 is where most of the work is, and step 3 is where most L1 tickets are weak. An
escalation that says "suspicious logon on WIN11-VICTIMA" and stops has skipped step 3.

## The three context questions

Ask these of any alert before touching a query. They are cheap, and in this lab each of them
has already changed a verdict at least once.

**1. What is this asset and what is normal on it?**
`WIN11-VICTIMA` (10.10.10.20) is a Windows 11 Pro endpoint with SMB, RDP and ICMP opened
deliberately. `10.10.10.5` is the Kali attacker VM — and is also the address reserved in the
plan for a future domain controller, a collision documented in `../lab/`. "Traffic from
10.10.10.5" means attacker today and will mean domain controller later; attribution by IP
alone has an expiry date.

**2. Who or what is the account, and is a human required?**
Logon type 2 does not imply a person at a keyboard. In this lab, `VBoxService.exe` produced
4624 events with logonType 2, logonProcessName `Advapi`, and `WIN11-VICTIMA$` as the subject
with logonId 0x3e7 (SYSTEM), for commands issued from the host with nobody at the console. A
genuine console logon shows logonProcessName `User32` / `Winlogon`. Read
`logonProcessName` before you assume intent.

**3. What is the rule actually matching on, and what does its level mean?**
Rule level is severity if the event were real, not the probability that it is. Measured on
2026-08-08: of 82 alerts in a nine-second window, the single level 15 was rule 92213 firing
on `__PSScriptPolicyTest_<random>.ps1`, a file PowerShell writes into `%TEMP%` to test its
own execution policy, dropped by the signed system `powershell.exe`. The same false positive
recurred 5 times on 2026-08-11 and 12 times on 2026-09-07. In the same 2026-09-07 exercise
the most informative alert of the reconnaissance phase was a level 6 (rule 92652, ANONYMOUS
LOGON). Sorting the queue by level and starting at the top is, in this lab, a way to spend
the shift on PowerShell talking to itself.

## Lab rules that apply to every playbook

**Read the right clock.** Wazuh's `@timestamp` is the manager's processing time and runs
behind the endpoint: measured on three consecutive `eventRecordID`s on 2026-08-11, the offset
was -1.754 s, -1.821 s and -1.757 s. The dashboard's default time axis uses it. Filter and
sort on `data.win.system.systemTime`. For Sysmon events 3 (network) and 22 (DNS) the channel
write is later still — 4.0 s and 3.2 s behind the event in the same measurement — so read the
event's own `UtcTime` field, never the channel's `TimeCreated`. There is no NTP configured
between the VMs; this is an open gap, not a solved problem.

**Absence of an alert is not absence of activity.** On 2026-08-08 the agent reported about
2,100 events and 835 alerts were indexed for that endpoint. In the 2026-08-11 exercise, 167
generated events produced 27 alerts. Anything that matched no rule is not searchable in
`wazuh-alerts-*` at all. When a playbook says "confirm on the endpoint", it is because the
SIEM cannot answer that question.

**Coverage has three layers, and only one of them fails loudly.** Generation (does Windows
log it) → collection (does the agent ship it) → detection (does a rule match it). Security
event 4697 "a service was installed" passes the first two layers and dies at the third: it
was confirmed present in the Security log on 2026-08-08 and returned 0 documents in
`wazuh-alerts-*`. A layer-3 hole produces no error and nothing to search for.

**Widen the window before declaring a gap.** On 2026-08-11 a count of 4 x 4624 / 2 alerted
looked like filtering. Widening the range from a 20-second to a 40-second window showed 8 x
4624, every one of them alerting: each invocation produced a *pair* of 4624 events and the
pairs were being cut in half by the window boundary. A false gap in a coverage claim is as
damaging as a false positive in a queue.

**The index is not grep.** A `query_string` search for the unique marker string used in the
2026-08-11 exercise returned 0 results while that string was sitting in
`data.win.eventdata.commandLine` in indexed documents. Query named fields
(`term` / `terms` / `match_phrase` on the field), not free text.

## Query harness

Two places to run things, and they answer different questions.

### A. The SIEM, from the host

The Wazuh indexer listens on 9200 only on localhost inside the SIEM VM, so a NAT port-forward
to it fails (curl error 35). The path that works is the dashboard's console proxy, already
exposed on 8443, which accepts basic auth:

```bash
curl -k -u admin:<REDACTED> \
  -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query.json
```

Every `query.json` in these playbooks assumes that call. Conventions used throughout:

- time range always on `data.win.system.systemTime`, never `@timestamp`;
- event ID as a string: `{"term": {"data.win.system.eventID": "4625"}}`;
- if a `terms` aggregation is rejected for the field type, check the mapping
  (`path=wazuh-alerts-*/_mapping`) and use the keyword subfield.

### B. The endpoint, for everything the SIEM never received

The agent forwards Security, System, Application, `Microsoft-Windows-Sysmon/Operational` and
`Microsoft-Windows-PowerShell/Operational`. Anything else — the Terminal Services channels in
particular — exists only on the host and has to be read there.

Reading the Security and Sysmon channels from the host account requires membership of
`Event Log Readers`, and that membership only takes effect after a reboot: adding it with
`net localgroup "Event Log Readers" <LAB_USER> /add` made `Get-LocalGroupMember` show it
immediately while remotely launched processes kept failing with "Attempted to perform an
unauthorized operation" until the VM was restarted. Group membership lives in the token, not
in the SAM.

Running a query script inside the VM from the host:

```powershell
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vbox guestcontrol "WIN11-VICTIMA" copyto "<REPO>\playbooks\q.ps1" "C:\lab\q.ps1" `
    --username <LAB_USER> --password <REDACTED>
& $vbox guestcontrol "WIN11-VICTIMA" run --exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    --username <LAB_USER> --password <REDACTED> `
    -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\lab\q.ps1
```

Two traps that cost real time here: on Windows the binary name must be repeated after `--`
(VirtualBox supplies its own `argv[0]`, and on Linux guests it must *not* be repeated), and
arguments passed after `--` are unreliable — quotes are eaten and a repeated `argv[0]` made
PowerShell relaunch itself, producing two `powershell.exe` in the telemetry. Put everything
in a `.ps1` and run it with `-File`.

## Verdict vocabulary

Use exactly one of these four, and always with the field that decided it.

| Verdict | Means | Closes the ticket? |
|---|---|---|
| **True positive** | The event happened and is unauthorised or unexplained | No — escalate |
| **True, authorised** | The event happened and a known owner/change explains it | Yes, with the authorising reference written down |
| **False positive** | The rule matched something that is not what the rule name claims | Yes, plus a tuning note — a level 15 that fires on benign activity destroys the meaning of level 15 |
| **Needs escalation / undecided** | The data needed to decide is missing or out of my reach | No — escalate as undecided, and say which data is missing |

"Needs escalation" is a legitimate answer. Escalating an undecided alert with a clear
statement of what is missing is better work than guessing.

## What to write down, for every alert

Minimum record, whatever the verdict:

1. Alert identity: rule ID, rule level, rule description, agent, timestamp in `systemTime`.
2. The underlying event: channel, event ID, `eventRecordID` (this is the stable handle —
   use it to re-fetch the exact document).
3. The pivot values: `LogonId`, `ProcessGuid`, source IP, target account.
4. Verdict, and the single field that decided it.
5. What I could not determine, and why.
6. If false positive: the tuning that should be applied.

The `eventRecordID` matters more than it looks. It is the one identifier that lets somebody
else fetch exactly the document you were looking at, and it is how the clock offsets above
were measured in the first place.

## Honest limits of these playbooks

- Single endpoint, single attacker VM, no domain controller yet — nothing here has been
  tested against Kerberos, 4768/4769, or lateral movement between two Windows hosts.
- No network sensor. A 65,535-port SYN scan lasting 88 s produced 0 attributable alerts on
  2026-08-08. Anything a host agent cannot see, these playbooks cannot triage.
- The attacks that exercised these steps were run by the same person who investigated them.
  That is adversary emulation, not unscripted casework, and the playbooks inherit the
  optimism that comes with knowing the answer in advance.
