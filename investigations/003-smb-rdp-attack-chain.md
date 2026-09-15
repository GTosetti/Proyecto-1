# 003 - SMB and RDP attack chain against a Windows endpoint: what was detected and what was not

| | |
|---|---|
| Date of exercise | 2026-09-07 |
| Environment | Self-built home lab (`SOCLAB`, VirtualBox NAT network `10.10.10.0/24`) |
| Attacker | Kali Linux 2026.1, `10.10.10.5` |
| Target | `WIN11-VICTIMA`, Windows 11 Pro build 10.0.26200, `10.10.10.20` |
| Detection stack | Wazuh 4.14.7 all-in-one on Ubuntu Server 24.04.4 (`10.10.10.10`), Wazuh Windows agent 4.14.7-1, Sysmon64 with the SwiftOnSecurity configuration, Windows advanced audit policy |
| ATT&CK techniques | T1046, T1135, T1110.001, T1021.001, T1078.003 |
| Exercise type | Self-run purple-team exercise. One person executed the attack and then investigated it. |

## 0. Honest framing

This was **not an unscripted investigation**. The same person ran the attack from Kali and then
investigated it from the SIEM, and therefore knew the answer before opening the dashboard. What
the exercise does prove is narrower and still worth writing down: which parts of a textbook
initial-access chain leave usable evidence on a Windows endpoint, which parts leave none, and
which fields separate one kind of failure from another.

It is also **not a network investigation**. There is no packet capture here. Every measurement
below comes from Windows event logs, the Sysmon channel, and the Wazuh alert index.

Credentials are deliberately absent from this repository. The lab account is written as
`<LAB_USER>` throughout.

## 1. Method

The chain was run in three phases. Before each phase a **RecordId watermark** was taken from the
Security log so that the telemetry belonging to that phase could be bounded exactly, instead of
guessing a time range afterwards:

```powershell
# Watermark: the last record number before the phase starts
Get-WinEvent -LogName Security -MaxEvents 1 | Select-Object RecordId

# Harvest: only what came after the mark
$sec = Get-WinEvent -LogName Security -MaxEvents 4000 | Where-Object { $_.RecordId -gt <mark> }
$sec | Group-Object Id | Sort-Object Count -Descending
```

The `Message` property of a `4625` is not sufficient for this analysis - `Status`, `SubStatus`
and `LogonType` have to be read from the event XML:

```powershell
$sec | Where-Object { $_.Id -eq 4625 } | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [pscustomobject]@{ User    = $d['TargetUserName']; Type   = $d['LogonType']
                     SubStat = $d['SubStatus'];      Source = $d['IpAddress'] }
}
```

The endpoint collection ran over `VBoxManage guestcontrol` from the host, without an elevated
token, because the lab account had been added to the local `Event Log Readers` group beforehand.

The SIEM side was queried from the host through the Wazuh dashboard's console proxy on port
8443. The indexer itself listens on 9200 on localhost only inside the SIEM VM, so a NAT port
forward to it does not work:

```bash
curl -k -u admin:<REDACTED> -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query.json
```

```json
{ "size": 0,
  "query": { "bool": { "filter": [
    { "range": { "@timestamp": { "gte": "2026-09-07T18:26:40Z", "lte": "2026-09-07T18:40:00Z" } } },
    { "range": { "rule.level": { "gte": 5 } } } ] } },
  "aggs": { "rules": { "terms": { "field": "rule.id", "size": 30 },
    "aggs": { "level": { "max": { "field": "rule.level" } },
              "tech":  { "terms": { "field": "rule.mitre.id", "size": 4 } } } } } }
```

**Clock discipline.** Times below are the endpoint's own, read from
`data.win.system.systemTime`, not from Wazuh's `@timestamp`. Measured on three consecutive
event records in an earlier exercise, the manager's `@timestamp` - which is the dashboard's
default time axis - runs behind the endpoint by -1.754 s, -1.821 s and -1.757 s. Separately,
Sysmon writes network (EID 3) and DNS (EID 22) events to the channel 3 to 4 seconds after they
occur, so for those two the event's own `UtcTime` field is authoritative, not the channel's
`TimeCreated`.

## 2. Hypotheses, written before looking at the data

| # | Hypothesis | Result |
|---|---|---|
| 1 | A port scan against the endpoint will leave a clear trace in the SIEM | **False** |
| 2 | SMB password guessing will produce a burst of `4625` at logon type 3 | True |
| 3 | RDP password guessing will produce `4625` at logon type 10, because RDP is *RemoteInteractive* | **False** |

Two of three were wrong, and the two wrong ones are the useful part of this document.

## 3. Attack timeline

All times UTC, 2026-09-07. The endpoint's local time zone is UTC-03:00.

| Time (UTC) | Phase | Action | ATT&CK | Host-side artefact |
|---|---|---|---|---|
| 18:26:47 | 1 | `nmap -sn` sweep of `10.10.10.0/24`, 5 live hosts found | T1046 | none |
| 18:26:50 | 1 | `nmap -sS -sV` against 7 ports on `10.10.10.20` | T1046 | see below |
| 18:26:52 / 18:27:03 | 1 | The only two host-side traces of the scan: inbound connections to `:3389` from `10.10.10.5`, `Initiated=false` | T1046 | Sysmon EID 3 x2 |
| 18:27:42 | 1 | SMB null session via `netexec` | T1135 | Security 4624, `ANONYMOUS LOGON`, type 3, NTLM - Wazuh rule 92652, level 6 |
| 18:30:10 - 18:30:43 | 2 | 15 password attempts against 5 non-existent accounts, spaced about 2 s apart | T1110.001, T1087 | Security 4625 x15, `SubStatus 0xC0000064` |
| 18:30 (within the burst) | 2 | First correlation alert | T1110 | Wazuh rule 60204, level 10 |
| 18:31:13 - 18:31:16 | 2 | 3 password attempts against the real account | T1110.001 | Security 4625 x3, `SubStatus 0xC000006A` |
| 18:31:19 | 2 | Valid credential accepted over SMB | T1078.003 | Security 4624 type 3, NTLM - Wazuh rule 92657, level 6 |
| 18:31:19 | 2 | Share enumeration: `ADMIN$`, `C$`, `IPC$` (READ) | T1135 | `netexec --shares` |
| 18:33:28 - 18:33:29 | 3 | 4 failed RDP logins | T1021.001, T1110.001 | Security 4625 x4, **logon type 3** |
| 18:33:30 - 18:33:31 | 3 | 2 successful RDP authentications with `+auth-only`, no session created | T1021.001 | Security 4624 type 3, TS-RemoteConnectionManager EID 1149 |
| 18:35:09 | 3 | Full graphical RDP session established under `xvfb` | T1021.001, T1078.003 | Security 4624 **type 10**, `Negotiate`, `LogonProcessName=User32`; TS-LocalSessionManager 41 -> 42 -> 21 -> 22 |
| 18:36:49 | 3 | Session disconnected | - | TS-LocalSessionManager 24 and 40 |

Forcing a type 10 without a desktop required a long-lived headless session:

```bash
timeout 90 xvfb-run -a xfreerdp /v:10.10.10.20 /u:<LAB_USER> /p:<REDACTED> \
  /cert:ignore /w:1280 /h:800
```

Below roughly 60 seconds the session is cut before logon completes, and only EID 1149 and a
disconnect EID 40 remain - no type 10 at all.

## 4. Detection coverage

| Phase | Action | Detected | What fired, or why nothing did |
|---|---|---|---|
| 1 | ICMP sweep of the subnet | No | Windows does not log it, and no rule could |
| 1 | 7-port SYN and version scan | Partially, uselessly | 2 Sysmon EID 3 events, 0 Security 5156. No alert. *Filtering Platform Connection* auditing is deliberately off because of its volume |
| 1 | SMB null session | **Yes** | Security 4624 `ANONYMOUS LOGON` -> Wazuh rule 92652, level 6. The only reliable trace of the whole reconnaissance phase |
| 2 | 15 attempts against non-existent users | **Yes, as volume** | 20 x rule 60122 (level 5) accumulated into rule 60204 (level 10, T1110) x2 |
| 2 | 3 attempts against a real user | Not distinguished | Same rules. Rule 60204 does not read `SubStatus`, so it cannot separate enumeration from a targeted attack |
| 2 | Successful SMB logon with a valid credential | **Yes** | Security 4624 type 3 NTLM -> Wazuh rule 92657, level 6 |
| 2 | Share enumeration (`ADMIN$`, `C$`, `IPC$`) | No | No host event ties the enumeration to the session |
| 3 | 4 failed RDP logins | Yes, misclassified | 4625 at logon type 3, indistinguishable by type from the SMB failures |
| 3 | Full RDP session | **Yes** | 4624 type 10 -> rule 92657 (level 6, T1021.001) fired 3 times across the exercise |
| - | Background noise | False positive | Rule 92213 (level 15, mapped to T1105) fired 12 times on `__PSScriptPolicyTest_*.ps1`, a file signed system PowerShell writes into `%TEMP%` to test its own execution policy |

Wazuh alerts in the attack window: rule 60204 level 10 x2; rule 60122 level 5 x20; rule 92652
level 6; rule 92657 level 6 x3; rule 92213 level 15 x12.

## 5. Findings

### F-1. A port scan is nearly invisible to a host-agent-only architecture

The `-sS -sV` scan of 7 ports left exactly **2 Sysmon EID 3 events** and **0 Security 5156
events** on the endpoint. Neither produced an alert. The `Filtering Platform Connection` audit
subcategory, which would generate 5156/5157, is deliberately not enabled because of its volume.

This is a structural limit, not a misconfiguration. A Wazuh agent reads Windows event logs, and
Windows does not record a SYN to a closed port anywhere. The lab has host visibility and no
network visibility. The honest remediation is a network sensor on the segment, not more SIEM
rules.

### F-2. `SubStatus` separates a blind spray from a targeted attack, and lockout policy only covers the second

All 18 failures carried `Status = 0xC000006D`. The `SubStatus` split them cleanly:

| `SubStatus` | Meaning | Count | Target | Window (UTC) |
|---|---|---|---|---|
| `0xC0000064` | Account does not exist | 15 | `admin`, `administrador`, `backup`, `sqlsvc`, `helpdesk` | 18:30:10 - 18:30:43 |
| `0xC000006A` | Account exists, wrong password | 3 | the real lab account | 18:31:13 - 18:31:16 |

The local lockout policy is 10 attempts in 10 minutes. It is per account, so **the 15 attempts
against accounts that do not exist were free** - no counter was ever incremented, and the
attacker learned which of five guessed usernames was real at no cost. Lockout policy is blind to
the enumeration phase entirely, and the transition from `0xC0000064` to `0xC000006A` is the exact
moment enumeration turns into a targeted attack.

`WorkstationName` was empty (`-`) on every one of the 18 events, which is characteristic of
non-Windows tooling such as impacket or netexec and is a usable secondary indicator.

### F-3. With NLA enabled, a failed RDP login is logon type 3, not type 10

The four failed RDP attempts at 18:33:28 - 18:33:29 produced `4625` events at **logon type 3**.
The two `+auth-only` authentications that followed produced `4624` type 3 plus
TS-RemoteConnectionManager EID 1149 - still no type 10. The only logon type 10 in the entire
exercise appeared at 18:35:09, when a full graphical session actually established.

Network Level Authentication moves authentication in front of session creation, so with NLA on -
the default - an RDP failure is indistinguishable from an SMB failure by logon type alone. Any
detection written as "RDP brute force = `4625` logon type 10" misses every NLA-protected target,
which is to say almost all of them.

### F-4. The Windows 11 SMB rate limiter makes the attack look like a network problem

`Get-SmbServerConfiguration` on the endpoint returned `EnableAuthRateLimiter = True` and
`InvalidAuthenticationDelayTimeInMs = 2000`, the default on Windows 11 24H2 and later.

- Attacker side: `netexec` reported *"The NETBIOS connection with the remote host timed out"*
  rather than a wrong-password result. It looks like a broken network, not a working defence.
- Defender side: every `4625` was generated normally, and the 15 failures landed roughly 2
  seconds apart.

That 2-second spacing is a fingerprint of **the mitigation**, not of the attacker's tooling. An
analyst who reads the interval as attacker behaviour - "a slow, cautious tool" - builds a wrong
profile from a correct observation.

### F-5. Rule level is an opinion, not a fact about the event

The highest-value alert of the reconnaissance phase was the `ANONYMOUS LOGON` at **level 6**. The
twelve **level 15** alerts in the same window were all false positives on a file PowerShell
creates to test its own execution policy. The same false positive has now been reproduced three
times in this lab, on 2026-08-08 (x1), 2026-08-11 (x5) and 2026-09-07 (x12).

Severity encodes how bad an event would be if it were real, not how likely it is to be real.
Triaging a queue strictly top-down by level would have spent the shift on PowerShell talking to
itself and reached the anonymous SMB session last.

## 6. Impact assessment

The account whose password was guessed is a **local administrator**, so read access to `ADMIN$`
and `C$` implies full control of the endpoint, and the chain ended in an interactive remote
desktop session. Treated as a real incident this is initial access completed, not a failed
attempt.

## 7. Indicators

| Type | Value |
|---|---|
| Source address | `10.10.10.5` |
| Targeted accounts that do not exist | `admin`, `administrador`, `backup`, `sqlsvc`, `helpdesk` |
| Compromised account | a local administrator account on `WIN11-VICTIMA` (`<LAB_USER>`) |
| Authentication packages | NTLM over SMB, `Negotiate` on the RDP session |
| `WorkstationName` in the `4625` events | empty (`-`) |
| Timing pattern | failures spaced about 2 s apart - fingerprint of the SMB rate limiter, not of the attacker |
| Shares touched | `ADMIN$`, `C$`, `IPC$` (READ) |

## 8. Detection engineering conclusions

Stated as mitigation -> residual gap -> what to detect.

| Mitigation in place | Residual gap | What to detect |
|---|---|---|
| SMB authentication rate limiter, 2 s per failure | Slows only. A campaign at one attempt per hour evades any short correlation window | `4625` grouped by source IP over **long** windows (24 h), not only short ones |
| Account lockout, 10 attempts / 10 minutes | Does not apply to accounts that do not exist; the first 15 attempts were free. Lockout is also a denial of service against the legitimate user | `4740` (account locked out), and bursts of `0xC0000064` as a spraying signal |
| NLA on RDP | Prevents resource exhaustion; does not prevent credential guessing | `4625` logon type 3 correlated with the RDP listener's own events |
| SMB signing required | No protection against a valid stolen credential | `4624` type 3 NTLM from addresses that are not known workstations |
| Network connection auditing - **not enabled** | A port scan is almost invisible to the SIEM | Enable `Filtering Platform Connection` (5156/5157) and accept the volume, **or** accept that this belongs to a network IDS |

Concrete rules to write, in priority order:

1. **Password spraying versus a forgotten password.** Rule 60204 fires on the accumulation of
   60122 events but never reads `SubStatus`, so it cannot tell 15 failures across 5 non-existent
   users from one user who mistyped a password. Proposed: alert on a burst of Security `4625`
   with `SubStatus 0xC0000064` across three or more distinct `TargetUserName` values from one
   source `IpAddress` within a short window. Pair it with a 24-hour variant grouped by source IP,
   because the 2-second rate limiter guarantees a patient attacker evades the short window.
2. **Reclassify RDP failures.** Correlate Security `4625` logon type 3 with
   TerminalServices-RemoteConnectionManager EID 261/1149 in the same window, so a generic network
   logon failure is re-labelled as an RDP attempt. NLA makes the logon type alone insufficient.
3. **Tune rule 92213.** Exclude `TargetFilename` matching `__PSScriptPolicyTest_*.ps1` where the
   image is the signed system PowerShell. Until that is done, level 15 carries no information in
   this lab, and a level that carries no information is worse than no level at all.
4. **Give Sysmon EID 3 a reason to exist.** It is ingested and has zero detection coverage: the
   two inbound events in this exercise produced no alert. A first rule is inbound `Initiated=false`
   connections repeating from one source within a short window - weak against a real scan, but it
   is the only host-side signal that exists. Read the event's `UtcTime`, not the channel's
   `TimeCreated`.
5. **Not a rule: fix the clocks.** Configure NTP on both VMs and pin every dashboard query to
   `data.win.system.systemTime`. This matters more once a domain controller joins the lab, since
   Kerberos rejects a skew above five minutes.

## 9. Limitations

- Single self-run exercise, single endpoint, attacker and analyst are the same person.
- Host telemetry only. No packet capture, so nothing here says what the scan looked like on the
  wire.
- Absence of an alert is not absence of activity. The Wazuh index only contains what the ruleset
  recognises, so every coverage claim above is bounded by the ruleset, not by what the endpoint
  produced.
- The lab is a workgroup endpoint. Domain authentication would change the event set materially
  and is not covered.

## 10. What I would do differently

The two hypotheses I got wrong both came from the same mistake: assuming an event exists because
the activity exists. A port scan happens on the network, so the endpoint has nothing to log; RDP
is interactive, but NLA authenticates before the session is interactive. The general form of the
correction is that **you have to check the layer that writes the log, not the layer where the
action happens.**

The open question I could not answer from this data: how to reliably distinguish a legitimate
`4624` type 3 (a machine mounting a share) from a malicious one, when the credential is valid in
both cases. Nothing in the event itself separates them. The answer has to come from context -
source address, hour, frequency, baseline - and that is the next thing to study.
