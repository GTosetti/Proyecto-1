# Playbook: remote access (RDP and SMB)

Covers alerts about someone reaching the endpoint over the network: anonymous SMB sessions,
share enumeration, RDP connection attempts and successful remote logons. `WIN11-VICTIMA`
(10.10.10.20) has inbound ICMP, SMB and RDP opened deliberately, so "the port is reachable" is
never itself the finding here.

ATT&CK: T1021.001 (RDP), T1135 (Network Share Discovery), T1078.003 (Valid Accounts: Local),
T1046 (Network Service Discovery).

---

## 1. Trigger

| Rule | Level | Fires on | Lab observation |
|---|---|---|---|
| 92652 | 6 | ANONYMOUS LOGON (Security 4624, type 3, NTLM) | Fired on the SMB null session at 18:27:42 on 2026-09-07 — **the only reliable trace of the entire reconnaissance phase** |
| 92657 | 6 | Remote logon activity mapped to T1021.001 | Fired 3 times on 2026-09-07 |
| 60204 / 60122 | 10 / 5 | Logon failures — see `triage-failed-authentication.md` | 2 and 20 occurrences on 2026-09-07 |

Also a trigger with no rule behind it: a Security 4624 with **logon type 10** from any source,
and any 4624 type 3 from an address that has no business authenticating here. Those must be
hunted, not waited for.

The level-6 point is worth keeping in mind while working the queue. In the 2026-09-07 exercise
the highest-value alert of the reconnaissance phase was rule 92652 at level 6, while the same
window produced twelve level 15s that were all false positives on a PowerShell temp file. Rule
level is an opinion held by whoever wrote the rule.

---

## 2. Required context

| Question | Where |
|---|---|
| Should this source address reach SMB/RDP on this asset at all? | Lab map. 10.10.10.5 is the Kali attacker VM — and is the address reserved for the future DC01, so this attribution expires when stage 2 is built |
| Is NLA enabled on RDP? | `(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices).UserAuthenticationRequired` — it is, and section 3 is the consequence |
| Which channels exist in the SIEM? | Only Security, System, Application, Sysmon and PowerShell are forwarded by the agent. **The Terminal Services channels are not** — corroboration requires the endpoint |
| Is 5156 (Filtering Platform Connection) audited? | No, deliberately — it is very high volume. So there is no per-connection record in the Security log |

---

## 3. The trap: with NLA, a failed RDP logon is type 3, not type 10

Measured on 2026-09-07:

| Time | What happened | What Windows recorded |
|---|---|---|
| 18:33:28–18:33:29 | 4 failed RDP attempts | 4 x Security 4625, **logon type 3** |
| 18:33:30–18:33:31 | 2 authentications, auth-only (no session) | 4624 **type 3** + TS-RemoteConnectionManager 1149. Still no type 10 |
| 18:35:09 | A full graphical session established | 4624 **type 10**, AuthenticationPackage Negotiate, LogonProcessName User32, plus LocalSessionManager 41 → 42 → 21 → 22 → 24 |

Network Level Authentication moves authentication *in front of* session creation. Until a
session is actually created there is nothing "remote interactive" to record, so the failure is
logged as an ordinary network logon — indistinguishable by logon type from a failed SMB
authentication.

Two direct consequences for triage:

1. **A detection or a query built on "RDP brute force = 4625 type 10" misses every
   NLA-protected target**, and NLA is the default configuration.
2. **You cannot name the protocol from the logon type.** To say "RDP" in a ticket you need
   corroboration from the Terminal Services channels, which live only on the endpoint.

Logon types you will actually meet here:

| Type | Name | Reading |
|---|---|---|
| 2 | Interactive | Console — or a program calling `LogonUser()`; check `logonProcessName` (`User32`/`Winlogon` = real console, `Advapi` = a program) |
| 3 | Network | SMB, WMI, **and failed/auth-only RDP under NLA** |
| 5 | Service | Service control manager |
| 7 | Unlock | Screen unlocked |
| 10 | RemoteInteractive | RDP with a session genuinely established |
| 11 | CachedInteractive | Domain cached credentials — relevant once DC01 exists |

---

## 4. Decision tree

```
Remote-access alert
│
├─ Q1. Was it anonymous? (rule 92652 / TargetUserName = ANONYMOUS LOGON)
│     ──► SMB null session. This is reconnaissance (T1135 territory), and it is the single
│         most reliable host-side trace of a scan-and-enumerate phase in this lab.
│         TRUE POSITIVE if the source has no business here. Go to Q4 to scope, then escalate.
│         Note what it could see: a null session does not require credentials, so treat
│         everything IPC$ exposes as disclosed.
│
├─ Q2. Did authentication SUCCEED? (query A)
│   ├─ Only 4625 ──► this is a failed-auth ticket. Go to triage-failed-authentication.md
│   │                and come back only if a 4624 appears.
│   └─ 4624 present ──► continue. Record TargetLogonId now.
│
├─ Q3. Which protocol? Do NOT answer from the logon type. (query B, endpoint)
│   ├─ TS-RemoteConnectionManager 1149 present with the same Source Network Address
│   │     ──► RDP. 1149 carries the source address even when the logon type says "network".
│   ├─ LocalSessionManager 21/22/24/25 present ──► an RDP session actually ran. Note its
│   │     duration from 21 (logon) to 23/24 (logoff/disconnect).
│   ├─ Live SMB session visible (query C) or share access ──► SMB.
│   └─ Neither ──► say "network logon, protocol not established" in the ticket. That is an
│         honest answer; "RDP" without 1149 is a guess.
│
├─ Q4. Blast radius (query D)
│   a) Which account? Is it a local administrator?
│      Access to ADMIN$ or C$ as an administrator implies full control of the endpoint —
│      on 2026-09-07 share enumeration returned ADMIN$, C$ and IPC$ with READ.
│   b) Pivot on the LogonId: every 4688 / Sysmon 1 carrying it is what they did.
│      Verified end to end in this lab (4624 → 4688 → Sysmon 1 → 4634, same LogonId).
│   c) Is the session still open? (4634/4647 absent, or query C shows it live)
│   d) Did the same source touch anything else? Widen to the whole /24 in the SIEM.
│
└─ Q5. Verdict and hand-off. A successful remote logon from an unexpected source is never
      closed at L1. Escalate with the ten-line template.
```

---

## 5. Queries

### Query A — every authentication from one source, in order (SIEM)

`query-remote.json`:

```json
{
  "size": 100,
  "sort": [ { "data.win.system.systemTime": "asc" } ],
  "_source": ["data.win.system.systemTime","data.win.system.eventID","data.win.system.eventRecordID",
              "data.win.eventdata.targetUserName","data.win.eventdata.logonType",
              "data.win.eventdata.targetLogonId","data.win.eventdata.ipAddress",
              "data.win.eventdata.ipPort","data.win.eventdata.authenticationPackageName",
              "data.win.eventdata.logonProcessName","data.win.eventdata.subStatus",
              "rule.id","rule.level","rule.description"],
  "query": {
    "bool": {
      "filter": [
        { "terms": { "data.win.system.eventID": ["4624","4625","4634","4647","4672","4776"] } },
        { "term":  { "data.win.eventdata.ipAddress": "10.10.10.5" } },
        { "range": { "data.win.system.systemTime": { "gte": "2026-09-07T18:00:00Z", "lte": "2026-09-07T19:00:00Z" } } }
      ]
    }
  }
}
```

```bash
curl -k -u admin:<REDACTED> -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query-remote.json
```

Remember the time field: `data.win.system.systemTime`, not `@timestamp`, which lags the
endpoint by about 1.8 s (measured -1.754 / -1.821 / -1.757 s on three consecutive records).

### Query B — RDP corroboration (endpoint only — not in the SIEM)

```powershell
# Save as C:\lab\q-rdp.ps1 and run with -File.
$since = (Get-Date).AddHours(-2)

# Who connected, and from where. 1149 carries the source address even when logon type says 3.
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149,261; StartTime=$since
} | ForEach-Object {
  $x = [xml]$_.ToXml()
  [pscustomobject]@{
    Time   = $_.TimeCreated.ToString('o')
    Id     = $_.Id
    Fields = ($x.Event.UserData.EventXML.ChildNodes | ForEach-Object { "$($_.Name)=$($_.'#text')" }) -join ' '
  }
} | Format-Table -AutoSize

# Session lifecycle: 41/42 = session created/connected, 21 = logon, 22 = shell start,
# 24 = disconnected, 25 = reconnected, 23 = logoff, 40 = disconnect reason.
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; StartTime=$since
} | Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated | Format-Table -AutoSize
```

The observed sequence for a real session on 2026-09-07 was 41 → 42 → 21 → 22 → 24. A
connection that dies before logon leaves only 1149 and a 40.

### Query C — live SMB state (endpoint)

```powershell
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SessionId
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path
Get-SmbShare | Select-Object Name, Path, Description
quser                      # interactive and RDP sessions currently on the box
Get-SmbServerConfiguration | Select-Object EnableAuthRateLimiter, InvalidAuthenticationDelayTimeInMs
```

Share enumeration itself does not alert in this lab — on 2026-09-07 `ADMIN$`, `C$` and `IPC$`
were enumerated with READ at 18:31:19 and the trace of it is the preceding authentication, not
the enumeration. If you want to know what was reachable, ask the host.

### Query D — what happened inside the session (SIEM)

Take `TargetLogonId` from the 4624 and filter `subjectLogonId` / `targetLogonId` / `logonId`
on it, sorted by `systemTime`. Full query shape in
`triage-failed-authentication.md` §6, query C. Then hand the process results to
`triage-suspicious-process.md`.

### Query E — inbound connection attempts, as far as the host can see them

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3; StartTime=(Get-Date).AddHours(-2)} |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      UtcTime   = $d['UtcTime']            # NOT TimeCreated — measured 4.0 s of channel lag
      Initiated = $d['Initiated']          # false = inbound
      Src       = "$($d['SourceIp']):$($d['SourcePort'])"
      Dst       = "$($d['DestinationIp']):$($d['DestinationPort'])"
      Image     = $d['Image']
    }
  } | Sort-Object UtcTime | Format-Table -AutoSize
```

Expect very little. A 7-port `nmap -sS -sV` against this host on 2026-09-07 left exactly two
Sysmon 3 events (inbound to :3389 from 10.10.10.5, `Initiated=false`) and zero Security 5156
events. A full 65,535-port SYN scan on 2026-08-08 ran 88 seconds and produced zero
attributable alerts. **Port scanning is structurally invisible to a host-agent-only
architecture** — that is an architecture gap, not a missing rule, and the honest fix is a
network sensor on the segment rather than more Wazuh rules.

---

## 6. Verdict criteria

**True positive — reconnaissance**
ANONYMOUS LOGON (4624 type 3, NTLM) from an address with no business here, or inbound Sysmon 3
events to service ports from such an address. No credential was used; the finding is that
someone is mapping the host.

**True positive — unauthorised access**
A 4624 (type 3 or type 10) from an unexpected source, especially following 4625 failures with
SubStatus `0xC000006A`. If the account is a local administrator, treat access to `ADMIN$` or
`C$` as full control of the endpoint and escalate immediately rather than finishing the
investigation first.

**True, authorised**
Remote access explained by a named owner, a change record, or lab work you launched. Write the
source address, account, session `LogonId` and the authorising reference into the ticket.
In this lab, a type 10 logon from the host that matches a session you opened is this verdict —
and it should still be written down, because the alternative is treating every real detection
as "probably me".

**False positive**
Genuinely rare on these events; 4624/4625 are factual records. The false part is usually the
protocol attribution — "RDP brute force" claimed on 4625 type 3 with no 1149 to back it.
Correct the record rather than closing silently.

**Needs escalation / undecided**
1149 absent and no SMB session visible, so the protocol cannot be named; or the session closed
before you looked and no `LogonId` pivot is possible; or the source address is unattributable.
Escalate with what is known and name the missing piece.

---

## 7. What to write down

1. Rule ID and level, plus the `eventRecordID` of the triggering event.
2. Source address and port, target account, and whether the account is a local administrator.
3. Every authentication from that source in order, with event ID, logon type, authentication
   package, logon process and SubStatus — times from `systemTime`.
4. The protocol, **with the evidence that names it** (1149 / LocalSessionManager IDs / live
   SMB session), or an explicit statement that it could not be determined.
5. `TargetLogonId` and whether the session is still open (4634/4647 present or absent).
6. What the session did: processes carrying that LogonId, shares touched, files opened.
7. Session duration from the LocalSessionManager sequence, if RDP.
8. Containment status. In this lab the options are pulling the VM's lab NIC
   (`VBoxManage controlvm WIN11-VICTIMA setlinkstate<n> off`, where `<n>` is the adapter on
   SOCLAB — confirm it with `showvminfo --machinereadable` first) and the `base-limpia`
   snapshot. Restoring the snapshot destroys the evidence, so it comes last.
9. What is not visible: no network sensor, 5156 not audited, TS channels not in the SIEM.
10. The IP-attribution caveat if 10.10.10.5 is involved.

---

## 8. Reproducing this in the lab

Kept here because a detection you cannot trigger on demand is a detection you cannot test.

- Failed RDP under NLA (produces 4625 type 3, no type 10):
  `xfreerdp /v:10.10.10.20 /u:<user> /p:<wrong> /cert:ignore`
- A real type 10 without a desktop:
  `timeout 90 xvfb-run -a xfreerdp /v:10.10.10.20 /u:<user> /p:<pass> /cert:ignore /w:1280 /h:800`
  Under roughly 60 seconds the session is cut before the logon completes and you get only 1149
  and a disconnect 40 — measured on 2026-09-07.
- SMB null session (produces the 4624 ANONYMOUS LOGON and rule 92652):
  `smbclient -L //10.10.10.20 -N`
- Note for the attacker side: with `EnableAuthRateLimiter` on (default from Windows 11 24H2),
  a wrong SMB password comes back as *"The NETBIOS connection with the remote host timed
  out"*, not as a wrong-password message. That looks like a network problem and is a
  mitigation working. The 4625 is generated normally on the defender side.

Restore `base-limpia` afterwards.
