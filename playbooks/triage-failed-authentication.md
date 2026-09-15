# Playbook: failed authentication (4625 floods)

Covers password guessing, password spraying and user enumeration against a Windows endpoint.
Everything below was measured on `WIN11-VICTIMA` (10.10.10.20) during the exercises of
2026-08-08 and 2026-09-07.

ATT&CK: T1110.001 (Password Guessing), T1087 (Account Discovery).

---

## 1. Trigger

| Rule | Level | Fires on | Seen in lab |
|---|---|---|---|
| 60122 | 5 | A single Windows logon failure (Security 4625) | 20 alerts across the whole 2026-09-07 exercise |
| 60204 | 10 | Correlation: multiple logon failures in a short window (T1110) | 2 times on 2026-09-07 |

Note the 20. Rule 60122 fires once per 4625, and that exercise generated 22 of them (15
enumeration + 3 targeted over SMB, plus 4 failed RDP attempts). Two are unaccounted for. The
shortfall has not been traced to a cause, and it is recorded here rather than rounded away,
because "the alert count is lower than the event count" is itself a coverage observation and
the first thing to check on any burst is whether the queue saw all of it.

Rule 60204 is the one that lands in the queue. It is an accumulation of 60122 events. **It
does not read the `SubStatus` field**, which is the field that separates a user who forgot a
password from an attacker enumerating account names. Everything in this playbook exists
because the alert that woke you up cannot tell you which of those two things happened.

Also treat as a trigger, even with no 60204: any burst of 60122 from a single source address
that should never authenticate to this host.

---

## 2. Required context before querying

| Question | Where to get it | Lab value |
|---|---|---|
| Is the source address expected to authenticate here at all? | Lab network map, `../lab/` | 10.10.10.5 is the Kali attacker VM; it is also the address planned for the future DC01 — see the collision note in the README |
| What is the account lockout policy? | `net accounts` on the endpoint | Threshold 10 attempts / 10 minutes |
| Is SMB auth rate limiting on? | `Get-SmbServerConfiguration` | `EnableAuthRateLimiter = True`, `InvalidAuthenticationDelayTimeInMs = 2000` (default on Windows 11 24H2+) |
| Does the target account exist? | `Get-LocalUser` | Answered more cheaply by `SubStatus` — see below |

The rate limiter matters for reading the timeline, not just for defence. On 2026-09-07 the 15
failures were spaced about 2 seconds apart. **That spacing is the mitigation, not the
attacker's cadence.** An analyst who reports "the tool paced itself at 2 s" has described a
Windows setting and attributed it to the adversary.

---

## 3. The two fields that decide: Status and SubStatus

The 18 failures measured here all carried `Status = 0xC000006D` ("the logon is bad"), and for
that status the useful value is one level down in `SubStatus`. **That is not true of every
failure.** 4625 splits the reason across both fields, and which field carries it depends on
the reason — so read `Status` first and `SubStatus` second, always both.

| Status | SubStatus | Windows means | Triage means |
|---|---|---|---|
| `0xC000006D` | `0xC0000064` | The account name does not exist | Enumeration. The attacker is still shooting blind |
| `0xC000006D` | `0xC000006A` | The account exists, the password is wrong | Targeted. The attacker now knows where to aim |
| `0xC0000234` | `0x0` | Account locked out | The lockout policy engaged — check what preceded it. **The code is in `Status`; `SubStatus` is empty** |
| `0xC000006E` | `0xC0000072` | Account disabled | Someone is trying an account that was retired |
| `0xC000006E` | `0xC0000070` | Workstation restriction | Logon restriction hit — rare, worth a second look |

Only the first two rows have ever been produced in this lab. No account here was locked out,
disabled or restricted, so rows 3-5 come from Microsoft's 4625 reference, not from a
measurement — and that is exactly why they matter: a procedure that groups on `SubStatus`
alone renders a lockout as `0x0` and a disabled account as a code with no context, and the
analyst reads "unknown" where Windows wrote an answer.

Measured on 2026-09-07, 18 attempts from 10.10.10.5:

- 15 x 4625 with SubStatus `0xC0000064` against `admin`, `administrador`, `backup`, `sqlsvc`,
  `helpdesk` — accounts that do not exist — between 18:30:10 and 18:30:43;
- 3 x 4625 with SubStatus `0xC000006A` against the real lab account, 18:31:13 to 18:31:16;
- then a successful 4624, logon type 3, NTLM, at 18:31:19.

**The transition between the two SubStatus values is the moment the incident changes
character.** Everything before it is noise generation; everything after it is an attack with
a target.

### Why lockout policy does not mitigate the first branch

The lockout threshold was 10 attempts in 10 minutes. The 15 attempts against non-existent
accounts were never subject to it, because a lockout counter belongs to an account object and
those accounts have no object. An attacker can enumerate usernames indefinitely against a host
with a strict lockout policy and never trip it.

The consequence for triage: a `0xC0000064` burst is *not* "failed attempts, the control held".
It is free reconnaissance that the control never saw, and its real output is a list of which
names exist. The defensive value sits entirely in detection, not in prevention — which is
exactly why this alert lands on an analyst.

The secondary consequence: `0xC000006A` against a real account after a `0xC0000064` burst
means the enumeration phase succeeded. Raise the priority even if the attempt count is low.

---

## 4. The second field: LogonType

Same event ID, same description text, two completely different stories. Measured on
2026-08-08: 10 x 4625 split cleanly into two groups of five.

| | Group A | Group B |
|---|---|---|
| logonType | 2 (Interactive) | 3 (Network) |
| logonProcessName | `seclogo` (the runas service) | `NtLmSsp` |
| authenticationPackage | Negotiate | NTLM |
| ipAddress | `::1` | 10.10.10.5 |
| workstationName | WIN11-VICTIMA | KALI |
| Story | Local `runas` attempts | `smbclient` from the attacker VM |

Both groups carried SubStatus `0xC0000064`. If you count alerts without reading `logonType`
you have ten identical events; if you read it you have two incidents of different severity.

Two more reading notes measured in this lab:

- **`workstationName` empty (`-`)** on all 18 attempts of 2026-09-07 — a fingerprint of the
  client tool, not of the operating system behind it. The counter-example is in the Group B
  column above: on 2026-08-08 `smbclient`, from the same Kali VM against the same endpoint,
  populated the field with `KALI`. Two non-Windows tools, one OS, opposite behaviour. Treat an
  empty value as something to check (netexec / impacket-style clients leave it empty), never
  as evidence that the client was not Windows.
- **logon type 3 does not mean SMB.** With NLA enabled, failed RDP also arrives as type 3.
  See `triage-remote-access.md`; if RDP is plausible, that playbook's correlation step is
  mandatory before you name the protocol in a ticket.

---

## 5. Decision tree

```
4625 burst detected
│
├─ Q1. One source address or many?
│   ├─ Many distinct sources, one target account ──► distributed guessing. Widen to 24 h. Go to Q2 per source.
│   └─ One source ──► continue
│
├─ Q2. Group by Status AND SubStatus (query A — grouping on SubStatus alone loses two branches)
│   │
│   ├─ Mostly 0xC0000064 across ≥3 distinct target names
│   │     ──► USER ENUMERATION / SPRAYING. Lockout policy does not apply. TRUE POSITIVE.
│   │         Next question is not "did it succeed" but "which names came back different".
│   │         Go to Q4.
│   │
│   ├─ Mostly 0xC000006A against ONE account
│   │     ├─ logonType 2, logonProcessName User32/seclogo, ipAddress ::1 or local
│   │     │     ──► likely a user mistyping. Check count and spacing.
│   │     │         < lockout threshold, human-irregular spacing ──► TRUE, AUTHORISED (user error). Close.
│   │     └─ logonType 3 from a remote address
│   │           ──► TARGETED PASSWORD ATTACK. TRUE POSITIVE. Go to Q3.
│   │
│   ├─ 0xC0000064 burst FOLLOWED BY 0xC000006A on a real account
│   │     ──► enumeration succeeded and became targeted. Highest priority branch. Go to Q3.
│   │
│   ├─ Status 0xC0000234 present (SubStatus 0x0 — read the STATUS field for this one)
│   │     ──► the control engaged. Still triage the preceding attempts; a lockout is a symptom.
│   │
│   └─ Status 0xC000006E present
│         ──► not a password problem. SubStatus says which restriction: 0xC0000072 disabled,
│             0xC0000070 workstation. An attempt against a retired account is its own finding.
│
├─ Q3. Did any attempt SUCCEED? (query B — 4624 from the same source, same window +5 min)
│   ├─ No 4624 from that source ──► attack failed so far. Escalate as attempted access.
│   └─ 4624 present ──► THIS IS NO LONGER A FAILED-AUTH TICKET.
│         Take TargetLogonId and pivot (query C). Escalate immediately.
│         Hand over to triage-suspicious-process.md for post-access activity.
│
└─ Q4. Scope the campaign (query D)
      Re-run the source grouping over 24 h, not over the alert window.
      The 2 s rate limiter means a slow attacker (one attempt an hour) never
      accumulates enough events for rule 60204 to fire at all.
```

---

## 6. Queries

### Query A — group 4625 by source, Status and SubStatus (SIEM)

`query-a.json`:

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term":  { "data.win.system.eventID": "4625" } },
        { "range": { "data.win.system.systemTime": { "gte": "2026-09-07T18:00:00Z", "lte": "2026-09-07T19:00:00Z" } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "data.win.eventdata.ipAddress", "size": 20 },
      "aggs": {
        "by_status":      { "terms": { "field": "data.win.eventdata.status", "size": 10 } },
        "by_substatus":   { "terms": { "field": "data.win.eventdata.subStatus", "size": 10 } },
        "by_logontype":   { "terms": { "field": "data.win.eventdata.logonType", "size": 10 } },
        "distinct_users": { "cardinality": { "field": "data.win.eventdata.targetUserName" } },
        "user_list":      { "terms": { "field": "data.win.eventdata.targetUserName", "size": 25 } }
      }
    }
  }
}
```

```bash
curl -k -u admin:<REDACTED> -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query-a.json
```

Read it as: `distinct_users` high + `0xC0000064` dominant = enumeration.
`distinct_users` = 1 + `0xC000006A` dominant = targeted.

`by_status` is not decoration. Every failure this lab produced came back `0xC000006D`, so the
aggregation looks redundant until the day it is not: a lockout reports `0xC0000234` in `status`
with `subStatus` `0x0`, and `by_substatus` alone would show that as an unexplained `0x0`
bucket. `by_status` is the bucket that tells you the account hit a control rather than a wrong
password.

### Query B — did anything succeed from that source

`query-b.json` (widen the end of the range by at least 5 minutes past the last failure):

```json
{
  "size": 50,
  "sort": [ { "data.win.system.systemTime": "asc" } ],
  "_source": ["data.win.system.systemTime","data.win.system.eventID","data.win.system.eventRecordID",
              "data.win.eventdata.targetUserName","data.win.eventdata.logonType",
              "data.win.eventdata.targetLogonId","data.win.eventdata.ipAddress",
              "data.win.eventdata.authenticationPackageName","rule.id","rule.level"],
  "query": {
    "bool": {
      "filter": [
        { "terms": { "data.win.system.eventID": ["4624","4625","4648","4672"] } },
        { "term":  { "data.win.eventdata.ipAddress": "10.10.10.5" } },
        { "range": { "data.win.system.systemTime": { "gte": "2026-09-07T18:25:00Z", "lte": "2026-09-07T18:45:00Z" } } }
      ]
    }
  }
}
```

A 4624 in that result set ends this playbook and starts an intrusion ticket.

### Query C — pivot on the session (the "what did they do" query)

Take `TargetLogonId` from the successful 4624 and filter every event carrying it. Verified end
to end in this lab on 2026-08-11: 4624 `TargetLogonId` → 4688 `SubjectLogonId` for each
process → Sysmon 1 `LogonId` → 4634 `TargetLogonId` when the session closed, all the same
value.

```json
{
  "size": 200,
  "sort": [ { "data.win.system.systemTime": "asc" } ],
  "query": {
    "bool": {
      "should": [
        { "term": { "data.win.eventdata.subjectLogonId": "0x10cce5" } },
        { "term": { "data.win.eventdata.targetLogonId":  "0x10cce5" } },
        { "term": { "data.win.eventdata.logonId":        "0x10cce5" } }
      ],
      "minimum_should_match": 1
    }
  }
}
```

Fixed IDs that are not interesting on their own: `0x3e7` SYSTEM, `0x3e4` NETWORK SERVICE,
`0x3e5` LOCAL SERVICE.

### Query D — endpoint-side detail, and the long window

The SIEM has rule-filtered data. The endpoint has all of it. Run on `WIN11-VICTIMA`
(needs `Event Log Readers`, effective only after a reboot — see the README):

```powershell
# 24 hours of failed logons, decoded and grouped. Save as C:\lab\q-4625.ps1 and run with -File.
$rows = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      Time        = $_.TimeCreated.ToString('o')
      RecordId    = $_.RecordId
      Target      = $d['TargetUserName']
      Status      = $d['Status']          # 0xC0000234 (lockout) lives HERE, not in SubStatus
      SubStatus   = $d['SubStatus']
      LogonType   = $d['LogonType']
      Source      = $d['IpAddress']
      Workstation = $d['WorkstationName']
      LogonProc   = $d['LogonProcessName']
      AuthPkg     = $d['AuthenticationPackageName']
    }
  }

$rows | Group-Object Source, Status, SubStatus | Sort-Object Count -Descending |
        Select-Object Count, Name | Format-Table -AutoSize
$rows | Group-Object Source | ForEach-Object {
  "{0}: {1} attempts, {2} distinct targets, first {3}, last {4}" -f `
    $_.Name, $_.Count, ($_.Group.Target | Sort-Object -Unique).Count,
    ($_.Group.Time | Sort-Object)[0], ($_.Group.Time | Sort-Object)[-1]
}
$rows | Sort-Object Time | Select-Object Time, Target, Status, SubStatus, LogonType, Source | Format-Table -AutoSize
```

Also worth running once, to confirm the policy you are about to cite in a ticket:

```powershell
net accounts                     # lockout threshold and observation window
Get-SmbServerConfiguration | Select-Object EnableAuthRateLimiter, InvalidAuthenticationDelayTimeInMs
```

---

## 7. Verdict criteria

**True positive — enumeration / spraying**
≥3 distinct `targetUserName` values with SubStatus `0xC0000064` from one source address inside
a short window, from an address with no business authenticating to the host. Do not downgrade
it because "they all failed" — failure is the expected output of enumeration.

**True positive — targeted guessing**
SubStatus `0xC000006A` against a real account from a remote source, logon type 3, especially
if preceded by a `0xC0000064` burst. Highest priority of this playbook when no 4624 follows;
becomes an intrusion ticket if one does.

**True, authorised**
Attempts explained by a named owner or a known change: an admin testing a credential, a
service account with a stale password (look for repeated failures from the same source at a
fixed interval with logon type 3 and a service-shaped account name), or lab activity you
launched yourself. Write the authorising reference into the ticket — "it was me" is only an
acceptable close if the ticket says so.

**False positive**
Rare on 4625 itself; the event is factual. What is false is the *interpretation* — most often
a type 2 / `seclogo` / `::1` cluster read as a remote attack. Record the corrected reading.

**Needs escalation / undecided**
Source address not attributable; or the account is real, the failures stop abruptly and no
4624 is visible — you cannot prove the attacker failed, only that this host did not record a
success. Say that explicitly.

---

## 8. What to write down

1. Rule ID, level, and the window in `systemTime`.
2. Source address, and whether it should ever authenticate to this asset.
3. Total attempt count, split by `Status` **and** `SubStatus`, with the distinct target names
   listed.
4. Logon type, logonProcessName, authentication package, workstationName — and if
   workstationName is empty, that it is a tool fingerprint and not an OS attribution.
5. The timestamp of the transition `0xC0000064` → `0xC000006A`, if it happened.
6. Whether any 4624 followed from the same source, and its `TargetLogonId` if so.
7. Lockout policy as read from the host, and the explicit note that it does not cover the
   enumeration branch.
8. Spacing between attempts, **attributed to the rate limiter if it is ~2 s** rather than to
   the attacker.
9. `eventRecordID` of the first and last event in the burst, so the range can be re-fetched.
10. Anything you could not determine.

---

## 9. Known detection gaps this playbook works around

| Gap | Consequence for you | Evidence |
|---|---|---|
| Rule 60204 does not read `SubStatus` | Spraying and a forgetful user produce the same alert; you must branch manually | Rule fired twice at level 10 on 2026-09-07 by accumulating 60122 events |
| Short-window correlation only | A slow campaign never triggers 60204 at all; the 2 s rate limiter makes slow campaigns the sensible attacker choice | `EnableAuthRateLimiter = True`, delay 2000 ms, measured with `Get-SmbServerConfiguration` |
| Lockout policy blind to non-existent accounts | 15 of 18 attempts on 2026-09-07 were never subject to the threshold of 10 / 10 min | Attempt log, 18:30:10–18:30:43 |

Proposed rule work, recorded here so the gap is not just complained about: alert on Security
4625 with SubStatus `0xC0000064` across three or more distinct `targetUserName` values from
one source IP in a short window (enumeration), and pair it with a 24-hour variant grouped by
source IP only (slow campaigns). Neither is implemented yet — they are proposals, and until
they exist the manual branching above *is* the detection.
