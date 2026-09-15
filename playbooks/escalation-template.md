# Escalation note template

Ten lines. The test it has to pass: **a tier 2 analyst can act on it without asking a single
follow-up question.** If they have to come back and ask "from where?", "which account?", "is
it contained?", the note failed, regardless of how much investigation went into it.

Keep it to ten lines. Length is not thoroughness — the supporting detail belongs in the ticket
body and in the queries you ran; this is the part somebody reads in thirty seconds before
deciding what to do.

---

## The template

```
1.  TITLE        — what happened, to which asset, in one sentence. No rule names as titles.
2.  DETECTED BY  — rule ID + level + description, sensor, and the time the first alert fired.
3.  ASSET        — hostname, IP, OS build, what the box is for, telemetry on it.
4.  IDENTITY     — account(s) involved, local or domain, privileges held.
5.  SOURCE       — origin address/port, and whether it is expected to talk to this asset.
6.  TIMELINE     — the 4-6 events that carry the story, in order, with times. One line each.
7.  EVIDENCE     — event record IDs, LogonId, ProcessGuid, hashes, alert IDs. Re-fetchable.
8.  ASSESSMENT   — verdict, confidence, ATT&CK technique(s), and the field that decided it.
9.  BLAST RADIUS — what is reachable from here, and explicitly what is NOT yet known.
10. ASK          — what I want tier 2 to do, plus what I have already done / containment state.
```

Rules that apply to every line:

- **Times**: use the endpoint's own clock (`data.win.system.systemTime`, or `UtcTime` for
  Sysmon 3 and 22), and say which. Wazuh's `@timestamp` runs about 1.8 s behind the endpoint
  in this lab — measured at -1.754 s, -1.821 s and -1.757 s on three consecutive event
  records — so a note built on it puts events in the wrong order relative to endpoint data.
- **Line 9 is not optional.** "What I could not determine" is information, and omitting it
  makes tier 2 assume you checked.
- **Line 10 names an action**, not a feeling. "Please advise" is not an ask.
- No secrets in the note: account names are fine, passwords and hashes of credentials are not.

---

## Worked example — investigation 003 (2026-09-07)

Times as recorded by the endpoint's Security channel on 2026-09-07.

```
1.  TITLE
    Successful SMB authentication from 10.10.10.5 to WIN11-VICTIMA using a local
    administrator account, after username enumeration and password guessing; the same
    source later opened a full RDP session.

2.  DETECTED BY
    Wazuh rule 60204 level 10 "Multiple Windows Logon Failures" (T1110), fired twice by
    accumulating 20 x rule 60122 level 5. Sensor: Wazuh 4.14.7 agent on WIN11-VICTIMA,
    Security channel. First alert in the 18:30 failure burst.

3.  ASSET
    WIN11-VICTIMA / 10.10.10.20 / Windows 11 Pro build 10.0.26200, Private network profile.
    Lab endpoint with inbound ICMP, SMB and RDP deliberately open. Telemetry: advanced audit
    policy, 4688 with command line, Sysmon64 (SwiftOnSecurity config), PowerShell 4103/4104,
    Wazuh agent connected.

4.  IDENTITY
    Enumeration phase targeted five accounts that do not exist on this host (admin,
    administrador, backup, sqlsvc, helpdesk). The account that was actually compromised is
    the local lab account <LAB_USER>, a member of the local Administrators group.

5.  SOURCE
    10.10.10.5, NTLM, WorkstationName empty ("-") on all 18 attempts — a signature of
    non-Windows tooling rather than a Windows client. This address has no legitimate reason
    to authenticate to this endpoint. Caveat: 10.10.10.5 is also the address reserved for the
    planned DC01, so IP-based attribution here has an expiry date.

6.  TIMELINE
    18:26:47  Ping sweep of 10.10.10.0/24 from 10.10.10.5; 5 live hosts found. No alert.
    18:26:50  Service scan against 7 ports on 10.10.10.20. Host-side residue: 2 Sysmon
              EID 3 inbound to :3389, Initiated=false. No alert.
    18:27:42  SMB null session -> Security 4624 ANONYMOUS LOGON, type 3, NTLM.
              Wazuh rule 92652, level 6.
    18:30:10-18:30:43  15 x 4625, SubStatus 0xC0000064 (accounts do not exist) across
              5 distinct names. Never subject to the lockout policy.
    18:31:13-18:31:16  3 x 4625, SubStatus 0xC000006A (account exists, wrong password)
              against <LAB_USER>. Enumeration has become targeted.
    18:31:19  Security 4624, logon type 3, NTLM, from 10.10.10.5 — AUTHENTICATION SUCCEEDED.
              Shares enumerated immediately after: ADMIN$, C$, IPC$ (READ).
    18:33:28-18:33:29  4 x 4625 logon type 3 from the same source — RDP attempts, not SMB
              (with NLA a failed RDP logon is type 3, corroborated by TS-RemoteConnection-
              Manager 1149 with Source Network Address 10.10.10.5).
    18:35:09  Security 4624 logon type 10, Negotiate, LogonProcessName User32 — full RDP
              session established. LocalSessionManager 41 -> 42 -> 21 -> 22 -> 24.

7.  EVIDENCE
    Alerts: 60122 level 5 x20; 60204 level 10 x2; 92652 level 6 x1; 92657 level 6 x3.
    Distinguishing fields: Status 0xC000006D on all failures, SubStatus 0xC0000064 x15 and
    0xC000006A x3; logon types 3 and 10; AuthenticationPackage NTLM then Negotiate.
    Excluded as known false positive: 12 x rule 92213 level 15 on
    __PSScriptPolicyTest_*.ps1 written by the signed system powershell.exe (18 occurrences
    across three exercises, never once true).
    Re-fetch from wazuh-alerts-* by data.win.system.eventRecordID for the 4624 at 18:31:19
    and the 4624 at 18:35:09; pivot value is the TargetLogonId on those two events.

8.  ASSESSMENT
    TRUE POSITIVE. Confidence high. Chain: T1046 (service discovery) -> T1135 (share
    discovery, via the null session) -> T1110.001 (password guessing) -> T1078.003 (valid
    local account) -> T1021.001 (RDP). The field that decided it is SubStatus: the
    0xC0000064 -> 0xC000006A transition at 18:31:13 is the point at which blind enumeration
    became a targeted attack on a known account, and 3 minutes later it succeeded.
    Note on the failure spacing: the ~2 s gap between attempts is Windows'
    EnableAuthRateLimiter (InvalidAuthenticationDelayTimeInMs = 2000, default on 24H2+),
    not the attacker's pacing. Do not profile the tooling from it.

9.  BLAST RADIUS
    The compromised account is a local administrator and ADMIN$ / C$ were reachable, so
    assume full control of WIN11-VICTIMA, including credential material cached on it.
    NOT KNOWN: (a) what was executed inside the RDP session — process activity for that
    LogonId has not yet been enumerated; (b) whether other hosts on 10.10.10.0/24 were
    touched, because there is no network sensor and a 65,535-port scan produced zero alerts
    in an earlier test; (c) whether anything persisted — note that Security 4697 "a service
    was installed" reaches the SIEM but matches no rule, so service installation would be
    silent here and must be checked on the host via 7045.

10. ASK
    Requesting: (1) approval to isolate WIN11-VICTIMA from SOCLAB; (2) a credential reset for
    <LAB_USER>; (3) tier 2 review of the RDP session content. Already done: source and account
    identified, timeline built, no containment applied yet — the host is still connected and
    the RDP session's own events are still on it. The lab's rollback snapshot (base-limpia)
    exists but restoring it destroys the evidence, so it is deliberately not being used yet.
```

*Framing note, kept because it matters more than the note itself: this incident was an
adversary-emulation exercise I ran against my own lab and then investigated. The same person
executed and analysed it, knowing the answer in advance. The escalation note is written as it
would be for a real alert, but it is not evidence of unscripted casework.*

---

## Why each line exists

| Line | The question it prevents tier 2 from having to ask |
|---|---|
| 1 Title | "What am I looking at?" — a rule name as a title makes every ticket look identical in a list |
| 2 Detected by | "Do we trust this detector?" — level and rule ID let them weigh it; in this lab level 15 is the least trustworthy number on the page |
| 3 Asset | "Does this box matter, and can I even get logs from it?" |
| 4 Identity | "How much does this account get them?" — local admin changes the whole response |
| 5 Source | "Is this normal traffic?" — an address with no business here is half the verdict |
| 6 Timeline | "In what order?" — and it is where the wrong clock silently ruins a note |
| 7 Evidence | "Can I see it myself?" — record IDs and LogonId make it re-fetchable rather than retold |
| 8 Assessment | "What do you actually think, and why?" — the deciding field is what makes it reviewable |
| 9 Blast radius | "What else is on fire?" and "what did you not check?" |
| 10 Ask | "What do you want from me?" — plus the containment state, which determines urgency |

## Anti-patterns

- **A rule name as the title.** "Multiple Windows Logon Failures" describes the detector, not
  the incident.
- **Alert counts as evidence.** "20 alerts" is not a finding; "15 failures against accounts
  that do not exist, then 3 against one that does" is.
- **Protocol claimed without corroboration.** Logon type 3 does not mean SMB — under NLA a
  failed RDP logon is type 3 too. Name the protocol only with 1149 / session events behind it.
- **Severity borrowed from the rule level.** Twelve level 15s in this exercise were all false
  positives; the most useful alert of the reconnaissance phase was a level 6.
- **A silent blast-radius line.** If the process activity in the session has not been
  enumerated, say so. Tier 2 will assume it was.
- **Stopping at "failed attempts".** The enumeration branch of a 4625 flood is not covered by
  the lockout policy at all: the 15 attempts against non-existent accounts on 2026-09-07 were
  never subject to the threshold of 10 per 10 minutes, because a lockout counter belongs to an
  account object and those accounts have none.
- **Passwords, hashes or tokens pasted into the note.** Account names yes; secrets never.

## Blank, for copy-paste

```
1.  TITLE:
2.  DETECTED BY:        rule / level / sensor / first-alert time (endpoint clock)
3.  ASSET:              host / IP / OS build / role / telemetry present
4.  IDENTITY:           account(s) / local or domain / privileges
5.  SOURCE:             address:port / expected here? / client fingerprint
6.  TIMELINE:           4-6 lines, in order, endpoint clock
7.  EVIDENCE:           eventRecordIDs / LogonId / ProcessGuid / hashes / alert IDs
8.  ASSESSMENT:         verdict / confidence / ATT&CK / the deciding field
9.  BLAST RADIUS:       reachable from here / NOT KNOWN:
10. ASK:                requested action / already done / containment state
```
