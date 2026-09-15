# Sigma rules

Detection rules written against telemetry measured in the home SOC lab described elsewhere in
this repository: one Windows 11 Pro endpoint with advanced audit policy and Sysmon, a Wazuh
4.14.7 all-in-one manager, and a Kali VM used as the attacker, on a VirtualBox NAT network.

Every rule in this directory answers something the lab actually produced: an event that was
generated but never alerted, an alert that fired on the wrong thing, or a field that turned
out to be the one that mattered. Nothing here is copied from a public ruleset, and the
thresholds are lab numbers, not defaults.

This file documents the six **authentication and credential access** rules. Other files in
this directory cover process, script, network and file telemetry and are documented with
their own rules.

## Naming convention

The community convention, as used by SigmaHQ:

```
<category-or-product>_<service-or-detail>_<what it detects>.yml
```

- Lowercase, words separated by underscores, `.yml` (not `.yaml`).
- Rules tied to a Windows channel are prefixed by product and service: `win_security_*`,
  `win_system_*`. Rules tied to a generic Sigma log source category use the category:
  `proc_creation_win_*`, `dns_query_win_*`, `net_connection_win_*`, `file_event_win_*`.
- `susp_` marks a rule that describes something suspicious rather than something known bad.
- The filename never carries the event ID. The event ID belongs in the detection, and rules
  that grow to cover a second event ID should not have to be renamed.

| File | Detects |
|---|---|
| `win_security_password_spray_nonexistent_accounts.yml` | 4625 / SubStatus `0xC0000064`, several distinct unknown usernames from one source |
| `win_security_targeted_password_guessing_valid_account.yml` | 4625 / SubStatus `0xC000006A`, repeated wrong passwords against a real account |
| `win_security_anonymous_logon_smb_null_session.yml` | 4624 ANONYMOUS LOGON, logon type 3, from a remote address |
| `win_security_rdp_bruteforce_behind_nla.yml` | Burst of 4625 logon type 3 corroborated by the RDP listener channel |
| `win_security_successful_interactive_rdp_session.yml` | 4624 logon type 10 corroborated by TerminalServices LocalSessionManager 21/22 |
| `win_security_susp_service_installation.yml` | 4697, service image outside System32, masquerading name, or interpreter as service |

## File layout: several documents per file

Four of the six files contain **more than one YAML document**, separated by `---`:

- a **base rule** (or two) with `logsource` + `detection`, carrying a `name:` field, and
- one or more **correlation rules** (Sigma specification 2.0) that reference those names and
  add the threshold or the cross-channel requirement.

This is deliberate. The old aggregation syntax (`condition: selection | count(x) by y > 3`)
is not part of the current Sigma specification and pySigma does not parse it; counting and
cross-source correlation are expressed with correlation rules instead. Keeping a base rule
and its correlations in one file keeps one detection idea in one place — the alternative,
scattering `name:` references across files, only works if the whole directory is always
loaded as a single collection.

Consequences for anything that reads these files:

- Parse with `yaml.safe_load_all`, not `safe_load`. A single-document loader raises on every
  multi-document file here.
- Base rules are marked `level: informational` and are not meant to be alerted on directly.
  The alerting document is the correlation, or — in `win_security_rdp_bruteforce_behind_nla.yml`
  — the `level: medium` burst correlation, which is the part that converts everywhere.
- Every document carries its own `id` (UUIDv4, all distinct), `status: experimental`,
  `date`/`modified`, `tags`, `falsepositives` and `level`.

## Converting with sigma-cli

Measured on 2026-09-15 with **sigma-cli 3.1.0** on the lab host; the commands and the
outputs below are transcripts, not illustrations.

```bash
pip install sigma-cli
sigma plugin install elasticsearch    # provides lucene, eql, esql and the ecs_windows pipeline
sigma plugin install opensearch       # provides opensearch_lucene, open_search_ppl

sigma list targets
sigma list pipelines
sigma check detections/sigma/
```

`sigma check` on the six files in this document reports:

```
Found 0 errors, 0 condition errors and 0 issues.
```

### Atomic rules

```bash
sigma convert -t opensearch_lucene -p ecs_windows --disable-pipeline-check \
  detections/sigma/win_security_anonymous_logon_smb_null_session.yml
```

```
winlog.channel:Security AND ((event.code:4624 AND winlog.event_data.TargetUserName:"ANONYMOUS LOGON"
AND winlog.event_data.LogonType:3) AND (NOT (source.ip:(\- OR 127.0.0.1 OR \:\:1))))
```

`--disable-pipeline-check` is required because `ecs_windows` registers itself against the
backend id `opensearch`, while the target id is `opensearch_lucene`; the pipeline itself
converts correctly. Note that ECS renames fields: `IpAddress` becomes `source.ip` and
`ServiceName` becomes `service.name`. If your index is not Winlogbeat-shaped — a raw Wazuh
index is not — the pipeline is the wrong one and the field names have to be mapped
separately (see the Wazuh section).

### Correlation rules

Support is uneven, and this is worth knowing before writing a rule that depends on it:

| Target | Correlation support (measured with `sigma list correlation-methods <target>`) |
|---|---|
| `opensearch_lucene` | none — conversion fails with "Backend does not support correlation rules" |
| `lucene` | none |
| `eql` | `sequence` (ordered only) |
| `esql` | `stats` |

`event_count` and `value_count` correlations convert cleanly to ES|QL:

```bash
sigma convert -t esql -p ecs_windows --disable-pipeline-check \
  detections/sigma/win_security_password_spray_nonexistent_accounts.yml
```

```
from * metadata _id, _index, _version | where winlog.channel=="Security" and event.code=="4625"
and winlog.event_data.SubStatus=="0xC0000064"
| eval timebucket=date_trunc(15minutes, @timestamp)
| stats value_count=count_distinct(winlog.event_data.TargetUserName), ... by timebucket, source.ip
| where value_count >= 3
```

Two limitations were hit and are documented inside the affected rules rather than hidden:

1. **Field aliases** (`correlation.aliases`, used in
   `win_security_successful_interactive_rdp_session.yml` to join `IpAddress` to `Address`)
   are rejected by the ES|QL backend: *"Correlation field normalization is not supported by
   backend"*. Replacing the aliases block with `group-by: [Computer]` converts cleanly —
   verified on a copy — and costs the source-address grouping.
2. **Correlations that reference other correlations** (the chained rule in
   `win_security_rdp_bruteforce_behind_nla.yml`) are valid Sigma but render as a nested
   subquery inside a `where` clause, which is not valid ES|QL. The YAML states the intent;
   the SIEM implements it.

A rule whose logsource service is unknown to the pipeline loses its channel restriction
**silently**: `terminalservices-remoteconnectionmanager` is not mapped by `ecs_windows`, and
the converted query matched event IDs 261 and 1149 across every index with no channel filter.
That rule therefore names `Channel` as a detection field as well. The sibling service
`terminalservices-localsessionmanager` is mapped, and does not need the workaround. Always
read the converted query before deploying it.

## Running them on Wazuh

Wazuh is not one of the sigma-cli targets, and its indexer is not queried directly in this
lab — the indexer listens on 9200 on localhost only inside the SIEM VM, so the working path
from the host is the dashboard console proxy already exposed on 8443:

```bash
curl -k -u admin:<REDACTED> -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query.json
```

Two things have to be translated by hand:

**Field names.** Wazuh's eventchannel decoder exposes Windows fields as
`data.win.system.eventID`, `data.win.system.channel`, `data.win.eventdata.subStatus`,
`data.win.eventdata.targetUserName`, `data.win.eventdata.ipAddress`,
`data.win.eventdata.logonType` — the XML element name with a lowercase first letter. In
`local_rules.xml` the `data.` prefix is dropped (`win.eventdata.subStatus`).

**Correlation.** Wazuh expresses it as a composite rule with `frequency` / `timeframe` and
`same_field` / `different_field`, which is exactly how its own rule 60204 works. Sketch for
the first rule in this directory:

```xml
<group name="local,windows,authentication_failures,">
  <!-- base: win_security_4625_substatus_no_such_user -->
  <rule id="100200" level="3">
    <if_sid>60122</if_sid>
    <field name="win.eventdata.subStatus">0xC0000064</field>
    <description>Failed logon against a non-existent account from $(win.eventdata.ipAddress)</description>
    <mitre><id>T1110.001</id></mitre>
  </rule>

  <!-- correlation: 3 distinct unknown usernames from one source in 15 minutes -->
  <rule id="100201" level="10" frequency="3" timeframe="900">
    <if_matched_sid>100200</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <different_field>win.eventdata.targetUserName</different_field>
    <description>Password spraying: several non-existent accounts probed from one source</description>
    <mitre><id>T1110.003</id></mitre>
  </rule>
</group>
```

Custom rule ids must be 100000 or above. The 24-hour variant becomes `timeframe="86400"`,
which is the documented ceiling for that attribute. Verify the effective threshold by
generating exactly N events and counting alerts rather than trusting `frequency`: the
counting semantics have differed between versions, and the whole point of this repository is
that the number gets checked.

**Status: not yet deployed.** These XML sketches have not been loaded into the lab manager.
The Sigma files are the specification and have been validated; the Wazuh translation is the
next lab task, with the `base-limpia` snapshots available for rollback.

## How each rule was validated in the lab

Events were read on the endpoint with `Get-WinEvent -FilterHashtable`, driven from the host
through `VBoxManage guestcontrol` (which required adding the lab account to the local
`Event Log Readers` group and rebooting — group membership lives in the token, not in the
SAM, so the change does not take effect until the token is reissued). Alerts were counted by
querying `wazuh-alerts-*` through the dashboard console proxy shown above.

| Rule | What was generated, and when | What was observed |
|---|---|---|
| Password spray against non-existent accounts | 2026-09-07, 18:30:10–18:30:43: 15 authentication attempts from 10.10.10.5 against 5 account names that do not exist | 15 × 4625, Status `0xC000006D`, SubStatus `0xC0000064`, `WorkstationName` empty. The local lockout policy (10 attempts / 10 min) never applied. Stock ruleset: rule 60122 × 20 at level 5 and rule 60204 × 2 at level 10, neither of which reads SubStatus |
| Targeted password guessing | 2026-09-07, 18:31:13–18:31:16: 3 attempts against a real local account, then a successful logon at 18:31:19 | 3 × 4625 with SubStatus `0xC000006A`, then 4624 logon type 3, NTLM. The SubStatus transition is the only field that marks the change from enumeration to a targeted attack |
| Anonymous logon / SMB null session | 2026-09-07, 18:27:42: SMB null session from the attacker VM | 4624, `ANONYMOUS LOGON`, logon type 3, NTLM, from 10.10.10.5. Wazuh rule 92652, level 6 — the only reliable host-side trace of the entire reconnaissance phase, which also included an nmap sweep and a 7-port service scan that left 2 Sysmon Event ID 3 records and 0 Security 5156 records |
| RDP brute force behind NLA | 2026-09-07, 18:33:28–18:33:29: 4 failed RDP logins | 4 × 4625 with **logon type 3, not 10** — indistinguishable from SMB failures by logon type. TerminalServices-RemoteConnectionManager 1149 recorded at 18:33:30–18:33:31 carrying the source network address. Event ID 261 was not separately confirmed and is flagged as unvalidated inside the rule |
| Successful interactive RDP session | 2026-09-07, 18:35:09: full graphical session via `xvfb-run -a xfreerdp`, held open 90 s | 4624 logon type 10, AuthenticationPackage `Negotiate`, LogonProcess `User32`, plus LocalSessionManager 41 → 42 → 21 → 22 → 24. Sessions held under roughly 60 s were cut before logon completed and produced only the listener events |
| Service installation (4697) | 2026-08-08, 21:44:56 local: a test service was installed | `Get-WinEvent` returned the 4697; the Security channel is forwarded by the agent; a `wazuh-alerts-*` query returned **0 documents** with event ID 4697. The same installation alerted through event ID 7045 from the System channel |

The 2026-08-08 exercise is also what set the thresholds' negative test. It produced 10 × 4625
with the same SubStatus `0xC0000064` as the spray — 5 local `runas` attempts (logon type 2,
`seclogo`, `::1`) and 5 SMB attempts from Kali (logon type 3, `NtLmSsp`, 10.10.10.5) — but
only one account name per source. The spray rule requires 3 distinct names per source and
therefore stays silent on it, which is the behaviour that separates it from a failure counter.

## Limits of this ruleset

Stated because a coverage claim that is not bounded is a false claim.

- **Host visibility is not network visibility.** A 65,535-port SYN scan lasting 88 seconds
  produced 0 attributable alerts, because Windows does not log a SYN to a closed port
  anywhere. No Sigma rule fixes that; it needs Windows Filtering Platform auditing (5156,
  deliberately not enabled here because of volume) or a network sensor.
- **The alert index is bounded by the ruleset, not by the endpoint.** In the 2026-08-08
  exercise roughly 2,100 events reached the manager and 835 alerts were indexed for the
  endpoint; in the 2026-08-11 exercise, 167 generated events produced 27 alerts. Absence of
  an alert is not absence of activity.
- **Clocks disagree.** The Wazuh manager `@timestamp` — the dashboard's default time axis —
  ran 1.75–1.82 s behind the endpoint across three consecutive event records. Time-window
  correlations should be evaluated against `data.win.system.systemTime`, and Sysmon events 3
  and 22 need their own `UtcTime` field, which in the lab was 3.2 s and 4.0 s ahead of the
  channel's `TimeCreated`. The five-minute windows used here absorb that skew; a
  thirty-second window would not.
- **Some channels are not collected yet.** The lab agent forwards Security, System,
  Application, `Microsoft-Windows-Sysmon/Operational` and
  `Microsoft-Windows-PowerShell/Operational`. The two Terminal Services channels used by the
  RDP rules must be added to `ossec.conf` first, otherwise those correlations can never fire.
- **One event ID on the priority list has never been generated here at all**: 1102, audit log
  cleared. No rule for it appears in this directory, because nothing has been measured about
  it yet.

## ATT&CK tags and version drift

Tags follow the Sigma taxonomy (`attack.<tactic>`, `attack.t####`). Note that ATT&CK v18
renamed tactic TA0005 from *Defense Evasion* to *Stealth*: `sigma check` with sigma-cli 3.1.0
rejects `attack.defense-evasion` as an invalid ATT&CK tag and accepts `attack.stealth`, which
is what these rules use. Most third-party documentation still uses the old name, so expect
the mismatch when cross-referencing. Version 18 also replaced the prose *Detection* section
of technique pages with Detection Strategies (`DET####`) and Analytics (`AN####`).
