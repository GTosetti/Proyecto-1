# Sigma rules

Detection rules written against telemetry measured in the home SOC lab described elsewhere in
this repository: one Windows 11 Pro endpoint with advanced audit policy and Sysmon, a Wazuh
4.14.7 all-in-one manager, and a Kali VM used as the attacker, on a VirtualBox NAT network.

Every rule in this directory starts from something the lab actually produced: an event that
was generated but never alerted, an alert that fired on the wrong thing, or a field that
turned out to be the one that mattered. That is true of the *gap* in every case; it is not
true that every rule has a true positive behind it. Four do not: the office and browser rule
runs against software that is not installed here, the network-connection rule has only
inbound evidence, the DNS rule has one benign lookup, and no correlation in this directory
has ever been executed against lab data.

The log sources, fields and thresholds were chosen from measurements in this lab. Where a
detection converges on a well-known public pattern — the encoded-PowerShell command line is
the obvious case — that is noted in its `references`.

This file documents the six **Windows Security-channel** rules: five on authentication and
credential access, plus the 4697 service-installation rule, which is persistence and
masquerading rather than credential access and is grouped here only by channel. Other files
in this directory cover process, script, network and file telemetry; each of those rules is
documented in its own `description` block, and there is no second index file.

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
| `win_security_rdp_bruteforce_behind_nla.yml` | Burst of 4625 logon type 3 on a host with concurrent RDP listener activity |
| `win_security_successful_interactive_rdp_session.yml` | 4624 logon type 10 corroborated by TerminalServices LocalSessionManager 21 (logon) or 22 (shell start) |
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
sigma plugin install sysmon           # provides the sysmon pipeline; see the pipeline note below

sigma list targets
sigma list pipelines
sigma check -i detections/sigma/
```

`sigma check` over the whole directory — 12 files holding 21 rule documents, 7 of them
correlation rules — reports:

```
Found 0 errors, 0 condition errors and 0 issues.
```

`-i` is not optional. Without it `sigma check` defaults to `--pass-on-issues`: validation
issues, including an invalid ATT&CK tag, are printed and the command still exits 0.

### Atomic rules

```bash
sigma convert -t opensearch_lucene -p ecs_windows --disable-pipeline-check \
  detections/sigma/win_security_anonymous_logon_smb_null_session.yml
```

```
winlog.channel:Security AND ((event.code:4624 AND winlog.event_data.TargetUserName:"ANONYMOUS LOGON"
AND winlog.event_data.LogonType:3) AND (NOT ((source.ip:(127.0.0.1 OR \:\:1)) OR source.ip:\-)))
```

`--disable-pipeline-check` is required because `ecs_windows` registers itself against the
backend id `opensearch`, while the target id is `opensearch_lucene`; the pipeline itself
converts correctly. Note that ECS renames fields: `IpAddress` becomes `source.ip` and
`ServiceName` becomes `service.name`. If your index is not Winlogbeat-shaped — a raw Wazuh
index is not — the pipeline is the wrong one and the field names have to be mapped
separately (see the Wazuh section).

Read that last clause carefully, because it is a trap this rule walks into and had to be
restructured around. `source.ip` is an `ip`-typed field in ECS, and Windows writes the
literal `-` in `IpAddress` when there is no source address. Comparing a typed `ip` field to
`-` is a parse error, not a non-match: the backend rejects the query rather than returning
zero rows. The `-` is therefore in its own filter block in the rule, so that on a typed index
it can be swapped for a missing-field check without touching the rest of the condition. The
query above is the untyped form and is what a Wazuh index, where the same value is a string,
will accept.

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

`timespan` is a calendar bucket, not a sliding window. Look at the `date_trunc` in that
output: pySigma renders every correlation window as a fixed bucket on the wall clock, so
"within 15 minutes" means "inside the same quarter-hour". The effective window therefore
varies between 1× and 2× the declared span depending on where the activity falls, and a
burst that straddles a boundary is counted as two halves and may never reach the threshold.
The thresholds in these rules are **not** lowered to compensate: a lower number has no
measurement behind it, and the correct answer is a backend with a real sliding window.
Wazuh's `frequency` / `timeframe` is one, which is another reason the SIEM implementation is
the one this lab would deploy.

Three limitations were hit and are documented inside the affected rules rather than hidden:

1. **Field aliases** (`correlation.aliases`, used in
   `win_security_successful_interactive_rdp_session.yml` to join `IpAddress` to `Address`)
   are rejected by the ES|QL backend: *"Correlation field normalization is not supported by
   backend"*. Replacing the aliases block with `group-by: [host.name]` converts cleanly —
   verified on a copy — and costs the source-address grouping.
2. **Correlations that reference other correlations** (the chained rule in
   `win_security_rdp_bruteforce_behind_nla.yml`) are valid Sigma but render as a nested
   subquery inside a `where` clause, which is not valid ES|QL. The YAML states the intent;
   the SIEM implements it.
3. **`Computer` is not a group-by key.** It is a System-block field, and `ecs_windows` has
   no mapping for it, so it converts to `winlog.event_data.Computer` — a column that does
   not exist in a Winlogbeat-shaped index. Grouping on a field that is always null pools
   every host into one bucket, which silently turns "four failures on one host" into "four
   failures anywhere". Both RDP correlations group on `host.name` for that reason. This is
   the same class of failure as the silently dropped channel restriction below: the rule
   converts, runs, returns rows, and means something other than what it says.

A rule whose logsource service is unknown to the pipeline loses its channel restriction
**silently**: `terminalservices-remoteconnectionmanager` is not mapped by `ecs_windows`, and
the converted query matched event IDs 261 and 1149 across every index with no channel filter.
That rule therefore names `Channel` as a detection field as well. The sibling service
`terminalservices-localsessionmanager` is mapped, and does not need the workaround. Always
read the converted query before deploying it.

The same trap catches the six **category-based** rules in this directory — three
`proc_creation`, one each of `dns_query`, `net_connection` and `file_event`. `ecs_windows`
maps fields, not log-source categories; the category mapping lives in the separate `sysmon`
pipeline, and the documented conversion command has to load both, most specific first:

```bash
sigma plugin install sysmon
sigma convert -t opensearch_lucene -p sysmon -p ecs_windows --disable-pipeline-check \
  detections/sigma/dns_query_win_unexpected_process.yml
```

Measured on 2026-09-15 on the lab host, where the `sysmon` plugin is **not** installed: with
`-p ecs_windows` alone, the `dns_query` rule converts to a bare
`process.executable.caseless:(...)` with no channel clause at all — every restriction to
Sysmon Event ID 22 is gone, and the query matches ordinary process-creation documents for the
same binaries. The two pipelines that *are* installed here, `windows-logsources` and
`windows-audit` from `pysigma-pipeline-windows`, do not supply the missing category mapping:
tested individually, both produced the same unrestricted query. The output of the two-pipeline
command above has therefore not been captured on this host and is not published here. The
correct fix is not to hard-code `Channel` into those six rules — that trades portability for a
pipeline install — but the rules must not be deployed from a single-pipeline conversion
either. Read the converted query first; if the channel clause is missing, the pipeline is.

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
The Sigma files parse cleanly under `sigma check` 3.1.0 and convert on the backends listed
above; none has been validated in the sense defined in `../README.md`, which requires the
rule to be deployed, the source activity to be re-run, and a query to return the alert. The
Wazuh translation is the next lab task, with the `base-limpia` snapshots available for
rollback.

## What was measured in the lab behind each rule

None of these rules has been run against lab data. The table records the observation that
motivated each one, and what the stock ruleset did with the same telemetry.

Events were read on the endpoint with `Get-WinEvent -FilterHashtable`, driven from the host
through `VBoxManage guestcontrol` (which required adding the lab account to the local
`Event Log Readers` group and rebooting — group membership lives in the token, not in the
SAM, so the change does not take effect until the token is reissued). Alerts were counted by
querying `wazuh-alerts-*` through the dashboard console proxy shown above.

| Rule | What was generated, and when | What was observed |
|---|---|---|
| Password spray against non-existent accounts | 2026-09-07, 18:30:10–18:30:43: 15 authentication attempts from 10.10.10.5 against 5 account names that do not exist | 15 × 4625, Status `0xC000006D`, SubStatus `0xC0000064`, `WorkstationName` empty — a netexec fingerprint, not an operating-system one: smbclient from the same Kali VM populated it with `KALI` on 2026-08-08. The local lockout policy (10 attempts / 10 min) never applied. Stock ruleset, counted over the whole exercise rather than this phase: rule 60122 × 20 at level 5 and rule 60204 × 2 at level 10, neither of which reads SubStatus. The exercise recorded 22 type 3 failures in total, so two produced no 60122 at all; the difference is unexplained and is itself a coverage observation |
| Targeted password guessing | 2026-09-07, 18:31:13–18:31:16: 3 attempts against a real local account, then a successful logon at 18:31:19 | 3 × 4625 with SubStatus `0xC000006A`, then 4624 logon type 3, NTLM. The SubStatus transition is the only field that marks the change from enumeration to a targeted attack |
| Anonymous logon / SMB null session | 2026-09-07, 18:27:42: SMB null session from the attacker VM | 4624, `ANONYMOUS LOGON`, logon type 3, NTLM, from 10.10.10.5. Wazuh rule 92652, level 6 — the only reliable host-side trace of the entire reconnaissance phase, which also included an nmap sweep and a 7-port service scan that left 2 Sysmon Event ID 3 records and 0 Security 5156 records — 5156 is "connection permitted" and its subcategory is off here, so that zero bounds nothing about the filtered ports; see the limits section below |
| Failed logon burst with RDP listener activity | 2026-09-07, 18:33:28–18:33:29: 4 failed RDP logins | 4 × 4625 with **logon type 3, not 10** — indistinguishable from SMB failures by logon type. TerminalServices-RemoteConnectionManager 1149 recorded at 18:33:30–18:33:31 carrying the source network address — but 1149 is "User authentication SUCCEEDED", and those two belong to the auth-only authentications that worked, not to the four failures. Event ID 261, the event a pure failure burst should produce, was not separately confirmed and is flagged as unvalidated inside the rule |
| Successful interactive RDP session | 2026-09-07, 18:35:09: full graphical session via `xvfb-run -a xfreerdp`, held open 90 s | 4624 logon type 10, AuthenticationPackage `Negotiate`, LogonProcess `User32`, plus LocalSessionManager 41 → 42 → 21 → 22 for the establishment, then 24 at the 18:36:49 disconnect. EID 22 is shell start, not reconnection — reconnection is 25 and has never been produced here. Sessions held under roughly 60 s were cut before logon completed and produced only the listener events |
| Service installation (4697) | 2026-08-08, 21:44:56 local: a test service was installed | `Get-WinEvent` returned the 4697; the Security channel is declared to the agent and the agent reported connected, so collection is expected but was not independently verified; a `wazuh-alerts-*` query returned **0 documents** with event ID 4697. The same installation alerted through event ID 7045 from the System channel |

The 2026-08-08 exercise is also what set the thresholds' negative test. It produced 10 × 4625
with the same SubStatus `0xC0000064` as the spray — 5 local `runas` attempts (logon type 2,
`seclogo`, `::1`) and 5 SMB attempts from Kali (logon type 3, `NtLmSsp`, 10.10.10.5) — but
only one account name per source. The spray rule requires 3 distinct names per source and
therefore stays silent on it, which is the behaviour that separates it from a failure counter.

## Limits of this ruleset

Stated because a coverage claim that is not bounded is a false claim.

- **Host visibility is not network visibility.** A 65,535-port SYN scan lasting 88 seconds
  produced 0 attributable alerts. With the audit subcategories enabled on this endpoint,
  nothing recorded the scan. The subcategory that would is **Audit Filtering Platform Packet
  Drop** (5152/5153), which is off here because of volume and has never been measured in this
  lab; **Audit Filtering Platform Connection** (5156/5157) is the wrong one — 5156 is
  "connection permitted", so it would have recorded only the eight open ports and nothing
  about the 65,527 that were filtered. No Sigma rule in this directory fixes either case. The
  recommended answer remains a network sensor.
- **The alert index is bounded by the ruleset, not by the endpoint.** In the 2026-08-08
  exercise roughly 2,100 events reached the manager and 835 alerts were indexed for the
  endpoint; in the 2026-08-11 exercise, 172 generated events produced 36 alerts. (The first
  per-channel count gave 167 and 27 - it clipped events at the window boundary; the widened
  recount is in `../../investigations/002-process-telemetry-correlation.md`.) The point
  survives the arithmetic: absence of an alert is not absence of activity.
- **Clocks disagree.** The Wazuh manager `@timestamp` — the dashboard's default time axis —
  ran 1.75–1.82 s behind the endpoint across three consecutive event records. Time-window
  correlations should be evaluated against `data.win.system.systemTime`, and Sysmon events 3
  and 22 need their own `UtcTime` field: the channel wrote them 3.2 s and 4.0 s *after* they
  occurred, so a timeline sorted on `TimeCreated` places a DNS query after the process that
  issued it. The five-minute windows used here absorb that skew; a thirty-second window would
  not.
- **Some channels are not collected yet.** The lab agent forwards Security, System,
  Application, `Microsoft-Windows-Sysmon/Operational` and
  `Microsoft-Windows-PowerShell/Operational`. The two Terminal Services channels used by the
  RDP rules must be added to `ossec.conf` first, otherwise those correlations can never fire.
- **1102, audit log cleared, has never been generated in this lab**, and no query has ever
  been run against it. No rule for it appears in this directory, because nothing has been
  measured about it yet.

## ATT&CK tags and version drift

Tags follow the Sigma taxonomy (`attack.<tactic>`, `attack.t####`). Note that ATT&CK v18
renamed tactic TA0005 from *Defense Evasion* to *Stealth*: `sigma check` with sigma-cli 3.1.0
rejects `attack.defense-evasion` as an invalid ATT&CK tag and accepts `attack.stealth`, which
is what these rules use. Most third-party documentation still uses the old name, so expect
the mismatch when cross-referencing. Version 18 also replaced the prose *Detection* section
of technique pages with Detection Strategies (`DET####`) and Analytics (`AN####`).
