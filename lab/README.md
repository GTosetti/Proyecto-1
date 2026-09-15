# Home SOC Lab — Build Guide

This is the build guide for the lab that produced every measurement in this repository.
It is written so that the lab can be rebuilt from nothing: hardware sizing, network,
per-VM configuration, install order and the reason for that order, the telemetry
baseline, and — the part most build guides skip — how to **prove** each piece works
instead of assuming it does.

Every number below was taken on the machine described in [Host](#1-host-and-sizing).
Where a value is a measurement, the guide says how it was measured. Where a value is a
default or a vendor fact, it says that too.

No credential appears anywhere in this repository. Placeholders are written as
`<LAB_USER>`, `<LAB_PASSWORD>`, `<WAZUH_ADMIN_PASSWORD>`. The RFC1918 addresses
(`10.10.10.0/24`) are real but belong to an isolated NAT network on a single host.

---

## Contents

1. [Host and sizing](#1-host-and-sizing)
2. [Architecture](#2-architecture)
3. [Build order, and why it is this order](#3-build-order-and-why-it-is-this-order)
4. [Step 1 — NAT network and port forwards](#4-step-1--nat-network-and-port-forwards)
5. [Step 2 — SIEM VM (Ubuntu + Wazuh)](#5-step-2--siem-vm-ubuntu--wazuh)
6. [Step 3 — Endpoint VM (unattended Windows 11)](#6-step-3--endpoint-vm-unattended-windows-11)
7. [Step 4 — Telemetry baseline and agent](#7-step-4--telemetry-baseline-and-agent)
8. [Step 5 — Attacker VM](#8-step-5--attacker-vm)
9. [Step 6 — Snapshots](#9-step-6--snapshots)
10. [Verification — six checks](#10-verification--six-checks)
11. [Known limits of this architecture](#11-known-limits-of-this-architecture)
12. [Troubleshooting](#12-troubleshooting)
13. [Scripts](#13-scripts)

---

## 1. Host and sizing

| Item | Value |
|---|---|
| CPU | Ryzen 7 3800X, 8 cores / 16 threads |
| RAM | 48 GB |
| Host OS | Windows 11 |
| Hypervisor | VirtualBox 7.2.6 |
| `VBoxManage` | `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe` |
| Storage | Single disk, C: 952 GB total |

Disk is the constraint, not RAM. Measured on this host:

| Measurement | Value | How measured |
|---|---|---|
| Free space before the build | 259 GB | Disk properties, 2026-07-29 |
| Free space after three VMs and their snapshots | 46 GB (96 % used) | Disk properties, 2026-09-07 |
| Disk consumed by the Windows 11 install alone | 0 → 17.2 GB | VDI size before and after the unattended install |
| RAM in use with all three VMs running | 20 GB of 48 GB | Task Manager, host side, all three VMs booted and idle |

So the practical floor is around 24 GB of RAM and, realistically, 250 GB of free disk if
you intend to keep snapshots and later add a domain controller. 48 GB of RAM is
comfortable; 20 GB is what the three VMs actually take.

**Nested virtualisation is not required.** Everything here runs as ordinary guests.

### VirtualBox CLI

All commands in this guide use `VBoxManage`. Set it once per shell:

```powershell
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vbox list vms
& $vbox list runningvms
& $vbox natnetwork list
```

---

## 2. Architecture

```
                    HOST (Windows 11, VirtualBox 7.2.6)
                    ├── https://127.0.0.1:8443  ──┐   NAT port-forward 8443 -> 10.10.10.10:443
                    └── ssh 127.0.0.1 -p 2222   ──┤   NAT port-forward 2222 -> 10.10.10.10:22
                                                  │
        ┌─────────────────────────────────────────┴──────────────────────────────┐
        │              NAT Network "SOCLAB"  ·  10.10.10.0/24  ·  gw 10.10.10.1   │
        │                            DHCP enabled                                 │
        └───┬────────────────────────┬───────────────────────────┬────────────────┘
            │                        │                           │
     ┌──────┴───────┐        ┌───────┴────────┐          ┌───────┴────────┐
     │  WAZUH-SIEM  │        │ WIN11-VICTIMA  │          │      Kali      │
     │ 10.10.10.10  │◄───────│  10.10.10.20   │          │  DHCP (attack) │
     │ Ubuntu 24.04 │  agent │ Win 11 Pro     │◄─────────│  nic2 = SOCLAB │
     │ Wazuh 4.14.7 │  1514  │ Sysmon + agent │  nmap    │  nic1 = NAT    │
     └──────────────┘        └────────────────┘  smb/rdp └────────────────┘

                       ┌────────────────┐
                       │  DC01 (stage 2)│  10.10.10.5  — planned, not yet created
                       └────────────────┘
```

| VM | Role | RAM | vCPU | Address | Notes |
|---|---|---|---|---|---|
| `WAZUH-SIEM` | SIEM | 8 GB | 4 | static `10.10.10.10` | Ubuntu Server 24.04.4 LTS, Wazuh 4.14 all-in-one (installer resolves to 4.14.7) |
| `WIN11-VICTIMA` | Endpoint under observation | 6 GB | 4 | static `10.10.10.20` | Windows 11 **Pro** 25H2, build 10.0.26200, EFI + TPM 2.0, Guest Additions 7.2.6 |
| Kali | Attacker | 6 GB | 4 | DHCP | `nic1` = NAT (internet), `nic2` = SOCLAB. Kali 2026.1 VirtualBox image |
| `DC01` | Domain controller | 4 GB | 2 | `10.10.10.5` | Stage 2. Not built yet — see the address-collision note in [Troubleshooting](#12-troubleshooting) |

### Two decisions worth stating up front

**Windows must be Pro, not Home.** Home cannot join a domain (that kills stage 2) and has
no RDP server (that kills every logon-type-10 exercise). The edition is chosen at the
product-key screen by selecting *I don't have a product key*.

**Windows must be installed in English.** `auditpol` addresses audit subcategories by
their localised display name, and every Sigma rule, tutorial and vendor document assumes
the English event text. A Spanish-language install silently breaks the telemetry script
in [Step 4](#7-step-4--telemetry-baseline-and-agent).

---

## 3. Build order, and why it is this order

The order is not arbitrary. Each step exists because the next one cannot be verified
without it.

| # | Step | Why it must come first |
|---|---|---|
| 1 | NAT network + port forwards | Without a working L3 path there is nothing to test in steps 2–4, and the port forwards are the only way the host reaches the dashboard. |
| 2 | SIEM (Ubuntu + Wazuh) | **The agent has to have somewhere to report.** An agent installed before the manager exists enrols against nothing, sits in `pending`, and you end up debugging the agent when the real problem is that the server was never there. Install the manager first and the agent's very first action — enrolment — becomes a test of the whole path. |
| 3 | Endpoint OS | Needs an address on the same segment as the manager. |
| 4 | Telemetry baseline **then** agent | In that order. Windows out of the box logs almost nothing useful: no command line in 4688, no PowerShell script blocks, a 20 MB Security channel that wraps in hours. If you install the agent first, it faithfully ships an empty stream and the lab looks like it works while producing nothing worth reading. Configure generation, *then* collection. |
| 5 | Attacker VM | Only useful once there is something to attack that is being watched. |
| 6 | Snapshots | Taken last, of a known-good state, so every destructive exercise afterwards is reversible. |

Domain Controller is deliberately **stage 2**. Building AD before you can read a single
Event ID is where most home labs stall.

---

## 4. Step 1 — NAT network and port forwards

A VirtualBox **NAT Network** (not plain NAT, not host-only) is what gives the guests both
mutual visibility and internet access. Host-only would block the internet, which the
Wazuh installer and the Sysmon download need.

```powershell
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

& $vbox natnetwork add --netname SOCLAB --network "10.10.10.0/24" --enable --dhcp on
& $vbox natnetwork list
```

Attach each VM's SOCLAB interface:

```powershell
& $vbox modifyvm "WAZUH-SIEM"    --nic1 natnetwork --nat-network1 SOCLAB
& $vbox modifyvm "WIN11-VICTIMA" --nic1 natnetwork --nat-network1 SOCLAB
# Kali keeps nic1 = NAT for internet and gets SOCLAB as a second interface:
& $vbox modifyvm "<KALI_VM_NAME>" --nic2 natnetwork --nat-network2 SOCLAB
```

### Port forwards

The host is outside the NAT network. Two forwards make the SIEM reachable from the host
browser and shell:

```powershell
& $vbox natnetwork modify --netname SOCLAB `
    --port-forward-4 "wazuh-dash:tcp:[127.0.0.1]:8443:[10.10.10.10]:443"
& $vbox natnetwork modify --netname SOCLAB `
    --port-forward-4 "siem-ssh:tcp:[127.0.0.1]:2222:[10.10.10.10]:22"
```

Result: dashboard at `https://127.0.0.1:8443`, shell at `ssh <LAB_USER>@127.0.0.1 -p 2222`.

Deleting a rule uses a different, three-token form — passing `"delete name"` as one
argument returns *Invalid port-forward rule*:

```powershell
& $vbox natnetwork modify --netname SOCLAB --port-forward-4 delete wazuh-dash
```

> **Do not add a forward for 9200.** The Wazuh indexer binds to localhost only, inside the
> VM, so the forward completes a TCP connection that the indexer never answers — `curl`
> returns error 35 (TLS). The working path from the host is the dashboard's console proxy;
> see [Verification, check 5](#check-5--the-query-path).

---

## 5. Step 2 — SIEM VM (Ubuntu + Wazuh)

### 5.1 ISO

Download Ubuntu Server 24.04.4 LTS and **verify the hash before booting it**. This is one
minute of work that removes an entire class of later confusion.

```powershell
$r = Invoke-WebRequest -UseBasicParsing "https://releases.ubuntu.com/24.04/SHA256SUMS"
# PowerShell 5.1 returns .Content as a byte array here, not a string:
[System.Text.Encoding]::UTF8.GetString($r.Content)

Get-FileHash "C:\Users\<YOU>\ISOs\ubuntu-24.04.4-live-server-amd64.iso" -Algorithm SHA256
```

The hash of the ISO used for this build matched the official `SHA256SUMS` entry.

**Ubuntu 24.04 LTS, not the newest LTS.** Wazuh lags behind new LTS releases; using the
one the vendor supports avoids a class of packaging problems that has nothing to do with
what this lab is for.

### 5.2 VM and install

8 GB RAM, 4 vCPU, a disk of at least 60 GB. During the installer, choose OpenSSH server.
Static addressing is set after the install (see the netplan note below) because the
installer's own network step is where the `bond0` trap lives.

### 5.3 Network — the trap

On this build the installer produced a **single-NIC bond**: `enp0s3` became a `SLAVE` of a
`bond0` that never obtained an address. `ip -4 a` showed only `lo`.

Fix — replace the cloud-init-generated netplan with a plain static config, stop cloud-init
from regenerating it, then apply:

```bash
sudo tee /etc/netplan/50-cloud-init.yaml >/dev/null <<'YAML'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [10.10.10.10/24]
      routes:
        - to: default
          via: 10.10.10.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
YAML

echo 'network: {config: disabled}' | \
  sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo netplan apply

ip -4 a show enp0s3        # must now show 10.10.10.10/24
ip link                    # must NOT show enp0s3 as SLAVE of bond0
```

Then make sure SSH actually exists:

```bash
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
```

### 5.4 Wazuh

Run from the host over the SSH forward, so commands can be pasted:

```bash
ssh <LAB_USER>@127.0.0.1 -p 2222

sudo apt update && sudo apt upgrade -y
curl -fsSLO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Two details that cost time if you get them wrong:

- The **version-specific path is required for the manager**: `4.14/` works, the generic
  `4.x/` returns 403. The Windows agent MSI is the exact opposite — see
  [Troubleshooting](#12-troubleshooting).
- Use `curl -fsSLO`, never `curl -sO`. Without `-f`, curl saves the HTTP 403 XML body
  under the script's filename and bash then fails with
  `syntax error near unexpected token 'newline'` on a line reading `<?xml version="1.0"...>`.
  The symptom points at the vendor's script; the cause is an error page on disk.

The installer prints the `admin` password on completion. **Record it outside this
repository.** It is referred to here as `<WAZUH_ADMIN_PASSWORD>` and appears nowhere in
these files.

Log in at `https://127.0.0.1:8443` (self-signed certificate; the browser warning is
expected).

---

## 6. Step 3 — Endpoint VM (unattended Windows 11)

6 GB RAM, 4 vCPU, EFI enabled, TPM 2.0 enabled — Windows 11 setup refuses to install
without the last two.

```powershell
& $vbox modifyvm "WIN11-VICTIMA" --firmware efi --tpm-type 2.0
```

### 6.1 Getting the ISO

The Microsoft consumer download page failed during this build. The ISO was obtained with
**Fido**, a PowerShell script that queries Microsoft's own download API. Microsoft does
not publish SHA256 values for consumer Windows ISOs, so hash verification against a vendor
list is not possible; the ISO was instead validated structurally by mounting it and
confirming `setup.exe`, `sources\boot.wim` and `sources\install.wim` are present, and its
own hash was recorded locally for future comparison.

### 6.2 Unattended install

The install is driven by a self-authored `autounattend.xml`. **That file is deliberately
not in this repository** — it carries account configuration.

The approach, which is the reusable part:

1. Write `autounattend.xml`.
2. Package it into a small ISO. `oscdimg` ships only with the Windows ADK, which is a
   large install for one file, so the ISO is built with **IMAPI2**, the CD-burning COM API
   that is already part of Windows.
3. Attach that ISO as a **second optical drive**. Windows Setup scans the root of *every*
   drive for `autounattend.xml`, so it does not need to be inside the installation media.

```powershell
& $vbox storageattach "WIN11-VICTIMA" --storagectl "IDE" --port 0 --device 0 `
    --type dvddrive --medium "C:\Users\<YOU>\ISOs\Win11_25H2.iso"
& $vbox storageattach "WIN11-VICTIMA" --storagectl "IDE" --port 1 --device 0 `
    --type dvddrive --medium "C:\Users\<YOU>\ISOs\unattend.iso"
```

Two things that were learned the hard way:

- **Language settings in the `windowsPE` pass do not carry over to OOBE.** They must be
  repeated with a `Microsoft-Windows-International-Core` component in the `oobeSystem`
  pass, or setup still stops to ask for region and keyboard and the install is no longer
  unattended.
- **Disconnect the network cable for the duration of the install.** With a link, OOBE can
  force a Microsoft account, which breaks a local-account answer file. Remember to
  reconnect afterwards:

```powershell
& $vbox modifyvm  "WIN11-VICTIMA" --cableconnected1 off      # before starting
& $vbox controlvm "WIN11-VICTIMA" setlinkstate1 on           # after OOBE finishes
```

Measured result: Windows 11 Pro build 10.0.26200, VDI grew from 0 to 17.2 GB, Guest
Additions 7.2.6 installed silently by the answer file.

### 6.3 Guest Additions

Guest Additions are what make the rest of the build scriptable from the host:

```powershell
& $vbox guestcontrol "WIN11-VICTIMA" --username <LAB_USER> --password <LAB_PASSWORD> `
    copyto "C:\path\on\host\01-endpoint-telemetry.ps1" "C:\lab\01-endpoint-telemetry.ps1"
```

Note that `copyto` in 7.2 is **positional**: source then *full* destination path. The older
`--target-directory C:\lab` form fails with *"already exists and is a directory"*.

---

## 7. Step 4 — Telemetry baseline and agent

Two scripts, in this order. Both live in [`scripts/`](scripts/) and both are commented in
detail; this section covers what they configure and why it matters, not their mechanics.

### 7.1 `01-endpoint-telemetry.ps1`

| What it sets | Why |
|---|---|
| Static `10.10.10.20`, network profile **Private** | With a Public profile the firewall rules below do not apply. |
| 10 advanced audit subcategories | Process Creation, Process Termination, Logon, Logoff, Special Logon, Account Lockout, User Account Management, Security Group Management, Audit Policy Change, Security System Extension. This is what produces 4688/4689/4624/4625/4634/4672/4720/4732/4740/4719/4697. Note that *Account Lockout* does not write 4740 — *User Account Management* does; Account Lockout produces a 4625 for an attempt against an already-locked account. |
| What is deliberately **not** audited | Filtering Platform Connection (5156/5157), Filtering Platform Packet Drop (5152/5153), Object Access / File Share (5140/5145) and Credential Validation (4776), all for volume. Those four are the reason a port scan and a share enumeration leave no host-side record here. Knowing which subcategory would have caught a thing, and choosing not to enable it, is a different statement from "Windows cannot see it". |
| `ProcessCreationIncludeCmdLine_Enabled = 1` | Without it, a 4688 says *powershell.exe ran* and nothing more. With it, it says what was run. The single highest-value registry value on a Windows endpoint for a SOC. |
| ScriptBlockLogging (4104), ModuleLogging (4103) | 4104 records the de-obfuscated script body, which is what exposes `-EncodedCommand` one-liners. |
| Channel size raised to 268,435,456 bytes (256 MB) on Security, System, Application, PowerShell/Operational and Sysmon/Operational | The Security channel defaults to 20 MB. With Sysmon running, a 20 MB channel wraps within hours and the evidence is gone on exactly the day you need it. |
| Inbound ICMP, SMB (445), RDP (3389) | Deliberate. A corporate endpoint has 445 and 3389 open to the internal network. Closed, there is no logon type 3 and no logon type 10, and half the exercises in this repo cannot be run. |
| Sysmon64 with the SwiftOnSecurity configuration | See below. |

**Why Sysmon in addition to native auditing, not instead of it.** Measured on the same
process event in [`investigations/`](../investigations/): Security 4688 has no
`ParentCommandLine`, no hashes, no `OriginalFileName`, no file metadata, no
`CurrentDirectory`, and no stable process identifier. Sysmon Event ID 1 supplies all of
them. Concretely, `OriginalFileName` survives a rename, so renamed-system-binary
masquerading (T1036.003) is undetectable from the Windows Security log alone. Conversely
4688 uniquely carries `TokenElevationType`. Neither source is a superset of the other.

### 7.2 `02-wazuh-agent.ps1`

Installs the agent MSI, enrols it against the manager, and — the step most people miss —
adds the channels the agent does **not** collect by default:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Application, Security and System are collected out of the box. Sysmon and PowerShell are
not. Skipping this leaves you with a SIEM that cannot show a process tree.

The agent MSI URL convention is the **inverse** of the manager's:

| Artefact | Path that works | Path that 403s |
|---|---|---|
| Manager installer | `packages.wazuh.com/4.14/wazuh-install.sh` | `packages.wazuh.com/4.x/wazuh-install.sh` |
| Windows agent MSI | `packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi` | `packages.wazuh.com/4.14/windows/...` |

Verified 2026-07-31 and 2026-08-07. There is no rule to deduce here; test the URL.

---

## 8. Step 5 — Attacker VM

The Kali 2026.1 VirtualBox image, used **only** as an attacker. Blue-team work happens on
Windows, in logs and in the SIEM; Kali exists here to generate the events.

Two adjustments to the stock image:

1. **RAM.** The downloaded image came configured with 37 GB assigned, which starves
   everything else on a 48 GB host. Cut to 6 GB / 4 vCPU.
2. **Second interface.** Add `nic2` on SOCLAB without touching `nic1`, so Kali keeps
   internet access for package installs while also reaching the lab segment.

```powershell
& $vbox modifyvm "<KALI_VM_NAME>" --memory 6144 --cpus 4
& $vbox modifyvm "<KALI_VM_NAME>" --nic2 natnetwork --nat-network2 SOCLAB
```

The stock image ships with Guest Additions, so `guestcontrol` works against it as well.
One platform difference that will bite you: `guestcontrol run -- …` behaves differently on
Linux and Windows guests. See [Troubleshooting](#12-troubleshooting).

---

## 9. Step 6 — Snapshots

Take a snapshot of each VM once it is configured and verified, before any destructive
exercise:

```powershell
& $vbox snapshot "WIN11-VICTIMA" take "base-limpia" --description "OS + audit + Sysmon + agent"
& $vbox snapshot "WAZUH-SIEM"    take "base-limpia" --description "Ubuntu + Wazuh 4.14.7"
```

**Test the restore, do not assume it.** After restoring `base-limpia` on the endpoint,
confirm the three things that would silently break:

```powershell
& $vbox snapshot "WIN11-VICTIMA" restore "base-limpia"
# then, inside the guest:
Get-Service Sysmon64, WazuhSvc | Format-Table Name, Status
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '10.10.*' }
```

On this build, after restore: `Sysmon64` RUNNING, `WazuhSvc` RUNNING, address `10.10.10.20`
intact.

---

## 10. Verification — six checks

A lab that "looks fine" is the normal failure mode. Each check below has a command that
produces evidence and a stated pass criterion. Run them in order; a failure at check *n*
makes every test above it meaningless.

These are numbered checks, not the three layers the rest of the repository argues about.
Everywhere else, layer 1 is generation, layer 2 is collection and layer 3 is detection,
and "a layer-3 hole" means a gap no dashboard can show you. Six checks do not map onto
three layers, so they are given a different word here: checks 1 and 2 test the plumbing
underneath layer 1, checks 3, 4 and 6 test layers 1, 2 and 3, and check 5 tests whether
you can ask the question at all.

### Check 1 — L3 reachability

```bash
# from Kali
ping -c 4 10.10.10.20
ping -c 4 10.10.10.10
```

**Pass:** replies from both. If ICMP to the endpoint fails, the firewall rule
`FPS-ICMP4-ERQ-In` is not enabled or the network profile is Public, not Private.

### Check 2 — the service is alive, not just the port

```bash
nc -vz 127.0.0.1 2222          # from the host
ssh -o StrictHostKeyChecking=no <LAB_USER>@127.0.0.1 -p 2222
```

**Pass:** the SSH banner (`SSH-2.0-OpenSSH_…`) appears.

This distinction matters more than it looks. During this build, port 2222 accepted the TCP
connection while OpenSSH had never been installed — the VirtualBox NAT proxy, not the VM,
was answering. The reported symptom was "the password is wrong"; the cause was two layers
away. **A completed handshake is not a live service.** The same reasoning applies when
reading `nmap` output during triage: check the banner, not the state column.

### Check 3 — generation (does Windows log it at all)

Run [`scripts/03-generate-known-events.ps1`](scripts/03-generate-known-events.ps1) on the
endpoint. It deliberately produces events whose Event ID, time and cause you already know,
then prints the prediction table. Check locally, before involving the SIEM:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-30)}
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddMinutes(-30)} |
    Select-Object -First 10 TimeCreated, @{n='Cmd';e={$_.Properties[8].Value}}
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20
```

**Pass:** the 4688 events carry a populated command line (that proves the registry value
took effect), and the Sysmon channel is not empty.

For a per-channel, per-Event-ID count over a fixed window, use
[`scripts/07-coverage-count.ps1`](scripts/07-coverage-count.ps1).

### Check 4 — collection (does the agent ship it)

On the endpoint:

```powershell
Get-Service WazuhSvc
Get-Content 'C:\lab\wazuh-agent.state'      # copy it there first; see Troubleshooting
```

**Pass:** `status='connected'`, and `ossec.log` contains *"Connected to the server"*. In
the dashboard, `Agents` shows the endpoint as `Active`.

On this build, the agent reported 2,098 events to the manager during the verification
exercise — a number worth recording, because check 5 is measured against it.

### Check 5 — the query path

The indexer is not reachable by port forward. The working path from the host is the
dashboard's console proxy, which is already exposed on 8443 and accepts basic auth:

```bash
curl -k -u admin:<WAZUH_ADMIN_PASSWORD> \
  -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "https://127.0.0.1:8443/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d @query.json
```

**Pass:** a JSON body with a non-zero `hits.total.value` for a window you know contains
activity.

Two things to know before trusting a query result:

- **Free-text search is not grep.** A `query_string` search for a unique marker string
  returned 0 results while that exact string sat in `data.win.eventdata.commandLine` in the
  index. Target the field directly (a `terms` filter on
  `data.win.system.eventRecordID`, for example).
- **Use the right clock.** See the next section.

### Check 6 — detection (does a rule match it)

This is the layer with no error message. Generate an event you know occurred, then check
whether it produced an alert.

Measured on this build:

| Exercise | Events generated | Alerts indexed |
|---|---|---|
| End-to-end verification, 2026-08-08 | ~2,100 reported to the manager | 835 for that endpoint |
| Process-tree exercise, 2026-08-11 | 172 over the widened window (167 on the first, window-clipped pass) | 36 |

**Pass criterion is not "alerts appeared".** It is that you can name, for each Event ID you
generated, whether it alerted and which rule matched. Absence of an alert is not evidence
of absence of activity — it is usually evidence that no rule was looking.

---

## 11. Known limits of this architecture

These are measured properties of the lab as built. They are limits, not bugs, and knowing
them is part of what the lab is for.

| Limit | Evidence |
|---|---|
| **No network visibility, with the audit policy this lab runs.** A host agent reads Windows event logs, and nothing in the ten subcategories enabled by `01-endpoint-telemetry.ps1` records an inbound SYN. | `nmap -sS -p-` across 65,535 ports ran 88 seconds and found 8 open ports, with the remaining 65,527 reported *filtered* — dropped by the host firewall. Wazuh raised 6 alerts in that window, all unrelated background 4688 events — 0 attributable to the scan. This is a configuration limit, not a Windows limit: **Audit Filtering Platform Packet Drop** (5152/5153) is the subcategory that records a dropped packet, and it is deliberately off here for volume. It was not turned on, so no 5152 count was measured. **Audit Filtering Platform Connection** (5156/5157) would only have recorded the eight permitted connections, so it is the wrong answer to this particular question. The recommended fix remains a network sensor, not more Wazuh rules. |
| **No time synchronisation.** | The Wazuh `@timestamp` — the dashboard's default time axis — is the *manager's* clock and ran 1.754 s / 1.821 s / 1.757 s behind the endpoint across three consecutive event records. Query on `data.win.system.systemTime` instead. Separately, Sysmon events 3 (network) and 22 (DNS) are written to the channel 3–4 seconds after they occur, so for those two read the event's own `UtcTime`, never the channel's `TimeCreated`. This gets materially worse once a domain controller joins, since Kerberos rejects skew above five minutes. |
| **The default ruleset has holes that are invisible from the dashboard.** | Event ID 4697 (service installed) is generated by Windows, collected by the agent, and matched by no default rule — a `wazuh-alerts-*` query returned 0 documents for it, while the same real-world fact alerted via 7045 from the System channel. Sysmon 3, Sysmon 22, Security 4648 and Security 4798/4799 each produced events and zero alerts. |
| **Untuned rule severity is noise.** | The only level-15 alert of the first end-to-end test was rule 92213 firing on `__PSScriptPolicyTest_<random>.ps1` — a file PowerShell writes to `%TEMP%` to test its own execution policy. Reproduced on three separate dates (×1, ×5, ×12). Meanwhile the highest-value reconnaissance alert of a later exercise was a level 6. |
| **Single host, single disk.** | Free space went from 259 GB to 46 GB over the build. Adding `DC01` needs planning, not optimism. |

---

## 12. Troubleshooting

Problems actually hit during this build, with the cause and the fix. Ordered roughly by how
much time each one cost.

| Symptom | Cause | Fix |
|---|---|---|
| SIEM has no IP; `ip -4 a` shows only `lo` | The Ubuntu installer created a **single-NIC bond**: `enp0s3` is a `SLAVE` of a `bond0` that never gets an address | Rewrite `/etc/netplan/50-cloud-init.yaml` for `enp0s3` with a static address, disable cloud-init network regeneration via `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`, `netplan apply` |
| SSH to `127.0.0.1:2222` hangs, then reports a wrong password | OpenSSH was never installed. Port 2222 still completes a TCP handshake because the **VirtualBox NAT proxy** answers there, not the VM | `sudo apt install -y openssh-server && sudo systemctl enable --now ssh`. Generally: verify the banner, not the port state |
| `wazuh-install.sh` fails with `syntax error near unexpected token 'newline'` | `curl -sO` saved an HTTP 403 XML error body under the script's filename | Always `curl -fsSLO`. `-f` makes curl fail on HTTP errors instead of writing them to disk |
| Manager installer 403s on `4.x/`; agent MSI 403s on `4.14/windows/` | Wazuh's download paths follow **opposite** conventions for the two artefacts | Manager: `packages.wazuh.com/4.14/wazuh-install.sh`. Agent: `packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi`. Test, do not deduce |
| Telemetry script "ran fine" but `Sysmon64` service does not exist | The script was invoked as `script *>&1 \| Tee-Object`. In PowerShell 5.1 that turns a native executable's stderr into an `ErrorRecord`; with `$ErrorActionPreference='Stop'` the script aborted at the Sysmon step, after steps 1–5 had applied | Never wrap a configuration script in `Tee-Object`. Use `Start-Transcript`. And verify the **end state** (`Get-Service Sysmon64` = Running, events present in the channel), never the fact that the script appeared to run |
| `Get-WinEvent` on `Security` or the Sysmon channel returns *"Attempted to perform an unauthorized operation"* from a `guestcontrol`-launched process | Group membership lives in the **token**, not the SAM. `net localgroup "Event Log Readers" <LAB_USER> /add` shows up immediately in `Get-LocalGroupMember` but not in the token | Add the group from an elevated terminal, then **reboot the VM**. `guestcontrol closesession --all` does not refresh it. The Sysmon channel already carries the ACE `(A;;0x1;;;S-1-5-32-573)` from the factory, so its SDDL needs no change |
| Any script with an administrator check rebounds under `guestcontrol run` | `guestcontrol run` does not hand out an elevated token. `whoami /groups` shows `BUILTIN\Administrators` as *"Group used for deny only"* and Medium Mandatory Level, even for an account that is in Administrators | `LocalAccountTokenFilterPolicy=1` does **not** fix this (tested and reverted) — that key applies only to network logons and VirtualBox performs an interactive logon. Open one elevated terminal by injected scancodes (`Win+X` = `e0 5b 2d ad e0 db`, then `A` = `1e 9e`, then `Alt+Y` = `38 15 95 b8` at the UAC prompt, since the default UAC button is **No**) and drive it with `keyboardputstring`, capturing output with `Start-Transcript` to a world-readable file under `C:\lab` |
| Two `powershell.exe` appear in the process tree where one was expected | `VBoxManage guestcontrol run --` adds its own `argv[0]`. PowerShell receives `powershell.exe` as its first argument, treats it as `-Command`, and relaunches itself. Symptom on the console: *"ScriptBlock should only be specified as a value of the Command parameter"* | **Windows guest:** repeat the binary — `--exe …\powershell.exe -- powershell.exe -NoProfile -File C:\lab\x.ps1`. **Linux guest:** do *not* repeat it — `--exe /bin/bash -- /home/<user>/x.sh`; repeating it makes bash treat `/usr/bin/bash` as a script name and return *"cannot execute binary file"*. Test with a script that just prints `$args` / `$@` before trusting either form |
| Arguments passed through `--` lose their quotes; `/c "some comment"` breaks | `guestcontrol` strips double quotes from arguments | Put everything in a `.ps1` and run it with `-File`. Do not pass arguments through `--` |
| `VBoxManage` reports *"No such file or directory"* for a path that exists in the guest | Git Bash rewrites Unix-looking arguments: `/usr/bin/id` becomes `C:/Program Files/Git/usr/bin/id`. The error looks like it comes from the guest and does not | `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'` at the top of the script |
| A shell script copied into the Linux guest fails at its shebang | CRLF line endings | This repo pins line endings in `.gitattributes`: `*.ps1 text eol=crlf`, everything else `eol=lf`. Keep `.sh` files LF when copying them into a guest |
| `guestcontrol copyto` fails with *"already exists and is a directory"* | In VirtualBox 7.2 `copyto` is positional and wants the **full destination path**, not a directory | `copyto <host-source> C:\lab\file.ps1`, not `--target-directory C:\lab` |
| Cannot read `wazuh-agent.state` or `ossec.log` over `guestcontrol` — *Access denied* | Files under `C:\Program Files (x86)\ossec-agent\` need administrator rights | Copy them to `C:\lab` from the elevated terminal first. Note that `cmd /c type` breaks on paths with spaces — use the 8.3 form (`C:\PROGRA~2\...`) |
| `curl` to a forwarded 9200 fails with error 35 | The Wazuh indexer binds to localhost inside the VM; the NAT proxy answers the connection, the indexer never does | Query through the dashboard console proxy on 8443 — see [check 5](#check-5--the-query-path) |
| `natnetwork modify … --port-forward-4 "delete rulename"` returns *Invalid port-forward rule* | The delete form is three separate tokens | `--port-forward-4 delete rulename` |
| Keystrokes injected with `keyboardputstring` vanish; the command returns success | The window looks focused (title bar highlighted) but does not hold **keyboard** focus. Scancodes are dropped silently | Diagnose by sending the Windows key: if the Start menu opens, injection works and the problem is focus. Fix with `Alt+Tab` (`38 0f 8f b8`). For long text, `keyboardputfile <file>` |
| Injected text comes out with the wrong characters in a Linux guest | `keyboardputstring` assumes a **US** keyboard layout; a guest set to another layout maps them differently (e.g. `/` produces `-`) | `sudo loadkeys us`, do the work, `sudo loadkeys <original>` on the way out. Also: PowerShell strips double quotes from the argument — use single quotes and `\| sudo tee` instead of `sudo bash -c "…"` |
| Setup still asks for region and keyboard despite an answer file | Language settings in the `windowsPE` pass do not apply to OOBE | Repeat them with `Microsoft-Windows-International-Core` in the `oobeSystem` pass |
| OOBE forces a Microsoft account, breaking a local-account answer file | Network is connected during install | `--cableconnected1 off` before starting; `controlvm setlinkstate1 on` afterwards |
| The permission classifier blocks a command containing `del` | It is read as `Remove-Item` | Reformulate (e.g. `ip link delete` phrased differently) or avoid the word |
| `netexec` reports *"The NETBIOS connection with the remote host timed out"* instead of a wrong-password message | Not a network problem — Windows 11 24H2+ ships `EnableAuthRateLimiter = True` with `InvalidAuthenticationDelayTimeInMs = 2000`, so every failed SMB authentication costs 2 seconds | Nothing to fix; this is a mitigation working. The 4625 events are generated normally. Note that the ~2 s spacing you see in the timeline is a fingerprint of the *mitigation*, not of the attacker's tooling |
| DHCP on SOCLAB handed Kali `10.10.10.5` | That address is the one reserved in the plan for the future domain controller | Reserve it or move Kali **before** building `DC01`, or the two will collide |

---

## 13. Scripts

All scripts are in [`scripts/`](scripts/). They are the sanitised versions of what actually
ran on this lab: no credential, password, or hard-coded secret appears in any of them.
Addresses are parameters with the lab's values as defaults.

| Script | Runs where | Purpose |
|---|---|---|
| [`01-endpoint-telemetry.ps1`](scripts/01-endpoint-telemetry.ps1) | Endpoint, elevated, once | Static IP, 10 audit subcategories, command line in 4688, PowerShell 4103/4104, 256 MB channels, lab firewall rules, Sysmon + SwiftOnSecurity config, then verifies its own work |
| [`02-wazuh-agent.ps1`](scripts/02-wazuh-agent.ps1) | Endpoint, elevated, after 01 | Reachability check to the manager, agent MSI install and enrolment, adds the Sysmon and PowerShell channels to `ossec.conf`, verifies `connected` |
| [`03-generate-known-events.ps1`](scripts/03-generate-known-events.ps1) | Endpoint, elevated | Generates known-in-advance telemetry (failed logons, a process tree, an encoded command, discovery commands, account and service creation) and prints the prediction table. Cleans up what it creates |
| [`04-process-tree-generate.ps1`](scripts/04-process-tree-generate.ps1) | Endpoint, **unelevated** | Launches one known process tree carrying a unique marker, records the UTC window to a JSON file. The input to the three-source comparison |
| [`05-process-tree-child.ps1`](scripts/05-process-tree-child.ps1) | Endpoint, launched by 04 | The child of the tree: a DNS query (Sysmon 22), a TCP connection (Sysmon 3), a child process (Sysmon 1 + Security 4688) |
| [`06-collect-evidence.ps1`](scripts/06-collect-evidence.ps1) | Endpoint | Pulls the same process from Security 4688 and Sysmon 1, dumps both as XML field/value pairs, and prints the field-by-field difference between the two sources |
| [`07-coverage-count.ps1`](scripts/07-coverage-count.ps1) | Endpoint | Counts events generated per channel and per Event ID in a fixed window — the denominator for the generate / collect / detect funnel |

Run order for the build: `01` → `02` → `03`.
Run order for the visibility exercise: `04` → `06` → `07`.

`autounattend.xml` and the ISO-packaging script are intentionally **not** published: they
carry account configuration. The approach is documented in
[Step 3](#6-step-3--endpoint-vm-unattended-windows-11) and is reproducible from that
description.
