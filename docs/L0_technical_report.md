# NetSpectra - L0: Lab & Attack Simulation
## Detailed Technical Documentation

---

## Overview

L0 is the foundation layer of NetSpectra. Before any detection can be written, before any
alert can fire, before any compliance report can be generated - there must be a controlled,
reproducible environment that generates real attack traffic. L0 establishes exactly that:
a fully isolated lab network with a dedicated attacker machine, multiple vulnerable targets,
and a complete attack simulation suite covering network-layer and web-layer threats.

Every decision in L0 was made with one goal in mind: producing authentic, MITRE ATT&CK-mapped
attack traffic that will serve as the ground truth for detection engineering in L3.

---

## 1. Lab Infrastructure

### 1.1 Platform Choice: VirtualBox over Docker

The initial design considered Docker for all lab components. After evaluation, VirtualBox
was chosen for the attacker/victim machines. The reasoning:

| Criterion | Docker | VirtualBox |
|---|---|---|
| OS-level simulation | Shares host kernel | Full OS kernel per VM |
| SSH server fidelity | Limited, non-standard | Full OpenSSH stack |
| Network stack | NAT by default, complex bridging | Native bridging, Host-only adapter |
| Metasploitable compatibility | Not officially supported | Full support, standard image |
| Realism of generated traffic | Reduced | Full production-equivalent |

Metasploitable2 and Windows 11 are full operating systems with complete service stacks
(OpenSSH, FTP, Telnet, HTTP). Running them inside Docker would strip away the exact
behaviors that make them valuable as targets. VirtualBox preserves full fidelity.

**DVWA is the exception** - it is a stateless PHP web application with no OS-level
dependencies. Docker is the correct choice here: a single `docker run` command
provisions the full web stack (Apache + PHP + MySQL) in under 60 seconds, versus
hours of manual OS setup. This is the standard industry approach.

### 1.2 Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              VirtualBox Host-Only Network                    │
│                   192.168.56.0/24                           │
│                                                             │
│  ┌─────────────────┐    ┌──────────────────────────────┐   │
│  │  Kali Attacker  │    │   Metasploitable Target      │   │
│  │  eth1:          │───▶│   eth0: 192.168.56.103       │   │
│  │  192.168.56.107 │    │   24 open services           │   │
│  │                 │    └──────────────────────────────┘   │
│  │  (also eth0:    │    ┌──────────────────────────────┐   │
│  │   10.0.2.15     │───▶│   Windows 11 Victim          │   │
│  │   NAT/internet) │    │   eth0: 192.168.56.104       │   │
│  │                 │    └──────────────────────────────┘   │
│  │  Docker:        │                                        │
│  │  DVWA on        │                                        │
│  │  127.0.0.1:80   │                                        │
│  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
                    ▲
                    │ NO INTERNET ACCESS
                    │ (Host-only = isolated)
```

**Why Host-only Adapter?**

Host-only creates a private virtual network that exists only between the host machine
and the VMs. There is no routing to the external internet. This is critical for two reasons:

1. **Legal:** Tools like nmap, hydra, and medusa are attack tools. Running them
   against any external network without explicit written authorization is illegal
   under computer fraud laws in most jurisdictions. Host-only ensures they can
   never reach the internet accidentally.

2. **Reproducibility:** A closed network produces consistent, noise-free traffic.
   There is no external background traffic to confuse Zeek logs or Sigma detections.
   Every packet in the PCAP is intentional.

### 1.3 Kali Network Configuration

Kali requires dual-interface setup: one for internet access (package installation,
tool updates) and one for the lab network (attack traffic, target communication).

```
Interface   IP              Role
eth0        10.0.2.15/24    NAT — internet access (apt, pip, docker pull)
eth1        192.168.56.107  Host-only — lab network (attack traffic)
lo          127.0.0.1       Loopback — local services (DVWA, HTTP C2 listener)
```

**Static route configuration (persistent across reboots):**
```bash
sudo nmcli connection modify "Wired connection 1" +ipv4.routes "192.168.56.0/24"
sudo nmcli connection up "Wired connection 1"
```

Without this route, Linux would attempt to send `192.168.56.x` traffic via `eth0` (NAT),
which has no route to that network. The static route forces all lab traffic through `eth1`.

**DNS configuration:**
```bash
sudo nmcli connection add type ethernet ifname eth0 \
  con-name "NAT-eth0" ipv4.method auto ipv4.dns "8.8.8.8 8.8.4.4"
```

NetworkManager was overwriting `/etc/resolv.conf` with an empty DNS server, breaking
name resolution. Binding Google DNS directly to the NetworkManager connection profile
ensures it persists across network restarts.

### 1.4 Component Inventory

**NetSpectra-Kali-Attacker**
- OS: Kali Linux (rolling release)
- Python: 3.13.12
- Git: 2.51.0
- Tools: nmap 7.98, medusa 2.3, hydra, paramiko, requests
- Role: All attack simulations originate from this machine

**NetSpectra-Metasploitable-Victim** — `192.168.56.103`
- OS: Ubuntu Linux 2.6.24-16-server (intentionally outdated)
- Open services (24 total): FTP (21), SSH (22), Telnet (23), SMTP (25),
  HTTP (80), RPC (111), NetBIOS (139/445), PostgreSQL (5432),
  VNC (5900), IRC (6667), and others
- Credentials: `msfadmin / msfadmin`
- Role: Primary network-layer attack target (brute force, post-exploitation)

**NetSpectra-Win11-Victim** — `192.168.56.104`
- OS: Windows 11
- Role: Windows-specific attack surface for future detection scenarios

**DVWA (Docker container on Kali)**
- Image: `vulnerables/web-dvwa:latest`
- Container: `netspectra-dvwa`
- Port mapping: `0.0.0.0:80 → 80/tcp`
- Credentials: `admin / password`
- Vulnerabilities: SQL Injection, Blind SQL Injection, XSS (DOM/Reflected/Stored),
  CSRF, File Inclusion, File Upload, Command Injection, Brute Force
- Role: Web-layer attack target (HTTP detection traffic for L3)

---

## 2. Reconnaissance - MITRE T1046

### 2.1 Tool: nmap 7.98

```bash
nmap -sV 192.168.56.103
```

**Flags explained:**
- `-sV`: Service version detection — nmap sends protocol-specific probes to each
  open port and attempts to identify the exact service and version running.
  This is more aggressive than a simple port scan and generates richer traffic.

**Result: 24 open ports**

| Port | Protocol | Service | Version |
|---|---|---|---|
| 21/tcp | FTP | vsftpd | 2.3.4 |
| 22/tcp | SSH | OpenSSH | 4.7p1 |
| 23/tcp | Telnet | Linux telnetd | - |
| 25/tcp | SMTP | Postfix smtpd | - |
| 80/tcp | HTTP | Apache httpd | 2.2.8 |
| 111/tcp | RPC | rpcbind | 2 |
| 139/tcp | NetBIOS | Samba smbd | 3.X-4.X |
| 445/tcp | SMB | Samba smbd | 3.X-4.X |
| 512/tcp | exec | netkit-rsh rexecd | - |
| 513/tcp | login | OpenBSD rlogind | - |
| 514/tcp | shell | Netkit rshd | - |
| 1099/tcp | RMI | GNU Classpath rmiregistry | - |
| 1524/tcp | bindshell | Metasploitable root shell | - |
| 2049/tcp | NFS | - | - |
| 2121/tcp | FTP | ProFTPD | 1.3.1 |
| 3306/tcp | MySQL | MySQL | 5.0.51a |
| 5432/tcp | PostgreSQL | PostgreSQL | 8.3.0-8.3.7 |
| 5900/tcp | VNC | VNC | protocol 3.3 |
| 6000/tcp | X11 | - | - |
| 6667/tcp | IRC | UnrealIRCd | - |
| 8009/tcp | AJP | Apache Jserv | 1.3 |
| 8180/tcp | HTTP | Apache Tomcat/Coyote | 1.1 |

**Why this matters for L3:**
When Zeek captures this scan, `conn.log` will show `192.168.56.107` connecting to
`192.168.56.103` on 24 different destination ports within a few seconds. This is the
exact pattern our T1046 Sigma rule will detect: high port count from single source
in a short time window.

**MITRE mapping:** T1046 - Network Service Scanning
**Evidence:** `screenshots/L0/04_nmap_recon_results.png`

---

## 3. Brute Force Attack - MITRE T1110

### 3.1 Tool selection: medusa over hydra

Initial attempt used `hydra`:
```bash
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt 192.168.56.103 ssh
```

**Result:** `[ERROR] could not connect to ssh://192.168.56.103:22 - libssh error`

Metasploitable2 runs OpenSSH 4.7p1 (2008). Modern hydra uses libssh which dropped
support for legacy SSH key exchange algorithms required by this version. This is a
real-world compatibility issue: old infrastructure does not always work with new tools.

**Resolution:** switched to medusa 2.3, which implements its own SSH client and
supports legacy algorithms:

```bash
# First, gunzip the wordlist (ships compressed in Kali)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Run brute force
medusa -h 192.168.56.103 -u msfadmin -P /usr/share/wordlists/rockyou.txt -M ssh
```

**Flags explained:**
- `-h`: target host
- `-u`: single username (we know the username from service enumeration)
- `-P`: password wordlist (rockyou.txt — 14.3 million real passwords from data breaches)
- `-M ssh`: module to use (medusa supports 20+ protocols)

**Result:**
```
ACCOUNT FOUND: [ssh] Host: 192.168.56.103 User: msfadmin Password: msfadmin [SUCCESS]
```

**rockyou.txt context:** This wordlist was extracted from a 2009 RockYou data breach
that exposed 32 million plaintext passwords. It is the industry-standard baseline
for password auditing because it reflects real human password choices.

**Post-brute-force access verification:**
```bash
ssh msfadmin@192.168.56.103
whoami   # → msfadmin
id       # → uid=1000(msfadmin) gid=1000(msfadmin) groups=1000(msfadmin)...
```

**Why this matters for L3:**
Zeek's `ssh.log` will record: multiple failed authentication attempts from
`192.168.56.107` to `192.168.56.103:22`, followed by one successful authentication.
This is the exact pattern our T1110 Sigma rule will detect.

**MITRE mapping:** T1110 - Brute Force / T1110.001 — Password Guessing
**Evidence:** `screenshots/L0/05_medusa_and_ssh_success.png`

---

## 4. Attack Simulation - Custom C2 Scripts

### 4.1 Design rationale: two separate scenarios

Two C2 scripts were built, each targeting a different MITRE technique:

| Script | Protocol | MITRE | Detection signal |
|---|---|---|---|
| `netspectra_c2_ssh.py` | SSH (port 22) | T1021 — Remote Services | Periodic authenticated SSH sessions |
| `netspectra_c2_beacon.py` + `netspectra_c2_listener.py` | HTTP (port 8080) | T1071.001 - Web Protocols | Periodic HTTP GET with jitter |

This is intentional: a single C2 scenario would only validate one detection. Having
two distinct protocols means L3 will have two separate Sigma rules, two separate
true-positive PCAPs, and two separate detection validation tests.

### 4.2 SSH-based C2 - `netspectra_c2_ssh.py`

**Location:** `lab/attack_simulation/ssh_post_exploitation/netspectra_c2_ssh.py`

**Behavior:**
- Opens a new SSH session to `192.168.56.103` every `30 ± 10` seconds (jitter)
- Each session executes `whoami` and closes (lightweight check-in)
- Every 5th check-in executes a deeper reconnaissance sequence:
  `id`, `hostname`, `uname -a`, `ifconfig`
- All activity logged to console with check-in counter

**Key design decisions:**

*Jitter:* `sleep_time = 30 + random.uniform(-10, 10)` - Real C2 frameworks
(Cobalt Strike, Metasploit, Sliver) always add jitter to beacon intervals.
A perfectly regular interval (every 30.000 seconds) is trivially detectable
by simple statistical analysis. Jitter mimics human-like irregularity while
maintaining a detectable mean interval - which our detection engine will
identify through statistical analysis of inter-connection times.

*Periodic deep recon:* Real operators do not run reconnaissance on every
check-in (generates too much noise). They check in frequently but only
execute commands occasionally. The 1-in-5 pattern reflects this.

**MITRE mapping:** T1021 - Remote Services, T1059 - Command and Scripting Interpreter

### 4.3 HTTP-based C2 - Listener + Beacon

**Location:** `lab/attack_simulation/http_c2_beacon/`

**Why HTTP?**
Most enterprise environments allow outbound HTTP/HTTPS traffic. Firewalls and
proxies rarely block it. Real-world C2 frameworks (Cobalt Strike's HTTP listener,
Covenant, Havoc) use HTTP/HTTPS as their primary communication channel precisely
because it blends into normal web traffic. This is what MITRE T1071.001 describes.

**Listener — `netspectra_c2_listener.py`:**

```
[*] NetSpectra C2 Listener started on port 8080
[*] Log file: c2_checkins.log
[2026-07-21T22:47:37] Check-in from 127.0.0.1 → /beacon (UA: python-requests/2.32.5)
[2026-07-21T22:48:15] Check-in from 127.0.0.1 → /beacon (UA: python-requests/2.32.5)
```

Logs every check-in with: ISO timestamp, client IP, endpoint path, User-Agent.
User-Agent is logged because real C2 detection often relies on anomalous
User-Agent strings (e.g. a corporate workstation sending "python-requests/2.32.5"
is immediately suspicious).

**Beacon - `netspectra_c2_beacon.py`:**

```
[*] NetSpectra Beacon started. Target: http://127.0.0.1:8080/beacon
[+] Check-in sent. Status: 200
[*] Next check-in in 38.4 seconds...
[+] Check-in sent. Status: 200
[*] Next check-in in 26.1 seconds...
```

Sends HTTP GET to `/beacon` every `30 ± 10` seconds. Writes its own log
(`beacon_sent.log`) for ground-truth comparison with Zeek's `http.log` in L3.

**Ground truth purpose:** In L3, we will compare:
- `beacon_sent.log`: "beacon sent at T=0, T=38.4, T=64.5..."
- Zeek `http.log`: "HTTP GET received at T=0.001, T=38.401, T=64.502..."

This proves our detection captures every beacon with near-zero latency.

**MITRE mapping:** T1071.001 - Application Layer Protocol: Web Protocols

---

## 5. DVWA - Web Attack Surface

### 5.1 Why DVWA is necessary

Metasploitable provides network-service attack surface: SSH, FTP, Telnet — these
generate `conn.log` and `ssh.log` entries in Zeek. But NetSpectra's detection suite
also targets web-layer attacks (T1190 — Exploit Public-Facing Application,
T1110.001 — Web Brute Force). These require HTTP traffic, which means a web target.

DVWA provides a complete web vulnerability laboratory:

| DVWA Module | Attack Type | MITRE Technique | L3 Detection |
|---|---|---|---|
| Brute Force | HTTP login brute force | T1110.001 | HTTP POST flood to /login |
| SQL Injection | Database extraction | T1190 | Malicious SQL in HTTP params |
| Command Injection | OS command execution | T1059 | Shell metacharacters in HTTP |
| XSS (Reflected) | Script injection | T1059.007 | Script tags in HTTP params |
| File Upload | Webshell upload | T1505.003 | Executable upload via HTTP |

### 5.2 Deployment

```bash
# Pull the official DVWA image
docker pull vulnerables/web-dvwa

# Run as named container, map port 80
docker run -d \
  --name netspectra-dvwa \
  -p 80:80 \
  vulnerables/web-dvwa

# Verify
docker ps
# → netspectra-dvwa   Up X seconds   0.0.0.0:80→80/tcp
```

**Database initialization:**
Navigate to `http://127.0.0.1/setup.php` → "Create / Reset Database"
This initializes the MySQL schema required for SQL Injection modules.

**Access:**
```
URL:      http://127.0.0.1/login.php
Username: admin
Password: password
```

**MITRE mapping:** T1190 - Exploit Public-Facing Application (target setup)
**Evidence:** `screenshots/L0/08_dvwa_dashboard.png`

---

## 6. Evidence & Verification

### 6.1 Screenshot inventory

| File | Content | Verifies |
|---|---|---|
| `01_kali_network_interfaces.png` | `ip a` output — eth0 + eth1 | Dual-interface setup |
| `02_metasploitable_ifconfig.png` | `/sbin/ifconfig` — 192.168.56.103 | Target reachability |
| `03_ping_connectivity.png` | `ping -c 4 192.168.56.103` — 0% loss | Network isolation working |
| `04_nmap_recon_results.png` | 24 open ports with versions | T1046 simulation |
| `05_medusa_and_ssh_success.png` | ACCOUNT FOUND + `whoami` | T1110 + T1021 simulation |
| `06_http_c2_beacon_test.png` | Listener + beacon terminals | T1071.001 simulation |
| `07_ssh_c2_test.png` | SSH C2 check-ins | T1021 beacon simulation |
| `08_dvwa_dashboard.png` | DVWA welcome screen | Web target deployment |

### 6.2 Connectivity verification

```
Kali → Metasploitable:  ping 0% loss ✅
Metasploitable → Kali:  ping 0% loss ✅
Kali → Internet (eth0): ping 8.8.8.8 success ✅
Kali → DVWA (local):    HTTP 200 on 127.0.0.1:80 ✅
```

---

## 7. Technical Problems Encountered & Solutions

Real-world infrastructure work always involves unexpected problems.
The following were encountered and resolved during L0:

### Problem 1: hydra incompatible with legacy SSH

**Symptom:** `[ERROR] could not connect to ssh://192.168.56.103:22 - libssh error`
**Root cause:** Metasploitable runs OpenSSH 4.7p1 with deprecated key exchange
algorithms. Modern libssh (used by hydra) dropped support for these.
**Solution:** Switched to medusa 2.3, which uses its own SSH implementation.
**Lesson:** In real engagements, tool compatibility with legacy targets is a
common constraint. A competent security engineer knows multiple tools per protocol.

### Problem 2: Kali Host-only adapter lost after reboot

**Symptom:** `ping 192.168.56.103` → "Destination Host Unreachable"
**Root cause:** VirtualBox had only one adapter (NAT). Host-only adapter
was not configured in VirtualBox settings, so `eth1` never existed.
**Solution:**
1. VirtualBox → Kali Settings → Network → Adapter 2 → Host-only Adapter
2. `sudo nmcli device connect eth1`
3. Static route via nmcli (persistent)
**Lesson:** VM network configuration must be verified at the hypervisor level,
not just the OS level. `ip a` showing no `eth1` = adapter not provisioned in VirtualBox.

### Problem 3: DNS resolution failure

**Symptom:** `apt update` → "Temporary failure resolving 'http.kali.org'"
**Root cause:** NetworkManager was overwriting `/etc/resolv.conf` with empty DNS
on every network restart, because no DNS server was bound to the connection profile.
**Solution:** Bound Google DNS (8.8.8.8, 8.8.4.4) directly to the NetworkManager
connection profile using `nmcli`. This persists across restarts.
**Lesson:** On systems using NetworkManager, never edit `/etc/resolv.conf` directly.
Always configure DNS through nmcli or the connection profile.

### Problem 4: Incorrect routing (lab traffic going via NAT)

**Symptom:** `ping 192.168.56.103` failed, but `ping -I eth1 192.168.56.103` worked
**Root cause:** Linux routing table had no specific route for `192.168.56.0/24`.
Default route sent all traffic via `eth0` (NAT), which has no path to lab network.
**Solution:** `sudo ip route add 192.168.56.0/24 dev eth1` (then made permanent via nmcli)
**Lesson:** When a machine has multiple interfaces, routing must be explicitly configured.
Diagnosing with `-I eth1` flag was the key troubleshooting technique.

---

## 8. L0 → L1 Handoff

L0 has produced the following assets that L1 will consume:

**Attack traffic generators (to be replayed under tcpdump/Zeek in L1):**
- nmap scan → produces port scan traffic (T1046)
- medusa brute force → produces SSH authentication flood (T1110)
- `netspectra_c2_ssh.py` → produces periodic SSH sessions (T1021)
- `netspectra_c2_beacon.py` → produces periodic HTTP GET requests (T1071.001)
- DVWA attack modules → produces web attack HTTP traffic (T1190, T1110.001)

**In L1, each of these will be re-executed while tcpdump captures the traffic.**
The resulting PCAPs will then be analyzed by Zeek to produce structured logs.
These logs become the input for Sigma detection rules in L3.

The chain: `L0 attack → L1 PCAP → L1 Zeek logs → L3 Sigma detection → L4 alert`

---

*Document version: L0-FINAL | Author: Khayal Kocharili | NetSpectra Project*