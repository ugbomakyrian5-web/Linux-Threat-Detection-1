# 🔍 SOC Investigation: Linux Threat Detection 1 – SSH Attacks, Web Exploitation & Process Tree Analysis

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-black?style=flat&logo=tryhackme)](https://tryhackme.com)
[![Path](https://img.shields.io/badge/Path-SOC%20Level%201-blue?style=flat)](https://tryhackme.com/path/outline/soclevel1)
[![Topic](https://img.shields.io/badge/Topic-Linux%20Initial%20Access%20Detection-007ACC?style=flat)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat)]()
[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat)]()
[![Tools](https://img.shields.io/badge/Tools-auth.log%20%7C%20nginx%20logs%20%7C%20auditd%20%7C%20ausearch-blue?style=flat)]()

Linux Initial Access detection investigation covering the three most common real-world attack vectors on Linux systems — SSH brute-force and breach, web application exploitation via command injection, and process tree analysis to trace attack origins. Investigated using `/var/log/auth.log`, Nginx web logs, and auditd runtime telemetry.

**Attack chains uncovered:**
> SSH Brute-Force → Root Breach (91.224.92.79) | Web Command Injection (TryPingMe) → Python Reverse Shell → Auditd Process Tree Reconstruction

---

## 📌 Investigation Summary

| Field | Detail |
|-------|--------|
| **Target Host** | thm-vm (Ubuntu Linux) |
| **Scenario 1** | SSH Initial Access — first login: 2024-10-22, key-based authentication |
| **Scenario 2** | SSH Brute-Force — botnet targeted root, roy, sol, user from multiple IPs |
| **Attacker IP (Root Breach)** | `91.224.92.79` — password brute-force succeeded against root |
| **Scenario 3** | Web exploitation — TryPingMe command injection via `/ping?host=` parameter |
| **Vulnerable File** | `/opt/trypingme/main.py` — flag: `THM{i_am_vulnerable!}` |
| **Reverse Shell** | Python reverse shell to `10.14.105.255:1337` |
| **Evidence Sources** | `/var/log/auth.log`, `/var/log/nginx/access.log`, auditd (`ausearch`) |
| **Outcome** | Full attack chain reconstructed — SSH breach, web exploitation, and reverse shell confirmed via process tree |

---

## 🎯 Key Findings

| # | Finding | Evidence Source |
|---|---------|----------------|
| 1 | First SSH login for ubuntu: `2024-10-22` via public key from `10.9.254.186` | `/var/log/auth.log` |
| 2 | SSH brute-force started `2025-08-21` — botnet targeted root, roy, sol, user | `/var/log/auth.log` |
| 3 | Root account breached — `91.224.92.79` successful password login | `/var/log/auth.log` |
| 4 | Attacker attempted to open `/opt/trypingme/main.py` via command injection | Nginx access.log + auditd |
| 5 | Flag `THM{i_am_vulnerable!}` found inside vulnerable Python web app | `/opt/trypingme/main.py` |
| 6 | `whoami` PPID: `1018` (sh process) — PID of TryPingMe app: `577` | auditd process tree |
| 7 | Python used to open reverse shell to `10.14.105.255:1337` | auditd PROCTITLE |

---

## 🔎 Investigation Walkthrough

### Phase 1 — SSH Log Analysis: First Login & Brute-Force Detection

**Log File**: `/var/log/auth.log`

**Commands used**:
```bash
cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'
cat /var/log/auth.log | grep "Accepted" | grep "root"
```

Authentication log analysis revealed the ubuntu user's first SSH login on `2024-10-22` using **public key authentication** from `10.9.254.186` — a legitimate, secure login method confirming proper initial access controls.

However, from `2025-08-21T16:38` onward, the logs showed a sustained brute-force campaign from multiple IPs targeting four usernames — `root`, `roy`, `sol`, and `user` — across different source addresses including `197.39.195.136`, `193.46.255.33`, `45.88.8.186`, and `80.94.95.112`. This multi-IP, multi-username pattern is characteristic of a coordinated botnet credential stuffing attack.

Filtering for successful root logins confirmed the breach — `91.224.92.79` achieved a successful password login to the root account at `2025-08-21T17:10:08` — granting the attacker full administrative access to the system.

**Key indicators**:
- Multiple `Failed password` events from different IPs across short timeframe — botnet pattern
- `Accepted password` for root from an external, unknown IP — definitive breach confirmation
- Password-based root login is a high-severity finding on any Linux server

#### 📸 Screenshot 1 — `/var/log/auth.log`: First Ubuntu SSH Login — `2024-10-22` via Public Key
<img width="1366" height="728" alt="First SSH Login" src="https://github.com/ugbomakyrian5-web/linux-threat-detection-1/blob/main/screenshots/1_auth_log_first_ssh_login.png" />

*auth.log — Accepted publickey for ubuntu from 10.9.254.186 — first SSH login 2024-10-22 confirmed*

#### 📸 Screenshot 2 — `/var/log/auth.log`: Botnet Brute-Force — root, roy, sol, user Targeted
<img width="1366" height="728" alt="SSH Brute Force Botnet" src="https://github.com/ugbomakyrian5-web/linux-threat-detection-1/blob/main/screenshots/2_auth_log_botnet_brute_force.png" />

*auth.log — Failed password for root, sol, roy, user from multiple IPs — coordinated botnet brute-force confirmed*

#### 📸 Screenshot 3 — `/var/log/auth.log`: Root Breach — `91.224.92.79` Successful Login
<img width="1366" height="728" alt="Root Breach" src="https://github.com/ugbomakyrian5-web/linux-threat-detection-1/blob/main/screenshots/3_auth_log_root_breach.png" />

*auth.log — Accepted password for root from 91.224.92.79 port 51555 — root account compromised*

---

### Phase 2 — Web Application Exploitation: TryPingMe Command Injection

**Log File**: `/var/log/nginx/access.log` + auditd

**Commands used**:
```bash
cat /var/log/nginx/access.log
ausearch -i -x python3
cat /opt/trypingme/main.py
```

Nginx web log analysis revealed the attacker at `10.14.105.255` systematically probing the `/ping` endpoint — first with harmless input (`hello`), then progressively escalating to command injection attempts (`whoami`, `;whoami`, `;ls`). The transition from `500` error responses to `200` success on `;whoami` confirmed the command injection vulnerability.

The attacker then attempted to read the application source code by accessing `/opt/trypingme/main.py` via the injection. Auditd captured the full Python process (`/usr/bin/python3 /opt/trypingme/main.py`) executing the attacker's injected commands.

Inspecting `main.py` directly revealed the vulnerability — `subprocess.check_output(cmd, shell=True)` with no input sanitisation — and the embedded flag `THM{i_am_vulnerable!}` confirming the application's insecure design.

**Key indicator**: Web logs showing systematic progression from benign requests to OS command injection — `?host=whoami` → `?host=;whoami` (HTTP 200) — confirms successful command injection exploitation.

#### 📸 Screenshot 4 — Auditd: Attacker Accessing `/opt/trypingme/main.py` via Python
<img width="1366" height="728" alt="Command Injection auditd" src="https://github.com/ugbomakyrian5-web/linux-threat-detection-1/blob/main/screenshots/4_auditd_trypingme_python_access.png" />

*auditd — proctitle=/usr/bin/python3 /opt/trypingme/main.py — attacker reading app source via command injection confirmed*

#### 📸 Screenshot 5 — `main.py` Source: Vulnerable Code + Flag `THM{i_am_vulnerable!}`
<img width="1366" height="728" alt="Vulnerable Python App Flag" src="https://github.com/ugbomakyrian5-web/linux-threat-detection-1/blob/main/screenshots/5_trypingme_vulnerable_code_flag.png" />

*main.py — subprocess.check_output(cmd, shell=True) with no input sanitisation — THM{i_am_vulnerable!} flag confirmed*

---

### Phase 3 — Process Tree Analysis: Reverse Shell Traced to TryPingMe

**Commands used**:
```bash
ausearch -i -x whoami
ausearch -i --pid 1018
ausearch -i --pid 577
```

Process tree analysis connected the suspicious `whoami` command back to its true origin. Starting from the `whoami` execution (PID 1020, PPID 1018), walking up the tree revealed:

**Process tree reconstructed**:
PID 577  — /usr/bin/python3 /opt/trypingme/main.py  (TryPingMe app — PPID 1)
└── PID 1018 — /bin/sh -c ping -c 2 ;whoami        (shell spawned by app)
└── PID 1020 — whoami                          (suspicious command)

The `whoami` command (PID 1020) had PPID 1018 — a `/bin/sh` process. Walking up to PID 577 confirmed the root of the attack: `/usr/bin/python3 /opt/trypingme/main.py` — the TryPingMe web application spawning shell commands directly.

Further auditd analysis revealed the attacker escalated from `whoami` to a full **Python reverse shell** — a one-liner connecting back to `10.14.105.255:1337` using `socket`, `subprocess`, and `os.dup2` — the classic Python reverse shell pattern.

**Key insight**: Process tree analysis traced the attack from a single suspicious `whoami` all the way back to the vulnerable web application — without it, the reverse shell would appear as an isolated, unexplained event.

#### 📸 Screenshot 6 — Auditd Process Tree: `whoami` PPID=1018, TryPingMe PID=577, Python Reverse Shell Confirmed
<img width="1366" height="728" alt="Process Tree Reverse Shell" src="https://github.com/ugbomakyrian5-web/linux-threat-detection-1/blob/main/screenshots/6_auditd_process_tree_reverse_shell.png" />

*ausearch process tree — whoami PPID: 1018, TryPingMe PID: 577, Python reverse shell to 10.14.105.255:1337 confirmed*

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed |
|--------|-----------|----|----------|
| Initial Access | External Remote Services | T1133 | SSH exposed — brute-forced by botnet |
| Credential Access | Brute Force: Password Spraying | T1110.003 | Multi-IP, multi-user SSH credential attack |
| Initial Access | Exploit Public-Facing Application | T1190 | TryPingMe command injection via /ping endpoint |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Shell commands injected via web parameter |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | Python reverse shell to attacker C2 |
| Command & Control | Application Layer Protocol | T1071 | Reverse shell callback to 10.14.105.255:1337 |
| Discovery | System Information Discovery | T1082 | `whoami`, `ls` executed via command injection |

---

## 🛡 Containment & Hardening Recommendations

### Immediate Response
- **Block `91.224.92.79`** at firewall — root account compromised from this IP
- **Reset root password** and **audit all active sessions** immediately
- **Take TryPingMe offline** — command injection vulnerability confirmed
- **Block `10.14.105.255`** — confirmed attacker C2 for reverse shell
- **Kill any active reverse shell sessions** from `10.14.105.255:1337`

### SSH Hardening
```bash
# Disable root login via SSH
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Disable password authentication — enforce key-based only
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Install and configure fail2ban
apt install fail2ban
# Set maxretry=3 bantime=86400 in /etc/fail2ban/jail.local
```

### Web Application Fix
```python
# VULNERABLE — never do this
cmd = f"ping -c 2 {host}"
result = subprocess.check_output(cmd, shell=True)

# SECURE — use list arguments and validate input
import re
if not re.match(r'^[\d.]+$', host):
    return "Invalid host"
result = subprocess.check_output(["ping", "-c", "2", host])
```

### Detection Rules (SIEM)
```bash
# SSH brute-force detection
Alert: >5 "Failed password" from single IP within 60 seconds in auth.log

# Root SSH password login
Alert: auth.log — "Accepted password for root" from external IP (not RFC1918)

# Command injection in web logs
Alert: nginx access.log — ?host= parameter containing semicolons, pipes,
backticks, or Linux commands (whoami, ls, id, curl, wget)

# Suspicious process spawned by web server
Alert: auditd — python3/php/node parent process spawning sh/bash/whoami/curl

# Reverse shell pattern
Alert: auditd — python3 -c containing socket.connect AND os.dup2
```

---

## 📌 Investigator Notes

> Linux Initial Access investigations require correlating across multiple log sources — no single file tells the complete story.
>
> In this investigation:
> `/var/log/auth.log` → confirmed the SSH brute-force timeline and the root breach
> `/var/log/nginx/access.log` → revealed the command injection exploitation pattern
> `auditd` → the only source that captured the full process tree from web request to reverse shell
>
> The most important technique demonstrated here is **process tree analysis**.
> A single `whoami` alert means nothing in isolation.
> But traced back through PPID → PID → grandparent PID, it revealed the entire attack origin:
> web request → Python app → shell → whoami → reverse shell.
>
> Process tree analysis works across every Initial Access technique —
> SSH breach, web exploitation, supply chain, or phishing.
> Learn it once, apply it everywhere.

---

## 📌 Key Linux Initial Access Detection Reference

| Attack Vector | Log Source | Key Indicator |
|--------------|-----------|---------------|
| SSH brute-force | `/var/log/auth.log` | Multiple `Failed password` from single IP |
| SSH breach | `/var/log/auth.log` | `Accepted password` from external IP |
| Web command injection | `/var/log/nginx/access.log` | OS commands in query parameters |
| Process origin | auditd (`ausearch`) | PPID chain tracing to web app parent |
| Reverse shell | auditd | Python/bash socket + os.dup2 pattern |

---

## 📌 Skills Demonstrated

- Linux authentication log analysis — SSH brute-force and breach detection
- Web application log analysis — command injection pattern identification
- Auditd process tree reconstruction — PPID/PID chain analysis
- Reverse shell identification via auditd PROCTITLE field
- Multi-source attack chain correlation (auth.log + nginx + auditd)
- MITRE ATT&CK mapping for Linux Initial Access techniques
- Structured, SOC-grade incident documentation

---

**Completed**: May 2026

Full portfolio of SOC investigations available at [github.com/ugbomakyrian5-web](https://github.com/ugbomakyrian5-web)

Feel free to fork, star, or reach out. Open to feedback and collaboration!

MIT License – see the [LICENSE](LICENSE) file for details.
