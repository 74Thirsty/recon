# Recon — Technical Manual

**Author:** C. Hirschauer  
**License:** MIT  
**Python:** 3.8+  
**Zero third-party dependencies** for the main application.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Installation & Requirements](#2-installation--requirements)
3. [Launching the Application](#3-launching-the-application)
4. [Main Menu Reference](#4-main-menu-reference)
5. [Option 1 — Smart Target Profile](#5-option-1--smart-target-profile)
6. [Option 2 — Nmap Scanning Arsenal](#6-option-2--nmap-scanning-arsenal)
7. [Option 3 — DNS & Subdomain Intelligence](#7-option-3--dns--subdomain-intelligence)
8. [Option 4 — Web Footprinting Toolkit](#8-option-4--web-footprinting-toolkit)
9. [Option 5 — Packet Capture & Monitoring](#9-option-5--packet-capture--monitoring)
10. [Option 6 — OSINT Automation Suite](#10-option-6--osint-automation-suite)
11. [Option 7 — Individual Intelligence Workflows](#11-option-7--individual-intelligence-workflows)
12. [Option 8 — Utility Toolbox](#12-option-8--utility-toolbox)
13. [Option 9 — Dependency Health & Installation](#13-option-9--dependency-health--installation)
14. [Option 10 — Wireless Capture & Cracking](#14-option-10--wireless-capture--cracking)
15. [Hashcat Attack Suite — Deep Reference](#15-hashcat-attack-suite--deep-reference)
16. [Wireless Auditing Workflow Guide](#16-wireless-auditing-workflow-guide)
17. [Report System](#17-report-system)
18. [FTP CLI Sub-Application](#18-ftp-cli-sub-application)
19. [Execution Policy & Security Model](#19-execution-policy--security-model)
20. [Dependency Manager](#20-dependency-manager)
21. [Troubleshooting](#21-troubleshooting)
22. [Appendix A — Hashcat Mode Reference](#22-appendix-a--hashcat-mode-reference)
23. [Appendix B — Nmap Flag Reference](#23-appendix-b--nmap-flag-reference)
24. [Appendix C — Report File Naming Conventions](#24-appendix-c--report-file-naming-conventions)

---

## 1. Architecture Overview

Recon is a single-file Python application (`recon.py`, ~2150 lines) with a bash launcher (`recon.sh`). It uses **zero third-party packages** — every import is from the Python standard library. External tools (nmap, tshark, hashcat, etc.) are invoked via `subprocess` and resolved through a built-in dependency manager.

### File Structure

```
recon/
├── recon.py                  # Main application (all logic in one file)
├── recon.sh                  # Bash launcher — finds python3, exec's recon.py
├── README.md                 # This manual
├── AGENTS.md                 # Agent instruction file
├── .gitignore                # Ignores reports/, *.pcap, *.pcapng, __pycache__
├── recon-x86_64.AppImage     # Pre-built portable binary (optional)
├── reports/                  # Auto-created output directory (gitignored)
│   └── {timestamp}_{target}_{prefix}.{ext}
├── .lib_venv/                # Minimal Python 3.13.5 virtual environment
└── ftp-cli/                  # Separate FTP client sub-application
    ├── ftp_cli.py            # Typer CLI entrypoint
    ├── ftp_client.py         # Async FTP client (aioftp)
    ├── config.py             # Server profile persistence (JSON)
    ├── shell.py              # Interactive FTP shell (cmd2)
    └── utils/
        ├── __init__.py
        └── progress.py       # Rich progress bar for transfers
```

### Class Hierarchy

```
ToolMetadata          — Dataclass describing a tool's install metadata
DependencyManager     — Tool resolution, availability checks, guided installation
ReconApp              — Main application: menus, workflows, command execution
```

### Execution Flow

```
main() → ReconApp.__init__() → ReconApp.run()
  ├── display_banner()           — Clears screen, prints ASCII art (figlet)
  ├── DependencyManager.startup_check()  — Prints tool health report
  └── Main Loop                  — Dispatches menu selections
       ├── Comprehensive Profile → Resolution → Geolocation/HTTP → WHOIS → DNS
       ├── Nmap Menu → 9 profiles + custom → subprocess.Popen (live streaming)
       ├── DNS Menu → Records → Subdomains → Zone transfer attempts
       ├── Web Menu → HTTP preview → WhatWeb fingerprinting
       ├── Packet Capture → Interface select → tshark (background thread)
       ├── OSINT Menu → PhoneInfoga / SpiderFoot / StormBreaker / Holehe / Osintgram
       ├── Individuals Menu → Phone / Email / Name / Legal / Income / Career
       ├── Utility Menu → IP/domain validation, DNS, public IP
       ├── Dependencies Menu → Health check + install launcher
       ├── Wireless Menu → 13-option suite (monitor mode, services, capture, cracking)
       └── Exit → SystemExit(0)
```

---

## 2. Installation & Requirements

### Core Requirements

| Tool | Package | Required? | Purpose |
|------|---------|-----------|---------|
| Python 3.8+ | system | **Yes** | Runtime |
| `nmap` | nmap | **Yes** | Port scanning, service detection |
| `tshark` | wireshark | **Yes** | Packet capture |

### Optional Tools

| Tool | Purpose |
|------|---------|
| `figlet` | ASCII art banner |
| `whois` | WHOIS lookups |
| `dig` | DNS record queries |
| `nslookup` | DNS fallback queries |
| `whatweb` | Web technology fingerprinting |
| `subfinder` | Subdomain enumeration |
| `airmon-ng` | Monitor mode enable/disable |
| `airodump-ng` | 802.11 packet capture |
| `aireplay-ng` | Deauthentication attacks |
| `besside-ng` | Automated WPA capture |
| `wash` | WPS network discovery |
| `reaver` | WPS PIN brute-force |
| `iw` | Wireless interface enumeration |
| `hcxtools` | pcap to hashcat format conversion |
| `hashcat` | Password cracking |
| `curl` | Public IP lookup |
| `phoneinfoga` | Phone number intelligence |
| `spiderfoot` | Multi-source OSINT |
| `stormbreaker` | Payload/orchestration OSINT |
| `holehe` | Email registration enumeration |
| `osintgram` | Instagram intelligence |

Install recipes are centralized in [Dependency Manager](#20-dependency-manager).

### Platform Support

The dependency manager auto-detects your package manager and suggests install commands for:

- `apt` (Debian/Ubuntu)
- `dnf` / `yum` (Fedora/RHEL)
- `pacman` (Arch)
- `apk` (Alpine)
- `brew` (macOS)

---

## 3. Launching the Application

### Preferred: Bash Launcher

```bash
chmod +x recon.sh
./recon.sh
```

The launcher searches for `python3` then `python` on your PATH, and exec's `recon.py` with any arguments forwarded.

### Direct Python Execution

```bash
python3 recon.py
```

### Pre-Built AppImage

```bash
chmod +x recon-x86_64.AppImage
./recon-x86_64.AppImage
```

The AppImage is a self-contained portable binary — no Python installation required.

### Startup Sequence

1. Screen clears
2. ASCII art banner renders (figlet if available, otherwise plain text)
3. Dependency health report prints — shows which tools are detected and which are missing
4. Main menu appears

---

## 4. Main Menu Reference

```
====================
 RECONNAISSANCE
====================
1)  Smart target profile (IP/Domain intelligence)
2)  Nmap scanning arsenal
3)  DNS + subdomain intelligence
4)  Web footprinting toolkit
5)  Packet capture & monitoring
6)  OSINT automation & social recon
7)  Individual intelligence workflows
8)  Utility toolbox
9)  Dependency health & installation
10) Wireless capture & cracking
0)  Exit
```

| Option | Handler | Description |
|--------|---------|-------------|
| 1 | `comprehensive_profile()` | Full target intelligence package (resolution, geolocation, WHOIS, DNS, HTTP) |
| 2 | `nmap_menu()` | 9 pre-built Nmap scan profiles plus custom command execution |
| 3 | `dns_menu()` | DNS record enumeration, subdomain discovery, zone transfer attempts |
| 4 | `web_menu()` | HTTP header inspection, page title extraction, WhatWeb technology detection |
| 5 | `packet_capture_menu()` | TShark-based live packet capture with interface selection and BPF filters |
| 6 | `osint_menu()` | PhoneInfoga, SpiderFoot, StormBreaker, Holehe, Osintgram sub-menu |
| 7 | `individuals_menu()` | Guided intelligence workflows for phone, email, name, legal, income, career |
| 8 | `utility_menu()` | IP/domain validation, DNS lookup, public IPv4 detection |
| 9 | `dependencies_menu()` | Tool health report and guided installation launcher |
| 10 | `wireless_menu()` | Full wireless auditing suite (13 sub-options) |
| 0 | `exit_app()` | Prints goodbye message and exits |

---

## 5. Option 1 — Smart Target Profile

**Purpose:** One-shot comprehensive intelligence gathering against a single IP address or domain name.

**Prompts:** Enter an IP address or domain name.

**Execution pipeline:**

| Step | Method | Description |
|------|--------|-------------|
| 1 | `_format_header()` | Generates timestamped report header |
| 2 | `_basic_resolution()` | Detects IP version (v4/v6) or resolves domain to IPs; performs reverse DNS for IPs |
| 3a | `_ip_geolocation()` | *(IP only)* Queries ipinfo.io for city, region, country, org, timezone |
| 3b | `_http_preview()` | *(Domain only)* Fetches HTTPS/HTTP headers: Server, X-Powered-By, Content-Type, Set-Cookie |
| 4 | `_whois_lookup()` | WHOIS data with 60-line console preview; full output saved separately |
| 5 | `_dns_records_summary()` | Queries A, AAAA, MX, NS, TXT, CNAME, SOA records |

**Output:** `reports/{timestamp}_{target}_profile.txt`

**DNS query resolution order:**
1. `dig` (preferred — cleanest output)
2. `nslookup` (fallback — parsed with `_parse_nslookup_output()`)
3. Python `socket` module (last resort — limited record types)

---

## 6. Option 2 — Nmap Scanning Arsenal

**Requires:** `nmap` (auto-prompted if missing)

### Scan Profiles

| # | Profile | Flags | Description |
|---|---------|-------|-------------|
| 1 | Quick scan | `-T4 -Pn` | Top 1000 TCP ports, fastest timing |
| 2 | Full TCP scan | `-T4 -Pn -p-` | All 65535 TCP ports |
| 3 | Service & script | `-T4 -Pn -sV -sC` | Version detection + default NSE scripts |
| 4 | Aggressive | `-T4 -A` | OS detection, version, scripts, traceroute |
| 5 | Vulnerability scripts | `-T4 -Pn --script vuln` | NSE vulnerability category |
| 6 | Custom command | User-defined | Arbitrary Nmap arguments |
| 7 | Host discovery | `-sn` | Ping sweep only (no port scan) |
| 8 | UDP scan | `-T4 -Pn -sU --top-ports 200` | Top 200 UDP ports |
| 9 | Combined TCP+UDP | `-T4 -Pn -sS -sU --top-ports 100 -sV` | Top 100 of both with version |

### Execution Details

- Uses `subprocess.Popen` with `stdout=subprocess.PIPE, stderr=subprocess.STDOUT`
- Output streams **live** to the terminal line-by-line
- All output saved with `-oN` to `reports/{timestamp}_{target}_nmap.txt`

---

## 7. Option 3 — DNS & Subdomain Intelligence

**Prompts:** Enter a domain name.

### Sub-operations

| Step | Method | Description |
|------|--------|-------------|
| 1 | `_dns_records_summary()` | Queries 7 record types (A, AAAA, MX, NS, TXT, CNAME, SOA) via dig/nslookup/socket |
| 2 | `_subdomain_enumeration()` | Subfinder (if installed) or crt.sh certificate transparency API fallback |
| 3 | `_zone_transfer_attempt()` | Enumerates NS records, attempts AXFR zone transfer against each nameserver |

### crt.sh Fallback

When Subfinder is unavailable, the app queries `https://crt.sh/?q=%.{domain}&output=json` directly. Results are parsed from potentially multiple JSON objects in the response, deduplicated, and capped at 200 entries.

**Output:** `reports/{timestamp}_{target}_dns.txt`

---

## 8. Option 4 — Web Footprinting Toolkit

**Prompts:** Enter a domain or URL.

### Sub-operations

| Step | Method | Description |
|------|--------|-------------|
| 1 | `_http_preview(fetch_body=True)` | HTTPS/HTTP request with custom User-Agent (`Recon-Toolkit/1.0`); extracts status, headers, and `<title>` tag |
| 2 | `_technology_fingerprint()` | Runs WhatWeb with `--log-json` for technology detection |

### URL Resolution

`_build_url_candidates()` tries HTTPS first, then HTTP fallback:
```
https://target → http://target
```

**Output:**
- `reports/{timestamp}_{target}_web.txt` — HTTP preview + technology data
- `reports/{timestamp}_{target}_whatweb.json` — WhatWeb JSON log (if WhatWeb installed)

---

## 9. Option 5 — Packet Capture & Monitoring

**Requires:** `tshark` (auto-prompted if missing)

### Workflow

1. `_choose_interface()` — Runs `tshark -D`, lists numbered interfaces, prompts for selection
2. Prompts for BPF capture filter (optional, e.g. `port 443` or `host 192.168.1.1`)
3. Prompts for capture duration in seconds (optional)
4. Launches `tshark -i {iface} -w {output.pcap}` in a background process
5. Starts a daemon thread (`_capture_output_stream`) for live tshark output
6. Press **Enter** to stop capture early
7. Process terminated with 5-second grace period

**Output:** `reports/{timestamp}_{interface}_capture.pcap`

---

## 10. Option 6 — OSINT Automation Suite

### Sub-menu

| # | Tool | Method | Description |
|---|------|--------|-------------|
| 1 | PhoneInfoga | `phoneinfoga_lookup()` | E.164 phone number scan; output formats: json, pretty, yaml, csv |
| 2 | SpiderFoot | `spiderfoot_scan()` | Multi-module recon; target types: domain, ip, email, asn, phone, netblock, username, name |
| 3 | StormBreaker | `stormbreaker_workflow()` | Interactive or argument-based payload/orchestration |
| 4 | Holehe | `holehe_lookup()` | Email service registration enumeration; multi-email support (comma/space separated) |
| 5 | Osintgram | `osintgram_lookup()` | Instagram intelligence; single command or interactive shell mode |

### SpiderFoot Target Types

| Type | Example | Use Case |
|------|---------|----------|
| `domain` | example.com | Domain intelligence |
| `ip` | 1.2.3.4 | IP owner, hosting, history |
| `email` | user@example.com | Email-associated data |
| `asn` | AS12345 | Autonomous system info |
| `phone` | +15551234567 | Phone-associated data |
| `netblock` | 1.2.3.0/24 | Network block intelligence |
| `username` | johndoe | Username-associated accounts |
| `name` | John Doe | Name-associated data |

### SpiderFoot Output Formats

- `csv` — Default, easy to parse
- `json` — Structured data
- `tsv` — Tab-separated
- `sqlite` — Database format

---

## 11. Option 7 — Individual Intelligence Workflows

**Purpose:** Guided, profile-aware intelligence gathering for person-centric investigations.

### Sub-menu

| # | Workflow | Method | Description |
|---|----------|--------|-------------|
| 1 | Phone info | `phoneinfoga_lookup()` | PhoneInfoga E.164 scan |
| 2 | Email info | `holehe_lookup()` | Holehe email enumeration |
| 3 | Name info | `_spiderfoot_individual_workflow("name")` | SpiderFoot scan with `-t name` |
| 4 | Legal info | `_spiderfoot_individual_workflow("legal")` | SpiderFoot + WHOIS lookup |
| 5 | Income info | `_spiderfoot_individual_workflow("income")` | SpiderFoot scan |
| 6 | Career info | `_spiderfoot_individual_workflow("career")` | SpiderFoot + Osintgram `info` command |

### Workflow Engine

`_spiderfoot_individual_workflow(profile)` provides profile-specific prompts:

- **name**: Prompts for full name, runs SpiderFoot `-t name`
- **legal**: Prompts for domain/entity, runs SpiderFoot + WHOIS lookup
- **income**: Prompts for target, runs SpiderFoot
- **career**: Prompts for target, runs SpiderFoot + optional Osintgram `info` command

All workflows output JSON to `reports/`.

---

## 12. Option 8 — Utility Toolbox

| # | Tool | Method | Description |
|---|------|--------|-------------|
| 1 | Validate IP address | `_is_ip()` | Strict IPv4/IPv6 validation via `ipaddress.ip_address()` |
| 2 | Validate domain name | `_is_domain()` | RFC-compliant regex validation (max 253 chars, max 63 per label) |
| 3 | Reverse DNS lookup | `_reverse_dns_lookup()` | PTR record via `socket.gethostbyaddr()` — returns hostname + aliases |
| 4 | Resolve domain to IPs | `_resolve_domain()` | `socket.getaddrinfo()` — deduplicated, sorted results |
| 5 | Show public IPv4 | `_public_ipv4_lookup()` | `curl -4 ifconfig.me` with 15-second timeout |

---

## 13. Option 9 — Dependency Health & Installation

1. Runs `DependencyManager.startup_check()` — prints a table of all 22 registered tools with status (detected / missing)
2. Prompts for a tool name to attempt installation
3. Runs `DependencyManager.ensure_tool(tool)` for guided install

### Install Behavior

Recon never installs silently. Option 9 checks tool status, asks which missing tool to install, then runs the centralized recipe documented in [Dependency Manager](#20-dependency-manager) only after the user confirms `Attempt automatic installation? [y/N]:`.

---

## 14. Option 10 — Wireless Capture & Cracking

### Full Sub-menu

```
Wireless Capture & Cracking
---------------------------
  --- Interface Management ---
 1) List wireless interfaces (iw dev)
 2) Enable monitor mode (airmon-ng)
 3) Disable monitor mode (airmon-ng)
 4) Kill interfering processes (airmon-ng check kill)
  --- Service Control ---
 5) NetworkManager  [start/stop/restart/status]
 6) wpa_supplicant  [start/stop/restart/status]
  --- Scanning & Capture ---
 7)  Airodump-ng scan / capture
 8)  Besside-ng capture session
 9)  Wash WPS scan
  --- Attacks ---
10)  Aireplay-ng deauth test
11)  Reaver WPS PIN attack
  --- Cracking ---
12) HCXTools convert capture to hashcat format
13) Hashcat attack suite
 0) Back to main menu
```

### 14.1 — List Wireless Interfaces

**Requires:** `iw`

Runs `iw dev` to display all wireless interfaces with their current mode (managed/monitor), MAC address, SSID, and channel info.

**Output:** `reports/{timestamp}_iw_list_interfaces.txt`

### 14.2 — Enable Monitor Mode

**Requires:** `airmon-ng` (aircrack-ng package)

**Prompts:**
1. Wireless interface name (e.g., `wlan0`, `wlan0mon`)
2. Kill interfering processes? (Y/n) — runs `airmon-ng check kill` first if yes

**Command:** `sudo airmon-ng start {interface}`

If interfering processes are killed, NetworkManager, wpa_supplicant, and dhclient are stopped to prevent them from resetting the adapter.

**Output:** `reports/{timestamp}_{interface}_airmon_start.txt`

### 14.3 — Disable Monitor Mode

**Requires:** `airmon-ng`

**Prompts:**
1. Monitor mode interface name (e.g., `wlan0mon`)
2. Restart NetworkManager? (Y/n) — auto-restarts after disabling monitor mode

**Command:** `sudo airmon-ng stop {interface}`

**Output:** `reports/{timestamp}_{interface}_airmon_stop.txt`

### 14.4 — Kill Interfering Processes

**Requires:** `airmon-ng`

**Command:** `sudo airmon-ng check kill`

Kills NetworkManager, wpa_supplicant, dhclient, and any other process that may interfere with monitor mode or channel switching.

**Output:** `reports/{timestamp}_airmon_check_kill_processes.txt`

### 14.5 — NetworkManager Service Control

**Commands:** Uses `systemctl` (preferred) or `service` (fallback), all through `sudo`.

| Action | Command |
|--------|---------|
| Status | `sudo systemctl status NetworkManager` |
| Start | `sudo systemctl start NetworkManager` |
| Stop | `sudo systemctl stop NetworkManager` |
| Restart | `sudo systemctl restart NetworkManager` |

**Output:** `reports/{timestamp}_{service}_{action}.txt`

### 14.6 — wpa_supplicant Service Control

Same mechanism as NetworkManager. Useful for:
- Stopping wpa_supplicant before enabling monitor mode
- Restarting it after returning to managed mode

### 14.7 — Airodump-ng Scan / Capture

**Requires:** `airodump-ng` (aircrack-ng package)

**Prompts:**
1. Monitor mode interface
2. Capture mode:
   - **1) Scan all channels** — hops across all channels, discovers all APs
   - **2) Target specific BSSID** — locks to a BSSID and optionally a channel
   - **3) Target specific channel** — locks to a single channel
3. Write capture files to disk? (Y/n)
4. Additional flags (optional)

**Output:** `reports/{timestamp}_{interface}_airodump.cap` (if writing enabled)  
**Output:** `reports/{timestamp}_{interface}_airodump_session.txt`

### 14.8 — Besside-ng Capture Session

**Requires:** `besside-ng` (aircrack-ng package)

**Prompts:**
1. Monitor mode interface
2. Channel (optional)
3. Target BSSID (optional)
4. Additional flags (optional)

Automatically captures WPA/WPA2 handshakes and crackable PMKIDs. Press **Ctrl+C** to stop.

**Output:** `reports/{timestamp}_{interface}_besside.cap` + `reports/{timestamp}_{interface}_besside_session.txt`

### 14.9 — Wash WPS Scan

**Requires:** `wash` (reaver package)

**Prompts:**
1. Monitor mode interface
2. Scan specific interface only? (Y/n) — if no, scans all interfaces with `-f`

Discovers WPS-enabled networks showing BSSID, channel, RSSI, WPS version, and WPS locked status.

**Output:** `reports/{timestamp}_{interface}_wash_scan.txt`

### 14.10 — Aireplay-ng Deauth Test

**Requires:** `aireplay-ng` (aircrack-ng package)

**Prompts:**
1. Monitor mode interface
2. Deauth mode:
   - **1) Specific client** — deauthenticates a single client from an AP (`-c` flag)
   - **2) All clients from AP** — deauthenticates all clients from a BSSID (`-a` flag)
   - **3) Broadcast deauth** — deauthenticates all clients via broadcast
3. Target AP BSSID
4. Target client MAC (mode 1 only)
5. Number of deauth packets (default: 5)
6. Additional flags (optional)

**Warning:** Deauthentication attacks may be illegal in your jurisdiction. Use only on networks you own or have authorization to test.

**Output:** `reports/{timestamp}_{bssid}_aireplay_deauth.txt`

### 14.11 — Reaver WPS PIN Attack

**Requires:** `reaver` (reaver package)

**Prompts:**
1. Monitor mode interface
2. Target AP BSSID
3. Channel (optional — improves speed)
4. Path to known PINs file (optional — for targeted PIN lists)
5. Additional flags (optional)

Brute-forces the 8-digit WPS PIN to recover the WPA password. Press **Ctrl+C** to stop.

**Output:** `reports/{timestamp}_{bssid}_reaver_wps.txt`

### 14.12 — HCXTools Convert

**Requires:** `hcxtools` (hcxtools package)

**Prompts:**
1. Path to `.pcap` or `.pcapng` capture file
2. Additional HCXTools flags (optional)

Converts pcap captures to hashcat-ready `.hc22000` format using `hcxpcapngtool` (preferred) or `hcxpcaptool` (fallback).

**Output:**
- `reports/{timestamp}_{capture_stem}_hcxtools.hc22000` — Hashcat-ready capture
- `reports/{timestamp}_{capture_stem}_hcxtools_convert.txt` — Conversion log

### 14.13 — Hashcat Attack Suite

See [Section 15](#15-hashcat-attack-suite--deep-reference) for the complete reference.

---

## 15. Hashcat Attack Suite — Deep Reference

**Requires:** `hashcat` (hashcat package)

### Sub-menu

```
Hashcat Attack Suite
--------------------
  --- Attacks ---
 1) Dictionary attack (-a 0)
 2) Combinator attack (-a 1)
 3) Brute-force / Mask attack (-a 3)
 4) Hybrid Wordlist + Mask (-a 6)
 5) Hybrid Mask + Wordlist (-a 7)
 6) Association attack (-a 9)
 7) Rule-based dictionary attack (-a 0 -r)
  --- Utilities ---
 8) Show cracked hashes (--show)
 9) Benchmark GPU performance (-b)
10) Hash type lookup (--example-hashes)
11) Identify hash type (hashid)
12) Session restore (--restore)
13) Custom hashcat command
  --- HCXTools ---
14) Convert capture to hashcat format (hcxpcapngtool)
 0) Back to wireless menu
```

### Common Prompts (All Attacks)

Every attack prompts for:

| Prompt | Default | Description |
|--------|---------|-------------|
| Hash file path | *(required)* | Path to hash file (e.g., `.hc22000`, `.ntlm`, `.md5`) |
| Hash mode (`-m`) | `22000` | Hashcat hash type (22000 = WPA-PBKDF2-PMKID+EAPOL) |
| Session name | *(optional)* | `--session` flag for session persistence |
| `--force` | `N` | Forces hashcat to run despite warnings |
| Workload profile | *(optional)* | 1=low, 2=default, 3=high, 4=nightmare |
| Additional flags | *(optional)* | Free-form extra hashcat arguments |

### 15.1 — Dictionary Attack (`-a 0`)

The simplest and often most effective attack. Tests every password in a wordlist against the hash.

**Additional prompts:**
- Wordlist path (required)

**Example command generated:**
```
hashcat -a 0 -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt --outfile reports/...hashcat.txt
```

**Tips:**
- Start with `/usr/share/wordlists/rockyou.txt` (common on Kali/Parrot)
- SecLists provides curated wordlists: `https://github.com/danielmiessler/SecLists`
- Combine with rules (option 7) for mutations

### 15.2 — Combinator Attack (`-a 1`)

Combines every entry from two wordlists by concatenation. If wordlist1 has "pass" and wordlist2 has "123", it tests "pass123".

**Additional prompts:**
- First wordlist path (required)
- Second wordlist path (required)

**Example command generated:**
```
hashcat -a 1 -m 22000 hash.hc22000 wordlist1.txt wordlist2.txt --outfile reports/...hashcat.txt
```

### 15.3 — Brute-Force / Mask Attack (`-a 3`)

Tests all passwords matching a mask pattern. Each character position is defined by a placeholder.

**Mask Placeholders:**

| Placeholder | Character Set |
|-------------|---------------|
| `?l` | Lowercase letters (a-z) |
| `?u` | Uppercase letters (A-Z) |
| `?d` | Digits (0-9) |
| `?s` | Special characters |
| `?a` | All printable characters |
| `?b` | All 256 bytes |

**Additional prompts:**
- Mask string (required) — e.g., `?d?d?d?d?d?d?d?d` for 8-digit PIN
- Increment mode (Y/n) — tries lengths from min to max
- Increment minimum length
- Increment maximum length
- Custom charset (optional) — e.g., `-1 ?l?d` defines `?1` as lowercase+digits

**Example command generated:**
```
hashcat -a 3 -m 22000 hash.hc22000 ?d?d?d?d?d?d?d?d --increment --increment-min 1 --increment-max 8 --outfile reports/...hashcat.txt
```

### 15.4 — Hybrid Wordlist + Mask (`-a 6`)

Appends a mask to each wordlist entry. If wordlist has "password" and mask is `?d?d`, it tests "password00" through "password99".

**Additional prompts:**
- Wordlist path (required)
- Mask string (required)

**Example command generated:**
```
hashcat -a 6 -m 22000 hash.hc22000 wordlist.txt ?d?d?d --outfile reports/...hashcat.txt
```

### 15.5 — Hybrid Mask + Wordlist (`-a 7`)

Prepends a mask to each wordlist entry. If mask is `?d?d` and wordlist has "password", it tests "00password" through "99password".

**Additional prompts:**
- Mask string (required)
- Wordlist path (required)

**Example command generated:**
```
hashcat -a 7 -m 22000 hash.hc22000 ?d?d?d wordlist.txt --outfile reports/...hashcat.txt
```

### 15.6 — Association Attack (`-a 9`)

Tests combinations of entries from two wordlists using an association algorithm (different from combinator — uses positional mapping).

**Additional prompts:**
- First wordlist path (required)
- Second wordlist path (required)

### 15.7 — Rule-Based Dictionary Attack (`-a 0 -r`)

Applies transformation rules to each wordlist entry, generating multiple candidate passwords per entry. Rules can append numbers, toggle case, leet-speak substitute, etc.

**Additional prompts:**
- Wordlist path (required)
- Rules files (one or more, enter empty to finish)

**Common Rule Files:**

| File | Description |
|------|-------------|
| `rules/best64.rule` | Top 64 most effective rules |
| `rules/dive.rule` | Large rule set (~100K rules) |
| `rules/d3ad0ne.rule` | Comprehensive rule collection |
| `rules/toggles1-5.rule` | Case toggle variations |

**Example command generated (multiple rule files):**
```
hashcat -a 0 -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule -r rules/dive.rule --outfile reports/...hashcat.txt
```

### 15.8 — Show Cracked Hashes (`--show`)

Displays previously cracked hashes from the potfile.

**Command:** `hashcat -m {mode} hashfile --show --outfile reports/...hashcat_show.txt`

### 15.9 — Benchmark GPU Performance (`-b`)

Tests GPU cracking speed for all hash types or a specific mode.

**Command:** `hashcat -b` or `hashcat -b -m {mode}`

**Output:** `reports/{timestamp}_benchmark_hashcat_benchmark.txt`

### 15.10 — Hash Type Lookup (`--example-hashes`)

Displays example hashes for any hash mode, showing the expected input format.

**Command:** `hashcat --example-hashes` or `hashcat --example-hashes -m {mode}`

**Output:** `reports/{timestamp}_{mode}_hashcat_example_hashes.txt`

### 15.11 — Identify Hash Type

Uses `hashid` or `name-that-hash` (third-party, must be installed separately via `pip3 install hashid`) to identify unknown hash types.

**Prompts:** Enter hash string or path to file containing hashes.

**Output:** `reports/{timestamp}_{hash}_hash_identify.txt`

### 15.12 — Session Restore

Resumes a previous hashcat session that was interrupted.

**Prompts:** Session name (the name given when starting the attack).

**Command:** `hashcat --restore --session {name}`

### 15.13 — Custom Hashcat Command

Runs an arbitrary hashcat command. Prompts for the full argument string after `hashcat`.

**Example:** User enters `-m 1000 -a 3 ?a?a?a?a?a?a --force` and the app runs `hashcat -m 1000 -a 3 ?a?a?a?a?a?a --force --outfile reports/...hashcat_custom.txt`.

---

## 16. Wireless Auditing Workflow Guide

### Standard WPA/WPA2 Cracking Workflow

```
1. List interfaces (option 1) — identify your wireless adapter
2. Stop services (options 5/6) — stop NetworkManager and wpa_supplicant
3. Enable monitor mode (option 2) — airmon-ng start wlan0
4. Scan targets (option 7) — airodump-ng to discover networks
5. Target specific AP (option 7, mode 2) — lock BSSID + channel
6. Capture handshake (option 8) — besside-ng or airodump-ng with -w
7. (Optional) Deauth clients (option 10) — force handshake reassociation
8. Disable monitor mode (option 3) — airmon-ng stop wlan0mon
9. Restart services (options 5/6) — restart NetworkManager/wpa_supplicant
10. Convert capture (option 12) — hcxpcapngtool pcap → .hc22000
11. Crack password (option 13) — hashcat dictionary/mask/rule attack
```

### WPS Attack Workflow

```
1. Enable monitor mode (option 2)
2. WPS scan (option 9) — wash to find WPS-enabled networks
3. Note locked vs unlocked status
4. Reaver attack (option 11) — brute-force WPS PIN
5. Use recovered PIN to derive WPA password
```

### PMKID Attack Workflow

```
1. Enable monitor mode (option 2)
2. Capture PMKID (option 7/8) — airodump-ng or besside-ng
3. Convert (option 12) — hcxpcapngtool extracts PMKID from EAPOL
4. Crack (option 13) — hashcat -m 22000 (no client association needed)
```

---

## 17. Report System

### Directory

All output is written to `reports/` (auto-created at startup).

### Naming Convention

```
{YYYYMMDD}_{HHMMSS}_{sanitized_target}_{prefix}.{extension}
```

- **Timestamp:** UTC format `YYYYMMDD_HHMMSS`
- **Target:** Non-alphanumeric characters replaced with `_`, truncated to 50 characters
- **Prefix:** Operation-specific identifier
- **Extension:** File type indicator

### Report Prefixes

| Prefix | Operation |
|--------|-----------|
| `profile` | Comprehensive target profile |
| `nmap` | Nmap scan output |
| `dns` | DNS intelligence |
| `web` | Web footprinting |
| `capture` | TShark packet capture |
| `whois` | Extended WHOIS output |
| `subfinder` | Subfinder subdomain results |
| `zone_transfer_{ns}` | Zone transfer per nameserver |
| `whatweb` | WhatWeb JSON log |
| `airmon_start` / `airmon_stop` / `airmon_check_kill` | Airmon-ng operations |
| `airodump` / `airodump_session` | Airodump-ng captures |
| `besside` / `besside_session` | Besside-ng captures |
| `wash_scan` | Wash WPS scan |
| `aireplay_deauth` | Deauthentication logs |
| `reaver_wps` | Reaver WPS attack |
| `hcxtools` / `hcxtools_convert` | HCXTools conversion |
| `hashcat` / `hashcat_session` | Hashcat output / cracked hashes |
| `hashcat_benchmark` | GPU benchmark results |
| `hashcat_example_hashes` | Example hash display |
| `hashcat_restore` | Session restore logs |
| `hashcat_show` | Cracked hash display |
| `hashcat_custom` | Custom command logs |
| `hash_identify` | Hash type identification |
| `phoneinfoga` | Phone intelligence |
| `spiderfoot_*` | SpiderFoot output (format in name) |
| `stormbreaker` | StormBreaker transcript |
| `holehe` | Holehe email enumeration |
| `osintgram_*` | Osintgram output (command in name) |
| `individual_{profile}` | Individual workflow report |
| `{service}_{action}` | Service control logs (e.g., `NetworkManager_restart`) |
| `iw_list` | Wireless interface listing |

### File Types

| Extension | Usage |
|-----------|-------|
| `.txt` | Default — text reports, command output |
| `.pcap` | TShark packet captures |
| `.cap` | Airodump-ng / Besside-ng captures |
| `.hc22000` | Hashcat-ready WPA captures |
| `.json` | WhatWeb logs, SpiderFoot output |

### Gitignore

`reports/`, `*.pcap`, `*.pcapng`, and `__pycache__/` are gitignored by default.

---

## 18. FTP CLI Sub-Application

A separate interactive FTP client located in `ftp-cli/`. Requires third-party packages: `typer`, `rich`, `cmd2`, `aioftp`.

### Running

```bash
python ftp-cli/ftp_cli.py
```

### CLI Commands (Typer)

| Command | Description |
|---------|-------------|
| `add-server` | Save a new FTP server profile (name, host, user, password, port, --secure) |
| `list-servers` | Display saved profiles in a Rich table |
| `remove-server` | Delete a saved server profile by name |
| `connect` | Connect to saved server and launch interactive shell |

### Interactive Shell Commands (cmd2)

| Command | Description |
|---------|-------------|
| `pwd` | Show current remote working directory |
| `cd <path>` | Change remote directory |
| `ls [path]` | List directory contents (Rich table: name, type, size, modified) |
| `get <remote> [local]` | Download file with progress bar |
| `put <local> [remote]` | Upload file with progress bar |
| `mkdir <path>` | Create remote directory |
| `rm <path>` | Delete remote file |
| `disconnect` / `exit` / `quit` | Disconnect and exit shell |

### Architecture

- **ConfigManager** — JSON-based profile persistence at `~/.ftpcli/config.json`
- **FTPClient** — Async wrapper using `aioftp` with dedicated event loop thread; TLS/SSL support
- **Progress** — Rich progress bar with transfer speed, elapsed/remaining time
- **Chunk size:** 64KB for uploads and downloads

---

## 19. Execution Policy & Security Model

### Fixed Tool Launch Patterns

Recon enforces predetermined launch patterns for all integrated tools. If an expected executable is missing from PATH, the workflow stops and shows install guidance. **No ad-hoc command strings are accepted at runtime** — this prevents injection of arbitrary commands through tool parameters.

### Subprocess Safety

| Feature | Implementation |
|---------|----------------|
| Exit code handling | `check=False` on all `subprocess.run()` calls — never raises on non-zero exit |
| Error catching | `FileNotFoundError` caught and displayed as "tool not found" |
| Output capture | stdout and stderr captured, printed live, and saved to reports |
| Nmap streaming | Uses `subprocess.Popen` for line-by-line live output |
| Thread safety | Daemon thread used for live packet capture output |
| HTTP timeouts | 10-45 seconds depending on endpoint |
| SSL verification | Uses `ssl.create_default_context()` for all HTTPS requests |

### Tool Resolution

`_get_tool_command(tool)` resolves tools through the `DependencyManager`:
1. Check if tool is on PATH via `command_prefix()`
2. If not found, call `ensure_tool()` which prompts for auto-install
3. If install fails, show manual install instructions
4. Return `None` if tool cannot be resolved — workflow stops gracefully

### Service Control

Service management commands (`systemctl`, `service`) are always run through `sudo`. The app auto-detects `systemctl` availability and falls back to `service` on older systems.

---

## 20. Dependency Manager

This section is the single source of truth for tool install recipes. Other sections describe what a tool does and refer back here for installation behavior.

### User-Confirmed Auto-Installation

Recon never installs silently. When a missing tool is selected, Recon asks:

```text
Attempt automatic installation? [y/N]:
```

If the user answers `y`, the dependency manager runs the configured install recipe for that tool.

For package-manager tools, Recon detects your OS and package manager, then runs the appropriate install command:

| Package Manager | Detection | Install Command |
|-----------------|-----------|-----------------|
| apt | `/usr/bin/apt` or `/usr/bin/apt-get` | `sudo apt install -y {package}` |
| dnf | `/usr/bin/dnf` | `sudo dnf install -y {package}` |
| yum | `/usr/bin/yum` | `sudo yum install -y {package}` |
| pacman | `/usr/bin/pacman` | `sudo pacman -S --noconfirm {package}` |
| apk | `/sbin/apk` | `sudo apk add {package}` |
| brew | `/usr/local/bin/brew` or `/opt/homebrew/bin/brew` | `brew install {package}` |

GitHub-backed tools are stored under `~/.local/share/recon/tools`. Launchers are created in `~/.local/bin`, and Recon checks that directory when resolving commands.

If auto-install fails, the app shows the failed command and the manual install hint.

### Registered Tools (22)

| Key | Friendly Name | Install Recipe | Optional | Executables |
|-----|---------------|----------------|----------|-------------|
| `nmap` | Nmap | Package manager: `nmap` | **No** | `nmap` |
| `tshark` | TShark | Package manager: `wireshark` | **No** | `tshark` |
| `figlet` | Figlet | Package manager: `figlet` | Yes | `figlet` |
| `whois` | Whois | Package manager: `whois` | Yes | `whois` |
| `dig` | Dig | Package manager: `dnsutils` / `bind-utils` / `bind` | Yes | `dig` |
| `nslookup` | Nslookup | Package manager: `dnsutils` / `bind-utils` / `bind` | Yes | `nslookup` |
| `whatweb` | WhatWeb | Package manager: `whatweb` | Yes | `whatweb` |
| `subfinder` | Subfinder | Package manager: `subfinder` | Yes | `subfinder` |
| `airmon-ng` | Airmon-ng | Package manager: `aircrack-ng` | Yes | `airmon-ng` |
| `airodump-ng` | Airodump-ng | Package manager: `aircrack-ng` | Yes | `airodump-ng` |
| `aireplay-ng` | Aireplay-ng | Package manager: `aircrack-ng` | Yes | `aireplay-ng` |
| `besside-ng` | Besside-ng | Package manager: `aircrack-ng` | Yes | `besside-ng` |
| `wash` | Wash | Package manager: `reaver` | Yes | `wash` |
| `reaver` | Reaver | Package manager: `reaver` | Yes | `reaver` |
| `iw` | iw | Package manager: `iw` | Yes | `iw` |
| `hcxtools` | HCXTools | Package manager: `hcxtools` | Yes | `hcxpcapngtool`, `hcxpcaptool` |
| `hashcat` | Hashcat | Package manager: `hashcat` | Yes | `hashcat` |
| `curl` | curl | Package manager: `curl` | Yes | `curl` |
| `phoneinfoga` | PhoneInfoga | `go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest` | Yes | `phoneinfoga`, `phoneinfoga.py` |
| `spiderfoot` | SpiderFoot | Clone `https://github.com/smicallef/spiderfoot.git`, install requirements, create `sfcli.py` launcher | Yes | `sfcli`, `spiderfoot`, `sfcli.py` |
| `stormbreaker` | StormBreaker | Clone `https://github.com/ultrasecurity/Storm-Breaker.git`, install requirements, create `stormbreaker` launcher | Yes | `stormbreaker`, `storm-breaker`, `stormbreaker.py` |
| `holehe` | Holehe | `python3 -m pip install --user holehe` | Yes | `holehe` |
| `osintgram` | Osintgram | Clone `https://github.com/Datalux/Osintgram.git`, install requirements, create `osintgram` launcher | Yes | `osintgram` |

### Python Script Handling

For tools distributed as `.py` files (PhoneInfoga, SpiderFoot, StormBreaker), the dependency manager auto-wraps the command with the Python interpreter:
```
python3 /path/to/script.py [args]
```

For tools installed from GitHub by Recon, wrappers are written to `~/.local/bin` and point back to the cloned checkout under `~/.local/share/recon/tools`.

---

## 21. Troubleshooting

### "Command not found" Errors

Run **Option 9 (Dependency health)** from the main menu to see which tools are detected. The app will suggest install commands for your platform.

### TShark Requires Root

On some systems, tshark needs root privileges to capture packets. Run with `sudo`:
```bash
sudo ./recon.sh
```

Or set the proper capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
```

### Airmon-ng Fails to Enable Monitor Mode

1. Ensure you stopped NetworkManager and wpa_supplicant first (options 5/6)
2. Run `airmon-ng check kill` (option 4) to stop interfering processes
3. Verify your adapter supports monitor mode (`iw list` under "Supported interface modes")

### Hashcat "No devices found"

1. Ensure you have compatible GPU drivers installed
2. Run `hashcat -b` (option 9 in hashcat menu) to verify GPU detection
3. For NVIDIA: install `nvidia-driver` and `nvidia-cuda-toolkit`
4. For AMD: install `rocm-dev`

### Zone Transfer Fails

Most public DNS servers reject zone transfers. This is expected behavior — the tool attempts AXFR against each discovered nameserver but success requires misconfigured DNS.

### crt.sh Returns No Subdomains

The crt.sh API may be rate-limited or down. Subfinder (if installed) provides a more reliable subdomain enumeration source.

---

## 22. Appendix A — Hashcat Mode Reference

Common hash modes for use with `-m`:

| Mode | Hash Type |
|------|-----------|
| 0 | MD5 |
| 100 | SHA1 |
| 300 | MySQL4.1/MySQL5 |
| 400 | phpass (WordPress, Joomla, phpBB3) |
| 500 | md5crypt ($1$) |
| 900 | MD4 |
| 1000 | NTLM |
| 1400 | SHA-256 |
| 1700 | SHA-512 |
| 1800 | sha512crypt ($6$) |
| 2100 | Domain Cached Credentials 2 (DCC2, MS Cache2) |
| 22000 | WPA-PBKDF2-PMKID+EAPOL |
| 2500 | WPA-EAPOL-PBKDF2 (legacy) |
| 3000 | LM |
| 3100 | Oracle 7-10g |
| 3200 | bcrypt ($2*$) |
| 5500 | NetNTLMv1 / NetNTLMv1+ESS |
| 5600 | NetNTLMv2 |
| 7300 | IPMI2 RAKP HMAC-SHA1 |
| 7500 | Kerberos 5 AS-REQ Pre-Auth (etype 23) |
| 8600 | Lotus Notes/Domino 5 |
| 9600 | MS Office 2013 |
| 11300 | Bitcoin/Litecoin wallet.dat |
| 13100 | Kerberos 5 TGS-REP (etype 23) |
| 15300 | DPAPI masterkey v1 |
| 16800 | WPA-PMKID-PBKDF2 |
| 16900 | Ansible vault |
| 22100 | BitLocker |

Full list: `hashcat --example-hashes` or run option 10 in the hashcat menu.

---

## 23. Appendix B — Nmap Flag Reference

| Flag | Description |
|------|-------------|
| `-T4` | Aggressive timing template (faster) |
| `-Pn` | Skip host discovery (treat all hosts as online) |
| `-p-` | Scan all 65535 ports |
| `-sV` | Service/version detection |
| `-sC` | Run default NSE scripts |
| `-sS` | TCP SYN scan (stealth) |
| `-sU` | UDP scan |
| `-A` | Aggressive: OS detection, version, scripts, traceroute |
| `-sn` | Ping scan only (no port scan) |
| `--top-ports N` | Scan top N most common ports |
| `--script vuln` | Run vulnerability detection scripts |
| `-oN file` | Output to normal format file |

---

## 24. Appendix C — Report File Naming Conventions

Complete mapping of every report type:

| Operation | File Pattern |
|-----------|-------------|
| Target profile | `{ts}_{target}_profile.txt` |
| Nmap scan | `{ts}_{target}_nmap.txt` |
| DNS intelligence | `{ts}_{target}_dns.txt` |
| Web footprinting | `{ts}_{target}_web.txt` |
| Packet capture | `{ts}_{interface}_capture.pcap` |
| WHOIS (extended) | `{ts}_{target}_whois.txt` |
| Subdomain enum | `{ts}_{domain}_subfinder.txt` |
| Zone transfer | `{ts}_{domain}_zone_transfer_{ns}.txt` |
| WhatWeb | `{ts}_{target}_whatweb.json` |
| Airmon start | `{ts}_{iface}_airmon_start.txt` |
| Airmon stop | `{ts}_{iface}_airmon_stop.txt` |
| Airmon check kill | `{ts}_airmon_check_kill_processes.txt` |
| Airodump capture | `{ts}_{iface}_airodump.cap` |
| Airodump session | `{ts}_{iface}_airodump_session.txt` |
| Besside capture | `{ts}_{iface}_besside.cap` |
| Besside session | `{ts}_{iface}_besside_session.txt` |
| Wash scan | `{ts}_{iface}_wash_scan.txt` |
| Deauth | `{ts}_{bssid}_aireplay_deauth.txt` |
| Reaver WPS | `{ts}_{bssid}_reaver_wps.txt` |
| HCXTools conversion | `{ts}_{stem}_hcxtools.hc22000` |
| HCXTools log | `{ts}_{stem}_hcxtools_convert.txt` |
| Hashcat output | `{ts}_{stem}_hashcat.txt` |
| Hashcat session | `{ts}_{stem}_hashcat_session.txt` |
| Hashcat benchmark | `{ts}_benchmark_hashcat_benchmark.txt` |
| Hashcat example hashes | `{ts}_{mode}_hashcat_example_hashes.txt` |
| Hashcat show | `{ts}_{stem}_hashcat_show.txt` |
| Hashcat restore | `{ts}_{session}_hashcat_restore.txt` |
| Hashcat custom | `{ts}_custom_hashcat_custom.txt` |
| Hash identify | `{ts}_{hash}_hash_identify.txt` |
| PhoneInfoga | `{ts}_{phone}_phoneinfoga.txt` |
| SpiderFoot | `{ts}_{target}_spiderfoot_{format}.txt` |
| StormBreaker | `{ts}_{target}_stormbreaker.txt` |
| Holehe | `{ts}_{email}_holehe.txt` |
| Osintgram | `{ts}_{target}_osintgram_{cmd}.txt` |
| Individual workflow | `{ts}_{target}_individual_{profile}.txt` |
| Service control | `{ts}_{service}_{action}.txt` |
| IW list | `{ts}_interfaces_iw_list.txt` |
