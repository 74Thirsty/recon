# Recon by C. Hirschauer

`Recon` is now a full-fledged, Python-driven OSINT workstation that pulls together the
most useful reconnaissance workflows into a single interactive terminal interface.
From one launch command you can profile targets, run tailored Nmap scans, capture
packets, interrogate DNS, enumerate subdomains, fingerprint web stacks, and export
artifact-rich reports for later analysis.

## Highlights

- **Smart target profiling** – Resolve domains/IPs, run WHOIS, geolocate IPs, fetch HTTP
  previews, and capture DNS summaries in one pass.
- **Nmap scanning arsenal** – Pick from tuned profiles (quick, full, service detection,
  aggressive, vuln scripts) or provide custom arguments and automatically archive the
  output under `reports/`.
- **DNS & subdomain intelligence** – Pull record sets, attempt zone transfers, and
  enumerate subdomains via Subfinder or the public crt.sh API.
- **Web footprinting toolkit** – Inspect HTTP headers, capture page titles, and (when
  available) run WhatWeb fingerprinting with JSON logs.
- **Packet capture & monitoring** – Browse available interfaces, set capture filters, and
  write `.pcap` files with a single keystroke to stop recording.
- **Utility toolbox** – Validate IPs/domains, resolve hosts, and perform reverse lookups.
- **OSINT automation** – Launch PhoneInfoga, SpiderFoot, StormBreaker, Holehe, and
  Osintgram directly from the toolkit with automatic report export.
- **Dependency concierge** – Check required/optional tooling status and trigger guided
  installation attempts from inside the app.

All results are written to timestamped files inside `reports/`, making it easy to track
findings or hand them off to teammates.

## Requirements

- **Python 3.8+** (the launcher automatically locates `python3` or `python`).
- **Core tools** (auto-install prompts available on Linux/macOS):
  - `nmap`
  - `tshark`
- **Optional enrichments** (detected automatically, install recommended):
  - `figlet` – ASCII art banner
  - `whois` – WHOIS lookups
  - `dig`/`nslookup` – detailed DNS queries
  - `whatweb` – web technology fingerprinting
  - `subfinder` – high-fidelity subdomain enumeration
  - `phoneinfoga`, `spiderfoot`, `stormbreaker`, `holehe`, `osintgram` – advanced OSINT
    tooling surfaced in the dedicated automation menu (manual installation guidance shown
    in-app when missing)

If automatic installation is not possible, the app shows the exact package names to
install for `apt`, `yum/dnf`, `pacman`, `apk`, or `brew`.

## Getting Started

```bash
# Clone and enter the project
git clone https://github.com/74Thirsty/recon.git
cd recon

# Make the launcher executable (first run only)
chmod +x recon.sh

# Fire up the toolkit
./recon.sh
```

On startup the banner appears, followed by a dependency health report and the main menu.
Pick any action by number, follow the prompts, and watch results stream live while being
written to disk.

### Running directly with Python

```bash
python3 recon.py
```

## Reports

Every action creates a timestamped artifact under `reports/`:

- `*_profile.txt` – complete target intelligence packages
- `*_nmap.txt` – raw Nmap output
- `*_dns.txt` – DNS record/subdomain details
- `*_web.txt` – HTTP/Web technology notes
- `*_capture.pcap` – packet capture files
- `*_whois.txt` / `zone_transfer_*.txt` – extended WHOIS / zone transfer logs
- `whatweb` and other integrations write supplementary JSON/text alongside their reports

Feel free to add `reports/` to your ignore list if you keep the repo clean (a starter
`.gitignore` is included).

## Tips for Effective Use

- Start with **Smart target profile** to collect baseline intel before deeper dives.
- Use the **Dependency health** menu whenever you switch machines; it keeps tooling
  consistent and suggests install commands when something is missing.
- Pair Nmap scans with subsequent **Web footprinting** to quickly understand exposed
  services.
- When subfinder is unavailable, the app gracefully falls back to crt.sh so you never
  lose visibility into certificate-derived subdomains.
- Explore the **OSINT automation suite** to fan out to PhoneInfoga, SpiderFoot,
  StormBreaker, Holehe, and Osintgram while keeping all transcripts under `reports/`.

## Contributing

1. Fork the repository and create a feature branch.
2. Run `./recon.sh` and exercise the new feature before submitting.
3. Submit a pull request describing the enhancement or bug fix.

Pull requests for new integrations, reporting formats, or workflow improvements are very
welcome.

## License

MIT – see the [LICENSE](LICENSE) file for details.
