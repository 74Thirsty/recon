#!/usr/bin/env python3
"""Advanced interactive OSINT and network reconnaissance helper."""
from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


REPORTS_DIR = Path(__file__).resolve().parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ToolMetadata:
    """Metadata describing how to install a tool across common platforms."""

    friendly_name: str
    packages: Dict[str, str]
    optional: bool = False


class DependencyManager:
    """Handle tool availability checks and optional installation flows."""

    def __init__(self) -> None:
        self.tools: Dict[str, ToolMetadata] = {
            "nmap": ToolMetadata("Nmap", {"apt": "nmap", "yum": "nmap", "brew": "nmap"}),
            "tshark": ToolMetadata(
                "TShark", {"apt": "wireshark", "yum": "wireshark", "brew": "wireshark"}
            ),
            "figlet": ToolMetadata("Figlet", {"apt": "figlet", "yum": "figlet", "brew": "figlet"}, optional=True),
            "whois": ToolMetadata("Whois", {"apt": "whois", "yum": "whois", "brew": "whois"}, optional=True),
            "dig": ToolMetadata(
                "Dig", {"apt": "dnsutils", "yum": "bind-utils", "brew": "bind"}, optional=True
            ),
            "nslookup": ToolMetadata(
                "Nslookup", {"apt": "dnsutils", "yum": "bind-utils", "brew": "bind"}, optional=True
            ),
            "whatweb": ToolMetadata(
                "WhatWeb", {"apt": "whatweb", "yum": "whatweb", "brew": "whatweb"}, optional=True
            ),
            "subfinder": ToolMetadata(
                "Subfinder", {"apt": "subfinder", "yum": "subfinder", "brew": "subfinder"}, optional=True
            ),
        }

    def tool_available(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def ensure_tool(self, tool: str, *, interactive: bool = True) -> bool:
        metadata = self.tools.get(tool)
        if metadata is None:
            return shutil.which(tool) is not None

        if self.tool_available(tool):
            return True

        message = f"[!] {metadata.friendly_name} ({tool}) is not installed."
        if metadata.optional:
            message += " This feature is optional but recommended."
        print(message)

        if not interactive:
            return False

        response = input("Attempt automatic installation? [y/N]: ").strip().lower()
        if response != "y":
            print("Skipped automatic installation. Please install manually using your package manager.")
            return False

        if not self._attempt_install(tool, metadata.packages):
            print("[ERROR] Unable to install automatically. Please install manually.")
            return False

        if self.tool_available(tool):
            print(f"[INFO] {metadata.friendly_name} installed successfully.")
            return True

        print(f"[WARNING] {metadata.friendly_name} still not detected after installation attempt.")
        return False

    def _attempt_install(self, tool: str, packages: Dict[str, str]) -> bool:
        system = platform.system()
        package_manager = None
        if system == "Linux":
            for candidate in ("apt", "apt-get", "dnf", "yum", "pacman", "apk"):
                if shutil.which(candidate):
                    package_manager = candidate
                    break
        elif system == "Darwin":
            if shutil.which("brew"):
                package_manager = "brew"
        else:
            print("[ERROR] Automatic installation is only supported on Linux or macOS.")
            return False

        if package_manager is None:
            print("[ERROR] Could not determine a supported package manager.")
            return False

        package_name = packages.get(package_manager)
        if package_name is None:
            # Fallback to a generic package if available
            package_name = packages.get("apt") or packages.get("brew") or packages.get("yum")
            if package_name is None:
                print("[ERROR] No package mapping found for this platform.")
                return False

        install_cmd: List[str]
        if package_manager in {"apt", "apt-get", "dnf", "yum"}:
            install_cmd = ["sudo", package_manager, "install", "-y", package_name]
        elif package_manager == "pacman":
            install_cmd = ["sudo", "pacman", "-S", package_name, "--noconfirm"]
        elif package_manager == "apk":
            install_cmd = ["sudo", "apk", "add", package_name]
        elif package_manager == "brew":
            install_cmd = ["brew", "install", package_name]
        else:
            print("[ERROR] Unsupported package manager for automatic installation.")
            return False

        print("[INFO] Running:", " ".join(install_cmd))
        try:
            subprocess.run(install_cmd, check=True)
        except subprocess.CalledProcessError as exc:
            print(f"[ERROR] Installation command failed with exit code {exc.returncode}.")
            return False
        except FileNotFoundError:
            print("[ERROR] Installation command not found. Ensure the package manager is available.")
            return False
        return True

    def startup_check(self) -> None:
        print("\n[+] Checking key dependencies...\n")
        for tool in ("nmap", "tshark"):
            available = self.tool_available(tool)
            status = "Available" if available else "Missing"
            print(f" - {tool:<9} : {status}")
        print("\nOptional tooling status:")
        for tool, meta in self.tools.items():
            if tool in {"nmap", "tshark"}:
                continue
            status = "Available" if self.tool_available(tool) else "Missing"
            suffix = " (optional)" if meta.optional else ""
            print(f" - {tool:<9} : {status}{suffix}")
        print()


def clear_screen() -> None:
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def display_banner() -> None:
    clear_screen()
    print("========================================")
    print("        RECON by C. Hirschauer")
    print("========================================\n")

    if shutil.which("figlet"):
        try:
            subprocess.run(["figlet", "-f", "slant", "RECON"], check=False)
            print()
        except Exception:
            pass


class ReconApp:
    def __init__(self) -> None:
        self.dependency_manager = DependencyManager()
        self.ssl_context = ssl.create_default_context()

    def run(self) -> None:
        display_banner()
        self.dependency_manager.startup_check()

        while True:
            self.print_main_menu()
            choice = input("Select an option: ").strip()
            handlers = {
                "1": self.comprehensive_profile,
                "2": self.nmap_menu,
                "3": self.dns_menu,
                "4": self.web_menu,
                "5": self.packet_capture_menu,
                "6": self.utility_menu,
                "7": self.dependencies_menu,
                "0": self.exit_app,
            }
            handler = handlers.get(choice)
            if handler:
                try:
                    handler()
                except KeyboardInterrupt:
                    print("\n[!] Operation cancelled by user. Returning to main menu.\n")
                except Exception as exc:  # pragma: no cover - defensive logging
                    print(f"[ERROR] An unexpected error occurred: {exc}")
            else:
                print("[!] Invalid selection. Please choose a valid option.\n")

    def print_main_menu(self) -> None:
        print("==============================")
        print("  Advanced Reconnaissance Hub")
        print("==============================")
        print("1) Smart target profile (IP/Domain intelligence)")
        print("2) Nmap scanning arsenal")
        print("3) DNS + subdomain intelligence")
        print("4) Web footprinting toolkit")
        print("5) Packet capture & monitoring")
        print("6) Utility toolbox")
        print("7) Dependency health & installation")
        print("0) Exit")
        print("==============================")

    # ------------------------------------------------------------------
    # Comprehensive recon
    # ------------------------------------------------------------------
    def comprehensive_profile(self) -> None:
        target = input("Enter an IP address or domain: ").strip()
        if not target:
            print("[!] No target provided.\n")
            return

        report_path = self._create_report_path("profile", target)
        print(f"[INFO] Writing profile to {report_path}\n")
        lines: List[str] = []
        lines.append(self._format_header("Target Profile", target))
        lines.append(self._basic_resolution(target))
        if self._is_ip(target):
            lines.append(self._ip_geolocation(target))
            lines.append(self._reverse_dns_lookup(target))
        else:
            lines.append(self._http_preview(target))
        lines.append(self._whois_lookup(target))
        lines.append(self._dns_records_summary(target))
        content = "\n".join(section for section in lines if section)
        report_path.write_text(content)
        print(content)
        print("[+] Profile complete.\n")

    # ------------------------------------------------------------------
    # Nmap scanning
    # ------------------------------------------------------------------
    def nmap_menu(self) -> None:
        if not self.dependency_manager.ensure_tool("nmap"):
            print("[!] Nmap is required for this feature.\n")
            return

        print("\n========================")
        print(" Nmap Scanning Profiles")
        print("========================")
        print("1) Quick scan (top 1000 ports)")
        print("2) Full TCP scan (all ports)")
        print("3) Service & script scan (-sV -sC)")
        print("4) Aggressive scan with OS detection (-A)")
        print("5) Vulnerability scripts (--script vuln)")
        print("6) Custom command")
        print("0) Back to main menu")
        print("========================")

        choice = input("Select scan profile: ").strip()
        if choice == "0":
            return

        target = input("Enter target (IP, CIDR, or hostname): ").strip()
        if not target:
            print("[!] No target specified.\n")
            return

        output_file = self._create_report_path("nmap", target)
        base_cmd = ["nmap", "-oN", str(output_file)]
        if choice == "1":
            cmd = base_cmd + ["-T4", "-Pn", target]
        elif choice == "2":
            cmd = base_cmd + ["-T4", "-Pn", "-p-", target]
        elif choice == "3":
            cmd = base_cmd + ["-T4", "-Pn", "-sV", "-sC", target]
        elif choice == "4":
            cmd = base_cmd + ["-T4", "-A", target]
        elif choice == "5":
            cmd = base_cmd + ["-T4", "-Pn", "--script", "vuln", target]
        elif choice == "6":
            custom = input("Enter custom Nmap arguments (excluding target and -oN): ").strip()
            if custom:
                cmd = base_cmd + shlex.split(custom) + [target]
            else:
                cmd = base_cmd + [target]
        else:
            print("[!] Invalid selection.\n")
            return

        print(f"[INFO] Executing: {' '.join(cmd)}")
        try:
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
                assert proc.stdout is not None
                for line in proc.stdout:
                    print(line, end="")
                proc.wait()
                if proc.returncode not in (0, None):
                    print(f"\n[WARNING] Nmap exited with code {proc.returncode}.")
        except FileNotFoundError:
            print("[ERROR] Nmap command not found.\n")
            return
        print(f"\n[+] Results saved to {output_file}\n")

    # ------------------------------------------------------------------
    # DNS Intelligence
    # ------------------------------------------------------------------
    def dns_menu(self) -> None:
        target = input("Enter a domain name: ").strip()
        if not target:
            print("[!] Domain is required.\n")
            return
        report_path = self._create_report_path("dns", target)
        sections = [self._format_header("DNS Intelligence", target)]
        sections.append(self._dns_records_summary(target))
        sections.append(self._subdomain_enumeration(target))
        sections.append(self._zone_transfer_attempt(target))
        content = "\n".join(section for section in sections if section)
        report_path.write_text(content)
        print(content)
        print(f"[+] DNS intelligence saved to {report_path}\n")

    # ------------------------------------------------------------------
    # Web Footprinting
    # ------------------------------------------------------------------
    def web_menu(self) -> None:
        target = input("Enter a domain or URL: ").strip()
        if not target:
            print("[!] Target is required.\n")
            return

        normalized_url = self._normalize_url(target)
        report_path = self._create_report_path("web", normalized_url)
        sections = [self._format_header("Web Footprinting", normalized_url)]
        sections.append(self._http_preview(normalized_url, fetch_body=True))
        sections.append(self._technology_fingerprint(normalized_url))
        content = "\n".join(section for section in sections if section)
        report_path.write_text(content)
        print(content)
        print(f"[+] Web footprinting saved to {report_path}\n")

    # ------------------------------------------------------------------
    # Packet capture
    # ------------------------------------------------------------------
    def packet_capture_menu(self) -> None:
        if not self.dependency_manager.ensure_tool("tshark"):
            print("[!] TShark is required for packet capture.\n")
            return

        interface = self._choose_interface()
        if not interface:
            print("[!] No interface selected.\n")
            return

        capture_filter = input("Capture filter (BPF syntax, optional): ").strip()
        duration = input("Capture duration in seconds (leave blank for manual stop): ").strip()
        report_path = self._create_report_path("capture", interface, extension="pcap")

        cmd = ["tshark", "-i", interface, "-w", str(report_path)]
        if capture_filter:
            cmd += ["-f", capture_filter]
        if duration.isdigit():
            cmd += ["-a", f"duration:{duration}"]

        print(f"[INFO] Starting capture on interface {interface}. Output -> {report_path}")
        print("Press Enter to stop the capture early.\n")

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        stopper = threading.Thread(target=self._capture_output_stream, args=(process,))
        stopper.daemon = True
        stopper.start()

        try:
            input()
        except KeyboardInterrupt:
            pass
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        print(f"[+] Capture saved to {report_path}\n")

    def _capture_output_stream(self, process: subprocess.Popen) -> None:
        if process.stdout is None:
            return
        for line in process.stdout:
            print(line.rstrip())

    # ------------------------------------------------------------------
    # Utility toolbox
    # ------------------------------------------------------------------
    def utility_menu(self) -> None:
        while True:
            print("\nUtility Toolbox")
            print("----------------")
            print("1) Validate IP address")
            print("2) Validate domain name")
            print("3) Reverse DNS lookup")
            print("4) Resolve domain to IPs")
            print("0) Back to main menu")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                target = input("IP to validate: ").strip()
                print("Valid" if self._is_ip(target) else "Invalid")
            elif choice == "2":
                target = input("Domain to validate: ").strip()
                print("Valid" if self._is_domain(target) else "Invalid")
            elif choice == "3":
                target = input("IP address: ").strip()
                print(self._reverse_dns_lookup(target))
            elif choice == "4":
                target = input("Domain: ").strip()
                print(self._resolve_domain(target))
            elif choice == "0":
                print()
                break
            else:
                print("[!] Invalid selection.\n")

    # ------------------------------------------------------------------
    # Dependency helper
    # ------------------------------------------------------------------
    def dependencies_menu(self) -> None:
        self.dependency_manager.startup_check()
        tool = input("Enter tool name to attempt installation (blank to return): ").strip()
        if not tool:
            return
        if tool not in self.dependency_manager.tools:
            print("[!] Unknown tool.\n")
            return
        self.dependency_manager.ensure_tool(tool)

    # ------------------------------------------------------------------
    def exit_app(self) -> None:
        print("\nGoodbye and happy hunting!\n")
        raise SystemExit(0)

    # ------------------------------------------------------------------
    # Helper functions
    # ------------------------------------------------------------------
    def _format_header(self, title: str, target: str) -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        return textwrap.dedent(
            f"""
            ========================================
            {title}
            Target   : {target}
            Generated: {timestamp}
            ========================================
            """.strip("\n")
        )

    def _basic_resolution(self, target: str) -> str:
        lines = ["\n[+] Resolution"]
        if self._is_ip(target):
            lines.append(f" - Detected as IPv{ipaddress.ip_address(target).version}")
            lines.append(self._reverse_dns_lookup(target))
        else:
            lines.append(self._resolve_domain(target))
        return "\n".join(lines)

    def _whois_lookup(self, target: str) -> str:
        lines = ["\n[+] WHOIS"]
        if not self.dependency_manager.tool_available("whois"):
            lines.append("Whois utility not detected. Install 'whois' to enable this feature.")
            return "\n".join(lines)
        cmd = ["whois", target]
        try:
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        except Exception as exc:
            lines.append(f"WHOIS lookup failed: {exc}")
            return "\n".join(lines)

        data = output.stdout.strip() or output.stderr.strip()
        if not data:
            lines.append("No WHOIS data returned.")
            return "\n".join(lines)

        entries = data.splitlines()
        preview_lines = entries[:60]
        lines.extend(preview_lines)
        if len(entries) > 60:
            log_path = self._create_report_path("whois", target)
            log_path.write_text(data)
            lines.append("...")
            lines.append(f"Full WHOIS output saved to {log_path}")
        return "\n".join(lines)

    def _resolve_domain(self, domain: str) -> str:
        if not self._is_domain(domain):
            return "[!] Invalid domain name provided."
        try:
            infos = socket.getaddrinfo(domain, None)
            addresses = sorted({info[4][0] for info in infos})
            if not addresses:
                return "[!] No addresses resolved for domain."
            formatted = "\n".join(f" - {addr}" for addr in addresses)
            return f"Resolved addresses:\n{formatted}"
        except socket.gaierror as exc:
            return f"[!] DNS resolution failed: {exc}"

    def _reverse_dns_lookup(self, ip_addr: str) -> str:
        if not self._is_ip(ip_addr):
            return "[!] Invalid IP address provided."
        try:
            host, aliases, _ = socket.gethostbyaddr(ip_addr)
            names = [host] + aliases
            formatted = "\n".join(f" - {name}" for name in dict.fromkeys(names))
            return f"Reverse DNS results:\n{formatted}"
        except socket.herror:
            return "Reverse DNS: no PTR record found."

    def _ip_geolocation(self, ip_addr: str) -> str:
        if not self._is_ip(ip_addr):
            return ""
        url = f"https://ipinfo.io/{ip_addr}/json"
        print("[INFO] Querying IP geolocation from ipinfo.io...")
        try:
            with urllib.request.urlopen(url, timeout=10, context=self.ssl_context) as response:
                data = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            return f"IP Geolocation lookup failed: {exc}"
        lines = ["\n[+] IP Geolocation (ipinfo.io)"]
        for key in ("ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"):
            if key in data:
                lines.append(f" - {key.title()}: {data[key]}")
        return "\n".join(lines)

    def _http_preview(self, target: str, *, fetch_body: bool = False) -> str:
        url = self._normalize_url(target)
        print(f"[INFO] Fetching {url}...")
        request = urllib.request.Request(url, headers={"User-Agent": "Recon-Toolkit/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=15, context=self.ssl_context) as response:
                status = response.status
                reason = response.reason
                headers = dict(response.headers)
                body = response.read(8192) if fetch_body else b""
        except urllib.error.URLError as exc:
            return f"HTTP request failed: {exc}"

        lines = ["\n[+] HTTP Preview"]
        lines.append(f"Status: {status} {reason}")
        for header in ("Server", "X-Powered-By", "Content-Type", "Set-Cookie"):
            if header in headers:
                value = headers[header]
                if isinstance(value, list):
                    value = "; ".join(value)
                lines.append(f"{header}: {value}")
        if fetch_body:
            title = self._extract_title(body.decode("utf-8", errors="ignore"))
            if title:
                lines.append(f"Page Title: {title}")
        return "\n".join(lines)

    def _extract_title(self, html: str) -> Optional[str]:
        match = re.search(r"<title>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(1)).strip()
        return None

    def _technology_fingerprint(self, url: str) -> str:
        lines = ["\n[+] Technology Fingerprinting"]
        if self.dependency_manager.tool_available("whatweb"):
            report_path = self._create_report_path("whatweb", url)
            cmd = ["whatweb", url, "--log-json", str(report_path.with_suffix(".json"))]
            print(f"[INFO] Running WhatWeb -> {report_path}")
            try:
                output = subprocess.run(cmd, capture_output=True, text=True, check=False)
                lines.append(output.stdout.strip() or "See JSON log for details.")
                lines.append(f"WhatWeb JSON log saved to {report_path.with_suffix('.json')}")
            except Exception as exc:
                lines.append(f"WhatWeb execution failed: {exc}")
        else:
            lines.append("WhatWeb not available. Showing header-derived hints only.")
        return "\n".join(lines)

    def _dns_records_summary(self, domain: str) -> str:
        if not self._is_domain(domain) and not self._is_ip(domain):
            return ""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        lines = ["\n[+] DNS Records"]
        for record in record_types:
            output = self._query_dns(domain, record)
            if output:
                lines.append(f"{record} records:\n{output}")
            else:
                lines.append(f"{record} records: None found")
        return "\n".join(lines)

    def _query_dns(self, domain: str, record_type: str) -> str:
        dig_available = self.dependency_manager.tool_available("dig")
        nslookup_available = self.dependency_manager.tool_available("nslookup")
        if dig_available:
            cmd = ["dig", "+short", domain, record_type]
        elif nslookup_available:
            cmd = ["nslookup", "-type=" + record_type, domain]
        else:
            # fallback using socket for basic A/AAAA
            if record_type in {"A", "AAAA"}:
                return self._resolve_domain(domain)
            return "[!] dig/nslookup not available."
        try:
            output = subprocess.run(cmd, capture_output=True, text=True, check=False)
            data = output.stdout.strip()
            return data or ""
        except Exception as exc:
            return f"DNS query failed: {exc}"

    def _subdomain_enumeration(self, domain: str) -> str:
        lines = ["\n[+] Subdomain Enumeration"]
        if self.dependency_manager.tool_available("subfinder"):
            output_file = self._create_report_path("subfinder", domain)
            cmd = ["subfinder", "-d", domain, "-o", str(output_file)]
            print(f"[INFO] Running Subfinder -> {output_file}")
            try:
                subprocess.run(cmd, check=False)
                lines.append(f"Subfinder results saved to {output_file}")
            except Exception as exc:
                lines.append(f"Subfinder execution failed: {exc}")
        else:
            results = self._fetch_crtsh(domain)
            if results:
                formatted = "\n".join(f" - {entry}" for entry in results)
                lines.append("crt.sh results:\n" + formatted)
            else:
                lines.append("No subdomains found or crt.sh unavailable.")
        return "\n".join(lines)

    def _fetch_crtsh(self, domain: str) -> List[str]:
        query = urllib.parse.quote(f"%.{domain}")
        url = f"https://crt.sh/?q={query}&output=json"
        try:
            with urllib.request.urlopen(url, timeout=30, context=self.ssl_context) as response:
                data = response.read().decode("utf-8", errors="ignore")
        except Exception:
            return []
        candidates: List[str] = []
        try:
            items = json.loads(data)
            if isinstance(items, list):
                for item in items:
                    name = item.get("name_value")
                    if not name:
                        continue
                    for entry in str(name).split("\n"):
                        entry = entry.strip()
                        if entry and entry.endswith(domain):
                            candidates.append(entry)
        except json.JSONDecodeError:
            # Fallback: crt.sh may return multiple JSON objects separated by newlines
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                name = item.get("name_value")
                if not name:
                    continue
                for entry in str(name).split("\n"):
                    entry = entry.strip()
                    if entry and entry.endswith(domain):
                        candidates.append(entry)
        unique = sorted(set(candidates))
        return unique[:200]

    def _zone_transfer_attempt(self, domain: str) -> str:
        nameservers_output = self._query_dns(domain, "NS")
        if not nameservers_output or "[!]" in nameservers_output:
            return ""
        nameservers = [line.strip().rstrip('.') for line in nameservers_output.splitlines() if line.strip()]
        if not nameservers:
            return ""
        lines = ["\n[+] Zone Transfer Attempts"]
        for ns in nameservers:
            cmd = ["dig", "@" + ns, domain, "AXFR"]
            if not self.dependency_manager.tool_available("dig"):
                lines.append("dig not available for zone transfer testing.")
                break
            try:
                output = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
                if "Transfer failed" in output.stdout or "connection failed" in output.stdout:
                    lines.append(f" - {ns}: Transfer failed or refused.")
                elif output.stdout.strip():
                    log_path = self._create_report_path(f"zone_transfer_{ns}", domain)
                    log_path.write_text(output.stdout)
                    lines.append(f" - {ns}: Potential zone transfer! Data saved to {log_path}")
                else:
                    lines.append(f" - {ns}: No data returned.")
            except subprocess.TimeoutExpired:
                lines.append(f" - {ns}: Timed out.")
        return "\n".join(lines)

    def _choose_interface(self) -> Optional[str]:
        print("[INFO] Enumerating capture interfaces with TShark...")
        try:
            result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=False)
        except Exception as exc:
            print(f"[ERROR] Unable to list interfaces: {exc}")
            return None
        interfaces = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            interfaces.append(line)
            print(line)
        if not interfaces:
            print("[!] No interfaces reported by TShark.")
            return None
        selection = input("Select interface (number or name): ").strip()
        if not selection:
            return None
        if selection.isdigit():
            return selection
        return selection

    def _create_report_path(self, prefix: str, target: str, *, extension: str = "txt") -> Path:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", target)[:50] or "target"
        filename = f"{timestamp}_{safe_target}_{prefix}.{extension}"
        return REPORTS_DIR / filename

    def _normalize_url(self, target: str) -> str:
        if re.match(r"^https?://", target, re.IGNORECASE):
            return target
        return f"https://{target}"

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_domain(self, value: str) -> bool:
        if not value or len(value) > 253:
            return False
        pattern = re.compile(
            r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)" r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
        )
        return bool(pattern.match(value))


def main() -> None:
    app = ReconApp()
    try:
        app.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting...\n")


if __name__ == "__main__":
    main()
