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
    executables: Optional[List[str]] = None
    install_hint: Optional[str] = None


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
            "phoneinfoga": ToolMetadata(
                friendly_name="PhoneInfoga",
                packages={},
                optional=True,
                executables=["phoneinfoga"],
                install_hint=(
                    "Install via pip (pip3 install phoneinfoga) or follow the instructions "
                    "at https://github.com/sundowndev/PhoneInfoga."
                ),
            ),
            "spiderfoot": ToolMetadata(
                friendly_name="SpiderFoot",
                packages={},
                optional=True,
                executables=["sfcli", "spiderfoot", "sfcli.py"],
                install_hint=(
                    "SpiderFoot does not have a native package in most distributions. Clone the "
                    "project from https://github.com/smicallef/spiderfoot and expose sfcli.py on "
                    "your PATH."
                ),
            ),
            "stormbreaker": ToolMetadata(
                friendly_name="StormBreaker",
                packages={},
                optional=True,
                executables=["stormbreaker", "storm-breaker", "stormbreaker.py"],
                install_hint=(
                    "StormBreaker typically runs from its Git repository. Clone "
                    "https://github.com/ultrasecurity/Storm-Breaker and expose the launcher "
                    "script or provide its path manually."
                ),
            ),
            "holehe": ToolMetadata(
                friendly_name="Holehe",
                packages={},
                optional=True,
                executables=["holehe"],
                install_hint=(
                    "Install via pip (pip3 install holehe) or consult "
                    "https://github.com/megadose/holehe for manual setup steps."
                ),
            ),
            "osintgram": ToolMetadata(
                friendly_name="Osintgram",
                packages={},
                optional=True,
                executables=["osintgram"],
                install_hint=(
                    "Osintgram is normally executed from its repository. Clone "
                    "https://github.com/Datalux/Osintgram and run main.py with python3, or create "
                    "an 'osintgram' wrapper in your PATH."
                ),
            ),
        }

    def tool_available(self, tool: str) -> bool:
        if tool in self.tools:
            return self.command_prefix(tool) is not None
        return shutil.which(tool) is not None

    def command_prefix(self, tool: str) -> Optional[List[str]]:
        metadata = self.tools.get(tool)
        candidates = metadata.executables if metadata and metadata.executables else [tool]
        for candidate in candidates:
            path = shutil.which(candidate)
            if not path:
                continue
            if path.endswith(".py"):
                python = sys.executable or shutil.which("python3") or shutil.which("python")
                if python:
                    return [python, path]
            return [path]
        return None

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

        if not metadata.packages:
            if metadata.install_hint:
                print(metadata.install_hint)
            else:
                print("Automatic installation is not configured for this tool. Please install it manually.")
            return False

        if not interactive:
            if metadata.install_hint:
                print(metadata.install_hint)
            return False

        response = input("Attempt automatic installation? [y/N]: ").strip().lower()
        if response != "y":
            print("Skipped automatic installation. Please install manually using your package manager.")
            return False

        if not self._attempt_install(tool, metadata.packages):
            print("[ERROR] Unable to install automatically. Please install manually.")
            if metadata.install_hint:
                print(metadata.install_hint)
            return False

        if self.tool_available(tool):
            print(f"[INFO] {metadata.friendly_name} installed successfully.")
            return True

        print(f"[WARNING] {metadata.friendly_name} still not detected after installation attempt.")
        if metadata.install_hint:
            print(metadata.install_hint)
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
                "6": self.osint_menu,
                "7": self.utility_menu,
                "8": self.dependencies_menu,
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
        print("6) OSINT automation & social recon")
        print("7) Utility toolbox")
        print("8) Dependency health & installation")
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

        primary_url = self._build_url_candidates(target)[0]
        report_path = self._create_report_path("web", primary_url)
        sections = [self._format_header("Web Footprinting", primary_url)]
        sections.append(self._http_preview(target, fetch_body=True))
        sections.append(self._technology_fingerprint(target))
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
    # OSINT automation & specialty tooling
    # ------------------------------------------------------------------
    def osint_menu(self) -> None:
        while True:
            print("\nOSINT Automation Suite")
            print("----------------------")
            print("1) PhoneInfoga phone intelligence")
            print("2) SpiderFoot multi-source reconnaissance")
            print("3) StormBreaker payload/orchestration")
            print("4) Holehe email enumeration")
            print("5) Osintgram Instagram intelligence")
            print("0) Back to main menu")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                self.phoneinfoga_lookup()
            elif choice == "2":
                self.spiderfoot_scan()
            elif choice == "3":
                self.stormbreaker_workflow()
            elif choice == "4":
                self.holehe_lookup()
            elif choice == "5":
                self.osintgram_lookup()
            elif choice == "0":
                print()
                return
            else:
                print("[!] Invalid selection.\n")

    def phoneinfoga_lookup(self) -> None:
        base_cmd = self._get_tool_command("phoneinfoga")
        if not base_cmd:
            return
        number = input("Phone number (E.164 format, e.g. +15551234567): ").strip()
        if not number:
            print("[!] No phone number provided.\n")
            return
        fmt = input("Output format [json/pretty/yaml/csv] (default json): ").strip().lower()
        if not fmt:
            fmt = "json"
        allowed_formats = {"json", "pretty", "yaml", "csv"}
        if fmt not in allowed_formats:
            print("[!] Unknown format supplied. Falling back to json.\n")
            fmt = "json"
        extra_args = input("Additional PhoneInfoga flags (optional): ").strip()
        cmd = list(base_cmd) + ["scan", "-n", number, "-f", fmt]
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("phoneinfoga", number)
        if not output.strip():
            output = "[!] PhoneInfoga returned no data."
        report_path.write_text(output)
        print(f"[+] PhoneInfoga results saved to {report_path}\n")

    def spiderfoot_scan(self) -> None:
        base_cmd = self._get_tool_command("spiderfoot")
        if not base_cmd:
            return
        target = input("Target for SpiderFoot: ").strip()
        if not target:
            print("[!] No target provided.\n")
            return
        target_type = input(
            "Target type [domain/ip/email/asn/phone/netblock/username/name] (leave blank for auto): "
        ).strip().lower()
        modules = input("Comma-separated module IDs (leave blank for defaults): ").strip()
        output_format = input("Output format [csv/json/tsv/sqlite] (default csv): ").strip().lower()
        extra_args = input("Additional SpiderFoot flags (optional): ").strip()

        cmd = list(base_cmd)
        cmd += ["-s", target]
        allowed_types = {"domain", "ip", "email", "asn", "phone", "netblock", "username", "name"}
        if target_type:
            if target_type in allowed_types:
                cmd += ["-t", target_type]
            else:
                print("[!] Unrecognized target type supplied. Add it manually via extra flags if required.")
        if modules:
            cmd += ["-m", modules]
        if not output_format:
            output_format = "csv"
        output_flag_tokens = []
        if extra_args:
            try:
                output_flag_tokens = shlex.split(extra_args)
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        has_output_flag = any(
            token in {"-o", "--output"} or token.startswith("--output=") for token in output_flag_tokens
        )
        if not has_output_flag and output_format:
            cmd += ["-o", output_format]
        cmd.extend(output_flag_tokens)

        output = self._run_command_capture(cmd)
        if output is None:
            return
        label = output_format or "stdout"
        report_path = self._create_report_path(f"spiderfoot_{label}", target)
        if not output.strip():
            output = (
                "[!] SpiderFoot produced no stdout output. Check the specified modules/flags or the tool's logs."
            )
        report_path.write_text(output)
        print(f"[+] SpiderFoot output saved to {report_path}\n")

    def stormbreaker_workflow(self) -> None:
        base_cmd = self._get_tool_command("stormbreaker")
        if not base_cmd:
            return
        descriptor = input("Short label for this StormBreaker run (optional): ").strip() or "stormbreaker"
        extra_args = input(
            "StormBreaker arguments (blank for interactive mode; output will not be captured in interactive mode): "
        ).strip()
        if not extra_args:
            print("[INFO] Launching StormBreaker interactively. Press Ctrl+C to return when finished.\n")
            try:
                subprocess.run(base_cmd, check=False)
            except FileNotFoundError:
                print("[ERROR] StormBreaker command not found.\n")
            except Exception as exc:
                print(f"[ERROR] StormBreaker execution failed: {exc}\n")
            return
        try:
            cmd = list(base_cmd) + shlex.split(extra_args)
        except ValueError as exc:
            print(f"[!] Unable to parse arguments: {exc}\n")
            return
        output = self._run_command_capture(cmd)
        if output is None:
            return
        if not output.strip():
            output = (
                "[!] StormBreaker completed without stdout output. Review any payloads or logs generated by the tool."
            )
        report_path = self._create_report_path("stormbreaker", descriptor)
        report_path.write_text(output)
        print(f"[+] StormBreaker transcript saved to {report_path}\n")

    def holehe_lookup(self) -> None:
        base_cmd = self._get_tool_command("holehe")
        if not base_cmd:
            return
        email_input = input("Email address(es) (comma or space separated): ").strip()
        if not email_input:
            print("[!] No email addresses provided.\n")
            return
        emails = [item for item in re.split(r"[\s,]+", email_input) if item]
        if not emails:
            print("[!] No valid email addresses detected.\n")
            return
        extra_args = input("Additional Holehe flags (applied to all targets, optional): ").strip()
        try:
            extra_tokens = shlex.split(extra_args) if extra_args else []
        except ValueError as exc:
            print(f"[!] Unable to parse extra arguments: {exc}\n")
            return
        chunks: List[str] = []
        for email in emails:
            header = f"===== {email} ====="
            print(f"\n{header}")
            cmd = list(base_cmd) + extra_tokens + [email]
            output = self._run_command_capture(cmd)
            if output is None:
                chunks.append(f"{header}\n[!] Holehe execution failed for this address.")
                continue
            if not output.strip():
                chunks.append(f"{header}\n[!] No output returned. Consult Holehe logs.")
            else:
                chunks.append(f"{header}\n{output.rstrip()}")
        if not chunks:
            print("[!] No results to record.\n")
            return
        report_path = self._create_report_path("holehe", emails[0])
        report_text = "\n\n".join(chunks) + "\n"
        report_path.write_text(report_text)
        print(f"\n[+] Holehe summary saved to {report_path}\n")

    def osintgram_lookup(self) -> None:
        base_cmd = self._get_tool_command("osintgram")
        if not base_cmd:
            return
        username = input("Instagram username/target: ").strip()
        if not username:
            print("[!] No username provided.\n")
            return
        command = input(
            "Osintgram command/module (e.g. info, followers). Leave blank for interactive shell: "
        ).strip()
        extra_args = input("Additional Osintgram flags (optional): ").strip()
        if not command:
            print("[INFO] Launching Osintgram interactive shell. Use 'exit' within the tool to return.\n")
            try:
                subprocess.run(list(base_cmd) + [username], check=False)
            except FileNotFoundError:
                print("[ERROR] Osintgram command not found.\n")
            except Exception as exc:
                print(f"[ERROR] Osintgram execution failed: {exc}\n")
            return
        try:
            extra_tokens = shlex.split(extra_args) if extra_args else []
        except ValueError as exc:
            print(f"[!] Unable to parse extra arguments: {exc}\n")
            return
        cmd = list(base_cmd) + [username, command] + extra_tokens
        output = self._run_command_capture(cmd)
        if output is None:
            return
        if not output.strip():
            output = "[!] Osintgram returned no output. Verify authentication and module support."
        report_path = self._create_report_path(f"osintgram_{command}", username)
        report_path.write_text(output)
        print(f"[+] Osintgram output saved to {report_path}\n")

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
    def _get_tool_command(self, tool: str) -> Optional[List[str]]:
        base_cmd = self.dependency_manager.command_prefix(tool)
        if base_cmd:
            return base_cmd
        metadata = self.dependency_manager.tools.get(tool)
        friendly = metadata.friendly_name if metadata else tool
        self.dependency_manager.ensure_tool(tool, interactive=False)
        manual = input(
            f"Provide the full command to execute {friendly} (blank to cancel): "
        ).strip()
        if not manual:
            print("[!] Command entry cancelled.\n")
            return None
        try:
            return shlex.split(manual)
        except ValueError as exc:
            print(f"[ERROR] Unable to parse command: {exc}\n")
            return None

    def _format_command(self, cmd: List[str]) -> str:
        try:
            return shlex.join(cmd)
        except AttributeError:  # pragma: no cover - Python < 3.8 fallback
            return " ".join(shlex.quote(part) for part in cmd)

    def _run_command_capture(self, cmd: List[str]) -> Optional[str]:
        print(f"[INFO] Executing: {self._format_command(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            print("[ERROR] Command not found. Ensure the tool is on your PATH.\n")
            return None
        except Exception as exc:
            print(f"[ERROR] Failed to execute command: {exc}\n")
            return None
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if stdout:
            print(stdout, end="" if stdout.endswith("\n") else "\n")
        if stderr:
            print(stderr, end="" if stderr.endswith("\n") else "\n")
        if result.returncode not in (0, None):
            print(f"[WARNING] Command exited with code {result.returncode}.\n")
        combined = stdout
        if stderr:
            if combined and not combined.endswith("\n"):
                combined += "\n"
            combined += stderr
        return combined

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
        last_error: Optional[Exception] = None
        for url in self._build_url_candidates(target):
            print(f"[INFO] Fetching {url}...")
            request = urllib.request.Request(url, headers={"User-Agent": "Recon-Toolkit/1.0"})
            try:
                with urllib.request.urlopen(request, timeout=15, context=self.ssl_context) as response:
                    status = response.status
                    reason = response.reason
                    headers = dict(response.headers)
                    body = response.read(8192) if fetch_body else b""
                break
            except urllib.error.URLError as exc:
                last_error = exc
                continue
        else:
            return f"HTTP request failed: {last_error or 'Unable to reach host'}"

        lines = ["\n[+] HTTP Preview"]
        lines.append(f"URL: {url}")
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

    def _technology_fingerprint(self, target: str) -> str:
        lines = ["\n[+] Technology Fingerprinting"]
        if self.dependency_manager.tool_available("whatweb"):
            for candidate in self._build_url_candidates(target):
                report_path = self._create_report_path("whatweb", candidate)
                log_path = report_path.with_suffix(".json")
                cmd = ["whatweb", candidate, "--log-json", str(log_path)]
                print(f"[INFO] Running WhatWeb -> {report_path}")
                try:
                    output = subprocess.run(cmd, capture_output=True, text=True, check=False)
                except Exception as exc:
                    lines.append(f"WhatWeb execution failed: {exc}")
                    break

                if output.returncode not in (0, None) and not output.stdout.strip():
                    # Try the next candidate (e.g. fallback from HTTPS -> HTTP)
                    print(f"[WARNING] WhatWeb returned code {output.returncode} for {candidate}. Trying fallback.")
                    continue

                lines.append(output.stdout.strip() or "See JSON log for details.")
                lines.append(f"WhatWeb JSON log saved to {log_path}")
                break
            else:
                lines.append("WhatWeb did not return data for any URL candidates.")
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
            if record_type in {"A", "AAAA"}:
                return self._resolve_domain(domain)
            return "[!] dig/nslookup not available."

        try:
            output = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=15
            )
        except subprocess.TimeoutExpired:
            return "[!] DNS query timed out."
        except Exception as exc:
            return f"DNS query failed: {exc}"

        data = (output.stdout or "").strip()
        if not data:
            data = (output.stderr or "").strip()
        if not data:
            return ""

        if dig_available:
            return data
        return "\n".join(self._parse_nslookup_output(data, record_type))

    def _parse_nslookup_output(self, raw: str, record_type: str) -> List[str]:
        values: List[str] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lowered = stripped.lower()
            if lowered.startswith(
                (
                    "server:",
                    "address:",
                    "non-authoritative",
                    "authoritative",
                    "name:",
                    "> ",
                    "***",
                )
            ):
                if record_type in {"A", "AAAA"} and lowered.startswith("address:"):
                    value = stripped.split(":", 1)[-1].strip()
                    if value:
                        values.append(value)
                continue

            if " = " in stripped:
                value = stripped.split("=", 1)[1].strip()
            elif record_type in {"A", "AAAA"} and "address" in lowered:
                value = stripped.split(None, 1)[-1].strip()
            else:
                # Fallback: use final token
                value = stripped.split()[-1].strip()

            if not value:
                continue
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            value = value.rstrip('.')
            values.append(value)

        # Remove duplicates while preserving order
        seen = set()
        unique_values = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            unique_values.append(value)
        return unique_values

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
        nameservers = []
        for line in nameservers_output.splitlines():
            candidate = line.strip().rstrip('.')
            if not candidate:
                continue
            if not self._is_domain(candidate):
                continue
            if candidate not in nameservers:
                nameservers.append(candidate)
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

    def _build_url_candidates(self, target: str) -> List[str]:
        target = target.strip()
        if not target:
            return ["https://"]
        if re.match(r"^https?://", target, re.IGNORECASE):
            return [target]
        host = target.lstrip('/')
        return [f"https://{host}", f"http://{host}"]

    def _normalize_url(self, target: str) -> str:
        return self._build_url_candidates(target)[0]

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
