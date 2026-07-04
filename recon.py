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
            "besside-ng": ToolMetadata(
                "Besside-ng",
                {"apt": "aircrack-ng", "yum": "aircrack-ng", "brew": "aircrack-ng"},
                optional=True,
            ),
            "airmon-ng": ToolMetadata(
                "Airmon-ng",
                {"apt": "aircrack-ng", "yum": "aircrack-ng", "brew": "aircrack-ng"},
                optional=True,
                executables=["airmon-ng"],
            ),
            "airodump-ng": ToolMetadata(
                "Airodump-ng",
                {"apt": "aircrack-ng", "yum": "aircrack-ng", "brew": "aircrack-ng"},
                optional=True,
                executables=["airodump-ng"],
            ),
            "aireplay-ng": ToolMetadata(
                "Aireplay-ng",
                {"apt": "aircrack-ng", "yum": "aircrack-ng", "brew": "aircrack-ng"},
                optional=True,
                executables=["aireplay-ng"],
            ),
            "wash": ToolMetadata(
                "Wash",
                {"apt": "reaver", "yum": "reaver", "brew": "reaver"},
                optional=True,
                executables=["wash"],
            ),
            "reaver": ToolMetadata(
                "Reaver",
                {"apt": "reaver", "yum": "reaver", "brew": "reaver"},
                optional=True,
                executables=["reaver"],
            ),
            "iw": ToolMetadata(
                "iw",
                {"apt": "iw", "yum": "iw", "brew": "iw"},
                optional=True,
                executables=["iw"],
            ),
            "hcxtools": ToolMetadata(
                "HCXTools",
                {"apt": "hcxtools", "yum": "hcxtools", "brew": "hcxtools"},
                optional=True,
                executables=["hcxpcapngtool", "hcxpcaptool"],
            ),
            "hashcat": ToolMetadata(
                "Hashcat", {"apt": "hashcat", "yum": "hashcat", "brew": "hashcat"}, optional=True
            ),
            "phoneinfoga": ToolMetadata(
                friendly_name="PhoneInfoga",
                packages={},
                optional=True,
                executables=["phoneinfoga", "phoneinfoga.py"],
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
            "curl": ToolMetadata(
                friendly_name="curl",
                packages={"apt": "curl", "yum": "curl", "brew": "curl", "apk": "curl"},
                optional=True,
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


        # Always prompt for install, even if no package mapping
        response = input("Attempt automatic installation? [y/N]: ").strip().lower()
        if response != "y":
            print("Skipped automatic installation. Please install manually using your package manager or the instructions below.")
            if metadata.install_hint:
                print(f"Manual install: {metadata.install_hint}")
            else:
                print(f"No automatic install available for '{tool}'. Please refer to the official documentation or project page.")
            print(f"Example: Search for '{tool}' on GitHub or the official site, download the binary or clone the repo, and place the executable in your PATH.")
            return False

        # If package mapping exists, try auto-install
        if metadata.packages:
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
        else:
            # No package mapping: open install link or print instructions
            if metadata.install_hint and metadata.install_hint.startswith("http"):
                import webbrowser
                print(f"Opening install page: {metadata.install_hint}")
                try:
                    webbrowser.open(metadata.install_hint)
                except Exception:
                    print("[ERROR] Could not open browser. Please visit the link manually.")
            else:
                print("[INFO] Please follow these instructions to install:")
                if metadata.install_hint:
                    print(metadata.install_hint)
                else:
                    print(f"No automatic install available for '{tool}'. Please refer to the official documentation or project page.")
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
                "7": self.individuals_menu,
                "8": self.utility_menu,
                "9": self.dependencies_menu,
                "10": self.wireless_menu,
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
        print("7) Individual intelligence workflows")
        print("8) Utility toolbox")
        print("9) Dependency health & installation")
        print("10) Wireless capture & cracking")
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
        print("7) Host discovery / ping sweep (-sn)")
        print("8) UDP scan (top 200 ports)")
        print("9) Combined TCP+UDP service scan (top 100 ports)")
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
        elif choice == "7":
            cmd = base_cmd + ["-sn", target]
        elif choice == "8":
            cmd = base_cmd + ["-T4", "-Pn", "-sU", "--top-ports", "200", target]
        elif choice == "9":
            cmd = base_cmd + ["-T4", "-Pn", "-sS", "-sU", "--top-ports", "100", "-sV", target]
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
    # Wireless capture & cracking
    # ------------------------------------------------------------------
    def wireless_menu(self) -> None:
        while True:
            print("\nWireless Capture & Cracking")
            print("---------------------------")
            print("  --- Interface Management ---")
            print(" 1) List wireless interfaces (iw dev)")
            print(" 2) Enable monitor mode (airmon-ng)")
            print(" 3) Disable monitor mode (airmon-ng)")
            print(" 4) Kill interfering processes (airmon-ng check kill)")
            print("  --- Service Control ---")
            print(" 5) NetworkManager  [start/stop/restart/status]")
            print(" 6) wpa_supplicant  [start/stop/restart/status]")
            print("  --- Scanning & Capture ---")
            print(" 7)  Airodump-ng scan / capture")
            print(" 8)  Besside-ng capture session")
            print(" 9)  Wash WPS scan")
            print("  --- Attacks ---")
            print("10)  Aireplay-ng deauth test")
            print("11)  Reaver WPS PIN attack")
            print("  --- Cracking ---")
            print("12) HCXTools convert capture to hashcat format")
            print("13) Hashcat attack suite")
            print(" 0) Back to main menu")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                self._wireless_list_interfaces()
            elif choice == "2":
                self._wireless_enable_monitor()
            elif choice == "3":
                self._wireless_disable_monitor()
            elif choice == "4":
                self._wireless_check_kill()
            elif choice == "5":
                self._service_control("NetworkManager")
            elif choice == "6":
                self._service_control("wpa_supplicant")
            elif choice == "7":
                self._airodump_capture()
            elif choice == "8":
                self.besside_capture()
            elif choice == "9":
                self._wash_scan()
            elif choice == "10":
                self._aireplay_deauth()
            elif choice == "11":
                self._reaver_wps()
            elif choice == "12":
                self.hcxtools_convert()
            elif choice == "13":
                self.hashcat_menu()
            elif choice == "0":
                print()
                return
            else:
                print("[!] Invalid selection.\n")

    def _wireless_enable_monitor(self) -> None:
        base_cmd = self._get_tool_command("airmon-ng")
        if not base_cmd:
            return
        interface = input("Wireless interface to enable monitor mode on: ").strip()
        if not interface:
            print("[!] Interface is required.\n")
            return
        kill_procs = input("Kill interfering processes first? [Y/n]: ").strip().lower()
        if kill_procs != "n":
            print("[INFO] Killing interfering processes...")
            kill_cmd = ["sudo"] + list(base_cmd) + ["check", "kill"]
            self._run_command_capture(kill_cmd)
        cmd = ["sudo"] + list(base_cmd) + ["start", interface]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("airmon_start", interface)
        report_path.write_text(output)
        print(f"[+] Monitor mode enabled on {interface}")
        print(f"[+] Log saved to {report_path}\n")

    def _wireless_disable_monitor(self) -> None:
        base_cmd = self._get_tool_command("airmon-ng")
        if not base_cmd:
            return
        interface = input("Wireless interface to disable monitor mode on: ").strip()
        if not interface:
            print("[!] Interface is required.\n")
            return
        cmd = ["sudo"] + list(base_cmd) + ["stop", interface]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("airmon_stop", interface)
        report_path.write_text(output)
        print(f"[+] Monitor mode disabled on {interface}")
        print(f"[+] Log saved to {report_path}\n")
        restart_nm = input("Restart NetworkManager? [Y/n]: ").strip().lower()
        if restart_nm != "n":
            self._service_control("NetworkManager", action="restart")

    def _wireless_check_kill(self) -> None:
        base_cmd = self._get_tool_command("airmon-ng")
        if not base_cmd:
            return
        cmd = ["sudo"] + list(base_cmd) + ["check", "kill"]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("airmon_check_kill", "processes")
        report_path.write_text(output)
        print(f"[+] Interfering processes killed")
        print(f"[+] Log saved to {report_path}\n")

    def _service_control(self, service: str, action: Optional[str] = None) -> None:
        if action is None:
            print(f"\n{service} Service Control")
            print("-" * (len(service) + 16))
            print("1) Status")
            print("2) Start")
            print("3) Stop")
            print("4) Restart")
            print("0) Cancel")
            choice = input("Choose an action: ").strip()
            action_map = {"1": "status", "2": "start", "3": "stop", "4": "restart"}
            action = action_map.get(choice)
            if not action:
                return
        systemctl = shutil.which("systemctl")
        if systemctl:
            cmd = ["sudo", systemctl, action, service]
        else:
            cmd = ["sudo", "service", service, action]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path(service, action)
        report_path.write_text(output)
        print(f"[+] {service} {action} completed")
        print(f"[+] Log saved to {report_path}\n")

    def _wireless_list_interfaces(self) -> None:
        iw_cmd = shutil.which("iw")
        if not iw_cmd:
            print("[!] iw not found. Install with: apt install iw\n")
            return
        cmd = [iw_cmd, "dev"]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("iw_list", "interfaces")
        report_path.write_text(output)
        print(f"[+] Interface list saved to {report_path}\n")

    def _airodump_capture(self) -> None:
        base_cmd = self._get_tool_command("airodump-ng")
        if not base_cmd:
            return
        interface = input("Monitor mode interface: ").strip()
        if not interface:
            print("[!] Interface is required.\n")
            return
        print("Capture modes:")
        print("  1) Scan all channels (discovery)")
        print("  2) Target specific BSSID")
        print("  3) Target specific channel")
        mode = input("Choose mode [1]: ").strip() or "1"
        cmd = list(base_cmd) + [interface]
        bssid = ""
        channel = ""
        if mode == "2":
            bssid = input("Target BSSID: ").strip()
            if bssid:
                cmd += ["--bssid", bssid]
            channel = input("Channel (recommended for targeted capture): ").strip()
            if channel:
                cmd += ["-c", channel]
        elif mode == "3":
            channel = input("Channel: ").strip()
            if channel:
                cmd += ["-c", channel]
        write_capture = input("Write capture files to disk? [Y/n]: ").strip().lower()
        if write_capture != "n":
            output_path = self._create_report_path("airodump", interface, extension="cap")
            prefix = str(output_path.with_suffix(""))
            cmd += ["-w", prefix]
        extra_args = input("Additional airodump-ng flags (optional): ").strip()
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        print("[INFO] Launching airodump-ng. Press Ctrl+C to stop.\n")
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("airodump_session", interface)
        report_path.write_text(output or "[!] No output captured from airodump-ng.")
        print(f"[+] Airodump-ng output saved to {report_path}\n")

    def _wash_scan(self) -> None:
        base_cmd = self._get_tool_command("wash")
        if not base_cmd:
            return
        interface = input("Monitor mode interface: ").strip()
        if not interface:
            print("[!] Interface is required.\n")
            return
        cmd = list(base_cmd) + ["-i", interface]
        scan_iface = input("Scan specific interface only? [Y/n]: ").strip().lower()
        if scan_iface == "n":
            cmd.append("-f")
        extra_args = input("Additional wash flags (optional): ").strip()
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        print("[INFO] Scanning for WPS-enabled networks...\n")
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("wash_scan", interface)
        report_path.write_text(output)
        print(f"[+] Wash scan results saved to {report_path}\n")

    def _aireplay_deauth(self) -> None:
        base_cmd = self._get_tool_command("aireplay-ng")
        if not base_cmd:
            return
        interface = input("Monitor mode interface: ").strip()
        if not interface:
            print("[!] Interface is required.\n")
            return
        print("Deauth modes:")
        print("  1) Deauth specific client (-c)")
        print("  2) Deauth all clients from AP (-a)")
        print("  3) Broadcast deauth (-a broadcast)")
        mode = input("Choose mode [2]: ").strip() or "2"
        bssid = input("Target AP BSSID: ").strip()
        if not bssid:
            print("[!] BSSID is required.\n")
            return
        cmd = list(base_cmd) + ["--deauth", "5", "-a", bssid, interface]
        if mode == "1":
            client = input("Target client MAC: ").strip()
            if client:
                cmd = list(base_cmd) + ["--deauth", "5", "-a", bssid, "-c", client, interface]
        count = input("Number of deauth packets [5]: ").strip()
        if count:
            cmd[2] = count
        extra_args = input("Additional aireplay-ng flags (optional): ").strip()
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        print("[INFO] Sending deauthentication packets. Press Ctrl+C to stop.\n")
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("aireplay_deauth", bssid)
        report_path.write_text(output)
        print(f"[+] Deauth log saved to {report_path}\n")

    def _reaver_wps(self) -> None:
        base_cmd = self._get_tool_command("reaver")
        if not base_cmd:
            return
        interface = input("Monitor mode interface: ").strip()
        if not interface:
            print("[!] Interface is required.\n")
            return
        bssid = input("Target AP BSSID: ").strip()
        if not bssid:
            print("[!] BSSID is required.\n")
            return
        cmd = list(base_cmd) + ["-i", interface, "-b", bssid]
        channel = input("Channel (optional, improves speed): ").strip()
        if channel:
            cmd += ["-c", channel]
        pin_path = input("Path to known PINs file (optional): ").strip()
        if pin_path:
            cmd += ["-f", pin_path]
        extra_args = input("Additional reaver flags (optional): ").strip()
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        print("[INFO] Launching Reaver WPS PIN attack. Press Ctrl+C to stop.\n")
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("reaver_wps", bssid)
        report_path.write_text(output)
        print(f"[+] Reaver output saved to {report_path}\n")

    def besside_capture(self) -> None:
        base_cmd = self._get_tool_command("besside-ng")
        if not base_cmd:
            return
        interface = input("Wireless interface (monitor mode): ").strip()
        if not interface:
            print("[!] Interface is required.\n")
            return
        channel = input("Channel (optional): ").strip()
        bssid = input("Target BSSID (optional): ").strip()
        extra_args = input("Additional Besside-ng flags (optional): ").strip()
        output_path = self._create_report_path("besside", interface, extension="cap")
        output_prefix = str(output_path.with_suffix(""))
        cmd = list(base_cmd) + ["-i", interface, "-w", output_prefix]
        if channel:
            cmd += ["-c", channel]
        if bssid:
            cmd += ["-b", bssid]
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        print(
            "[INFO] Launching Besside-ng. Press Ctrl+C to stop when enough data has been captured.\n"
        )
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("besside_session", interface)
        report_path.write_text(output or "[!] No output captured from Besside-ng.")
        print(f"[+] Besside-ng output saved to {report_path}\n")
        print(f"[INFO] Capture artifacts saved with prefix {output_prefix}\n")

    def hcxtools_convert(self) -> None:
        converter_cmd = self._get_hcxtools_converter()
        if not converter_cmd:
            return
        capture_path = input("Path to .pcap/.pcapng capture file: ").strip()
        if not capture_path:
            print("[!] Capture file is required.\n")
            return
        capture = Path(capture_path)
        if not capture.exists():
            print("[!] Capture file not found.\n")
            return
        extra_args = input("Additional HCXTools flags (optional): ").strip()
        output_path = self._create_report_path("hcxtools", capture.stem, extension="hc22000")
        cmd = list(converter_cmd) + ["-o", str(output_path), str(capture)]
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("hcxtools_convert", capture.stem)
        report_path.write_text(output or "[!] No output captured from HCXTools.")
        print(f"[+] HCXTools conversion log saved to {report_path}\n")
        print(f"[+] Hashcat-ready capture saved to {output_path}\n")

    def hashcat_menu(self) -> None:
        while True:
            print("\nHashcat Attack Suite")
            print("--------------------")
            print("  --- Attacks ---")
            print(" 1) Dictionary attack (-a 0)")
            print(" 2) Combinator attack (-a 1)")
            print(" 3) Brute-force / Mask attack (-a 3)")
            print(" 4) Hybrid Wordlist + Mask (-a 6)")
            print(" 5) Hybrid Mask + Wordlist (-a 7)")
            print(" 6) Association attack (-a 9)")
            print(" 7) Rule-based dictionary attack (-a 0 -r)")
            print("  --- Utilities ---")
            print(" 8) Show cracked hashes (--show)")
            print(" 9) Benchmark GPU performance (-b)")
            print("10) Hash type lookup (--example-hashes)")
            print("11) Identify hash type (hashid)")
            print("12) Session restore (--restore)")
            print("13) Custom hashcat command")
            print("  --- HCXTools ---")
            print("14) Convert capture to hashcat format (hcxpcapngtool)")
            print(" 0) Back to wireless menu")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                self._hashcat_dictionary()
            elif choice == "2":
                self._hashcat_combinator()
            elif choice == "3":
                self._hashcat_mask()
            elif choice == "4":
                self._hashcat_hybrid_wordlist_mask()
            elif choice == "5":
                self._hashcat_hybrid_mask_wordlist()
            elif choice == "6":
                self._hashcat_association()
            elif choice == "7":
                self._hashcat_rule_based()
            elif choice == "8":
                self._hashcat_show()
            elif choice == "9":
                self._hashcat_benchmark()
            elif choice == "10":
                self._hashcat_example_hashes()
            elif choice == "11":
                self._hashcat_identify_hash()
            elif choice == "12":
                self._hashcat_restore()
            elif choice == "13":
                self._hashcat_custom()
            elif choice == "14":
                self.hcxtools_convert()
            elif choice == "0":
                print()
                return
            else:
                print("[!] Invalid selection.\n")

    def _hashcat_get_common(self) -> Optional[tuple]:
        base_cmd = self._get_tool_command("hashcat")
        if not base_cmd:
            return None
        hash_path = input("Path to hash file (e.g. .hc22000): ").strip()
        if not hash_path:
            print("[!] Hash file is required.\n")
            return None
        hash_file = Path(hash_path)
        if not hash_file.exists():
            print("[!] Hash file not found.\n")
            return None
        hash_mode = input("Hash mode (-m) [default 22000]: ").strip() or "22000"
        return base_cmd, hash_file, hash_mode

    def _hashcat_get_session_flags(self) -> List[str]:
        session_name = input("Session name (optional): ").strip()
        flags: List[str] = []
        if session_name:
            flags += ["--session", session_name]
        return flags

    def _hashcat_get_common_flags(self) -> List[str]:
        force = input("Use --force? [y/N]: ").strip().lower()
        flags: List[str] = []
        if force == "y":
            flags.append("--force")
        workload = input("Workload profile (1=low, 2=default, 3=high, 4=nightmare) [optional]: ").strip()
        if workload in {"1", "2", "3", "4"}:
            flags += ["--workload-profile", workload]
        return flags

    def _hashcat_execute(self, cmd: List[str], hash_file: Path, label: str) -> None:
        extra_args = input("Additional Hashcat flags (optional): ").strip()
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        output_path = self._create_report_path("hashcat", hash_file.stem)
        cmd += ["--outfile", str(output_path)]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("hashcat_session", hash_file.stem)
        report_path.write_text(output or "[!] No output captured from Hashcat.")
        print(f"[+] Hashcat session log saved to {report_path}")
        print(f"[+] Cracked hashes saved to {output_path}\n")

    def _hashcat_dictionary(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        wordlist = input("Wordlist path (e.g. /usr/share/wordlists/rockyou.txt): ").strip()
        if not wordlist:
            print("[!] Wordlist path is required for dictionary attack.\n")
            return
        cmd = list(base_cmd) + ["-a", "0", "-m", hash_mode, str(hash_file), wordlist]
        cmd += self._hashcat_get_session_flags()
        cmd += self._hashcat_get_common_flags()
        self._hashcat_execute(cmd, hash_file, "dictionary")

    def _hashcat_combinator(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        wordlist1 = input("First wordlist path: ").strip()
        if not wordlist1:
            print("[!] First wordlist is required.\n")
            return
        wordlist2 = input("Second wordlist path: ").strip()
        if not wordlist2:
            print("[!] Second wordlist is required for combinator attack.\n")
            return
        cmd = list(base_cmd) + ["-a", "1", "-m", hash_mode, str(hash_file), wordlist1, wordlist2]
        cmd += self._hashcat_get_session_flags()
        cmd += self._hashcat_get_common_flags()
        self._hashcat_execute(cmd, hash_file, "combinator")

    def _hashcat_mask(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        print("Mask placeholders: ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all")
        print("Example: ?d?d?d?d?d?d?d?d = 8-digit PIN")
        mask = input("Mask string: ").strip()
        if not mask:
            print("[!] Mask is required for brute-force attack.\n")
            return
        cmd = list(base_cmd) + ["-a", "3", "-m", hash_mode, str(hash_file), mask]
        increment = input("Use increment mode? [Y/n]: ").strip().lower()
        if increment != "n":
            cmd.append("--increment")
            inc_min = input("Increment minimum length (optional): ").strip()
            if inc_min:
                cmd += ["--increment-min", inc_min]
            inc_max = input("Increment maximum length (optional): ").strip()
            if inc_max:
                cmd += ["--increment-max", inc_max]
        custom_charset = input("Custom charset? (e.g. -1 ?l?d for charset 1) [optional]: ").strip()
        if custom_charset:
            try:
                cmd.extend(shlex.split(custom_charset))
            except ValueError:
                print("[!] Invalid charset syntax.\n")
                return
        cmd += self._hashcat_get_session_flags()
        cmd += self._hashcat_get_common_flags()
        self._hashcat_execute(cmd, hash_file, "mask")

    def _hashcat_hybrid_wordlist_mask(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        wordlist = input("Wordlist path: ").strip()
        if not wordlist:
            print("[!] Wordlist is required for hybrid attack.\n")
            return
        print("Mask placeholders: ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all")
        mask = input("Mask string (appended to wordlist entries): ").strip()
        if not mask:
            print("[!] Mask is required.\n")
            return
        cmd = list(base_cmd) + ["-a", "6", "-m", hash_mode, str(hash_file), wordlist, mask]
        cmd += self._hashcat_get_session_flags()
        cmd += self._hashcat_get_common_flags()
        self._hashcat_execute(cmd, hash_file, "hybrid_wl_mask")

    def _hashcat_hybrid_mask_wordlist(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        print("Mask placeholders: ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all")
        mask = input("Mask string (prepended to wordlist entries): ").strip()
        if not mask:
            print("[!] Mask is required.\n")
            return
        wordlist = input("Wordlist path: ").strip()
        if not wordlist:
            print("[!] Wordlist is required for hybrid attack.\n")
            return
        cmd = list(base_cmd) + ["-a", "7", "-m", hash_mode, str(hash_file), mask, wordlist]
        cmd += self._hashcat_get_session_flags()
        cmd += self._hashcat_get_common_flags()
        self._hashcat_execute(cmd, hash_file, "hybrid_mask_wl")

    def _hashcat_association(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        wordlist1 = input("First wordlist path: ").strip()
        if not wordlist1:
            print("[!] First wordlist is required.\n")
            return
        wordlist2 = input("Second wordlist path: ").strip()
        if not wordlist2:
            print("[!] Second wordlist is required for association attack.\n")
            return
        cmd = list(base_cmd) + ["-a", "9", "-m", hash_mode, str(hash_file), wordlist1, wordlist2]
        cmd += self._hashcat_get_session_flags()
        cmd += self._hashcat_get_common_flags()
        self._hashcat_execute(cmd, hash_file, "association")

    def _hashcat_rule_based(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        wordlist = input("Wordlist path: ").strip()
        if not wordlist:
            print("[!] Wordlist is required for rule-based attack.\n")
            return
        print("Common rule files: rules/best64.rule, rules/dive.rule, rules/d3ad0ne.rule")
        print("You can specify multiple rules with repeated -r flags.")
        rules: List[str] = []
        while True:
            rule = input("Rules file path (empty to finish): ").strip()
            if not rule:
                break
            rules.append(rule)
        cmd = list(base_cmd) + ["-a", "0", "-m", hash_mode, str(hash_file), wordlist]
        for r in rules:
            cmd += ["-r", r]
        cmd += self._hashcat_get_session_flags()
        cmd += self._hashcat_get_common_flags()
        self._hashcat_execute(cmd, hash_file, "rule_based")

    def _hashcat_show(self) -> None:
        common = self._hashcat_get_common()
        if not common:
            return
        base_cmd, hash_file, hash_mode = common
        output_path = self._create_report_path("hashcat_show", hash_file.stem)
        cmd = list(base_cmd) + ["-m", hash_mode, str(hash_file), "--show", "--outfile", str(output_path)]
        extra_args = input("Additional flags (optional): ").strip()
        if extra_args:
            try:
                cmd.extend(shlex.split(extra_args))
            except ValueError as exc:
                print(f"[!] Unable to parse extra arguments: {exc}\n")
                return
        output = self._run_command_capture(cmd)
        if output is None:
            return
        print(f"[+] Cracked hashes saved to {output_path}\n")

    def _hashcat_benchmark(self) -> None:
        base_cmd = self._get_tool_command("hashcat")
        if not base_cmd:
            return
        hash_mode = input("Benchmark specific hash mode? (empty for all) [optional]: ").strip()
        cmd = list(base_cmd) + ["-b"]
        if hash_mode:
            cmd += ["-m", hash_mode]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("hashcat_benchmark", "benchmark")
        report_path.write_text(output)
        print(f"[+] Benchmark results saved to {report_path}\n")

    def _hashcat_example_hashes(self) -> None:
        base_cmd = self._get_tool_command("hashcat")
        if not base_cmd:
            return
        hash_mode = input("Hash mode (-m) to look up (empty for all): ").strip()
        cmd = list(base_cmd) + ["--example-hashes"]
        if hash_mode:
            cmd += ["-m", hash_mode]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("hashcat_example_hashes", hash_mode or "all")
        report_path.write_text(output)
        print(f"[+] Example hashes saved to {report_path}\n")

    def _hashcat_identify_hash(self) -> None:
        hash_input = input("Enter hash string or path to hash file: ").strip()
        if not hash_input:
            print("[!] Hash input is required.\n")
            return
        hash_path = Path(hash_input)
        if hash_path.exists():
            hashcat_path = shutil.which("hashid") or shutil.which("name-that-hash")
            if not hashcat_path:
                print("[!] hashid or name-that-hash not found. Install with: pip3 install hashid")
                return
            cmd = [hashcat_path, "-f", str(hash_path)]
        else:
            hashcat_path = shutil.which("hashid") or shutil.which("name-that-hash")
            if not hashcat_path:
                print("[!] hashid or name-that-hash not found. Install with: pip3 install hashid")
                return
            cmd = [hashcat_path, hash_input]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("hash_identify", hash_input[:30])
        report_path.write_text(output)
        print(f"[+] Hash identification saved to {report_path}\n")

    def _hashcat_restore(self) -> None:
        base_cmd = self._get_tool_command("hashcat")
        if not base_cmd:
            return
        session_name = input("Session name to restore: ").strip()
        if not session_name:
            print("[!] Session name is required.\n")
            return
        cmd = list(base_cmd) + ["--restore", "--session", session_name]
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("hashcat_restore", session_name)
        report_path.write_text(output)
        print(f"[+] Session restore log saved to {report_path}\n")

    def _hashcat_custom(self) -> None:
        base_cmd = self._get_tool_command("hashcat")
        if not base_cmd:
            return
        custom = input("Enter full hashcat command (after 'hashcat'): ").strip()
        if not custom:
            print("[!] No command provided.\n")
            return
        try:
            args = shlex.split(custom)
        except ValueError as exc:
            print(f"[!] Unable to parse arguments: {exc}\n")
            return
        cmd = list(base_cmd) + args
        output = self._run_command_capture(cmd)
        if output is None:
            return
        report_path = self._create_report_path("hashcat_custom", "custom")
        report_path.write_text(output)
        print(f"[+] Custom command log saved to {report_path}\n")

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
        cmd = list(base_cmd) + ["scan", "-n", number, "-f", fmt]
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
        chunks: List[str] = []
        for email in emails:
            header = f"===== {email} ====="
            print(f"\n{header}")
            cmd = list(base_cmd) + [email]
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

    # ------------------------------------------------------------------
    # Individual intelligence workflows
    # ------------------------------------------------------------------
    def individuals_menu(self) -> None:
        while True:
            print("\nIndividual Intelligence Workflows")
            print("--------------------------------")
            print("1) Gather phone info (PhoneInfoga)")
            print("2) Gather email info (Holehe)")
            print("3) Gather name info (SpiderFoot)")
            print("4) Gather legal info (SpiderFoot + Whois)")
            print("5) Gather income info (SpiderFoot)")
            print("6) Gather career info (SpiderFoot + Osintgram)")
            print("0) Back to main menu")
            choice = input("Choose an option: ").strip()
            if choice == "1":
                self.phoneinfoga_lookup()
            elif choice == "2":
                self.holehe_lookup()
            elif choice == "3":
                self._spiderfoot_individual_workflow("name")
            elif choice == "4":
                self._spiderfoot_individual_workflow("legal")
            elif choice == "5":
                self._spiderfoot_individual_workflow("income")
            elif choice == "6":
                self._spiderfoot_individual_workflow("career")
            elif choice == "0":
                print()
                return
            else:
                print("[!] Invalid selection.\n")

    def _spiderfoot_individual_workflow(self, profile: str) -> None:
        base_cmd = self._get_tool_command("spiderfoot")
        if not base_cmd:
            return
        prompt_map = {
            "name": "Full name or alias",
            "legal": "Legal name, company name, or jurisdiction-specific identifier",
            "income": "Name, employer handle, or wallet-linked alias",
            "career": "Name or professional username",
        }
        target = input(f"{prompt_map.get(profile, 'Target')}: ").strip()
        if not target:
            print("[!] Target is required.\n")
            return
        output_format = "json"
        cmd = list(base_cmd) + ["-s", target, "-t", "name", "-o", output_format]
        output = self._run_command_capture(cmd)
        if output is None:
            return

        lines = [f"Profile: {profile}", f"Target: {target}", "", output.rstrip() or "[!] No output returned."]

        if profile == "legal" and self.dependency_manager.tool_available("whois"):
            whois_output = self._run_command_capture(["whois", target])
            if whois_output is not None:
                lines.extend(["", "===== WHOIS =====", whois_output.rstrip() or "[!] No WHOIS output returned."])

        if profile == "career":
            osintgram_cmd = self.dependency_manager.command_prefix("osintgram")
            if osintgram_cmd:
                instagram_user = input("Instagram username (optional, press Enter to skip): ").strip()
                if instagram_user:
                    ig_output = self._run_command_capture(list(osintgram_cmd) + [instagram_user, "info"])
                    if ig_output is not None:
                        lines.extend(["", "===== OSINTGRAM INFO =====", ig_output.rstrip() or "[!] No Osintgram output returned."])

        report_path = self._create_report_path(f"individual_{profile}", target)
        report_path.write_text("\n".join(lines) + "\n")
        print(f"[+] Individual {profile} report saved to {report_path}\n")

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
            print("5) Show public IPv4 (forced IPv4 lookup)")
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
            elif choice == "5":
                print(self._public_ipv4_lookup())
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
        print(f"[!] {friendly} command was not detected on PATH.")
        self.dependency_manager.ensure_tool(tool, interactive=False)
        print("[!] Recon no longer accepts ad-hoc command strings for tool execution.")
        print("    Install the expected executable and rerun this workflow.\n")
        return None

    def _get_hcxtools_converter(self) -> Optional[List[str]]:
        base_cmd = self._get_tool_command("hcxtools")
        if not base_cmd:
            return None
        candidate = Path(base_cmd[-1]).name
        fallback = Path(base_cmd[0]).name
        if candidate in {"hcxpcapngtool", "hcxpcaptool"} or fallback in {"hcxpcapngtool", "hcxpcaptool"}:
            return base_cmd
        print("[!] HCXTools conversion requires hcxpcapngtool or hcxpcaptool in your PATH.\n")
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

    def _public_ipv4_lookup(self) -> str:
        if not self.dependency_manager.ensure_tool("curl"):
            return "[!] curl is required to perform a forced IPv4 lookup. Install curl and try again."
        cmd = ["curl", "-4", "ifconfig.me"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        except subprocess.TimeoutExpired:
            return "[!] Timed out while querying ifconfig.me."
        except Exception as exc:
            return f"[!] Failed to query ifconfig.me: {exc}"
        output = (result.stdout or "").strip()
        if not output:
            stderr = (result.stderr or "").strip()
            if stderr:
                return f"[!] curl error: {stderr}"
            return "[!] No response received from ifconfig.me."
        return f"[+] Public IPv4 (forced): {output}"

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
