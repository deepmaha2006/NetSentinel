#!/usr/bin/env python3
"""
NetSentinel - Network Vulnerability Scanner
Author: Deepesh Kumar Mahawar (deepmaha2006)
Description: A powerful network scanner that discovers open ports, 
             identifies running services, performs banner grabbing,
             and generates detailed vulnerability reports.
"""

import socket
import sys
import threading
import time
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI Color codes for terminal output
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
MAGENTA = "\033[95m"

BANNER = f"""
{GREEN}{BOLD}
 ███╗   ██╗███████╗████████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ██╔██╗ ██║█████╗     ██║       ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ██║╚██╗██║██╔══╝     ██║       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ██║ ╚████║███████╗   ██║       ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{RESET}
{CYAN}                    Network Vulnerability Scanner v1.0{RESET}
{YELLOW}                    Author: Deepesh Kumar Mahawar{RESET}
{RED}             [!] For educational and authorized use only [!]{RESET}
"""

# Common ports and their service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch"
}

# Known vulnerabilities for common services
KNOWN_VULNS = {
    "FTP":           "CVE-2010-4221 - ProFTPD SQL Injection | Cleartext credential transmission",
    "Telnet":        "CVE-1999-0619 - Cleartext protocol, credentials exposed | MITM vulnerable",
    "SSH":           "Check version - CVE-2023-38408 if OpenSSH < 9.3p2",
    "SMB":           "CVE-2017-0144 (EternalBlue) - Check for MS17-010 | SMBGhost CVE-2020-0796",
    "RDP":           "CVE-2019-0708 (BlueKeep) | CVE-2020-0609 | Enable NLA",
    "MySQL":         "CVE-2012-2122 - Authentication bypass | Check for default credentials",
    "HTTP":          "Check for outdated web server | Missing security headers | Directory listing",
    "HTTPS":         "Check SSL/TLS version - disable TLS 1.0/1.1 | Certificate validity",
    "Redis":         "CVE-2022-0543 - Unauthenticated access | Default config exposes data",
    "MongoDB":       "CVE-2013-4650 - Default no-auth config | Remote code execution risk",
}


def print_banner():
    """Print the tool banner."""
    print(BANNER)


def resolve_host(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"{RED}[!] Cannot resolve host: {target}{RESET}")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send HTTP request for web ports
        if port in [80, 8080, 8000]:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner automatically
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else "No banner"
    except Exception:
        return "Unable to grab banner"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """Scan a single port and return result."""
    result = {
        "port": port,
        "state": "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": "",
        "vulnerability": ""
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = sock.connect_ex((ip, port))
        if conn == 0:
            result["state"] = "open"
            result["banner"] = grab_banner(ip, port)
            service = result["service"].upper()
            for svc, vuln in KNOWN_VULNS.items():
                if svc in service or service in svc:
                    result["vulnerability"] = vuln
                    break
        sock.close()
    except Exception:
        pass
    return result


def scan_target(target: str, port_range: tuple = (1, 1024), threads: int = 100) -> dict:
    """
    Scan target host across a port range using threading.
    
    Args:
        target: IP address or hostname
        port_range: Tuple of (start_port, end_port)
        threads: Number of concurrent threads
    
    Returns:
        Dictionary with scan results
    """
    print_banner()
    ip = resolve_host(target)
    start_port, end_port = port_range
    ports = list(range(start_port, end_port + 1))

    print(f"\n{CYAN}[*] Target    : {BOLD}{target}{RESET} ({ip})")
    print(f"{CYAN}[*] Port Range: {start_port} - {end_port}")
    print(f"{CYAN}[*] Threads   : {threads}")
    print(f"{CYAN}[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{YELLOW}{'─' * 70}{RESET}\n")

    open_ports = []
    scanned = 0
    total = len(ports)

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            scanned += 1
            if result["state"] == "open":
                open_ports.append(result)
                svc = result["service"]
                banner_short = result["banner"][:60] if result["banner"] else ""
                vuln_tag = f" {RED}[VULN]{RESET}" if result["vulnerability"] else ""
                print(f"  {GREEN}[OPEN]{RESET}  Port {BOLD}{result['port']:5}{RESET}/tcp  {CYAN}{svc:15}{RESET} {YELLOW}{banner_short}{RESET}{vuln_tag}")

            # Progress
            pct = int((scanned / total) * 40)
            bar = "█" * pct + "░" * (40 - pct)
            sys.stdout.write(f"\r  {CYAN}Progress: [{bar}] {scanned}/{total}{RESET}")
            sys.stdout.flush()

    elapsed = time.time() - start_time
    print(f"\n\n{YELLOW}{'─' * 70}{RESET}")
    print(f"{GREEN}[+] Scan complete in {elapsed:.2f}s | {len(open_ports)} open port(s) found{RESET}\n")

    scan_result = {
        "target": target,
        "ip": ip,
        "scan_time": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "port_range": f"{start_port}-{end_port}",
        "open_ports": open_ports
    }

    return scan_result


def generate_report(scan_result: dict, output_file: str = None) -> str:
    """Generate a detailed vulnerability report from scan results."""
    target = scan_result["target"]
    ip = scan_result["ip"]
    open_ports = scan_result["open_ports"]

    report_lines = [
        "=" * 70,
        "           NETSENTINEL - VULNERABILITY SCAN REPORT",
        "=" * 70,
        f"Target Host  : {target}",
        f"IP Address   : {ip}",
        f"Scan Date    : {scan_result['scan_time']}",
        f"Port Range   : {scan_result['port_range']}",
        f"Elapsed Time : {scan_result['elapsed_seconds']}s",
        f"Open Ports   : {len(open_ports)}",
        "=" * 70,
        "",
    ]

    if not open_ports:
        report_lines.append("No open ports found.")
    else:
        report_lines.append("OPEN PORTS & SERVICES:")
        report_lines.append("-" * 70)
        for p in open_ports:
            report_lines.append(f"\n  Port    : {p['port']}/tcp")
            report_lines.append(f"  Service : {p['service']}")
            report_lines.append(f"  Banner  : {p['banner'][:100]}")
            if p["vulnerability"]:
                report_lines.append(f"  [!] VULNERABILITY: {p['vulnerability']}")
            report_lines.append(f"  Risk    : {'HIGH' if p['vulnerability'] else 'LOW'}")
            report_lines.append("")

        # Risk summary
        risky = [p for p in open_ports if p["vulnerability"]]
        report_lines.append("=" * 70)
        report_lines.append("RISK SUMMARY:")
        report_lines.append(f"  High Risk Services : {len(risky)}")
        report_lines.append(f"  Low Risk Services  : {len(open_ports) - len(risky)}")
        report_lines.append("")
        report_lines.append("RECOMMENDATIONS:")
        report_lines.append("  1. Close all unused ports using firewall rules")
        report_lines.append("  2. Update all services to latest stable versions")
        report_lines.append("  3. Replace Telnet/FTP with SSH/SFTP")
        report_lines.append("  4. Enable fail2ban for brute-force protection")
        report_lines.append("  5. Conduct regular vulnerability assessments")

    report_lines.append("=" * 70)
    report_lines.append("          Generated by NetSentinel | github.com/deepmaha2006")
    report_lines.append("=" * 70)

    report = "\n".join(report_lines)

    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"\n{GREEN}[+] Report saved to: {output_file}{RESET}")

    return report


def main():
    """Main entry point for NetSentinel."""
    print(f"\n{CYAN}NetSentinel Network Vulnerability Scanner{RESET}")
    print(f"{YELLOW}Usage: python scanner.py <target> [start_port] [end_port]{RESET}\n")

    if len(sys.argv) < 2:
        # Interactive mode
        target = input(f"{CYAN}[?] Enter target IP/hostname: {RESET}").strip()
        port_input = input(f"{CYAN}[?] Port range (default 1-1024): {RESET}").strip()
        if port_input and "-" in port_input:
            parts = port_input.split("-")
            start_p, end_p = int(parts[0]), int(parts[1])
        else:
            start_p, end_p = 1, 1024
    else:
        target = sys.argv[1]
        start_p = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        end_p = int(sys.argv[3]) if len(sys.argv) > 3 else 1024

    result = scan_target(target, port_range=(start_p, end_p))

    # Print report
    report = generate_report(result)
    print(report)

    # Save report
    filename = f"report_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    generate_report(result, output_file=filename)

    # Save JSON
    json_file = filename.replace(".txt", ".json")
    with open(json_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"{GREEN}[+] JSON data saved to: {json_file}{RESET}\n")


if __name__ == "__main__":
    main()
