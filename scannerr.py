#!/usr/bin/env python3
"""
Vulnerability Scanner - Mini Project
Scans for open ports, weak configurations, outdated software,
and generates a detailed HTML vulnerability report.
"""

import socket
import subprocess
import json
import datetime
import platform
import sys
import os
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ─────────────────────────── Data Models ────────────────────────────

@dataclass
class Vulnerability:
    title: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    description: str
    recommendation: str
    detail: str = ""

@dataclass
class ScanResult:
    target: str
    scan_time: str
    open_ports: List[dict] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    system_info: dict = field(default_factory=dict)


# ─────────────────────────── Port Scanner ───────────────────────────

WELL_KNOWN_PORTS = {
    21:   ("FTP",        "HIGH",   "FTP transmits data in plaintext. Use SFTP or FTPS instead."),
    22:   ("SSH",        "INFO",   "SSH is open. Ensure strong keys and disable password auth."),
    23:   ("Telnet",     "CRITICAL","Telnet is unencrypted. Replace with SSH immediately."),
    25:   ("SMTP",       "MEDIUM", "SMTP open. Check relay settings to prevent spam abuse."),
    53:   ("DNS",        "MEDIUM", "DNS open. Verify zone-transfer restrictions."),
    80:   ("HTTP",       "MEDIUM", "HTTP is unencrypted. Redirect all traffic to HTTPS."),
    110:  ("POP3",       "HIGH",   "POP3 sends credentials in plaintext."),
    135:  ("MS-RPC",     "HIGH",   "MS-RPC can be exploited. Restrict with a firewall."),
    139:  ("NetBIOS",    "HIGH",   "NetBIOS can leak system info. Disable if unused."),
    143:  ("IMAP",       "HIGH",   "IMAP sends credentials in plaintext. Use IMAPS (993)."),
    443:  ("HTTPS",      "INFO",   "HTTPS is open. Verify certificate validity."),
    445:  ("SMB",        "CRITICAL","SMB can be exploited (EternalBlue). Patch and firewall."),
    1433: ("MSSQL",      "HIGH",   "SQL Server exposed. Restrict access to trusted hosts."),
    1521: ("Oracle DB",  "HIGH",   "Oracle DB exposed. Restrict access to trusted hosts."),
    3306: ("MySQL",      "HIGH",   "MySQL exposed. Bind to localhost unless required."),
    3389: ("RDP",        "HIGH",   "RDP exposed. Use VPN + NLA; disable if unused."),
    5432: ("PostgreSQL", "HIGH",   "PostgreSQL exposed. Bind to localhost unless required."),
    5900: ("VNC",        "HIGH",   "VNC exposed. Use VPN; strong password required."),
    6379: ("Redis",      "CRITICAL","Redis exposed. No auth by default — critical risk."),
    8080: ("HTTP-Alt",   "MEDIUM", "Alternate HTTP port open. Ensure it's intentional."),
    8443: ("HTTPS-Alt",  "INFO",   "Alternate HTTPS port open."),
    27017:("MongoDB",    "CRITICAL","MongoDB exposed. No auth by default — critical risk."),
    9200: ("Elasticsearch","CRITICAL","Elasticsearch exposed. No auth by default — critical risk."),
}

def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Try to connect to a single port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def scan_ports(host: str, port_range: tuple = (1, 1024), extra_ports: list = None) -> List[dict]:
    """Scan a range of ports using threads."""
    open_ports = []
    ports_to_scan = list(range(port_range[0], port_range[1] + 1))
    if extra_ports:
        ports_to_scan = list(set(ports_to_scan + extra_ports))

    print(f"  Scanning {len(ports_to_scan)} ports on {host} ...", end="", flush=True)

    def check(port):
        if scan_port(host, port):
            service, severity, note = WELL_KNOWN_PORTS.get(port, ("Unknown", "INFO", "Unknown service."))
            return {"port": port, "service": service, "severity": severity, "note": note}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        results = list(ex.map(check, ports_to_scan))

    open_ports = [r for r in results if r]
    open_ports.sort(key=lambda x: x["port"])
    print(f" done. Found {len(open_ports)} open port(s).")
    return open_ports


# ─────────────────────────── HTTP Checks ────────────────────────────

def check_http_headers(target: str) -> List[Vulnerability]:
    """Check for missing/weak HTTP security headers."""
    vulns = []
    if not REQUESTS_AVAILABLE:
        return vulns

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(url, timeout=5, verify=False,
                                headers={"User-Agent": "VulnScanner/1.0"})
            headers = {k.lower(): v for k, v in resp.headers.items()}

            security_headers = {
                "strict-transport-security": (
                    "HIGH", "HSTS Missing",
                    "HTTP Strict-Transport-Security header is absent.",
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
                "x-frame-options": (
                    "MEDIUM", "Clickjacking Risk",
                    "X-Frame-Options header is missing. Site may be embeddable in iframes.",
                    "Add: X-Frame-Options: DENY or SAMEORIGIN"
                ),
                "x-content-type-options": (
                    "MEDIUM", "MIME Sniffing Risk",
                    "X-Content-Type-Options header is missing.",
                    "Add: X-Content-Type-Options: nosniff"
                ),
                "content-security-policy": (
                    "MEDIUM", "No Content Security Policy",
                    "CSP header absent. XSS attacks may succeed.",
                    "Define a Content-Security-Policy header."
                ),
                "x-xss-protection": (
                    "LOW", "XSS Filter Disabled",
                    "X-XSS-Protection header missing.",
                    "Add: X-XSS-Protection: 1; mode=block"
                ),
                "referrer-policy": (
                    "LOW", "Referrer Policy Missing",
                    "Referrer-Policy header absent.",
                    "Add: Referrer-Policy: no-referrer-when-downgrade"
                ),
                "permissions-policy": (
                    "LOW", "Permissions Policy Missing",
                    "Permissions-Policy header absent.",
                    "Add a Permissions-Policy header to limit browser features."
                ),
            }

            for hdr, (severity, title, desc, rec) in security_headers.items():
                if hdr not in headers:
                    vulns.append(Vulnerability(
                        title=title,
                        severity=severity,
                        category="HTTP Headers",
                        description=desc,
                        recommendation=rec,
                        detail=f"Checked on {url}"
                    ))

            # Server banner disclosure
            server = headers.get("server", "")
            if server and any(c.isdigit() for c in server):
                vulns.append(Vulnerability(
                    title="Server Version Disclosure",
                    severity="LOW",
                    category="Information Disclosure",
                    description=f"Server header reveals version: {server}",
                    recommendation="Configure the server to suppress version info.",
                    detail=f"Header value: Server: {server}"
                ))

            # Check for HTTP (no redirect to HTTPS)
            if scheme == "http" and resp.status_code == 200:
                vulns.append(Vulnerability(
                    title="No HTTPS Redirect",
                    severity="HIGH",
                    category="Transport Security",
                    description="The site responds over plain HTTP without redirecting to HTTPS.",
                    recommendation="Configure a 301 redirect from HTTP to HTTPS.",
                    detail=f"HTTP {resp.status_code} at {url}"
                ))

            break   # stop after first successful connection
        except Exception:
            continue

    return vulns


# ─────────────────────────── System Checks ──────────────────────────

def get_system_info() -> dict:
    """Collect local system information."""
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
        "architecture": platform.machine(),
    }
    return info

def check_software_versions() -> List[Vulnerability]:
    """Check for potentially outdated software versions."""
    vulns = []
    tools = {
        "openssl version": ("OpenSSL", "1.1.1", "HIGH"),
        "curl --version": ("curl", "7.80", "MEDIUM"),
        "ssh -V":          ("OpenSSH", "8.0", "MEDIUM"),
        "python3 --version":("Python", "3.10", "LOW"),
        "nginx -v":        ("nginx", "1.20", "MEDIUM"),
        "apache2 -v":      ("Apache", "2.4.50", "MEDIUM"),
    }

    for cmd, (name, min_ver, severity) in tools.items():
        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=3
            )
            output = (result.stdout + result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr) else ""
            if output:
                # Extract first version-like token
                import re
                ver_match = re.search(r"(\d+\.\d+[\.\d]*)", output)
                found_ver = ver_match.group(1) if ver_match else "unknown"

                def ver_tuple(v):
                    try:
                        return tuple(int(x) for x in v.split("."))
                    except Exception:
                        return (0,)

                if ver_tuple(found_ver) < ver_tuple(min_ver):
                    vulns.append(Vulnerability(
                        title=f"Outdated {name} Version",
                        severity=severity,
                        category="Software Versions",
                        description=f"{name} version {found_ver} is below recommended minimum {min_ver}.",
                        recommendation=f"Update {name} to the latest stable release.",
                        detail=f"Detected: {output}"
                    ))
        except Exception:
            pass

    return vulns

def check_firewall() -> List[Vulnerability]:
    """Check if a firewall is active (Linux only)."""
    vulns = []
    if platform.system() != "Linux":
        return vulns
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5
        )
        if "Chain INPUT (policy ACCEPT)" in result.stdout and result.stdout.count("\n") < 6:
            vulns.append(Vulnerability(
                title="Firewall May Be Disabled / Default-Accept",
                severity="HIGH",
                category="Network Security",
                description="iptables shows a default ACCEPT policy with no rules. Firewall may be inactive.",
                recommendation="Configure iptables or ufw with a proper rule set.",
                detail="iptables -L -n shows no blocking rules."
            ))
    except Exception:
        pass
    return vulns


# ─────────────────────────── Report Generator ───────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

def generate_html_report(result: ScanResult, output_path: str):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for v in result.vulnerabilities:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    sorted_vulns = sorted(result.vulnerabilities, key=lambda v: SEVERITY_ORDER.get(v.severity, 99))

    port_rows = ""
    for p in result.open_ports:
        color = SEVERITY_COLOR.get(p["severity"], "#6b7280")
        port_rows += f"""
        <tr>
          <td><strong>{p['port']}</strong></td>
          <td>{p['service']}</td>
          <td><span class="badge" style="background:{color}">{p['severity']}</span></td>
          <td>{p['note']}</td>
        </tr>"""

    vuln_cards = ""
    for v in sorted_vulns:
        color = SEVERITY_COLOR.get(v.severity, "#6b7280")
        detail_block = f'<p class="detail">ℹ {v.detail}</p>' if v.detail else ""
        vuln_cards += f"""
        <div class="card">
          <div class="card-header" style="border-left: 5px solid {color};">
            <span class="badge" style="background:{color}">{v.severity}</span>
            <span class="card-title">{v.title}</span>
            <span class="category-tag">{v.category}</span>
          </div>
          <div class="card-body">
            <p><strong>Description:</strong> {v.description}</p>
            <p><strong>Recommendation:</strong> {v.recommendation}</p>
            {detail_block}
          </div>
        </div>"""

    sysinfo_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in result.system_info.items()
    )

    summary_badges = "".join(
        f'<div class="summary-item"><span class="big-num" style="color:{SEVERITY_COLOR[s]}">{counts[s]}</span><span class="sev-label">{s}</span></div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    total = len(result.vulnerabilities)
    open_port_count = len(result.open_ports)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Report – {result.target}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #273548;
    --text: #e2e8f0; --muted: #94a3b8; --border: #334155;
    --accent: #38bdf8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
          color: var(--text); padding: 2rem; }}
  h1 {{ font-size: 2rem; color: var(--accent); margin-bottom: .25rem; }}
  .subtitle {{ color: var(--muted); margin-bottom: 2rem; font-size: .95rem; }}
  .summary-grid {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .summary-item {{ background: var(--surface); border: 1px solid var(--border);
                   border-radius: 10px; padding: 1rem 1.5rem; text-align: center;
                   min-width: 100px; flex: 1; }}
  .big-num {{ display: block; font-size: 2.5rem; font-weight: 700; }}
  .sev-label {{ font-size: .75rem; color: var(--muted); letter-spacing: .05em; }}
  .stat-row {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat-box {{ background: var(--surface); border: 1px solid var(--border);
               border-radius: 8px; padding: .75rem 1.25rem; }}
  .stat-box span {{ font-size: 1.5rem; font-weight: 700; color: var(--accent); }}
  h2 {{ font-size: 1.25rem; color: var(--accent); margin: 2rem 0 1rem; padding-bottom: .5rem;
         border-bottom: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface);
           border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }}
  th {{ background: var(--surface2); padding: .75rem 1rem; text-align: left;
        font-size: .8rem; letter-spacing: .05em; color: var(--muted); }}
  td {{ padding: .75rem 1rem; border-top: 1px solid var(--border);
        font-size: .9rem; }}
  .badge {{ display: inline-block; padding: .2rem .6rem; border-radius: 4px;
             color: #fff; font-size: .75rem; font-weight: 700; }}
  .card {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  .card-header {{ display: flex; align-items: center; gap: .75rem;
                  padding: .85rem 1rem; background: var(--surface2); flex-wrap: wrap; }}
  .card-title {{ font-weight: 600; flex: 1; }}
  .category-tag {{ font-size: .72rem; color: var(--muted); background: var(--bg);
                   padding: .2rem .5rem; border-radius: 4px; }}
  .card-body {{ padding: .85rem 1rem; font-size: .9rem; line-height: 1.6; }}
  .card-body p {{ margin-bottom: .4rem; }}
  .detail {{ color: var(--muted); font-size: .82rem; font-style: italic; }}
  .no-vulns {{ color: var(--muted); font-style: italic; padding: 1rem; }}
  footer {{ margin-top: 3rem; text-align: center; color: var(--muted); font-size: .8rem; }}
  @media print {{ body {{ background: #fff; color: #000; }} }}
</style>
</head>
<body>

<h1>🔍 Vulnerability Scanner Report</h1>
<p class="subtitle">Target: <strong>{result.target}</strong> &nbsp;|&nbsp; Scanned: {result.scan_time}</p>

<div class="summary-grid">{summary_badges}</div>

<div class="stat-row">
  <div class="stat-box">Open Ports: <span>{open_port_count}</span></div>
  <div class="stat-box">Total Findings: <span>{total}</span></div>
</div>

<h2>📡 Open Ports</h2>
{"<table><thead><tr><th>PORT</th><th>SERVICE</th><th>RISK</th><th>NOTES</th></tr></thead><tbody>" + port_rows + "</tbody></table>"
  if result.open_ports else '<p class="no-vulns">No open ports detected in scanned range.</p>'}

<h2>⚠️ Vulnerability Findings</h2>
{"".join(vuln_cards) if vuln_cards else '<p class="no-vulns">No vulnerabilities found.</p>'}

<h2>💻 System Information</h2>
<table>
  <thead><tr><th>KEY</th><th>VALUE</th></tr></thead>
  <tbody>{sysinfo_rows}</tbody>
</table>

<footer>Generated by VulnScanner v1.0 · {result.scan_time}</footer>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)


# ─────────────────────────── Main Runner ────────────────────────────

def resolve_target(target: str) -> str:
    """Resolve hostname to IP."""
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"  Resolved {target} → {ip}")
        return ip
    except socket.gaierror:
        print(f"  [!] Could not resolve hostname: {target}")
        return target

def run_scan(target: str, port_range: tuple = (1, 1024), output_dir: str = ".") -> str:
    print(f"\n{'='*55}")
    print(f"  VULNERABILITY SCANNER")
    print(f"{'='*55}")
    print(f"  Target  : {target}")
    print(f"  Ports   : {port_range[0]}–{port_range[1]}")
    print(f"{'='*55}\n")

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = ScanResult(target=target, scan_time=scan_time)

    # 1. Resolve
    resolved = resolve_target(target)

    # 2. Port scan
    print("[1/4] Port Scanning ...")
    extra = list(WELL_KNOWN_PORTS.keys())  # always check known risky ports
    result.open_ports = scan_ports(resolved, port_range, extra_ports=extra)

    # 3. HTTP header checks
    print("[2/4] HTTP Security Header Analysis ...")
    http_vulns = check_http_headers(target)
    result.vulnerabilities.extend(http_vulns)
    print(f"       {len(http_vulns)} header issue(s) found.")

    # 4. Software versions
    print("[3/4] Software Version Checks ...")
    sw_vulns = check_software_versions()
    result.vulnerabilities.extend(sw_vulns)
    print(f"       {len(sw_vulns)} outdated software finding(s).")

    # 5. Firewall check
    print("[4/4] Firewall / OS Checks ...")
    fw_vulns = check_firewall()
    result.vulnerabilities.extend(fw_vulns)
    print(f"       {len(fw_vulns)} firewall issue(s).")

    # 6. System info
    result.system_info = get_system_info()

    # 7. Convert open port risks to Vulnerability entries
    for p in result.open_ports:
        if p["severity"] in ("CRITICAL", "HIGH"):
            result.vulnerabilities.append(Vulnerability(
                title=f"Risky Port {p['port']} ({p['service']}) Open",
                severity=p["severity"],
                category="Open Ports",
                description=p["note"],
                recommendation=f"Review whether port {p['port']} needs to be publicly accessible.",
                detail=f"Port {p['port']}/{p['service']} is open on {resolved}"
            ))

    # 8. Generate report
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target.replace(".", "_").replace(":", "_")
    report_name = f"vuln_report_{safe_target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join(output_dir, report_name)
    generate_html_report(result, report_path)

    # Summary
    counts = {}
    for v in result.vulnerabilities:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    print(f"\n{'='*55}")
    print("  SCAN COMPLETE — SUMMARY")
    print(f"{'='*55}")
    print(f"  Open Ports : {len(result.open_ports)}")
    print(f"  Findings   : {len(result.vulnerabilities)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev, 0):
            print(f"    {sev:<10}: {counts[sev]}")
    print(f"\n  Report saved → {report_path}")
    print(f"{'='*55}\n")

    return report_path


# ─────────────────────────── CLI Entry ──────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner — scans ports, headers, and software versions."
    )
    parser.add_argument("target", help="Target hostname or IP (e.g. scanme.nmap.org)")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range, e.g. 1-1024 (default) or 1-65535")
    parser.add_argument("--output", default="reports",
                        help="Directory to save HTML report (default: ./reports)")
    args = parser.parse_args()

    start, end = (int(x) for x in args.ports.split("-"))
    run_scan(args.target, port_range=(start, end), output_dir=args.output)
