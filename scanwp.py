#!/usr/bin/env python3

import json
import subprocess
import os
from datetime import datetime

API_TOKEN = os.getenv("WPSCAN_API_TOKEN")
if not API_TOKEN:
    print("❌ Please set your WPScan API token in the WPSCAN_API_TOKEN environment variable.")
    exit(1)

def banner():
    print("\n" + "="*60)
    print("🔍 WordPress Vulnerability Scanner CLI - by Emmanuel")
    print("="*60 + "\n")

def prompt_url():
    url = input("🌐 Enter WordPress site URL (e.g., https://example.com): ").strip()
    return url

def run_wpscan(url, output_file="scan_raw.json"):
    print("\n🚀 Running WPScan... (this may take a minute)")
    cmd = [
        "wpscan",
        "--url", url,
        "--format", "json",
        "--output", output_file,
        "--enumerate", "vt,u,vp,tt",
        "--api-token", API_TOKEN
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL)
    if not os.path.exists(output_file):
        print("❌ WPScan failed or no output generated.")
        exit(1)
    with open(output_file) as f:
        return json.load(f)

def estimate_severity(title):
    title = title.lower()
    if 'unauthenticated' in title: return 'Critical'
    if 'authenticated' in title: return 'High'
    if 'disclosure' in title or 'exposure' in title: return 'Low'
    return 'Medium'

def detect_type(title):
    title = title.lower()
    if 'xss' in title: return "XSS"
    if 'csrf' in title: return "CSRF"
    if 'sql' in title or 'sqli' in title: return "SQL Injection"
    if 'ssrf' in title: return "SSRF"
    if 'redirect' in title: return "Open Redirect"
    if 'bypass' in title: return "Auth Bypass"
    return "Other"

def parse_output(data):
    site_info = {
        "URL": data["target_url"],
        "IP": data["target_ip"],
        "WordPress": data["version"]["number"],
        "Outdated": data["version"]["status"] == "insecure",
        "PHP": "",
        "Server": ""
    }

    headers = []
    public_files = []
    for finding in data["interesting_findings"]:
        if finding["type"] == "headers":
            for entry in finding["interesting_entries"]:
                headers.append(entry)
                if entry.lower().startswith("x-powered-by:"):
                    site_info["PHP"] = entry.split(":", 1)[1].strip()
                elif entry.lower().startswith("server:"):
                    site_info["Server"] = entry.split(":", 1)[1].strip()
        elif finding["type"] in ["readme", "xmlrpc", "wp_cron"]:
            public_files.append(finding["url"])

    users = list(data.get("users", {}).keys())

    theme = data.get("main_theme", {})
    theme_info = f"{theme['style_name']} v{theme['version']['number']} (latest: {theme['latest_version']})"
    if theme.get("outdated"):
        theme_info += " ⚠️ Outdated"

    vulnerabilities = []
    for vuln in data["version"].get("vulnerabilities", []):
        vulnerabilities.append({
            "title": vuln["title"],
            "severity": estimate_severity(vuln["title"]),
            "type": detect_type(vuln["title"]),
            "fixed_in": vuln.get("fixed_in"),
            "cve": vuln.get("references", {}).get("cve", []),
            "references": vuln.get("references", {}).get("url", [])
        })

    plugin_vulns = []
    for name, plugin in data.get("plugins", {}).items():
        for vuln in plugin.get("vulnerabilities", []):
            plugin_vulns.append({
                "name": name,
                "title": vuln["title"],
                "severity": estimate_severity(vuln["title"]),
                "type": detect_type(vuln["title"]),
                "fixed_in": vuln.get("fixed_in")
            })

    theme_vulns = []
    for name, theme in data.get("themes", {}).items():
        for vuln in theme.get("vulnerabilities", []):
            theme_vulns.append({
                "name": name,
                "title": vuln["title"],
                "severity": estimate_severity(vuln["title"]),
                "type": detect_type(vuln["title"]),
                "fixed_in": vuln.get("fixed_in")
            })

    return {
        "site_info": site_info,
        "headers": headers,
        "public_files": public_files,
        "users": users,
        "theme": theme_info,
        "vulnerabilities": vulnerabilities,
        "plugin_vulnerabilities": plugin_vulns,
        "theme_vulnerabilities": theme_vulns
    }

def print_report(report):
    print("\n📄 Site Information")
    for k, v in report["site_info"].items():
        print(f"  - {k}: {v}")

    print("\n🎨 Theme")
    print(f"  - {report['theme']}")

    print("\n👥 Users Found")
    if report["users"]:
        for user in report["users"]:
            print(f"  - {user}")
    else:
        print("  - None")

    print("\n🗂️ Public Files")
    if report["public_files"]:
        for f in report["public_files"]:
            print(f"  - {f}")
    else:
        print("  - None")

    print("\n🔐 HTTP Headers")
    for h in report["headers"]:
        print(f"  - {h}")

    print("\n🚨 Core Vulnerabilities")
    for v in report["vulnerabilities"]:
        print(f"\n  🔸 {v['title']}")
        print(f"     - Severity : {v['severity']}")
        print(f"     - Type     : {v['type']}")
        if v.get("fixed_in"):
            print(f"     - Fixed In : {v['fixed_in']}")
        if v.get("cve"):
            print(f"     - CVE(s)   : {', '.join(v['cve'])}")
        if v.get("references"):
            print(f"     - References(s)   : {', '.join(v['references'])}")

    print("\n🧩 Plugin Vulnerabilities")
    for v in report["plugin_vulnerabilities"]:
        print(f"\n  🔌 Plugin: {v['name']}")
        print(f"     - Title    : {v['title']}")
        print(f"     - Severity : {v['severity']}")
        print(f"     - Type     : {v['type']}")
        if v.get("fixed_in"):
            print(f"     - Fixed In : {v['fixed_in']}")

    print("\n🎨 Theme Vulnerabilities")
    for v in report["theme_vulnerabilities"]:
        print(f"\n  🎨 Theme: {v['name']}")
        print(f"     - Title    : {v['title']}")
        print(f"     - Severity : {v['severity']}")
        print(f"     - Type     : {v['type']}")
        if v.get("fixed_in"):
            print(f"     - Fixed In : {v['fixed_in']}")

    print("\n✅ Scan completed at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def main():
    banner()
    url = prompt_url()
    raw = run_wpscan(url)
    report = parse_output(raw)
    print_report(report)

if __name__ == "__main__":
    main()