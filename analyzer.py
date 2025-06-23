from datetime import datetime
import pandas as pd
import socket
import requests
import re


def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "(no hostname)"


def geolocate_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,proxy,hosting", timeout=2)
        data = response.json()
        if data['status'] == 'success':
            tags = []
            if data.get('proxy'): tags.append("Proxy")
            if data.get('hosting'): tags.append("Hosting")
            tag_str = f" [{' | '.join(tags)}]" if tags else ""
            return f"{data['country']} | {data['regionName']} | {data['city']}{tag_str}"
        else:
            return "(location unknown)"
    except:
        return "(location error)"


def is_known_vpn(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        data = response.json()
        if data.get("org") and any(keyword in data["org"].lower() for keyword in ["vpn", "hosting", "cloud", "digitalocean", "aws", "azure", "ovh", "linode"]):
            return True
    except:
        pass
    return False


def detect_payloads(url):
    payloads = {
        "XSS": ["<script", "onerror=", "alert(", "<svg"],
        "SQLi": ["' or 1=1", "union select", "--", "' and"],
        "LFI": ["../", "/etc/passwd"],
        "RCE": [";", "|", "`", "$", "cmd="]
    }
    detected = []
    url_lower = url.lower()
    for p_type, patterns in payloads.items():
        if any(p in url_lower for p in patterns):
            detected.append(p_type)
    return detected


def analyze_log(df):
    report = []
    suspicious_ips = set()
    ip_payloads = {}
    ip_urls = {}
    fast_access = {}

    if df.empty:
        return "Log file is empty or parsing failed."

    df['timestamp'] = df['datetime'].dt.floor('min')


    # Detect payloads in URLs
    for _, row in df.iterrows():
        ip = row['ip']
        url = row['url']
        ip_urls.setdefault(ip, []).append(url)
        findings = detect_payloads(url)
        if findings:
            ip_payloads.setdefault(ip, set()).update(findings)
            suspicious_ips.add(ip)

    # Fast access burst check
    access_counts = df.groupby(['ip', 'timestamp']).size().reset_index(name='count')
    fast = access_counts[access_counts['count'] >= 10]
    if not fast.empty:
        report.append("\n⚡ Fast access bursts detected:")
        for _, row in fast.iterrows():
            ip = row['ip']
            suspicious_ips.add(ip)
            fast_access[ip] = fast_access.get(ip, 0) + 1
            report.append(f"- {ip} made {row['count']} requests at {row['timestamp']}")

    # Known attack paths
    attack_paths = ['/admin', '/phpmyadmin', '/config.php', '/.env', '/wp-login.php']
    attack_hits = df[df['url'].isin(attack_paths)]
    if not attack_hits.empty:
        report.append("\n🛠️ Access to known attack paths:")
        for _, row in attack_hits.iterrows():
            suspicious_ips.add(row['ip'])
            report.append(f"- {row['ip']} -> {row['url']}")

    # Frequent requests per IP
    ip_counts = df['ip'].value_counts()
    frequent_ips = ip_counts[ip_counts > 3]
    if not frequent_ips.empty:
        report.append("\n🔁 Frequent requests from IPs:")
        for ip, count in frequent_ips.items():
            suspicious_ips.add(ip)
            report.append(f"- {ip} ({resolve_ip(ip)}): {count} requests")

    # Night-time access detection (0-5 AM)
    night = df[df['datetime'].dt.hour.between(0, 5)]
    if not night.empty:
        report.append("\n🌙 Night-time access:")
        for _, row in night.iterrows():
            suspicious_ips.add(row['ip'])
            t = row['datetime'].strftime('%H:%M')
            report.append(f"- {row['ip']} at {t} -> {row['url']}")

    # Status 4xx/5xx errors
    errors = df[df['status'].astype(str).str.startswith(('4', '5'))]
    if not errors.empty:
        report.append("\n🚨 Access errors (4xx/5xx):")
        for _, row in errors.iterrows():
            suspicious_ips.add(row['ip'])
            report.append(f"- {row['ip']} -> {row['url']} [{row['status']}]")

    # Uncommon HTTP methods
    common_methods = {'GET', 'POST', 'HEAD'}
    uncommon = df[~df['method'].isin(common_methods)]
    if not uncommon.empty:
        report.append("\n🧪 Uncommon HTTP methods:")
        for _, row in uncommon.iterrows():
            suspicious_ips.add(row['ip'])
            report.append(f"- {row['ip']} used {row['method']} on {row['url']}")

    # Brute-force login detection (401)
    brute_df = df[df['status'] == '401']
    brute_attempts = brute_df['ip'].value_counts()
    if not brute_attempts.empty:
        report.append("\n🔐 Brute-force suspicion (401 Unauthorized):")
        for ip, count in brute_attempts.items():
            if count >= 3:
                suspicious_ips.add(ip)
                report.append(f"- {ip}: {count} attempts")

    # DoS detection (5xx flood)
    dos_df = df[df['status'].astype(str).str.startswith('5')]
    if not dos_df.empty and dos_df['ip'].value_counts().max() > 3:
        report.append("\n🔥 Possible DoS attack:")
        for ip, count in dos_df['ip'].value_counts().items():
            if count > 3:
                suspicious_ips.add(ip)
                report.append(f"- {ip}: {count} 5xx errors")

    # Suspicious high diversity of endpoints from single IP
    endpoint_diversity = df.groupby('ip')['url'].nunique()
    suspicious_diverse = endpoint_diversity[endpoint_diversity > 10]
    if not suspicious_diverse.empty:
        report.append("\n🕵️ High endpoint diversity per IP:")
        for ip, count in suspicious_diverse.items():
            suspicious_ips.add(ip)
            report.append(f"- {ip}: {count} unique endpoints")

    # Summary of suspicious IPs
    if suspicious_ips:
        report.append("\n📍 Summary of Suspicious IPs:")
        for ip in sorted(suspicious_ips):
            geo = geolocate_ip(ip)
            vpn = " [VPN suspected]" if is_known_vpn(ip) else ""
            payloads = ", ".join(ip_payloads.get(ip, []))
            note = f" | Payloads: {payloads}" if payloads else ""
            report.append(f"- {ip} ({resolve_ip(ip)}) | {geo}{vpn}{note}")

    if not report:
        return "✅ No anomalies detected."

    return '\n'.join(report)
