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
    """
    Super-analyze classic server logs (DataFrame).
    """
    report = []
    suspicious_ips = set()
    ip_payloads = {}
    ip_urls = {}
    fast_access = {}

    if df.empty:
        return "Log file is empty or parsing failed."

    # Ensure datetime and timestamp columns
    if 'datetime' in df.columns:
        df['timestamp'] = df['datetime'].dt.floor('min')
    elif 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.floor('min')

    report.append("=== DeepLog Log Super Analysis ===\n")

    # 1. Event frequency (by URL)
    if 'url' in df.columns:
        url_counts = df['url'].value_counts()
        report.append("🗂️ Endpoint Frequency:")
        for url, count in url_counts.items():
            report.append(f"  - {url}: {count}")
        report.append("")

    # 2. HTTP Methods
    if 'method' in df.columns:
        method_counts = df['method'].value_counts()
        report.append("🔎 HTTP Methods Used:")
        for method, count in method_counts.items():
            report.append(f"  - {method}: {count}")
        report.append("")

    # 3. Status Codes
    if 'status' in df.columns:
        status_counts = df['status'].value_counts()
        report.append("📊 Status Codes:")
        for status, count in status_counts.items():
            report.append(f"  - {status}: {count}")
        report.append("")

    # 4. Top IPs
    if 'ip' in df.columns:
        ip_counts = df['ip'].value_counts()
        report.append("🌐 Top IPs:")
        for ip, count in ip_counts.items():
            report.append(f"  - {ip} ({resolve_ip(ip)}): {count} requests")
        report.append("")

    # 5. Top endpoints/targets
    if 'url' in df.columns:
        top_endpoints = df['url'].value_counts().head(10)
        report.append("🎯 Top Endpoints:")
        for url, count in top_endpoints.items():
            report.append(f"  - {url}: {count} hits")
        report.append("")

    # 6. Detect payloads in URLs
    if 'url' in df.columns and 'ip' in df.columns:
        for _, row in df.iterrows():
            ip = row['ip']
            url = row['url']
            ip_urls.setdefault(ip, []).append(url)
            findings = detect_payloads(url)
            if findings:
                ip_payloads.setdefault(ip, set()).update(findings)
                suspicious_ips.add(ip)
        if ip_payloads:
            report.append("💉 Payloads Detected:")
            for ip, payloads in ip_payloads.items():
                report.append(f"  - {ip}: {', '.join(payloads)}")
            report.append("")

    # 7. Fast access burst check
    if 'ip' in df.columns and 'timestamp' in df.columns:
        access_counts = df.groupby(['ip', 'timestamp']).size().reset_index(name='count')
        fast = access_counts[access_counts['count'] >= 10]
        if not fast.empty:
            report.append("⚡ Fast access bursts detected:")
            for _, row in fast.iterrows():
                ip = row['ip']
                suspicious_ips.add(ip)
                fast_access[ip] = fast_access.get(ip, 0) + 1
                report.append(f"  - {ip} made {row['count']} requests at {row['timestamp']}")
            report.append("")

    # 8. Known attack paths
    attack_paths = ['/admin', '/phpmyadmin', '/config.php', '/.env', '/wp-login.php']
    if 'url' in df.columns:
        attack_hits = df[df['url'].isin(attack_paths)]
        if not attack_hits.empty:
            report.append("🛠️ Access to known attack paths:")
            for _, row in attack_hits.iterrows():
                suspicious_ips.add(row['ip'])
                report.append(f"  - {row['ip']} -> {row['url']}")
            report.append("")

    # 9. Frequent requests per IP
    if 'ip' in df.columns:
        frequent_ips = df['ip'].value_counts()
        frequent_ips = frequent_ips[frequent_ips > 3]
        if not frequent_ips.empty:
            report.append("🔁 Frequent requests from IPs:")
            for ip, count in frequent_ips.items():
                suspicious_ips.add(ip)
                report.append(f"  - {ip} ({resolve_ip(ip)}): {count} requests")
            report.append("")

    # 10. Night-time access detection (0-5 AM)
    if 'datetime' in df.columns:
        night = df[df['datetime'].dt.hour.between(0, 5)]
        if not night.empty:
            report.append("🌙 Night-time access:")
            for _, row in night.iterrows():
                suspicious_ips.add(row['ip'])
                t = row['datetime'].strftime('%H:%M')
                report.append(f"  - {row['ip']} at {t} -> {row['url']}")
            report.append("")

    # 11. Status 4xx/5xx errors
    if 'status' in df.columns:
        errors = df[df['status'].astype(str).str.startswith(('4', '5'))]
        if not errors.empty:
            report.append("🚨 Access errors (4xx/5xx):")
            for _, row in errors.iterrows():
                suspicious_ips.add(row['ip'])
                report.append(f"  - {row['ip']} -> {row['url']} [{row['status']}]")
            report.append("")

    # 12. Uncommon HTTP methods
    if 'method' in df.columns:
        common_methods = {'GET', 'POST', 'HEAD'}
        uncommon = df[~df['method'].isin(common_methods)]
        if not uncommon.empty:
            report.append("🧪 Uncommon HTTP methods:")
            for _, row in uncommon.iterrows():
                suspicious_ips.add(row['ip'])
                report.append(f"  - {row['ip']} used {row['method']} on {row['url']}")
            report.append("")

    # 13. Brute-force login detection (401)
    if 'status' in df.columns and 'ip' in df.columns:
        brute_df = df[df['status'] == '401']
        brute_attempts = brute_df['ip'].value_counts()
        if not brute_attempts.empty:
            report.append("🔐 Brute-force suspicion (401 Unauthorized):")
            for ip, count in brute_attempts.items():
                if count >= 3:
                    suspicious_ips.add(ip)
                    report.append(f"  - {ip}: {count} attempts")
            report.append("")

    # 14. DoS detection (5xx flood)
    if 'status' in df.columns and 'ip' in df.columns:
        dos_df = df[df['status'].astype(str).str.startswith('5')]
        if not dos_df.empty and dos_df['ip'].value_counts().max() > 3:
            report.append("🔥 Possible DoS attack:")
            for ip, count in dos_df['ip'].value_counts().items():
                if count > 3:
                    suspicious_ips.add(ip)
                    report.append(f"  - {ip}: {count} 5xx errors")
            report.append("")

    # 15. Suspicious high diversity of endpoints from single IP
    if 'ip' in df.columns and 'url' in df.columns:
        endpoint_diversity = df.groupby('ip')['url'].nunique()
        suspicious_diverse = endpoint_diversity[endpoint_diversity > 10]
        if not suspicious_diverse.empty:
            report.append("🕵️ High endpoint diversity per IP:")
            for ip, count in suspicious_diverse.items():
                suspicious_ips.add(ip)
                report.append(f"  - {ip}: {count} unique endpoints")
            report.append("")

    # 16. Timeline of requests
    if 'datetime' in df.columns:
        df_sorted = df.sort_values('datetime')
        report.append("🕒 Timeline of Requests:")
        for _, row in df_sorted.iterrows():
            ts = row.get('datetime', '')
            ip = row.get('ip', '')
            url = row.get('url', '')
            method = row.get('method', '')
            status = row.get('status', '')
            line = f"  - [{ts}] {ip} {method} {url} [{status}]"
            report.append(line)
        report.append("")

    # 17. Summary of suspicious IPs
    if suspicious_ips:
        report.append("📍 Summary of Suspicious IPs:")
        for ip in sorted(suspicious_ips):
            geo = geolocate_ip(ip)
            vpn = " [VPN suspected]" if is_known_vpn(ip) else ""
            payloads = ", ".join(ip_payloads.get(ip, []))
            note = f" | Payloads: {payloads}" if payloads else ""
            report.append(f"  - {ip} ({resolve_ip(ip)}) | {geo}{vpn}{note}")
        report.append("")

    if len(report) == 1:
        return "✅ No significant events found in log."

    return '\n'.join(report)

def analyze_json_log(json_data):
    """
    Super-analyze logs in JSON format (list of dicts).
    """
    import pandas as pd

    if not json_data or not isinstance(json_data, list):
        return "JSON log is empty or invalid format."

    df = pd.DataFrame(json_data)
    report = []

    # Convert timestamp to datetime if present
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    report.append("=== DeepLog JSON Super Analysis ===\n")

    # 1. Event frequency
    if 'event' in df.columns:
        event_counts = df['event'].value_counts()
        report.append("🗂️ Event Frequency:")
        for event, count in event_counts.items():
            report.append(f"  - {event}: {count}")
        report.append("")

    # 2. Log levels
    if 'level' in df.columns:
        level_counts = df['level'].value_counts()
        report.append("🔎 Log Levels:")
        for level, count in level_counts.items():
            report.append(f"  - {level}: {count}")
        report.append("")

    # 3. User activity
    if 'user' in df.columns:
        user_counts = df['user'].value_counts()
        report.append("👤 User Activity:")
        for user, count in user_counts.items():
            report.append(f"  - {user}: {count} events")
        report.append("")

    # 4. Top targets
    if 'target' in df.columns:
        target_counts = df['target'].value_counts()
        report.append("🎯 Top Targets:")
        for tgt, count in target_counts.items():
            report.append(f"  - {tgt}: {count} events")
        report.append("")

    # 5. Top scanners
    if 'scanner' in df.columns:
        scanner_counts = df['scanner'].value_counts()
        report.append("🛠️ Scanners Used:")
        for scanner, count in scanner_counts.items():
            report.append(f"  - {scanner}: {count} times")
        report.append("")

    # 6. Vulnerabilities found
    if 'vulnerability' in df.columns:
        vuln_counts = df['vulnerability'].value_counts()
        report.append("⚠️ Vulnerabilities Detected:")
        for vuln, count in vuln_counts.items():
            report.append(f"  - {vuln}: {count} times")
        report.append("")

    # 7. Errors and warnings
    if 'level' in df.columns:
        errors = df[df['level'].isin(['ERROR', 'WARNING'])]
        if not errors.empty:
            report.append("🚨 Errors and Warnings:")
            for _, row in errors.iterrows():
                ts = row.get('timestamp', '')
                evt = row.get('event', '')
                msg = row.get('message', '')
                report.append(f"  - [{ts}] {evt}: {msg}")
            report.append("")

    # 8. Timeline of events
    if 'timestamp' in df.columns:
        df_sorted = df.sort_values('timestamp')
        report.append("🕒 Timeline of Events:")
        for _, row in df_sorted.iterrows():
            ts = row.get('timestamp', '')
            evt = row.get('event', '')
            msg = row.get('message', '')
            user = row.get('user', '')
            line = f"  - [{ts}] {evt}"
            if user:
                line += f" (user: {user})"
            if msg:
                line += f": {msg}"
            report.append(line)
        report.append("")

    # 9. Files involved
    if 'file' in df.columns or 'filename' in df.columns:
        files = pd.concat([
            df['file'] if 'file' in df.columns else pd.Series(dtype=str),
            df['filename'] if 'filename' in df.columns else pd.Series(dtype=str)
        ])
        file_counts = files.value_counts()
        if not file_counts.empty:
            report.append("📄 Files Involved:")
            for fname, count in file_counts.items():
                report.append(f"  - {fname}: {count} times")
            report.append("")

    # 10. Payloads detected
    if 'payload' in df.columns:
        payloads = df['payload'].dropna().unique()
        if len(payloads):
            report.append("💉 Payloads Detected:")
            for payload in payloads:
                report.append(f"  - {payload}")
            report.append("")

    # 11. Statuses
    if 'status' in df.columns:
        status_counts = df['status'].value_counts()
        report.append("📊 Status Codes:")
        for status, count in status_counts.items():
            report.append(f"  - {status}: {count}")
        report.append("")

    # 12. Success/failure of reports
    if 'status' in df.columns and 'event' in df.columns:
        report_events = df[df['event'].str.contains('Report', na=False)]
        if not report_events.empty:
            report.append("📑 Report Generation Events:")
            for _, row in report_events.iterrows():
                ts = row.get('timestamp', '')
                fname = row.get('filename', row.get('file', ''))
                status = row.get('status', '')
                msg = row.get('message', '')
                report.append(f"  - [{ts}] {fname} ({status}): {msg}")
            report.append("")

    # 13. Anything else you want to add...

    if len(report) == 1:
        return "✅ No significant events found in JSON log."

    return "\n".join(report)
