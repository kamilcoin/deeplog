from datetime import datetime
import pandas as pd

def analyze_log(df):
    report = []

    if df.empty:
        return "Log file is empty or parsing failed."

    # Frequent requests per IP
    ip_counts = df['ip'].value_counts()
    frequent_ips = ip_counts[ip_counts > 3]
    if not frequent_ips.empty:
        report.append("\n🔁 Frequent requests from IPs:")
        for ip, count in frequent_ips.items():
            report.append(f"- IP {ip}: {count} requests")

    # Night-time access detection (0-5 AM)
    night = df[df['datetime'].dt.hour.between(0, 5)]
    if not night.empty:
        report.append("\n🌙 Night-time access:")
        for _, row in night.iterrows():
            t = row['datetime'].strftime('%H:%M')
            report.append(f"- {row['ip']} at {t} -> {row['url']}")

    # Status 4xx/5xx errors
    errors = df[df['status'].astype(str).str.startswith(('4', '5'))]
    if not errors.empty:
        report.append("\n🚨 Access errors (4xx/5xx):")
        for _, row in errors.iterrows():
            report.append(f"- {row['ip']} -> {row['url']} [{row['status']}]")

    # Uncommon HTTP methods
    common_methods = {'GET', 'POST', 'HEAD'}
    uncommon = df[~df['method'].isin(common_methods)]
    if not uncommon.empty:
        report.append("\n🧪 Uncommon HTTP methods:")
        for _, row in uncommon.iterrows():
            report.append(f"- {row['ip']} used {row['method']} on {row['url']}")

    # Brute-force login detection (401)
    brute_df = df[df['status'] == '401']
    brute_attempts = brute_df['ip'].value_counts()
    if not brute_attempts.empty:
        report.append("\n🔐 Brute-force suspicion (401 Unauthorized):")
        for ip, count in brute_attempts.items():
            if count >= 3:
                report.append(f"- {ip}: {count} attempts")

    # DoS detection (5xx flood)
    dos_df = df[df['status'].astype(str).str.startswith('5')]
    if not dos_df.empty and dos_df['ip'].value_counts().max() > 3:
        report.append("\n🔥 Possible DoS attack:")
        for ip, count in dos_df['ip'].value_counts().items():
            if count > 3:
                report.append(f"- {ip}: {count} 5xx errors")

    # Suspicious high diversity of endpoints from single IP
    endpoint_diversity = df.groupby('ip')['url'].nunique()
    suspicious_diverse = endpoint_diversity[endpoint_diversity > 10]
    if not suspicious_diverse.empty:
        report.append("\n🕵️ High endpoint diversity per IP:")
        for ip, count in suspicious_diverse.items():
            report.append(f"- {ip}: {count} unique endpoints")

    # Repeated error status by one IP
    repeated_errors = df[df['status'].astype(str).str.startswith(('4', '5'))]
    repeated_by_ip = repeated_errors.groupby(['ip', 'status']).size().reset_index(name='count')
    repeated_by_ip = repeated_by_ip[repeated_by_ip['count'] >= 5]
    if not repeated_by_ip.empty:
        report.append("\n⚠️ Repeated errors by single IP:")
        for _, row in repeated_by_ip.iterrows():
            report.append(f"- {row['ip']} -> status {row['status']} {row['count']} times")

    if not report:
        return "✅ No anomalies detected."

    return '\n'.join(report)
