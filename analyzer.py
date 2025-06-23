from datetime import datetime
import pandas as pd

def analyze_log(df):
    report = []

    # Анализ IP по частоте запросов
    ip_counts = df['ip'].value_counts()
    suspicious_ips = ip_counts[ip_counts > 3]
    if not suspicious_ips.empty:
        report.append("🔴 Подозрительные IP (частые запросы):")
        for ip, count in suspicious_ips.items():
            report.append(f"— IP {ip}: {count} запросов")

    # Подозрительные запросы по времени (ночь)
    night_access = df[df['datetime'].dt.hour.isin(range(0, 6))]
    if not night_access.empty:
        report.append("\n🌙 Подозрительные ночные доступы:")
        for _, row in night_access.iterrows():
            time_str = row['datetime'].strftime('%d/%m/%Y %H:%M:%S')
            report.append(f"— IP {row['ip']} в {time_str}")

    # Анализ ошибок доступа (статус 4xx и 5xx)
    errors = df[df['status'].astype(str).str.startswith(('4', '5'))]
    if not errors.empty:
        report.append("\n🚨 Обнаружены ошибки доступа:")
        for _, row in errors.iterrows():
            report.append(f"— IP {row['ip']} запросил {row['url']} (статус {row['status']})")

    if not report:
        report.append("✅ Аномалий не обнаружено.")

    return '\n'.join(report)
