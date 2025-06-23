from datetime import datetime
import pandas as pd

def analyze_log(df):
    report = []

    if df.empty:
        return "Лог-файл пуст или не удалось распарсить."

    # Проверка на частые запросы
    ip_counts = df['ip'].value_counts()
    frequent_ips = ip_counts[ip_counts > 3]
    if not frequent_ips.empty:
        report.append("\n🔁 Частые запросы с IP:")
        for ip, count in frequent_ips.items():
            report.append(f"- IP {ip}: {count} запросов")

    # Проверка на ночной доступ (0-5 ч)
    night = df[df['datetime'].dt.hour.between(0, 5)]
    if not night.empty:
        report.append("\n🌙 Доступ в ночное время:")
        for _, row in night.iterrows():
            t = row['datetime'].strftime('%H:%M')
            report.append(f"- {row['ip']} в {t} -> {row['url']}")

    # Ошибки 4xx и 5xx
    errors = df[df['status'].astype(str).str.startswith(('4', '5'))]
    if not errors.empty:
        report.append("\n🚨 Ошибки доступа (4xx/5xx):")
        for _, row in errors.iterrows():
            report.append(f"- {row['ip']} -> {row['url']} [{row['status']}]")

    # Проверка на нестандартные HTTP-методы
    common_methods = {'GET', 'POST', 'HEAD'}
    uncommon = df[~df['method'].isin(common_methods)]
    if not uncommon.empty:
        report.append("\n🧪 Подозрительные HTTP-методы:")
        for _, row in uncommon.iterrows():
            report.append(f"- {row['ip']} использует {row['method']} на {row['url']}")

    # Анализ последовательных неудачных логинов (401)
    brute_df = df[df['status'] == '401']
    brute_attempts = brute_df['ip'].value_counts()
    if not brute_attempts.empty:
        report.append("\n🔐 Подозрение на брутфорс (401):")
        for ip, count in brute_attempts.items():
            if count >= 3:
                report.append(f"- {ip}: {count} попыток")

    # Анализ частоты 5xx (возможный DoS)
    dos_df = df[df['status'].astype(str).str.startswith('5')]
    if not dos_df.empty and dos_df['ip'].value_counts().max() > 3:
        report.append("\n🔥 Возможная DoS-атака:")
        for ip, count in dos_df['ip'].value_counts().items():
            if count > 3:
                report.append(f"- {ip}: {count} ошибок 5xx")

    if not report:
        return "✅ Аномалий не выявлено."

    return '\n'.join(report)