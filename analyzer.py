import geoip2.database
from datetime import datetime

def get_country(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        response = reader.country(ip)
        return response.country.name
    except:
        return 'Unknown'

def analyze_log(df):
    report = []
    ips = df['ip'].value_counts()

    unusual_ips = [ip for ip, count in ips.items() if count > 50]
    for ip in unusual_ips:
        country = get_country(ip)
        report.append(f'🔴 Подозрительный IP {ip} ({country}): более 50 запросов.')

    if len(report) == 0:
        report.append('🟢 Аномалий не выявлено.')

    return '\n'.join(report)
