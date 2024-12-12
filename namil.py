import re
import json
import csv
from collections import defaultdict
from bs4 import BeautifulSoup
log_file = 'server_logs.txt'
log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) /login HTTP/1.1" (\d+) (\d+)'
html_file = 'index.html'
uğursuz_giriş = defaultdict(int)
log_data = []
with open(log_file, 'r') as f:
    for line in f:
        match = re.search(log_pattern, line)
        if match:
            ip = match.group(1)
            tarix = match.group(2)
            metod = match.group(3)
            status_kodu = match.group(4)
            ölçüsü = match.group(5)
            log_data.append({'IP': ip, 'Tarix': tarix, 'Metod': metod, 'Status': status_kodu})
            if status_kodu in {'400', '401', '403', '404', '429'}:
                uğursuz_giriş[ip] += 1
uğursuz_giriş_ip = {ip: count for ip, count in uğursuz_giriş.items() if count > 5}
threat_ips = []
with open(html_file, 'r') as f:
    soup = BeautifulSoup(f, 'html.parser')
    rows = soup.find_all('tr')
    for row in rows[1:]:
        cols = row.find_all('td')
        if cols:
            threat_ips.append(cols[0].text.strip())
threat_ip_data = [entry for entry in log_data if entry['IP'] in threat_ips]
with open('failed_logins.json', 'w') as f:
    json.dump(uğursuz_giriş_ip, f, indent=4)
with open('threat_ips.json', 'w') as f:
    json.dump(threat_ips, f, indent=4)
combined_security_data = {
    'failed_logins': uğursuz_giriş_ip,
    'threat_ips': threat_ips
}
with open('combined_security_data.json', 'w') as f:
    json.dump(combined_security_data, f, indent=4)
with open('log_analysis.txt', 'w') as f:
    for ip, count in uğursuz_giriş_ip.items():
        f.write(f"{ip} failed {count} login attempts\n")
with open('log_analysis.csv', 'w', newline='') as csvfile:
    fieldnames = ['IP', 'Tarix', 'Metod', 'Status']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for entry in log_data:
        writer.writerow(entry)
print("Bütün əməliyyatlar yerinə yetirildi")