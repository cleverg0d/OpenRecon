# 🛰️ OpenRecon — Asynchronous Reconnaissance Tool for Domain Enumeration
# python3 openrecon.py -d example.com
# 👨‍💻 Author Stanislav Istyagin (aka `@clevergod`)
import argparse
import sys
import time
import socket
import concurrent.futures
import requests
import whois
import ssl
import os
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich import box
import urllib3
import subprocess
from ipwhois import IPWhois
import html

def print_banner():
    print(r"""
 .d88888b.                         8888888b.
d88P" "Y88b                        888   Y88b
888     888                        888    888
888     88888888b.  .d88b. 88888b. 888   d88P .d88b.  .d8888b .d88b. 88888b.
888     888888 "88bd8P  Y8b888 "88b8888888P" d8P  Y8bd88P"   d88""88b888 "88b
888     888888  88888888888888  888888 T88b  88888888888     888  888888  888
Y88b. .d88P888 d88PY8b.    888  888888  T88b Y8b.    Y88b.   Y88..88P888  888
 "Y88888P" 88888P"  "Y8888 888  888888   T88b "Y8888  "Y8888P "Y88P" 888  888
           888
           888
           888
░█▀▄░█░█░░░█▀▀░█░░░█▀▀░█░█░█▀▀░█▀▄░█▀▀░█▀█░█▀▄
░█▀▄░░█░░░░█░░░█░░░█▀▀░▀▄▀░█▀▀░█▀▄░█░█░█░█░█░█
░▀▀░░░▀░░░░▀▀▀░▀▀▀░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀░
""")

# Call banner at startup
print_banner()

parser = argparse.ArgumentParser(
    description="OpenRecon — Asynchronous Reconnaissance Tool for Domain Enumeration"
)
parser.add_argument("-d", "--domain", required=True, help="Target domain")
parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
parser.add_argument("-f", "--full", action="store_true", help="Enable full scan mode")
parser.add_argument("-o", "--output", help="Output file name (CSV format)")
parser.add_argument("--debug", action="store_true", help="Enable debug output")
args = parser.parse_args()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

DEFAULT_PORTS = [80, 443, 40443, 8080, 8443, 8090, 445, 22, 21, 3389, 5985]
FALLBACK_SUBS = ['www', 'mail', 'vpn', 'adfs', 'telbot', 'drive', 'api', 'dev', 'test', 'sip', 'ftp', 'autodiscover', 'crm', 'vpn2', 'doc', 'owa', 'portal', 'remote', 'trade', 'admin', 'cloud']


def get_hosting_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        whois_ip = IPWhois(ip)
        data = whois_ip.lookup_rdap()
        return ip, data.get('network', {}).get('name', '-'), f"{data.get('asn_country_code', '-')}, {data.get('asn_description', '-')}"
    except:
        return '-', '-', '-'


def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {k: (v if v else '-') for k, v in {
            'domain': w.domain_name,
            'org': w.org,
            'name': w.name,
            'emails': w.emails,
            'registrar': w.registrar,
            'status': w.status,
            'created': w.creation_date,
            'expires': w.expiration_date,
            'updated': w.updated_date,
            'name_servers': w.name_servers,
            'dnssec': w.dnssec,
            'country': w.country,
            'city': w.city,
            'state': w.state,
            'postal': w.registrant_postal_code
        }.items()}
    except:
        return {k: '-' for k in ['domain', 'org', 'name', 'emails', 'registrar', 'status', 'created', 'expires', 'updated', 'name_servers', 'dnssec', 'country', 'city', 'state', 'postal']}


def batch_lines(file_path, batch_size=5000):
    with open(file_path) as f:
        batch = []
        for line in f:
            line = line.strip()
            if not line or '*' in line or '@' in line:
                continue
            batch.append(line)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch


def get_crtsh_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subdomains = set()
        for item in data:
            name = item['name_value'].split('\n')
            for n in name:
                if domain in n:
                    subdomains.add(n.strip())
        return list(subdomains)
    except:
        return []


def get_chaos_subdomains(domain):
    try:
        if subprocess.call(["which", "chaos-client"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            return []
        key = os.getenv("PDCP_API_KEY")
        cmd = ["chaos-client", "-d", domain]
        if key:
            cmd.insert(1, f"-key={key}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return [line.strip() for line in result.stdout.splitlines() if line.strip() and not line.startswith("[")]
    except:
        return []


def resolve(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def scan_ports(ip, full=False):
    open_ports = []
    ports = range(1, 65536) if full else DEFAULT_PORTS
    for port in ports:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect((ip, port))
            if port == 443:
                try:
                    context = ssl.create_default_context()
                    with context.wrap_socket(socket.socket(), server_hostname=ip) as ssock:
                        ssock.settimeout(1)
                        ssock.connect((ip, port))
                        cert = ssock.getpeercert()
                        ssl.match_hostname(cert, ip)
                        open_ports.append(f"{port}🔒")
                except ssl.CertificateError:
                    open_ports.append(f"{port}🔓")
                except:
                    open_ports.append(f"{port}⚠️")
            elif port == 80:
                open_ports.append(f"{port}🔓")
            elif port == 445:
                open_ports.append("📁")
            elif port in [22, 3389, 5985]:
                open_ports.append("🖥️")
            elif port == 21:
                open_ports.append("📂")
            else:
                open_ports.append(str(port))
        except:
            pass
        s.close()
    return open_ports


def check_alive(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=3, verify=False)
        if resp.status_code in [200, 301, 302]:
            return '✅'
        elif resp.status_code >= 500:
            return '❌'
        else:
            return '⚠️'
    except:
        return '❌'


def detect_tech(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=3, verify=False)
        server = resp.headers.get('Server', '-')
        powered = resp.headers.get('X-Powered-By', '-')
        techs = set(filter(lambda t: t.lower() != 'unknown', [server, powered]))
        return ', '.join(techs) or '-'
    except:
        return '-'


def detect_waf(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=3, verify=False)
        headers = resp.headers
        cookies = resp.cookies.get_dict()
        if 'cloudflare' in headers.get('Server', '').lower():
            return 'Cloudflare'
        elif 'cookiesession1' in cookies:
            return 'FortiWeb'
        else:
            return '-'
    except:
        return '-'


def export_results(output_path, results):
    os.makedirs(output_path, exist_ok=True)
    base_name = os.path.basename(output_path.rstrip("/"))
    json_path = os.path.join(output_path, f"{base_name}.json")
    csv_path = os.path.join(output_path, f"{base_name}.csv")
    txt_path = os.path.join(output_path, f"{base_name}.txt")

    with open(json_path, 'w') as jf:
        json.dump(results, jf, indent=4)
    with open(csv_path, 'w', newline='') as cf:
        writer = csv.writer(cf)
        writer.writerow(['IP', 'Domain', 'Ports', 'Alive', 'Tech', 'WAF'])
        for row in results:
            writer.writerow([row['ip'], row['domain'], row['ports'], row['alive'], row['tech'], row['waf']])
    with open(txt_path, 'w') as tf:
        for row in results:
            if row['alive'] == '✅':
                tf.write(f"{row['domain']}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('-w', '--wordlist')
    parser.add_argument('-t', '--threads', type=int, default=50)
    parser.add_argument('-f', '--full', action='store_true')
    parser.add_argument('-o', '--output')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    domain = args.domain
    console.print(f"\n[bold green][+] Starting at:[/] {datetime.now().strftime('%d.%m.%Y %H:%M')}")
    console.print("[bold green][+] Target:[/]", domain)
    start_time = time.time()

    whois_info = get_whois_info(domain)
    ip_host, host_org, host_loc = get_hosting_info(domain)

    whois_panel = Panel(
        f"📛 [bold]{whois_info['domain']}[/]  🏢 [bold]{html.unescape(str(whois_info['org']))}[/]\n"
        f"🌐 IP: {ip_host} 🏢 Org: {host_org} 📍 Location: {host_loc}\n"
        f"📅 Created: {whois_info['created']}  ⌛ Expires: {whois_info['expires']}  🕑 Updated: {whois_info['updated']}\n"
        f"🌍 Registrar: {whois_info['registrar']}\n"
        f"🖥️ Name Servers: {whois_info['name_servers']}\n"
        f"👤 Name: {whois_info['name']}  📧 Email: {whois_info['emails']}\n"
        f"🔒 DNSSEC: {whois_info['dnssec']}\n"
        f"🌎 Country: {whois_info['country']}  🏙️ City: {whois_info['city']}  🏴 State: {whois_info['state']}  📮 Postal: {whois_info['postal']}",
        title="[bold cyan]WHOIS Info[/]",
        box=box.DOUBLE
    )
    console.print(whois_panel)

    subdomains = set(get_crtsh_subdomains(domain))
    subdomains.update(get_chaos_subdomains(domain))

    if args.wordlist:
        try:
            total = sum(1 for _ in open(args.wordlist))
            console.print(f"[blue]Loaded wordlist with {total:,} entries. Processing in batches...[/]")
            for batch in batch_lines(args.wordlist, batch_size=5000):
                subdomains.update(f"{line}.{domain}" for line in batch)
        except Exception as e:
            if args.debug:
                console.print(f"[red]Error loading wordlist: {e}")

    subdomains.update(f"{s}.{domain}" for s in FALLBACK_SUBS)
    subdomains = sorted(set(s for s in subdomains if not s.startswith("*")))

    results = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(subdomains))
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_sub = {executor.submit(resolve, sub): sub for sub in subdomains}
            ip_map = {future_to_sub[f]: f.result() for f in concurrent.futures.as_completed(future_to_sub)}

        for sub, ip in sorted(ip_map.items(), key=lambda x: (x[1] or 'zzz', x[0])):
            progress.update(task, advance=1)
            if ip:
                ip_display = f"[red]{ip}[/]" if ip.startswith(('192.', '10.', '172.')) else ip
                open_ports = scan_ports(ip, full=args.full)
                alive = check_alive(sub)
                tech = detect_tech(sub)
                waf = detect_waf(sub)
                results.append({
                    'ip': ip_display,
                    'domain': sub,
                    'ports': ', '.join(open_ports) or '-',
                    'alive': alive,
                    'tech': tech,
                    'waf': waf
                })

    table = Table(title="OpenRecon Summary", box=box.DOUBLE)
    table.add_column("IP")
    table.add_column("Domain")
    table.add_column("Ports")
    table.add_column("Alive")
    table.add_column("Tech")
    table.add_column("WAF")

    for row in results:
        table.add_row(row['ip'], row['domain'], row['ports'], row['alive'], row['tech'], row['waf'])

    console.print(table)

    if args.output:
        export_results(output_base, results)

    elapsed = time.time() - start_time
    console.print(f"\n✅ [bold green]Scanning complete in[/] {int(elapsed // 60):02d}:{int(elapsed % 60):02d} ({len(results)}/{len(subdomains)} subdomains processed)")
    console.print("\n[bold yellow]Legend:[/] ✅ alive, ❌ not reachable, ⚠️ unstable; 🔒 valid HTTPS, 🔓 self-signed, ⚠️ insecure HTTP; 🖥️ RDP/SSH, 📁 SMB, 📂 FTP")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[red]\n[!] Interrupted by user")
        sys.exit(0)