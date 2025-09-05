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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# -----------------
# Tuning & defaults
# -----------------
DEFAULT_PORTS = [80, 443, 40443, 8080, 8443, 8090, 445, 22, 21, 3389, 5985]
FALLBACK_SUBS = ['www', 'mail', 'vpn', 'adfs', 'telbot', 'drive', 'api', 'dev', 'test', 'sip', 'ftp', 'autodiscover', 'crm', 'vpn2', 'doc', 'owa', 'portal', 'remote', 'trade', 'admin', 'cloud']

# Timeouts / concurrency
PORT_CONNECT_TIMEOUT = 0.18
TLS_HANDSHAKE_TIMEOUT = 0.7
HTTP_TIMEOUT = 2.5
WHOIS_TIMEOUT = 8
RESOLVE_THREADS = 200
PORT_WORKERS_FULL = 300
PORT_WORKERS_DEFAULT = 80

# --------------
# Fancy banner
# --------------

def print_banner():
    console.print("""
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
""", style="bold white")

# -----------------
# Helpers
# -----------------

def get_hosting_info(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        whois_ip = IPWhois(ip)
        data = whois_ip.lookup_rdap()
        org = data.get('network', {}).get('name', '-')
        loc = f"{data.get('asn_country_code', '-')}, {data.get('asn_description', '-')}"
        return ip, org, loc
    except Exception:
        return '-', '-', '-'


def _whois_fetch(domain: str):
    return whois.whois(domain)


def get_whois_info(domain: str) -> dict:
    defaults = {
        'domain': domain,
        'org': '-', 'name': '-', 'emails': '-', 'registrar': '-', 'status': '-',
        'created': '-', 'expires': '-', 'updated': '-', 'name_servers': '-', 'dnssec': '-',
        'country': '-', 'city': '-', 'state': '-', 'postal': '-',
    }
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_whois_fetch, domain)
            w = fut.result(timeout=WHOIS_TIMEOUT)

        def _fmt(v):
            if v is None:
                return '-'
            if isinstance(v, (list, tuple, set)):
                return str(sorted(v))
            return str(v)

        return {
            'domain': _fmt(getattr(w, 'domain_name', domain)),
            'org': _fmt(getattr(w, 'org', '-')),
            'name': _fmt(getattr(w, 'name', '-')),
            'emails': _fmt(getattr(w, 'emails', '-')),
            'registrar': _fmt(getattr(w, 'registrar', '-')),
            'status': _fmt(getattr(w, 'status', '-')),
            'created': _fmt(getattr(w, 'creation_date', '-')),
            'expires': _fmt(getattr(w, 'expiration_date', '-')),
            'updated': _fmt(getattr(w, 'updated_date', '-')),
            'name_servers': _fmt(getattr(w, 'name_servers', '-')),
            'dnssec': _fmt(getattr(w, 'dnssec', '-')),
            'country': _fmt(getattr(w, 'country', '-')),
            'city': _fmt(getattr(w, 'city', '-')),
            'state': _fmt(getattr(w, 'state', '-')),
            'postal': _fmt(getattr(w, 'registrant_postal_code', '-')),
        }
    except Exception:
        return defaults


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
        subs = set()
        for item in data:
            for n in item['name_value'].split('\n'):
                if domain in n:
                    subs.add(n.strip())
        return list(subs)
    except Exception:
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
        return [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith("[")]
    except Exception:
        return []


def resolve(domain: str):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# --------- Fast port scan (concurrent) ---------

def _probe_port(ip: str, port: int) -> str | None:
    try:
        with socket.create_connection((ip, port), PORT_CONNECT_TIMEOUT):
            if port == 445:
                return "📁"
            if port in (22, 3389, 5985):
                return "🖥️"
            if port == 21:
                return "📂"
            if port == 80:
                return "80🔓"
            if port == 443:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(socket.socket(), server_hostname=ip) as ss:
                        ss.settimeout(TLS_HANDSHAKE_TIMEOUT)
                        ss.connect((ip, 443))
                        _ = ss.getpeercert(False)
                    return "443🔒"
                except ssl.SSLError:
                    return "443🔓"
                except Exception:
                    return "443⚠️"
            return str(port)
    except Exception:
        return None


def scan_ports(ip: str, full: bool = False) -> list[str]:
    ports = (range(1, 65536) if full else DEFAULT_PORTS)
    workers = PORT_WORKERS_FULL if full else PORT_WORKERS_DEFAULT
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_probe_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            if res:
                out.append(res)
    def _key(v: str):
        try:
            return (0, int(''.join(ch for ch in v if ch.isdigit())))
        except ValueError:
            return (1, v)
    return sorted(out, key=_key)


def check_alive(domain: str) -> str:
    try:
        r = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT, verify=False)
        if r.status_code in (200, 301, 302, 403):
            return '✅'
        if r.status_code >= 500:
            return '❌'
        return '⚠️'
    except Exception:
        try:
            r = requests.get(f"http://{domain}", timeout=HTTP_TIMEOUT, verify=False)
            if r.status_code in (200, 301, 302, 403):
                return '✅'
            if r.status_code >= 500:
                return '❌'
            return '⚠️'
        except Exception:
            return '❌'


def detect_tech(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT, verify=False)
        server = resp.headers.get('Server', '-')
        powered = resp.headers.get('X-Powered-By', '-')
        techs = set(filter(lambda t: t and t != '-' and t.lower() != 'unknown', [server, powered]))
        return ', '.join(techs) or '-'
    except Exception:
        return '-'


def detect_waf(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT, verify=False)
        headers = resp.headers
        cookies = resp.cookies.get_dict()
        if 'cloudflare' in headers.get('Server', '').lower():
            return 'Cloudflare'
        elif 'cookiesession1' in cookies:
            return 'FortiWeb'
        else:
            return '-'
    except Exception:
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
            writer.writerow([row['ip_plain'], row['domain'], row['ports'], row['alive'], row['tech'], row['waf']])
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

    # Banner & header
    print_banner()
    console.print(f"[bold green][+] Starting at:[/] {datetime.now().strftime('%d.%m.%Y %H:%M')}")
    console.print("[bold green][+] Target:[/]", args.domain)

    domain = args.domain
    start_time = time.time()

    # WHOIS + hosting
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

    # Subdomain sources
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

    # Resolve (fast) & filter unroutable
    results = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=RESOLVE_THREADS) as ex:
            futs = {ex.submit(resolve, s): s for s in subdomains}
            ip_map = {}
            for fut in concurrent.futures.as_completed(futs):
                sub = futs[fut]
                try:
                    ip = fut.result()
                    if ip:
                        ip_map[sub] = ip
                except Exception:
                    pass
        progress.update(task, total=len(ip_map))

        # port/tech checks for resolved only
        for sub, ip in sorted(ip_map.items(), key=lambda x: (x[1] or 'zzz', x[0])):
            progress.advance(task)
            ip_display = f"[red]{ip}[/]" if ip.startswith(('192.', '10.', '172.')) else ip
            open_ports = scan_ports(ip, full=args.full)
            alive = check_alive(sub)
            tech = detect_tech(sub)
            waf = detect_waf(sub)
            results.append({
                'ip': ip_display,
                'ip_plain': ip,
                'domain': sub,
                'ports': ', '.join(open_ports) or '-',
                'alive': alive,
                'tech': tech,
                'waf': waf
            })

    # Table
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

    # Exports
    if args.output:
        output_base = os.path.join(args.output, f"{domain}_{datetime.now().strftime('%d.%m.%Y')}")
        export_results(output_base, results)

    elapsed = time.time() - start_time
    console.print(f"\n✅ [bold green]Scanning complete in[/] {int(elapsed // 60):02d}:{int(elapsed % 60):02d} ({len(results)}/{len(subdomains)} subdomains processed)")
    console.print("\n[bold yellow]Legend:[/] ✅ alive, ❌ not reachable, ⚠️ unstable; 🔒 valid HTTPS, 🔓 self-signed, ⚠️ insecure HTTP; 🖥️ RDP/SSH, 📁 SMB, 📂 FTP")


if __name__ == "__main__":
    try:
        console.show_cursor(True)
        main()
    except KeyboardInterrupt:
        console.print("[red]\n[!] Interrupted by user")
        sys.exit(0)
    finally:
        # гарантированно вернём курсор, даже если rich/progress оборвало
        try:
            console.show_cursor(True)
        except Exception:
            pass