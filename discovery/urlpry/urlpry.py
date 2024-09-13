#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import time
import subprocess
import requests
import dns.resolver
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from typing import List, Dict, Optional, Union
from rich.console import Console
import platform

console = Console()

DEFAULT_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 3000, 3306, 8080, 8443, 5432]


def format_dict(data: Union[Dict, List]) -> str:
    if not data:
        return "No data available."
    if isinstance(data, list):
        return ", ".join(str(item) for item in data)
    return "\n".join(f"{key}: {value}" if not isinstance(value, dict)
                     else f"{key}: {format_dict(value)}"
                     for key, value in data.items())


def safe_resolve_dns(fqdn: str, record_type: str) -> Union[List[str], str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        result = resolver.resolve(fqdn, record_type)
        return [str(rdata) for rdata in result]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return f'No {record_type} record found'
    except dns.exception.Timeout:
        return f'{record_type} query timed out'
    except dns.exception.DNSException as e:
        return f'Error resolving {record_type}: {str(e)}'


def telnet_cdn_waf_detection(fqdn: str, port: int = 80) -> Optional[Dict[str, str]]:
    try:
        sock = socket.create_connection((fqdn, port), timeout=5)
        request = f"GET / HTTP/1.1\r\nHost: {fqdn}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()
        headers = response.split("\r\n\r\n")[0].split("\r\n")
        return {header.split(":")[0].strip(): header.split(":")[1].strip() for header in headers[1:] if len(header.split(":")) == 2}
    except (socket.timeout, socket.error) as e:
        return {"Error": str(e)}


def get_http_info(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Union[Dict, str, int, float]]:
    try:
        start = time.time()
        response = requests.get(url, headers=headers, allow_redirects=True)
        elapsed_time = time.time() - start
        soup = BeautifulSoup(response.text, 'html.parser')

        return {
            'General': dict(response.headers),
            'Status Code': response.status_code,
            'Response Time (seconds)': elapsed_time,
            'Final URL': response.url,
            'Content-Type': response.headers.get('Content-Type'),
            'Server': response.headers.get('Server'),
            'Content-Length': response.headers.get('Content-Length'),
            'Cookies': dict(response.cookies.get_dict()),
            'HTML Info': {
                'Title': soup.title.string if soup.title else 'No title',
                'Meta': {meta.attrs.get('name', 'unknown'): meta.attrs.get('content', '') for meta in soup.find_all('meta')},
                'Forms': len(soup.find_all('form')),
                'Buttons': len(soup.find_all('button'))
            }
        }
    except requests.RequestException as e:
        return {'Error': str(e)}


def extract_full_and_domain(url: str) -> Dict[str, str]:
    fqdn = urlparse(url).hostname
    domain_parts = tldextract.extract(fqdn)
    return {"fqdn": fqdn, "domain": f"{domain_parts.domain}.{domain_parts.suffix}"}


def get_dns_records(fqdn: str, domain: str) -> Dict[str, Union[List[str], str]]:
    return {
        'CNAME': safe_resolve_dns(fqdn, 'CNAME'),
        'TXT': safe_resolve_dns(domain, 'TXT'),
        'PTR': safe_resolve_dns(socket.gethostbyname(fqdn), 'PTR'),
        'IP Address': socket.gethostbyname(fqdn)
    }


def get_ssl_certificate(fqdn: str) -> Dict[str, Union[Dict, List[str], str]]:
    try:
        conn = ssl.create_default_context().wrap_socket(socket.socket(socket.AF_INET), server_hostname=fqdn)
        conn.connect((fqdn, 443))
        cert = conn.getpeercert()
        return {
            'Subject': dict(x[0] for x in cert['subject']),
            'Issuer': dict(x[0] for x in cert['issuer']),
            'Valid From': cert['notBefore'],
            'Valid To': cert['notAfter'],
            'SAN': [entry[1] for entry in cert.get('subjectAltName', [])]
        }
    except Exception as e:
        return {'Error': str(e)}


def safe_resolve_cname(fqdn: str) -> Union[str, None]:
    try:
        answers = dns.resolver.Resolver().resolve(fqdn, 'CNAME')
        return str(answers[0].target).strip('.').lower()
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.DNSException:
        return None


def detect_cdn(fqdn: str) -> str:
    CDN_PROVIDERS = {
        'cloudflare': 'cloudflare',
        'akamai': 'akamai',
        'fastly': 'fastly',
        'incapsula': 'incapsula',
        'stackpath': 'stackpath',
        'cdn77': 'cdn77',
        'cloudfront': 'cloudfront',
        'azure': 'azure',
        'google': 'google',
        'gcp': 'gcp'
    }

    cname_record = safe_resolve_cname(fqdn)
    if cname_record:
        for provider, keyword in CDN_PROVIDERS.items():
            if keyword in cname_record:
                return provider.capitalize()
        if 'edgekey.net' in cname_record or 'edgesuite.net' in cname_record:
            return 'Akamai CDN (CNAME)'

    telnet_headers = telnet_cdn_waf_detection(fqdn)
    if telnet_headers and "Error" not in telnet_headers:
        server_header = telnet_headers.get('Server', '').lower()
        for provider, keyword in CDN_PROVIDERS.items():
            if keyword in server_header:
                return provider.capitalize()
        if 'akamaighost' in server_header:
            return 'Akamai CDN (Server Header)'

    return 'No CDN detected'


def detect_waf(http_info: Dict[str, Union[str, Dict]], fqdn: str) -> str:
    waf_headers = {
        'Cloudflare': ['cf-ray', 'cf-request-id'],
        'Akamai': ['akamai-x-cache', 'akamai-x-get-cache-key', 'x-akamai-transformed'],
        'Incapsula': ['x-iinfo', 'x-cdn', 'x-visid'],
        'F5': ['x-waf', 'x-protection', 'x-firewall'],
        'AWS': ['x-amzn-requestid', 'x-amz-cf-id'],
        'Barracuda': ['x-barracuda'],
        'StackPath': ['x-stackpath-request-id', 'x-stackpath-proxy'],
        'Sucuri': ['x-sucuri-id'],
        'Fortinet': ['x-fortinet-forbidden'],
    }

    waf_error_patterns = {
        'Cloudflare': ['cloudflare-nginx', 'Attention Required'],
        'Akamai': ['Reference #', 'Access Denied - Akamai'],
        'F5': ['Request Blocked', 'The page cannot be displayed'],
        'AWS': ['403 Forbidden', 'Request Blocked by AWS WAF'],
        'Incapsula': ['Incapsula incident ID', 'Incapsula Error'],
        'Sucuri': ['Sucuri WebSite Firewall'],
        'Fortinet': ['Access to this web site is blocked', 'FortiGuard'],
    }

    for waf_name, headers in waf_headers.items():
        if any(header in http_info.get('General', {}) for header in headers):
            return waf_name

    html_content = http_info.get('HTML Info', {}).get('Title', '')
    for waf_name, patterns in waf_error_patterns.items():
        if any(pattern.lower() in html_content.lower() for pattern in patterns):
            return f"{waf_name} detected via HTML error patterns"

    akamai_headers = {"Pragma": "akamai-x-get-extracted-values"}
    try:
        response = requests.get(f"http://{fqdn}", headers=akamai_headers, allow_redirects=True)
        if 'x-akamai-session-info' in response.headers and 'waf' in response.headers['x-akamai-session-info'].lower():
            return 'Akamai WAF (Pragma Header)'
    except requests.RequestException:
        pass

    telnet_headers = telnet_cdn_waf_detection(fqdn)
    if telnet_headers and "Error" not in telnet_headers:
        for waf_name, headers in waf_headers.items():
            if any(header in telnet_headers for header in headers):
                return f"WAF detected via Telnet ({waf_name})"

    return 'No WAF detected'


def scan_ports(host: str, ports: List[int] = DEFAULT_PORTS) -> Union[List[int], str]:
    open_ports = []
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return f"Could not resolve {host} to an IP address."
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports


def extract_javascript_files(url: str) -> Union[List[str], Dict[str, str]]:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        return [script.get('src') for script in soup.find_all('script') if script.get('src')]
    except requests.RequestException as e:
        return {'Error': str(e)}


def detect_social_media_links(url: str) -> Union[List[str], Dict[str, str]]:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        return [a['href'] for a in soup.find_all('a', href=True) if any(social in a['href'] for social in ['facebook.com', 'twitter.com', 'linkedin.com'])]
    except requests.RequestException as e:
        return {'Error': str(e)}


def enumerate_subdomains(fqdn: str) -> Union[str, Dict[str, str]]:
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{fqdn}&output=json")
        if response.status_code == 200:
            crt_data = response.json()
            subdomains = {entry['name_value'].lower() for entry in crt_data if not entry['name_value'].startswith('*')}
            sorted_subdomains = sorted(subdomains)
            return ', '.join(sorted_subdomains) if sorted_subdomains else 'No subdomains found'
        return 'No subdomains found'
    except requests.RequestException as e:
        return {'Error': str(e)}


def check_ssl_pinning(url: str) -> str:
    try:
        response = requests.head(url, allow_redirects=True)
        return response.headers.get('Public-Key-Pins', 'No SSL Pinning detected')
    except requests.RequestException as e:
        return f"Error checking SSL Pinning: {str(e)}"


def get_whois_info(fqdn: str) -> Dict[str, Union[str, List[str], Dict]]:
    whois_info = {}
    try:
        fqdn_info = whois.whois(fqdn)
        whois_info.update({
            'Registrar': fqdn_info.registrar,
            'Creation Date': fqdn_info.creation_date,
            'Expiration Date': fqdn_info.expiration_date,
            'Updated Date': fqdn_info.updated_date,
            'Name Servers': fqdn_info.name_servers,
            'Status': fqdn_info.status
        })
    except Exception as e:
        whois_info['Error'] = f"An error occurred while fetching WHOIS information: {str(e)}"
    return whois_info


def get_http_security_headers(url: str) -> Dict[str, str]:
    headers = ['Strict-Transport-Security', 'X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy', 'X-Content-Type-Options']
    try:
        response = requests.head(url, allow_redirects=True)
        return {header: response.headers.get(header, 'Not Present') for header in headers}
    except requests.RequestException as e:
        return {'Error': str(e)}


def get_additional_dns_records(fqdn: str) -> Dict[str, Union[List[str], str]]:
    return {
        'MX': safe_resolve_dns(fqdn, 'MX'),
        'NS': safe_resolve_dns(fqdn, 'NS'),
        'SOA': safe_resolve_dns(fqdn, 'SOA'),
        'AAAA': safe_resolve_dns(fqdn, 'AAAA')
    }


def check_ssl_health(fqdn: str) -> Dict[str, str]:
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=fqdn)
        conn.connect((fqdn, 443))
        cert = conn.getpeercert()
        valid_from = cert['notBefore']
        valid_to = cert['notAfter']
        return {
            'SSL Certificate Valid From': valid_from,
            'SSL Certificate Valid To': valid_to,
            'SSL Expiry Status': 'Valid' if valid_to > time.strftime('%b %d %H:%M:%S %Y GMT') else 'Expired'
        }
    except Exception as e:
        return {'Error': str(e)}


def get_asn_info(ip: Optional[str]) -> Dict[str, Union[str, Dict]]:
    if not ip:
        return {}
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        return response.json()
    except requests.RequestException as e:
        return {'Error': str(e)}


def traceroute(fqdn: str, timeout: int = 10) -> str:
    try:
        if platform.system().lower() == 'windows':
            return "Traceroute is not available on Windows. Please use an alternative method."
        result = subprocess.run(['traceroute', fqdn], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return f"Traceroute timed out after {timeout} seconds."
    except FileNotFoundError:
        return "Traceroute command not found. Please install traceroute or use another method."
    except Exception as e:
        return str(e)


def get_ip_geolocation(ip: Optional[str]) -> Dict[str, Union[str, Dict]]:
    if not ip:
        return {}
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        return response.json()
    except requests.RequestException as e:
        return {'Error': str(e)}


def website_speed_test(url: str) -> Dict[str, Union[float, str]]:
    try:
        start_time = time.time()
        response = requests.get(url)
        load_time = time.time() - start_time
        return {
            'Load Time (seconds)': load_time,
            'First Byte Time (seconds)': response.elapsed.total_seconds()
        }
    except requests.RequestException as e:
        return {'Error': str(e)}


def print_info(http_info: Dict, dns_records: Dict, ssl_info: Dict, whois_info: Dict, ip_geolocation: Optional[Dict], open_ports: Union[List[int], str], security_headers: Dict, output_json: bool = False) -> None:
    output = {
        "HTTP Information": http_info or "No HTTP information collected",
        "DNS Records": dns_records or "No DNS information collected",
        "SSL Certificate Information": ssl_info or "No SSL information collected",
        "WHOIS Information": whois_info or "No WHOIS information collected",
        "IP Geolocation": ip_geolocation if ip_geolocation else "No IP Geolocation information collected",
        "Open Ports": open_ports or "No open ports collected",
        "HTTP Security Headers": security_headers or "No HTTP security headers collected"
    }
    if output_json:
        console.print(json.dumps(output, indent=2))
    else:
        for section, data in output.items():
            console.print(f"[bold yellow]{section}[/bold yellow]:")
            if isinstance(data, (dict, list)):
                console.print(format_dict(data))
            else:
                console.print(data)

def main() -> None:
    parser = argparse.ArgumentParser(description="URL inspection tool")
    parser.add_argument("url", help="The URL to inspect")
    parser.add_argument("-p", "--pragma", action="store_true", help="Include Akamai Pragma headers")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--port-scan", action="store_true", help="Perform port scanning")
    parser.add_argument("--dns-info", action="store_true", help="Collect DNS information")
    parser.add_argument("--traceroute", action="store_true", help="Perform a traceroute")
    parser.add_argument("--ssl-info", action="store_true", help="Collect SSL certificate information")
    parser.add_argument("--whois-info", action="store_true", help="Collect WHOIS information")
    parser.add_argument("--geo-info", action="store_true", help="Collect IP Geolocation information")
    parser.add_argument("--cdn-info", action="store_true", help="Check for CDN presence")
    parser.add_argument("--ssl-pinning", action="store_true", help="Check for SSL pinning")
    parser.add_argument("--waf-info", action="store_true", help="Check for Web Application Firewall (WAF)")
    parser.add_argument("--speed-test", action="store_true", help="Perform website speed test")
    parser.add_argument("--js-files", action="store_true", help="Extract linked JavaScript files")
    parser.add_argument("--social-links", action="store_true", help="Extract social media links")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")

    args = parser.parse_args()
    specified_args = any(vars(args).values()) and any([args.port_scan, args.dns_info, args.traceroute, args.ssl_info, args.whois_info, args.geo_info, args.cdn_info, args.ssl_pinning, args.waf_info, args.speed_test, args.js_files, args.social_links, args.subdomains])

    fqdn_info = extract_full_and_domain(args.url)
    fqdn = fqdn_info["fqdn"]
    domain = fqdn_info["domain"]

    dns_records, ip_addr = None, None
    http_info, ssl_info, whois_info, ip_geolocation = None, None, None, None
    open_ports, security_headers, cdn, ssl_pinning = None, None, None, None
    waf_detection, speed_test, js_files, social_links, subdomains = None, None, None, None, None
    traceroute_info = None

    if not specified_args:
        dns_records = get_dns_records(fqdn, domain)
        ip_addr = dns_records.get('A') if dns_records else None
        http_info = get_http_info(args.url, args.pragma)
        ssl_info = get_ssl_certificate(fqdn)
        whois_info = get_whois_info(domain)
        ip_geolocation = get_ip_geolocation(ip_addr[0]) if ip_addr else None
        open_ports = scan_ports(fqdn)
        security_headers = get_http_security_headers(args.url)

        waf_detection = detect_waf(http_info, fqdn)
        cdn_detection = detect_cdn(fqdn)

        ssl_pinning = check_ssl_pinning(args.url)
        speed_test = website_speed_test(args.url)
        js_files = extract_javascript_files(args.url)
        social_links = detect_social_media_links(args.url)
        subdomains = enumerate_subdomains(domain)
        traceroute_info = traceroute(fqdn)

        print_info(http_info, dns_records, ssl_info, whois_info, ip_geolocation, open_ports, security_headers, args.json)

        console.print(f"\n[bold yellow]CDN Detection[/bold yellow]: {cdn_detection}")
        console.print(f"\n[bold yellow]SSL Pinning[/bold yellow]: {ssl_pinning}")
        console.print(f"\n[bold yellow]WAF Detection[/bold yellow]: {waf_detection}")
        console.print(f"\n[bold yellow]Website Speed Test[/bold yellow]: {format_dict(speed_test)}")
        console.print(f"\n[bold yellow]Extracted JavaScript Files[/bold yellow]: {format_dict(js_files)}")
        console.print(f"\n[bold yellow]Social Media Links[/bold yellow]: {format_dict(social_links)}")

        if isinstance(subdomains, str):
            console.print(f"\n[bold yellow]Subdomains[/bold yellow]: {subdomains}")
        else:
            console.print(f"\n[bold yellow]Subdomains[/bold yellow]: {', '.join(subdomains)}")

        console.print(f"\n[bold yellow]Traceroute[/bold yellow]: {traceroute_info}")

    else:
        if args.dns_info:
            dns_records = get_dns_records(fqdn, domain)
            ip_addr = dns_records.get('IP Address') if dns_records else None
            console.print(f"\n\n[bold yellow]DNS Records[/bold yellow]:\n{format_dict(dns_records)}")

        if not args.port_scan:
            http_info = get_http_info(args.url, args.pragma)

        if args.ssl_info:
            ssl_info = get_ssl_certificate(fqdn)
            console.print(f"\n\n[bold yellow]SSL Certificate Information[/bold yellow]:\n{format_dict(ssl_info)}")

        if args.whois_info:
            whois_info = get_whois_info(fqdn)
            console.print(f"\n\n[bold yellow]WHOIS Information[/bold yellow]:\n{format_dict(whois_info)}")

        if args.geo_info and ip_addr:
            ip_geolocation = get_ip_geolocation(ip_addr)
            console.print(f"\n\n[bold yellow]IP Geolocation[/bold yellow]:\n{format_dict(ip_geolocation)}")

        if args.port_scan:
            open_ports = scan_ports(fqdn)
            console.print(f"\n\n[bold yellow]Open Ports[/bold yellow]:\n{format_dict({'Ports': open_ports})}")

        if args.cdn_info and http_info:
            cdn = detect_cdn(fqdn)
            console.print(f"\n\n[bold yellow]CDN Detection[/bold yellow]:\n{cdn}")

        if args.ssl_pinning:
            ssl_pinning = check_ssl_pinning(args.url)
            console.print(f"\n\n[bold yellow]SSL Pinning[/bold yellow]:\n{ssl_pinning}")

        if args.waf_info and http_info:
            waf_detection = detect_waf(http_info, fqdn)
            console.print(f"\n\n[bold yellow]WAF Detection[/bold yellow]:\n{waf_detection}")

        if args.speed_test:
            speed_test = website_speed_test(args.url)
            console.print(f"\n\n[bold yellow]Website Speed Test[/bold yellow]:\n{format_dict(speed_test)}")

        if args.js_files:
            js_files = extract_javascript_files(args.url)
            console.print(f"\n\n[bold yellow]Extracted JavaScript Files[/bold yellow]:\n{format_dict({'JavaScript Files': js_files})}")

        if args.social_links:
            social_links = detect_social_media_links(args.url)
            console.print(f"\n\n[bold yellow]Social Media Links[/bold yellow]:\n{format_dict({'Social Links': social_links})}")

        if args.subdomains:
            subdomains = enumerate_subdomains(fqdn)
            if isinstance(subdomains, str):
                console.print(f"\n[bold yellow]Subdomains[/bold yellow]: {subdomains}")
            else:
                console.print(f"\n[bold yellow]Subdomains[/bold yellow]: {', '.join(subdomains)}")

        if args.traceroute:
            traceroute_info = traceroute(fqdn)
            console.print(f"\n\n[bold yellow]Traceroute[/bold yellow]:\n{traceroute_info}")

if __name__ == "__main__":
    main()
