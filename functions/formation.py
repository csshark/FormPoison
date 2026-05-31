#!/usr/bin/env python3
"""
FormAtion - Advanced Web Form Analysis Module for FormPoison
PortSwigger Research-Based Web Application Security Analyzer
Uses official FormPoison flags only 
Scan command recommendation is not a bug - just launch it :) 
"""

import asyncio
import aiohttp
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import json
import ssl
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.text import Text
from rich.syntax import Syntax
from rich.tree import Tree
import logging
import copy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('FormAtion')

console = Console()

# Official FormPoison flags mapping
FORMPOISON_FLAGS = {
    # Threat types
    '-t': {'type': 'threat', 'values': ['Java', 'SQL', 'HTML'], 'description': 'Select threat type'},
    
    # Modes
    '--filemode': {'type': 'mode', 'description': 'Filename injection mode'},
    '--login': {'type': 'mode', 'description': 'Login+password mode only'},
    '--mXSS': {'type': 'mode', 'description': 'Mutation XSS injections only'},
    '--brute': {'type': 'mode', 'description': 'Maximum requests speed'},
    '--interactive': {'type': 'mode', 'description': 'Interactive field injecting mode'},
    
    # Scanning
    '-qs': {'type': 'scan', 'description': 'Quick input fields scan'},
    '--check': {'type': 'scan', 'description': 'Quick input fields scan/check'},
    '--scan': {'type': 'scan', 'description': 'Deep scan for .js code and web audit'},
    '--auto-target': {'type': 'scan', 'description': 'Perform scan results-based injections'},
    
    # Verbosity
    '-v': {'type': 'output', 'description': 'Verbose mode'},
    '--verbose': {'type': 'output', 'description': 'Verbose mode'},
    '--verbose-all': {'type': 'output', 'description': 'Advanced output with response body'},
    
    # Method
    '--method': {'type': 'request', 'values': ['GET', 'POST', 'PUT', 'DELETE'], 'description': 'Force request method'},
    
    # Bypass techniques
    '--waf-bypass': {'type': 'bypass', 'description': 'Load CDN/WAF evasion payloads'},
    '--csp-bypass': {'type': 'bypass', 'description': 'Load CSP bypass payloads'},
    '--sanitizer-bypass': {'type': 'bypass', 'description': 'Load HTML sanitizer bypass payloads'},
    '--encoder-bypass': {'type': 'bypass', 'description': 'Load encoder bypass payloads'},
    '--encoding-confusion': {'type': 'bypass', 'description': 'Load encoding confusion payloads'},
    '--size-overflow': {'type': 'bypass', 'description': 'Load size overflow payloads'},
    
    # Performance
    '--concurrent': {'type': 'performance', 'range': '10-500', 'default': 50},
    '--timeout': {'type': 'performance', 'range': '3-60', 'default': 15},
    '--batch-size': {'type': 'performance', 'range': '10-1000', 'default': 100},
    '--batch-delay': {'type': 'performance', 'range': '0-10', 'default': 1},
    '--retries': {'type': 'performance', 'range': '1-5', 'default': 2},
    '-s': {'type': 'performance', 'description': 'Delay between requests'},
    '--seconds': {'type': 'performance', 'description': 'Delay between requests'},
    
    # Other
    '--filter': {'type': 'filter', 'description': 'Filter payloads by pattern'},
    '--fieldname': {'type': 'target', 'description': 'Specify fieldname to target'},
    '-p': {'type': 'payload', 'description': 'Custom payloads file path'},
    '--payloads': {'type': 'payload', 'description': 'Custom payloads file path'},
    '--cookies': {'type': 'auth', 'description': 'Specify user cookie'},
    '-ua': {'type': 'request', 'description': 'Specify User-Agent'},
    '--user-agent': {'type': 'request', 'description': 'Specify User-Agent'},
    '--proxy': {'type': 'connection', 'description': 'Specify proxy'},
    '--ssl-cert': {'type': 'connection', 'description': 'SSL certificate file'},
    '--ssl-key': {'type': 'connection', 'description': 'SSL private key'},
    '--ssl-verify': {'type': 'connection', 'description': 'Verify SSL certificate'},
    '--max-urls': {'type': 'scan', 'description': 'Max URLs to scan'},
    '--max-depth': {'type': 'scan', 'description': 'Max scan depth'},
    '--max-workers': {'type': 'scan', 'description': 'Number of workers for scanning'},
}

class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class FieldAnalysis:
    element_type: str = ""
    field_type: str = ""
    name: str = ""
    id: str = ""
    value: str = ""
    attributes: Dict[str, str] = field(default_factory=dict)
    suspicious_patterns: List[str] = field(default_factory=list)
    field_category: str = 'other'
    portswigger_risks: List[str] = field(default_factory=list)
    is_text_input: bool = False
    threat_level: str = 'low'
    security_implications: List[str] = field(default_factory=list)
    potential_payloads: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class FormAnalysis:
    form_id: int = 0
    action: str = ""
    method: str = ""
    enctype: str = ""
    all_fields: List[FieldAnalysis] = field(default_factory=list)
    text_input_fields: List[FieldAnalysis] = field(default_factory=list)
    non_text_fields: List[FieldAnalysis] = field(default_factory=list)
    vulnerability_indicators: List[str] = field(default_factory=list)
    complexity_score: int = 0
    portswigger_vectors: List[str] = field(default_factory=list)
    html_source: str = ''
    
    def to_dict(self) -> Dict:
        return {
            'form_id': self.form_id,
            'action': self.action,
            'method': self.method,
            'enctype': self.enctype,
            'all_fields': [f.to_dict() for f in self.all_fields],
            'text_input_fields': [f.to_dict() for f in self.text_input_fields],
            'non_text_fields': [f.to_dict() for f in self.non_text_fields],
            'vulnerability_indicators': self.vulnerability_indicators,
            'complexity_score': self.complexity_score,
            'portswigger_vectors': self.portswigger_vectors,
            'html_source': self.html_source
        }

class FormAtionAnalyzer:
    """Advanced form analysis engine using official FormPoison flags."""
    
    VERSION = "2.0.0"
    
    def __init__(self, url: str, user_agent: Optional[str] = None, 
                 proxies: Optional[str] = None, timeout: int = 30,
                 max_redirects: int = 5, verify_ssl: bool = True):
        self.url = url
        self.user_agent = user_agent or f"FormAtion/{self.VERSION} (Security Analyzer)"
        self.proxies = proxies
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Results containers
        self.results = {
            'url': url,
            'scan_timestamp': datetime.now().isoformat(),
            'forms_analysis': [],
            'security_headers': {},
            'technology_stack': {},
            'recommendations': [],
            'formpoison_flags': [],
            'formpoison_command': '',
            'attack_vectors': [],
            'compliance_report': {},
            'risk_assessment': {},
            'remediation_plan': []
        }
        
        self.response_headers: Dict[str, str] = {}
        self.page_content: Optional[str] = None
        self.parsed_url = urlparse(url)
        
        # Official flag usage tracking
        self.recommended_flags: Set[str] = set()
        self.flag_reasons: Dict[str, str] = {}
        
        # Security patterns for analysis
        self.security_patterns = self._load_security_patterns()
        self.technology_fingerprints = self._load_technology_fingerprints()
    
    @staticmethod
    def _escape_markup(text: str) -> str:
        """Escape Rich markup characters in text."""
        if not isinstance(text, str):
            text = str(text)
        return text.replace('[', '\\[')
    
    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load comprehensive security testing patterns."""
        return {
            'xss_vectors': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                'javascript:alert(1)',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
            ],
            'sql_injection': [
                "' OR '1'='1",
                "1' OR '1'='1' --",
                "admin'--",
                "1; DROP TABLE users--",
                "' UNION SELECT NULL--"
            ],
            'command_injection': [
                '; ls -la',
                '| cat /etc/passwd',
                '`id`',
                '$(whoami)'
            ]
        }
    
    def _load_technology_fingerprints(self) -> Dict[str, Dict[str, Any]]:
        """Load technology detection fingerprints."""
        return {
            'frameworks': {
                'React': {
                    'patterns': ['react', 'react-dom', '_reactRootContainer'],
                    'version_regex': r'React v?(\d+\.\d+\.\d+)',
                    'category': 'frontend'
                },
                'Vue.js': {
                    'patterns': ['vue', 'vue.js', '__vue__', 'v-bind'],
                    'version_regex': r'Vue\.js v?(\d+\.\d+\.\d+)',
                    'category': 'frontend'
                },
                'Angular': {
                    'patterns': ['angular', 'ng-version', 'ng-app'],
                    'version_regex': r'Angular(?:JS)? v?(\d+\.\d+\.\d+)',
                    'category': 'frontend'
                },
                'Django': {
                    'patterns': ['django', 'csrfmiddlewaretoken'],
                    'version_regex': r'Django ([\d.]+)',
                    'category': 'backend'
                },
                'Laravel': {
                    'patterns': ['laravel', 'csrf-token', 'laravel_session'],
                    'version_regex': r'Laravel v?(\d+\.\d+\.\d+)',
                    'category': 'backend'
                }
            },
            'cms': {
                'WordPress': {
                    'patterns': ['wp-content', 'wp-includes', 'wp-json'],
                    'version_regex': r'WordPress ([\d.]+)',
                    'meta_key': 'generator'
                },
                'Drupal': {
                    'patterns': ['drupal', 'sites/default'],
                    'version_regex': r'Drupal ([\d.]+)',
                    'meta_key': 'generator'
                },
                'Joomla': {
                    'patterns': ['joomla', 'media/system/js/'],
                    'version_regex': r'Joomla! ([\d.]+)',
                    'meta_key': 'generator'
                }
            }
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=10)
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers={'User-Agent': self.user_agent}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    def _add_flag(self, flag: str, reason: str) -> None:
        """Add a FormPoison flag with reason."""
        # Normalize flag names
        flag_map = {
            '--verbose': '-v',
            '--check': '-qs',
            '--payloads': '-p',
            '--user-agent': '-ua',
            '--seconds': '-s',
            '--brute-force': '--brute',
            '--sqli': '-t SQL',
            '--xss': '-t HTML',
        }
        
        flag = flag_map.get(flag, flag)
        self.recommended_flags.add(flag)
        
        if flag not in self.flag_reasons:
            self.flag_reasons[flag] = reason
    
    async def analyze_site(self) -> Dict[str, Any]:
        """Main analysis orchestration method."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Analyzing web forms...", total=None)
            
            console.print(Panel.fit(
                f"[bold cyan]FormAtion {self.VERSION} - Advanced Web Form Analysis[/bold cyan]\n"
                f"[dim]Target: {self._escape_markup(self.url)}[/dim]\n"
                f"[dim]Using official FormPoison flags[/dim]",
                border_style="cyan"
            ))
            
            # Phase 1: Fetch and parse
            progress.update(task, description="[cyan]Fetching page content...")
            self.page_content = await self._fetch_page()
            if not self.page_content:
                console.print("[bold red]Failed to fetch page content[/bold red]")
                return self.results
            
            # Phase 2: Form analysis
            progress.update(task, description="[cyan]Analyzing forms and fields...")
            await self._analyze_forms_deep()
            
            # Phase 3: Security headers
            progress.update(task, description="[cyan]Checking security headers...")
            await self._analyze_security_headers()
            
            # Phase 4: Technology detection
            progress.update(task, description="[cyan]Detecting technology stack...")
            await self._detect_technology_stack()
            
            # Phase 5: Generate recommendations with official flags
            progress.update(task, description="[cyan]Generating recommendations...")
            self._generate_recommendations_with_official_flags()
            
            # Phase 6: Risk assessment
            self._create_risk_assessment()
            
            # Display results
            self._display_comprehensive_report()
            
        return self.results
    
    async def _fetch_page(self) -> Optional[str]:
        """Enhanced page fetching with retry logic."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if not self.session:
                    await self.__aenter__()
                
                async with self.session.get(
                    self.url,
                    proxy=self.proxies,
                    allow_redirects=True,
                    max_redirects=self.max_redirects
                ) as response:
                    self.results['response_code'] = response.status
                    self.results['content_type'] = response.headers.get('Content-Type', '')
                    self.results['server'] = response.headers.get('Server', '')
                    self.results['final_url'] = str(response.url)
                    
                    self.response_headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    if response.history:
                        self.results['redirect_chain'] = [
                            {'url': str(h.url), 'status': h.status} 
                            for h in response.history
                        ]
                    
                    content = await response.text()
                    self.results['page_size'] = len(content)
                    return content
                    
            except asyncio.TimeoutError:
                logger.warning(f"Timeout on attempt {attempt + 1}")
                if attempt == max_retries - 1:
                    console.print(f"[red]Timeout fetching {self._escape_markup(self.url)}[/red]")
                    return None
                await asyncio.sleep(2 ** attempt)
                
            except Exception as e:
                logger.error(f"Error: {e}")
                if attempt == max_retries - 1:
                    console.print(f"[red]Error: {self._escape_markup(str(e))}[/red]")
                    return None
                await asyncio.sleep(2 ** attempt)
        
        return None
    
    async def _analyze_forms_deep(self) -> None:
        """Enhanced form analysis."""
        if not self.page_content:
            return
        
        soup = BeautifulSoup(self.page_content, 'html.parser')
        forms = soup.find_all('form')
        
        console.print(f"\n[bold yellow]Found {len(forms)} forms[/bold yellow]")
        
        for i, form in enumerate(forms):
            form_analysis = FormAnalysis(
                form_id=i + 1,
                action=form.get('action', ''),
                method=form.get('method', 'GET').upper(),
                enctype=form.get('enctype', ''),
                html_source=str(form)[:3000]
            )
            
            interactive_elements = {
                'inputs': form.find_all('input'),
                'textareas': form.find_all('textarea'),
                'selects': form.find_all('select'),
                'buttons': form.find_all('button')
            }
            
            all_fields = []
            for element_type, elements in interactive_elements.items():
                for element in elements:
                    field_info = self._analyze_field(element, element_type)
                    all_fields.append(field_info)
                    
                    if field_info.is_text_input:
                        form_analysis.text_input_fields.append(field_info)
                    else:
                        form_analysis.non_text_fields.append(field_info)
            
            form_analysis.all_fields = all_fields
            
            self._assess_form_vulnerability(form_analysis)
            self._detect_attack_vectors(form_analysis)
            
            self.results['forms_analysis'].append(form_analysis.to_dict())
    
    def _analyze_field(self, field, element_type: str) -> FieldAnalysis:
        """Analyze individual form field."""
        field_type = field.get('type', 'text') if field.name == 'input' else field.name
        field_name = field.get('name', '')
        field_id = field.get('id', '')
        field_value = field.get('value', '')
        
        field_analysis = FieldAnalysis(
            element_type=element_type,
            field_type=field_type,
            name=field_name,
            id=field_id,
            value=field_value,
            attributes=dict(field.attrs),
            is_text_input=self._is_text_input(field)
        )
        
        field_analysis.field_category = self._categorize_field(
            field_name, field_id, field_type, element_type
        )
        
        self._detect_patterns(field_analysis)
        self._detect_risks(field_analysis)
        self._assess_threat_level(field_analysis)
        
        return field_analysis
    
    def _is_text_input(self, field) -> bool:
        """Check if field is text input."""
        if field.name == 'textarea':
            return True
        if field.name == 'input':
            field_type = field.get('type', 'text').lower()
            return field_type in [
                'text', 'password', 'email', 'search', 'url', 'tel',
                'number', 'date', 'datetime', 'datetime-local', 'month',
                'week', 'time', 'range', 'color', 'hidden'
            ]
        if field.name == 'select':
            return True
        return False
    
    def _categorize_field(self, name: str, id_: str, type_: str, element_type: str) -> str:
        """Categorize field by type."""
        name_lower = name.lower()
        id_lower = id_.lower()
        
        categories = {
            'password': ['password', 'pass', 'pwd', 'secret', 'passwd', 'pin'],
            'login': ['user', 'login', 'email', 'username', 'account', 'uid'],
            'file_upload': ['file', 'upload', 'attachment', 'avatar', 'photo'],
            'search': ['search', 'query', 'q', 'keyword', 'find'],
            'content': ['comment', 'message', 'content', 'body', 'description', 'bio'],
            'contact': ['name', 'phone', 'tel', 'address', 'city', 'zip', 'state'],
            'hidden': ['hidden', 'csrf', 'token', 'nonce', 'session'],
            'choice': ['checkbox', 'radio', 'choice', 'option', 'select'],
            'payment': ['credit', 'card', 'payment', 'billing', 'cc', 'cvv'],
            'url': ['url', 'link', 'website', 'href', 'redirect', 'callback'],
            'database': ['id', 'uid', 'pid', 'item_id', 'record_id']
        }
        
        for category, keywords in categories.items():
            if any(kw in name_lower or kw in id_lower for kw in keywords):
                if category == 'password' or type_ == 'password':
                    return 'password'
                elif category == 'hidden' or type_ == 'hidden':
                    return 'hidden'
                elif category == 'file_upload' or type_ == 'file':
                    return 'file_upload'
                return category
        
        if element_type == 'select':
            return 'dropdown'
        elif element_type == 'button' or type_ in ['submit', 'button', 'reset']:
            return 'button'
        
        return 'other'
    
    def _detect_patterns(self, field_analysis: FieldAnalysis) -> None:
        """Detect suspicious patterns."""
        name = field_analysis.name.lower()
        attrs = field_analysis.attributes
        field_type = field_analysis.field_type
        
        # Validation checks
        if field_analysis.is_text_input:
            validation_attrs = ['maxlength', 'pattern', 'required', 'min', 'max', 'minlength']
            if not any(attr in attrs for attr in validation_attrs):
                field_analysis.suspicious_patterns.append('no_client_side_validation')
        
        # Sensitive field exposure
        sensitive_names = ['csrf', 'token', 'auth', 'key', 'hash', 'nonce', 'session', 'jwt']
        if any(sensitive in name for sensitive in sensitive_names):
            field_analysis.suspicious_patterns.append('sensitive_field_exposed')
        
        # Autocomplete issues
        if attrs.get('autocomplete') == 'on' and field_analysis.field_category in ['password', 'login']:
            field_analysis.suspicious_patterns.append('autocomplete_enabled_on_sensitive')
        
        # Hidden field with value
        if field_type == 'hidden' and field_analysis.value:
            field_analysis.suspicious_patterns.append('hidden_field_with_value')
        
        # No file type restriction
        if field_analysis.field_category == 'file_upload' and 'accept' not in attrs:
            field_analysis.suspicious_patterns.append('unrestricted_file_types')
    
    def _detect_risks(self, field_analysis: FieldAnalysis) -> None:
        """Detect PortSwigger risks."""
        field_category = field_analysis.field_category
        field_type = field_analysis.field_type
        
        risk_map = {
            'content': ['reflected_xss', 'stored_xss', 'dom_xss'],
            'search': ['reflected_xss', 'sql_injection'],
            'login': ['sql_injection', 'nosql_injection', 'authentication_bypass'],
            'password': ['credential_stuffing', 'brute_force'],
            'url': ['open_redirect', 'ssrf'],
            'file_upload': ['file_upload_xss', 'rce_upload', 'path_traversal'],
            'payment': ['payment_injection', 'price_manipulation'],
            'database': ['idor', 'mass_assignment'],
            'hidden': ['csrf_token_analysis', 'parameter_pollution'],
            'choice': ['parameter_tampering', 'business_logic_bypass']
        }
        
        if field_category in risk_map:
            field_analysis.portswigger_risks.extend(risk_map[field_category])
        
        # Type-specific risks
        if field_type == 'email':
            field_analysis.portswigger_risks.extend(['email_injection', 'header_injection'])
        elif field_type == 'number':
            field_analysis.portswigger_risks.extend(['integer_overflow', 'negative_value_injection'])
        
        field_analysis.portswigger_risks = list(set(field_analysis.portswigger_risks))
    
    def _assess_threat_level(self, field_analysis: FieldAnalysis) -> None:
        """Assess threat level."""
        threat_score = 0
        
        risk_weights = {
            'sql_injection': 5, 'rce_upload': 5, 'stored_xss': 4,
            'command_injection': 5, 'ssrf': 4, 'reflected_xss': 3,
            'file_upload_xss': 3, 'dom_xss': 3, 'authentication_bypass': 4,
            'idor': 3, 'open_redirect': 2, 'csrf_token_analysis': 1,
            'parameter_tampering': 2, 'credential_stuffing': 2, 'brute_force': 2
        }
        
        for risk in field_analysis.portswigger_risks:
            threat_score += risk_weights.get(risk, 1)
        
        if threat_score >= 7:
            field_analysis.threat_level = 'high'
        elif threat_score >= 4:
            field_analysis.threat_level = 'medium'
        elif threat_score >= 2:
            field_analysis.threat_level = 'low'
        else:
            field_analysis.threat_level = 'info'
    
    def _assess_form_vulnerability(self, form_analysis: FormAnalysis) -> None:
        """Assess form vulnerability."""
        score = 0
        indicators = []
        vectors = []
        
        # GET method risks
        if form_analysis.method == 'GET':
            score += 3
            indicators.append('get_method_used')
            vectors.append('reflected_xss_via_get')
        
        # CSRF check
        has_csrf = any('csrf' in f.name.lower() or 'token' in f.name.lower() 
                      for f in form_analysis.all_fields)
        if not has_csrf:
            score += 5
            indicators.append('no_csrf_protection')
            vectors.append('csrf_vulnerable')
        
        # Login form detection
        login_fields = sum(1 for f in form_analysis.text_input_fields if f.field_category == 'login')
        password_fields = sum(1 for f in form_analysis.text_input_fields if f.field_category == 'password')
        
        if login_fields > 0 and password_fields > 0:
            score += 4
            indicators.append('login_form_detected')
            vectors.extend(['credential_stuffing', 'brute_force_login'])
        
        # File upload detection
        if any(f.field_category == 'file_upload' for f in form_analysis.all_fields):
            score += 5
            indicators.append('file_upload_detected')
            vectors.extend(['malicious_file_upload', 'stored_xss_via_files'])
        
        # Unvalidated fields
        unvalidated = sum(1 for f in form_analysis.text_input_fields 
                        if 'no_client_side_validation' in f.suspicious_patterns)
        if unvalidated > 0:
            score += unvalidated * 2
            indicators.append(f'{unvalidated}_unvalidated_fields')
            vectors.append('input_validation_bypass')
        
        form_analysis.complexity_score = score
        form_analysis.vulnerability_indicators = indicators
        form_analysis.portswigger_vectors = list(set(vectors))
    
    def _detect_attack_vectors(self, form_analysis: FormAnalysis) -> None:
        """Detect attack vectors."""
        # DOM XSS
        if any(f.field_category in ['search', 'content', 'url'] 
               for f in form_analysis.text_input_fields):
            form_analysis.portswigger_vectors.append('dom_xss_potential')
        
        # Template injection
        if any('{{' in f.value or '}}' in f.value or '${' in f.value 
               for f in form_analysis.text_input_fields):
            form_analysis.portswigger_vectors.append('template_injection_potential')
        
        # HTTP Parameter Pollution
        if form_analysis.method == 'GET' and len(form_analysis.text_input_fields) > 2:
            form_analysis.portswigger_vectors.append('http_parameter_pollution')
        
        # Business logic
        if any(f.field_category == 'payment' for f in form_analysis.all_fields):
            if any(f.field_category == 'choice' for f in form_analysis.all_fields):
                form_analysis.portswigger_vectors.append('business_logic_manipulation')
        
        form_analysis.portswigger_vectors = list(set(form_analysis.portswigger_vectors))
    
    async def _analyze_security_headers(self) -> None:
        """Analyze security headers."""
        security_headers = {
            'Content-Security-Policy': {
                'risk': 'high',
                'description': 'CSP prevents XSS attacks'
            },
            'X-Frame-Options': {
                'risk': 'medium',
                'description': 'Prevents clickjacking'
            },
            'Strict-Transport-Security': {
                'risk': 'high',
                'description': 'Enforces HTTPS'
            },
            'X-Content-Type-Options': {
                'risk': 'low',
                'description': 'Prevents MIME sniffing'
            },
            'X-XSS-Protection': {
                'risk': 'medium',
                'description': 'XSS filter'
            },
            'Referrer-Policy': {
                'risk': 'low',
                'description': 'Controls referrer information'
            },
            'Permissions-Policy': {
                'risk': 'medium',
                'description': 'Controls browser features'
            }
        }
        
        headers_analysis = {}
        
        for header, config in security_headers.items():
            value = self.response_headers.get(header.lower())
            status = "Present" if value else "Missing"
            
            headers_analysis[header] = {
                'value': value,
                'status': status,
                'risk_level': config['risk'],
                'description': config['description'],
                'is_compliant': value is not None
            }
        
        # Cookie security
        if 'set-cookie' in self.response_headers:
            cookies = self.response_headers['set-cookie']
            cookie_secure = all(flag in cookies.lower() for flag in ['secure', 'httponly', 'samesite'])
            
            headers_analysis['Cookie-Security'] = {
                'value': 'Secure' if cookie_secure else 'Insecure',
                'status': 'Secure' if cookie_secure else 'Insecure',
                'risk_level': 'high',
                'description': 'Cookie security attributes',
                'is_compliant': cookie_secure
            }
        
        self.results['security_headers'] = headers_analysis
    
    async def _detect_technology_stack(self) -> None:
        """Detect technology stack."""
        if not self.page_content:
            return
        
        soup = BeautifulSoup(self.page_content, 'html.parser')
        tech_stack = {}
        
        # Script-based detection
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '').lower()
            content = (script.string or '').lower()
            
            for framework, fingerprint in self.technology_fingerprints['frameworks'].items():
                if any(pattern in src or pattern in content for pattern in fingerprint['patterns']):
                    version_match = re.search(fingerprint['version_regex'], src + content)
                    version = version_match.group(1) if version_match else None
                    tech_name = f"{framework} {version or ''}".strip()
                    
                    category = fingerprint['category'] + '_frameworks'
                    if category not in tech_stack:
                        tech_stack[category] = []
                    if tech_name not in tech_stack[category]:
                        tech_stack[category].append(tech_name)
        
        # Meta generator detection
        for meta in soup.find_all('meta'):
            if meta.get('name', '').lower() == 'generator':
                content = meta.get('content', '').lower()
                for cms, fingerprint in self.technology_fingerprints['cms'].items():
                    if cms.lower() in content:
                        version_match = re.search(fingerprint['version_regex'], content)
                        version = version_match.group(1) if version_match else None
                        tech_name = f"{cms} {version or ''}".strip()
                        
                        if 'cms' not in tech_stack:
                            tech_stack['cms'] = []
                        if tech_name not in tech_stack['cms']:
                            tech_stack['cms'].append(tech_name)
        
        # Server detection
        server = self.response_headers.get('server', '').lower()
        if server:
            tech_stack['web_servers'] = []
            if 'apache' in server:
                tech_stack['web_servers'].append('Apache')
            elif 'nginx' in server:
                tech_stack['web_servers'].append('Nginx')
            elif 'iis' in server:
                tech_stack['web_servers'].append('Microsoft IIS')
        
        # Language detection
        powered_by = self.response_headers.get('x-powered-by', '').lower()
        languages = {'php': 'PHP', 'asp.net': 'C#/ASP.NET', 'node': 'Node.js',
                    'python': 'Python', 'ruby': 'Ruby', 'java': 'Java'}
        
        for indicator, language in languages.items():
            if indicator in server or indicator in powered_by:
                if 'programming_languages' not in tech_stack:
                    tech_stack['programming_languages'] = []
                if language not in tech_stack['programming_languages']:
                    tech_stack['programming_languages'].append(language)
        
        self.results['technology_stack'] = tech_stack
    
    def _generate_recommendations_with_official_flags(self) -> None:
        """Generate recommendations using only official FormPoison flags."""
        recommendations = []
        attack_vectors = set()
        
        # Analyze each form
        for form in self.results['forms_analysis']:
            form_id = form.get('form_id', 0)
            score = form.get('complexity_score', 0)
            indicators = form.get('vulnerability_indicators', [])
            vectors = form.get('portswigger_vectors', [])
            text_fields = form.get('text_input_fields', [])
            
            # High complexity forms
            if score >= 10:
                recommendations.append(f"[CRITICAL] Form {form_id}: Very high risk (Score: {score})")
                self._add_flag('--verbose-all', f'Form {form_id} high complexity')
                attack_vectors.add('Multiple Attack Vectors')
            elif score >= 7:
                recommendations.append(f"[HIGH] Form {form_id}: High risk (Score: {score})")
                self._add_flag('-v', f'Form {form_id} high risk - verbose recommended')
            
            # Login forms
            if 'login_form_detected' in indicators:
                recommendations.append(f"Form {form_id}: Login form detected")
                self._add_flag('--login', f'Form {form_id} is login form')
                attack_vectors.add('Authentication Bypass')
            
            # File upload
            if 'file_upload_detected' in indicators:
                recommendations.append(f"Form {form_id}: File upload detected")
                self._add_flag('--filemode', f'Form {form_id} has file upload')
                attack_vectors.add('File Upload Attack')
            
            # GET method
            if 'get_method_used' in indicators:
                recommendations.append(f"Form {form_id}: Uses GET method")
                self._add_flag('--method GET', 'GET forms detected')
                attack_vectors.add('Reflected XSS via GET')
            
            # SQL Injection potential
            sql_fields = [f for f in text_fields if 'sql_injection' in f.get('portswigger_risks', [])]
            if sql_fields:
                recommendations.append(f"Form {form_id}: SQL injection potential in {len(sql_fields)} fields")
                self._add_flag('-t SQL', f'Form {form_id} has SQL injection potential')
                attack_vectors.add('SQL Injection')
            
            # XSS potential
            xss_fields = [f for f in text_fields if any(r in f.get('portswigger_risks', []) 
                         for r in ['reflected_xss', 'stored_xss', 'dom_xss'])]
            if xss_fields:
                recommendations.append(f"Form {form_id}: XSS potential in {len(xss_fields)} fields")
                self._add_flag('-t HTML', f'Form {form_id} has XSS potential')
                attack_vectors.add('Cross-Site Scripting (XSS)')
            
            # Mutation XSS
            if 'dom_xss_potential' in vectors:
                recommendations.append(f"Form {form_id}: DOM XSS potential")
                self._add_flag('--mXSS', f'Form {form_id} DOM XSS potential')
                attack_vectors.add('Mutation XSS')
            
            # Multiple text fields
            if len(text_fields) > 5:
                recommendations.append(f"Form {form_id}: Multiple text fields ({len(text_fields)})")
                self._add_flag('--brute', f'Form {form_id} has {len(text_fields)} text fields')
                attack_vectors.add('Brute Force')
        
        # Technology-specific recommendations
        tech = self.results.get('technology_stack', {})
        
        # Frontend frameworks - sanitizer bypass
        if 'frontend_frameworks' in tech:
            frameworks = tech['frontend_frameworks']
            recommendations.append(f"Modern JS frameworks detected: {', '.join(frameworks)}")
            self._add_flag('--sanitizer-bypass', f'Frameworks detected: {", ".join(frameworks)}')
            self._add_flag('--mXSS', 'Framework mutation XSS')
            attack_vectors.add('Sanitizer Bypass')
        
        # CMS detection - encoder bypass
        if 'cms' in tech:
            cms_list = tech['cms']
            recommendations.append(f"CMS detected: {', '.join(cms_list)}")
            self._add_flag('--encoder-bypass', f'CMS detected: {", ".join(cms_list)}')
            attack_vectors.add('CMS-Specific Attacks')
        
        # Backend frameworks
        if 'backend_frameworks' in tech:
            backend = tech['backend_frameworks']
            recommendations.append(f"Backend frameworks: {', '.join(backend)}")
            self._add_flag('--encoder-bypass', f'Backend: {", ".join(backend)}')
        
        # ASP.NET specific
        if any('ASP.NET' in str(fw) for fw in tech.get('backend_frameworks', [])):
            self._add_flag('--encoding-confusion', 'ASP.NET detected')
            self._add_flag('--encoder-bypass', 'ASP.NET encoder bypass')
        
        # WordPress specific
        if any('WordPress' in cms for cms in tech.get('cms', [])):
            self._add_flag('--sanitizer-bypass', 'WordPress sanitizer bypass')
        
        # PHP/Python detection
        if any(lang in str(tech.get('programming_languages', [])) for lang in ['PHP', 'Python']):
            self._add_flag('--encoder-bypass', 'PHP/Python encoder bypass')
        
        # Security headers analysis
        headers = self.results.get('security_headers', {})
        
        # CSP detection
        if headers.get('Content-Security-Policy', {}).get('is_compliant'):
            recommendations.append("CSP detected - may need bypass")
            self._add_flag('--csp-bypass', 'CSP header present')
            attack_vectors.add('CSP Bypass')
        else:
            recommendations.append("No CSP detected - XSS easier to exploit")
        
        # CDN/WAF detection
        server = self.response_headers.get('server', '').lower()
        if any(cdn in server for cdn in ['cloudflare', 'cloudfront', 'akamai', 'fastly']):
            recommendations.append("CDN/WAF detected")
            self._add_flag('--waf-bypass', f'CDN/WAF: {server}')
            attack_vectors.add('WAF Bypass')
        
        # Large forms - size overflow
        total_fields = sum(len(f.get('all_fields', [])) for f in self.results['forms_analysis'])
        if total_fields > 15:
            self._add_flag('--size-overflow', f'Large forms ({total_fields} total fields)')
            attack_vectors.add('Size Overflow')
        
        # GET forms - encoding confusion
        if any(form.get('method') == 'GET' for form in self.results['forms_analysis']):
            self._add_flag('--encoding-confusion', 'GET forms detected')
        
        # Scan recommendations
        if total_fields > 10:
            self._add_flag('--scan', 'Complex form structure - deep scan recommended')
            self._add_flag('--auto-target', 'Auto-target based on scan results')
        else:
            self._add_flag('-qs', 'Quick scan recommended')
        
        # Performance recommendations based on form count
        form_count = len(self.results['forms_analysis'])
        if form_count > 3:
            self._add_flag('--concurrent', 'Multiple forms - concurrent recommended')
            self._add_flag('--batch-size', 'Batch processing recommended')
        
        # Build final command
        sorted_flags = sorted(self.recommended_flags)
        command = f"python formpoison.py {self.url} {' '.join(sorted_flags)}"
        
        recommendations.append(f"[bold]Recommended FormPoison command:[/bold]")
        recommendations.append(f"[cyan]{command}[/cyan]")
        
        self.results['recommendations'] = recommendations
        self.results['formpoison_flags'] = sorted_flags
        self.results['formpoison_command'] = command
        self.results['attack_vectors'] = list(attack_vectors)
    
    def _create_risk_assessment(self) -> None:
        """Create overall risk assessment."""
        total_forms = len(self.results['forms_analysis'])
        high_risk_forms = sum(1 for f in self.results['forms_analysis'] if f.get('complexity_score', 0) >= 7)
        critical_forms = sum(1 for f in self.results['forms_analysis'] if f.get('complexity_score', 0) >= 10)
        
        risk_score = 0
        risk_score += len(self.results.get('attack_vectors', [])) * 5
        risk_score += high_risk_forms * 10
        risk_score += critical_forms * 15
        
        missing_critical = sum(
            1 for info in self.results.get('security_headers', {}).values()
            if info.get('status') == 'Missing' and info.get('risk_level') == 'high'
        )
        risk_score += missing_critical * 8
        risk_score = min(risk_score, 100)
        
        if risk_score >= 75:
            risk_level = 'CRITICAL'
            color = 'red'
        elif risk_score >= 50:
            risk_level = 'HIGH'
            color = 'orange1'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
            color = 'yellow'
        else:
            risk_level = 'LOW'
            color = 'green'
        
        self.results['risk_assessment'] = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'color': color,
            'critical_forms': critical_forms,
            'high_risk_forms': high_risk_forms,
            'total_forms': total_forms,
            'attack_vectors_count': len(self.results.get('attack_vectors', []))
        }
    
    def _display_comprehensive_report(self) -> None:
        """Display comprehensive analysis report."""
        
        # Executive Summary
        risk = self.results.get('risk_assessment', {})
        risk_color = risk.get('color', 'white')
        risk_level = risk.get('risk_level', 'UNKNOWN')
        
        console.print(Panel.fit(
            f"[bold]EXECUTIVE SUMMARY[/bold]\n\n"
            f"Target: {self._escape_markup(self.results['url'])}\n"
            f"Risk Level: [bold {risk_color}]{risk_level}[/bold {risk_color}]\n"
            f"Risk Score: {risk.get('risk_score', 0)}/100\n"
            f"Forms: {risk.get('total_forms', 0)} "
            f"(Critical: {risk.get('critical_forms', 0)}, "
            f"High: {risk.get('high_risk_forms', 0)})\n"
            f"Attack Vectors: {risk.get('attack_vectors_count', 0)}",
            title="FormAtion Analysis",
            border_style=risk_color
        ))
        
        # Forms Analysis
        if self.results['forms_analysis']:
            console.print("\n[bold cyan]FORM ANALYSIS[/bold cyan]")
            
            for form in self.results['forms_analysis']:
                form_id = form.get('form_id', 0)
                score = form.get('complexity_score', 0)
                
                if score >= 10:
                    risk_color, risk_level = 'red', 'CRITICAL'
                elif score >= 7:
                    risk_color, risk_level = 'orange1', 'HIGH'
                elif score >= 4:
                    risk_color, risk_level = 'yellow', 'MEDIUM'
                else:
                    risk_color, risk_level = 'green', 'LOW'
                
                form_table = Table(
                    title=f"Form {form_id} - {risk_level} (Score: {score})",
                    header_style=f"bold {risk_color}",
                    box=box.ROUNDED
                )
                
                form_table.add_column("Field", style="cyan")
                form_table.add_column("Type", style="white")
                form_table.add_column("Category", style="green")
                form_table.add_column("Risks", style="red")
                
                for field in form.get('text_input_fields', []):
                    risks = ', '.join(field.get('portswigger_risks', [])[:3])
                    form_table.add_row(
                        self._escape_markup(field.get('name', 'N/A')),
                        self._escape_markup(field.get('field_type', 'text')),
                        self._escape_markup(field.get('field_category', 'other')),
                        self._escape_markup(risks) if risks else 'None'
                    )
                
                console.print(form_table)
                
                if form.get('portswigger_vectors'):
                    safe_vectors = self._escape_markup(', '.join(form['portswigger_vectors'][:5]))
                    console.print(f"[bold cyan]Attack Vectors:[/bold cyan] {safe_vectors}")
        
        # Security Headers
        if self.results.get('security_headers'):
            console.print("\n[bold cyan]SECURITY HEADERS[/bold cyan]")
            
            headers_table = Table(
                title="Security Headers",
                header_style="bold blue",
                box=box.ROUNDED
            )
            
            headers_table.add_column("Header", style="cyan")
            headers_table.add_column("Status", style="white")
            headers_table.add_column("Risk", style="red")
            
            for header, info in self.results['security_headers'].items():
                is_compliant = info.get('is_compliant', False)
                status_style = 'green' if is_compliant else 'red'
                status_text = info.get('status', 'Unknown')
                
                headers_table.add_row(
                    self._escape_markup(header),
                    f"[{status_style}]{self._escape_markup(status_text)}[/{status_style}]",
                    info.get('risk_level', 'unknown').upper()
                )
            
            console.print(headers_table)
        
        # Technology Stack
        if self.results.get('technology_stack'):
            console.print("\n[bold cyan]TECHNOLOGY STACK[/bold cyan]")
            
            tech_tree = Tree("Detected Technologies")
            for category, technologies in self.results['technology_stack'].items():
                if technologies:
                    category_node = tech_tree.add(f"[bold]{self._escape_markup(category.replace('_', ' ').title())}[/bold]")
                    for tech in technologies:
                        category_node.add(f"[green]{self._escape_markup(tech)}[/green]")
            
            console.print(tech_tree)
        
        # FormPoison Command
        if self.results.get('formpoison_command'):
            console.print(Panel.fit(
                f"[bold cyan]Recommended FormPoison Command[/bold cyan]\n\n"
                f"[white]{self._escape_markup(self.results['formpoison_command'])}[/white]\n\n"
                f"[dim]Flags: {self._escape_markup(', '.join(self.results.get('formpoison_flags', [])))}[/dim]",
                border_style="cyan",
                title="Execute"
            ))
        
        # Flag explanations
        if self.flag_reasons:
            console.print("\n[bold yellow]FLAG RECOMMENDATIONS:[/bold yellow]")
            for flag, reason in self.flag_reasons.items():
                console.print(f"  [cyan]{self._escape_markup(flag)}[/cyan]: {self._escape_markup(reason)}")
        
        # Attack Vectors
        if self.results.get('attack_vectors'):
            console.print("\n[bold red]ATTACK VECTORS:[/bold red]")
            for vector in self.results['attack_vectors']:
                console.print(f"  [yellow]{self._escape_markup(vector)}[/yellow]")
        
        # Recommendations
        if self.results.get('recommendations'):
            console.print("\n[bold green]RECOMMENDATIONS:[/bold green]")
            for rec in self.results['recommendations']:
                if not rec.startswith('[bold]'):
                    console.print(f"  {self._escape_markup(rec)}")
                else:
                    console.print(f"  {rec}")

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="FormAtion - Advanced Web Form Analyzer for FormPoison"
    )
    
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--max-redirects", type=int, default=5, help="Maximum redirects")
    parser.add_argument("--version", action="version", version=f"FormAtion {FormAtionAnalyzer.VERSION}")
    
    args = parser.parse_args()
    
    console.print(Panel.fit(
        "[bold cyan]FormAtion[/bold cyan] [bold white]v" + FormAtionAnalyzer.VERSION + "[/bold white]\n"
        "[dim]Advanced Web Form Analyzer - Pre-scout for FormPoison[/dim]\n"
        "[dim]Using official FormPoison flags only[/dim]",
        border_style="cyan"
    ))
    
    analyzer = FormAtionAnalyzer(
        url=args.url,
        user_agent=args.user_agent,
        proxies=args.proxy,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        verify_ssl=not args.no_ssl_verify
    )
    
    try:
        async with analyzer:
            results = await analyzer.analyze_site()
    except Exception as e:
        error_msg = str(e).replace('[', '\\[')
        console.print(f"[bold red]Error during FormAtion analysis:[/bold red] [red]{error_msg}[/red]")
        logger.exception("Analysis failed")
        return
    finally:
        if analyzer.session and not analyzer.session.closed:
            await analyzer.session.close()
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            console.print(f"\n[bold green]Results saved to: {args.output}[/bold green]")
        except Exception as e:
            error_msg = str(e).replace('[', '\\[')
            console.print(f"[bold red]Error saving results:[/bold red] [red]{error_msg}[/red]")

if __name__ == "__main__":
    asyncio.run(main())
