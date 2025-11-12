#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import ssl
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.syntax import Syntax
import random

console = Console()

class FormAtionAnalyzer:
    def __init__(self, url, user_agent=None, proxies=None):
        self.url = url
        self.user_agent = user_agent or "FormAtion/1.0"
        self.proxies = proxies
        self.results = {
            'url': url,
            'forms_analysis': [],
            'security_headers': {},
            'technology_stack': {},
            'recommendations': [],
            'formpoison_flags': [],
            'attack_vectors': []
        }
        self.response_headers = {}
    
    async def analyze_site(self):
        console.print(Panel.fit("🔍 [bold cyan]FormAtion - Starting Deep Analysis[/bold cyan]", border_style="cyan"))
        
        content = await self.fetch_page()
        if not content:
            console.print("[bold red]❌ Failed to fetch page content[/bold red]")
            return self.results

        await self.analyze_forms(content)

        await self.analyze_security_headers()

        await self.detect_technology_stack(content)

        self.generate_recommendations()
        
        self.display_report()
        
        return self.results
    
    async def fetch_page(self):
        try:
            headers = {'User-Agent': self.user_agent}
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.url, headers=headers, proxy=self.proxies) as response:
                    self.results['response_code'] = response.status
                    self.results['content_type'] = response.headers.get('Content-Type', '')
                    self.results['server'] = response.headers.get('Server', '')
                    
                    for key, value in response.headers.items():
                        self.response_headers[key.lower()] = value
                    
                    return await response.text()
        except Exception as e:
            console.print(f"[red]Error fetching page: {str(e)}[/red]")
            return None
    
    async def analyze_forms(self, content):
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')
        
        console.print(f"\n[bold yellow]📋 Found {len(forms)} forms[/bold yellow]")
        
        for i, form in enumerate(forms):
            form_analysis = {
                'form_id': i + 1,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', ''),
                'all_fields': [],
                'text_input_fields': [],
                'non_text_fields': [],
                'vulnerability_indicators': [],
                'complexity_score': 0,
                'portswigger_vectors': [],
                'html_source': str(form)[:2000]
            }
            
            inputs = form.find_all('input')
            textareas = form.find_all('textarea')
            selects = form.find_all('select')
            buttons = form.find_all('button')
            
            all_fields = inputs + textareas + selects + buttons
            
            for field in all_fields:
                field_info = self.analyze_field(field)
                form_analysis['all_fields'].append(field_info)
                
                if self.is_text_input_field(field):
                    form_analysis['text_input_fields'].append(field_info)
                else:
                    form_analysis['non_text_fields'].append(field_info)
            
            self.assess_form_vulnerability(form_analysis)
            
            self.detect_portswigger_vectors(form_analysis)
            
            self.results['forms_analysis'].append(form_analysis)
    
    def is_text_input_field(self, field):
        if field.name == 'textarea':
            return True
            
        if field.name == 'input':
            field_type = field.get('type', 'text').lower()
            text_input_types = [
                'text', 'password', 'email', 'search', 'url', 'tel', 
                'number', 'date', 'datetime', 'datetime-local', 'month', 
                'week', 'time', 'range', 'color'
            ]
            return field_type in text_input_types
            
        if field.name == 'select':
            return True  
            
        return False
    
    def analyze_field(self, field):
        field_type = field.get('type', 'text') if field.name == 'input' else field.name
        field_name = field.get('name', '')
        field_id = field.get('id', '')
        field_value = field.get('value', '')
        
        field_analysis = {
            'element_type': field.name,
            'type': field_type,
            'name': field_name,
            'id': field_id,
            'value': field_value,
            'attributes': dict(field.attrs),
            'suspicious_patterns': [],
            'field_category': 'other',
            'portswigger_risks': [],
            'is_text_input': self.is_text_input_field(field),
            'threat_level': 'low'
        }
        
        field_analysis['field_category'] = self.categorize_field(field_name, field_id, field_type, field.name)
        
        self.detect_suspicious_patterns(field_analysis)
        
        self.detect_portswigger_risks(field_analysis)
        
        self.assess_field_threat_level(field_analysis)
        
        return field_analysis
    
    def categorize_field(self, name, id, type, element_type):
        name_lower = name.lower()
        id_lower = id.lower()
        
        # Login fields
        login_keywords = ['user', 'login', 'email', 'username', 'account', 'uid']
        if any(keyword in name_lower or keyword in id_lower for keyword in login_keywords):
            return 'login'
        
        # Password fields
        password_keywords = ['password', 'pass', 'pwd', 'secret', 'passwd']
        if any(keyword in name_lower or keyword in id_lower for keyword in password_keywords) or type == 'password':
            return 'password'
        
        # File upload
        if type == 'file':
            return 'file_upload'
        
        # Search fields
        search_keywords = ['search', 'query', 'q', 'keyword']
        if any(keyword in name_lower or keyword in id_lower for keyword in search_keywords):
            return 'search'
        
        # Comment/Content fields
        content_keywords = ['comment', 'message', 'content', 'body', 'description', 'bio']
        if any(keyword in name_lower or keyword in id_lower for keyword in content_keywords):
            return 'content'
        
        # Contact fields
        contact_keywords = ['name', 'phone', 'tel', 'address', 'city', 'zip']
        if any(keyword in name_lower or keyword in id_lower for keyword in contact_keywords):
            return 'contact'
            
        # Hidden fields (often contain sensitive data)
        if type == 'hidden':
            return 'hidden'
        
        # Checkbox/Radio buttons
        if type in ['checkbox', 'radio']:
            return 'choice'
            
        # Submit buttons
        if type == 'submit' or element_type == 'button':
            return 'button'
            
        # Select dropdowns
        if element_type == 'select':
            return 'dropdown'
        
        return 'other'
    
    def detect_suspicious_patterns(self, field_analysis):
        name = field_analysis['name'].lower()
        attrs = field_analysis['attributes']
        field_type = field_analysis['type']
        element_type = field_analysis['element_type']
        
        if field_analysis['is_text_input'] and not any(attr in attrs for attr in ['maxlength', 'pattern', 'required', 'min', 'max']):
            field_analysis['suspicious_patterns'].append('no_client_side_validation')
        
        suspicious_names = ['csrf', 'token', 'auth', 'key', 'hash', 'nonce', 'session']
        if any(suspicious in name for suspicious in suspicious_names):
            field_analysis['suspicious_patterns'].append('suspicious_field_name')
        
        # Auto-complete enabled on sensitive fields
        if attrs.get('autocomplete') == 'on' and field_analysis['field_category'] in ['password', 'login']:
            field_analysis['suspicious_patterns'].append('autocomplete_enabled')
        
        # Hidden fields with values (potential sensitive data exposure)
        if field_type == 'hidden' and field_analysis.get('value'):
            field_analysis['suspicious_patterns'].append('hidden_field_with_value')
        
        # Checkbox/radio with predefined values (parameter tampering)
        if field_type in ['checkbox', 'radio'] and field_analysis.get('value'):
            field_analysis['suspicious_patterns'].append('predefined_choice_value')
    
    def detect_portswigger_risks(self, field_analysis):
        field_type = field_analysis['type']
        field_category = field_analysis['field_category']
        is_text_input = field_analysis['is_text_input']
        
        # XSS risks 
        if is_text_input and field_category in ['content', 'search', 'comment']:
            field_analysis['portswigger_risks'].append('reflected_xss')
        
        if is_text_input and field_category in ['content', 'comment']:
            field_analysis['portswigger_risks'].append('stored_xss')
        
        # SQL Injection risks 
        if is_text_input and field_category in ['login', 'search']:
            field_analysis['portswigger_risks'].append('sql_injection')
        
        # File upload risks
        if field_category == 'file_upload':
            field_analysis['portswigger_risks'].extend(['file_upload_xss', 'rce_upload'])
        
        # CSRF risks
        if field_category == 'hidden' and 'token' in field_analysis['name'].lower():
            field_analysis['portswigger_risks'].append('csrf_token_detected')
        
        # Parameter tampering for choice fields
        if field_category == 'choice' and field_analysis.get('value'):
            field_analysis['portswigger_risks'].append('parameter_tampering')
    
    def assess_field_threat_level(self, field_analysis):
        threat_score = 0
 
        if any(risk in field_analysis['portswigger_risks'] for risk in ['sql_injection', 'rce_upload', 'stored_xss']):
            threat_score += 3
        elif any(risk in field_analysis['portswigger_risks'] for risk in ['reflected_xss', 'file_upload_xss']):
            threat_score += 2
        elif any(risk in field_analysis['portswigger_risks'] for risk in ['csrf_token_detected', 'parameter_tampering']):
            threat_score += 1

        threat_score += len(field_analysis['suspicious_patterns'])
        
        if threat_score >= 3:
            field_analysis['threat_level'] = 'high'
        elif threat_score >= 2:
            field_analysis['threat_level'] = 'medium'
        else:
            field_analysis['threat_level'] = 'low'
    
    def assess_form_vulnerability(self, form_analysis):
        score = 0
        indicators = []
        portswigger_vectors = []
        
        #  GET - (PortSwigger: Reflected XSS)
        if form_analysis['method'] == 'GET':
            score += 2
            indicators.append('get_method_used')
            portswigger_vectors.append('reflected_xss_via_get')
        
        # no CSRF (PortSwigger: CSRF attacks)
        has_csrf = any('csrf' in field['name'].lower() or 'token' in field['name'].lower() 
                      for field in form_analysis['all_fields'])
        if not has_csrf:
            score += 3
            indicators.append('no_csrf_protection')
            portswigger_vectors.append('csrf_vulnerable')
        
        # validaiton missing (PortSwigger: Input validation bypass)
        unvalidated_text_fields = sum(1 for field in form_analysis['text_input_fields'] 
                                    if 'no_client_side_validation' in field['suspicious_patterns'])
        if unvalidated_text_fields > 0:
            score += unvalidated_text_fields
            indicators.append(f'{unvalidated_text_fields}_unvalidated_text_fields')
            portswigger_vectors.append('input_validation_bypass')
        
        # Login:Pass(PortSwigger: Authentication attacks)
        login_fields = sum(1 for field in form_analysis['text_input_fields'] if field['field_category'] == 'login')
        password_fields = sum(1 for field in form_analysis['text_input_fields'] if field['field_category'] == 'password')
        
        if login_fields > 0 and password_fields > 0:
            score += 2
            indicators.append('login_form_detected')
            portswigger_vectors.extend(['credential_stuffing', 'brute_force_login'])
        
        # File upload (PortSwigger: File upload vulnerabilities)
        if any(field['field_category'] == 'file_upload' for field in form_analysis['all_fields']):
            score += 3
            indicators.append('file_upload_detected')
            portswigger_vectors.extend(['malicious_file_upload', 'stored_xss_via_files'])
        
        # Hidden fields with values (PortSwigger: Insecure direct object references)
        hidden_with_values = sum(1 for field in form_analysis['all_fields'] 
                               if 'hidden_field_with_value' in field['suspicious_patterns'])
        if hidden_with_values > 0:
            score += 2
            indicators.append('hidden_fields_with_values')
            portswigger_vectors.append('idor_via_hidden_fields')
        
        # Choice fields with predefined values (Parameter tampering)
        choice_fields = sum(1 for field in form_analysis['non_text_fields'] 
                          if field['field_category'] == 'choice')
        if choice_fields > 0:
            score += 1
            indicators.append(f'{choice_fields}_choice_fields')
            portswigger_vectors.append('parameter_tampering')
        
        form_analysis['complexity_score'] = score
        form_analysis['vulnerability_indicators'] = indicators
        form_analysis['portswigger_vectors'] = portswigger_vectors
    
    def detect_portswigger_vectors(self, form_analysis):
        if any(field['field_category'] in ['search', 'content'] for field in form_analysis['text_input_fields']):
            form_analysis['portswigger_vectors'].append('dom_xss_potential')

        if form_analysis['method'] == 'GET' and len(form_analysis['text_input_fields']) > 1:
            form_analysis['portswigger_vectors'].append('http_parameter_pollution')
        
        if any('{{' in field.get('value', '') or '}}' in field.get('value', '') 
               for field in form_analysis['text_input_fields']):
            form_analysis['portswigger_vectors'].append('client_template_injection')
    
    async def analyze_security_headers(self):
        try:
            headers = {'User-Agent': self.user_agent}
            
            async with aiohttp.ClientSession() as session:
                async with session.head(self.url, headers=headers, proxy=self.proxies) as response:
                    security_headers = {
                        'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                        'X-Frame-Options': response.headers.get('X-Frame-Options'),
                        'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                        'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                        'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                        'Referrer-Policy': response.headers.get('Referrer-Policy'),
                        'Permissions-Policy': response.headers.get('Permissions-Policy')
                    }
                    
                    self.results['security_headers'] = security_headers
        except Exception as e:
            console.print(f"[yellow]Warning: Could not analyze security headers: {str(e)}[/yellow]")
    
    async def detect_technology_stack(self, content):
        soup = BeautifulSoup(content, 'html.parser')
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
            'other_technologies': []
        }
        
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '').lower()
            script_content = (script.string or '').lower()
            
            
            script_attrs = []
            for attr_value in script.attrs.values():
                if isinstance(attr_value, list):
                    script_attrs=extend(attr_value)
                else:
                    script_attrs.append(attr_value)
            
            script_attrs = ' '.join(str(val).lower() for val in script_attrs)
            
            # React
            if any(indicator in src or indicator in script_content or indicator in script_attrs 
                   for indicator in ['react', 'react-dom', 'react.production.min.js']):
                tech_stack['frontend_frameworks'].append('React')
            
            # Vue.js
            elif any(indicator in src or indicator in script_content 
                    for indicator in ['vue', 'vue.js', 'vue.min.js']):
                tech_stack['frontend_frameworks'].append('Vue.js')
            
            # Angular
            elif any(indicator in src or indicator in script_content or 'ng-' in script_attrs
                    for indicator in ['angular', 'angular.js', 'angular.min.js']):
                tech_stack['frontend_frameworks'].append('Angular')
            
            # jQuery
            elif any(indicator in src or indicator in script_content
                    for indicator in ['jquery', 'jquery.min.js', 'jquery-']):
                tech_stack['libraries'].append('jQuery')
            
            # Bootstrap
            elif 'bootstrap' in src:
                tech_stack['libraries'].append('Bootstrap')
            
            # Font Awesome
            elif 'font-awesome' in src or 'fontawesome' in src:
                tech_stack['libraries'].append('Font Awesome')
            
            # Google Analytics
            elif 'google-analytics' in src or 'ga.js' in src or 'gtag' in src:
                tech_stack['analytics'].append('Google Analytics')
            
            # Google Tag Manager
            elif 'gtm.js' in src or 'googletagmanager' in src:
                tech_stack['analytics'].append('Google Tag Manager')
            
            # Facebook Pixel
            elif 'facebook.net' in src and 'pixel' in src:
                tech_stack['analytics'].append('Facebook Pixel')
        
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '').lower()
            
            # Bootstrap CSS
            if 'bootstrap' in href:
                tech_stack['libraries'].append('Bootstrap')
            
            # Font Awesome CSS
            elif 'font-awesome' in href or 'fontawesome' in href:
                tech_stack['libraries'].append('Font Awesome')
            
            # Materialize CSS
            elif 'materialize' in href:
                tech_stack['libraries'].append('Materialize CSS')
            
            # Tailwind CSS
            elif 'tailwind' in href:
                tech_stack['libraries'].append('Tailwind CSS')

        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content_val = meta.get('content', '').lower()
            http_equiv = meta.get('http-equiv', '').lower()
            charset = meta.get('charset', '').lower()
            
            # Generatory CMS
            if 'generator' in name:
                if 'wordpress' in content_val:
                    tech_stack['cms'].append('WordPress')
                elif 'joomla' in content_val:
                    tech_stack['cms'].append('Joomla')
                elif 'drupal' in content_val:
                    tech_stack['cms'].append('Drupal')
                elif 'magento' in content_val:
                    tech_stack['cms'].append('Magento')
                elif 'shopify' in content_val:
                    tech_stack['cms'].append('Shopify')
                elif 'prestashop' in content_val:
                    tech_stack['cms'].append('PrestaShop')
                else:
                    tech_stack['cms'].append(content_val)
            
            # CSRF protection
            elif 'csrf-token' in name or 'csrf-token' in content_val:
                tech_stack['security_features'].append('CSRF Protection')
            
            # Viewport - mobile framework indicator
            elif name == 'viewport':
                tech_stack['other_technologies'].append('Responsive Design')
            
            # X-UA-Compatible - IE compatibility
            elif http_equiv == 'x-ua-compatible':
                tech_stack['other_technologies'].append('IE Compatibility Mode')
        
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
        for comment in comments:
            comment_text = comment.lower()
            
            # WordPress
            if 'wordpress' in comment_text:
                tech_stack['cms'].append('WordPress')
            
            # Joomla
            elif 'joomla' in comment_text:
                tech_stack['cms'].append('Joomla')
            
            # Drupal
            elif 'drupal' in comment_text:
                tech_stack['cms'].append('Drupal')
        
        forms = soup.find_all('form')
        for form in forms:
            classes = form.get('class', [])
            
            attrs_list = []
            for attr_value in form.attrs.values():
                if isinstance(attr_value, list):
                    attrs_list.extend(attr_value)
                else: 
                    attrs_list.append(attr_value)
            attrs = ' '.join(str(val).lower() for val in attrs_list)
            
            action = form.get('action', '').lower()
            id_attr = form.get('id', '').lower()
            
            # Django
            if any('django' in str(cls).lower() for cls in classes) or 'csrfmiddlewaretoken' in attrs:
                tech_stack['backend_frameworks'].append('Django')
                tech_stack['programming_languages'].append('Python')
            
            # Laravel
            elif any('laravel' in str(cls).lower() for cls in classes) or '_token' in attrs:
                tech_stack['backend_frameworks'].append('Laravel')
                tech_stack['programming_languages'].append('PHP')
            
            # Ruby on Rails
            elif 'authenticity_token' in attrs or any('rails' in str(cls).lower() for cls in classes):
                tech_stack['backend_frameworks'].append('Ruby on Rails')
                tech_stack['programming_languages'].append('Ruby')
            
            # ASP.NET
            elif '__viewstate' in attrs or '__eventvalidation' in attrs:
                tech_stack['backend_frameworks'].append('ASP.NET')
                tech_stack['programming_languages'].append('C#')
            
            # Spring
            elif any('spring' in str(cls).lower() for cls in classes):
                tech_stack['backend_frameworks'].append('Spring')
                tech_stack['programming_languages'].append('Java')
        
        divs = soup.find_all('div')
        for div in divs[:50]:  
            classes = div.get('class', [])
            id_attr = div.get('id', '').lower()
            
            # WordPress specific
            if any('wp-' in str(cls).lower() for cls in classes) or 'wp-' in id_attr:
                tech_stack['cms'].append('WordPress')
            
            # Bootstrap specific
            if any(('container' in str(cls).lower() or 'row' in str(cls).lower() or 
                    'col-' in str(cls).lower()) for cls in classes):
                tech_stack['libraries'].append('Bootstrap')
        
        if self.results.get('server'):
            server = self.results['server'].lower()
            
            # Web servers
            if 'apache' in server:
                tech_stack['web_servers'].append('Apache')
            elif 'nginx' in server:
                tech_stack['web_servers'].append('Nginx')
            elif 'iis' in server:
                tech_stack['web_servers'].append('IIS')
                tech_stack['programming_languages'].append('ASP.NET')
            elif 'litespeed' in server:
                tech_stack['web_servers'].append('LiteSpeed')
            elif 'caddy' in server:
                tech_stack['web_servers'].append('Caddy')
            
            # Backend technologies via Server header
            if 'php' in server:
                tech_stack['programming_languages'].append('PHP')
            elif 'python' in server:
                tech_stack['programming_languages'].append('Python')
            elif 'node' in server:
                tech_stack['programming_languages'].append('JavaScript (Node.js)')
            elif 'ruby' in server:
                tech_stack['programming_languages'].append('Ruby')
            elif 'java' in server:
                tech_stack['programming_languages'].append('Java')
        
        if hasattr(self, 'response_headers'):
            powered_by = self.response_headers.get('x-powered-by', '').lower()
            if 'php' in powered_by:
                tech_stack['programming_languages'].append('PHP')
            elif 'asp.net' in powered_by:
                tech_stack['backend_frameworks'].append('ASP.NET')
            elif 'express' in powered_by:
                tech_stack['backend_frameworks'].append('Express.js')
                tech_stack['programming_languages'].append('JavaScript (Node.js)')

        all_srcs = [script.get('src', '').lower() for script in scripts] + \
                   [link.get('href', '').lower() for link in soup.find_all('link')] + \
                   [img.get('src', '').lower() for img in soup.find_all('img')]
        
        for src in all_srcs:
            # Cloudflare
            if 'cloudflare' in src:
                tech_stack['cdn'].append('Cloudflare')
            # AWS CloudFront
            elif 'cloudfront' in src:
                tech_stack['cdn'].append('AWS CloudFront')
            # Google Cloud CDN
            elif 'googleapis' in src or 'gstatic' in src:
                tech_stack['cdn'].append('Google CDN')
            # Microsoft Azure CDN
            elif 'azure' in src:
                tech_stack['cdn'].append('Azure CDN')
            # jQuery CDN
            elif 'code.jquery.com' in src:
                tech_stack['cdn'].append('jQuery CDN')
            # Bootstrap CDN
            elif 'bootstrapcdn' in src:
                tech_stack['cdn'].append('Bootstrap CDN')
            # CDNJS
            elif 'cdnjs' in src:
                tech_stack['cdn'].append('CDNJS')
        
        if hasattr(self, 'response_headers'):
            cookies = self.response_headers.get('set-cookie', '')
            if 'wordpress' in cookies.lower() or 'wp-' in cookies.lower():
                tech_stack['cms'].append('WordPress')
            elif 'joomla' in cookies.lower():
                tech_stack['cms'].append('Joomla')
            elif 'drupal' in cookies.lower():
                tech_stack['cms'].append('Drupal')
            elif 'laravel' in cookies.lower() or 'laravel_session' in cookies.lower():
                tech_stack['backend_frameworks'].append('Laravel')
        
        parsed_url = urlparse(self.url)
        path = parsed_url.path.lower()
        
        if '/wp-content/' in path or '/wp-admin/' in path or '/wp-includes/' in path:
            tech_stack['cms'].append('WordPress')

        if '/media/system/' in path or '/components/com_' in path:
            tech_stack['cms'].append('Joomla')

        if '/sites/default/' in path or '/modules/' in path:
            tech_stack['cms'].append('Drupal')
        
        categories_to_remove = []
        for category in tech_stack:
            tech_stack[category] = list(set(tech_stack[category]))
            if not tech_stack[category]:
                categories_to_remove.append(category)
                
        for category in categories_to_remove:
            del tech_stack[category]
            
        
        self.results['technology_stack'] = tech_stack

    def generate_recommendations(self):
        recommendations = []
        formpoison_flags = []
        attack_vectors = []
        
        for form in self.results['forms_analysis']:
            form_id = form['form_id']
            
            if form['complexity_score'] >= 5:
                recommendations.append(f"Form {form_id}: High vulnerability potential (Score: {form['complexity_score']})")
            
            text_fields_count = len(form['text_input_fields'])
            non_text_fields_count = len(form['non_text_fields'])
            
            console.print(f"[dim]Form {form_id}: {text_fields_count} text fields, {non_text_fields_count} non-text fields[/dim]")
            
            if 'login_form_detected' in form['vulnerability_indicators']:
                recommendations.append(f"Form {form_id}: Login form detected - test authentication bypass (PortSwigger: Authentication)")
                formpoison_flags.append("--login")
                attack_vectors.append("Authentication Bypass")
            
            if any(field['field_category'] == 'file_upload' for field in form['all_fields']):
                recommendations.append(f"Form {form_id}: File upload - test for XSS in filenames (PortSwigger: File Upload XSS)")
                formpoison_flags.append("--filemode")
                attack_vectors.append("File Upload XSS")
            
            if 'get_method_used' in form['vulnerability_indicators']:
                recommendations.append(f"Form {form_id}: GET method - test for reflected XSS (PortSwigger: Reflected XSS)")
                formpoison_flags.append("--method GET")
                attack_vectors.append("Reflected XSS")
            
            if 'no_csrf_protection' in form['vulnerability_indicators']:
                recommendations.append(f"Form {form_id}: No CSRF protection - test CSRF attacks (PortSwigger: CSRF)")
                attack_vectors.append("CSRF Attack")
            
            if any('sql_injection' in field['portswigger_risks'] for field in form['text_input_fields']):
                recommendations.append(f"Form {form_id}: SQL injection potential - test with SQL payloads")
                formpoison_flags.append("-t SQL")
                attack_vectors.append("SQL Injection")
            
            if any('dom_xss_potential' in vector for vector in form['portswigger_vectors']):
                recommendations.append(f"Form {form_id}: DOM XSS potential - test mutation XSS")
                formpoison_flags.append("--mXSS")
                attack_vectors.append("DOM XSS")
            
            if any(field['field_category'] == 'choice' for field in form['non_text_fields']):
                recommendations.append(f"Form {form_id}: Choice fields detected - test parameter tampering")
                attack_vectors.append("Parameter Tampering")
        
        tech = self.results['technology_stack']
        
        # WAF Detection and Bypass Recommendations
        if any(server in tech.get('web_servers', []) for server in ['Cloudflare', 'AWS CloudFront', 'Azure CDN']):
            recommendations.append("CDN/WAF detected - use WAF bypass payloads")
            formpoison_flags.append("--waf-bypass")
            attack_vectors.append("WAF Bypass")
        
        # CSP Bypass Recommendations
        headers = self.results['security_headers']
        if headers.get('Content-Security-Policy'):
            recommendations.append("CSP detected - test CSP bypass techniques")
            formpoison_flags.append("--csp-bypass")
            attack_vectors.append("CSP Bypass")
        else:
            recommendations.append("No CSP - higher XSS success rate (PortSwigger: CSP Bypass)")
            attack_vectors.append("CSP Bypass")
        
        # Sanitizer Bypass Recommendations
        if any(framework in tech.get('frontend_frameworks', []) for framework in ['React', 'Vue.js', 'Angular']):
            recommendations.append("Modern JS framework - test for sanitizer bypass and mutation XSS")
            formpoison_flags.extend(["--sanitizer-bypass", "--mXSS"])
            attack_vectors.extend(["Sanitizer Bypass", "Mutation XSS"])
        
        # Encoder Bypass Recommendations
        if 'WordPress' in tech.get('cms', []) or any(lang in tech.get('programming_languages', []) for lang in ['PHP', 'Python']):
            recommendations.append("Common CMS/framework - test encoder bypass techniques")
            formpoison_flags.append("--encoder-bypass")
            attack_vectors.append("Encoder Bypass")
        
        # Encoding Confusion Recommendations
        if any(form['method'] == 'GET' for form in self.results['forms_analysis']):
            recommendations.append("GET forms detected - test encoding confusion and parameter pollution")
            formpoison_flags.extend(["--encoding-confusion", "--method GET"])
            attack_vectors.extend(["Encoding Confusion", "HTTP Parameter Pollution"])
        
        # Size Overflow Recommendations
        total_text_fields = sum(len(form['text_input_fields']) for form in self.results['forms_analysis'])
        if total_text_fields > 5:
            formpoison_flags.append("--brute")
            recommendations.append(f"Multiple text fields ({total_text_fields}) - use brute force for efficiency")
        
        # Size overflow for forms with many fields or large input areas
        large_forms = [f for f in self.results['forms_analysis'] if len(f['all_fields']) > 10]
        if large_forms:
            recommendations.append("Large forms detected - test size overflow attacks")
            formpoison_flags.append("--size-overflow")
            attack_vectors.append("Size Overflow")
        
        # Additional technology-specific recommendations
        if 'WordPress' in tech.get('cms', []):
            recommendations.append("WordPress detected - test WordPress-specific payloads and sanitizer bypasses")
            formpoison_flags.extend(["--sanitizer-bypass", "--encoder-bypass"])
            attack_vectors.append("WordPress XSS")
        
        if any('ASP.NET' in framework for framework in tech.get('backend_frameworks', [])):
            recommendations.append("ASP.NET detected - test ViewState and encoder bypasses")
            formpoison_flags.extend(["--encoder-bypass", "--encoding-confusion"])
            attack_vectors.append("ASP.NET Bypass")
        
        # Headers analysis for additional bypass recommendations
        if not headers.get('X-Frame-Options'):
            recommendations.append("No X-Frame-Options - clickjacking possible (PortSwigger: Clickjacking)")
            attack_vectors.append("Clickjacking")
        
        if not headers.get('Strict-Transport-Security'):
            recommendations.append("No HSTS - SSL stripping possible")
            attack_vectors.append("SSL Stripping")
        
        # Verbosity based on complexity
        high_risk_forms = sum(1 for f in self.results['forms_analysis'] if f['complexity_score'] >= 5)
        if high_risk_forms > 0 or total_text_fields > 10:
            formpoison_flags.append("--verbose-all")
            recommendations.append("High risk forms detected - use --verbose-all for detailed response analysis")
        else:
            formpoison_flags.append("--verbose")
            recommendations.append("Use --verbose for basic progress information")
        
        # Remove duplicate flags while preserving order
        seen = set()
        unique_flags = []
        for flag in formpoison_flags:
            if flag not in seen:
                seen.add(flag)
                unique_flags.append(flag)
        
        self.results['recommendations'] = recommendations
        self.results['formpoison_flags'] = unique_flags
        self.results['attack_vectors'] = list(set(attack_vectors))
    
    def visualize_form_structure(self, form_analysis):
        form_id = form_analysis['form_id']
        action = form_analysis['action'] or 'self'
        method = form_analysis['method']
        
        console.print(f"\n[bold cyan] FORM {form_id} VISUALIZATION[/bold cyan]")
        console.print(f"[bold white]Method: {method} | Action: {action}[/bold white]")
        
        form_viz = []
        
        for field in form_analysis['all_fields']:
            field_name = field['name'] or field['id'] or 'unnamed'
            field_type = field['type']
            element_type = field['element_type']
            threat_level = field['threat_level']

            if element_type == 'input':
                if field_type == 'text':
                    icon = "📝"
                elif field_type == 'password':
                    icon = "🔒"
                elif field_type == 'email':
                    icon = "📧"
                elif field_type == 'file':
                    icon = "📁"
                elif field_type == 'hidden':
                    icon = "👻"
                elif field_type in ['checkbox', 'radio']:
                    icon = "☑️"
                elif field_type == 'submit':
                    icon = "🚀"
                else:
                    icon = "⚙️"
            elif element_type == 'textarea':
                icon = "📄"
            elif element_type == 'select':
                icon = "🔽"
            elif element_type == 'button':
                icon = "🔘"
            else:
                icon = "❓"

            threat_color = {
                'high': 'red',
                'medium': 'yellow', 
                'low': 'green'
            }[threat_level]

            threats = []
            if field['portswigger_risks']:
                threats.extend(field['portswigger_risks'])
            if field['suspicious_patterns']:
                threats.extend(field['suspicious_patterns'])
            
            threats_text = ", ".join(threats) if threats else "No specific threats"
            line = f"{icon} [bold white]{field_name}[/bold white] ([dim]{field_type}[/dim])"
            line += f" - Threat: [bold {threat_color}]{threat_level.upper()}[/bold {threat_color}]"
            line += f" - {threats_text}"
            
            form_viz.append(line)
        
        for line in form_viz:
            console.print(f"  {line}")
        
        high_threats = sum(1 for field in form_analysis['all_fields'] if field['threat_level'] == 'high')
        medium_threats = sum(1 for field in form_analysis['all_fields'] if field['threat_level'] == 'medium')
        
        if high_threats > 0 or medium_threats > 0:
            console.print(f"\n[bold red]⚠️  FORM {form_id} THREAT SUMMARY:[/bold red]")
            console.print(f"  [red]• High threats: {high_threats}[/red]")
            console.print(f"  [yellow]• Medium threats: {medium_threats}[/yellow]")
            
            if form_analysis['portswigger_vectors']:
                console.print(f"  [cyan]• Attack vectors: {', '.join(form_analysis['portswigger_vectors'])}[/cyan]")
    
    def display_report(self):
        console.print(Panel.fit("📊 [bold green]FormAtion Analysis Report[/bold green]", border_style="green"))
        
        total_text_fields = sum(len(form['text_input_fields']) for form in self.results['forms_analysis'])
        total_non_text_fields = sum(len(form['non_text_fields']) for form in self.results['forms_analysis'])
        
        summary_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        summary_table.add_column("Metric", style="cyan", width=20)
        summary_table.add_column("Value", style="white", width=15)
        
        summary_table.add_row("URL", self.results['url'])
        summary_table.add_row("Forms Found", str(len(self.results['forms_analysis'])))
        summary_table.add_row("Text Input Fields", str(total_text_fields))
        summary_table.add_row("Non-Text Fields", str(total_non_text_fields))
        summary_table.add_row("Response Code", str(self.results.get('response_code', 'N/A')))
        summary_table.add_row("High Risk Forms", 
                             str(sum(1 for f in self.results['forms_analysis'] if f['complexity_score'] >= 5)))
        summary_table.add_row("Server", self.results.get('server', 'N/A'))
        
        console.print(summary_table)
        
        for form in self.results['forms_analysis']:
            if form['text_input_fields']:
                form_table = Table(
                    title=f"📝 Form {form['form_id']} - TEXT INPUT FIELDS ({form['method']} {form['action'] or 'self'})",
                    show_header=True, 
                    header_style="bold yellow",
                    box=box.ROUNDED
                )
                form_table.add_column("Field Name", style="cyan", width=20)
                form_table.add_column("Type", style="white", width=12)
                form_table.add_column("Category", style="green", width=15)
                form_table.add_column("Risk Indicators", style="red", width=25)
                form_table.add_column("PortSwigger Risks", style="magenta", width=25)
                
                for field in form['text_input_fields']:
                    risk_indicators = ", ".join(field['suspicious_patterns'])
                    portswigger_risks = ", ".join(field['portswigger_risks'])
                    
                    form_table.add_row(
                        field['name'] or field['id'] or 'N/A',
                        field['type'],
                        field['field_category'],
                        risk_indicators if risk_indicators else "None",
                        portswigger_risks if portswigger_risks else "None"
                    )
                
                console.print(form_table)
            
            if form['non_text_fields']:
                non_text_table = Table(
                    title=f"Form {form['form_id']} - NON-TEXT FIELDS",
                    show_header=True, 
                    header_style="bold blue",
                    box=box.ROUNDED
                )
                non_text_table.add_column("Field Name", style="cyan", width=20)
                non_text_table.add_column("Element", style="white", width=12)
                non_text_table.add_column("Type", style="green", width=15)
                non_text_table.add_column("Category", style="yellow", width=15)
                
                for field in form['non_text_fields']:
                    non_text_table.add_row(
                        field['name'] or field['id'] or 'N/A',
                        field['element_type'],
                        field['type'],
                        field['field_category']
                    )
                
                console.print(non_text_table)

            risk_level = "High" if form['complexity_score'] >= 5 else "Medium" if form['complexity_score'] >= 3 else "Low"
            risk_color = 'red' if risk_level == 'High' else 'yellow' if risk_level == 'Medium' else 'green'
            
            console.print(f"🔒 [bold {risk_color}]Form Risk Level: {risk_level} (Score: {form['complexity_score']})[/]")
            
            if form['portswigger_vectors']:
                vectors_text = ", ".join(form['portswigger_vectors'])
                console.print(f" [bold cyan]PortSwigger Vectors:[/bold cyan] {vectors_text}")
        
        console.print(Panel.fit(" [bold cyan]FORM VISUALIZATION WITH THREATS[/bold cyan]", border_style="cyan"))
        for form in self.results['forms_analysis']:
            self.visualize_form_structure(form)
        
        if self.results['technology_stack']:
            console.print(Panel.fit("🔧 [bold blue]Technology Stack Analysis[/bold blue]", border_style="blue"))
            
            for category, technologies in self.results['technology_stack'].items():
                if technologies:
                    tech_table = Table(title=f"{category.replace('_', ' ').title()}", 
                                     show_header=True, header_style="bold cyan", box=box.ROUNDED)
                    tech_table.add_column("Technology", style="white")
                    tech_table.add_column("Confidence", style="green")
                    
                    for tech in technologies:
                        confidence = "High" if any(source in category for source in ['backend', 'cms', 'server']) else "Medium"
                        tech_table.add_row(tech, confidence)
                    
                    console.print(tech_table)
        
        if self.results['formpoison_flags']:
            command = f"python formpoison.py {self.url} {' '.join(self.results['formpoison_flags'])}"
            console.print(Panel.fit(
                f"🎯 [bold cyan]Recommended FormPoison Command[/bold cyan]\n\n[bold white]{command}[/bold white]",
                border_style="cyan",
                box=box.DOUBLE
            ))
        
        if self.results['recommendations']:
            console.print("\n[bold yellow]📝 PortSwigger-Based Recommendations:[/bold yellow]")
            for rec in self.results['recommendations']:
                console.print(f"  • {rec}")
        
        if self.results['attack_vectors']:
            console.print("\n[bold red]⚡ Identified Attack Vectors:[/bold red]")
            for vector in self.results['attack_vectors']:
                console.print(f"  • {vector}")
        
        sec_table = Table(title="Security Headers Analysis", show_header=True, header_style="bold red", box=box.ROUNDED)
        sec_table.add_column("Header", style="cyan", width=25)
        sec_table.add_column("Status", style="white", width=15)
        sec_table.add_column("Risk", style="red", width=20)
        
        headers = self.results['security_headers']
        security_headers_info = {
            'Content-Security-Policy': ('High', 'XSS Protection'),
            'X-Frame-Options': ('Medium', 'Clickjacking Protection'),
            'Strict-Transport-Security': ('High', 'SSL Enforcement'),
            'X-XSS-Protection': ('Medium', 'XSS Filter'),
            'X-Content-Type-Options': ('Low', 'MIME Sniffing'),
            'Referrer-Policy': ('Low', 'Referrer Control'),
            'Permissions-Policy': ('Medium', 'Feature Control')
        }
        
        for header, value in headers.items():
            status = "✅ Present" if value else "❌ Missing"
            risk_level, description = security_headers_info.get(header, ('Unknown', ''))
            sec_table.add_row(header, status, f"{risk_level} - {description}")
        
        console.print(sec_table)

async def main():
    parser = argparse.ArgumentParser(description="FormAtion - Advanced Web Form Analyzer")
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--output", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    banner_text = Text()
    banner_text.append("╔═══════════════════════════════════════╗\n", style="cyan")
    banner_text.append("║            ", style="cyan")
    banner_text.append("FormAtion", style="bold cyan")
    banner_text.append(" v1.0             ║\n", style="cyan")
    banner_text.append("║    ", style="cyan")
    banner_text.append("Advanced Web Form Analyzer", style="bold yellow")
    banner_text.append("         ║\n", style="cyan")
    banner_text.append("║      ", style="cyan")
    banner_text.append("Pre-scout for FormPoison", style="bold white")
    banner_text.append("         ║\n", style="cyan")
    banner_text.append("║       ", style="cyan")
    banner_text.append("PortSwigger Methodology", style="bold red")
    banner_text.append("         ║\n", style="cyan")
    banner_text.append("╚═══════════════════════════════════════╝", style="cyan")
    
    console.print(Panel.fit(banner_text, border_style="cyan"))
    
    analyzer = FormAtionAnalyzer(args.url, args.user_agent, args.proxy)
    results = await analyzer.analyze_site()
   
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[bold green]Results saved to: {args.output}[/bold green]")

if __name__ == "__main__":
    asyncio.run(main())
