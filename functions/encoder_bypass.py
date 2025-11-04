import base64
import urllib.parse
import random

class EncoderBypass:
    def __init__(self):
        self.encoding_schemes = [
            "base64",
            "url_encode",
            "html_entities",
            "unicode_escape",
            "hex_encoding",
            "multiple_encoding"
        ]
    
    def base64_encode(self, payload):
        variations = [
            base64.b64encode(payload.encode()).decode(),
            base64.b64encode(payload.encode()).decode().replace('=', ''),
            base64.urlsafe_b64encode(payload.encode()).decode()
        ]
        return random.choice(variations)
    
    def url_encode_variations(self, payload):
        variations = [
            urllib.parse.quote(payload),
            urllib.parse.quote_plus(payload),
            ''.join(f'%{ord(c):02x}' for c in payload),
            payload.replace(' ', '%20').replace('<', '%3C').replace('>', '%3E')
        ]
        return random.choice(variations)
    
    def html_entity_variations(self, payload):
        entity_map = {
            '<': ['&lt;', '&#60;', '&#x3c;'],
            '>': ['&gt;', '&#62;', '&#x3e;'],
            '"': ['&quot;', '&#34;', '&#x22;'],
            "'": ['&#39;', '&#x27;'],
            '&': ['&amp;', '&#38;', '&#x26;']
        }
        
        result = payload
        for char, replacements in entity_map.items():
            if char in result:
                result = result.replace(char, random.choice(replacements))
        return result
    
    def unicode_escape_variations(self, payload):
        variations = [
            ''.join(f'\\u{ord(c):04x}' for c in payload),
            ''.join(f'\\x{ord(c):02x}' for c in payload),
            payload.encode('unicode_escape').decode()
        ]
        return random.choice(variations)
    
    def hex_encoding(self, payload):
        hex_encoded = payload.encode().hex()
        variations = [
            hex_encoded,
            '0x' + hex_encoded,
            '\\x' + '\\x'.join(payload.encode().hex()[i:i+2] for i in range(0, len(hex_encoded), 2))
        ]
        return random.choice(variations)
    
    def multiple_encoding(self, payload, layers=3):
        encoders = [
            self.base64_encode,
            self.url_encode_variations,
            self.html_entity_variations,
            self.unicode_escape_variations
        ]
        
        current = payload
        for _ in range(layers):
            encoder = random.choice(encoders)
            current = encoder(current)
        
        return current
    
    def generate_encoding_confusion(self, payload, count=10):
        confused = set()
        
        while len(confused) < count:
            # Mix different encoding schemes
            schemes = random.sample(self.encoding_schemes, random.randint(2, 4))
            
            current = payload
            for scheme in schemes:
                if scheme == "base64":
                    current = self.base64_encode(current)
                elif scheme == "url_encode":
                    current = self.url_encode_variations(current)
                elif scheme == "html_entities":
                    current = self.html_entity_variations(current)
                elif scheme == "unicode_escape":
                    current = self.unicode_escape_variations(current)
                elif scheme == "hex_encoding":
                    current = self.hex_encoding(current)
                elif scheme == "multiple_encoding":
                    current = self.multiple_encoding(current)
            
            confused.add(current)
        
        return list(confused)[:count]

encoder_bypass = EncoderBypass()
