import random
import string

class SizeOverflow:
    def __init__(self):
        self.overflow_patterns = [
            "long_string",
            "repeated_pattern", 
            "nested_structure",
            "memory_exhaustion",
            "boundary_overflow"
        ]
    
    def generate_long_string(self, base_payload, multiplier=1000):
        padding = ''.join(random.choices(string.ascii_letters + string.digits, k=multiplier * 1000))
        
        patterns = [
            # Prefix overflow
            padding + base_payload,
            # Suffix overflow  
            base_payload + padding,
            # Surround overflow
            padding + base_payload + padding,
            # Interleaved overflow
            base_payload.join([padding] * 10)
        ]
        
        return random.choice(patterns)
    
    def repeated_pattern_overflow(self, base_payload, repeat_count=10000):
        patterns = [
            base_payload * repeat_count,
            (base_payload + "A" * 100) * (repeat_count // 100),
            ''.join(base_payload * i for i in range(1, repeat_count // 100))
        ]
        
        return random.choice(patterns)
    
    def nested_structure_overflow(self, base_payload, depth=100):
        opener = random.choice(['<', '{', '[', '('])
        closer = {'<': '>', '{': '}', '[': ']', '(': ')'}[opener]
        
        nested = opener * depth + base_payload + closer * depth
        
        variations = [
            nested,
            # mix nesting
            '<div>' * depth + base_payload + '</div>' * depth,
            # JSON nesting
            '{"a":' * depth + f'"{base_payload}"' + '}' * depth
        ]
        
        return random.choice(variations)
    
    def memory_exhaustion_vectors(self, base_payload):
        memory_hogs = [
            # Array-like structures
            'A' * (10 * 1024 * 1024) + base_payload,  # 10MB string
            # Many small elements
            ' '.join([base_payload] * 100000),
            # Large numbers
            '9' * 1000000 + base_payload,
            # XML bomb style
            f'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "{base_payload}">]><lolz>&lol;</lolz>'
        ]
        
        return random.choice(memory_hogs)
    #out of bounds ! 
    def boundary_overflow(self, base_payload, boundary_sizes=[255, 1023, 4095, 8191]):
        boundary = random.choice(boundary_sizes)
        padding_size = boundary - len(base_payload) + random.randint(1, 100)
        
        if padding_size > 0:
            padding = 'A' * padding_size
            patterns = [
                padding + base_payload,
                base_payload + padding,
                padding[:len(padding)//2] + base_payload + padding[len(padding)//2:]
            ]
            return random.choice(patterns)
        
        return base_payload
    
    def generate_overflow_payloads(self, base_payload, count=8):
        overflow_payloads = set()
        
        techniques = [
            lambda: self.generate_long_string(base_payload, random.randint(10, 100)),
            lambda: self.repeated_pattern_overflow(base_payload, random.randint(1000, 10000)),
            lambda: self.nested_structure_overflow(base_payload, random.randint(50, 500)),
            lambda: self.memory_exhaustion_vectors(base_payload),
            lambda: self.boundary_overflow(base_payload)
        ]
        
        while len(overflow_payloads) < count:
            technique = random.choice(techniques)
            overflow_payloads.add(technique())
        
        return list(overflow_payloads)[:count]

size_overflow = SizeOverflow()
