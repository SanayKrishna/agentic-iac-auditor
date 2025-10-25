#!/usr/bin/env python3
"""
Standalone test to verify the scanner works
Run: python test_scanner.py
"""

import re

WEAK_TLS_POLICIES = [
    "TLS-1-0",
    "TLS-1-1", 
    "SSL-3.0",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
    "ELBSecurityPolicy-2015-05",
    "ELBSecurityPolicy-2016-08",
]

# Your exact file content
tf_code = '''resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.my_lb.arn
  port              = 443
  protocol          = "HTTPS"

  ssl_policy = "ELBSecurityPolicy-2015-05"  # ❌ Outdated, weak TLS version
  certificate_arn = aws_acm_certificate.my_cert.arn
}'''

print("="*70)
print("TESTING TERRAFORM SCANNER")
print("="*70)

print("\n📄 Input Terraform code:")
print("-"*70)
print(tf_code)
print("-"*70)

print("\n🔍 Running scan...")

# The exact regex from the scanner
lb_pattern = r'resource\s+"aws_lb_listener"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'

matches = list(re.finditer(lb_pattern, tf_code, re.DOTALL))
print(f"\n📊 Found {len(matches)} aws_lb_listener resource(s)")

for idx, match in enumerate(matches, 1):
    listener_name = match.group(1)
    listener_block = match.group(2)
    
    print(f"\n✅ Match #{idx}:")
    print(f"   Listener name: {listener_name}")
    print(f"   Block content length: {len(listener_block)} chars")
    
    # Extract ssl_policy
    ssl_match = re.search(r'ssl_policy\s*=\s*"([^"]+)"', listener_block)
    
    if ssl_match:
        ssl_policy = ssl_match.group(1)
        print(f"   ✅ SSL Policy found: {ssl_policy}")
        
        if ssl_policy in WEAK_TLS_POLICIES:
            print(f"   🚨 WEAK POLICY DETECTED!")
            print(f"\n   Issue:")
            print(f"   ❌ Load Balancer Listener '{listener_name}' uses weak TLS/SSL policy: {ssl_policy}")
        else:
            print(f"   ✅ Policy is not in weak list")
    else:
        print(f"   ❌ No ssl_policy found")

print("\n" + "="*70)
print("TEST COMPLETE")
print("="*70)