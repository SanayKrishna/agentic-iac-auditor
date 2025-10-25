#!/usr/bin/env python3
"""
Standalone test script to debug HCL2 parsing issues
Run this directly: python debug_test.py
"""

import hcl2
import json

# Your weak_tls.tf content
tf_code = '''resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.my_lb.arn
  port              = 443
  protocol          = "HTTPS"

  ssl_policy = "ELBSecurityPolicy-2015-05"  # ❌ Outdated, weak TLS version
  certificate_arn = aws_acm_certificate.my_cert.arn
}'''

print("=" * 60)
print("TESTING HCL2 PARSING")
print("=" * 60)

try:
    parsed = hcl2.loads(tf_code)
    print("\n✅ Parsing successful!")
    print("\n📦 Full parsed structure:")
    print(json.dumps(parsed, indent=2, default=str))
    
    print("\n" + "=" * 60)
    print("ANALYZING STRUCTURE")
    print("=" * 60)
    
    # Check if resources exist
    resources = parsed.get("resource", [])
    print(f"\n📊 Number of resource blocks: {len(resources)}")
    
    for idx, resource in enumerate(resources):
        print(f"\n🔍 Resource Block {idx}:")
        for r_type, r_blocks in resource.items():
            print(f"   Type: {r_type}")
            for r_name, r_attrs in r_blocks.items():
                print(f"   Name: {r_name}")
                print(f"   Attributes: {list(r_attrs.keys())}")
                
                # Check SSL policy specifically
                if "ssl_policy" in r_attrs:
                    ssl_policy = r_attrs["ssl_policy"]
                    print(f"   ✅ ssl_policy found: {ssl_policy}")
                    print(f"   Type: {type(ssl_policy)}")
                    
                    # Check if it's in weak list
                    WEAK_TLS_POLICIES = [
                        "TLS-1-0",
                        "TLS-1-1",
                        "SSL-3.0",
                        "ELBSecurityPolicy-TLS-1-0-2015-04",
                        "ELBSecurityPolicy-2015-05",
                        "ELBSecurityPolicy-2016-08",
                    ]
                    
                    # Handle list or string
                    policy_value = ssl_policy[0] if isinstance(ssl_policy, list) else ssl_policy
                    
                    if policy_value in WEAK_TLS_POLICIES:
                        print(f"   🚨 MATCH! '{policy_value}' is in weak policies list")
                    else:
                        print(f"   ❌ NO MATCH: '{policy_value}' not in weak policies")
                        print(f"   Weak policies list: {WEAK_TLS_POLICIES}")
                else:
                    print(f"   ❌ ssl_policy NOT found in attributes")
                    
except Exception as e:
    print(f"\n❌ Parsing failed: {str(e)}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("TEST COMPLETE")
print("=" * 60)