# src/scanner.py
import hcl2
import re

WEAK_TLS_POLICIES = [
    "TLS-1-0",
    "TLS-1-1", 
    "SSL-3.0",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
    "ELBSecurityPolicy-2015-05",
    "ELBSecurityPolicy-2016-08",
]

def extract_value(data, key, default=""):
    """
    Safely extract values from HCL2 parsed data.
    Handles both list and direct values.
    """
    value = data.get(key, default)
    
    # If it's a list, return the first element
    if isinstance(value, list):
        return value[0] if len(value) > 0 else default
    
    return value if value else default


def scan_with_regex(tf_code):
    """
    Fallback regex-based scanning for when HCL2 parsing has issues.
    """
    results = []
    
    # Pattern for aws_lb_listener with ssl_policy
    lb_pattern = r'resource\s+"aws_lb_listener"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    
    for match in re.finditer(lb_pattern, tf_code, re.DOTALL):
        listener_name = match.group(1)
        listener_block = match.group(2)
        
        # Extract ssl_policy value
        ssl_match = re.search(r'ssl_policy\s*=\s*"([^"]+)"', listener_block)
        if ssl_match:
            ssl_policy = ssl_match.group(1)
            if ssl_policy in WEAK_TLS_POLICIES:
                results.append(
                    f"❌ **Critical**: Load Balancer Listener `{listener_name}` uses weak TLS/SSL policy `{ssl_policy}`.\n"
                    f"   **Recommendation**: Upgrade to `ELBSecurityPolicy-TLS13-1-2-2021-06` or `ELBSecurityPolicy-TLS-1-2-2017-01`."
                )
    
    # Pattern for S3 buckets with public ACL
    s3_pattern = r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{([^}]*)\}'
    for match in re.finditer(s3_pattern, tf_code, re.DOTALL):
        bucket_name = match.group(1)
        bucket_block = match.group(2)
        
        acl_match = re.search(r'acl\s*=\s*"([^"]+)"', bucket_block)
        if acl_match:
            acl = acl_match.group(1)
            if acl in ["public-read", "public-read-write", "website"]:
                results.append(
                    f"❌ **Critical**: S3 bucket `{bucket_name}` is publicly accessible (acl={acl}).\n"
                    f"   **Recommendation**: Change ACL to 'private' and use bucket policies."
                )
        
        # Check for encryption
        if "server_side_encryption_configuration" not in bucket_block:
            results.append(
                f"⚠️ **Warning**: S3 bucket `{bucket_name}` has no server-side encryption.\n"
                f"   **Recommendation**: Enable SSE with AES256 or KMS."
            )
    
    # Pattern for security groups with 0.0.0.0/0
    sg_pattern = r'resource\s+"aws_security_group"\s+"([^"]+)"\s*\{(.*?)\}'
    for match in re.finditer(sg_pattern, tf_code, re.DOTALL):
        sg_name = match.group(1)
        sg_block = match.group(2)
        
        if "0.0.0.0/0" in sg_block:
            results.append(
                f"❌ **Critical**: Security Group `{sg_name}` allows ingress from 0.0.0.0/0.\n"
                f"   **Recommendation**: Restrict to specific IP ranges."
            )
    
    return results


def scan_with_hcl2(tf_code):
    """
    Primary scanning method using HCL2 parser.
    """
    results = []
    
    try:
        tf_dict = hcl2.loads(tf_code)
    except Exception as e:
        return [f"⚠️ HCL2 parsing failed: {str(e)}. Using regex fallback..."]
    
    resources = tf_dict.get("resource", [])
    
    if not resources:
        return []
    
    for resource in resources:
        for r_type, r_blocks in resource.items():
            for r_name, r_attrs in r_blocks.items():
                
                # S3 Bucket checks
                if r_type == "aws_s3_bucket":
                    acl = extract_value(r_attrs, "acl", "")
                    
                    if acl in ["public-read", "public-read-write", "website"]:
                        results.append(
                            f"❌ **Critical**: S3 bucket `{r_name}` is publicly accessible (acl={acl}).\n"
                            f"   **Recommendation**: Change ACL to 'private' and use bucket policies."
                        )
                    
                    if "server_side_encryption_configuration" not in r_attrs:
                        results.append(
                            f"⚠️ **Warning**: S3 bucket `{r_name}` has no server-side encryption.\n"
                            f"   **Recommendation**: Enable SSE with AES256 or KMS."
                        )
                
                # Security Group checks
                elif r_type == "aws_security_group":
                    ingress_list = r_attrs.get("ingress", [])
                    if not isinstance(ingress_list, list):
                        ingress_list = [ingress_list]
                    
                    for ingress in ingress_list:
                        if not isinstance(ingress, dict):
                            continue
                        
                        cidrs = ingress.get("cidr_blocks", [])
                        if not isinstance(cidrs, list):
                            cidrs = [cidrs]
                        
                        for cidr in cidrs:
                            if cidr == "0.0.0.0/0":
                                from_port = ingress.get("from_port", "unknown")
                                to_port = ingress.get("to_port", "unknown")
                                results.append(
                                    f"❌ **Critical**: Security Group `{r_name}` allows ingress from 0.0.0.0/0 "
                                    f"on ports {from_port}-{to_port}.\n"
                                    f"   **Recommendation**: Restrict to specific IP ranges."
                                )
                
                # Load Balancer Listener checks
                elif r_type == "aws_lb_listener":
                    ssl_policy = extract_value(r_attrs, "ssl_policy", "")
                    protocol = extract_value(r_attrs, "protocol", "")
                    port = extract_value(r_attrs, "port", "")
                    
                    if protocol in ["HTTPS", "TLS"] and ssl_policy:
                        if ssl_policy in WEAK_TLS_POLICIES:
                            results.append(
                                f"❌ **Critical**: Load Balancer Listener `{r_name}` uses weak TLS/SSL policy `{ssl_policy}` "
                                f"on port {port}.\n"
                                f"   **Recommendation**: Upgrade to `ELBSecurityPolicy-TLS13-1-2-2021-06` or "
                                f"`ELBSecurityPolicy-TLS-1-2-2017-01`."
                            )
    
    return results


def scan_terraform_code(tf_code: str):
    """
    Main scanning function. Uses HCL2 parser first, then regex fallback.
    """
    # Try HCL2 parsing first
    results = scan_with_hcl2(tf_code)
    
    # If HCL2 found issues, return them
    if results and not any("parsing failed" in r.lower() for r in results):
        if not results:
            return ["✅ **No security issues detected!** Your Terraform configuration follows security best practices."]
        return results
    
    # Fallback to regex parsing
    regex_results = scan_with_regex(tf_code)
    
    if regex_results:
        return regex_results
    
    # If both methods found nothing
    return ["✅ **No security issues detected!** Your Terraform configuration follows security best practices."]