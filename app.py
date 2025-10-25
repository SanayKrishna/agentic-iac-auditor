# src/app.py
import gradio as gr
import re
import datetime

# Inline scanner
WEAK_TLS_POLICIES = [
    "TLS-1-0",
    "TLS-1-1", 
    "SSL-3.0",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
    "ELBSecurityPolicy-2015-05",
    "ELBSecurityPolicy-2016-08",
]

def scan_terraform_file(tf_code):
    """Direct regex-based scanner with detailed findings"""
    results = []
    
    if not tf_code or len(tf_code.strip()) == 0:
        return ["❌ File is empty or couldn't be read"]
    
    # Check for Load Balancer Listener with weak SSL
    lb_pattern = r'resource\s+"aws_lb_listener"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    
    for match in re.finditer(lb_pattern, tf_code, re.DOTALL):
        listener_name = match.group(1)
        listener_block = match.group(2)
        
        ssl_match = re.search(r'ssl_policy\s*=\s*"([^"]+)"', listener_block)
        if ssl_match:
            ssl_policy = ssl_match.group(1)
            
            if ssl_policy in WEAK_TLS_POLICIES:
                results.append({
                    "severity": "critical",
                    "category": "Encryption & TLS",
                    "resource_type": "AWS Load Balancer Listener",
                    "resource_name": listener_name,
                    "title": f"Weak TLS/SSL Policy Detected: {ssl_policy}",
                    "description": f"The load balancer listener `{listener_name}` is configured with an outdated TLS/SSL policy `{ssl_policy}`. This policy supports deprecated encryption protocols that are vulnerable to various attacks including POODLE, BEAST, and downgrade attacks.",
                    "impact": "**High Impact**: Attackers can exploit weak encryption to intercept and decrypt sensitive data transmitted through your load balancer. This affects all traffic passing through the listener including customer data, API requests, and authentication credentials.",
                    "attack_vectors": [
                        "Man-in-the-Middle (MITM) attacks exploiting weak ciphers",
                        "Protocol downgrade attacks forcing older TLS versions",
                        "POODLE and BEAST attacks on SSL 3.0 and TLS 1.0",
                        "Traffic decryption using compromised cipher suites"
                    ],
                    "affected_compliance": ["PCI DSS 3.2.1", "HIPAA", "SOC 2", "GDPR"],
                    "remediation": {
                        "immediate": "Update the SSL policy to a modern version immediately",
                        "recommended_policies": [
                            "ELBSecurityPolicy-TLS13-1-2-2021-06 (Best - TLS 1.3)",
                            "ELBSecurityPolicy-TLS-1-2-2017-01 (Good - TLS 1.2+)"
                        ],
                        "code_fix": f'''resource "aws_lb_listener" "{listener_name}" {{
  # ... other configuration ...
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}}''',
                        "additional_steps": [
                            "Test the new policy in a staging environment first",
                            "Monitor application logs for SSL handshake errors",
                            "Update client applications if they don't support TLS 1.2+",
                            "Document the change in your security changelog"
                        ]
                    },
                    "references": [
                        "AWS ELB Security Policies: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
                        "NIST TLS Guidelines: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf"
                    ]
                })
    
    # Check for S3 buckets
    s3_pattern = r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{([^}]*)\}'
    
    for match in re.finditer(s3_pattern, tf_code, re.DOTALL):
        bucket_name = match.group(1)
        bucket_block = match.group(2)
        
        acl_match = re.search(r'acl\s*=\s*"([^"]+)"', bucket_block)
        if acl_match:
            acl = acl_match.group(1)
            if acl in ["public-read", "public-read-write", "website"]:
                results.append({
                    "severity": "critical",
                    "category": "Data Exposure",
                    "resource_type": "AWS S3 Bucket",
                    "resource_name": bucket_name,
                    "title": f"Publicly Accessible S3 Bucket (ACL: {acl})",
                    "description": f"The S3 bucket `{bucket_name}` is configured with a public ACL setting `{acl}`, making all objects potentially accessible to anyone on the internet without authentication.",
                    "impact": "**Critical Impact**: All data stored in this bucket can be accessed, listed, and potentially downloaded by unauthorized parties. This includes sensitive files, backups, user data, and configuration files. Public write access (`public-read-write`) additionally allows attackers to upload malicious content or consume your storage quota.",
                    "attack_vectors": [
                        "Unauthorized data exfiltration and download",
                        "Enumeration of bucket contents and file structure",
                        "Malicious file uploads (if write access enabled)",
                        "Storage quota exhaustion attacks",
                        "Hosting malware or phishing content on your infrastructure"
                    ],
                    "affected_compliance": ["PCI DSS", "HIPAA", "SOC 2", "GDPR", "CCPA"],
                    "remediation": {
                        "immediate": "Block all public access immediately using AWS Console or CLI",
                        "recommended_configuration": "Use private ACLs with bucket policies for controlled access",
                        "code_fix": f'''resource "aws_s3_bucket" "{bucket_name}" {{
  # Remove public ACL
  acl = "private"
}}

resource "aws_s3_bucket_public_access_block" "{bucket_name}_block" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',
                        "additional_steps": [
                            "Audit current bucket contents for sensitive data",
                            "Review CloudTrail logs for unauthorized access attempts",
                            "Implement least-privilege IAM policies for bucket access",
                            "Enable S3 access logging for monitoring",
                            "Consider using VPC endpoints for private access"
                        ]
                    },
                    "references": [
                        "AWS S3 Security Best Practices: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
                        "Blocking Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                    ]
                })
        
        if "server_side_encryption_configuration" not in bucket_block:
            results.append({
                "severity": "high",
                "category": "Encryption at Rest",
                "resource_type": "AWS S3 Bucket",
                "resource_name": bucket_name,
                "title": "Missing Server-Side Encryption",
                "description": f"The S3 bucket `{bucket_name}` does not have server-side encryption configured. All data stored in this bucket is unencrypted at rest, making it vulnerable if physical storage media is compromised or AWS infrastructure is breached.",
                "impact": "**High Impact**: Data stored without encryption can be read if storage devices are physically accessed, improperly decommissioned, or if there's unauthorized access to AWS backend systems. This violates many compliance requirements and increases liability in case of a breach.",
                "attack_vectors": [
                    "Physical theft of storage media",
                    "Unauthorized AWS employee access",
                    "Data exposure during hardware decommissioning",
                    "Snapshots and backups containing unencrypted data"
                ],
                "affected_compliance": ["PCI DSS", "HIPAA", "SOC 2", "GDPR", "ISO 27001"],
                "remediation": {
                    "immediate": "Enable default encryption on the bucket",
                    "recommended_configuration": "Use AES-256 (SSE-S3) or AWS KMS (SSE-KMS) encryption",
                    "code_fix": f'''resource "aws_s3_bucket" "{bucket_name}" {{
  # ... other configuration ...
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm     = "aws:kms"  # or "AES256" for SSE-S3
      kms_master_key_id = aws_kms_key.my_key.arn  # optional, for KMS
    }}
    bucket_key_enabled = true  # Reduces KMS costs
  }}
}}''',
                    "additional_steps": [
                        "Enable bucket versioning for additional data protection",
                        "Use KMS for enhanced key management and audit trails",
                        "Enable CloudTrail to monitor encryption-related events",
                        "Update bucket policies to require encrypted uploads",
                        "Rotate KMS keys periodically if using SSE-KMS"
                    ]
                },
                "references": [
                    "S3 Encryption Guide: https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",
                    "AWS KMS Best Practices: https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html"
                ]
            })
    
    # Check for security groups
    sg_pattern = r'resource\s+"aws_security_group"\s+"([^"]+)"\s*\{((?:[^{}]|\{[^}]*\})*)\}'
    
    for match in re.finditer(sg_pattern, tf_code, re.DOTALL):
        sg_name = match.group(1)
        sg_block = match.group(2)
        
        ingress_pattern = r'ingress\s*\{([^}]*)\}'
        for ing_match in re.finditer(ingress_pattern, sg_block):
            ingress_block = ing_match.group(1)
            
            if "0.0.0.0/0" in ingress_block:
                port_match = re.search(r'from_port\s*=\s*(\d+)', ingress_block)
                to_port_match = re.search(r'to_port\s*=\s*(\d+)', ingress_block)
                protocol_match = re.search(r'protocol\s*=\s*"([^"]+)"', ingress_block)
                
                port = port_match.group(1) if port_match else "unknown"
                to_port = to_port_match.group(1) if to_port_match else port
                protocol = protocol_match.group(1) if protocol_match else "tcp"
                
                port_desc = port if port == to_port else f"{port}-{to_port}"
                
                # Determine severity based on port
                common_dangerous_ports = {
                    "22": "SSH - Remote shell access",
                    "3389": "RDP - Windows remote desktop",
                    "3306": "MySQL database",
                    "5432": "PostgreSQL database",
                    "6379": "Redis cache",
                    "27017": "MongoDB database",
                    "1433": "MSSQL database"
                }
                
                port_info = common_dangerous_ports.get(port, f"Service on port {port}")
                
                results.append({
                    "severity": "critical",
                    "category": "Network Security",
                    "resource_type": "AWS Security Group",
                    "resource_name": sg_name,
                    "title": f"Unrestricted Internet Access on Port {port_desc} ({protocol.upper()})",
                    "description": f"The security group `{sg_name}` allows ingress traffic from 0.0.0.0/0 (the entire internet) on port {port_desc} using {protocol.upper()} protocol. This exposes {port_info} to potential attacks from any source on the internet.",
                    "impact": f"**Critical Impact**: Any instance attached to this security group is directly accessible from the internet on port {port_desc}. Attackers can attempt brute-force attacks, exploit vulnerabilities, or perform reconnaissance without any network-level restrictions.",
                    "attack_vectors": [
                        f"Brute-force authentication attempts on port {port}",
                        "Exploitation of application vulnerabilities",
                        "DDoS attacks targeting exposed services",
                        "Port scanning and service fingerprinting",
                        "Zero-day exploit attempts"
                    ],
                    "affected_compliance": ["CIS AWS Foundations", "PCI DSS", "SOC 2", "NIST"],
                    "remediation": {
                        "immediate": "Restrict source IP ranges to trusted networks only",
                        "recommended_configuration": "Use specific CIDR blocks or reference other security groups",
                        "code_fix": f'''resource "aws_security_group" "{sg_name}" {{
  # ... other configuration ...

  ingress {{
    from_port   = {port}
    to_port     = {to_port}
    protocol    = "{protocol}"
    # Replace 0.0.0.0/0 with specific IP ranges:
    cidr_blocks = [
      "10.0.0.0/8",      # Corporate VPN
      "203.0.113.0/24",  # Office network
    ]
    description = "Restricted access from trusted networks only"
  }}
}}''',
                        "additional_steps": [
                            "Use AWS Systems Manager Session Manager instead of direct SSH/RDP",
                            "Implement a bastion host or VPN for remote access",
                            "Enable VPC Flow Logs to monitor traffic patterns",
                            "Set up AWS GuardDuty for threat detection",
                            "Use security group references for inter-service communication",
                            "Implement connection rate limiting at application level"
                        ]
                    },
                    "references": [
                        "AWS Security Group Best Practices: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
                        "CIS AWS Foundations Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services"
                    ]
                })
    
    if not results:
        return [{
            "severity": "success",
            "title": "No Security Issues Detected",
            "description": "Your Terraform configuration passed all security checks. No critical vulnerabilities, misconfigurations, or compliance violations were found.",
            "recommendations": [
                "Continue to follow security best practices",
                "Regularly update this security audit as your infrastructure evolves",
                "Consider implementing AWS Security Hub for continuous monitoring",
                "Enable AWS Config for compliance tracking",
                "Review IAM policies for least-privilege access"
            ]
        }]
    
    return results


def audit_terraform(file):
    """Main audit function with enhanced reporting"""
    
    if file is None:
        return "⚠️ **Please upload a Terraform (.tf) file.**"
    
    try:
        # Read file
        if isinstance(file, str):
            with open(file, 'r', encoding='utf-8') as f:
                tf_content = f.read()
        elif hasattr(file, 'name'):
            with open(file.name, 'r', encoding='utf-8') as f:
                tf_content = f.read()
        else:
            return f"❌ **Could not read file**"
        
        # Run scan
        issues = scan_terraform_file(tf_content)
        
        # Count lines and resources
        line_count = len(tf_content.split('\n'))
        resource_count = len(re.findall(r'resource\s+"[^"]+"\s+"[^"]+"', tf_content))
        
        # Format output with enhanced styling
        filename = file if isinstance(file, str) else (file.name if hasattr(file, 'name') else "uploaded file")
        filename = filename.split('/')[-1].split('\\')[-1]
        
        # Header
        report = f"""# 🛡️ Infrastructure Security Audit Report

---

## 📋 Scan Overview

| Attribute | Value |
|-----------|-------|
| **File Name** | `{filename}` |
| **Lines of Code** | {line_count} |
| **Resources Scanned** | {resource_count} |
| **Scan Date** | {datetime.datetime.now().strftime('%B %d, %Y at %H:%M:%S')} |
| **Security Checks** | TLS/SSL Policies, S3 Security, Network Rules |

---

"""
        
        # Handle success case
        if len(issues) == 1 and issues[0].get("severity") == "success":
            report += f"""## ✅ {issues[0]['title']}

{issues[0]['description']}

### 🎯 Recommended Best Practices

"""
            for idx, rec in enumerate(issues[0]['recommendations'], 1):
                report += f"{idx}. {rec}\n"
            
            report += f"""

---

## 📊 Final Assessment

**Status**: 🟢 **PASSED** - No security vulnerabilities detected

Your Terraform configuration demonstrates strong security practices. Continue monitoring and updating your infrastructure as requirements evolve.

"""
            return report
        
        # Count severity levels
        critical_count = sum(1 for i in issues if i.get("severity") == "critical")
        high_count = sum(1 for i in issues if i.get("severity") == "high")
        medium_count = sum(1 for i in issues if i.get("severity") == "medium")
        low_count = sum(1 for i in issues if i.get("severity") == "low")
        
        # Risk score calculation
        risk_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2) + (low_count * 1)
        
        if risk_score >= 20:
            risk_level = "🔴 CRITICAL"
            risk_desc = "Immediate action required"
        elif risk_score >= 10:
            risk_level = "🟠 HIGH"
            risk_desc = "Address issues promptly"
        elif risk_score >= 5:
            risk_level = "🟡 MEDIUM"
            risk_desc = "Schedule remediation"
        else:
            risk_level = "🟢 LOW"
            risk_desc = "Monitor and improve"
        
        # Summary section
        report += f"""## 🚨 Executive Summary

**Risk Level**: {risk_level} - {risk_desc}

| Severity | Count | Priority |
|----------|-------|----------|
| 🔴 Critical | {critical_count} | Fix immediately |
| 🟠 High | {high_count} | Fix within 24 hours |
| 🟡 Medium | {medium_count} | Fix within 1 week |
| 🟢 Low | {low_count} | Fix within 1 month |

**Overall Risk Score**: {risk_score}/100

---

## 🔍 Detailed Findings

"""
        
        # Add detailed findings
        for idx, issue in enumerate(issues, 1):
            severity = issue.get("severity", "unknown")
            
            # Severity emoji and color
            severity_icons = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢"
            }
            icon = severity_icons.get(severity, "⚪")
            
            report += f"""### {icon} Finding #{idx}: {issue['title']}

**Severity**: {severity.upper()} | **Category**: {issue.get('category', 'General')} | **Resource**: {issue.get('resource_type', 'N/A')}

---

#### 📌 Resource Affected
`{issue.get('resource_name', 'Unknown')}`

#### 📝 Description
{issue['description']}

#### ⚠️ Security Impact
{issue.get('impact', 'Security implications need immediate review.')}

"""
            
            # Attack vectors
            if 'attack_vectors' in issue:
                report += "#### 🎯 Potential Attack Vectors\n\n"
                for vector in issue['attack_vectors']:
                    report += f"- {vector}\n"
                report += "\n"
            
            # Compliance
            if 'affected_compliance' in issue:
                report += f"#### 📜 Compliance Frameworks Affected\n"
                report += ", ".join(f"`{c}`" for c in issue['affected_compliance'])
                report += "\n\n"
            
            # Remediation
            if 'remediation' in issue:
                rem = issue['remediation']
                report += f"""#### 🔧 Remediation Steps

**Immediate Action**: {rem.get('immediate', 'Review and fix immediately')}

"""
                if 'recommended_policies' in rem or 'recommended_configuration' in rem:
                    report += "**Recommended Configuration**:\n"
                    if 'recommended_policies' in rem:
                        for policy in rem['recommended_policies']:
                            report += f"- {policy}\n"
                    if 'recommended_configuration' in rem:
                        report += f"- {rem['recommended_configuration']}\n"
                    report += "\n"
                
                if 'code_fix' in rem:
                    report += "**Terraform Code Fix**:\n\n```hcl\n"
                    report += rem['code_fix']
                    report += "\n```\n\n"
                
                if 'additional_steps' in rem:
                    report += "**Additional Security Measures**:\n\n"
                    for step in rem['additional_steps']:
                        report += f"- {step}\n"
                    report += "\n"
            
            # References
            if 'references' in issue:
                report += "#### 📚 References & Documentation\n\n"
                for ref in issue['references']:
                    report += f"- {ref}\n"
                report += "\n"
            
            report += "---\n\n"
        
        # Final recommendations
        report += f"""## 🎯 Prioritized Action Plan

### Immediate Actions (Next 24 Hours)
"""
        immediate_actions = [i for i in issues if i.get('severity') in ['critical', 'high']]
        if immediate_actions:
            for idx, issue in enumerate(immediate_actions[:5], 1):
                report += f"{idx}. **{issue['title']}** - {issue.get('remediation', {}).get('immediate', 'Fix immediately')}\n"
        else:
            report += "No immediate actions required.\n"
        
        report += f"""

### Short-term Improvements (This Week)
- Review and update all security group rules
- Enable encryption on all S3 buckets
- Implement AWS Config for continuous compliance monitoring
- Set up AWS Security Hub for centralized security findings
- Review IAM policies for least-privilege access

### Long-term Security Enhancements
- Implement Infrastructure as Code security scanning in CI/CD
- Enable AWS GuardDuty for threat detection
- Set up automated compliance reporting
- Conduct regular security audits and penetration testing
- Implement security training for development team

---

## 📊 Security Posture Summary

"""
        
        if risk_score >= 20:
            report += """**Status**: ⛔ **CRITICAL RISK** - Infrastructure has significant security vulnerabilities

Your infrastructure requires immediate attention. Multiple critical issues expose your resources to potential attacks. Follow the remediation steps above to secure your infrastructure.
"""
        elif risk_score >= 10:
            report += """**Status**: ⚠️ **HIGH RISK** - Security improvements needed urgently

Several important security issues were identified. Address these promptly to reduce your attack surface and maintain compliance.
"""
        elif risk_score >= 5:
            report += """**Status**: ⚡ **MODERATE RISK** - Some security enhancements recommended

Your infrastructure has a reasonable security baseline but improvements are needed in specific areas.
"""
        else:
            report += """**Status**: ✅ **LOW RISK** - Good security practices in place

Your infrastructure demonstrates solid security fundamentals. Continue monitoring and addressing the identified issues.
"""
        
        report += f"""

---

## 💡 Next Steps

1. **Review** this report with your security team
2. **Prioritize** fixes based on severity and business impact
3. **Test** all changes in a non-production environment first
4. **Implement** fixes following the provided code examples
5. **Verify** fixes by running this scan again
6. **Monitor** your infrastructure continuously for new issues

---

*Report generated by Terraform Security Auditor | Powered by intelligent pattern recognition*
"""
        
        return report
        
    except Exception as e:
        import traceback
        return f"❌ **Error:** {str(e)}\n\n```\n{traceback.format_exc()}\n```"


# Clean Blue & White Theme with Fixed Text Visibility
custom_css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --primary-blue: #2563eb;
    --blue-600: #1d4ed8;
    --blue-700: #1e40af;
    --blue-50: #eff6ff;
    --blue-100: #dbeafe;
    --blue-200: #bfdbfe;    
    --accent-cyan: #06b6d4;
    --cyan-500: #14b8a6;
    --white: #ffffff;
    --gray-50: #f9fafb;
    --gray-100: #f3f4f6;
    --gray-200: #e5e7eb;
    --gray-300: #d1d5db;
    --gray-700: #374151;
    --gray-800: #1f2937;
    --gray-900: #111827;
    --shadow-blue: rgba(37, 99, 235, 0.15);
    --shadow-lg: rgba(17, 24, 39, 0.1);
}

html, body {
    scroll-behavior: smooth;
    overflow-x: hidden;
    margin: 0;
    padding: 0;     
}

body {
    background: var(--white);
    position: relative;
}

.gradio-container {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    background: linear-gradient(135deg, 
        var(--white) 0%, 
        var(--blue-50) 50%, 
        var(--white) 100%) !important;
    min-height: 100vh !important;
    max-width: 100vw !important;
    margin: 0 !important;
    padding: 0 !important;
    overflow-x: hidden !important;
    position: relative;
}

/* CRITICAL: Force all text to be dark and visible */
.gradio-container,
.gradio-container *,
.gr-box,
.gr-box *,
.gr-form,
.gr-form *,
.gr-panel,
.gr-panel * {
    color: var(--gray-900) !important;
}

/* Animated background elements */
.gradio-container::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: 
        radial-gradient(circle at 20% 30%, rgba(37, 99, 235, 0.08) 0%, transparent 50%),
        radial-gradient(circle at 80% 20%, rgba(6, 182, 212, 0.06) 0%, transparent 50%),
        radial-gradient(circle at 50% 80%, rgba(37, 99, 235, 0.05) 0%, transparent 60%);
    animation: backgroundShift 20s ease-in-out infinite alternate;
    pointer-events: none;
    z-index: 0;
}

@keyframes backgroundShift {
    0% { transform: translate(0, 0) scale(1); }
    50% { transform: translate(20px, -30px) scale(1.05); }
    100% { transform: translate(-15px, 15px) scale(1); }
}

@keyframes dramaticEntrance {
    0% {
        opacity: 0;
        transform: translateY(80px) scale(0.9) rotateX(15deg);
        filter: blur(10px);
    }
    60% {
        transform: translateY(-10px) scale(1.02) rotateX(-2deg);
    }
    100% {
        opacity: 1;
        transform: translateY(0) scale(1) rotateX(0);
        filter: blur(0);
    }
}

@keyframes slideInLeft {
    0% {
        opacity: 0;
        transform: translateX(-150px) rotateY(20deg);
        filter: blur(8px);
    }
    100% {
        opacity: 1;
        transform: translateX(0) rotateY(0);
        filter: blur(0);
    }
}

@keyframes slideInRight {
    0% {
        opacity: 0;
        transform: translateX(150px) rotateY(-20deg);
        filter: blur(8px);
    }
    100% {
        opacity: 1;
        transform: translateX(0) rotateY(0);
        filter: blur(0);
    }
}

@keyframes gentleFloat {
    0%, 100% {
        transform: translateY(0px) rotate(0deg);
    }
    25% {
        transform: translateY(-15px) rotate(-2deg);
    }
    75% {
        transform: translateY(-8px) rotate(2deg);
    }
}

@keyframes blueGlow {
    0%, 100% {
        text-shadow: 
            0 0 40px rgba(37, 99, 235, 0.4),
            0 0 80px rgba(6, 182, 212, 0.3),
            0 5px 30px rgba(37, 99, 235, 0.3);
        filter: drop-shadow(0 10px 30px rgba(37, 99, 235, 0.3));
    }
    50% {
        text-shadow: 
            0 0 60px rgba(37, 99, 235, 0.6),
            0 0 100px rgba(6, 182, 212, 0.4),
            0 8px 40px rgba(37, 99, 235, 0.5);
        filter: drop-shadow(0 15px 40px rgba(37, 99, 235, 0.4));
    }
}

@keyframes cardGlow {
    0%, 100% {
        transform: translate(0, 0) scale(1);
        opacity: 0.5;
    }
    50% {
        transform: translate(10%, -10%) scale(1.1);
        opacity: 0.8;
    }
}

@keyframes shimmerBlue {
    0%, 100% {
        box-shadow: 
            0 0 40px rgba(37, 99, 235, 0.3),
            0 0 80px rgba(6, 182, 212, 0.2),
            inset 0 0 30px rgba(37, 99, 235, 0.05);
    }
    50% {
        box-shadow: 
            0 0 60px rgba(37, 99, 235, 0.5),
            0 0 120px rgba(6, 182, 212, 0.3),
            inset 0 0 40px rgba(37, 99, 235, 0.1);
    }
}

/* Hero section with dramatic styling */
.hero-section {
    position: relative;
    min-height: 75vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 6rem 2rem 5rem;
    text-align: center;
    animation: dramaticEntrance 1.4s cubic-bezier(0.34, 1.56, 0.64, 1) backwards;
    z-index: 1;
}

.shield-container {
    position: relative;
    margin-bottom: 3rem;
    animation: gentleFloat 6s ease-in-out infinite;
    filter: drop-shadow(0 30px 60px rgba(37, 99, 235, 0.3));
}

.shield-icon {
    font-size: 10rem;
    display: inline-block;
    animation: blueGlow 4s ease-in-out infinite;
}

.decorative-circle {
    position: absolute;
    border-radius: 50%;
    opacity: 0.4;
}

.circle-1 {
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(37, 99, 235, 0.2) 0%, transparent 70%);
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    animation: pulseBlue 5s ease-in-out infinite;
    border: 2px solid rgba(37, 99, 235, 0.2);
}

.circle-2 {
    width: 550px;
    height: 550px;
    background: radial-gradient(circle, rgba(6, 182, 212, 0.15) 0%, transparent 70%);
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    animation: pulseBlue 5s ease-in-out infinite 1s;
    border: 2px solid rgba(6, 182, 212, 0.15);
}

@keyframes pulseBlue {
    0%, 100% {
        transform: translate(-50%, -50%) scale(1);
        opacity: 0.4;
    }
    50% {
        transform: translate(-50%, -50%) scale(1.15);
        opacity: 0.2;
    }
}

.hero-title {
    font-family: 'Inter', sans-serif;
    font-size: clamp(3.5rem, 10vw, 7rem);
    font-weight: 900;
    background: linear-gradient(135deg, 
        var(--primary-blue) 0%, 
        var(--blue-600) 30%,
        var(--accent-cyan) 70%,
        var(--cyan-500) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 2rem;
    letter-spacing: -0.03em;
    line-height: 1;
    text-shadow: 0 8px 32px rgba(37, 99, 235, 0.4);
    filter: drop-shadow(0 4px 20px rgba(37, 99, 235, 0.3));
    animation: blueGlow 4s ease-in-out infinite;
}

.hero-subtitle {
    font-family: 'Inter', sans-serif;
    font-size: clamp(1.3rem, 3vw, 1.7rem);
    color: var(--gray-900) !important;
    font-weight: 500;
    max-width: 750px;
    margin: 0 auto 3rem;
    line-height: 1.8;
}

/* Content sections */
.content-section {
    position: relative;
    max-width: 1500px;
    margin: 0 auto;
    padding: 3rem 2rem;
    z-index: 1;
}

/* Clean glass cards */
.glass-card {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(20px);
    border: 2px solid var(--gray-200);
    border-radius: 24px;
    padding: 3.5rem;
    box-shadow: 
        0 20px 60px var(--shadow-lg),
        0 0 0 1px rgba(255, 255, 255, 0.5) inset;
    transition: all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
    position: relative;
    overflow: hidden;
}

.glass-card::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle, rgba(37, 99, 235, 0.08) 0%, transparent 70%);
    animation: cardGlow 8s ease-in-out infinite;
    pointer-events: none;
}

.glass-card::after {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, 
        transparent, 
        rgba(37, 99, 235, 0.1), 
        transparent);
    transition: left 0.8s ease;
}

.glass-card:hover::after {
    left: 100%;
}

.glass-card:hover {
    transform: translateY(-15px) scale(1.02);
    box-shadow: 
        0 40px 100px var(--shadow-blue),
        0 20px 60px rgba(37, 99, 235, 0.2),
        0 0 0 1px rgba(37, 99, 235, 0.2) inset;
    border-color: var(--primary-blue);
    animation: shimmerBlue 2s ease-in-out infinite;
}

/* Upload section */
.upload-section {
    animation: slideInLeft 1.2s cubic-bezier(0.34, 1.56, 0.64, 1) 0.3s backwards;
}

.gradio-file {
    background: var(--white) !important;
    backdrop-filter: blur(15px) !important;
    border: 3px dashed var(--blue-200) !important;
    border-radius: 24px !important;
    padding: 5rem 3rem !important;
    transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
}

/* Force dark text in file upload area */
.gradio-file,
.gradio-file *,
.gradio-file .wrap,
.gradio-file .wrap *,
.gradio-file label,
.gradio-file .or,
.file-preview,
.file-preview *,
.upload-text,
.drop-container,
.drop-container * {
    color: var(--gray-900) !important;
    background: transparent !important;
}

.gradio-file button {
    background: var(--primary-blue) !important;
    color: var(--white) !important;
    border: none !important;
    padding: 0.75rem 2rem !important;
    border-radius: 12px !important;
    font-weight: 600 !important;
    transition: all 0.3s ease !important;
}

.gradio-file button:hover {
    background: var(--blue-600) !important;
    transform: translateY(-2px) !important;
    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3) !important;
}

.gradio-file:hover {
    border-color: var(--primary-blue) !important;
    background: var(--gray-50) !important;
    transform: scale(1.03) translateY(-8px);
    box-shadow: 
        0 30px 70px var(--shadow-blue),
        inset 0 0 30px rgba(37, 99, 235, 0.05);
}

/* Output section */
.output-section {
    animation: slideInRight 1.2s cubic-bezier(0.34, 1.56, 0.64, 1) 0.5s backwards;
}

.output-card {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(20px);
    border: 2px solid var(--gray-200);
    border-radius: 24px;
    padding: 3rem;
    min-height: 600px;
    box-shadow: 
        0 20px 60px var(--shadow-lg),
        0 0 0 1px rgba(255, 255, 255, 0.5) inset;
    color: var(--gray-900) !important;
    line-height: 1.9;
}

/* Force all output card text to be dark */
.output-card,
.output-card * {
    color: var(--gray-900) !important;
}

/* Feature grid */
.features-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
    gap: 2.5rem;
    margin: 6rem 0 5rem;
    animation: dramaticEntrance 1.4s cubic-bezier(0.34, 1.56, 0.64, 1) 0.7s backwards;
}

.feature-item {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(20px);
    border: 2px solid var(--gray-200);
    border-radius: 20px;
    padding: 3rem;
    box-shadow: 
        0 15px 50px var(--shadow-lg),
        0 0 0 1px rgba(255, 255, 255, 0.5) inset;
    transition: all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
    position: relative;
    overflow: hidden;
}

.feature-item::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 4px;
    background: linear-gradient(90deg, 
        var(--primary-blue), 
        var(--accent-cyan));
    transform: scaleX(0);
    transition: transform 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.feature-item:hover::before {
    transform: scaleX(1);
}

.feature-item:hover {
    transform: translateY(-18px) scale(1.05) rotateX(2deg);
    box-shadow: 
        0 35px 90px var(--shadow-blue),
        0 20px 50px rgba(37, 99, 235, 0.3),
        0 0 0 1px rgba(37, 99, 235, 0.2) inset;
    border-color: var(--primary-blue);
    animation: shimmerBlue 2s ease-in-out infinite;
}

.feature-icon {
    font-size: 4.5rem;
    margin-bottom: 2rem;
    display: block;
    filter: drop-shadow(0 8px 20px rgba(37, 99, 235, 0.4));
    animation: gentleFloat 5s ease-in-out infinite;
}

.feature-title {
    font-family: 'Inter', sans-serif;
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--primary-blue) !important;
    margin-bottom: 1.2rem;
    text-shadow: 0 2px 10px rgba(37, 99, 235, 0.2);
}

.feature-desc {
    color: var(--gray-900) !important;
    font-size: 1.1rem;
    line-height: 1.8;
}

/* Stats badges */
.stats-container {
    display: flex;
    justify-content: center;
    gap: 2rem;
    flex-wrap: wrap;
    margin: 5rem 0;
    animation: dramaticEntrance 1.6s cubic-bezier(0.34, 1.56, 0.64, 1) 0.9s backwards;
}

.stat-badge {
    background: linear-gradient(135deg, 
        var(--primary-blue) 0%, 
        var(--blue-600) 100%);
    color: var(--white) !important;
    padding: 1.3rem 3rem;
    border-radius: 60px;
    font-weight: 700;
    font-size: 1.1rem;
    box-shadow: 
        0 15px 40px rgba(37, 99, 235, 0.3),
        inset 0 2px 0 rgba(255, 255, 255, 0.2);
    transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
    border: 2px solid rgba(255, 255, 255, 0.2);
    text-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

.stat-badge:hover {
    transform: translateY(-8px) scale(1.1) rotate(-2deg);
    box-shadow: 
        0 25px 60px rgba(37, 99, 235, 0.5),
        inset 0 2px 0 rgba(255, 255, 255, 0.3);
    animation: shimmerBlue 1.5s ease-in-out infinite;
}

/* Footer */
.footer-section {
    text-align: center;
    padding: 5rem 2rem;
    color: var(--gray-900) !important;
    border-top: 2px solid var(--gray-200);
    margin-top: 6rem;
    background: rgba(255, 255, 255, 0.8);
    animation: dramaticEntrance 1.8s cubic-bezier(0.34, 1.56, 0.64, 1) 1.1s backwards;
}

.footer-section,
.footer-section * {
    color: var(--gray-900) !important;
}

/* Labels and input text - force dark color */
label,
.label-wrap,
.label-wrap * {
    color: var(--gray-900) !important;
    font-weight: 700 !important;
    font-size: 1.2rem !important;
    margin-bottom: 1.2rem !important;
}

/* Scrollbar */
::-webkit-scrollbar {
    width: 14px;
}

::-webkit-scrollbar-track {
    background: var(--gray-100);
    border-left: 1px solid var(--gray-200);
}

::-webkit-scrollbar-thumb {
    background: linear-gradient(135deg, 
        var(--primary-blue), 
        var(--accent-cyan));
    border-radius: 8px;
    border: 2px solid var(--gray-100);
    box-shadow: inset 0 0 10px rgba(37, 99, 235, 0.3);
}

::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(135deg, 
        var(--blue-600), 
        var(--primary-blue));
}

/* Responsive */
@media (max-width: 768px) {
    .hero-title {
        font-size: 3rem;
    }
    
    .glass-card {
        padding: 2.5rem;
    }
    
    .features-grid {
        grid-template-columns: 1fr;
    }
    
    .shield-icon {
        font-size: 6rem;
    }
}

/* Enhanced report styling - all text forced to dark */
.output-card h1 {
    color: var(--primary-blue) !important;
    font-family: 'Inter', sans-serif;
    font-size: 2.5rem;
    margin-bottom: 1.5rem;
    font-weight: 800;
    text-shadow: 0 4px 16px rgba(37, 99, 235, 0.2);
}

.output-card h2 {
    color: var(--blue-600) !important;
    font-family: 'Inter', sans-serif;
    font-size: 1.8rem;
    margin-top: 2.5rem;
    margin-bottom: 1.2rem;
    font-weight: 700;
    text-shadow: 0 2px 12px rgba(37, 99, 235, 0.15);
}

.output-card h3 {
    color: var(--blue-700) !important;
    font-family: 'Inter', sans-serif;
    font-size: 1.6rem;
    margin-top: 3rem;
    margin-bottom: 1.5rem;
    font-weight: 700;
    text-shadow: 0 2px 12px rgba(37, 99, 235, 0.15);
    padding-bottom: 0.5rem;
    border-bottom: 2px solid var(--blue-200);
}

.output-card h4 {
    color: var(--accent-cyan) !important;
    font-family: 'Inter', sans-serif;
    font-size: 1.3rem;
    margin-top: 2rem;
    margin-bottom: 1rem;
    font-weight: 600;
    text-shadow: 0 1px 8px rgba(6, 182, 212, 0.15);
}

.output-card code {
    background: var(--blue-50) !important;
    padding: 0.4rem 1rem;
    border-radius: 8px;
    font-family: 'JetBrains Mono', 'SF Mono', 'Monaco', monospace;
    color: var(--blue-700) !important;
    font-size: 0.9em;
    border: 1px solid var(--blue-200);
    box-shadow: inset 0 1px 3px rgba(37, 99, 235, 0.1);
}

.output-card hr {
    border: none;
    border-top: 2px solid var(--blue-100);
    margin: 3rem 0;
    box-shadow: 0 1px 0 rgba(37, 99, 235, 0.05);
}

.output-card strong {
    color: var(--primary-blue) !important;
    font-weight: 700;
    text-shadow: 0 1px 4px rgba(37, 99, 235, 0.1);
}

.output-card p {
    color: var(--gray-900) !important;
}

.output-card li {
    color: var(--gray-900) !important;
    margin: 0.8rem 0;
}

.output-card a {
    color: var(--primary-blue) !important;
    text-decoration: underline;
}

/* Report tables */
.output-card table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin: 1.5rem 0;
    background: var(--white);
    border-radius: 12px;
    overflow: hidden;
    border: 2px solid var(--blue-100);
    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.08);
}

.output-card table thead {
    background: linear-gradient(135deg, 
        var(--blue-50) 0%, 
        var(--blue-100) 100%);
}

.output-card table th {
    color: var(--primary-blue) !important;
    font-weight: 700;
    padding: 1rem 1.5rem;
    text-align: left;
    font-size: 1.05rem;
    border-bottom: 2px solid var(--blue-200);
    text-shadow: 0 1px 2px rgba(37, 99, 235, 0.1);
}

.output-card table td {
    padding: 1rem 1.5rem;
    color: var(--gray-900) !important;
    border-bottom: 1px solid var(--blue-100);
}

.output-card table tr:last-child td {
    border-bottom: none;
}

.output-card table tr:hover {
    background: var(--blue-50);
}

.output-card blockquote {
    background: var(--blue-50);
    border-left: 4px solid var(--primary-blue);
    padding: 1rem 1.5rem;
    margin: 1.5rem 0;
    border-radius: 0 8px 8px 0;
    color: var(--gray-900) !important;
}

.output-card pre {
    background: var(--gray-900) !important;
    border: 2px solid var(--blue-200);
    border-radius: 12px;
    padding: 1.5rem;
    margin: 1.5rem 0;
    overflow-x: auto;
    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.1);
}

.output-card pre code {
    background: transparent !important;
    padding: 0;
    border: none;
    box-shadow: none;
    color: var(--blue-100) !important;
    font-size: 0.9rem;
    line-height: 1.6;
}

.output-card ul {
    margin: 1rem 0;
    padding-left: 2rem;
}

.output-card ul li {
    margin: 0.8rem 0;
    line-height: 1.7;
    color: var(--gray-900) !important;
}

.output-card ol {
    margin: 1rem 0;
    padding-left: 2rem;
}

.output-card ol li {
    margin: 0.8rem 0;
    color: var(--gray-900) !important;
    line-height: 1.7;
}

.output-card em {
    color: var(--primary-blue) !important;
    font-style: normal;
    font-weight: 600;
}

/* Input fields */
input, 
textarea,
select {
    color: var(--gray-900) !important;
    background: var(--white) !important;
    border: 2px solid var(--gray-200) !important;
}

/* Markdown content */
.markdown-body,
.prose,
.markdown-body *,
.prose * {
    color: var(--gray-900) !important;
}

/* Override any Gradio default styles */
.svelte-1ed2p3z,
.svelte-1ed2p3z *,
.gr-prose,
.gr-prose * {
    color: var(--gray-900) !important;
}
</style>
"""

# HTML content
hero_html = custom_css + """
<div class="hero-section">
    <div class="shield-container">
        <div class="decorative-circle circle-1"></div>
        <div class="decorative-circle circle-2"></div>
        <span class="shield-icon">🛡️</span>
    </div>
    <h1 class="hero-title">Terraform Security Auditor</h1>
    <p class="hero-subtitle">Enterprise-grade infrastructure security scanning with intelligent vulnerability detection and real-time analysis</p>
</div>
"""

features_html = """
<div class="content-section">
    <div class="features-grid">
        <div class="feature-item">
            <span class="feature-icon">🔐</span>
            <div class="feature-title">TLS/SSL Policy Detection</div>
            <div class="feature-desc">Advanced pattern matching identifies weak encryption policies and outdated TLS versions in load balancers</div>
        </div>
        <div class="feature-item">
            <span class="feature-icon">☁️</span>
            <div class="feature-title">S3 Security Analysis</div>
            <div class="feature-desc">Comprehensive scanning for public buckets, missing encryption, and compliance violations</div>
        </div>
        <div class="feature-item">
            <span class="feature-icon">🌐</span>
            <div class="feature-title">Network Security Audit</div>
            <div class="feature-desc">Deep inspection of security groups detecting unrestricted internet access and open ports</div>
        </div>
    </div>
    
    <div class="stats-container">
        <div class="stat-badge">⚡ Lightning Fast</div>
        <div class="stat-badge">🎯 Highly Accurate</div>
        <div class="stat-badge">🔒 Enterprise Ready</div>
    </div>
</div>
"""

footer_html = """
<div class="footer-section">
    <p style="font-size: 1.2rem; margin-bottom: 1rem; font-weight: 600;">Powered by intelligent pattern recognition & regex analysis</p>
    <p style="font-size: 1.05rem; opacity: 0.85;">Protect your cloud infrastructure from security misconfigurations</p>
</div>
"""

# Create interface
with gr.Blocks(theme=gr.themes.Soft()) as demo:
    gr.HTML(hero_html)
    
    with gr.Column(elem_classes="content-section upload-section"):
        with gr.Column(elem_classes="glass-card"):
            file_input = gr.File(
                label="📁 Drop your Terraform configuration here",
                file_types=[".tf"],
                file_count="single"
            )
    
    with gr.Column(elem_classes="content-section output-section"):
        with gr.Column(elem_classes="output-card"):
            output = gr.Markdown(
                value="**Ready to scan.** Upload a `.tf` file above to begin comprehensive security analysis...",
            )
    
    gr.HTML(features_html)
    gr.HTML(footer_html)
    
    # Auto-scan on file upload
    file_input.change(
        fn=audit_terraform,
        inputs=file_input,
        outputs=output
    )

if __name__ == "__main__":
    demo.launch(server_name="127.0.0.1", server_port=7860)