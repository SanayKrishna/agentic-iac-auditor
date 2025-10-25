# Agentic IaC Auditor

Agentic IaC Auditor is an AI-assisted Infrastructure-as-Code (IaC) auditing framework designed to automatically detect misconfigurations, security risks, and compliance violations in Terraform configurations. It leverages intelligent scanning logic to identify issues such as public S3 buckets, weak TLS policies, missing encryption settings, and insecure IAM configurations—ensuring cloud infrastructure aligns with security best practices and organizational compliance standards.

## Features
- Automated scanning of Terraform (`.tf`) files for misconfigurations.
- Detection of security risks like public exposure, weak encryption, and outdated TLS policies.
- Modular and extensible architecture supporting future policy integrations.
- Lightweight, agent-based design suitable for CI/CD pipelines.
- Fast local scanning with zero external API dependency.

## Project Structure
agentic-iac-auditor/
│
├── main.py                 # Core execution and rule orchestration
├── rules/                  # Modular rule definitions for specific checks
│   ├── s3_public_access.py
│   ├── weak_tls_policy.py
│   ├── unencrypted_storage.py
│   └── insecure_iam_policy.py
├── examples/               # Example Terraform files for testing
│   ├── s3_public.tf
│   ├── weak_tls.tf
│   └── unencrypted_ebs.tf
└── requirements.txt         # Python dependencies

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/SanayKrishna/agentic-iac-auditor.git
   cd agentic-iac-auditor
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
To run the auditor against your Terraform configurations:
```bash
python main.py --path /path/to/terraform/files
```
Example:
```bash
python main.py --path ./examples
```
Output:
```
[!] Detected: Public S3 Bucket (aws_s3_bucket.public)
[!] Detected: Weak TLS Policy (ELBSecurityPolicy-2015-05)
[!] Detected: Unencrypted EBS Volume (aws_ebs_volume.unencrypted)
No issues detected in remaining files.
```

## Supported Rules
| Category | Rule Name | Description |
|-----------|------------|-------------|
| S3 Security | Public Access | Detects buckets with `acl = "public-read"` or `public-read-write`. |
| TLS Security | Weak Policy | Identifies outdated SSL/TLS configurations. |
| Storage Security | Missing Encryption | Detects volumes or databases lacking encryption. |
| IAM Security | Insecure Policy | Flags overly permissive IAM policies using `"*"` actions or resources. |

## Tech Stack
- **Language:** Python 3.x  
- **Core Modules:** `os`, `re`, `json`  
- **Extensibility:** Easily integrate new rules by adding Python modules to `/rules`.

## Roadmap
- Integration with AWS Config and Security Hub APIs.
- Support for other IaC formats (CloudFormation, Pulumi).
- AI-based remediation recommendations.
- GitHub Actions integration for automated IaC auditing.

## License
This project is licensed under the MIT License. See `LICENSE` for details.

## Maintainer
**Sanay Krishna**  
Cloud Security & DevSecOps Researcher  
Maintained for open-source community security advancement.

