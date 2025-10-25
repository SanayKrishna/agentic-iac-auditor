# Agentic IaC Auditor

## Project Overview
Agentic IaC Auditor is a full-stack AI-driven platform designed to **audit and remediate Terraform Infrastructure-as-Code (IaC) files**. The system detects vulnerabilities and misconfigurations in cloud infrastructure, applies fixes while preserving functionality, and generates clear human-readable summaries for developers and security teams.

The goal is to **streamline cloud security audits**, reduce manual review effort, and ensure infrastructure adheres to best practices.

## Project Structure
src/
  ├── app.py             # Gradio front-end and app logic
  ├── agents.py          # AI agents definitions (auditor, remediator, explainer)
  ├── main.py            # Core orchestration logic
  ├── task.py            # Task management for AI agents
  ├── database.py        # Simple database handling (optional)
  ├── orchestrator.py    # AI orchestration and playbooks

venv/                     # Python virtual environment
requirements.txt          # Python dependencies

## Agents Overview

1. **iac_auditor_agent**
   - Role: Senior Infrastructure Security Engineer
   - Goal: Audit Terraform IaC files for vulnerabilities and misconfigurations. Deliver a clear, actionable report with precise security findings.
   - Backstory: Experienced cloud security professional skilled in AWS, Azure, and GCP security best practices. Trained to detect IaC misconfigurations and compliance issues.
   - Verbose: True

2. **iac_remediator_agent**
   - Role: Cloud Security DevOps Specialist
   - Goal: Fix Terraform code while preserving its functionality but making it compliant and secure.
   - Backstory: DevOps and cloud compliance specialist who can intelligently rewrite Terraform configurations to follow least privilege, secure-by-default, and encryption standards.
   - Verbose: True

3. **iac_explainer_agent**
   - Role: Technical Security Writer
   - Goal: Generate a human-readable summary of the Terraform audit and remediation results.
   - Backstory: Cybersecurity technical writer who explains security changes clearly for developers, including the reasoning and impact of each fix.
   - Verbose: True

## Usage
1. **Set up environment**
   - `python -m venv venv`
   - `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Linux/Mac)
   - `pip install -r requirements.txt`

2. **Run the app**
   - `python app.py`
   - Open the local URL in a browser (usually http://127.0.0.1:7860)
   - Upload a Terraform `.tf` file and click submit

## Example Terraform File
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-insecure-project-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow HTTP and SSH traffic"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
