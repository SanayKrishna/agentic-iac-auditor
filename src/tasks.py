# src/tasks.py
from crewai import Task

iac_audit_task = Task(
    name="IaC Audit",
    description=(
        "Analyze the uploaded Terraform (.tf) code for cloud security risks and misconfigurations. "
        "Look for open security groups, public buckets, hardcoded secrets, weak encryption, and IAM privilege issues. "
        "Output should be structured, human-readable, and contain the specific resource name and fix recommendation."
    ),
    expected_output="A Markdown report listing all security issues, their explanations, and suggested remediations."
)

iac_remediation_task = Task(
    name="IaC Remediation",
    description=(
        "Receive the identified issues and automatically generate a secure, corrected version of the Terraform code. "
        "Apply best practices (least privilege, encryption, private networking). "
        "Ensure syntax is valid HCL and compatible with Terraform v1.6+."
    ),
    expected_output="A secure and corrected Terraform file content (.tf) with explanations in comments."
)

iac_explanation_task = Task(
    name="IaC Explanation",
    description=(
        "Compare the insecure and remediated Terraform code. "
        "Explain each fix in plain developer language—what was wrong, how it was fixed, and why it matters for security."
    ),
    expected_output="A final Markdown report explaining each security improvement between the original and remediated code."
)
