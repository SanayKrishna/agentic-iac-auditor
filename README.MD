# Agentic IaC Auditor

A Terraform security checker with a Gradio web UI. Upload a `.tf` file and it reports risky configurations, each with a severity, an explanation, and a rewritten Terraform block that fixes it.

## What it checks

The checks in the web app are regex-based and run locally, with no API calls:

| Check | Severity | Looks for |
| --- | --- | --- |
| Weak TLS policy | Critical | `aws_lb_listener` using an outdated `ssl_policy` |
| Public S3 bucket | Critical | `aws_s3_bucket` with `acl` set to `public-read`, `public-read-write` or `website` |
| Unencrypted S3 bucket | High | `aws_s3_bucket` with no server-side encryption configuration |
| Open security group | Critical | `aws_security_group` ingress from `0.0.0.0/0` |

For each finding the report suggests a fix, for example a `ELBSecurityPolicy-TLS13-1-2-2021-06` listener, a private bucket with a public access block, or an encryption configuration resource.

## The agent part

`src/` holds a CrewAI setup with three agents: an auditor, a remediator that rewrites the Terraform, and an explainer that writes the report. There is also an `hcl2`-based scanner in `src/scanner.py` that parses the file properly instead of using regex. Neither is wired into the Gradio app yet. Connecting them, so the agents can review what the rule checks miss, is the next step.

## Run it

Python 3.10 or newer.

```bash
git clone https://github.com/SanayKrishna/agentic-iac-auditor.git
cd agentic-iac-auditor
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install gradio python-hcl2 crewai==0.28.0 crewai-tools==0.4.7 openai python-dotenv
python app.py
```

Open http://127.0.0.1:7860 and upload a file. The repo includes sample files to try:

```text
weak_tls.tf                 outdated listener TLS policy
simple_insecure.tf          public bucket and open security group
iam_and_storage.tf          storage and IAM misconfigurations
public_rds.tf               publicly reachable database
hardcoded_secret.tf         credentials in plain text
combined_vulnerabilities.tf several of the above together
```

Some of these samples (IAM, RDS, hardcoded secrets) cover issues the current rule set does not detect yet. They are there for the agent pipeline.

## Project layout

```text
app.py              Gradio UI and the regex scanner
src/agents.py       CrewAI agent definitions
src/tasks.py        CrewAI task definitions
src/scanner.py      hcl2 parser with a regex fallback
src/tools/          file reader tool for the agents
test_scanner.py     scanner tests
```

## Limitations

- Regex matching breaks on unusual formatting and nested blocks, which is why the hcl2 scanner exists.
- AWS only. No Azure or GCP resources are checked.
- IAM wildcards, public RDS and hardcoded secrets are not detected by the web app yet.
