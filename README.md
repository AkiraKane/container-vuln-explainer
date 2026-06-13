# Container Vulnerability Explainer 🛡️🤖

A CLI tool that takes Trivy CVE scan output and uses AI to explain vulnerabilities in plain English with actionable fix suggestions. Perfect for developers who aren't security experts.

## What It Does

1. **Parses** Trivy JSON scan output
2. **Explains** each CVE in plain English
3. **Suggests** specific fix actions (upgrade, patch, workaround)
4. **Prioritizes** by severity (critical first)

## Quick Start

```bash
# Scan an image and explain
trivy image nginx:latest --format json > scan.json
python src/main.py scan.json

# Pipe directly from trivy
trivy image nginx:latest --format json | python src/main.py -

# Show summary only (no AI)
python src/main.py scan.json --summary

# Output as JSON
python src/main.py scan.json --output json
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Trivy Scan     │────▶│  Trivy Parser   │────▶│   LLM Client    │
│  (JSON)         │     │  (structured)   │     │   (Ollama)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │                         │
                              ▼                         ▼
                        ┌─────────────────┐     ┌─────────────────┐
                        │  ScanResult     │────▶│   Explanation   │
                        │  .to_prompt()   │     │   (markdown)    │
                        └─────────────────┘     └─────────────────┘
```

## Example

Given Trivy scan output:
```json
{
  "Results": [{
    "Target": "nginx:latest",
    "Vulnerabilities": [{
      "VulnerabilityID": "CVE-2024-1234",
      "Severity": "CRITICAL",
      "PkgName": "openssl",
      "InstalledVersion": "1.1.1",
      "FixedVersion": "1.1.2"
    }]
  }]
}
```

Output:
```
Target: nginx:latest
Vulnerabilities: 1
  Critical: 1
  High: 0
  Medium: 0
  Low: 0

## Critical Vulnerabilities

### CVE-2024-1234: Buffer Overflow in OpenSSL

**What it means:** A buffer overflow vulnerability in OpenSSL could allow
an attacker to execute arbitrary code on your server.

**Impact:** An attacker could potentially gain full control of the container
by sending specially crafted requests to services using OpenSSL.

**Fix:** Upgrade OpenSSL from 1.1.1 to 1.1.2:
```bash
apt-get update && apt-get install openssl=1.1.2
```

**Priority:** CRITICAL — Fix this immediately before deploying to production.
```

## Features

- **Structured Parsing**: Extracts CVE ID, severity, package, versions
- **AI Explanation**: Converts technical CVE descriptions to plain English
- **Actionable Fixes**: Suggests specific upgrade commands
- **Severity Grouping**: Critical issues first
- **Batch Processing**: Handles multiple scan results

## Requirements

- Python 3.11+
- Trivy installed (`brew install trivy` or see [docs](https://aquasecurity.github.io/trivy/))
- Ollama running locally (or OPENAI_API_KEY)

## Installation

```bash
git clone https://github.com/AkiraKane/container-vuln-explainer.git
cd container-vuln-explainer
```

## Docker

```bash
docker build -t container-vuln-explainer .
docker run -v $(pwd):/app/input container-vuln-explainer
```

## GitHub Actions

Automatically scan images weekly and explain vulnerabilities:
```yaml
- uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'your-image:latest'
    format: 'json'
    output: 'trivy-results.json'

- run: python src/main.py trivy-results.json
```

## Interview Talking Points

- **Security Automation**: Integrates CVE scanning into CI/CD pipeline
- **Developer Experience**: Makes security accessible to non-experts
- **Prompt Engineering**: Structured prompts for actionable security advice
- **Compliance**: Helps meet security audit requirements

## License

MIT
