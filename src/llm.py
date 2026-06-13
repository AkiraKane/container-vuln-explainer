"""LLM client for explaining CVE vulnerabilities."""

import json
import urllib.request
import urllib.error
import os


SYSTEM_PROMPT = """You are an expert security engineer explaining CVE vulnerabilities to developers.

Given a list of vulnerabilities from a Trivy scan, explain them in plain English.

Rules:
- Explain what each vulnerability means in simple terms
- Describe the real-world impact (what could an attacker do?)
- Suggest specific fix actions (upgrade, patch, workaround)
- Prioritize by severity (critical first)
- Use bullet points for readability
- Group by package when multiple CVEs affect the same package
- Mention if vulnerabilities are related or chained
- Be actionable — developers should know exactly what to do

Output in markdown format."""


def explain_vulnerabilities(
    vuln_prompt: str,
    ollama_url: str = "http://localhost:11434",
    model: str = "llama3.2",
) -> str:
    """Generate plain English explanation of vulnerabilities."""
    user_prompt = f"""Explain these vulnerabilities and suggest fixes:

{vuln_prompt}"""

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {"temperature": 0.3},
    }

    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            return result["message"]["content"].strip()
    except urllib.error.URLError:
        openai_key = os.environ.get("OPENAI_API_KEY")
        if openai_key:
            return _explain_openai(vuln_prompt, openai_key)
        raise ConnectionError(
            f"Cannot connect to Ollama at {ollama_url}. "
            "Start Ollama: ollama serve"
        )


def _explain_openai(vuln_prompt: str, api_key: str) -> str:
    """Fallback to OpenAI."""
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Explain these vulnerabilities:\n\n{vuln_prompt}"},
        ],
        "temperature": 0.3,
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())
        return result["choices"][0]["message"]["content"].strip()


def check_ollama(ollama_url: str = "http://localhost:11434") -> bool:
    """Check if Ollama is running."""
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False
