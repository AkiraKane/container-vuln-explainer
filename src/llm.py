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


def suggest_fix(vuln, base_image: str = "",
                ollama_url: str = "http://localhost:11434",
                model: str = "llama3.2") -> str:
    """Ask the LLM for a specific remediation suggestion for one CVE.

    Args:
        vuln: A Vulnerability instance (or any object with id, severity, package,
              installed_version, fixed_version, title, description attributes).
        base_image: The current base image from the Dockerfile (e.g. "python:3.11-slim").

    Returns:
        A plain-text remediation suggestion.
    """
    system = """You are a container security engineer. Given a single CVE and the current
base image of a Dockerfile, produce a concise remediation suggestion.

Rules:
- If the package has a fixed_version, recommend upgrading to it.
- If the base image is outdated, suggest a newer tag (e.g. python:3.12-slim).
- If no fix exists, recommend a mitigation or alternative package.
- Keep the response under 200 words.
- Do NOT wrap the response in markdown code fences."""

    user_msg = f"""CVE: {vuln.id}
Severity: {vuln.severity}
Package: {vuln.package}
Installed version: {vuln.installed_version}
Fixed version: {vuln.fixed_version or 'N/A'}
Title: {vuln.title or 'N/A'}
Description: {(vuln.description or 'N/A')[:300]}
Current base image: {base_image or 'unknown'}

Suggest a specific fix."""

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "stream": False,
        "options": {"temperature": 0.2},
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
            return _suggest_fix_openai(user_msg, system, openai_key)
        raise ConnectionError(
            f"Cannot connect to Ollama at {ollama_url}. "
            "Start Ollama: ollama serve"
        )


def _suggest_fix_openai(user_msg: str, system: str, api_key: str) -> str:
    """OpenAI fallback for suggest_fix."""
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.2,
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


def patch_dockerfile(dockerfile: str, fixes: list,
                     ollama_url: str = "http://localhost:11434",
                     model: str = "llama3.2") -> str:
    """Apply a list of remediation suggestions to produce a patched Dockerfile.

    Args:
        dockerfile: The original Dockerfile contents.
        fixes: A list of fix-suggestion strings (one per CVE).

    Returns:
        The patched Dockerfile contents as a string.
    """
    system = """You are a container security engineer. Given an original Dockerfile and a
list of remediation suggestions, produce an updated Dockerfile that addresses
all the fixes.

Rules:
- Only change what is necessary (base image tags, apt-get upgrade lines, etc.).
- Preserve the original structure, comments, and intent.
- Add comments (## security fix) next to changed lines.
- Output ONLY the Dockerfile content. No markdown fences, no explanation."""

    fixes_text = "\n".join(f"- {f}" for f in fixes)
    user_msg = f"""Original Dockerfile:
```
{dockerfile}
```

Remediation suggestions to apply:
{fixes_text}

Output the patched Dockerfile."""

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "stream": False,
        "options": {"temperature": 0.1},
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
            text = result["message"]["content"].strip()
    except urllib.error.URLError:
        openai_key = os.environ.get("OPENAI_API_KEY")
        if openai_key:
            text = _patch_dockerfile_openai(user_msg, system, openai_key)
        else:
            raise ConnectionError(
                f"Cannot connect to Ollama at {ollama_url}. "
                "Start Ollama: ollama serve"
            )

    # Strip markdown fences if the LLM added them anyway
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last fence lines
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text


def _patch_dockerfile_openai(user_msg: str, system: str, api_key: str) -> str:
    """OpenAI fallback for patch_dockerfile."""
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.1,
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
