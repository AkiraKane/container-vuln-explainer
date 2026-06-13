"""Scan-Fix-Verify agent loop for container vulnerability remediation."""

import json
import subprocess
import shutil
import tempfile
import os

from trivy_parser import (
    ScanResult,
    Vulnerability,
    parse_trivy_json,
    run_trivy_scan,
    compare_scans,
)
from llm import suggest_fix, patch_dockerfile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    """Return True if the Docker CLI is reachable."""
    return shutil.which("docker") is not None


def _build_image(dockerfile_path: str, tag: str) -> bool:
    """Build a Docker image from *dockerfile_path*. Returns True on success."""
    cmd = ["docker", "build", "-t", tag, "-f", dockerfile_path, "."]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _critical_high_vulns(scan: ScanResult) -> list[Vulnerability]:
    """Return only CRITICAL and HIGH vulnerabilities from a scan."""
    return [v for v in scan.vulnerabilities if v.severity in ("CRITICAL", "HIGH")]


def _extract_base_image(dockerfile: str) -> str:
    """Best-effort extraction of the first FROM image in a Dockerfile."""
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1]
    return ""


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _build_report(
    image: str,
    original_scan: ScanResult,
    fixes: list[dict],
    patched_dockerfile: str,
    comparison: dict | None,
    docker_available: bool,
    verified: bool,
) -> dict:
    """Assemble the final structured report."""
    report = {
        "image": image,
        "original_summary": {
            "total": original_scan.total_count,
            "critical": original_scan.critical_count,
            "high": original_scan.high_count,
            "medium": original_scan.medium_count,
            "low": original_scan.low_count,
        },
        "fixes_applied": fixes,
        "fixes_count": len(fixes),
        "patched_dockerfile": patched_dockerfile,
        "docker_available": docker_available,
        "verified": verified,
    }
    if comparison is not None:
        report["verification"] = comparison
    return report


def _format_report(report: dict) -> str:
    """Render a human-readable markdown report."""
    lines = [
        "# Container Vulnerability Remediation Report",
        "",
        f"**Image:** `{report['image']}`",
        "",
        "## Original Scan Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| Critical | {report['original_summary']['critical']} |",
        f"| High     | {report['original_summary']['high']} |",
        f"| Medium   | {report['original_summary']['medium']} |",
        f"| Low      | {report['original_summary']['low']} |",
        f"| **Total** | **{report['original_summary']['total']}** |",
        "",
        "## Fixes Applied",
        "",
    ]

    if not report["fixes_applied"]:
        lines.append("_No CRITICAL/HIGH vulnerabilities found._")
    else:
        for i, fix in enumerate(report["fixes_applied"], 1):
            lines.append(f"### {i}. {fix['cve']} ({fix['severity']})")
            lines.append(f"- **Package:** {fix['package']} {fix['installed_version']}")
            if fix.get("fixed_version"):
                lines.append(f"- **Fixed version:** {fix['fixed_version']}")
            lines.append(f"- **Suggestion:** {fix['suggestion']}")
            lines.append("")

    lines.append(f"**Total fixes suggested:** {report['fixes_count']}")
    lines.append("")

    # Verification section
    if report["verified"] and report.get("verification"):
        comp = report["verification"]
        lines.append("## Verification (Re-scan after rebuild)")
        lines.append("")
        lines.append(f"- **Fixed CVEs:** {comp['summary']['fixed_count']}")
        lines.append(f"- **Remaining CVEs:** {comp['summary']['remaining_count']}")
        lines.append(f"- **New CVEs:** {comp['summary']['new_count']}")
        lines.append("")
        lines.append(f"| Metric | Before | After |")
        lines.append(f"|--------|--------|-------|")
        lines.append(f"| Total  | {comp['summary']['before_total']} | {comp['summary']['after_total']} |")
        bs = comp['summary']['before_severity']
        at = comp['summary']['after_severity']
        lines.append(f"| Critical | {bs['CRITICAL']} | {at['CRITICAL']} |")
        lines.append(f"| High     | {bs['HIGH']} | {at['HIGH']} |")
        lines.append(f"| Medium   | {bs['MEDIUM']} | {at['MEDIUM']} |")
        lines.append(f"| Low      | {bs['LOW']} | {at['LOW']} |")
    elif not report["docker_available"]:
        lines.append("## Verification")
        lines.append("")
        lines.append("_Docker not available -- verification skipped._")
    else:
        lines.append("## Verification")
        lines.append("")
        lines.append("_Verification was not requested (--verify flag)._")

    lines.append("")
    lines.append("## Patched Dockerfile")
    lines.append("")
    lines.append("```dockerfile")
    lines.append(report.get("patched_dockerfile", "# (none generated)"))
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def run_agent(
    image: str,
    dockerfile_path: str | None = None,
    max_fixes: int = 10,
    verify: bool = False,
    ollama_url: str = "http://localhost:11434",
    model: str = "llama3.2",
) -> dict:
    """Execute the full scan-fix-verify agent loop.

    Parameters
    ----------
    image : str
        Container image to scan.
    dockerfile_path : str | None
        Path to the original Dockerfile. If ``None``, no Dockerfile patching
        is performed and only scan results are returned.
    max_fixes : int
        Maximum number of CVE fixes to process.
    verify : bool
        If True and Docker is available, rebuild the image and re-scan.
    ollama_url, model : LLM connection details.

    Returns
    -------
    dict  (report dict suitable for JSON serialisation)
    """
    # ------------------------------------------------------------------
    # 1. SCAN
    # ------------------------------------------------------------------
    original_scan = run_trivy_scan(image)

    critical_high = _critical_high_vulns(original_scan)
    if not critical_high:
        return _build_report(
            image=image,
            original_scan=original_scan,
            fixes=[],
            patched_dockerfile="",
            comparison=None,
            docker_available=_docker_available(),
            verified=False,
        )

    # Cap the number of fixes
    critical_high = critical_high[:max_fixes]

    # ------------------------------------------------------------------
    # 2. ANALYZE + FIX -- ask the LLM for remediation per CVE
    # ------------------------------------------------------------------
    base_image = ""
    original_dockerfile = ""
    if dockerfile_path and os.path.isfile(dockerfile_path):
        with open(dockerfile_path) as fh:
            original_dockerfile = fh.read()
        base_image = _extract_base_image(original_dockerfile)

    fixes: list[dict] = []
    fix_suggestions: list[str] = []

    for vuln in critical_high:
        try:
            suggestion = suggest_fix(
                vuln,
                base_image=base_image,
                ollama_url=ollama_url,
                model=model,
            )
        except ConnectionError:
            suggestion = f"Upgrade {vuln.package} to {vuln.fixed_version or 'latest'}"

        fix_record = {
            "cve": vuln.id,
            "severity": vuln.severity,
            "package": vuln.package,
            "installed_version": vuln.installed_version,
            "fixed_version": vuln.fixed_version,
            "suggestion": suggestion,
        }
        fixes.append(fix_record)
        fix_suggestions.append(suggestion)

    # ------------------------------------------------------------------
    # 3. FIX -- patch the Dockerfile
    # ------------------------------------------------------------------
    patched_dockerfile = ""
    if original_dockerfile and fix_suggestions:
        try:
            patched_dockerfile = patch_dockerfile(
                original_dockerfile,
                fix_suggestions,
                ollama_url=ollama_url,
                model=model,
            )
        except ConnectionError:
            patched_dockerfile = "# Could not connect to LLM -- patch manually\n" + original_dockerfile

    # ------------------------------------------------------------------
    # 4. VERIFY -- rebuild and re-scan (optional)
    # ------------------------------------------------------------------
    comparison = None
    verified = False

    if verify and patched_dockerfile and _docker_available():
        with tempfile.TemporaryDirectory() as tmpdir:
            patched_path = os.path.join(tmpdir, "Dockerfile")
            with open(patched_path, "w") as fh:
                fh.write(patched_dockerfile)

            tag = f"{image.split(':')[0]}:patched"
            if _build_image(patched_path, tag):
                new_scan = run_trivy_scan(tag)
                comparison = compare_scans(original_scan, new_scan)
                verified = True

    # ------------------------------------------------------------------
    # 5. REPORT
    # ------------------------------------------------------------------
    return _build_report(
        image=image,
        original_scan=original_scan,
        fixes=fixes,
        patched_dockerfile=patched_dockerfile,
        comparison=comparison,
        docker_available=_docker_available(),
        verified=verified,
    )


def format_agent_report(report: dict) -> str:
    """Public wrapper to format a report dict as markdown."""
    return _format_report(report)
