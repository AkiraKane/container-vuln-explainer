"""Parse Trivy scan output into structured vulnerability data."""

import json
from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    """A single CVE vulnerability."""
    id: str  # CVE-YYYY-NNNN
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    package: str
    installed_version: str
    fixed_version: str = ""
    title: str = ""
    description: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def severity_score(self) -> int:
        """Numeric score for sorting (higher = more severe)."""
        scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return scores.get(self.severity, 0)


@dataclass
class ScanResult:
    """Parsed Trivy scan results."""
    target: str  # image name or filesystem path
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "LOW")

    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)

    def to_prompt(self) -> str:
        """Convert to prompt for LLM explanation."""
        parts = [
            f"Target: {self.target}",
            f"Total vulnerabilities: {self.total_count}",
            f"  Critical: {self.critical_count}",
            f"  High: {self.high_count}",
            f"  Medium: {self.medium_count}",
            f"  Low: {self.low_count}",
            "",
        ]

        # Group by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            vulns = [v for v in self.vulnerabilities if v.severity == severity]
            if not vulns:
                continue

            parts.append(f"## {severity} ({len(vulns)})")
            parts.append("")

            for v in vulns[:20]:  # Limit per severity
                parts.append(f"### {v.id}")
                parts.append(f"Package: {v.package} ({v.installed_version})")
                if v.fixed_version:
                    parts.append(f"Fixed in: {v.fixed_version}")
                if v.title:
                    parts.append(f"Title: {v.title}")
                if v.description:
                    # Truncate long descriptions
                    desc = v.description[:300]
                    if len(v.description) > 300:
                        desc += "..."
                    parts.append(f"Description: {desc}")
                parts.append("")

            if len(vulns) > 20:
                parts.append(f"... and {len(vulns) - 20} more {severity} vulnerabilities")
                parts.append("")

        return "\n".join(parts)


def parse_trivy_json(json_str: str) -> list[ScanResult]:
    """Parse Trivy JSON output."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return []

    results = []

    # Handle Trivy v2 JSON format
    if "Results" in data:
        for result_data in data["Results"]:
            result = ScanResult(target=result_data.get("Target", "unknown"))

            for vuln_data in result_data.get("Vulnerabilities", []):
                vuln = Vulnerability(
                    id=vuln_data.get("VulnerabilityID", ""),
                    severity=vuln_data.get("Severity", "UNKNOWN"),
                    package=vuln_data.get("PkgName", ""),
                    installed_version=vuln_data.get("InstalledVersion", ""),
                    fixed_version=vuln_data.get("FixedVersion", ""),
                    title=vuln_data.get("Title", ""),
                    description=vuln_data.get("Description", ""),
                    references=vuln_data.get("PrimaryURL", []),
                )
                result.vulnerabilities.append(vuln)

            # Sort by severity
            result.vulnerabilities.sort(key=lambda v: v.severity_score, reverse=True)
            results.append(result)

    return results


def parse_trivy_output(output: str) -> list[ScanResult]:
    """Parse Trivy text or JSON output."""
    # Try JSON first
    if output.strip().startswith("{"):
        return parse_trivy_json(output)

    # Parse text output (simplified)
    results = []
    current_target = "unknown"
    current_vulns = []

    for line in output.split("\n"):
        line = line.strip()

        # Detect target (image name or file)
        if line.startswith("Total:") or line.startswith("┌"):
            continue

        # Parse vulnerability lines (Trivy table format)
        if "|" in line and "CVE-" in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 4:
                vuln = Vulnerability(
                    id=parts[0] if "CVE-" in parts[0] else "",
                    severity=parts[1] if parts[1] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN",
                    package=parts[2] if len(parts) > 2 else "",
                    installed_version=parts[3] if len(parts) > 3 else "",
                    fixed_version=parts[4] if len(parts) > 4 else "",
                )
                if vuln.id:
                    current_vulns.append(vuln)

    if current_vulns:
        result = ScanResult(target=current_target, vulnerabilities=current_vulns)
        results.append(result)

    return results


def run_trivy_scan(target: str, scan_type: str = "image") -> str:
    """Run Trivy scan and return JSON output."""
    import subprocess

    cmd = ["trivy", "scan", "--format", "json"]

    if scan_type == "image":
        cmd.extend(["--image", target])
    elif scan_type == "filesystem":
        cmd.extend(["--path", target])
    elif scan_type == "repo":
        cmd.extend(["--repo", target])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except FileNotFoundError:
        return '{"error": "Trivy not installed. Install: https://aquasecurity.github.io/trivy/"}'
    except subprocess.TimeoutExpired:
        return '{"error": "Trivy scan timed out (5 minutes)"}'
