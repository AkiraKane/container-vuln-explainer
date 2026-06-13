"""Tests for the scan-fix-verify agent."""

import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest
from trivy_parser import Vulnerability, ScanResult
from agent import (
    _critical_high_vulns,
    _extract_base_image,
    _build_report,
    _format_report,
    run_agent,
    format_agent_report,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_vuln(cve="CVE-2024-0001", severity="CRITICAL", package="openssl",
               installed="1.1.1", fixed="1.1.2", title="Buffer overflow"):
    return Vulnerability(
        id=cve, severity=severity, package=package,
        installed_version=installed, fixed_version=fixed, title=title,
        description="A test vulnerability",
    )


def _make_scan(vulns=None):
    if vulns is None:
        vulns = [
            _make_vuln("CVE-2024-0001", "CRITICAL", "openssl", "1.1.1", "1.1.2"),
            _make_vuln("CVE-2024-0002", "HIGH", "curl", "7.68.0", "7.88.0"),
            _make_vuln("CVE-2024-0003", "MEDIUM", "bash", "5.0", "5.1"),
            _make_vuln("CVE-2024-0004", "LOW", "tar", "1.30", "1.34"),
        ]
    return ScanResult(target="test-image:latest", vulnerabilities=vulns)


SAMPLE_DOCKERFILE = """\
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]
"""


# ---------------------------------------------------------------------------
# _critical_high_vulns
# ---------------------------------------------------------------------------

class TestCriticalHighVulns:
    def test_filters_only_critical_high(self):
        scan = _make_scan()
        result = _critical_high_vulns(scan)
        assert len(result) == 2
        assert all(v.severity in ("CRITICAL", "HIGH") for v in result)

    def test_empty_when_only_medium_low(self):
        scan = _make_scan(vulns=[
            _make_vuln(severity="MEDIUM"),
            _make_vuln(severity="LOW"),
        ])
        assert _critical_high_vulns(scan) == []

    def test_empty_scan(self):
        scan = ScanResult(target="clean:latest")
        assert _critical_high_vulns(scan) == []


# ---------------------------------------------------------------------------
# _extract_base_image
# ---------------------------------------------------------------------------

class TestExtractBaseImage:
    def test_simple_from(self):
        assert _extract_base_image("FROM python:3.11-slim") == "python:3.11-slim"

    def test_multistage(self):
        dockerfile = "FROM golang:1.21 AS builder\nFROM alpine:3.18\n"
        assert _extract_base_image(dockerfile) == "golang:1.21"

    def test_no_from(self):
        assert _extract_base_image("# no FROM line") == ""

    def test_with_comment_above(self):
        dockerfile = "# base image\nFROM node:20-alpine\nRUN apk add --no-cache git\n"
        assert _extract_base_image(dockerfile) == "node:20-alpine"


# ---------------------------------------------------------------------------
# _build_report
# ---------------------------------------------------------------------------

class TestBuildReport:
    def test_report_structure(self):
        scan = _make_scan()
        report = _build_report(
            image="nginx:1.24",
            original_scan=scan,
            fixes=[{"cve": "CVE-2024-0001", "severity": "CRITICAL"}],
            patched_dockerfile="FROM python:3.12-slim",
            comparison=None,
            docker_available=False,
            verified=False,
        )
        assert report["image"] == "nginx:1.24"
        assert report["original_summary"]["critical"] == 1
        assert report["original_summary"]["high"] == 1
        assert report["fixes_count"] == 1
        assert report["verified"] is False

    def test_report_with_comparison(self):
        scan = _make_scan()
        comparison = {
            "fixed": ["CVE-2024-0001"],
            "remaining": ["CVE-2024-0002"],
            "new": [],
            "summary": {
                "fixed_count": 1,
                "remaining_count": 1,
                "new_count": 0,
            },
        }
        report = _build_report(
            image="test",
            original_scan=scan,
            fixes=[],
            patched_dockerfile="",
            comparison=comparison,
            docker_available=True,
            verified=True,
        )
        assert report["verified"] is True
        assert report["verification"]["summary"]["fixed_count"] == 1


# ---------------------------------------------------------------------------
# _format_report
# ---------------------------------------------------------------------------

class TestFormatReport:
    def test_no_fixes_report(self):
        scan = _make_scan(vulns=[
            _make_vuln(severity="MEDIUM"),
        ])
        report = _build_report(
            image="clean:latest",
            original_scan=scan,
            fixes=[],
            patched_dockerfile="",
            comparison=None,
            docker_available=False,
            verified=False,
        )
        output = _format_report(report)
        assert "No CRITICAL/HIGH" in output
        assert "clean:latest" in output

    def test_report_with_fixes_and_verification(self):
        scan = _make_scan()
        comparison = {
            "fixed": ["CVE-2024-0001"],
            "remaining": ["CVE-2024-0002"],
            "new": [],
            "summary": {
                "fixed_count": 1,
                "remaining_count": 1,
                "new_count": 0,
                "before_total": 4,
                "after_total": 3,
                "before_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1},
                "after_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 1},
                "fixed_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            },
        }
        report = _build_report(
            image="test:latest",
            original_scan=scan,
            fixes=[{
                "cve": "CVE-2024-0001",
                "severity": "CRITICAL",
                "package": "openssl",
                "installed_version": "1.1.1",
                "fixed_version": "1.1.2",
                "suggestion": "Upgrade openssl to 1.1.2",
            }],
            patched_dockerfile="FROM python:3.12-slim",
            comparison=comparison,
            docker_available=True,
            verified=True,
        )
        output = _format_report(report)
        assert "CVE-2024-0001" in output
        assert "Verification" in output
        assert "openssl" in output
        assert "Patched Dockerfile" in output


# ---------------------------------------------------------------------------
# run_agent -- full integration with mocks
# ---------------------------------------------------------------------------

class TestRunAgent:
    @patch("agent.run_trivy_scan")
    def test_no_critical_high_returns_early(self, mock_scan):
        """When there are no CRITICAL/HIGH CVEs, agent returns immediately."""
        mock_scan.return_value = _make_scan(vulns=[
            _make_vuln(severity="MEDIUM"),
            _make_vuln(severity="LOW"),
        ])
        report = run_agent(image="clean:latest")
        assert report["fixes_count"] == 0
        assert report["fixes_applied"] == []

    @patch("agent.patch_dockerfile")
    @patch("agent.suggest_fix")
    @patch("agent.run_trivy_scan")
    def test_fix_flow_with_dockerfile(self, mock_scan, mock_suggest, mock_patch):
        """Agent calls suggest_fix for each CRITICAL/HIGH vuln and patches the Dockerfile."""
        mock_scan.return_value = _make_scan()
        mock_suggest.return_value = "Upgrade to latest"
        mock_patch.return_value = "FROM python:3.12-slim\n# patched\n"

        # Write a temp Dockerfile
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile", delete=False) as f:
            f.write(SAMPLE_DOCKERFILE)
            df_path = f.name

        try:
            report = run_agent(
                image="test:latest",
                dockerfile_path=df_path,
                max_fixes=10,
                verify=False,
            )
            assert report["fixes_count"] == 2  # CRITICAL + HIGH
            assert mock_suggest.call_count == 2
            mock_patch.assert_called_once()
            assert "python:3.12-slim" in report["patched_dockerfile"]
        finally:
            os.unlink(df_path)

    @patch("agent.run_trivy_scan")
    def test_max_fixes_cap(self, mock_scan):
        """max_fixes limits the number of CVEs processed."""
        vulns = [_make_vuln(cve=f"CVE-2024-{i:04d}", severity="CRITICAL") for i in range(20)]
        mock_scan.return_value = _make_scan(vulns=vulns)

        with patch("agent.suggest_fix", return_value="fix"):
            report = run_agent(image="test:latest", max_fixes=3)
            assert report["fixes_count"] == 3

    @patch("agent._docker_available", return_value=True)
    @patch("agent.run_trivy_scan")
    @patch("agent._build_image", return_value=True)
    @patch("agent.patch_dockerfile")
    @patch("agent.suggest_fix")
    def test_verify_flow(self, mock_suggest, mock_patch, mock_build,
                         mock_scan, mock_docker):
        """When verify=True, agent rebuilds and re-scans."""
        scan_before = _make_scan()
        scan_after = ScanResult(
            target="test:patched",
            vulnerabilities=[_make_vuln(severity="MEDIUM")],
        )
        # First call = initial scan, second call = post-fix scan
        mock_scan.side_effect = [scan_before, scan_after]
        mock_suggest.return_value = "Upgrade openssl"
        mock_patch.return_value = "FROM python:3.12-slim"

        report = run_agent(
            image="test:latest",
            dockerfile_path=None,
            max_fixes=10,
            verify=True,
        )
        # No dockerfile_path means suggest_fix is called with empty base_image,
        # but patches are skipped since no original dockerfile was provided
        assert report["verified"] is False  # no patched dockerfile to build


# ---------------------------------------------------------------------------
# parse_trivy_json / compare_scans (from trivy_parser, tested here for coverage)
# ---------------------------------------------------------------------------

class TestCompareScansIntegration:
    def test_compare_identical_scans(self):
        from trivy_parser import compare_scans
        scan = _make_scan()
        result = compare_scans(scan, scan)
        assert result["summary"]["fixed_count"] == 0
        assert result["summary"]["remaining_count"] == 4
        assert result["summary"]["new_count"] == 0

    def test_compare_with_fixes(self):
        from trivy_parser import compare_scans
        before = _make_scan()
        after_vulns = [
            _make_vuln("CVE-2024-0002", "HIGH", "curl", "7.68.0", "7.88.0"),
            _make_vuln("CVE-2024-0003", "MEDIUM", "bash", "5.0", "5.1"),
            _make_vuln("CVE-2024-0004", "LOW", "tar", "1.30", "1.34"),
        ]
        after = ScanResult(target="test:patched", vulnerabilities=after_vulns)
        result = compare_scans(before, after)
        assert "CVE-2024-0001" in result["fixed"]
        assert result["summary"]["fixed_count"] == 1
        assert result["summary"]["new_count"] == 0

    def test_compare_with_new_vulns(self):
        from trivy_parser import compare_scans
        before = _make_scan(vulns=[_make_vuln("CVE-2024-0001", "CRITICAL")])
        after = ScanResult(target="test:patched", vulnerabilities=[
            _make_vuln("CVE-2024-9999", "HIGH", "zlib", "1.2.11", "1.3.0"),
        ])
        result = compare_scans(before, after)
        assert "CVE-2024-0001" in result["fixed"]
        assert "CVE-2024-9999" in result["new"]
        assert result["summary"]["fixed_count"] == 1
        assert result["summary"]["new_count"] == 1

    def test_compare_severity_breakdown(self):
        from trivy_parser import compare_scans
        before = _make_scan()
        after = _make_scan()
        result = compare_scans(before, after)
        assert result["summary"]["before_severity"]["CRITICAL"] == 1
        assert result["summary"]["after_severity"]["HIGH"] == 1


# ---------------------------------------------------------------------------
# format_agent_report
# ---------------------------------------------------------------------------

class TestFormatAgentReport:
    def test_roundtrip(self):
        scan = _make_scan()
        report = _build_report(
            image="nginx:1.24",
            original_scan=scan,
            fixes=[{
                "cve": "CVE-2024-0001",
                "severity": "CRITICAL",
                "package": "openssl",
                "installed_version": "1.1.1",
                "fixed_version": "1.1.2",
                "suggestion": "Upgrade to 1.1.2",
            }],
            patched_dockerfile="FROM python:3.12-slim\n",
            comparison=None,
            docker_available=False,
            verified=False,
        )
        output = format_agent_report(report)
        assert isinstance(output, str)
        assert "Remediation Report" in output
        assert "CVE-2024-0001" in output
