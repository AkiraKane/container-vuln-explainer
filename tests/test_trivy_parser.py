"""Tests for Trivy parser."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest
from trivy_parser import Vulnerability, ScanResult, parse_trivy_json


class TestVulnerability:
    def test_severity_score(self):
        vuln = Vulnerability(id="CVE-2024-1234", severity="CRITICAL", package="test", installed_version="1.0")
        assert vuln.severity_score == 4

    def test_severity_score_high(self):
        vuln = Vulnerability(id="CVE-2024-1234", severity="HIGH", package="test", installed_version="1.0")
        assert vuln.severity_score == 3

    def test_severity_score_medium(self):
        vuln = Vulnerability(id="CVE-2024-1234", severity="MEDIUM", package="test", installed_version="1.0")
        assert vuln.severity_score == 2

    def test_severity_score_low(self):
        vuln = Vulnerability(id="CVE-2024-1234", severity="LOW", package="test", installed_version="1.0")
        assert vuln.severity_score == 1

    def test_severity_score_unknown(self):
        vuln = Vulnerability(id="CVE-2024-1234", severity="UNKNOWN", package="test", installed_version="1.0")
        assert vuln.severity_score == 0


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult(target="test-image")
        assert result.total_count == 0
        assert result.critical_count == 0
        assert result.high_count == 0

    def test_with_vulnerabilities(self):
        result = ScanResult(target="nginx:latest")
        result.vulnerabilities = [
            Vulnerability(id="CVE-2024-001", severity="CRITICAL", package="openssl", installed_version="1.1.1"),
            Vulnerability(id="CVE-2024-002", severity="HIGH", package="curl", installed_version="7.68"),
            Vulnerability(id="CVE-2024-003", severity="MEDIUM", package="bash", installed_version="5.0"),
            Vulnerability(id="CVE-2024-004", severity="LOW", package="tar", installed_version="1.30"),
        ]
        assert result.total_count == 4
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1

    def test_to_prompt(self):
        result = ScanResult(target="nginx:latest")
        result.vulnerabilities = [
            Vulnerability(
                id="CVE-2024-1234",
                severity="CRITICAL",
                package="openssl",
                installed_version="1.1.1",
                fixed_version="1.1.2",
                title="Buffer overflow in OpenSSL"
            )
        ]
        prompt = result.to_prompt()
        assert "nginx:latest" in prompt
        assert "CVE-2024-1234" in prompt
        assert "openssl" in prompt
        assert "1.1.2" in prompt


class TestParseTrivyJson:
    def test_empty_json(self):
        results = parse_trivy_json("{}")
        assert results == []

    def test_invalid_json(self):
        results = parse_trivy_json("not json")
        assert results == []

    def test_valid_trivy_json(self):
        json_str = '''
        {
            "Results": [
                {
                    "Target": "nginx:latest",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "Severity": "CRITICAL",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.2",
                            "Title": "Buffer overflow",
                            "Description": "A buffer overflow vulnerability"
                        }
                    ]
                }
            ]
        }
        '''
        results = parse_trivy_json(json_str)
        assert len(results) == 1
        assert results[0].target == "nginx:latest"
        assert results[0].total_count == 1
        assert results[0].vulnerabilities[0].id == "CVE-2024-1234"
        assert results[0].vulnerabilities[0].severity == "CRITICAL"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
