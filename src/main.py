#!/usr/bin/env python3
"""Container Vulnerability Explainer — explain Trivy CVEs in plain English using AI."""

import argparse
import sys
import os

from trivy_parser import parse_trivy_json, parse_trivy_output, ScanResult
from llm import explain_vulnerabilities, check_ollama


def main():
    parser = argparse.ArgumentParser(
        description="Explain Trivy CVE scan results in plain English using AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan.json                    # Explain vulnerabilities from JSON file
  %(prog)s scan.json --summary          # Show summary only (no AI)
  %(prog)s scan.json --output json      # Output as JSON
  trivy image nginx | %(prog)s -        # Pipe from trivy
        """,
    )
    parser.add_argument("file", help="Path to Trivy JSON output (use '-' for stdin)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Ollama API URL")
    parser.add_argument("--model", default="llama3.2",
                        help="Ollama model to use")
    parser.add_argument("--summary", action="store_true",
                        help="Show summary only (no AI explanation)")
    parser.add_argument("--output", choices=["markdown", "json"],
                        default="markdown", help="Output format")
    parser.add_argument("--max-vulns", type=int, default=50,
                        help="Max vulnerabilities to send to LLM")

    args = parser.parse_args()

    # Read input
    if args.file == "-":
        content = sys.stdin.read()
    else:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file) as f:
            content = f.read()

    # Parse Trivy output
    results = parse_trivy_json(content) if content.strip().startswith("{") else parse_trivy_output(content)

    if not results:
        print("Error: No vulnerabilities found or invalid Trivy output.", file=sys.stderr)
        sys.exit(1)

    # Show summary
    for result in results:
        print(f"Target: {result.target}")
        print(f"Vulnerabilities: {result.total_count}")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {result.medium_count}")
        print(f"  Low: {result.low_count}")
        print()

    # Summary only
    if args.summary:
        for result in results:
            print(result.to_prompt())
        return

    # JSON output
    if args.output == "json":
        import json
        data = []
        for result in results:
            data.append({
                "target": result.target,
                "total": result.total_count,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "severity": v.severity,
                        "package": v.package,
                        "installed_version": v.installed_version,
                        "fixed_version": v.fixed_version,
                        "title": v.title,
                    }
                    for v in result.vulnerabilities[:args.max_vulns]
                ]
            })
        print(json.dumps(data, indent=2))
        return

    # Check Ollama
    if not check_ollama(args.ollama_url):
        if not os.environ.get("OPENAI_API_KEY"):
            print("Error: Neither Ollama nor OPENAI_API_KEY available.",
                  file=sys.stderr)
            print("Use --summary to see data without AI.", file=sys.stderr)
            sys.exit(1)

    # Generate explanation
    for result in results:
        print(f"Analyzing {result.target}...")
        # Limit vulns to avoid context window issues
        limited_result = ScanResult(
            target=result.target,
            vulnerabilities=result.vulnerabilities[:args.max_vulns]
        )

        try:
            explanation = explain_vulnerabilities(
                limited_result.to_prompt(),
                ollama_url=args.ollama_url,
                model=args.model,
            )
        except ConnectionError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        print(explanation)
        print()


if __name__ == "__main__":
    main()
