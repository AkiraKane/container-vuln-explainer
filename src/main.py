#!/usr/bin/env python3
"""Container Vulnerability Explainer — explain Trivy CVEs in plain English using AI."""

import argparse
import json
import sys
import os

from trivy_parser import parse_trivy_json, parse_trivy_output, ScanResult
from llm import explain_vulnerabilities, check_ollama


def _run_agent(args):
    """Execute the scan-fix-verify agent subcommand."""
    from agent import run_agent, format_agent_report

    report = run_agent(
        image=args.image,
        dockerfile_path=args.dockerfile,
        max_fixes=args.max_fixes,
        verify=args.verify,
        ollama_url=args.ollama_url,
        model=args.model,
    )

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_agent_report(report))


def _run_explain(args):
    """Execute the default explain subcommand (original behaviour)."""
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


def main():
    parser = argparse.ArgumentParser(
        description="Container Vulnerability Explainer -- explain & remediate Trivy CVEs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan.json                    # Explain vulnerabilities from JSON file
  %(prog)s scan.json --summary          # Show summary only (no AI)
  %(prog)s scan.json --output json      # Output as JSON
  trivy image nginx | %(prog)s -        # Pipe from trivy
  %(prog)s agent nginx:1.24             # Scan-fix-verify agent loop
        """,
    )
    subparsers = parser.add_subparsers(dest="command")

    # -- explain (default) ------------------------------------------------
    explain_parser = subparsers.add_parser(
        "explain", help="Explain Trivy scan results (default command)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    explain_parser.add_argument("file", help="Path to Trivy JSON output (use '-' for stdin)")
    explain_parser.add_argument("--ollama-url", default="http://localhost:11434",
                                help="Ollama API URL")
    explain_parser.add_argument("--model", default="llama3.2",
                                help="Ollama model to use")
    explain_parser.add_argument("--summary", action="store_true",
                                help="Show summary only (no AI explanation)")
    explain_parser.add_argument("--output", choices=["markdown", "json"],
                                default="markdown", help="Output format")
    explain_parser.add_argument("--max-vulns", type=int, default=50,
                                help="Max vulnerabilities to send to LLM")

    # -- agent ------------------------------------------------------------
    agent_parser = subparsers.add_parser(
        "agent", help="Scan-fix-verify agent loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    agent_parser.add_argument("image", help="Container image to scan")
    agent_parser.add_argument("--dockerfile", default=None,
                              help="Path to the Dockerfile to patch")
    agent_parser.add_argument("--max-fixes", type=int, default=10,
                              help="Maximum number of CVE fixes to process (default: 10)")
    agent_parser.add_argument("--verify", action="store_true",
                              help="Rebuild image and re-scan to verify fixes")
    agent_parser.add_argument("--ollama-url", default="http://localhost:11434",
                              help="Ollama API URL")
    agent_parser.add_argument("--model", default="llama3.2",
                              help="Ollama model to use")
    agent_parser.add_argument("--output", choices=["markdown", "json"],
                              default="markdown", help="Output format")

    # -- legacy mode: if no subcommand is given and first arg is a file ---
    # We check sys.argv to decide whether to fall back to the old interface.
    if len(sys.argv) > 1 and sys.argv[1] not in ("agent", "explain", "-h", "--help"):
        # Legacy mode: treat as "explain <file> ..."
        args = parser.parse_args(["explain"] + sys.argv[1:])
        _run_explain(args)
        return

    args = parser.parse_args()

    if args.command == "agent":
        _run_agent(args)
    elif args.command == "explain":
        _run_explain(args)
    else:
        parser.print_help()

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
