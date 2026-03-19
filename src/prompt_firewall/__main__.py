"""
CLI entry point for prompt-firewall.

Usage::

    python -m prompt_firewall scan "Ignore all previous instructions"
    python -m prompt_firewall proxy --port 8080
    python -m prompt_firewall version
"""
from __future__ import annotations

import argparse
import json
import sys


def cmd_scan(args: argparse.Namespace) -> int:
    from prompt_firewall import PromptFirewall, FirewallConfig
    from prompt_firewall.config import SensitivityLevel

    sensitivity_map = {
        "strict": SensitivityLevel.STRICT,
        "moderate": SensitivityLevel.MODERATE,
        "permissive": SensitivityLevel.PERMISSIVE,
    }

    config = FirewallConfig(sensitivity=sensitivity_map[args.sensitivity])
    fw = PromptFirewall(config)

    if args.text:
        text = args.text
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print("Error: provide text as argument or via stdin", file=sys.stderr)
        return 2

    result = fw.scan(text)

    if args.json:
        print(json.dumps(result.model_dump(), indent=2, default=str))
    else:
        print(result.summary())
        if result.triggered_detectors:
            print(f"\nTriggered detectors: {', '.join(result.triggered_detectors)}")
            print(f"Threat level: {result.threat_level}")

    return 1 if result.blocked else 0


def cmd_proxy(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required for proxy mode: pip install uvicorn", file=sys.stderr)
        return 2

    from prompt_firewall.middleware.openai_proxy import create_proxy_app

    app = create_proxy_app(upstream_url=args.upstream)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    from prompt_firewall import __version__
    print(f"prompt-firewall {__version__}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="prompt-firewall",
        description="🛡️ Protect your LLM applications from prompt injection",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Scan text for prompt injection threats")
    scan_p.add_argument("text", nargs="?", help="Text to scan (or pipe via stdin)")
    scan_p.add_argument("--sensitivity", choices=["strict", "moderate", "permissive"], default="moderate")
    scan_p.add_argument("--json", action="store_true", help="Output JSON")
    scan_p.set_defaults(func=cmd_scan)

    # proxy
    proxy_p = sub.add_parser("proxy", help="Run OpenAI-compatible proxy with firewall")
    proxy_p.add_argument("--host", default="127.0.0.1")
    proxy_p.add_argument("--port", type=int, default=8080)
    proxy_p.add_argument("--upstream", default="https://api.openai.com")
    proxy_p.set_defaults(func=cmd_proxy)

    # version
    ver_p = sub.add_parser("version", help="Print version")
    ver_p.set_defaults(func=cmd_version)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
