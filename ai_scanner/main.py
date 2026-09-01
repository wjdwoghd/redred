"""Command-line entry point for REDRED capture analysis."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

try:
    from .config import ScannerConfig
    from .active_scanner import ActiveScanOptions, ActiveScanner
    from .exceptions import AIClientError, ConfigurationError, InputError, ScannerError
    from .finalize import finalize_scan
    from .review_cli import review_scan
    from .logging_config import configure_logging
    from .pipeline import run_pipeline
    from .raw_http_parser import load_raw_scan_input
    from .scan_scope import ScopeError, validate_target
    from .result_store import ResultStoreError
except ImportError:  # ``python main.py`` from ai_scanner/
    from config import ScannerConfig
    from active_scanner import ActiveScanOptions, ActiveScanner
    from exceptions import AIClientError, ConfigurationError, InputError, ScannerError
    from finalize import finalize_scan
    from review_cli import review_scan
    from logging_config import configure_logging
    from pipeline import run_pipeline
    from raw_http_parser import load_raw_scan_input
    from scan_scope import ScopeError, validate_target
    from result_store import ResultStoreError


LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build the small, script-friendly CLI argument parser."""

    parser = argparse.ArgumentParser(description="REDRED AI vulnerability analysis pipeline")
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--input", help="capture JSON path")
    source.add_argument("--request", help="raw HTTP request text path")
    parser.add_argument("--target", help="local training-server URL for active scanning")
    parser.add_argument("--finalize", help="human review JSON to finalize a scan")
    parser.add_argument("--review", help="interactive human review JSON editor")
    parser.add_argument("--scan", action="store_true", help="crawl target and run safe active probes")
    parser.add_argument("--scan-mode", choices=("single", "endpoint", "crawl"), default="crawl", help="active scan scope: one page, same-path endpoint functions, or same-origin crawl")
    parser.add_argument("--cookie", help="session Cookie header for active scanning")
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--delay-ms", type=int, default=350)
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout for active scan")
    parser.add_argument("--max-tests", type=int, default=100)
    parser.add_argument("--response", help="raw HTTP response text path (required with --request)")
    parser.add_argument("--baseline-request", help="raw baseline request text path")
    parser.add_argument("--baseline-response", help="raw baseline response text path")
    parser.add_argument("--verification-request", help="raw verification request text path")
    parser.add_argument("--verification-response", help="raw verification response text path")
    parser.add_argument("--mode", choices=("auto", "ai", "rules"), default=None)
    parser.add_argument("--output-dir", default=None, help="artifact directory (default: results/)")
    parser.add_argument("--verbose", action="store_true", help="enable debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a stable exit code for automation."""

    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)
    try:
        config = ScannerConfig.from_env(Path(__file__).resolve().parent)
        if args.finalize or args.review:
            if args.finalize and args.review:
                raise InputError("--finalize and --review are mutually exclusive")
            if any((args.scan, args.input, args.request, args.target)):
                raise InputError("--finalize/--review cannot be combined with scan/input/request/target")
            if args.review:
                review_scan(args.review)
                print(f"[+] Review JSON updated: {Path(args.review).resolve()}")
                return 0
            result = finalize_scan(args.finalize, config=config)
            print(f"[+] Final report generated: {result['root_directory'] / 'final_report.md'}")
            print(f"[+] Secure coding guide generated: {result['root_directory'] / 'secure_coding_guide.md'}")
            for pdf_name in ("final_report.pdf", "secure_coding_guide.pdf"):
                pdf_path = result["root_directory"] / pdf_name
                if pdf_path.exists():
                    print(f"[+] PDF generated: {pdf_path}")
            return 0
        if args.scan:
            if not args.target or args.input or args.request:
                raise InputError("--scan requires --target and cannot be combined with --input/--request")
            validated_target = validate_target(args.target)
            active = ActiveScanner(config=config, options=ActiveScanOptions(max_depth=args.max_depth, max_pages=args.max_pages, delay_ms=args.delay_ms, max_tests=args.max_tests, timeout=args.timeout, scan_mode=args.scan_mode))
            print(f"[+] Target validated: {validated_target}")
            print("[+] Crawling started")
            result = active.scan(validated_target, mode=args.mode, cookie=args.cookie)
            print(f"[+] Pages scanned: {len(result.crawl.pages)}")
            print(f"[+] Forms discovered: {len(result.crawl.forms)}")
            print(f"[+] Inputs tested: {result.summary['inputs_tested']}")
            print(f"[+] Active scan summary: {result.root_directory / 'scan_summary.json'}")
            print(f"[+] Diagnostic analysis: {result.root_directory / 'analysis.json'}")
            print(f"[+] Diagnostic guide: {result.root_directory / 'diagnostic_guide.md'}")
            diagnostic_pdf = result.root_directory / "diagnostic_guide.pdf"
            if diagnostic_pdf.exists():
                print(f"[+] Diagnostic PDF: {diagnostic_pdf}")
            print(f"[+] Review template: {result.root_directory / 'review.json'}")
            return 0
        if not args.input and not args.request:
            raise InputError("one of --input, --request or --target --scan is required")
        if args.target:
            raise InputError("--target must be combined with --scan")
        if args.request and not args.response:
            raise InputError("--response is required when --request is used")
        if args.response and not args.request:
            raise InputError("--request is required when --response is used")
        if args.request:
            scan_source = load_raw_scan_input(
                args.request,
                args.response,
                baseline_request_path=args.baseline_request,
                baseline_response_path=args.baseline_response,
                verification_request_path=args.verification_request,
                verification_response_path=args.verification_response,
                max_file_bytes=config.max_input_file_bytes,
            )
        else:
            for label, request_file, response_file in (
                ("baseline", args.baseline_request, args.baseline_response),
                ("verification", args.verification_request, args.verification_response),
            ):
                if request_file or response_file:
                    raise InputError(f"{label} raw options require --request/--response mode")
            scan_source = args.input
        print("[+] HTTP Request loaded")
        outcome = run_pipeline(
            scan_source,
            config=config,
            mode=args.mode,
            output_directory=args.output_dir,
        )
        print(f"[+] Parameters extracted: {len(outcome.candidates)}")
        print("[+] Response indicators analyzed")
        print("[+] AI vulnerability analysis started")
        print("[+] Analysis completed")
        for finding in outcome.analysis.findings:
            print(f"\nVulnerability : {finding.vulnerability_type.value}")
            print(f"Parameter     : {finding.location.parameter or '-'}")
            print(f"Severity      : {finding.severity.value}")
            print(f"Confidence    : {finding.confidence:.0%}")
            print(f"Status        : {finding.status.value}")
        print(f"\n[+] JSON saved: {outcome.artifacts.analysis_json}")
        print(f"[+] Report generated: {outcome.artifacts.report_markdown}")
        return 0
    except (InputError, ConfigurationError) as exc:
        LOGGER.error("input/configuration error: %s", exc)
        return 2
    except ScopeError as exc:
        LOGGER.error("scope error: %s", exc)
        return 2
    except (AIClientError,) as exc:
        LOGGER.error("AI analysis error: %s", exc)
        return 3
    except ResultStoreError as exc:
        LOGGER.error("artifact I/O error: %s", exc)
        return 4
    except ScannerError as exc:
        LOGGER.error("scanner error: %s", exc)
        return 5
    except Exception:
        LOGGER.exception("unexpected scanner error")
        return 5


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
