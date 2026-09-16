from __future__ import annotations

import argparse

from zap.reporter import ZapReporter
from zap.scanner import ZapScanner


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run an OWASP ZAP security scan."
    )

    parser.add_argument(
        "--target",
        default=None,
        help=(
            "Target URL. Defaults to the configured "
            "ZAP_TARGET_URL."
        ),
    )

    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable active scanning.",
    )

    parser.add_argument(
        "--active-timeout",
        type=int,
        default=600,
        help=(
            "Maximum number of seconds to wait for the "
            "active scan. Default: 600."
        ),
    )

    args = parser.parse_args()

    if args.active_timeout <= 0:
        parser.error(
            "--active-timeout must be greater than zero."
        )

    scanner = ZapScanner()

    alerts = scanner.run(
        target_url=args.target,
        active=args.active,
        active_timeout=args.active_timeout,
    )

    reporter = ZapReporter()

    json_report = reporter.write_json(alerts)
    markdown_report = reporter.write_markdown(alerts)
    summary_report = reporter.write_summary(alerts)

    print()
    print("ZAP scan completed.")
    print(f"Raw alerts:     {len(alerts)}")
    print(f"JSON report:    {json_report}")
    print(f"Markdown report:{markdown_report}")
    print(f"Summary:        {summary_report}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())