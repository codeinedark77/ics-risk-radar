"""CLI entrypoint:
  ics-risk-radar scan <inventory.yaml> [--out report.json]
                       [--telemetry telemetry.json] [--sarif-out findings.sarif]

telemetry.json (optional) is {"asset_id": [float, float, ...], ...}.
"""

from __future__ import annotations

import argparse
import json
import sys

from .inventory import AssetInventory
from .report import build_report
from .risk_engine import RiskEngine
from .sarif import write_sarif


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ics-risk-radar")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Scan an inventory YAML file and print/write a risk report",
    )
    scan.add_argument("inventory", help="Path to inventory YAML file")
    scan.add_argument(
        "--out", help="Write JSON report to this path instead of stdout"
    )
    scan.add_argument(
        "--telemetry", help="Path to a JSON file of {asset_id: [values...]}"
    )
    scan.add_argument(
        "--sarif-out", help="Also write findings as SARIF 2.1.0 to this path"
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        inv = AssetInventory.from_yaml(args.inventory)

        telemetry = None
        if args.telemetry:
            with open(args.telemetry) as fh:
                telemetry = json.load(fh)

        report = build_report(inv, telemetry=telemetry)

        if args.sarif_out:
            write_sarif(RiskEngine(inv).findings(), args.sarif_out)
            print(f"SARIF written to {args.sarif_out}")

        text = json.dumps(report, indent=2, default=str)
        if args.out:
            with open(args.out, "w") as fh:
                fh.write(text)
            print(f"Report written to {args.out}")
        else:
            print(text)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
