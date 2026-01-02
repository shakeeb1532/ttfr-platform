import argparse

from cli.commands import (
    run_analysis,
    run_detections,
    run_report,
    run_exec_summary,
)


def main():
    parser = argparse.ArgumentParser(
        prog="forensics",
        description="Time-Travel Forensic Analysis Platform",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Replay and analyze an incident")
    analyze.add_argument("input", help="Input JSONL event file")

    detect = sub.add_parser("detect", help="Run retroactive detections")
    detect.add_argument("input", help="Input JSONL event file")

    report = sub.add_parser("report", help="Generate full forensic report")
    report.add_argument("input", help="Input JSONL event file")

    exec_sum = sub.add_parser(
        "exec-summary", help="Generate executive summary"
    )
    exec_sum.add_argument("input", help="Input JSONL event file")

    args = parser.parse_args()

    if args.command == "analyze":
        run_analysis(args.input)
    elif args.command == "detect":
        run_detections(args.input)
    elif args.command == "report":
        run_report(args.input)
    elif args.command == "exec-summary":
        run_exec_summary(args.input)


if __name__ == "__main__":
    main()

