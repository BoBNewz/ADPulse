import argparse
import os
from typing import List

from src.evtx_parser import load_evtx_events
from src.rules_engine import RuleEngine, DetectionResult


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analysis of EVTX files for detecting Active Directory attacks using YAML rules."
    )
    parser.add_argument(
        "--evtx-path",
        default="./evtx/",
        help="Directory containing the EVTX files to analyze (default: ./evtx/).",
    )
    parser.add_argument(
        "--rules-path",
        default="./rules/",
        help="Directory containing the YAML rule files (default: ./rules/).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Displays detailed information about the detections.",
    )
    return parser.parse_args()


def print_table(detections: List[DetectionResult]) -> None:
    if not detections:
        print("No detections found.")
        return

    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box

        console = Console()
        table = Table(title="AD Attack Detections", box=box.HEAVY, show_lines=False)

        table.add_column("Attack", style="cyan", no_wrap=True)
        table.add_column("Score", justify="right", no_wrap=True)
        table.add_column("Date/Time", style="green")
        table.add_column("Source IP", style="yellow")
        table.add_column("User", style="blue")
        table.add_column("Details", style="white")

        def score_cell(score: int) -> str:
            if score >= 90:
                color = "red"
            elif score >= 80:
                color = "orange3"
            elif score >= 60:
                color = "yellow"
            else:
                color = "magenta"
            return f"[{color}]{score}%[/{color}]"

        for d in detections:
            table.add_row(
                d.attack_name,
                score_cell(d.score),
                d.timestamp or "",
                d.ip or "",
                d.user or "",
                d.details or "",
            )

        console.print(table)
        return
    except ModuleNotFoundError:
        pass

    # Fallback sans dépendance externe
    headers = ["Attack", "Score", "Date/Time", "Source IP", "User", "Details"]
    rows = []
    for d in detections:
        rows.append(
            [
                d.attack_name,
                f"{d.score}%",
                d.timestamp or "",
                d.ip or "",
                d.user or "",
                d.details or "",
            ]
        )

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(cell))

    def fmt(values):
        return " | ".join(values[i].ljust(col_widths[i]) for i in range(len(values)))

    sep = "-+-".join("-" * w for w in col_widths)
    print(fmt(headers))
    print(sep)
    for r in rows:
        print(fmt(r))


def main() -> None:
    args = parse_args()

    evtx_dir = args.evtx_path
    rules_dir = args.rules_path

    if not os.path.isdir(evtx_dir):
        raise SystemExit(f"The EVTX directory does not exist: {evtx_dir}")

    if not os.path.isdir(rules_dir):
        raise SystemExit(f"The rules directory does not exist: {rules_dir}")

    print("AD-EVTX-Analyzer")
    print(f"Analyzing EVTX files from: {evtx_dir}")
    print(f"Rules loaded from: {rules_dir}")

    events, stats = load_evtx_events(evtx_dir, verbose=args.verbose)
    total_events = int(stats.get("total_events", len(events)))
    total_files = int(stats.get("total_files", 0))
    print(f"\nEVTX loaded: {total_files} file(s)")
    print(f"Total events: {total_events}")

    engine = RuleEngine(rules_directory=rules_dir, verbose=args.verbose)
    print(f"Rules loaded: {len(engine.rules)}")
    for r in engine.rules:
        rname = r.get("name") or r.get("id")
        if rname:
            print(f"Rule loaded: {rname}")
    detections = engine.run(events)

    threshold = 20 if args.verbose else 60
    detections_filtered = [d for d in detections if d.score >= threshold]

    print_table(detections_filtered)
    print(f"\nTotal: {len(detections_filtered)} detection(s)")


if __name__ == "__main__":
    main()

