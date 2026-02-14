"""Windows Security Log Analyzer.

This script helps SOC teams and defenders collect and analyze Windows
Security log events. It supports two modes:

1. Live mode: queries the local Windows Security event log via PowerShell.
2. Demo mode: loads a crafted XML incident file for offline training.

The output can be rendered as a colored, modern terminal table and
exported to CSV for further analysis.
"""

import argparse
from collections import Counter
from typing import Optional, Sequence, Set, List

from colorama import Fore, Style, init as colorama_init

from models import SecurityEvent, parse_event_ids, parse_levels, normalize_level_name
from presentation import export_events_if_requested, render_events_if_requested
from sources import load_events_for_demo, load_events_for_live, resolve_demo_paths


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="Windows Security Log Analyzer - SOC helper",
    )
    parser.add_argument(
        "--log-name",
        default="Security",
        help="Windows Event Log name to query (default: Security)",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum number of recent events to collect (default: 500)",
    )
    parser.add_argument(
        "--all-events",
        action="store_true",
        help="Show all events instead of only important security events",
    )
    parser.add_argument(
        "--event-ids",
        help="Comma-separated list of event IDs to include (overrides default important set)",
    )
    parser.add_argument(
        "--levels",
        help="Comma-separated list of levels to include (debug,info,warning,error,critical)",
    )
    parser.add_argument(
        "--csv-output",
        help="Path to export filtered events as CSV",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Disable rich table UI; only perform CSV export",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use demo XML incident instead of live Windows event log",
    )
    parser.add_argument(
        "--hide-system-logons",
        action="store_true",
        help="Hide 4624 logons for Local System (S-1-5-18)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output in the terminal",
    )
    return parser


def print_summary(events: Sequence[SecurityEvent]) -> None:
    if not events:
        return
    total = len(events)
    by_category = Counter(e.category for e in events)
    print(Fore.CYAN + Style.BRIGHT + "Summary" + Style.RESET_ALL)
    print(Fore.CYAN + f"Total events: {total}" + Style.RESET_ALL)
    for category, count in by_category.most_common():
        print(Fore.CYAN + f"- {category}: {count}" + Style.RESET_ALL)


def filter_events_by_levels(
    events: Sequence[SecurityEvent],
    levels: Optional[Set[str]],
) -> List[SecurityEvent]:
    if not levels:
        return list(events)
    allowed = levels
    filtered: List[SecurityEvent] = []
    for event in events:
        normalized = normalize_level_name(event.level)
        if normalized in allowed:
            filtered.append(event)
    return filtered


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for the Windows Security Log Analyzer CLI."""

    colorama_init(autoreset=True)
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    important_only = not args.all_events
    event_ids = parse_event_ids(args.event_ids)
    levels = parse_levels(args.levels)
    print(Fore.CYAN + Style.BRIGHT + "Windows Security Log Analyzer" + Style.RESET_ALL)
    try:
        if args.demo:
            print(Fore.CYAN + "Loading events from demo XML incident..." + Style.RESET_ALL)
            demo_dir, _ = resolve_demo_paths()
            events = load_events_for_demo()
            if not args.csv_output:
                args.csv_output = str(demo_dir / "demo.csv")
            source_label = "demo incident"
        else:
            print(Fore.CYAN + "Collecting events from Windows Security log..." + Style.RESET_ALL)
            events = load_events_for_live(
                log_name=args.log_name,
                max_events=args.max_events,
                important_only=important_only,
                event_ids=event_ids,
                hide_system_logons=args.hide_system_logons,
            )
            source_label = f"log '{args.log_name}'"
    except FileNotFoundError as exc:
        print(Fore.RED + str(exc) + Style.RESET_ALL)
        return 1
    except Exception as exc:
        print(Fore.RED + f"Error while collecting events: {exc}" + Style.RESET_ALL)
        return 1
    events = filter_events_by_levels(events, levels)
    if not events:
        print(Fore.YELLOW + "No events found with the current filters." + Style.RESET_ALL)
    else:
        print(
            Fore.GREEN
            + f"Collected {len(events)} event(s) from {source_label}."
            + Style.RESET_ALL
        )
    try:
        export_events_if_requested(events, args.csv_output)
    except Exception as exc:
        print(Fore.RED + f"Failed to export CSV: {exc}" + Style.RESET_ALL)
    render_events_if_requested(
        events,
        show_ui=not args.no_ui,
        vertical=True,
        use_color=not args.no_color,
    )
    print_summary(events)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

