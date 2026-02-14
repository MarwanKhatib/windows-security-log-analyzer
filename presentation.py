"""Presentation helpers for terminal UI and CSV export."""

import csv
from textwrap import wrap
from typing import Iterable, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models import SecurityEvent, normalize_level_name


def truncate(text: str, max_length: int) -> str:
    """Return a truncated version of text limited to max_length characters."""

    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def color_for_event(event: SecurityEvent, use_color: bool) -> str:
    """Return a rich style name for an event based on its level."""

    if not use_color:
        return ""
    level = normalize_level_name(event.level)
    if level == "debug":
        return "bright_magenta"
    if level == "info":
        return "bright_cyan"
    if level == "warning":
        return "bright_yellow"
    if level == "error":
        return "bright_red"
    if level == "critical":
        return "bright_red"
    return ""


def render_table(events: Iterable[SecurityEvent], use_color: bool) -> None:
    """Render security events as a rich table in the terminal."""

    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Time", style="dim", width=20)
    table.add_column("ID", style="bold")
    table.add_column("Level")
    table.add_column("Category")
    table.add_column("Provider")
    table.add_column("Message", overflow="crop")
    for event in events:
        style = color_for_event(event, use_color)
        time_str = event.time_created.strftime("%Y-%m-%d %H:%M:%S")
        id_str = f"{event.event_id}"
        level_str = event.level or "-"
        category_str = event.category
        provider_str = truncate(event.provider or "-", 20)
        message_str = truncate(event.message or "-", 80)
        id_text = Text(id_str, style=style) if style else Text(id_str)
        level_text = Text(level_str, style=style) if style else Text(level_str)
        category_text = Text(category_str, style=style) if style else Text(category_str)
        table.add_row(
            time_str,
            id_text,
            level_text,
            category_text,
            provider_str,
            message_str,
        )
    console.print(table)


def render_vertical(events: Iterable[SecurityEvent], use_color: bool) -> None:
    """Render security events as vertical cards with key/value pairs."""

    console = Console()
    for event in events:
        severity_style = color_for_event(event, use_color)
        key_style = "bold white" if use_color else ""
        value_style = severity_style if use_color else ""
        time_str = event.time_created.strftime("%Y-%m-%d %H:%M:%S")
        provider = event.provider or "-"
        machine = event.machine_name or "-"
        message = event.message or "-"
        message = " ".join(message.split())
        wrapped_lines = wrap(message, width=80)
        text = Text()

        def add_kv(key: str, value: str) -> None:
            if key_style:
                text.append(f"{key}: ", style=key_style)
            else:
                text.append(f"{key}: ")
            if value_style:
                text.append(f"{value}\n", style=value_style)
            else:
                text.append(f"{value}\n")

        add_kv("Time", time_str)
        add_kv("ID", str(event.event_id))
        add_kv("Level", event.level or "-")
        add_kv("Category", event.category)
        add_kv("Provider", provider)
        add_kv("Machine", machine)
        if key_style:
            text.append("Message:\n", style=key_style)
        else:
            text.append("Message:\n")
        for line in wrapped_lines:
            text.append(f"  {line}\n", style=value_style or "")

        panel = Panel(text, border_style=severity_style or "", expand=False)
        console.print(panel)


def export_to_csv(events: Iterable[SecurityEvent], path: str) -> None:
    """Export security events to a CSV file at the given path."""

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "time_created",
                "event_id",
                "level",
                "category",
                "provider",
                "machine_name",
                "message",
            ]
        )
        for event in events:
            writer.writerow(
                [
                    event.time_created.isoformat(),
                    event.event_id,
                    event.level,
                    event.category,
                    event.provider,
                    event.machine_name,
                    event.message,
                ]
            )


def export_events_if_requested(events: List[SecurityEvent], csv_output: Optional[str]) -> None:
    """Export events to CSV if a path is provided."""

    if not csv_output:
        return
    export_to_csv(events, csv_output)
    print(f"Exported {len(events)} event(s) to CSV file: {csv_output}")


def render_events_if_requested(
    events: List[SecurityEvent],
    show_ui: bool,
    vertical: bool = False,
    use_color: bool = True,
) -> None:
    """Render events in the terminal if UI is enabled."""

    if not show_ui or not events:
        return
    if vertical:
        render_vertical(events, use_color)
    else:
        render_table(events, use_color)
