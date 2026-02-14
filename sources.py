"""Event sources (live Windows log and demo XML) for the analyzer."""

import platform
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Sequence, Set

from models import IMPORTANT_EVENT_IDS, SecurityEvent, categorize_event, parse_time

try:
    import win32con  # type: ignore
    import win32evtlog  # type: ignore
except Exception:  # pragma: no cover
    win32con = None  # type: ignore
    win32evtlog = None  # type: ignore


def is_windows() -> bool:
    """Return True if the current operating system is Windows."""

    return platform.system().lower() == "windows"


def get_raw_events(log_name: str, max_events: int) -> List[dict]:
    """Read raw events from a Windows event log and return them as dictionaries."""

    if not is_windows():
        raise RuntimeError("Windows Security Log Analyzer must be run on Windows")
    if win32evtlog is None or win32con is None:
        raise RuntimeError("pywin32 is required for live collection; install it with 'pip install pywin32'")
    handle = win32evtlog.OpenEventLog(None, log_name)  # type: ignore[arg-type]
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ  # type: ignore[operator]
    events: List[dict] = []
    read_total = 0
    try:
        while read_total < max_events:
            records = win32evtlog.ReadEventLog(handle, flags, 0)  # type: ignore[arg-type]
            if not records:
                break
            for record in records:
                event_id = int(record.EventID & 0xFFFF)
                level_type = record.EventType
                if level_type == win32con.EVENTLOG_ERROR_TYPE:  # type: ignore[union-attr]
                    level = "Error"
                elif level_type == win32con.EVENTLOG_WARNING_TYPE:  # type: ignore[union-attr]
                    level = "Warning"
                elif level_type == win32con.EVENTLOG_INFORMATION_TYPE:  # type: ignore[union-attr]
                    level = "Information"
                elif level_type == win32con.EVENTLOG_AUDIT_FAILURE:  # type: ignore[union-attr]
                    level = "Warning"
                elif level_type == win32con.EVENTLOG_AUDIT_SUCCESS:  # type: ignore[union-attr]
                    level = "Information"
                else:
                    level = "Information"
                provider = record.SourceName or ""
                machine_name = record.ComputerName or ""
                inserts = record.StringInserts or []
                message = " ".join(inserts)
                time_created = record.TimeGenerated.isoformat()
                events.append(
                    {
                        "TimeCreated": time_created,
                        "Id": event_id,
                        "LevelDisplayName": level,
                        "ProviderName": provider,
                        "MachineName": machine_name,
                        "Message": message,
                    }
                )
                read_total += 1
                if read_total >= max_events:
                    break
    finally:
        win32evtlog.CloseEventLog(handle)  # type: ignore[arg-type]
    return events


def normalize_event(raw: dict) -> Optional[SecurityEvent]:
    """Convert a raw event dictionary into a SecurityEvent instance."""

    try:
        event_id = int(raw.get("Id"))
    except (TypeError, ValueError):
        return None
    time_created_raw = None
    time_created_value = raw.get("TimeCreated")
    if isinstance(time_created_value, str):
        time_created_raw = time_created_value
    elif isinstance(time_created_value, dict):
        time_created_raw = time_created_value.get("DateTime")
    time_created = parse_time(time_created_raw)
    level = str(raw.get("LevelDisplayName") or "")
    provider = str(raw.get("ProviderName") or "")
    machine_name = str(raw.get("MachineName") or "")
    message = str(raw.get("Message") or "").replace("\r\n", " ").replace("\n", " ")
    category = categorize_event(event_id)
    return SecurityEvent(
        time_created=time_created,
        event_id=event_id,
        level=level,
        provider=provider,
        machine_name=machine_name,
        message=message,
        category=category,
    )


def collect_events(
    log_name: str,
    max_events: int,
    important_only: bool,
    event_ids: Optional[Sequence[int]] = None,
    hide_system_logons: bool = False,
) -> List[SecurityEvent]:
    """Collect and normalize events from a Windows event log."""

    if not is_windows():
        raise RuntimeError("Windows Security Log Analyzer must be run on Windows")
    ids_filter: Optional[Set[int]] = None
    if important_only and event_ids:
        ids_filter = set(event_ids)
    elif important_only:
        ids_filter = IMPORTANT_EVENT_IDS
    raw_events = get_raw_events(log_name, max_events)
    events: List[SecurityEvent] = []
    for raw in raw_events:
        normalized = normalize_event(raw)
        if not normalized:
            continue
        if hide_system_logons and normalized.event_id == 4624:
            msg_lower = normalized.message.lower()
            if "s-1-5-18 system nt authority" in msg_lower:
                continue
        if ids_filter is not None and normalized.event_id not in ids_filter:
            continue
        events.append(normalized)
    events.sort(key=lambda e: e.time_created, reverse=True)
    return events


def load_events_from_demo_xml(path: str) -> List[SecurityEvent]:
    """Load security events from a demo XML incident file."""

    tree = ET.parse(path)
    root = tree.getroot()
    events: List[SecurityEvent] = []
    for element in root.findall("Event"):
        time_created_text = element.findtext("TimeCreated")
        event_id_text = element.findtext("Id")
        level = element.findtext("Level") or ""
        provider = element.findtext("Provider") or ""
        machine_name = element.findtext("MachineName") or ""
        message = element.findtext("Message") or ""
        try:
            event_id = int(event_id_text) if event_id_text is not None else None
        except ValueError:
            event_id = None
        if event_id is None:
            continue
        time_created = parse_time(time_created_text)
        category = categorize_event(event_id)
        events.append(
            SecurityEvent(
                time_created=time_created,
                event_id=event_id,
                level=level,
                provider=provider,
                machine_name=machine_name,
                message=message,
                category=category,
            )
        )
    events.sort(key=lambda e: e.time_created, reverse=True)
    return events


def resolve_demo_paths() -> tuple[Path, Path]:
    """Return paths to the demo directory and incident XML file."""

    demo_dir = Path(__file__).with_name("demo")
    demo_xml_path = demo_dir / "demo_incident.xml"
    return demo_dir, demo_xml_path


def load_events_for_demo() -> List[SecurityEvent]:
    """Load security events when running in demo mode."""

    _, demo_xml_path = resolve_demo_paths()
    if not demo_xml_path.exists():
        raise FileNotFoundError(f"Demo XML file not found at: {demo_xml_path}")
    events = load_events_from_demo_xml(str(demo_xml_path))
    return events


def load_events_for_live(
    log_name: str,
    max_events: int,
    important_only: bool,
    event_ids: Optional[Sequence[int]],
    hide_system_logons: bool,
) -> List[SecurityEvent]:
    """Load security events from a live Windows Security log."""

    events = collect_events(
        log_name=log_name,
        max_events=max_events,
        important_only=important_only,
        event_ids=event_ids,
        hide_system_logons=hide_system_logons,
    )
    return events
