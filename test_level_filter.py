from datetime import datetime

from models import SecurityEvent, parse_levels, normalize_level_name
from app import filter_events_by_levels


def make_event(level: str) -> SecurityEvent:
    return SecurityEvent(
        time_created=datetime.utcnow(),
        event_id=0,
        level=level,
        provider="provider",
        machine_name="machine",
        message="message",
        category="category",
    )


def test_parse_levels_normalizes_input():
    levels = parse_levels("INFO, warning,ERROR")
    assert levels == {"info", "warning", "error"}


def test_normalize_level_name_variants():
    assert normalize_level_name("Information") == "info"
    assert normalize_level_name("WARN") == "warning"
    assert normalize_level_name("err") == "error"
    assert normalize_level_name("CRITICAL") == "critical"


def test_filter_events_by_levels_includes_only_requested_levels():
    events = [
        make_event("Information"),
        make_event("Warning"),
        make_event("Error"),
    ]
    levels = {"warning", "error"}
    filtered = filter_events_byLevels(events, levels)
    assert len(filtered) == 2
    assert normalize_level_name(filtered[0].level) in levels
    assert normalize_level_name(filtered[1].level) in levels

