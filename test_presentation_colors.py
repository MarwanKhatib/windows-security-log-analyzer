from datetime import datetime

from models import SecurityEvent
from presentation import color_for_event


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


def test_color_for_event_respects_use_color_flag():
    event = make_event("Information")
    assert color_for_event(event, use_color=False) == ""


def test_color_for_event_info_is_bright_cyan():
    event = make_event("Information")
    assert color_for_event(event, use_color=True) == "bright_cyan"


def test_color_for_event_warning_is_bright_yellow():
    event = make_event("Warning")
    assert color_for_event(event, use_color=True) == "bright_yellow"


def test_color_for_event_error_is_bright_red():
    event = make_event("Error")
    assert color_for_event(event, use_color=True) == "bright_red"


def test_color_for_event_critical_is_bright_red():
    event = make_event("Critical")
    assert color_for_event(event, use_color=True) == "bright_red"
