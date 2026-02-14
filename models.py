"""Data models and rule definitions for Windows Security Log Analyzer."""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class SecurityEvent:
    """Normalized representation of a Windows security event."""

    time_created: datetime
    event_id: int
    level: str
    provider: str
    machine_name: str
    message: str
    category: str


@dataclass(frozen=True)
class EventRule:
    """Rule describing how to interpret a specific event ID."""

    category: str
    severity: str


EVENT_RULES: Dict[int, EventRule] = {
    4624: EventRule(category="Logon success", severity="normal"),
    4625: EventRule(category="Logon failure", severity="critical"),
    4634: EventRule(category="Logoff", severity="normal"),
    4647: EventRule(category="Logoff", severity="normal"),
    4672: EventRule(category="Privilege assigned", severity="normal"),
    4688: EventRule(category="Process created", severity="suspicious"),
    4689: EventRule(category="Process exited", severity="info"),
    4720: EventRule(category="User account change", severity="suspicious"),
    4722: EventRule(category="User account change", severity="suspicious"),
    4723: EventRule(category="Password change attempt", severity="suspicious"),
    4724: EventRule(category="Password change attempt", severity="suspicious"),
    4725: EventRule(category="User account change", severity="suspicious"),
    4726: EventRule(category="User account change", severity="suspicious"),
    4732: EventRule(category="Group membership change", severity="suspicious"),
    4733: EventRule(category="Group membership change", severity="suspicious"),
    4768: EventRule(category="Kerberos authentication", severity="info"),
    4769: EventRule(category="Kerberos authentication", severity="info"),
    4770: EventRule(category="Kerberos authentication", severity="info"),
    4771: EventRule(category="Kerberos authentication", severity="info"),
    4798: EventRule(category="User enumeration", severity="suspicious"),
    4799: EventRule(category="User enumeration", severity="suspicious"),
}


IMPORTANT_EVENT_IDS: Set[int] = set(EVENT_RULES.keys())


def categorize_event(event_id: int) -> str:
    """Return a human-readable category name for a given event ID."""

    rule = EVENT_RULES.get(event_id)
    if rule is not None:
        return rule.category
    return "Other"


def parse_time(value: Optional[str]) -> datetime:
    """Parse an ISO 8601 timestamp string into a datetime object."""

    if not value:
        return datetime.fromtimestamp(0)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0)


def parse_event_ids(value: Optional[str]) -> Optional[List[int]]:
    """Parse a comma-separated string of event IDs into a list of integers."""

    if not value:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    result: List[int] = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            continue
    return result or None


def normalize_level_name(level: str) -> str:
    """Normalize a raw event level string into one of the canonical levels."""

    value = level.strip().lower()
    if value in {"debug", "verbose", "trace"}:
        return "debug"
    if value in {"information", "info"}:
        return "info"
    if value in {"warning", "warn"}:
        return "warning"
    if value in {"error", "err"}:
        return "error"
    if value in {"critical", "fatal"}:
        return "critical"
    return "info"


def parse_levels(value: Optional[str]) -> Optional[Set[str]]:
    """Parse a comma-separated list of levels into a set of canonical levels."""

    if not value:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    result: Set[str] = set()
    for part in parts:
        normalized = normalize_level_name(part)
        result.add(normalized)
    return result or None
