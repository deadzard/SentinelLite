"""
pipeline.py - glue between parsers, detectors, risk engine and the dashboard.

Keeping this logic out of app.py means it can be unit-tested without Streamlit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import pandas as pd

from detector import (DetectionConfig, PortRule, detect_auth_alerts, detect_unexpected_ports,
                      format_time, parse_policy_text)
from log_parser import empty_events
from nmap_parser import empty_ports
from recommendations import recommendation_text
from risk_engine import ScoringConfig, score_alerts

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY_PATH = BASE_DIR / "expected_ports.txt"

DEFAULT_LABEL = "Uploaded data"
SEVERITIES = ["High", "Medium", "Low"]
FINDING_COLUMNS = ["alert_id", "timestamp", "category", "source", "target", "rule_id", "detection_reason",
                   "rule_points", "risk_score", "severity", "score_breakdown", "recommendation", "data_source"]


@dataclass
class AnalysisResult:
    auth_events: pd.DataFrame
    scan_ports: pd.DataFrame
    findings: pd.DataFrame
    auth_label: str
    scan_label: str
    scan_time: Optional[datetime] = None

    @property
    def total_events(self) -> int:
        """Authentication events plus open-port observations analysed."""
        return len(self.auth_events) + len(self.scan_ports)


def load_default_policy_text() -> str:
    try:
        return DEFAULT_POLICY_PATH.read_text(encoding="utf-8")
    except OSError:
        return "# expected_ports.txt not found - add rules like:  127.0.0.1 22/tcp\n"


def analyze(auth_events: Optional[pd.DataFrame] = None,
            scan_ports: Optional[pd.DataFrame] = None,
            scan_time: Optional[datetime] = None,
            policy_rules: Optional[List[PortRule]] = None,
            detection: Optional[DetectionConfig] = None,
            scoring: Optional[ScoringConfig] = None,
            auth_label: str = DEFAULT_LABEL,
            scan_label: str = DEFAULT_LABEL) -> AnalysisResult:
    """Run both detectors, score the alerts and build the findings table."""
    auth_events = auth_events if auth_events is not None else empty_events()
    scan_ports = scan_ports if scan_ports is not None else empty_ports()

    alerts = detect_auth_alerts(auth_events, detection) if not auth_events.empty else []
    alerts += detect_unexpected_ports(scan_ports, policy_rules or [], scan_time)
    scored = score_alerts(alerts, scoring)

    rows = []
    for number, finding in enumerate(scored, start=1):
        alert = finding.alert
        label = auth_label if alert.category == "Authentication" else scan_label
        rows.append({
            "alert_id": f"SL-{number:03d}",
            "timestamp": format_time(alert.timestamp),
            "category": alert.category,
            "source": alert.source,
            "target": alert.target,
            "rule_id": alert.rule_id,
            "detection_reason": alert.reason,
            "rule_points": finding.rule_points,
            "risk_score": finding.risk_score,
            "severity": finding.severity,
            "score_breakdown": finding.breakdown,
            "recommendation": recommendation_text(alert),
            "data_source": label,
        })
    findings = pd.DataFrame(rows, columns=FINDING_COLUMNS)
    return AnalysisResult(auth_events, scan_ports, findings, auth_label, scan_label, scan_time)


def severity_counts(findings: pd.DataFrame) -> dict:
    counts = {name: 0 for name in SEVERITIES}
    if not findings.empty:
        for name, number in findings["severity"].value_counts().items():
            counts[str(name)] = int(number)
    return counts


@dataclass
class Verdict:
    level: str     # "nodata", "clean", "info", "medium" or "high"
    title: str
    detail: str


def verdict(findings: pd.DataFrame, records_analysed: int, category: Optional[str] = None) -> Verdict:
    """
    Plain-language CLEAN / ALERT verdict.
      no records loaded      -> NO DATA (never reported as clean)
      no alerts              -> CLEAN
      only Low alerts        -> CLEAN (informational notes only)
      any Medium             -> ALERTS RAISED (Medium)
      any High               -> ALERTS RAISED (High)
    category: None = overall, or "Authentication" / "Network" for one data source.
    """
    if records_analysed == 0:
        return Verdict("nodata", "NO DATA ANALYSED", "No records were loaded, so nothing can be called clean.")
    subset = findings if category is None else findings[findings["category"] == category]
    counts = severity_counts(subset)
    total = sum(counts.values())
    if total == 0:
        return Verdict("clean", "CLEAN", "No alerts were raised: no suspicious activity found by the rules.")
    if counts["High"]:
        return Verdict("high", "ALERTS RAISED - HIGH RISK",
                       f"{total} alert(s): {counts['High']} High, {counts['Medium']} Medium, {counts['Low']} Low.")
    if counts["Medium"]:
        return Verdict("medium", "ALERTS RAISED - MEDIUM RISK",
                       f"{total} alert(s): {counts['Medium']} Medium, {counts['Low']} Low. No High-risk alerts.")
    return Verdict("info", "CLEAN (informational notes only)",
                   f"{total} Low-risk note(s), such as isolated failed logins. No action normally needed.")


def _csv_safe(value):
    """Neutralise spreadsheet formula injection: text starting with = + - @ is prefixed with an apostrophe."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def findings_to_csv(findings: pd.DataFrame) -> str:
    """CSV text for the downloadable report (usernames come from uploaded files, so cells are sanitised)."""
    safe = findings.copy()
    for column in safe.columns:
        if not pd.api.types.is_numeric_dtype(safe[column]):
            safe[column] = safe[column].map(_csv_safe)
    return safe.to_csv(index=False)
