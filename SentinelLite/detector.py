"""
detector.py - rule-based detection of suspicious authentication and network activity.

Two detectors:
1. detect_auth_alerts()          - repeated failed logins from one IP in a ROLLING time window
2. detect_unexpected_ports()     - open ports that are not on the expected-port policy (allow-list)

Everything here is plain, readable Python. No machine learning, no hidden state.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import pandas as pd

# Rule identifiers (also used by risk_engine.py and recommendations.py)
RULE_AUTH_BRUTE = "AUTH-BRUTE-FORCE"        # 5+ failures from one IP inside the window
RULE_AUTH_BURST = "AUTH-FAILURE-BURST"      # 2-4 failures from one IP inside the window
RULE_AUTH_ISOLATED = "AUTH-ISOLATED-FAILURE"  # failures that never formed a burst
RULE_PORT_UNEXPECTED = "PORT-UNEXPECTED"    # open port not on the policy

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def format_time(value: Optional[datetime]) -> str:
    return value.strftime(TIME_FORMAT) if value else ""


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: int = 120           # rolling window length
    high_threshold: int = 5             # failures in one window => brute-force pattern
    medium_threshold: int = 2           # failures in one window => minor burst
    report_isolated_failures: bool = True
    success_followup_seconds: int = 600  # look for a success this long after a brute-force incident

    def __post_init__(self):
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0.")
        if self.medium_threshold < 2:
            raise ValueError("medium_threshold must be at least 2 (a single failure is 'isolated').")
        if self.high_threshold < self.medium_threshold:
            raise ValueError("high_threshold must be greater than or equal to medium_threshold.")


@dataclass
class Alert:
    """One detection, before risk scoring."""
    rule_id: str
    category: str                  # "Authentication" or "Network"
    timestamp: Optional[datetime]  # auth: first failure of the incident; network: scan start time
    source: str                    # the IP address the alert is about (login source or scanned host)
    target: str                    # usernames (auth) or port/protocol (network)
    reason: str                    # human-readable explanation of the rule that fired
    details: dict = field(default_factory=dict)


# =========================================================================== authentication
def detect_auth_alerts(events: pd.DataFrame, config: Optional[DetectionConfig] = None) -> List[Alert]:
    """
    Detect repeated failed logins per source IP using a rolling window.

    Window definition: a set of failures from the SAME IP whose first and last timestamps are
    at most `window_seconds` apart (inclusive). Different IPs are never combined.

    Counting rule (avoids double counting): overlapping windows are merged into ONE incident,
    so each failed login belongs to at most one incident.
      - peak failures in any window >= high_threshold (5)  -> AUTH-BRUTE-FORCE (High)
      - peak between medium_threshold (2) and 4            -> AUTH-FAILURE-BURST (Medium)
      - failures that never shared a window with another   -> AUTH-ISOLATED-FAILURE (Low, one per IP)
    Successful logins never count as failures.
    """
    cfg = config or DetectionConfig()
    needed = {"timestamp", "source_ip", "username", "status"}
    if not needed.issubset(events.columns):
        raise ValueError(f"events table is missing column(s): {sorted(needed - set(events.columns))}")
    if events.empty:
        return []

    ordered = events.assign(timestamp=pd.to_datetime(events["timestamp"])).sort_values("timestamp", kind="stable")
    failures: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    successes: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    for ts, ip, user, status in zip(ordered["timestamp"], ordered["source_ip"],
                                    ordered["username"], ordered["status"]):
        bucket = failures if status == "FAILED" else successes
        bucket[str(ip)].append((ts.to_pydatetime(warn=False), str(user)))

    window = timedelta(seconds=cfg.window_seconds)
    alerts: List[Alert] = []

    for ip in sorted(failures):
        fails = failures[ip]
        times = [t for t, _ in fails]
        incidents = _find_incidents(times, window, cfg.medium_threshold)
        in_incident = set()

        for start, end, peak in incidents:
            in_incident.update(range(start, end + 1))
            users = sorted({u for _, u in fails[start:end + 1]})
            count = end - start + 1
            first, last = times[start], times[end]
            details = {"failure_count": count, "peak_in_window": peak, "usernames": users,
                       "first_failure": format_time(first), "last_failure": format_time(last),
                       "success_after": None}
            span = (f"Incident spans {format_time(first)} to {format_time(last)}: {count} failed login(s) "
                    f"against {len(users)} username(s) ({_list_text(users)}).")

            if peak >= cfg.high_threshold:
                rule = RULE_AUTH_BRUTE
                reason = (f"Rule {rule}: {peak} failed logins from {ip} within {cfg.window_seconds} seconds "
                          f"(threshold: {cfg.high_threshold}+ failures from one IP in a rolling "
                          f"{cfg.window_seconds}-second window). {span}")
                follow = _success_after(successes.get(ip, []), first, last, cfg.success_followup_seconds)
                if follow is not None:
                    details["success_after"] = format_time(follow[0])
                    details["success_user"] = follow[1]
                    reason += (f" A SUCCESSFUL login from the same IP followed at {format_time(follow[0])} "
                               f"(user '{follow[1]}'). This is evidence only and is not added to the score.")
            else:
                rule = RULE_AUTH_BURST
                reason = (f"Rule {rule}: {peak} failed logins from {ip} within {cfg.window_seconds} seconds "
                          f"({cfg.medium_threshold}-{cfg.high_threshold - 1} failures in the window = Medium; "
                          f"below the {cfg.high_threshold}-failure brute-force threshold). {span}")
            alerts.append(Alert(rule, "Authentication", first, ip, _list_text(users), reason, details))

        if cfg.report_isolated_failures:
            isolated = [i for i in range(len(fails)) if i not in in_incident]
            if isolated:
                users = sorted({fails[i][1] for i in isolated})
                last = times[isolated[-1]]
                reason = (f"Rule {RULE_AUTH_ISOLATED}: {len(isolated)} failed login(s) from {ip} that never "
                          f"formed a burst (no other failure from this IP within {cfg.window_seconds} seconds). "
                          f"Usually a mistyped password; informational only.")
                alerts.append(Alert(RULE_AUTH_ISOLATED, "Authentication", last, ip, _list_text(users), reason,
                                    {"failure_count": len(isolated), "usernames": users,
                                     "last_failure": format_time(last)}))
    return alerts


def _find_incidents(times: List[datetime], window: timedelta, min_count: int) -> List[List[int]]:
    """
    Slide a window over the sorted failure times (two-pointer technique).
    Returns [start_index, end_index, peak_count] for each merged incident.
    """
    incidents: List[List[int]] = []
    left = 0
    for right, current in enumerate(times):
        while current - times[left] > window:   # drop failures that fell out of the window
            left += 1
        count = right - left + 1
        if count < min_count:
            continue
        if incidents and left <= incidents[-1][1]:   # shares failures with the previous incident: merge
            incidents[-1][1] = right
            incidents[-1][2] = max(incidents[-1][2], count)
        else:
            incidents.append([left, right, count])
    return incidents


def _success_after(successes: List[Tuple[datetime, str]], first: datetime, last: datetime,
                   followup_seconds: int) -> Optional[Tuple[datetime, str]]:
    limit = last + timedelta(seconds=followup_seconds)
    for ts, user in successes:   # already sorted by time
        if first <= ts <= limit:
            return ts, user
    return None


def _list_text(items: List[str], limit: int = 5) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f", ... (+{len(items) - limit} more)" if len(items) > limit else "")


# =========================================================================== network policy
@dataclass(frozen=True)
class PortRule:
    """One allow-list entry: host ('*' = every host), port range, protocol."""
    host: str
    port_start: int
    port_end: int
    protocol: str = "tcp"

    def matches(self, host: str, port: int, protocol: str) -> bool:
        return (self.host in ("*", host) and self.protocol == protocol
                and self.port_start <= port <= self.port_end)

    def label(self) -> str:
        ports = str(self.port_start) if self.port_start == self.port_end else f"{self.port_start}-{self.port_end}"
        return f"{ports}/{self.protocol}"


def parse_policy_text(text: str) -> Tuple[List[PortRule], List[str]]:
    """
    Parse the editable expected-port policy. One rule per line:

        HOST  PORT/PROTOCOL        e.g.  127.0.0.1  22/tcp
        *     443/tcp              ('*' = any host)
        *     8000-8010/tcp        (port range)
        # comments start with a hash

    Returns (rules, warnings). Bad lines are reported and skipped; they never crash the app.
    """
    rules: List[PortRule] = []
    warnings: List[str] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            warnings.append(f"Policy line {number}: expected 'HOST PORT/PROTOCOL', got '{raw_line.strip()[:60]}' - ignored.")
            continue
        host_text, port_text = parts
        try:
            host = "*" if host_text == "*" else str(ipaddress.ip_address(host_text))
        except ValueError:
            warnings.append(f"Policy line {number}: '{host_text[:40]}' is not an IP address or '*' - ignored.")
            continue
        port_part, _, proto = port_text.partition("/")
        proto = (proto or "tcp").lower()
        if proto not in ("tcp", "udp", "sctp"):
            warnings.append(f"Policy line {number}: unknown protocol '{proto[:10]}' - ignored.")
            continue
        try:
            low_text, dash, high_text = port_part.partition("-")
            low = int(low_text)
            high = int(high_text) if dash else low
            if not (1 <= low <= high <= 65535):
                raise ValueError
        except ValueError:
            warnings.append(f"Policy line {number}: invalid port '{port_part[:20]}' - ignored.")
            continue
        rules.append(PortRule(host, low, high, proto))
    return rules, warnings


def detect_unexpected_ports(ports: pd.DataFrame, rules: List[PortRule],
                            scan_time: Optional[datetime] = None) -> List[Alert]:
    """
    Flag every open port that no policy rule allows (default-deny).
    A host with no matching rules at all has NO approved ports, so every open port on it is flagged.
    """
    if ports is None or ports.empty:
        return []
    alerts: List[Alert] = []
    for row in ports.itertuples(index=False):
        host, port, proto = str(row.host_ip), int(row.port), str(row.protocol)
        if any(rule.matches(host, port, proto) for rule in rules):
            continue
        approved = sorted({r.label() for r in rules if r.host in ("*", host)})
        approved_text = ", ".join(approved) if approved else "none (no ports are approved for this host)"
        service = row.service or "unknown service"
        reason = (f"Rule {RULE_PORT_UNEXPECTED}: {host} has {port}/{proto} ({service}) open, but this port is not "
                  f"on the expected-port policy. Approved ports for this host: {approved_text}. "
                  f"Policy violated: only allow-listed ports may be exposed.")
        alerts.append(Alert(RULE_PORT_UNEXPECTED, "Network", scan_time, host, f"{port}/{proto}", reason,
                            {"port": port, "protocol": proto, "service": str(service),
                             "product": str(getattr(row, "product", "") or "")}))
    return alerts
