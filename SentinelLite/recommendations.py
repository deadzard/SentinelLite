"""
recommendations.py - DEFENSIVE advice for each detection.

SentinelLite only SUGGESTS actions for a human to review. It never blocks IP addresses,
changes firewall rules, or modifies the host.
"""
from __future__ import annotations

from typing import List

from detector import (Alert, RULE_AUTH_BRUTE, RULE_AUTH_BURST, RULE_AUTH_ISOLATED,
                      RULE_PORT_UNEXPECTED)

# Extra, port-specific hints (all defensive).
PORT_ADVICE = {
    21: "FTP sends passwords in clear text; prefer SFTP and disable FTP if it is not needed.",
    22: "SSH should use key-based login and be limited to trusted source addresses.",
    23: "Telnet is unencrypted and obsolete; disable it and use SSH instead.",
    445: "SMB file sharing should never be exposed beyond the trusted internal network.",
    3306: "Database ports (MySQL) should listen on localhost or a private network only.",
    3389: "Remote Desktop should sit behind a VPN with multi-factor authentication.",
    5432: "Database ports (PostgreSQL) should listen on localhost or a private network only.",
    5900: "VNC is weakly protected by default; tunnel it through a VPN/SSH or disable it.",
    8080: "Confirm which application is using this alternative web port and whether it is meant to be reachable.",
}


def recommendations_for(alert: Alert) -> List[str]:
    """Return an ordered list of defensive recommendations for one alert."""
    if alert.rule_id == RULE_AUTH_BRUTE:
        steps = [
            "Review the authentication logs for this source IP and the targeted accounts.",
            "Investigate whether the source IP is expected (known user, VPN, scanner or lab machine).",
            "Apply rate limiting, temporary account lockout or multi-factor authentication on the affected service.",
            "If the activity is unauthorised, ask the network administrator to consider a manual firewall block "
            "after review (SentinelLite itself changes nothing).",
        ]
        if alert.details.get("success_after"):
            steps.insert(0, "PRIORITY: a successful login from this IP followed the failures. Verify that session "
                            "and reset the account's credentials if it was not legitimate.")
        return steps
    if alert.rule_id == RULE_AUTH_BURST:
        return [
            "Review the authentication logs for this source IP.",
            "Check whether the user simply mistyped a password or whether the source IP is unexpected.",
            "Confirm that an account-lockout or rate-limiting policy exists; watch for the pattern repeating.",
        ]
    if alert.rule_id == RULE_AUTH_ISOLATED:
        return [
            "No action is normally needed for a single failed login.",
            "Note whether the same IP or account keeps appearing in later logs.",
        ]
    if alert.rule_id == RULE_PORT_UNEXPECTED:
        port = int(alert.details.get("port", 0))
        steps = [
            f"Verify the approved service and port inventory: should {alert.target} be open on {alert.source}?",
            "Review firewall rules and close or restrict the service (for example bind it to localhost "
            "or limit allowed source addresses) if it is not needed.",
        ]
        if port in PORT_ADVICE:
            steps.append(PORT_ADVICE[port])
        steps.append("If the service is legitimate, add it to the expected-port policy so it is documented.")
        return steps
    return ["Review this alert manually."]


def recommendation_text(alert: Alert) -> str:
    """Single-cell text for tables and the CSV report."""
    return " | ".join(recommendations_for(alert))
