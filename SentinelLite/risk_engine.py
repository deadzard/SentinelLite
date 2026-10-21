"""
risk_engine.py - transparent, configurable, rule-based risk scoring.

IMPORTANT: the points below are ILLUSTRATIVE PROJECT-DEFINED VALUES, not validated probabilities
of compromise and not the output of a trained model.

How the score is built
1. Every rule has a fixed number of points (see ScoringConfig).
2. Alerts are grouped by the IP address they are about (login source or scanned host).
3. Rules belong to a "family". Inside one family on one IP, ONLY THE HIGHEST rule counts.
   Example: 3 unexpected ports on one host => the port rule is counted once (30), not 3 x 30.
4. Family points are added and capped (default 100).
5. Severity: 0-29 Low, 30-59 Medium, 60-100 High.
Every finding carries a plain-text breakdown showing exactly this arithmetic.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

from detector import (Alert, RULE_AUTH_BRUTE, RULE_AUTH_BURST, RULE_AUTH_ISOLATED,
                      RULE_PORT_UNEXPECTED, format_time)

RULE_FAMILY = {
    RULE_AUTH_BRUTE: "AUTH-FAILURES",
    RULE_AUTH_BURST: "AUTH-FAILURES",
    RULE_AUTH_ISOLATED: "AUTH-FAILURES",
    RULE_PORT_UNEXPECTED: "PORT-EXPOSURE",
}


@dataclass(frozen=True)
class ScoringConfig:
    auth_brute_points: int = 70     # required by the project brief
    port_unexpected_points: int = 30  # required by the project brief
    auth_burst_points: int = 40     # project assumption (brief only says 2-4 failures = Medium)
    auth_isolated_points: int = 10  # project assumption (isolated failure = Low, informational)
    max_score: int = 100
    medium_min: int = 30            # 0-29 Low
    high_min: int = 60              # 30-59 Medium, 60-100 High

    def __post_init__(self):
        points = (self.auth_brute_points, self.port_unexpected_points,
                  self.auth_burst_points, self.auth_isolated_points)
        if any(p < 0 for p in points):
            raise ValueError("Rule points cannot be negative.")
        if not (0 < self.medium_min < self.high_min <= self.max_score):
            raise ValueError("Thresholds must satisfy 0 < medium_min < high_min <= max_score.")

    def points_for(self, rule_id: str) -> int:
        table = {RULE_AUTH_BRUTE: self.auth_brute_points, RULE_AUTH_BURST: self.auth_burst_points,
                 RULE_AUTH_ISOLATED: self.auth_isolated_points,
                 RULE_PORT_UNEXPECTED: self.port_unexpected_points}
        return table[rule_id]


@dataclass
class ScoredFinding:
    alert: Alert
    rule_points: int      # points of this alert's own rule
    risk_score: int       # combined score for the IP (after family de-duplication and cap)
    severity: str         # Low / Medium / High
    breakdown: str        # human-readable arithmetic


def classify_severity(score: float, config: Optional[ScoringConfig] = None) -> str:
    """Map a score to Low / Medium / High. Scores are clamped to 0..max_score first."""
    cfg = config or ScoringConfig()
    if score != score:  # NaN check
        raise ValueError("Score must be a number.")
    score = max(0, min(score, cfg.max_score))
    if score >= cfg.high_min:
        return "High"
    if score >= cfg.medium_min:
        return "Medium"
    return "Low"


def score_alerts(alerts: List[Alert], config: Optional[ScoringConfig] = None) -> List[ScoredFinding]:
    """Score every alert; the result is sorted by risk (highest first) with alert IDs assigned in order."""
    cfg = config or ScoringConfig()
    by_entity: Dict[str, List[Alert]] = defaultdict(list)
    for alert in alerts:
        by_entity[alert.source].append(alert)

    entity_result: Dict[str, tuple] = {}
    for entity, items in by_entity.items():
        families: Dict[str, List[Alert]] = defaultdict(list)
        for alert in items:
            families[RULE_FAMILY[alert.rule_id]].append(alert)
        parts, raw = [], 0
        for family in sorted(families):
            members = families[family]
            best = max(members, key=lambda a: cfg.points_for(a.rule_id))
            points = cfg.points_for(best.rule_id)
            raw += points
            note = f"{best.rule_id} {points}"
            if len(members) > 1:
                note += f" ({len(members)} alerts in this rule family; counted once, highest rule used)"
            parts.append(note)
        score = min(cfg.max_score, raw)
        text = " + ".join(parts) + f" = {raw}"
        if raw > cfg.max_score:
            text += f", capped at {cfg.max_score}"
        entity_result[entity] = (score, text)

    findings: List[ScoredFinding] = []
    for alert in alerts:
        score, text = entity_result[alert.source]
        own = cfg.points_for(alert.rule_id)
        breakdown = (f"This alert: {alert.rule_id} = {own} pts. "
                     f"Combined score for {alert.source}: {text}.")
        findings.append(ScoredFinding(alert, own, score, classify_severity(score, cfg), breakdown))

    # Highest risk first; ties broken by time, source and rule so the order is deterministic.
    findings.sort(key=lambda f: (-f.risk_score, format_time(f.alert.timestamp), f.alert.source,
                                 f.alert.rule_id, f.alert.target))
    return findings
