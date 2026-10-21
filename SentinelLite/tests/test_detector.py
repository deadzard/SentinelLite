"""Tests for detector.py: rolling-window login detection and expected-port policy checks."""
from detector import (DetectionConfig, RULE_AUTH_BRUTE, RULE_AUTH_BURST, RULE_AUTH_ISOLATED,
                      RULE_PORT_UNEXPECTED, detect_auth_alerts, detect_unexpected_ports,
                      parse_policy_text)
from tests.helpers import expect_error, failures, make_events, make_ports

IP = "203.0.113.5"


def rules_of(alerts):
    return sorted(a.rule_id for a in alerts)


# ----------------------------------------------------------------------------- authentication
def test_normal_logins_create_no_alerts():
    events = make_events([(0, "192.0.2.10", "alice", "SUCCESS"), (60, "192.0.2.11", "bob", "SUCCESS"),
                          (500, "192.0.2.10", "alice", "SUCCESS")])
    assert detect_auth_alerts(events) == []


def test_empty_events_create_no_alerts():
    assert detect_auth_alerts(make_events([])) == []


def test_isolated_failure_is_low_informational_never_high_or_medium_rule():
    events = make_events([(0, "192.0.2.10", "alice", "FAILED"), (10, "192.0.2.10", "alice", "SUCCESS")])
    alerts = detect_auth_alerts(events)
    assert rules_of(alerts) == [RULE_AUTH_ISOLATED]


def test_failures_far_apart_stay_isolated():
    events = make_events(failures(IP, [0, 300, 900]))
    assert rules_of(detect_auth_alerts(events)) == [RULE_AUTH_ISOLATED]


def test_five_failures_within_two_minutes_is_brute_force():
    alerts = detect_auth_alerts(make_events(failures(IP, [0, 20, 40, 60, 80])))
    assert rules_of(alerts) == [RULE_AUTH_BRUTE]
    assert alerts[0].details["peak_in_window"] == 5
    assert "5 failed logins" in alerts[0].reason and "120 seconds" in alerts[0].reason


def test_two_to_four_failures_are_medium_burst_not_brute_force():
    for count in (2, 3, 4):
        alerts = detect_auth_alerts(make_events(failures(IP, [i * 10 for i in range(count)])))
        assert rules_of(alerts) == [RULE_AUTH_BURST], count


def test_window_boundary_is_inclusive_at_120_seconds():
    assert rules_of(detect_auth_alerts(make_events(failures(IP, [0, 30, 60, 90, 120])))) == [RULE_AUTH_BRUTE]
    assert rules_of(detect_auth_alerts(make_events(failures(IP, [0, 30, 60, 90, 121])))) == [RULE_AUTH_BURST]


def test_slow_trickle_never_reaches_five_in_one_window():
    # 5 failures but 50 seconds apart: any 120-second window holds at most 3
    alerts = detect_auth_alerts(make_events(failures(IP, [0, 50, 100, 150, 200])))
    assert rules_of(alerts) == [RULE_AUTH_BURST]
    assert alerts[0].details["peak_in_window"] == 3


def test_rolling_window_catches_burst_that_straddles_fixed_buckets():
    # 3 failures at the end of minute 1 and 3 at the start of minute 2: a fixed bucket sees 3 + 3,
    # but a ROLLING window sees all 6 within 100 seconds.
    alerts = detect_auth_alerts(make_events(failures(IP, [70, 90, 110, 130, 150, 170])))
    assert rules_of(alerts) == [RULE_AUTH_BRUTE]
    assert alerts[0].details["peak_in_window"] == 6


def test_failures_from_different_ips_are_not_combined():
    rows = failures("203.0.113.5", [0, 10, 20]) + failures("203.0.113.6", [5, 15, 25])
    alerts = detect_auth_alerts(make_events(rows))
    assert rules_of(alerts) == [RULE_AUTH_BURST, RULE_AUTH_BURST]


def test_successful_logins_do_not_count_as_failures():
    rows = failures(IP, [0, 10, 20, 30]) + [(35, IP, "alice", "SUCCESS"), (36, IP, "alice", "SUCCESS")]
    assert rules_of(detect_auth_alerts(make_events(rows))) == [RULE_AUTH_BURST]


def test_overlapping_windows_merge_into_one_incident_without_double_counting():
    alerts = detect_auth_alerts(make_events(failures(IP, [0, 10, 20, 30, 40, 50, 60, 70])))
    assert len(alerts) == 1 and alerts[0].details["failure_count"] == 8


def test_two_separate_bursts_from_one_ip_are_two_incidents():
    alerts = detect_auth_alerts(make_events(failures(IP, [0, 10, 20, 30, 40, 1000, 1010, 1020, 1030, 1040])))
    assert rules_of(alerts) == [RULE_AUTH_BRUTE, RULE_AUTH_BRUTE]
    assert [a.details["failure_count"] for a in alerts] == [5, 5]


def test_unsorted_input_is_handled():
    rows = failures(IP, [80, 0, 60, 20, 40])
    assert rules_of(detect_auth_alerts(make_events(rows))) == [RULE_AUTH_BRUTE]


def test_success_after_brute_force_is_reported_as_evidence():
    rows = failures(IP, [0, 10, 20, 30, 40]) + [(100, IP, "admin", "SUCCESS")]
    alert = detect_auth_alerts(make_events(rows))[0]
    assert alert.details["success_after"] is not None and "SUCCESSFUL login" in alert.reason


def test_isolated_reporting_can_be_switched_off():
    events = make_events([(0, "192.0.2.10", "alice", "FAILED")])
    assert detect_auth_alerts(events, DetectionConfig(report_isolated_failures=False)) == []


def test_missing_columns_raise_value_error():
    import pandas as pd
    assert "missing" in expect_error(ValueError, detect_auth_alerts, pd.DataFrame({"timestamp": []}))


def test_detection_config_validation():
    expect_error(ValueError, DetectionConfig, 0)
    expect_error(ValueError, DetectionConfig, 120, 5, 1)
    expect_error(ValueError, DetectionConfig, 120, 2, 3)


# ----------------------------------------------------------------------------- network policy
POLICY = "127.0.0.1 22/tcp\n127.0.0.1 80/tcp\n"


def test_policy_parser_handles_comments_ranges_and_bad_lines():
    rules, warnings = parse_policy_text("# comment\n* 443/tcp  # inline\n10.0.0.1 8000-8010/tcp\n"
                                        "garbage\nnot-an-ip 22/tcp\n10.0.0.1 99999/tcp\n10.0.0.1 22/xyz\n")
    assert len(rules) == 2 and len(warnings) == 4
    assert rules[1].label() == "8000-8010/tcp"


def test_expected_ports_create_no_alerts():
    rules, _ = parse_policy_text(POLICY)
    assert detect_unexpected_ports(make_ports([("127.0.0.1", 22, "tcp", "ssh"), ("127.0.0.1", 80, "tcp", "http")]), rules) == []


def test_unexpected_port_is_flagged_and_policy_is_explained():
    rules, _ = parse_policy_text(POLICY)
    alerts = detect_unexpected_ports(make_ports([("127.0.0.1", 22, "tcp", "ssh"), ("127.0.0.1", 3306, "tcp", "mysql")]), rules)
    assert len(alerts) == 1 and alerts[0].rule_id == RULE_PORT_UNEXPECTED
    assert alerts[0].target == "3306/tcp"
    assert "not on the expected-port policy" in alerts[0].reason and "22/tcp" in alerts[0].reason


def test_wildcard_and_range_rules_match():
    rules, _ = parse_policy_text("* 443/tcp\n10.0.0.1 8000-8010/tcp\n")
    ports = make_ports([("10.0.0.2", 443, "tcp", "https"), ("10.0.0.1", 8005, "tcp", "http"), ("10.0.0.1", 8011, "tcp", "http")])
    assert [a.target for a in detect_unexpected_ports(ports, rules)] == ["8011/tcp"]


def test_protocol_must_match():
    rules, _ = parse_policy_text("127.0.0.1 53/tcp\n")
    assert len(detect_unexpected_ports(make_ports([("127.0.0.1", 53, "udp", "domain")]), rules)) == 1


def test_host_without_rules_has_no_approved_ports():
    rules, _ = parse_policy_text(POLICY)
    alerts = detect_unexpected_ports(make_ports([("192.168.1.9", 22, "tcp", "ssh")]), rules)
    assert len(alerts) == 1 and "no ports are approved" in alerts[0].reason


def test_empty_scan_creates_no_alerts():
    assert detect_unexpected_ports(make_ports([]), []) == []
