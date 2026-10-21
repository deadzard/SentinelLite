"""Tests for risk_engine.py and the end-to-end pipeline (scoring, boundaries, CSV export)."""
from detector import (Alert, DetectionConfig, RULE_AUTH_BRUTE, RULE_AUTH_BURST, RULE_AUTH_ISOLATED,
                      RULE_PORT_UNEXPECTED, parse_policy_text)
from log_parser import parse_auth_log
from nmap_parser import parse_nmap_xml
from pipeline import FINDING_COLUMNS, verdict, analyze, findings_to_csv, load_default_policy_text, severity_counts
from risk_engine import ScoringConfig, classify_severity, score_alerts
from tests.helpers import FIXTURES, FIXTURE_LABEL, TEST_FILES, expect_error, failures, make_events, make_ports

IP = "203.0.113.5"


def alert(rule, source=IP, port=None):
    details = {"port": port} if port else {}
    return Alert(rule, "Network" if port else "Authentication", None, source, "x", "reason", details)


# ----------------------------------------------------------------------------- boundaries
def test_severity_boundaries():
    expected = {0: "Low", 29: "Low", 30: "Medium", 59: "Medium", 60: "High", 100: "High"}
    for score, severity in expected.items():
        assert classify_severity(score) == severity, score


def test_out_of_range_scores_are_clamped():
    assert classify_severity(150) == "High"
    assert classify_severity(-5) == "Low"


def test_nan_score_is_rejected():
    expect_error(ValueError, classify_severity, float("nan"))


def test_default_points_match_the_brief():
    cfg = ScoringConfig()
    assert cfg.points_for(RULE_AUTH_BRUTE) == 70 and cfg.points_for(RULE_PORT_UNEXPECTED) == 30
    assert cfg.max_score == 100


def test_config_validation():
    expect_error(ValueError, ScoringConfig, -1)
    expect_error(ValueError, ScoringConfig, 70, 30, 40, 10, 100, 60, 30)


# ----------------------------------------------------------------------------- scoring
def test_single_rule_scores():
    assert score_alerts([alert(RULE_AUTH_BRUTE)])[0].risk_score == 70
    assert score_alerts([alert(RULE_AUTH_BRUTE)])[0].severity == "High"
    assert score_alerts([alert(RULE_PORT_UNEXPECTED, port=3306)])[0].severity == "Medium"
    assert score_alerts([alert(RULE_AUTH_BURST)])[0].severity == "Medium"
    assert score_alerts([alert(RULE_AUTH_ISOLATED)])[0].severity == "Low"


def test_combined_score_is_capped_at_100():
    findings = score_alerts([alert(RULE_AUTH_BRUTE), alert(RULE_PORT_UNEXPECTED, port=22)],
                            ScoringConfig(auth_brute_points=90))
    assert all(f.risk_score == 100 for f in findings)
    assert "capped at 100" in findings[0].breakdown


def test_default_combination_is_exactly_100():
    findings = score_alerts([alert(RULE_AUTH_BRUTE), alert(RULE_PORT_UNEXPECTED, port=22)])
    assert findings[0].risk_score == 100 and findings[0].severity == "High"


def test_repeated_port_alerts_on_one_host_are_counted_once():
    findings = score_alerts([alert(RULE_PORT_UNEXPECTED, port=p) for p in (3306, 8080, 5900)])
    assert all(f.risk_score == 30 for f in findings)
    assert "counted once" in findings[0].breakdown


def test_brute_force_and_burst_from_same_ip_use_highest_rule_only():
    findings = score_alerts([alert(RULE_AUTH_BRUTE), alert(RULE_AUTH_BURST)])
    assert all(f.risk_score == 70 for f in findings)


def test_different_ips_are_scored_independently():
    findings = score_alerts([alert(RULE_AUTH_BRUTE, "1.1.1.1"), alert(RULE_PORT_UNEXPECTED, "2.2.2.2", port=22)])
    assert sorted(f.risk_score for f in findings) == [30, 70]


def test_every_finding_has_a_breakdown_showing_its_rule():
    for finding in score_alerts([alert(RULE_AUTH_BRUTE), alert(RULE_PORT_UNEXPECTED, port=1)]):
        assert finding.alert.rule_id in finding.breakdown and "pts" in finding.breakdown


# ----------------------------------------------------------------------------- pipeline
def test_normal_events_do_not_create_a_high_risk_alert():
    events = make_events([(0, "192.0.2.10", "alice", "SUCCESS"), (30, "192.0.2.10", "alice", "FAILED"),
                          (60, "192.0.2.10", "alice", "SUCCESS")])
    result = analyze(events)
    assert severity_counts(result.findings)["High"] == 0
    assert result.findings["severity"].tolist() == ["Low"]


def test_clean_data_produces_no_findings():
    result = analyze(make_events([(0, "192.0.2.10", "alice", "SUCCESS")]),
                     make_ports([("127.0.0.1", 22, "tcp", "ssh")]), None, parse_policy_text("127.0.0.1 22/tcp")[0])
    assert result.findings.empty and result.total_events == 2


def test_no_input_at_all_does_not_crash():
    result = analyze()
    assert result.findings.empty and result.total_events == 0
    assert severity_counts(result.findings) == {"High": 0, "Medium": 0, "Low": 0}


def test_slow_trickle_is_not_high_risk_end_to_end():
    result = analyze(make_events(failures(IP, [0, 50, 100, 150, 200])))
    assert severity_counts(result.findings) == {"High": 0, "Medium": 1, "Low": 0}


def fixture_result():
    logs = parse_auth_log(FIXTURES / "sample_logs.csv")
    scan = parse_nmap_xml(FIXTURES / "sample_scan.xml")
    rules, _ = parse_policy_text((FIXTURES / "expected_ports.txt").read_text(encoding="utf-8"))
    return analyze(logs.events, scan.ports, scan.scan_time, rules, auth_label=FIXTURE_LABEL, scan_label=FIXTURE_LABEL)


def test_fixture_data_produces_the_expected_findings():
    result = fixture_result()
    assert result.total_events == 42
    assert severity_counts(result.findings) == {"High": 4, "Medium": 4, "Low": 2}
    assert list(result.findings.columns) == FINDING_COLUMNS
    assert result.findings["alert_id"].is_unique
    assert (result.findings["data_source"] == FIXTURE_LABEL).all()
    # one IP appears in BOTH datasets: brute force (70) + unexpected ports (30) = 100
    lab = result.findings[result.findings["source"] == "192.168.56.10"]
    assert len(lab) == 3 and (lab["risk_score"] == 100).all()


def test_csv_export_contains_findings_and_labels_data_source():
    result = fixture_result()
    text = findings_to_csv(result.findings)
    lines = text.strip().splitlines()
    assert lines[0].split(",")[0] == "alert_id" and len(lines) == len(result.findings) + 1
    assert FIXTURE_LABEL in text


def user_test_result(logs, scan):
    rules, _ = parse_policy_text(load_default_policy_text())
    l = parse_auth_log(TEST_FILES / logs) if logs else None
    s = parse_nmap_xml(TEST_FILES / scan) if scan else None
    return analyze(l.events if l else None, s.ports if s else None, s.scan_time if s else None, rules)


def test_alert_test_files_raise_the_documented_alerts_with_the_default_policy():
    result = user_test_result("alert_logs.csv", "alert_scan.xml")
    assert severity_counts(result.findings) == {"High": 1, "Medium": 3, "Low": 0}
    assert verdict(result.findings, result.total_events).level == "high"
    assert sorted(result.findings["rule_id"]) == ["AUTH-BRUTE-FORCE", "AUTH-FAILURE-BURST",
                                                  "PORT-UNEXPECTED", "PORT-UNEXPECTED"]
    only_logs = user_test_result("alert_logs.csv", None)
    assert severity_counts(only_logs.findings) == {"High": 1, "Medium": 1, "Low": 0}
    only_scan = user_test_result(None, "alert_scan.xml")
    assert severity_counts(only_scan.findings) == {"High": 0, "Medium": 2, "Low": 0}


def test_clean_test_files_are_reported_clean_with_the_default_policy():
    result = user_test_result("clean_logs.csv", "clean_scan.xml")
    assert result.findings.empty and result.total_events == 8
    assert verdict(result.findings, result.total_events).title == "CLEAN"


def test_csv_export_neutralises_spreadsheet_formulas():
    events = make_events(failures(IP, [0, 10, 20, 30, 40], user="=HYPERLINK(\"http://x\")"))
    result = analyze(events)
    assert result.findings.iloc[0]["target"].startswith("=")      # raw value kept on screen
    text = findings_to_csv(result.findings)
    assert "'=HYPERLINK" in text


def test_uploaded_label_is_carried_into_findings():
    result = analyze(make_events(failures(IP, [0, 10, 20])), auth_label="Uploaded file: my_log.csv")
    assert result.findings.iloc[0]["data_source"] == "Uploaded file: my_log.csv"


# ----------------------------------------------------------------------------- CLEAN / ALERT verdict
def test_verdict_no_data_is_never_called_clean():
    assert verdict(analyze().findings, 0).level == "nodata"


def test_verdict_clean_for_normal_logins():
    result = analyze(make_events([(0, "192.0.2.10", "alice", "SUCCESS")]))
    assert verdict(result.findings, result.total_events).title == "CLEAN"


def test_verdict_only_low_is_clean_with_notes():
    result = analyze(make_events([(0, "192.0.2.10", "alice", "FAILED")]))
    assert verdict(result.findings, result.total_events).level == "info"


def test_verdict_medium_and_high_raise_alerts():
    medium = analyze(make_events(failures(IP, [0, 10, 20])))
    high = analyze(make_events(failures(IP, [0, 10, 20, 30, 40])))
    assert verdict(medium.findings, medium.total_events).level == "medium"
    assert verdict(high.findings, high.total_events).level == "high"


def test_verdict_per_source_is_independent():
    result = analyze(make_events(failures(IP, [0, 10, 20, 30, 40])),
                     make_ports([("127.0.0.1", 22, "tcp", "ssh")]), None, parse_policy_text("127.0.0.1 22/tcp")[0])
    assert verdict(result.findings, len(result.auth_events), "Authentication").level == "high"
    assert verdict(result.findings, len(result.scan_ports), "Network").level == "clean"
