"""Tests for log_parser.py and nmap_parser.py (valid, malformed and hostile input)."""
from log_parser import LogParseError, parse_auth_log, parse_auth_log_bytes, parse_auth_log_text
from nmap_parser import ScanParseError, parse_nmap_xml, parse_nmap_xml_bytes, parse_nmap_xml_text
from tests.helpers import FIXTURES, TEST_FILES, expect_error

SAMPLE_LOGS_PATH = FIXTURES / "sample_logs.csv"
SAMPLE_SCAN_PATH = FIXTURES / "sample_scan.xml"

GOOD_HEADER = "timestamp,source_ip,username,status\n"


# ----------------------------------------------------------------------------- CSV
def test_sample_csv_loads_cleanly():
    parsed = parse_auth_log(SAMPLE_LOGS_PATH)
    assert len(parsed.events) > 20
    assert parsed.skipped_rows == 0 and parsed.warnings == []
    assert set(parsed.events["status"]) == {"SUCCESS", "FAILED"}


def test_valid_rows_are_normalised():
    parsed = parse_auth_log_text(GOOD_HEADER + "2026-10-19 09:00:00, 192.0.2.10 , alice ,success\n")
    row = parsed.events.iloc[0]
    assert row["source_ip"] == "192.0.2.10" and row["username"] == "alice" and row["status"] == "SUCCESS"


def test_header_aliases_and_case_are_accepted():
    parsed = parse_auth_log_text("Time,IP,User,Result\n2026-10-19 09:00:00,192.0.2.10,alice,Failed\n")
    assert parsed.events.iloc[0]["status"] == "FAILED"


def test_excel_bom_is_handled():
    raw = ("\ufeff" + GOOD_HEADER + "2026-10-19 09:00:00,192.0.2.10,alice,SUCCESS\n").encode("utf-8")
    assert len(parse_auth_log_bytes(raw).events) == 1


def test_timezone_aware_timestamps_become_utc():
    parsed = parse_auth_log_text(GOOD_HEADER + "2026-10-19T09:00:00+05:30,192.0.2.10,alice,SUCCESS\n")
    assert str(parsed.events.iloc[0]["timestamp"]) == "2026-10-19 03:30:00"


def test_malformed_rows_are_skipped_with_warnings_and_good_rows_kept():
    text = GOOD_HEADER + "\n".join([
        "2026-10-19 09:00:00,192.0.2.10,alice,SUCCESS",   # good
        "not-a-time,192.0.2.10,alice,SUCCESS",           # bad timestamp
        "2026-10-19 09:01:00,999.1.1.1,bob,FAILED",      # bad IP
        "2026-10-19 09:02:00,192.0.2.11,,FAILED",        # missing username
        "2026-10-19 09:03:00,192.0.2.11,bob,MAYBE",      # bad status
        "2026-10-19 09:04:00,192.0.2.11,bob",            # too few fields
    ]) + "\n"
    parsed = parse_auth_log_text(text)
    assert len(parsed.events) == 1
    assert parsed.skipped_rows == 5 and len(parsed.warnings) == 5
    assert "Line 3" in parsed.warnings[0] and "timestamp" in parsed.warnings[0]


def test_sample_file_with_errors_is_handled():
    for name in (FIXTURES / "sample_logs_with_errors.csv", TEST_FILES / "logs_with_errors.csv"):
        parsed = parse_auth_log(name)
        assert len(parsed.events) == 3 and parsed.skipped_rows == 5


def test_empty_file_gives_clear_error():
    assert "empty" in expect_error(LogParseError, parse_auth_log_bytes, b"   \n")
    assert "empty" in expect_error(LogParseError, parse_auth_log_text, "")


def test_header_only_file_gives_clear_error():
    assert "no event rows" in expect_error(LogParseError, parse_auth_log_text, GOOD_HEADER)


def test_missing_columns_are_named_in_error():
    message = expect_error(LogParseError, parse_auth_log_text, "timestamp,username\n2026-10-19 09:00:00,alice\n")
    assert "source_ip" in message and "status" in message


def test_all_rows_invalid_gives_clear_error():
    message = expect_error(LogParseError, parse_auth_log_text, GOOD_HEADER + "bad,bad,bad,bad\n")
    assert "No valid events" in message


def test_binary_and_non_utf8_uploads_are_rejected():
    assert "binary" in expect_error(LogParseError, parse_auth_log_bytes, b"PK\x03\x04\x00\x00data")
    assert "UTF-8" in expect_error(LogParseError, parse_auth_log_bytes, b"timestamp,\xff\xfe\xfa\n1,2\n")


def test_missing_file_gives_clear_error():
    assert "Could not read" in expect_error(LogParseError, parse_auth_log, "no_such_file.csv")


def test_unsupported_input_type_gives_clear_error():
    assert "Unsupported" in expect_error(LogParseError, parse_auth_log, 12345)


# ----------------------------------------------------------------------------- Nmap XML
def nmap_doc(hosts_xml, root_attrs='start="1792404720"'):
    return f'<?xml version="1.0"?>\n<nmaprun scanner="nmap" {root_attrs}>{hosts_xml}</nmaprun>'


HOST_OK = ('<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
           '<hostnames><hostname name="localhost"/></hostnames><ports>'
           '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>'
           '<port protocol="tcp" portid="23"><state state="closed"/></port>'
           '<port protocol="tcp" portid="25"><state state="filtered"/></port>'
           '<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>'
           '</ports></host>')


def test_sample_xml_parses_hosts_ports_and_services():
    scan = parse_nmap_xml(SAMPLE_SCAN_PATH)
    assert scan.hosts_total == 3 and scan.hosts_up == 2
    assert set(scan.ports["host_ip"]) == {"127.0.0.1", "192.168.56.10"}
    row = scan.ports[(scan.ports["host_ip"] == "127.0.0.1") & (scan.ports["port"] == 22)].iloc[0]
    assert row["service"] == "ssh" and row["protocol"] == "tcp" and "OpenSSH" in row["product"]
    assert scan.scan_time is not None


def test_only_open_ports_are_recorded():
    scan = parse_nmap_xml_text(nmap_doc(HOST_OK))
    assert sorted(zip(scan.ports["port"], scan.ports["protocol"])) == [(22, "tcp"), (53, "udp")]
    assert scan.ports.iloc[0]["hostname"] == "localhost"


def test_down_host_is_skipped_but_counted():
    down = '<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>'
    scan = parse_nmap_xml_text(nmap_doc(HOST_OK + down))
    assert scan.hosts_total == 2 and scan.hosts_up == 1


def test_host_without_ip_and_invalid_port_produce_warnings():
    no_ip = '<host><status state="up"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host>'
    bad_port = ('<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="99999"><state state="open"/></port></ports></host>')
    scan = parse_nmap_xml_text(nmap_doc(no_ip + bad_port))
    assert len(scan.warnings) >= 2 and scan.ports.empty


def test_real_nmap_style_doctype_and_stylesheet_are_accepted():
    text = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
            '<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n'
            + nmap_doc(HOST_OK).split("\n", 1)[1])
    assert len(parse_nmap_xml_text(text).ports) == 2


def test_malformed_xml_gives_clear_error():
    assert "Malformed XML" in expect_error(ScanParseError, parse_nmap_xml_text, "<nmaprun><host></nmaprun>")


def test_empty_and_wrong_root_xml_give_clear_errors():
    assert "empty" in expect_error(ScanParseError, parse_nmap_xml_text, "  ")
    assert "not look like an Nmap report" in expect_error(ScanParseError, parse_nmap_xml_text, "<html></html>")


def test_xml_entity_declarations_are_rejected():
    evil = '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    assert "entity" in expect_error(ScanParseError, parse_nmap_xml_text, evil).lower()


def test_binary_xml_upload_is_rejected():
    assert "UTF-8" in expect_error(ScanParseError, parse_nmap_xml_bytes, b"\xff\xfe\x00<")


def test_report_without_hosts_or_open_ports_warns_instead_of_crashing():
    scan = parse_nmap_xml_text(nmap_doc(""))
    assert scan.ports.empty and scan.warnings


def test_all_user_test_files_parse():
    assert len(parse_auth_log(TEST_FILES / "alert_logs.csv").events) == 11
    assert len(parse_auth_log(TEST_FILES / "clean_logs.csv").events) == 5
    assert len(parse_nmap_xml(TEST_FILES / "alert_scan.xml").ports) == 4
    assert len(parse_nmap_xml(TEST_FILES / "clean_scan.xml").ports) == 3
