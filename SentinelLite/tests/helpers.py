"""Small helpers shared by the test files (plain functions, no pytest magic)."""
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

BASE = datetime(2026, 10, 19, 12, 0, 0)
FIXTURES = Path(__file__).resolve().parent / "fixtures"      # test-only synthetic data, never loaded by the app
TEST_FILES = Path(__file__).resolve().parent.parent / "test_files"   # files a person uploads to try the app
FIXTURE_LABEL = "Fixture data (synthetic, tests only)"


def make_events(rows):
    """rows: list of (seconds_after_BASE, ip, username, status)."""
    return pd.DataFrame(
        [{"timestamp": BASE + timedelta(seconds=s), "source_ip": ip, "username": user,
          "status": status, "line": i + 2} for i, (s, ip, user, status) in enumerate(rows)],
        columns=["timestamp", "source_ip", "username", "status", "line"])


def failures(ip, offsets, user="alice"):
    return [(s, ip, user, "FAILED") for s in offsets]


def expect_error(exc_type, func, *args):
    """Assert that func(*args) raises exc_type and return the error message."""
    try:
        func(*args)
    except exc_type as exc:
        return str(exc)
    raise AssertionError(f"{exc_type.__name__} was not raised")


def make_ports(rows):
    """rows: list of (host_ip, port, protocol, service)."""
    return pd.DataFrame(
        [{"host_ip": h, "hostname": "", "port": p, "protocol": proto, "state": "open",
          "service": svc, "product": ""} for h, p, proto, svc in rows],
        columns=["host_ip", "hostname", "port", "protocol", "state", "service", "product"])
