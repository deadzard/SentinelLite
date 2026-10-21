"""
log_parser.py - load and validate authentication-event CSV files.

Expected columns (header names are case-insensitive; a few aliases are accepted):
    timestamp, source_ip, username, status

Design goals
* Never crash on bad input. Fatal problems (empty file, missing columns, no usable
  rows, binary data) raise LogParseError with a human-readable message.
* Row-level problems (bad timestamp, bad IP, unknown status, wrong field count)
  skip only that row and are reported as warnings.
* Output is a clean pandas DataFrame with normalised values:
    timestamp  -> naive datetime (timezone-aware inputs are converted to UTC)
    source_ip  -> normalised IPv4/IPv6 string
    username   -> stripped text
    status     -> "SUCCESS" or "FAILED"
    line       -> original line number in the CSV (for traceability)
"""
from __future__ import annotations

import csv
import io
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

REQUIRED_COLUMNS = ["timestamp", "source_ip", "username", "status"]
EVENT_COLUMNS = REQUIRED_COLUMNS + ["line"]

# Alternative header names that are mapped to the canonical names above.
COLUMN_ALIASES = {
    "time": "timestamp", "datetime": "timestamp", "date": "timestamp", "event_time": "timestamp",
    "ip": "source_ip", "src_ip": "source_ip", "sourceip": "source_ip", "ip_address": "source_ip",
    "remote_ip": "source_ip", "source": "source_ip",
    "user": "username", "user_name": "username", "account": "username",
    "login_status": "status", "result": "status", "outcome": "status",
}

SUCCESS_WORDS = {"success", "successful", "succeeded", "ok", "accepted"}
FAILED_WORDS = {"failed", "failure", "fail", "denied", "rejected"}

MAX_FILE_BYTES = 5 * 1024 * 1024   # 5 MB: plenty for a mini-project, stops accidental huge uploads
MAX_ROWS = 200_000
MAX_USERNAME_LEN = 128
MAX_WARNINGS_SHOWN = 20


class LogParseError(ValueError):
    """Raised when the whole authentication log cannot be used."""


@dataclass
class ParsedLogs:
    events: pd.DataFrame
    warnings: List[str] = field(default_factory=list)
    total_rows: int = 0      # data rows seen (blank lines excluded)
    skipped_rows: int = 0    # data rows rejected by validation


def empty_events() -> pd.DataFrame:
    """An empty events table with the right columns (used when nothing is loaded)."""
    return pd.DataFrame({
        "timestamp": pd.Series(dtype="datetime64[ns]"),
        "source_ip": pd.Series(dtype="object"),
        "username": pd.Series(dtype="object"),
        "status": pd.Series(dtype="object"),
        "line": pd.Series(dtype="int64"),
    })


# --------------------------------------------------------------------------- input handling
def parse_auth_log(source) -> ParsedLogs:
    """Parse a path (str/Path), raw bytes, or a file-like object."""
    if isinstance(source, (str, Path)):
        path = Path(source)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise LogParseError(f"'{path.name}' is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB.")
            raw = path.read_bytes()
        except OSError as exc:
            raise LogParseError(f"Could not read '{path.name}': {exc.strerror or exc}") from exc
    elif isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
    elif hasattr(source, "read"):
        raw = source.read()
        raw = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    else:
        raise LogParseError("Unsupported input type for the authentication log.")
    return parse_auth_log_bytes(raw)


def parse_auth_log_bytes(raw: bytes) -> ParsedLogs:
    if len(raw) > MAX_FILE_BYTES:
        raise LogParseError(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB limit.")
    if not raw.strip():
        raise LogParseError("The authentication log is empty (no header row and no events).")
    if b"\x00" in raw:
        raise LogParseError("The file looks like a binary file, not a CSV text file.")
    try:
        text = raw.decode("utf-8-sig")   # utf-8-sig also strips an Excel byte-order mark
    except UnicodeDecodeError as exc:
        raise LogParseError("The file is not valid UTF-8 text. Save it as 'CSV UTF-8' and try again.") from exc
    return parse_auth_log_text(text)


# --------------------------------------------------------------------------- core parser
def parse_auth_log_text(text: str) -> ParsedLogs:
    """Parse CSV text into a validated events table."""
    if not text.strip():
        raise LogParseError("The authentication log is empty (no header row and no events).")

    reader = csv.reader(io.StringIO(text))
    warnings: List[str] = []
    records: List[dict] = []
    total_rows = 0
    skipped = 0
    first_problem: Optional[str] = None

    try:
        header = next((row for row in reader if any(cell.strip() for cell in row)), None)
        if header is None:
            raise LogParseError("The authentication log is empty (no header row and no events).")

        column_index = _map_header(header)
        missing = [c for c in REQUIRED_COLUMNS if c not in column_index]
        if missing:
            found = ", ".join(c.strip() or "(blank)" for c in header)
            raise LogParseError(
                f"Missing required column(s): {', '.join(missing)}. "
                f"Required: {', '.join(REQUIRED_COLUMNS)}. Found: {found}."
            )

        for row in reader:
            if not any(cell.strip() for cell in row):
                continue  # ignore blank lines
            total_rows += 1
            if total_rows > MAX_ROWS:
                raise LogParseError(f"The log has more than {MAX_ROWS:,} rows, which is above the supported limit.")
            line = reader.line_num
            problem, record = _validate_row(row, len(header), column_index, line)
            if problem:
                skipped += 1
                first_problem = first_problem or f"line {line}: {problem}"
                if len(warnings) < MAX_WARNINGS_SHOWN:
                    warnings.append(f"Line {line}: {problem} - row skipped.")
            else:
                records.append(record)
    except csv.Error as exc:
        raise LogParseError(f"The file is not valid CSV: {exc}") from exc

    if skipped > MAX_WARNINGS_SHOWN:
        warnings.append(f"... and {skipped - MAX_WARNINGS_SHOWN} more rejected rows not listed.")
    if total_rows == 0:
        raise LogParseError("The file has a header row but no event rows.")
    if not records:
        raise LogParseError(
            f"No valid events found: all {total_rows} data row(s) were rejected. First problem: {first_problem}."
        )

    events = pd.DataFrame(records, columns=EVENT_COLUMNS)
    events = events.sort_values("timestamp", kind="stable").reset_index(drop=True)
    return ParsedLogs(events=events, warnings=warnings, total_rows=total_rows, skipped_rows=skipped)


# --------------------------------------------------------------------------- helpers
def _map_header(header: List[str]) -> Dict[str, int]:
    """Map canonical column name -> position, applying aliases (first match wins)."""
    mapping: Dict[str, int] = {}
    for position, raw_name in enumerate(header):
        name = raw_name.strip().lower().replace(" ", "_").replace("-", "_")
        name = COLUMN_ALIASES.get(name, name)
        if name in REQUIRED_COLUMNS and name not in mapping:
            mapping[name] = position
    return mapping


def _validate_row(row: List[str], n_columns: int, index: Dict[str, int],
                  line: int) -> Tuple[Optional[str], Optional[dict]]:
    """Return (problem, None) for a bad row or (None, record) for a good one."""
    if len(row) != n_columns:
        return f"expected {n_columns} fields but found {len(row)}", None

    timestamp = _parse_timestamp(row[index["timestamp"]])
    if timestamp is None:
        return f"invalid timestamp '{_short(row[index['timestamp']])}'", None

    try:
        ip = str(ipaddress.ip_address(row[index["source_ip"]].strip()))
    except ValueError:
        return f"invalid source IP '{_short(row[index['source_ip']])}'", None

    username = row[index["username"]].strip()
    if not username:
        return "missing username", None
    if len(username) > MAX_USERNAME_LEN:
        return f"username longer than {MAX_USERNAME_LEN} characters", None

    status_word = row[index["status"]].strip().lower()
    if status_word in SUCCESS_WORDS:
        status = "SUCCESS"
    elif status_word in FAILED_WORDS:
        status = "FAILED"
    else:
        return f"unknown login status '{_short(row[index['status']])}' (use SUCCESS or FAILED)", None

    return None, {"timestamp": timestamp, "source_ip": ip, "username": username,
                  "status": status, "line": line}


def _parse_timestamp(value: str) -> Optional[datetime]:
    """ISO-8601 first (e.g. 2026-10-19 09:15:00 or ...T09:15:00Z), then a few common formats."""
    text = value.strip()
    if not text:
        return None
    if text[-1] in "zZ":
        text = text[:-1] + "+00:00"
    parsed: Optional[datetime] = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None or not (1990 <= parsed.year <= 2100):
        return None
    if parsed.tzinfo is not None:  # normalise to naive UTC so all comparisons are consistent
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _short(value: str, limit: int = 40) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[:limit] + "..."
