"""
nmap_parser.py - read an Nmap XML report (nmap -oX file.xml) into a table of open ports.

SAFETY / ETHICS
* This module only READS an existing XML file. It never runs Nmap and never touches the network.
* Only scan localhost or a lab machine you own or have written permission to test.

Security note on XML: Python's ElementTree is not hardened against every XML attack, so files
that declare XML entities (<!ENTITY ...>) are rejected. Real Nmap reports never declare entities;
they only contain a plain "<!DOCTYPE nmaprun>" line, which is accepted.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pandas as pd

PORT_COLUMNS = ["host_ip", "hostname", "port", "protocol", "state", "service", "product"]
MAX_FILE_BYTES = 10 * 1024 * 1024


class ScanParseError(ValueError):
    """Raised when the Nmap XML report cannot be used."""


@dataclass
class ParsedScan:
    ports: pd.DataFrame                      # one row per OPEN port
    scan_time: Optional[datetime] = None     # UTC, from <nmaprun start="...">
    hosts_total: int = 0
    hosts_up: int = 0
    warnings: List[str] = field(default_factory=list)


def empty_ports() -> pd.DataFrame:
    return pd.DataFrame({
        "host_ip": pd.Series(dtype="object"), "hostname": pd.Series(dtype="object"),
        "port": pd.Series(dtype="int64"), "protocol": pd.Series(dtype="object"),
        "state": pd.Series(dtype="object"), "service": pd.Series(dtype="object"),
        "product": pd.Series(dtype="object"),
    })


def parse_nmap_xml(source) -> ParsedScan:
    """Parse a path (str/Path), raw bytes, or a file-like object."""
    if isinstance(source, (str, Path)):
        path = Path(source)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ScanParseError(f"'{path.name}' is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB.")
            raw = path.read_bytes()
        except OSError as exc:
            raise ScanParseError(f"Could not read '{path.name}': {exc.strerror or exc}") from exc
    elif isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
    elif hasattr(source, "read"):
        raw = source.read()
        raw = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    else:
        raise ScanParseError("Unsupported input type for the Nmap report.")
    return parse_nmap_xml_bytes(raw)


def parse_nmap_xml_bytes(raw: bytes) -> ParsedScan:
    if len(raw) > MAX_FILE_BYTES:
        raise ScanParseError(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB limit.")
    if not raw.strip():
        raise ScanParseError("The Nmap XML file is empty.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ScanParseError("The Nmap XML file is not UTF-8 text (Nmap normally writes UTF-8).") from exc
    return parse_nmap_xml_text(text)


def parse_nmap_xml_text(text: str) -> ParsedScan:
    if not text.strip():
        raise ScanParseError("The Nmap XML file is empty.")
    if "<!entity" in text.lower():
        raise ScanParseError("XML entity declarations are not accepted for security reasons. "
                             "Use an unmodified report produced by 'nmap -oX'.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ScanParseError(f"Malformed XML - the file could not be parsed ({exc}).") from exc

    if root.tag != "nmaprun":
        raise ScanParseError(f"This does not look like an Nmap report (root element is <{root.tag}>, expected <nmaprun>).")

    warnings: List[str] = []
    scan_time = _epoch_to_datetime(root.get("start"))
    rows: List[dict] = []
    hosts_total = hosts_up = 0

    for index, host in enumerate(root.findall("host"), start=1):
        hosts_total += 1
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue  # host did not answer: nothing to analyse

        ip = _host_address(host)
        if ip is None:
            warnings.append(f"Host #{index} has no IP address and was skipped.")
            continue
        hosts_up += 1

        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        for port_el in host.findall("ports/port"):
            port_id = port_el.get("portid", "")
            try:
                port = int(port_id)
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                warnings.append(f"Host {ip}: invalid port number '{port_id[:20]}' skipped.")
                continue
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue  # closed / filtered ports are not exposed services
            service_el = port_el.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            product = ""
            if service_el is not None:
                product = " ".join(p for p in (service_el.get("product", ""), service_el.get("version", "")) if p)
            rows.append({"host_ip": ip, "hostname": hostname, "port": port,
                         "protocol": (port_el.get("protocol") or "tcp").lower(),
                         "state": state, "service": service or "unknown", "product": product})

    if hosts_total == 0:
        warnings.append("The report contains no <host> entries (the scan may have found no live hosts).")
    elif not rows:
        warnings.append("No open ports were found in this report.")

    ports = pd.DataFrame(rows, columns=PORT_COLUMNS) if rows else empty_ports()
    return ParsedScan(ports=ports, scan_time=scan_time, hosts_total=hosts_total,
                      hosts_up=hosts_up, warnings=warnings)


def _host_address(host: ET.Element) -> Optional[str]:
    """Prefer an IPv4 address, then IPv6. MAC addresses are ignored."""
    addresses = {a.get("addrtype"): a.get("addr") for a in host.findall("address")}
    return addresses.get("ipv4") or addresses.get("ipv6") or None


def _epoch_to_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError, OSError):
        return None
