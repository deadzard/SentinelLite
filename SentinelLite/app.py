"""
app.py - SentinelLite Streamlit dashboard.

Run with:   streamlit run app.py

The page starts EMPTY: no results are shown until you upload a CSV and/or an Nmap XML file in the
sidebar (localhost or authorised lab machines only). There is no built-in demo data.

Design rule: every custom element sets BOTH its background and its text colour, so it stays readable
whether Streamlit is showing its light or its dark theme.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

import pandas as pd
import streamlit as st

from detector import DetectionConfig, parse_policy_text
from log_parser import LogParseError, empty_events, parse_auth_log
from nmap_parser import ScanParseError, empty_ports, parse_nmap_xml
from pipeline import (SEVERITIES, analyze, findings_to_csv, load_default_policy_text, severity_counts,
                      verdict)
from risk_engine import ScoringConfig

FAVICON_PATH = Path(__file__).resolve().parent / "assets" / "favicon.png"
try:
    from PIL import Image
    _icon = Image.open(FAVICON_PATH)
except Exception:  # Pillow missing or file removed: Streamlit's default icon is used
    _icon = None

st.set_page_config(page_title="SentinelLite", page_icon=_icon, layout="wide")

# ----------------------------------------------------------------------------- look and feel
# Colour pairs: (text colour, background colour)
LEVEL_COLORS = {
    "high": ("#B42318", "#FEE4E2"),
    "medium": ("#B54708", "#FEF0C7"),
    "clean": ("#067647", "#D1FADF"),
    "info": ("#067647", "#D1FADF"),
    "nodata": ("#3B4656", "#E4E7EC"),
}
SEVERITY_COLORS = {"High": LEVEL_COLORS["high"], "Medium": LEVEL_COLORS["medium"], "Low": LEVEL_COLORS["clean"]}

CSS = """
<style>
.block-container {padding-top: 1.6rem; padding-bottom: 2rem; max-width: 1280px;}

.sl-hero {background: #0B2545; color: #FFFFFF; padding: 22px 28px; border-radius: 8px; margin-bottom: 16px;}
.sl-hero-title {font-size: 1.9rem; font-weight: 700; line-height: 1.2; color: #FFFFFF;}
.sl-hero-sub {font-size: 1.05rem; color: #DCE6F5; margin-top: 4px;}
.sl-hero-text {font-size: 0.95rem; color: #C5D4EC; margin-top: 10px; max-width: 900px;}

.sl-verdict {border-radius: 8px; padding: 16px 22px; margin-bottom: 14px; border-left: 10px solid;}
.sl-verdict-title {font-size: 1.35rem; font-weight: 700;}
.sl-verdict-detail {font-size: 1rem; margin-top: 2px;}

.sl-card {background: #FFFFFF; color: #1B2430; border: 1px solid #D0D7E2; border-radius: 8px;
          padding: 14px 18px; min-height: 128px; margin-bottom: 14px;}
.sl-card-title {font-size: 0.78rem; font-weight: 700; letter-spacing: 0.06em; color: #556070;}
.sl-card-main {font-size: 1rem; font-weight: 600; margin: 4px 0 8px 0; word-break: break-word; color: #1B2430;}
.sl-card-sub {font-size: 0.88rem; color: #3B4656; margin-top: 6px;}
.sl-tag {display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.82rem; font-weight: 700;}

.sl-metric {background: #FFFFFF; color: #1B2430; border: 1px solid #D0D7E2; border-top: 5px solid #1F6FEB;
            border-radius: 8px; padding: 12px 16px; min-height: 108px; margin-bottom: 8px;}
.sl-metric-label {font-size: 0.85rem; font-weight: 600; color: #3B4656;}
.sl-metric-value {font-size: 2.2rem; font-weight: 700; line-height: 1.2; color: #0B2545;}
.sl-metric-sub {font-size: 0.78rem; color: #556070;}

.sl-section {background: #E8EEF7; color: #0B2545; border-left: 5px solid #1F6FEB; border-radius: 4px;
             padding: 8px 14px; font-size: 1.15rem; font-weight: 700; margin: 22px 0 10px 0;}
.sl-panel {background: #FFFFFF; color: #1B2430; border: 1px solid #D0D7E2; border-radius: 8px; padding: 10px 14px;}
.sl-text {background: #F8FAFC; color: #1B2430; border: 1px solid #D0D7E2; border-radius: 6px;
          padding: 10px 14px; font-size: 0.95rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word;}
.sl-step {display: flex; gap: 10px; margin: 8px 0; font-size: 0.95rem; line-height: 1.45;}
.sl-step-no {flex: 0 0 26px; height: 26px; border-radius: 6px; background: #1F6FEB; color: #FFFFFF;
             font-weight: 700; font-size: 0.82rem; text-align: center; line-height: 26px;}
.sl-legend {width: 100%; border-collapse: collapse; font-size: 0.92rem; color: #1B2430; background: #FFFFFF;}
.sl-legend td, .sl-legend th {padding: 7px 10px; border-bottom: 1px solid #D0D7E2; text-align: left; color: #1B2430;}
.sl-legend th {color: #556070; font-size: 0.78rem; letter-spacing: 0.05em;}
.sl-legend-note {font-size: 0.88rem; color: #3B4656; padding-top: 10px;}
.sl-footer {font-size: 0.82rem; opacity: 0.85; border-top: 1px solid #8892A0; padding-top: 12px; margin-top: 22px;}
</style>
"""
# flatten the CSS so Markdown never mistakes indented lines for a code block
CSS = "\n".join(line.strip() for line in CSS.splitlines() if line.strip())
st.markdown(CSS, unsafe_allow_html=True)


# ----------------------------------------------------------------------------- helpers
def esc(value) -> str:
    """HTML-escape anything that came from a file before it is placed in custom HTML."""
    return html.escape(str(value), quote=True)


def safe_name(name: str) -> str:
    """File names come from the user's computer; keep only harmless characters for display/CSV."""
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:60]


def tag(text: str, level: str) -> str:
    fg, bg = LEVEL_COLORS[level]
    return f'<span class="sl-tag" style="background:{bg};color:{fg};">{esc(text)}</span>'


def section(title: str) -> None:
    st.markdown(f'<div class="sl-section">{esc(title)}</div>', unsafe_allow_html=True)


def metric_card(label: str, value, sub: str = "", accent: str = "#1F6FEB") -> str:
    return (f'<div class="sl-metric" style="border-top-color:{accent};">'
            f'<div class="sl-metric-label">{esc(label)}</div>'
            f'<div class="sl-metric-value">{esc(value)}</div>'
            f'<div class="sl-metric-sub">{esc(sub)}</div></div>')


def style_severity(df: pd.DataFrame):
    """Colour the severity column. Falls back to a plain table if styling is unavailable."""
    try:
        def paint(value):
            fg, bg = SEVERITY_COLORS.get(value, ("#111111", "#FFFFFF"))
            return f"background-color: {bg}; color: {fg}; font-weight: 700;"
        return df.style.map(paint, subset=["severity"])
    except Exception:  # older pandas or missing jinja2: styling is cosmetic only
        return df


NO_FILE_LABEL = "No file uploaded, this source is not analysed"


def load_auth(uploaded):
    """Return (events, label, warnings, error). Nothing is loaded unless the person uploaded a file."""
    if uploaded is None:
        return empty_events(), NO_FILE_LABEL, [], None
    label = f"Uploaded file: {safe_name(uploaded.name)}"
    try:
        parsed = parse_auth_log(uploaded.getvalue())
        return parsed.events, label, parsed.warnings, None
    except LogParseError as exc:
        return empty_events(), "Upload rejected, no authentication data loaded", [], f"{label}: {exc}"


def load_scan(uploaded):
    """Return (ports, scan_time, label, warnings, error)."""
    if uploaded is None:
        return empty_ports(), None, NO_FILE_LABEL, [], None
    label = f"Uploaded file: {safe_name(uploaded.name)}"
    try:
        parsed = parse_nmap_xml(uploaded.getvalue())
        return parsed.ports, parsed.scan_time, label, parsed.warnings, None
    except ScanParseError as exc:
        return empty_ports(), None, "Upload rejected, no scan data loaded", [], f"{label}: {exc}"


def render_header() -> None:
    st.markdown(
        '<div class="sl-hero"><div class="sl-hero-title">SentinelLite</div>'
        '<div class="sl-hero-sub">Lightweight Security Event Detection and Risk Analysis Dashboard</div>'
        '<div class="sl-hero-text">Reads an authentication log (CSV) and an Nmap scan (XML), flags repeated '
        'failed logins and unexpected open ports, gives each finding an explainable risk score and suggests '
        'defensive actions. It runs locally and never blocks, scans or changes anything.</div></div>',
        unsafe_allow_html=True)


def render_footer() -> None:
    st.markdown(
        '<div class="sl-footer">SentinelLite is an educational mini-project, not a production IDS or SIEM. '
        'Risk scores are illustrative project-defined values, not validated probabilities of compromise. '
        'Only analyse data from systems you own or are authorised to test.</div>',
        unsafe_allow_html=True)


# ----------------------------------------------------------------------------- sidebar
if "uploader_key" not in st.session_state:
    st.session_state["uploader_key"] = 0
key = st.session_state["uploader_key"]

with st.sidebar:
    st.markdown("### SentinelLite")
    st.caption("Load data here, read the results on the right.")

    st.markdown("**1. Authentication log**")
    log_file = st.file_uploader("CSV file", type=["csv"], key=f"log_{key}",
                                help="Columns: timestamp, source_ip, username, status (SUCCESS/FAILED).")
    st.markdown("**2. Network scan**")
    scan_file = st.file_uploader("Nmap XML file", type=["xml"], key=f"scan_{key}",
                                 help="Created with: nmap -sV -oX scan.xml 127.0.0.1 (authorised targets only)")
    if st.button("Clear uploaded files"):
        st.session_state["uploader_key"] += 1   # a new key resets both uploaders and the policy box
        st.rerun()
    st.caption("Results appear only after you upload at least one file. You can upload just one of the two.")

    st.markdown("**3. Expected-port policy**")
    with st.expander("View or edit allowed ports", expanded=False):
        policy_text = st.text_area("One rule per line: HOST PORT/PROTOCOL", value=load_default_policy_text(),
                                   height=220, key=f"policy_{key}",
                                   help="Use * for any host. Ranges such as 8000-8010/tcp are allowed. "
                                        "Open ports not listed for a host are flagged.")

    st.markdown("**4. Settings**")
    with st.expander("Detection and scoring", expanded=False):
        window = st.number_input("Rolling window (seconds)", 10, 3600, 120, 10)
        high_failures = st.number_input("Failures for brute-force alert", 3, 100, 5, 1)
        p_brute = st.number_input("Points: repeated failures (5+)", 0, 100, 70, 5)
        p_burst = st.number_input("Points: failure burst (2-4)", 0, 100, 40, 5)
        p_isolated = st.number_input("Points: isolated failure", 0, 100, 10, 5)
        p_port = st.number_input("Points: unexpected port", 0, 100, 30, 5)
        st.caption("Scores are illustrative, project-defined values, not probabilities of compromise.")

# ----------------------------------------------------------------------------- empty state
if log_file is None and scan_file is None:
    render_header()
    st.markdown(
        '<div class="sl-verdict" style="background:#E4E7EC;border-left-color:#3B4656;color:#1B2430;">'
        '<div class="sl-verdict-title">No data loaded yet</div>'
        '<div class="sl-verdict-detail">Upload a file in the sidebar to see results. Nothing is analysed '
        'until you do.</div></div>', unsafe_allow_html=True)
    section("How to use it")
    st.markdown(
        '<div class="sl-panel">'
        '<div class="sl-step"><div class="sl-step-no">1</div><div><b>Authentication log.</b> Upload a CSV with the '
        'columns timestamp, source_ip, username, status (SUCCESS or FAILED) in the first upload box.</div></div>'
        '<div class="sl-step"><div class="sl-step-no">2</div><div><b>Network scan.</b> Upload an Nmap XML report '
        'in the second box. Create it only for localhost or a lab machine you are authorised to test: '
        '<code>nmap -sV -oX scan.xml 127.0.0.1</code></div></div>'
        '<div class="sl-step"><div class="sl-step-no">3</div><div><b>Read the verdict.</b> You get CLEAN or '
        'ALERTS RAISED, a risk score for every finding, the rule that fired and suggested defensive '
        'actions.</div></div></div>', unsafe_allow_html=True)
    render_footer()
    st.stop()

# ----------------------------------------------------------------------------- analysis
errors, warnings = [], []
try:
    detection = DetectionConfig(window_seconds=int(window), high_threshold=int(high_failures))
    scoring = ScoringConfig(auth_brute_points=int(p_brute), auth_burst_points=int(p_burst),
                            auth_isolated_points=int(p_isolated), port_unexpected_points=int(p_port))
except ValueError as exc:
    errors.append(f"Invalid settings, defaults used instead: {exc}")
    detection, scoring = DetectionConfig(), ScoringConfig()

auth_events, auth_label, w, e = load_auth(log_file)
warnings += w
errors += [e] if e else []
ports, scan_time, scan_label, w, e = load_scan(scan_file)
warnings += w
errors += [e] if e else []
policy_rules, w = parse_policy_text(policy_text)
warnings += w

result = analyze(auth_events, ports, scan_time, policy_rules, detection, scoring, auth_label, scan_label)
findings = result.findings
counts = severity_counts(findings)
overall = verdict(findings, result.total_events)
auth_v = verdict(findings, len(auth_events), "Authentication")
scan_v = verdict(findings, len(ports), "Network")

# ----------------------------------------------------------------------------- 1. header + verdict
render_header()

fg, bg = LEVEL_COLORS[overall.level]
st.markdown(
    f'<div class="sl-verdict" style="background:{bg};border-left-color:{fg};color:{fg};">'
    f'<div class="sl-verdict-title">Overall verdict: {esc(overall.title)}</div>'
    f'<div class="sl-verdict-detail">{esc(overall.detail)}</div></div>',
    unsafe_allow_html=True)


def source_card(title: str, label: str, v) -> str:
    return (f'<div class="sl-card"><div class="sl-card-title">{esc(title)}</div>'
            f'<div class="sl-card-main">{esc(label)}</div>{tag(v.title, v.level)}'
            f'<div class="sl-card-sub">{esc(v.detail)}</div></div>')


card_a, card_b = st.columns(2)
card_a.markdown(source_card("AUTHENTICATION DATA", auth_label, auth_v), unsafe_allow_html=True)
card_b.markdown(source_card("NETWORK SCAN DATA", scan_label, scan_v), unsafe_allow_html=True)

for message in errors:
    st.error(message)
if warnings:
    with st.expander(f"Input validation messages ({len(warnings)})"):
        for message in warnings:
            st.text(message)

# ----------------------------------------------------------------------------- 2. numbers
m = st.columns(5)
m[0].markdown(metric_card("Events analysed", result.total_events,
                          f"{len(auth_events)} logins + {len(ports)} open ports"), unsafe_allow_html=True)
m[1].markdown(metric_card("Alerts", len(findings), "all severities", "#556070"), unsafe_allow_html=True)
m[2].markdown(metric_card("High risk", counts["High"], "score 60 to 100", "#B42318"), unsafe_allow_html=True)
m[3].markdown(metric_card("Medium risk", counts["Medium"], "score 30 to 59", "#B54708"), unsafe_allow_html=True)
m[4].markdown(metric_card("Low risk", counts["Low"], "score 0 to 29", "#067647"), unsafe_allow_html=True)

# ----------------------------------------------------------------------------- 3. chart + legend
chart_col, legend_col = st.columns(2)
with chart_col:
    section("Alerts by severity")
    with st.container(border=True):
        chart = pd.DataFrame({"Severity": SEVERITIES, "Alerts": [counts[s] for s in SEVERITIES]})
        try:
            # sort=False keeps the order High, Medium, Low (a list is NOT a valid value for 'sort')
            st.bar_chart(chart, x="Severity", y="Alerts", sort=False, height=230)
        except Exception:  # Streamlit version without these options: plain chart
            st.bar_chart(chart.set_index("Severity"))
with legend_col:
    section("How scores work")
    st.markdown(
        '<div class="sl-panel"><table class="sl-legend"><tr><th>RULE</th><th>TRIGGER</th><th>POINTS</th></tr>'
        f'<tr><td>Repeated failures</td><td>{detection.high_threshold}+ failed logins from one IP in '
        f'{detection.window_seconds}s</td><td><b>{scoring.auth_brute_points}</b></td></tr>'
        f'<tr><td>Failure burst</td><td>2 to {detection.high_threshold - 1} failures in the window</td>'
        f'<td><b>{scoring.auth_burst_points}</b></td></tr>'
        f'<tr><td>Isolated failure</td><td>single failed login</td><td><b>{scoring.auth_isolated_points}</b></td></tr>'
        f'<tr><td>Unexpected port</td><td>open port not in the policy</td><td><b>{scoring.port_unexpected_points}</b></td></tr>'
        '</table>'
        f'<div class="sl-legend-note">Per IP: highest rule per family, summed, capped at {scoring.max_score}. '
        f'{tag("Low 0-29", "clean")} {tag("Medium 30-59", "medium")} {tag("High 60-100", "high")}<br>'
        'Illustrative project-defined scores, not probabilities of compromise.</div></div>',
        unsafe_allow_html=True)

# ----------------------------------------------------------------------------- 4. alerts table
section("Alerts and incidents")
f1, f2 = st.columns(2)
sev_choice = f1.multiselect("Filter by severity", SEVERITIES, default=SEVERITIES)
ip_choice = f2.multiselect("Filter by source IP (empty = all)", sorted(findings["source"].unique()))

view = findings[findings["severity"].isin(sev_choice)]
if ip_choice:
    view = view[view["source"].isin(ip_choice)]

if view.empty:
    st.info("No alerts match the current filters." if not findings.empty else
            "No alerts were generated for the loaded data.")
else:
    shown = view[["alert_id", "timestamp", "severity", "risk_score", "source", "target", "rule_id", "category"]]
    st.dataframe(style_severity(shown), hide_index=True, column_config={
        "alert_id": st.column_config.TextColumn("Alert", width="small"),
        "timestamp": st.column_config.TextColumn("Time", width="medium"),
        "severity": st.column_config.TextColumn("Severity", width="small"),
        "risk_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100,
                                                      format="%d", width="medium"),
        "source": st.column_config.TextColumn("Source IP", width="medium"),
        "target": st.column_config.TextColumn("Target", width="medium"),
        "rule_id": st.column_config.TextColumn("Rule", width="medium"),
        "category": st.column_config.TextColumn("Type", width="small"),
    })
    st.download_button("Download findings (CSV, rows currently shown)",
                       data=findings_to_csv(view).encode("utf-8"),
                       file_name="sentinellite_findings.csv", mime="text/csv")
    st.caption("Clear the filters to export the complete report. The data_source column records which uploaded file "
               "each finding came from.")

    # ------------------------------------------------------------------------- 5. explain one alert
    section("Explain an alert")
    labels = {r.alert_id: f"{r.alert_id} | {r.severity} | {r.source} | {r.rule_id}" for r in view.itertuples()}
    chosen = st.selectbox("Choose an alert", list(labels), format_func=lambda a: labels[a])
    row = view[view["alert_id"] == chosen].iloc[0]
    level = row["severity"].lower() if row["severity"] != "Low" else "clean"
    with st.container(border=True):
        st.markdown(
            f'{tag(row["severity"] + " risk", level)} &nbsp; <b>{esc(row["alert_id"])}</b> &nbsp;|&nbsp; '
            f'risk score <b>{int(row["risk_score"])}/100</b> &nbsp;|&nbsp; source <b>{esc(row["source"])}</b> '
            f'&nbsp;|&nbsp; target <b>{esc(row["target"])}</b>', unsafe_allow_html=True)
        left, right = st.columns(2)
        with left:
            st.markdown("**Why it fired** (detection rule)")
            st.markdown(f'<div class="sl-text">{esc(row["detection_reason"])}</div>', unsafe_allow_html=True)
            st.markdown("**Score breakdown**")
            st.markdown(f'<div class="sl-text">{esc(row["score_breakdown"])}</div>', unsafe_allow_html=True)
        with right:
            st.markdown("**Suggested defensive actions** (manual review only)")
            steps = "".join(f'<div class="sl-step"><div class="sl-step-no">{i}</div><div>{esc(s)}</div></div>'
                            for i, s in enumerate(row["recommendation"].split(" | "), start=1))
            st.markdown(steps, unsafe_allow_html=True)

# ----------------------------------------------------------------------------- 6. raw data
section("Loaded data")
tab_auth, tab_scan = st.tabs(["Authentication events", "Network scan results"])
with tab_auth:
    st.caption(f"Source: {auth_label}")
    if auth_events.empty:
        st.info("No authentication events loaded.")
    else:
        st.dataframe(auth_events[["timestamp", "source_ip", "username", "status"]], hide_index=True)
with tab_scan:
    st.caption(f"Source: {scan_label}" + (f" | scan time (UTC): {scan_time:%Y-%m-%d %H:%M:%S}" if scan_time else ""))
    if ports.empty:
        st.info("No open ports loaded.")
    else:
        st.dataframe(ports[["host_ip", "hostname", "port", "protocol", "service", "product"]], hide_index=True)

render_footer()
