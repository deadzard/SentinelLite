# SentinelLite - Presentation Guide (5-6 minutes)

## 1. Five-slide outline
1. **Problem and goal** - raw logs and scan output are hard to read; goal: explainable, local detection and prioritisation.
2. **Architecture** - CSV + Nmap XML → parsers → detectors → risk engine → recommendations → dashboard (use the Mermaid diagram from the README).
3. **Detection and scoring** - rolling 120 s window, 5+ = High pattern, 2-4 = Medium; unexpected-port policy; 70 / 30 points, cap 100, bands 0-29 / 30-59 / 60-100.
4. **Live demo** - see section 3.
5. **Testing, limitations, ethics, future work** - tests run, honest limits (not an IDS/SIEM), authorised use only.

## 2. Speaking script (about 5.5 minutes)
**Slide 1 (≈0:45).** "Good morning. Our project is SentinelLite, a lightweight security event detection and risk analysis
dashboard. Administrators drown in logs: thousands of login lines and port-scan results. Our goal was to build a small tool
that runs fully on a laptop, finds two common problems, and explains every decision it makes."

**Slide 2 (≈1:00).** "The tool takes two inputs: an authentication log in CSV form and an Nmap scan saved as XML. The parsers
validate the files: bad rows are skipped with a warning instead of crashing the program. The detectors apply rules, the risk
engine converts rules into scores, and the recommendation module suggests defensive steps. The result is a findings table
shown in a Streamlit dashboard and exportable as CSV. Nothing is blocked or changed automatically, and no internet is needed
after installation."

**Slide 3 (≈1:15).** "Rule one looks for repeated failed logins from the same IP inside a rolling two-minute window. Rolling
matters: a fixed one-minute bucket could miss six failures that straddle two buckets. Five or more in a window is the
brute-force pattern and scores 70, which is High. Two to four is a Medium burst. A lone failure is only a Low informational
note. Rule two compares open ports in the Nmap report with an editable expected-port policy; anything not allowed scores 30.
Scores are added per IP, but the same rule family is counted once, and the total is capped at 100. These are illustrative
project-defined scores, not probabilities of compromise."

**Slide 4 (≈2:00)** - run the demo in section 3 and narrate it.

**Slide 5 (≈0:45).** "We wrote automated tests for normal logins, isolated failures, repeated failures, rolling windows,
malformed files and score boundaries. The tool is rule-based, groups by IP, and uses small synthetic data, so it is a learning
project, not a production IDS or SIEM. Future work includes password-spraying detection, CIDR policies and real log formats.
We use it only on data from systems we own or are authorised to test. Thank you; we are happy to take questions."

## 3. Live demo sequence (about 2 minutes)
Files are in the `test_files` folder. The app starts empty.
| Time | Action | Say |
|---|---|---|
| 0:00 | App open on the empty start page | "Nothing is analysed until a file is uploaded." |
| 0:15 | Upload `alert_logs.csv` and `alert_scan.xml` | "One authentication log and one Nmap report, both synthetic." |
| 0:30 | Point at the verdict banner and metrics | "ALERTS RAISED - HIGH RISK. 15 events, 4 alerts: 1 High, 3 Medium." |
| 0:45 | Open **Explain an alert** on the High alert | "Six failures in 30 seconds from one IP: rule, threshold, score 70, recommendations." |
| 1:05 | Select the Medium login alert | "Only two failures, so a burst, not brute force." |
| 1:15 | Edit the policy: add `127.0.0.1 21/tcp` | "The FTP alert disappears because that port is now approved." |
| 1:30 | Click **Clear uploaded files**, upload `clean_logs.csv` and `clean_scan.xml` | "Normal activity gives CLEAN and no alerts." |
| 1:45 | Upload `logs_with_errors.csv`, then **Download findings (CSV)** | "Bad rows are listed and skipped; the report downloads as CSV." |

## 4. Viva questions and answers
1. **Why a rolling window instead of fixed time buckets?** A fixed bucket can split one attack across two buckets and miss it. A rolling window checks every 120-second span, so a burst is found wherever it starts.
2. **How does your window work technically?** Failures per IP are sorted by time; a two-pointer scan moves the left edge forward while the span exceeds 120 seconds, and counts the failures inside. It is linear after sorting.
3. **How do you avoid counting one failure many times?** Overlapping windows are merged into one incident, so each failure belongs to at most one incident. At scoring time only the highest rule per rule family counts for an IP, and the total is capped at 100.
4. **Why 70 and 30 points?** They are illustrative project-defined values: repeated failures are stronger evidence of an attack than an unexpected port, which may just be an undocumented service. They are not statistically validated and can be changed in the sidebar.
5. **Where do the 40 and 10 points come from?** The brief fixed only 70 and 30. We chose 40 for a 2-4 failure burst (Medium band) and 10 for isolated failures (Low band) as our own assumptions, and documented them.
6. **What are false positives here, and how could they occur?** A user who mistypes a password five times, a shared NAT address, or a legitimate service on an unlisted port. That is why every alert shows its reason and suggests *review*, not automatic blocking.
7. **What would cause false negatives?** A slow "low and slow" attack, or an attack spread across many IPs (password spraying/botnets), because we group by single IP and a 120 s window.
8. **Why not block the IP automatically?** Automatic blocking can lock out legitimate users or break services, and changing a firewall needs authorisation. SentinelLite only recommends actions for a human to take.
9. **How is this different from an IDS or SIEM?** An IDS inspects live traffic with large signature sets; a SIEM collects and correlates logs from many sources at scale with retention and alerting workflows. SentinelLite analyses two small files with four rules and is not production-grade.
10. **Why does Nmap XML get parsed instead of running Nmap?** It keeps the tool passive and safe: it never scans anything itself, so there is no risk of scanning an unauthorised system. The user runs Nmap deliberately against an authorised target.
11. **How do you handle bad input?** Row-level problems (bad timestamp, IP, status, field count) skip that row with a line-numbered warning. File-level problems (empty, missing columns, binary, malformed XML) show a clear error. The app continues running.
12. **Any security concerns in your own code?** XML with entity declarations is rejected (entity-expansion attacks); file size is limited; uploaded names and usernames are shown only as plain text; and CSV export prefixes cells starting with `=`, `+`, `-`, `@` to prevent spreadsheet formula injection.
13. **How does the expected-port policy work?** It is a default-deny allow-list: each line is `HOST PORT/PROTOCOL`. An open port that matches no rule for that host (or `*`) is flagged; a host with no rules has no approved ports.
14. **What does "Cloud" have to do with this?** The same checks apply to cloud VMs: exposed ports map to security-group rules and authentication logs come from cloud instances. The tool itself runs locally and uses no cloud services.
15. **How would you improve it?** Add password-spraying and impossible-travel rules, CIDR policies, more log formats, alert history, and tune thresholds on real (authorised) data.

## 5. Team contributions (fill in with the real, actual work of each member)
| Member name | Roll no. | Actual contribution (modules, tests, docs, slides, demo) | Files / commits |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
| | | | |

## 6. Measurable results to record after you run the project
Run `pytest -q` and the app yourself, then write down what you actually observe. Do **not** copy numbers you did not measure.
| Item | How to get it | Your recorded value |
|---|---|---|
| Python and package versions | `python --version`, `pip list` | |
| Tests passed / failed / total | output of `pytest -q` | |
| Test run time | last line of `pytest -q` | |
| Events loaded for `alert_logs.csv` | Authentication events tab | |
| Open-port records loaded for `alert_scan.xml` | Network scan tab | |
| Total alerts; High / Medium / Low for the alert pair | dashboard metrics | |
| Rows skipped for `logs_with_errors.csv` | validation messages | |
| Time for the app to start | stopwatch from running the launcher | |
| CSV report downloaded and opened successfully | yes / no | |
| Tested on (OS, browser) | | |
