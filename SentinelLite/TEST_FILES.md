# Test files: upload these to check that SentinelLite works

The app shows **nothing** until you upload a file. All files are in the `test_files` folder, are synthetic, and use the
default expected-port policy (`127.0.0.1` allows 22, 80 and 443). Upload the CSV in the first box and the XML in the second.

| Upload | Expected verdict | What you should see |
|---|---|---|
| `alert_logs.csv` + `alert_scan.xml` | **ALERTS RAISED - HIGH RISK** | 15 events, 4 alerts (1 High, 3 Medium). `198.51.100.200`: 6 failed logins in 30 seconds, score 70, High, with a later successful login noted as evidence. `bob` (`192.0.2.11`): 2 failures, score 40, Medium. Ports 21 (FTP) and 3389 (Remote Desktop) on 127.0.0.1 are not in the policy: 30 each, Medium. |
| `alert_logs.csv` only | ALERTS RAISED - HIGH RISK | 2 alerts (1 High, 1 Medium). The network box shows "No file uploaded". |
| `alert_scan.xml` only | ALERTS RAISED - MEDIUM RISK | 2 alerts (both Medium). |
| `clean_logs.csv` + `clean_scan.xml` | **CLEAN** | 8 events, 0 alerts. |
| `logs_with_errors.csv` | validation messages | 3 valid rows analysed, 5 rows skipped with line numbers. |
| an empty file | NO DATA ANALYSED | a clear error message, never reported as clean. |

Try it: after loading `alert_scan.xml`, open "View or edit allowed ports" in the sidebar and add `127.0.0.1 21/tcp`.
The FTP alert disappears.
