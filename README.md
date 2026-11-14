# Detection-as-Code: Tested Sigma Rules

[![Sigma rules CI](https://github.com/pulemoliserr/detection-as-code/actions/workflows/sigma-ci.yml/badge.svg)](https://github.com/pulemoliserr/detection-as-code/actions/workflows/sigma-ci.yml)

Part of my cybersecurity portfolio: [project write-up](https://pulemolise.net/cybersecurity/detection-as-code/) · [pulemolise.net](https://pulemolise.net)

A small, tested library of **Sigma detection rules**, each mapped to **MITRE ATT&CK** and checked automatically against sample attack and benign log events. Rules are converted to **Splunk** and **Elastic** queries on every commit.

Detection-as-code applies software practices to SOC detections: rules live in version control, every rule has tests, and a pipeline proves a change hasn't broken anything before it reaches the SIEM.

## What's in it

| | |
|---|---|
| **Rules** | 16 (12 detections + 2 brute-force correlations + their 2 base rules) |
| **ATT&CK coverage** | 15 techniques across 8 tactics: see [docs/coverage.md](docs/coverage.md) |
| **Log sources** | Windows Sysmon process creation, Windows Security log, Linux auth and process logs, web server logs |
| **Tests** | 119 sample events: every rule must fire on all its attack events and stay silent on benign look-alikes |
| **Outputs** | Splunk SPL and Elastic Lucene queries ([docs/queries.md](docs/queries.md)), an [ATT&CK Navigator layer](docs/attack-navigator-layer.json) |

| Rule | ATT&CK | Level |
|---|---|---|
| PowerShell encoded command | T1059.001, T1027 | high |
| PowerShell download cradle | T1059.001, T1105 | medium |
| Office app spawning a shell (malicious macro) | T1566.001, T1204.002 | high |
| Shadow copy / backup deletion (ransomware) | T1490 | critical |
| LSASS memory dump | T1003.001 | critical |
| Suspicious scheduled task | T1053.005 | medium |
| Security event log cleared | T1070.001 | high |
| User added to local Administrators | T1098 | medium |
| Windows logon brute force (correlation: 10+ failures / 5 min / source IP) | T1110 | high |
| Linux SSH brute force (correlation: 10+ failures / 5 min / source IP) | T1110.001 | high |
| Linux local user created | T1136.001 | medium |
| Linux permissions made world-writable | T1222.002 | medium |
| Web path traversal | T1190 | high |
| Web SQL injection | T1190 | high |

Several rules connect to earlier portfolio projects: the brute-force correlations to the website-compromise incident (05), the SQL injection rule to the SQL investigation (08), the world-writable rule to the Linux permissions lab (07), and the path-traversal rule to CWE-22, one of the most common weakness types in the KEV Tracker data.

## How the tests work

```
rules/*.yml ──pySigma──▶ SQL query ──▶ run against tests/<rule-id>.yml events in SQLite
                                         ├─ match:   every attack event must alert
                                         └─ nomatch: no benign event may alert
```

Each rule is converted to SQL with pySigma's SQLite backend and run against an in-memory table built from its test events. Correlation rules are tested with timed event sequences, for example 15 failed SSH logins in 30 seconds (must alert), and 9 in a burst or 12 spread over two hours (must not). The test runner also lints every rule: it must have an ATT&CK technique tag, a level, a description and documented false positives.

```text
$ python scripts/run_tests.py
Rule                                                Type         TP hits  FP hits  Result
------------------------------------------------------------------------------------------
Linux SSH Brute Force from a Single Source          correlation        6        0  PASS
Shadow Copy or Backup Catalog Deletion              detection          3        0  PASS
...
16/16 rules passed
```

The tests catch real mistakes. While building this, they showed that the first version of the LSASS rule missed the `comsvcs.dll MiniDump` technique, because attackers pass LSASS's process ID, not its name. The rule was fixed and the test now guards against that regression. Full output: [docs/test-results.txt](docs/test-results.txt).

## Run it

```bash
pip install -r requirements.txt
python scripts/run_tests.py                       # lint + test all rules

pip install --no-deps -r requirements-convert.txt # SIEM converters (see note in the file)
python scripts/build_docs.py                      # regenerate docs/
```

**CI:** `.github/workflows/sigma-ci.yml` runs the tests on every push and pull request, then converts the rules and uploads the SIEM queries as a build artifact. 

**ATT&CK Navigator:** open <https://mitre-attack.github.io/attack-navigator/>, choose *Open Existing Layer → Upload from local*, and select `docs/attack-navigator-layer.json` to see the coverage heatmap. A screenshot of it makes a good image for this README.

## Adding a rule

1. Write `rules/<platform>/<name>.yml` with a new UUID, ATT&CK tags, level and false positives.
2. Create `tests/<rule-id>.yml` with `match:` events (real attack examples) and `nomatch:` events (the closest benign activity you can think of).
3. Run `python scripts/run_tests.py` until it passes, then rebuild the docs.

## Limitations and next steps

- The sample events are hand-written. The next step is to replace them with **real logs from the home SOC lab**: run the matching Atomic Red Team tests, export the events, and use them as test data.
- Field names follow Sigma's generic taxonomy. Real SIEMs may need a field-mapping pipeline.
- Rule thresholds (such as 10 failures in 5 minutes) are starting points to tune against real traffic.

