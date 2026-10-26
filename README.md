# detection-as-code

Sigma detection rules managed like software: every rule is version-controlled, unit-tested against malicious and benign events, converted to Splunk and Elastic, and mapped to MITRE ATT&CK — automatically on every pull request.

## Pipeline

```
rules/*.yml (Sigma)
   │
   ├─ yamllint ............ syntax and style
   ├─ validate.py ......... required metadata, ATT&CK tags, unique IDs, fixtures exist, converts to every SIEM
   ├─ pytest .............. each rule fires on positive events and stays silent on negative ones
   ├─ convert.py .......... Splunk SPL · Elastic Lucene · Elastic ES|QL  → build/
   └─ coverage.py ......... ATT&CK Navigator layer + COVERAGE.md
```

Rules are tested by compiling Sigma to SQL (pySigma SQLite backend) and running it against each fixture event in an in-memory database. That means a rule is tested on its real logic, not by string matching, and a change that breaks a rule fails CI before it reaches a SIEM.

## Why the first two rules exist together

`win_proc_arp_cache_discovery` catches ARP cache enumeration through `arp.exe`. Emulating the same discovery step with PowerShell `Get-NetNeighbor` produced no alert: no new process is created, so the process-creation rule is blind. `win_ps_netneighbor_discovery` closes that gap using Script Block Logging (Event ID 4104). This is the workflow the repo is built around: emulate → find the gap → write the rule → prove it with tests.

## Layout

| Path | Contents |
| --- | --- |
| `rules/<platform>/<category>/` | Sigma rules |
| `tests/fixtures/<rule>.yml` | Positive and negative events for each rule |
| `scripts/` | Validation, conversion, coverage |
| `docs/rule-template.md` | ADS-style documentation template |
| `COVERAGE.md` | Generated ATT&CK coverage table |

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make            # lint, validate, test, build
```

## Adding a rule

1. Write the Sigma rule in `rules/…` with at least one `attack.tXXXX` tag.
2. Add `tests/fixtures/<same-name>.yml` with at least one positive and one negative event.
3. Run `make`, open a pull request; CI must be green to merge.

## Notes

- Field names follow Sysmon / Sigma conventions. Elastic queries use the ECS mapping from `pySigma-pipeline-elasticsearch`; Splunk queries do not include an index or sourcetype — prepend your own (e.g. `index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`).
- Fixtures are hand-written from real event structure. Replay against recorded attack data (OTRF Security-Datasets, Splunk attack_data) is the next step.
