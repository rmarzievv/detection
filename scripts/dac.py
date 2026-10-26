"""Shared helpers: load rules, evaluate them against events, convert them to SIEM queries."""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.splunk import splunk_windows_pipeline

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "tests" / "fixtures"

REQUIRED_FIELDS = ["title", "id", "status", "description", "author", "date",
                   "tags", "logsource", "detection", "falsepositives", "level"]
ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")

# Target SIEMs: name -> (backend factory, file extension)
TARGETS = {
    "splunk": (lambda: SplunkBackend(splunk_windows_pipeline()), "spl"),
    "elastic_lucene": (lambda: LuceneBackend(ecs_windows()), "lucene"),
    "elastic_esql": (lambda: ESQLBackend(ecs_windows()), "esql"),
}


@dataclass
class Rule:
    path: Path
    raw: dict
    text: str

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.raw.get("tags", [])
                if ATTACK_TECHNIQUE.match(t)]

    @property
    def fixture_path(self) -> Path:
        return FIXTURES_DIR / f"{self.stem}.yml"

    def collection(self) -> SigmaCollection:
        return SigmaCollection.from_yaml(self.text)


def load_rules() -> list[Rule]:
    rules = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        text = path.read_text(encoding="utf-8")
        rules.append(Rule(path=path, raw=yaml.safe_load(text), text=text))
    return rules


def load_fixture(rule: Rule) -> dict:
    return yaml.safe_load(rule.fixture_path.read_text(encoding="utf-8")) or {}


def matches(rule: Rule, event: dict) -> bool:
    """Evaluate the Sigma rule against one event using the SQLite backend.

    Sigma -> SQL WHERE clause, event -> one-row table. Every field the rule
    references must exist in the event (missing = NULL), so the table gets a
    column for each field name found in the rule's detection section too.
    """
    query = sqliteBackend().convert(rule.collection())[0]
    columns = set(event) | _detection_fields(rule.raw["detection"])
    db = sqlite3.connect(":memory:")
    cols_sql = ", ".join(f'"{c}" TEXT' for c in sorted(columns))
    db.execute(f"CREATE TABLE logs ({cols_sql})")
    db.execute(
        f"INSERT INTO logs ({', '.join(f'{chr(34)}{c}{chr(34)}' for c in event)}) "
        f"VALUES ({', '.join('?' for _ in event)})",
        [str(v) for v in event.values()],
    )
    return db.execute(query).fetchone() is not None


def _detection_fields(detection: dict) -> set[str]:
    fields = set()
    for key, value in detection.items():
        if key == "condition":
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                fields |= {k.split("|", 1)[0] for k in item}
    return fields


def convert(rule: Rule, target: str) -> str:
    factory, _ = TARGETS[target]
    return "\n".join(factory().convert(rule.collection()))
