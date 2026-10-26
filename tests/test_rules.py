"""Unit tests: every rule must fire on its positive cases and stay silent on negative ones."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from dac import load_fixture, load_rules, matches  # noqa: E402


def _cases(kind: str):
    for rule in load_rules():
        if not rule.fixture_path.exists():
            continue
        for case in load_fixture(rule).get(kind, []) or []:
            yield pytest.param(rule, case["event"], id=f"{rule.stem}::{case['name']}")


@pytest.mark.parametrize("rule,event", list(_cases("positive")))
def test_fires_on_positive(rule, event):
    assert matches(rule, event), "rule did not fire on a malicious event"


@pytest.mark.parametrize("rule,event", list(_cases("negative")))
def test_silent_on_negative(rule, event):
    assert not matches(rule, event), "rule fired on a benign event (false positive)"
