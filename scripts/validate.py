"""Lint the rule set: metadata, ATT&CK tags, unique IDs, fixtures present, rules convertible."""
import sys

from dac import ATTACK_TECHNIQUE, REQUIRED_FIELDS, TARGETS, convert, load_fixture, load_rules


def main() -> int:
    errors: list[str] = []
    seen_ids: dict[str, str] = {}
    rules = load_rules()

    for rule in rules:
        name = rule.path.relative_to(rule.path.parents[3])
        for field in REQUIRED_FIELDS:
            if field not in rule.raw:
                errors.append(f"{name}: missing '{field}'")
        if not any(ATTACK_TECHNIQUE.match(t) for t in rule.raw.get("tags", [])):
            errors.append(f"{name}: needs at least one attack.tXXXX technique tag")
        rid = str(rule.raw.get("id"))
        if rid in seen_ids:
            errors.append(f"{name}: duplicate id with {seen_ids[rid]}")
        seen_ids[rid] = str(name)

        if not rule.fixture_path.exists():
            errors.append(f"{name}: no fixture at tests/fixtures/{rule.stem}.yml")
        else:
            fx = load_fixture(rule)
            if not fx.get("positive") or not fx.get("negative"):
                errors.append(f"{name}: fixture needs >=1 positive and >=1 negative case")

        for target in TARGETS:
            try:
                convert(rule, target)
            except Exception as exc:  # pySigma raises many exception types
                errors.append(f"{name}: does not convert to {target}: {exc}")

    for e in errors:
        print(f"ERROR {e}")
    print(f"{len(rules)} rules checked, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
