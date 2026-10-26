"""Build an ATT&CK Navigator layer and COVERAGE.md from rule tags.

A technique counts as 'tested' only if its rule has passing fixtures; this script
assumes CI already ran pytest, so every rule in the repo is tested by construction.
"""
import json
import sys
from collections import defaultdict

from dac import ROOT, load_rules


def main() -> int:
    by_technique: dict[str, list[str]] = defaultdict(list)
    rules = load_rules()
    for rule in rules:
        for tech in rule.techniques:
            by_technique[tech].append(rule.raw["title"])

    layer = {
        "name": "detection-as-code coverage",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": "Techniques with at least one tested detection rule",
        "gradient": {"colors": ["#c6e2ff", "#1f5fa8"], "minValue": 1, "maxValue": 3},
        "techniques": [
            {"techniqueID": t, "score": len(r), "comment": "; ".join(r)}
            for t, r in sorted(by_technique.items())
        ],
    }
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    (build / "navigator_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

    lines = ["# Coverage", "", f"{len(rules)} rules, {len(by_technique)} ATT&CK techniques.", "",
             "| Technique | Rules |", "| --- | --- |"]
    for tech, titles in sorted(by_technique.items()):
        url = f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
        lines.append(f"| [{tech}]({url}) | {'<br>'.join(titles)} |")
    (ROOT / "COVERAGE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(by_technique)} techniques -> build/navigator_layer.json, COVERAGE.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
