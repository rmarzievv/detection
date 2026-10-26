"""Convert every Sigma rule into Splunk SPL, Elastic Lucene and Elastic ES|QL under build/."""
import sys

from dac import ROOT, TARGETS, convert, load_rules


def main() -> int:
    out = ROOT / "build"
    count = 0
    for rule in load_rules():
        for target, (_, ext) in TARGETS.items():
            path = out / target / f"{rule.stem}.{ext}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(convert(rule, target) + "\n", encoding="utf-8")
            count += 1
    print(f"wrote {count} queries to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
