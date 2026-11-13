"""Test every Sigma rule against its sample events.

For each rule in rules/, the matching tests/<rule-id>.yml file holds:
  match:   events the rule MUST alert on   (true positives; every one must hit)
  nomatch: events the rule must NOT alert on (benign look-alikes)

Each rule is converted to SQL with pySigma's SQLite backend and run against an
in-memory table built from those events. Correlation rules (e.g. brute force)
are tested the same way, using the events' `timestamp` field.

Usage:  python scripts/run_tests.py          (exit code 1 if anything fails)
"""
import re
import sqlite3
import sys
from pathlib import Path

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
TESTS = ROOT / "tests"
ATTACK_TAG = re.compile(r"^t\d{4}(\.\d{3})?$")


def load_rules():
    files = sorted(RULES.rglob("*.yml"))
    collection = SigmaCollection.merge([SigmaCollection.from_yaml(f.read_text()) for f in files])
    collection.resolve_rule_references()
    return collection


def make_table(events):
    con = sqlite3.connect(":memory:")
    cols = sorted({k for e in events for k in e})
    if not cols:
        cols = ["_empty"]
    con.execute("CREATE TABLE logs (" + ", ".join(f'"{c}"' for c in cols) + ")")
    for e in events:
        con.execute(
            "INSERT INTO logs (" + ", ".join(f'"{c}"' for c in cols) + ") VALUES ("
            + ", ".join("?" for _ in cols) + ")",
            [e.get(c) for c in cols],
        )
    return con


def hits(query, events):
    if not events:
        return 0
    con = make_table(events)
    try:
        return len(con.execute(query).fetchall())
    except sqlite3.OperationalError as exc:
        # a field the rule uses doesn't exist in these events -> the rule can't match them
        if "no such column" in str(exc):
            return 0
        raise


def to_query(backend, rule):
    if isinstance(rule, SigmaCorrelationRule):
        return backend.convert_correlation_rule(rule)[0]
    # base rules used only by a correlation are hidden from output by default;
    # convert them anyway so they can be tested on their own
    rule._output = True
    return backend.convert_rule(rule)[0]


def lint(rule, problems):
    tags = [t for t in rule.tags if t.namespace == "attack"]
    if not any(ATTACK_TAG.match(t.name) for t in tags):
        problems.append("no MITRE ATT&CK technique tag")
    if rule.level is None:
        problems.append("no level")
    if not rule.description:
        problems.append("no description")
    if not getattr(rule, "falsepositives", None):
        problems.append("no falsepositives listed")


def main():
    collection = load_rules()
    backend = sqliteBackend()
    seen_ids, failures, rows = set(), 0, []

    for rule in collection:
        rid = str(rule.id)
        problems = []
        if rid in seen_ids:
            problems.append("duplicate id")
        seen_ids.add(rid)
        lint(rule, problems)

        test_file = TESTS / f"{rid}.yml"
        if not test_file.exists():
            problems.append(f"missing test file tests/{rid}.yml")
            tp = fp = "-"
        else:
            spec = yaml.safe_load(test_file.read_text())
            match, nomatch = spec.get("match") or [], spec.get("nomatch") or []
            if not match or not nomatch:
                problems.append("tests need both match and nomatch events")
            query = to_query(backend, rule)
            tp, fp = hits(query, match), hits(query, nomatch)
            if isinstance(rule, SigmaCorrelationRule):
                if tp == 0:
                    problems.append("did not alert on its true-positive events")
            elif tp < len(match):
                problems.append(f"missed {len(match) - tp} of {len(match)} true-positive events")
            if fp > 0:
                problems.append(f"alerted {fp}x on benign events")

        kind = "correlation" if isinstance(rule, SigmaCorrelationRule) else "detection"
        rows.append((rule.title, kind, str(tp), str(fp), "PASS" if not problems else "FAIL"))
        if problems:
            failures += 1
            for p in problems:
                rows.append(("   -> " + p, "", "", "", ""))

    width = max(len(r[0]) for r in rows)
    print(f"{'Rule':<{width}}  {'Type':<11}  {'TP hits':>7}  {'FP hits':>7}  Result")
    print("-" * (width + 40))
    for title, kind, tp, fp, result in rows:
        print(f"{title:<{width}}  {kind:<11}  {tp:>7}  {fp:>7}  {result}")
    total = len(seen_ids)
    print(f"\n{total - failures}/{total} rules passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
