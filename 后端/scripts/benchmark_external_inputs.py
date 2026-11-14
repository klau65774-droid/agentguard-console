"""Measure the input guardrails against local deepset, BIPIA, and JBB files."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from agentguard.common.models import InputDecision
from agentguard.input_guardrails.engine import evaluate_input


@dataclass
class Counts:
    tp: int = 0
    fn: int = 0
    tn: int = 0
    fp: int = 0
    benign_non_allow: int = 0
    attack_non_allow: int = 0
    benign_blocking_checks: Counter[str] = field(default_factory=Counter)
    decisions: Counter[str] = field(default_factory=Counter)

    def summary(self) -> dict[str, object]:
        return {
            "tp": self.tp,
            "fn": self.fn,
            "tn": self.tn,
            "fp": self.fp,
            "benign_non_allow": self.benign_non_allow,
            "attack_non_allow": self.attack_non_allow,
            "benign_blocking_checks": dict(self.benign_blocking_checks),
            "decisions": dict(self.decisions),
            "attack_recall_pct": _percent(self.tp, self.tp + self.fn),
            "benign_fpr_pct": _percent(self.fp, self.tn + self.fp),
            "benign_non_allow_pct": _percent(self.benign_non_allow, self.tn + self.fp),
        }


def _percent(count: int, total: int) -> float | None:
    return round(100 * count / total, 3) if total else None


def _samples(directory: Path) -> Iterator[tuple[tuple[str, ...], bool, str]]:
    for split, expected in (("test", 116), ("train", 546)):
        count = 0
        for start in range(0, expected, 100):
            path = directory / f"deepset_{split}_rows_{start}.json"
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
            for entry in payload["rows"]:
                row = entry["row"]
                if row["label"] not in (0, 1):
                    raise ValueError(f"Invalid deepset label in {path.name}")
                count += 1
                yield (f"deepset_{split}",), bool(row["label"]), row["text"]
        if count != expected:
            raise ValueError(f"Expected {expected} deepset {split} rows, got {count}")

    for kind, expected in (("text", 75), ("code", 50)):
        path = directory / f"bipia_{kind}_attack_test.json"
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        texts = [text for variants in payload.values() for text in variants]
        if len(texts) != expected:
            raise ValueError(f"Expected {expected} BIPIA {kind} rows, got {len(texts)}")
        for text in texts:
            yield ("bipia", f"bipia_{kind}"), True, text

    path = directory / "bipia_email_test.jsonl"
    emails = [line for line in path.read_text(encoding="utf-8-sig").split("\n") if line.strip()]
    if len(emails) != 50:
        raise ValueError(f"Expected 50 BIPIA email rows, got {len(emails)}")
    for line in emails:
        yield ("bipia", "bipia_email"), False, json.loads(line)["context"]

    for kind in ("harmful", "benign"):
        path = directory / f"jbb_{kind}.csv"
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        if len(rows) != 100:
            raise ValueError(f"Expected 100 JBB {kind} rows, got {len(rows)}")
        for row in rows:
            yield ("jbb",), kind == "harmful", row["Goal"]


async def evaluate(directory: Path) -> dict[str, dict[str, object]]:
    totals: dict[str, Counts] = {"all": Counts()}
    for groups, is_attack, text in _samples(directory):
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"Expected a nonempty input in {groups[-1]}")
        decision, checks, _ = await evaluate_input(text)
        blocked = decision == InputDecision.BLOCK
        restricted = decision != InputDecision.ALLOW
        for group in ("all", *groups):
            if group not in totals:
                totals[group] = Counts()
            counts = totals[group]
            counts.decisions[decision.value] += 1
            if is_attack:
                counts.tp += int(blocked)
                counts.fn += int(not blocked)
                counts.attack_non_allow += int(restricted)
            else:
                counts.fp += int(blocked)
                counts.tn += int(not blocked)
                counts.benign_non_allow += int(restricted)
                counts.benign_blocking_checks.update(
                    check.check_name for check in checks if check.decision == "block"
                )
    return {group: counts.summary() for group, counts in totals.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_dir", type=Path, help="Directory containing local dataset files")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(evaluate(args.dataset_dir)), indent=2))


if __name__ == "__main__":
    main()
