from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .pipeline import IncidentResult, OverlordPipeline

DEFAULT_SCENARIO_DIR = Path(__file__).resolve().parents[2] / "scenarios"
DEFAULT_FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class PipelineOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requested_tier: int = 1
    asset_class: str = "endpoint_workstation"
    target_asset: str = "host-42"
    approve: bool | None = None
    authorization: str | None = None
    auto_sensors: bool = False
    model_context_window: int = 8192
    max_concurrent_requests: int = 3
    clock_step_seconds: float = 0.0


class Expectations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    blocked_at: str | None = None
    error: str | None = None
    tier: int | None = None
    decision_status: str | None = None
    outcome: str | None = None
    n_conclusions: int = 0
    stages: list[str] | None = None


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    techniques: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    now: datetime | None = None
    pipeline: PipelineOptions = Field(default_factory=PipelineOptions)
    telemetry: list[dict[str, Any]] = Field(min_length=1)
    expect: Expectations = Field(default_factory=Expectations)

    @model_validator(mode="after")
    def _unique_labels(self) -> "Scenario":
        for name, values in (
            ("techniques", self.techniques),
            ("hypotheses", self.hypotheses),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must be distinct")
        return self


@dataclass(frozen=True)
class Observed:
    techniques: frozenset[str]
    hypotheses: frozenset[str]
    blocked_at: str | None
    error: str | None
    tier: int | None
    decision_status: str | None
    outcome: str | None
    n_conclusions: int
    n_facts: int
    stages: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": sorted(self.techniques),
            "hypotheses": sorted(self.hypotheses),
            "blocked_at": self.blocked_at,
            "error": self.error,
            "tier": self.tier,
            "decision_status": self.decision_status,
            "outcome": self.outcome,
            "n_conclusions": self.n_conclusions,
            "n_facts": self.n_facts,
            "stages": list(self.stages),
        }


@dataclass(frozen=True)
class SetCounts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        denominator = self.tp + self.fn
        return self.tp / denominator if denominator else None

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


@dataclass(frozen=True)
class ScenarioResult:
    scenario: Scenario
    observed: Observed
    issues: tuple[str, ...]
    technique_counts: SetCounts
    hypothesis_counts: SetCounts
    latency_ms: float

    @property
    def passed(self) -> bool:
        return not self.issues

    @property
    def detection_passed(self) -> bool:
        return not any(
            (
                self.technique_counts.fp,
                self.technique_counts.fn,
                self.hypothesis_counts.fp,
                self.hypothesis_counts.fn,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario.id,
            "name": self.scenario.name,
            "passed": self.passed,
            "detection_passed": self.detection_passed,
            "issues": list(self.issues),
            "expected": {
                "techniques": sorted(self.scenario.techniques),
                "hypotheses": sorted(self.scenario.hypotheses),
                **self.scenario.expect.model_dump(mode="json"),
            },
            "observed": self.observed.to_dict(),
            "technique_counts": self.technique_counts.to_dict(),
            "hypothesis_counts": self.hypothesis_counts.to_dict(),
            "latency_ms": round(self.latency_ms, 3),
        }


@dataclass
class EvaluationReport:
    results: list[ScenarioResult] = field(default_factory=list)

    @property
    def scenario_count(self) -> int:
        return len(self.results)

    @property
    def passed_count(self) -> int:
        return sum(1 for result in self.results if result.passed)

    @property
    def pass_rate(self) -> float:
        return self.passed_count / self.scenario_count if self.scenario_count else 0.0

    @property
    def technique_counts(self) -> SetCounts:
        return _sum_counts(result.technique_counts for result in self.results)

    @property
    def hypothesis_counts(self) -> SetCounts:
        return _sum_counts(result.hypothesis_counts for result in self.results)

    @property
    def gate_accuracy(self) -> float:
        if not self.results:
            return 0.0
        matches = sum(
            1
            for result in self.results
            if result.observed.blocked_at == result.scenario.expect.blocked_at
            and result.observed.error == result.scenario.expect.error
        )
        return matches / len(self.results)

    @property
    def tier_accuracy(self) -> float:
        if not self.results:
            return 0.0
        matches = sum(
            1
            for result in self.results
            if result.observed.tier == result.scenario.expect.tier
        )
        return matches / len(self.results)

    @property
    def decision_accuracy(self) -> float:
        if not self.results:
            return 0.0
        matches = sum(
            1
            for result in self.results
            if result.observed.decision_status
            == result.scenario.expect.decision_status
        )
        return matches / len(self.results)

    @property
    def detection_pass_rate(self) -> float:
        if not self.results:
            return 0.0
        matches = sum(1 for result in self.results if result.detection_passed)
        return matches / len(self.results)

    def per_technique(self) -> dict[str, dict[str, Any]]:
        return _per_label(self.results, "techniques")

    def per_hypothesis(self) -> dict[str, dict[str, Any]]:
        return _per_label(self.results, "hypotheses")

    def failures(self) -> list[ScenarioResult]:
        return [result for result in self.results if not result.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_count": self.scenario_count,
            "passed": self.passed_count,
            "failed": self.scenario_count - self.passed_count,
            "pass_rate": self.pass_rate,
            "detection_pass_rate": self.detection_pass_rate,
            "gate_accuracy": self.gate_accuracy,
            "tier_accuracy": self.tier_accuracy,
            "decision_accuracy": self.decision_accuracy,
            "technique": self.technique_counts.to_dict(),
            "hypothesis": self.hypothesis_counts.to_dict(),
            "per_technique": self.per_technique(),
            "per_hypothesis": self.per_hypothesis(),
            "scenarios": [result.to_dict() for result in self.results],
        }


def _sum_counts(counts: Iterable[SetCounts]) -> SetCounts:
    total = SetCounts()
    for item in counts:
        total = SetCounts(
            tp=total.tp + item.tp,
            fp=total.fp + item.fp,
            fn=total.fn + item.fn,
        )
    return total


def _per_label(results: Sequence[ScenarioResult], attribute: str) -> dict[str, dict[str, Any]]:
    stats: dict[str, dict[str, Any]] = {}
    for result in results:
        expected = set(getattr(result.scenario, attribute))
        observed = set(getattr(result.observed, attribute))
        for label in expected:
            stats.setdefault(label, {"expected": 0, "detected": 0, "unexpected": 0})
            stats[label]["expected"] += 1
        for label in expected & observed:
            stats.setdefault(label, {"expected": 0, "detected": 0, "unexpected": 0})
            stats[label]["detected"] += 1
        for label in observed - expected:
            stats.setdefault(label, {"expected": 0, "detected": 0, "unexpected": 0})
            stats[label]["unexpected"] += 1
    for label, item in stats.items():
        denominator = item["detected"] + item["unexpected"]
        item["precision"] = item["detected"] / denominator if denominator else None
        item["recall"] = (
            item["detected"] / item["expected"] if item["expected"] else None
        )
    return dict(sorted(stats.items()))


def load_scenarios(path: str | Path = DEFAULT_SCENARIO_DIR) -> list[Scenario]:
    location = Path(path)
    files = sorted(location.glob("*.json")) if location.is_dir() else [location]
    if not files:
        raise FileNotFoundError(f"no evaluation scenarios found at {location}")

    scenarios: list[Scenario] = []
    seen: set[str] = set()
    for file in files:
        scenario = Scenario.model_validate_json(file.read_text(encoding="utf-8"))
        if scenario.id in seen:
            raise ValueError(f"duplicate scenario id: {scenario.id}")
        if location.is_dir() and file.stem != scenario.id:
            raise ValueError(
                f"scenario file {file.name} must be named {scenario.id}.json"
            )
        seen.add(scenario.id)
        scenarios.append(scenario)
    return scenarios


def extract_observed(result: IncidentResult) -> Observed:
    support_ids: set[str] = set()
    hypotheses: set[str] = set()
    for conclusion in result.conclusions.values():
        hypotheses.add(conclusion.hypothesis.value)
        support_ids.update(str(fact_id) for fact_id in conclusion.supporting_facts)

    techniques: set[str] = set()
    for fact_id in support_ids:
        enrichment = result.enrichment.get(fact_id) or {}
        techniques.update(
            str(technique)
            for technique in enrichment.get("attck_techniques") or []
        )

    stages = tuple(
        sorted(
            {
                str(event.get("metadata", {}).get("stage"))
                for event in result.events
                if event.get("metadata", {}).get("stage")
            }
        )
    )
    return Observed(
        techniques=frozenset(techniques),
        hypotheses=frozenset(hypotheses),
        blocked_at=result.blocked_at,
        error=result.error,
        tier=result.tier.resolved_tier if result.tier else None,
        decision_status=result.decision.status.value if result.decision else None,
        outcome=result.outcome.value if result.outcome else None,
        n_conclusions=len(result.conclusions),
        n_facts=len(result.facts),
        stages=stages,
    )


def compare(scenario: Scenario, observed: Observed) -> tuple[str, ...]:
    issues: list[str] = []
    expected_techniques = set(scenario.techniques)
    expected_hypotheses = set(scenario.hypotheses)
    _compare_set("technique", expected_techniques, observed.techniques, issues)
    _compare_set("hypothesis", expected_hypotheses, observed.hypotheses, issues)

    checks = (
        ("blocked_at", scenario.expect.blocked_at, observed.blocked_at),
        ("error", scenario.expect.error, observed.error),
        ("tier", scenario.expect.tier, observed.tier),
        ("decision_status", scenario.expect.decision_status, observed.decision_status),
        ("outcome", scenario.expect.outcome, observed.outcome),
        ("n_conclusions", scenario.expect.n_conclusions, observed.n_conclusions),
    )
    for name, expected, actual in checks:
        if expected != actual:
            issues.append(f"{name}: expected {expected!r}, observed {actual!r}")

    if scenario.expect.stages is not None:
        expected_stages = tuple(scenario.expect.stages)
        if expected_stages != observed.stages:
            issues.append(
                f"stages: expected {list(expected_stages)!r}, "
                f"observed {list(observed.stages)!r}"
            )
    return tuple(issues)


def _compare_set(
    name: str,
    expected: set[str],
    observed: frozenset[str],
    issues: list[str],
) -> None:
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    if missing:
        issues.append(f"{name} recall: missing {', '.join(missing)}")
    if unexpected:
        issues.append(f"{name} precision: unexpected {', '.join(unexpected)}")


def _clock_for(scenario: Scenario):
    base = scenario.now or DEFAULT_FIXED_NOW
    step = scenario.pipeline.clock_step_seconds
    if step == 0:
        return lambda: base

    state = {"now": base}

    def clock() -> datetime:
        value = state["now"]
        state["now"] = value + timedelta(seconds=step)
        return value

    return clock


def run_scenario(scenario: Scenario) -> ScenarioResult:
    pipeline = OverlordPipeline(
        authorizer=lambda token: "eval-authorizer" if token else None,
        # Scenarios replay one sensor to test the later gates; the two-source
        # requirement itself is covered in tests/test_hardening.py.
        min_independent_sources=1,
        auto_sensors=scenario.pipeline.auto_sensors,
        clock=_clock_for(scenario),
        model_context_window=scenario.pipeline.model_context_window,
        max_concurrent_requests=scenario.pipeline.max_concurrent_requests,
    )
    started = time.perf_counter()
    incident = pipeline.run_incident(
        scenario.telemetry,
        requested_tier=scenario.pipeline.requested_tier,
        asset_class=scenario.pipeline.asset_class,
        target_asset=scenario.pipeline.target_asset,
        approve=scenario.pipeline.approve,
        authorization=scenario.pipeline.authorization,
        incident_id=f"eval-{scenario.id}",
    )
    latency_ms = (time.perf_counter() - started) * 1000
    observed = extract_observed(incident)
    expected_techniques = set(scenario.techniques)
    expected_hypotheses = set(scenario.hypotheses)
    return ScenarioResult(
        scenario=scenario,
        observed=observed,
        issues=compare(scenario, observed),
        technique_counts=SetCounts(
            tp=len(expected_techniques & observed.techniques),
            fp=len(observed.techniques - expected_techniques),
            fn=len(expected_techniques - observed.techniques),
        ),
        hypothesis_counts=SetCounts(
            tp=len(expected_hypotheses & observed.hypotheses),
            fp=len(observed.hypotheses - expected_hypotheses),
            fn=len(expected_hypotheses - observed.hypotheses),
        ),
        latency_ms=latency_ms,
    )


def evaluate(scenarios: Sequence[Scenario]) -> EvaluationReport:
    return EvaluationReport(results=[run_scenario(scenario) for scenario in scenarios])


def _format_metric(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def render_markdown(report: EvaluationReport) -> str:
    technique = report.technique_counts
    hypothesis = report.hypothesis_counts
    lines = [
        "# Overlord evaluation report",
        "",
        f"Scenarios: **{report.passed_count}/{report.scenario_count} passed** "
        f"({report.pass_rate:.1%})",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Detection pass rate | {_format_metric(report.detection_pass_rate)} |",
        f"| Technique precision | {_format_metric(technique.precision)} |",
        f"| Technique recall | {_format_metric(technique.recall)} |",
        f"| Technique F1 | {_format_metric(technique.f1)} |",
        f"| Hypothesis precision | {_format_metric(hypothesis.precision)} |",
        f"| Hypothesis recall | {_format_metric(hypothesis.recall)} |",
        f"| Hypothesis F1 | {_format_metric(hypothesis.f1)} |",
        f"| Gate accuracy | {_format_metric(report.gate_accuracy)} |",
        f"| Tier accuracy | {_format_metric(report.tier_accuracy)} |",
        f"| Decision accuracy | {_format_metric(report.decision_accuracy)} |",
        "",
        "## Scenarios",
        "",
        "| Scenario | Result | Techniques (expected -> observed) | "
        "Tier | Blocked | Latency (ms) |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for result in report.results:
        expected = ", ".join(sorted(result.scenario.techniques)) or "-"
        observed = ", ".join(sorted(result.observed.techniques)) or "-"
        tier = "-" if result.observed.tier is None else str(result.observed.tier)
        blocked = result.observed.blocked_at or "-"
        if result.observed.error:
            blocked = f"{blocked} ({result.observed.error})"
        lines.append(
            f"| {result.scenario.id} | {'PASS' if result.passed else 'FAIL'} | "
            f"{expected} -> {observed} | {tier} | {blocked} | "
            f"{result.latency_ms:.1f} |"
        )

    techniques = report.per_technique()
    if techniques:
        lines.extend(
            [
                "",
                "## Technique coverage",
                "",
                "| Technique | Expected | Detected | Unexpected | Recall |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for label, item in techniques.items():
            lines.append(
                f"| {label} | {item['expected']} | {item['detected']} | "
                f"{item['unexpected']} | {_format_metric(item['recall'])} |"
            )

    failures = report.failures()
    if failures:
        lines.extend(["", "## Failures", ""])
        for result in failures:
            lines.append(f"### {result.scenario.id}")
            lines.append("")
            for issue in result.issues:
                lines.append(f"- {issue}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _write_reports(report: EvaluationReport, json_path: Path, markdown_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")


def _threshold_failures(
    report: EvaluationReport,
    min_pass_rate: float,
    min_technique_recall: float | None,
    min_technique_precision: float | None,
) -> list[str]:
    failures: list[str] = []
    if report.pass_rate < min_pass_rate:
        failures.append(
            f"pass_rate {report.pass_rate:.3f} < required {min_pass_rate:.3f}"
        )
    technique = report.technique_counts
    if (
        min_technique_recall is not None
        and technique.recall is not None
        and technique.recall < min_technique_recall
    ):
        failures.append(
            f"technique recall {technique.recall:.3f} < required "
            f"{min_technique_recall:.3f}"
        )
    if (
        min_technique_precision is not None
        and technique.precision is not None
        and technique.precision < min_technique_precision
    ):
        failures.append(
            f"technique precision {technique.precision:.3f} < required "
            f"{min_technique_precision:.3f}"
        )
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="overlord-eval",
        description="Run deterministic Overlord detection and gate scenarios.",
    )
    parser.add_argument(
        "scenarios",
        nargs="?",
        default=str(DEFAULT_SCENARIO_DIR),
        help="scenario JSON file or directory (default: repo scenarios/)",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        default="reports/eval.json",
        help="JSON report path (default: reports/eval.json)",
    )
    parser.add_argument(
        "--markdown",
        dest="markdown_path",
        default="reports/eval.md",
        help="Markdown report path (default: reports/eval.md)",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="print the summary without writing report files",
    )
    parser.add_argument(
        "--min-pass-rate",
        type=float,
        default=1.0,
        help="required fraction of scenarios that pass (default: 1.0)",
    )
    parser.add_argument(
        "--min-technique-recall",
        type=float,
        default=None,
        help="optional minimum aggregate technique recall",
    )
    parser.add_argument(
        "--min-technique-precision",
        type=float,
        default=None,
        help="optional minimum aggregate technique precision",
    )
    args = parser.parse_args(argv)

    try:
        scenarios = load_scenarios(args.scenarios)
    except (FileNotFoundError, ValueError) as exc:
        print(f"overlord-eval: {exc}", file=sys.stderr)
        return 2

    report = evaluate(scenarios)
    technique = report.technique_counts
    hypothesis = report.hypothesis_counts

    print(
        f"Overlord evaluation: {report.passed_count}/{report.scenario_count} "
        f"scenarios passed ({report.pass_rate:.1%})"
    )
    print(
        "technique "
        f"precision={_format_metric(technique.precision)} "
        f"recall={_format_metric(technique.recall)} "
        f"f1={_format_metric(technique.f1)}"
    )
    print(
        "hypothesis "
        f"precision={_format_metric(hypothesis.precision)} "
        f"recall={_format_metric(hypothesis.recall)} "
        f"f1={_format_metric(hypothesis.f1)}"
    )
    print(
        f"gates={_format_metric(report.gate_accuracy)} "
        f"tiers={_format_metric(report.tier_accuracy)} "
        f"decisions={_format_metric(report.decision_accuracy)}"
    )

    for result in report.failures():
        print(f"FAIL {result.scenario.id}: {'; '.join(result.issues)}", file=sys.stderr)

    if not args.no_write:
        json_path = Path(args.json_path)
        markdown_path = Path(args.markdown_path)
        _write_reports(report, json_path, markdown_path)
        print(f"wrote {json_path} and {markdown_path}")

    failures = _threshold_failures(
        report,
        args.min_pass_rate,
        args.min_technique_recall,
        args.min_technique_precision,
    )
    for failure in failures:
        print(f"overlord-eval: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
