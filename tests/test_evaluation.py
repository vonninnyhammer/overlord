from __future__ import annotations

import json

import pytest

from overlord.evaluation import (
    evaluate,
    load_scenarios,
    main,
    render_markdown,
    run_scenario,
)

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def test_golden_scenarios_all_pass():
    report = evaluate(load_scenarios())

    assert report.scenario_count >= 20
    assert report.passed_count == report.scenario_count
    assert report.pass_rate == 1.0
    assert report.technique_counts.fp == 0
    assert report.technique_counts.fn == 0
    assert report.hypothesis_counts.fp == 0
    assert report.hypothesis_counts.fn == 0
    assert report.gate_accuracy == 1.0
    assert report.tier_accuracy == 1.0
    assert report.decision_accuracy == 1.0


def test_missing_detection_is_a_false_negative():
    scenario = next(
        item for item in load_scenarios() if item.id == "credential-access-auth"
    )
    broken = scenario.model_copy(update={"techniques": ["T9999"]})

    result = run_scenario(broken)

    assert not result.passed
    assert result.technique_counts.fn == 1
    assert any("technique recall: missing T9999" in issue for issue in result.issues)


def test_unexpected_detection_is_a_false_positive():
    scenario = next(
        item for item in load_scenarios() if item.id == "credential-access-auth"
    )
    broken = scenario.model_copy(update={"techniques": [], "hypotheses": []})

    result = run_scenario(broken)

    assert not result.passed
    assert result.technique_counts.fp == 1
    assert result.hypothesis_counts.fp == 1
    assert any("technique precision: unexpected T1078" in issue for issue in result.issues)
    assert any(
        "hypothesis precision: unexpected credential_access" in issue
        for issue in result.issues
    )


def test_gate_mismatch_is_reported():
    scenario = next(
        item for item in load_scenarios() if item.id == "under-supported-single-fact"
    )
    broken = scenario.model_copy(
        update={"expect": scenario.expect.model_copy(update={"blocked_at": None})}
    )

    result = run_scenario(broken)

    assert not result.passed
    assert any("blocked_at: expected None" in issue for issue in result.issues)


def test_cli_writes_reports_and_fails_on_mismatch(tmp_path):
    scenario = next(
        item for item in load_scenarios() if item.id == "credential-access-auth"
    )
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(scenario.model_dump_json(), encoding="utf-8")
    json_path = tmp_path / "reports" / "eval.json"
    markdown_path = tmp_path / "reports" / "eval.md"

    code = main(
        [
            str(scenario_path),
            "--json",
            str(json_path),
            "--markdown",
            str(markdown_path),
        ]
    )

    assert code == 0
    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["passed"] == 1
    assert "Overlord evaluation report" in markdown_path.read_text(encoding="utf-8")

    scenario_path.write_text(
        scenario.model_copy(update={"techniques": ["T9999"]}).model_dump_json(),
        encoding="utf-8",
    )
    code = main(
        [
            str(scenario_path),
            "--json",
            str(json_path),
            "--markdown",
            str(markdown_path),
        ]
    )

    assert code == 1


def test_markdown_and_json_are_renderable():
    report = evaluate(load_scenarios())

    markdown = render_markdown(report)
    assert "## Technique coverage" in markdown
    assert "| credential-access-auth | PASS |" in markdown

    document = report.to_dict()
    assert document["scenario_count"] == report.scenario_count
    assert document["technique"]["recall"] == 1.0
    assert document["per_technique"]["T1078"]["expected"] >= 1
    json.dumps(document)


def test_load_scenarios_rejects_filename_mismatch(tmp_path):
    scenario = load_scenarios()[0]
    (tmp_path / "wrong-name.json").write_text(
        scenario.model_dump_json(), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="must be named"):
        load_scenarios(tmp_path)
