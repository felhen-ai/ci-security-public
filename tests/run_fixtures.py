#!/usr/bin/env python3
"""Contract test for the canonical Gitleaks policy."""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFIG = ROOT / "gitleaks.toml"
MANIFEST = ROOT / "tests" / "cases" / "manifest.json"
GITLEAKS = os.environ.get("GITLEAKS_BIN", "gitleaks")
OWN_RULE_IDS = (
    "url-embedded-credentials",
    "http-bearer-authorization",
    "http-basic-authorization",
    "telegram-bot-token-bare",
    "gcp-api-key-bare",
    "stripe-webhook-signing-secret",
    "generic-api-key",
)
FORBIDDEN_ROOT_SEGMENT = re.compile(r"^(?:tests?|__tests__|spec|fixtures?|testdata|e2e)$", re.I)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def checked_tempdir() -> pathlib.Path:
    root = pathlib.Path(tempfile.mkdtemp(prefix="felhen-scan-"))
    if any(FORBIDDEN_ROOT_SEGMENT.search(segment) for segment in root.parts):
        shutil.rmtree(root, ignore_errors=True)
        fail(f"temporary root has an allowlisted path segment: {root}")
    return root


def run_scan(config: pathlib.Path, root: pathlib.Path) -> list[str]:
    report = root.parent / f"{root.name}.report.json"
    completed = subprocess.run(
        [GITLEAKS, "dir", "-c", str(config), "--ignore-gitleaks-allow", "--redact=100", "--report-format", "json", "--report-path", str(report), str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
    )
    if completed.returncode not in (0, 1):
        fail(f"gitleaks execution error for {root.name}: exit {completed.returncode}")
    if not report.exists():
        return []
    try:
        findings = json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid gitleaks JSON report: {exc}")
    return sorted(finding["RuleID"] for finding in findings)


def materialize(case: dict) -> pathlib.Path:
    source = ROOT / case["source"]
    if not source.is_file():
        fail(f"missing source for {case['id']}: {case['source']}")
    logical_path = pathlib.PurePosixPath(case["logical_path"])
    if logical_path.is_absolute() or ".." in logical_path.parts:
        fail(f"unsafe logical_path for {case['id']}: {case['logical_path']}")
    root = checked_tempdir()
    target = root.joinpath(*logical_path.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return root


def config_without_rule(rule_id: str) -> pathlib.Path:
    text = CONFIG.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"(?ms)^\[\[rules\]\]\nid = \"{re.escape(rule_id)}\"\n.*?(?=^\[\[rules\]\]|\Z)"
    )
    updated, count = pattern.subn("", text, count=1)
    if count != 1:
        fail(f"could not remove own rule {rule_id} from copied config")
    handle = tempfile.NamedTemporaryFile(mode="w", prefix="felhen-gitleaks-config-", suffix=".toml", delete=False, encoding="utf-8")
    with handle:
        handle.write(updated)
    return pathlib.Path(handle.name)


def main() -> None:
    if not CONFIG.is_file() or not MANIFEST.is_file():
        fail("missing config or fixture manifest")
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cases = manifest["cases"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        fail(f"invalid fixture manifest: {exc}")
    if not isinstance(cases, list) or not cases:
        fail("fixture manifest has no cases")

    proof_cases: dict[str, list[dict]] = {rule: [] for rule in OWN_RULE_IDS}
    for case in cases:
        required = {"id", "source", "logical_path", "expected_rule_ids"}
        if not isinstance(case, dict) or set(case) != required:
            fail("each case must have exactly id, source, logical_path and expected_rule_ids")
        expected = sorted(case["expected_rule_ids"])
        root = materialize(case)
        try:
            observed = run_scan(CONFIG, root)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        if observed != expected:
            fail(f"{case['id']}: expected RuleIDs {expected}, observed {observed}")
        for rule_id in set(expected).intersection(OWN_RULE_IDS):
            proof_cases[rule_id].append(case)
        # generic-api-key customizes the inherited rule with path allowlists.
        # Its removal must therefore make one of its currently clean test paths fail.
        if case["id"].startswith("generic-") and not expected:
            proof_cases["generic-api-key"].append(case)

    for rule_id, cases_for_rule in proof_cases.items():
        if not cases_for_rule:
            fail(f"no positive fixture for own rule {rule_id}")
        stripped_config = config_without_rule(rule_id)
        try:
            behavior_changed = False
            for case in cases_for_rule:
                root = materialize(case)
                try:
                    observed = run_scan(stripped_config, root)
                finally:
                    shutil.rmtree(root, ignore_errors=True)
                if observed != sorted(case["expected_rule_ids"]):
                    behavior_changed = True
                    break
            if not behavior_changed:
                fail(f"removing {rule_id} did not change any fixture result")
        finally:
            stripped_config.unlink(missing_ok=True)
    print("PASS: all fixture RuleIDs and own-rule removal proofs match the contract")


if __name__ == "__main__":
    main()
