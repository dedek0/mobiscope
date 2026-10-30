#!/usr/bin/env python3
"""Compare the jadx and dex-decompile backends on one artifact.

Usage:
    scripts/evaluate-decompiler.py app.apk [--workdir targets/eval] [--json out.json]

The script runs `mobiscope analyze` twice with the same stages, measures wall
time and peak RSS with /usr/bin/time, then compares the finding sets. It is a
decision aid for ADR-009, not a unit test: the result depends on the artifact
and on the optional gitleaks/semgrep binaries.

Requirements:
    - mobiscope binary in ./bin/mobiscope (or $BINARY)
    - jadx and dex-decompile in PATH
    - /usr/bin/time with -v (GNU time) for RSS
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", help="APK/IPA to analyze")
    parser.add_argument("--workdir", default="targets/eval", help="output base directory")
    parser.add_argument("--json", default="", help="write the metrics report here")
    parser.add_argument(
        "--stages",
        default="inventory,gitleaks,semgrep",
        help="scanner stages to run after the decompiler (default: inventory,gitleaks,semgrep)",
    )
    parser.add_argument("--binary", default=os.environ.get("BINARY", "bin/mobiscope"))
    return parser.parse_args()


def find_session(workdir: Path) -> Path | None:
    for session in sorted(workdir.glob("*/session.json")):
        return session
    return None


def parse_time(path: Path) -> dict:
    metrics = {"elapsed_seconds": None, "peak_rss_mb": None}
    try:
        text = path.read_text()
    except OSError:
        return metrics
    match = re.search(r"Elapsed \(wall clock\) time .*?: ([\d:.]+)", text)
    if match:
        parts = match.group(1).split(":")
        seconds = 0.0
        for part in parts:
            seconds = seconds * 60 + float(part)
        metrics["elapsed_seconds"] = round(seconds, 3)
    match = re.search(r"Maximum resident set size \(kbytes\): (\d+)", text)
    if match:
        metrics["peak_rss_mb"] = round(int(match.group(1)) / 1024, 1)
    return metrics


def tool_duration(session: dict, tool: str) -> float | None:
    for entry in session.get("tool_results", []):
        if entry.get("tool_name") != tool:
            continue
        duration = entry.get("duration")
        if not duration:
            return None
        match = re.match(r"([\d.]+)(ms|s|m|h)", duration)
        if not match:
            return None
        value = float(match.group(1))
        unit = match.group(2)
        return {"ms": value / 1000, "s": value, "m": value * 60, "h": value * 3600}[unit]
    return None


def load_session(workdir: Path) -> tuple[dict, list[dict]]:
    session_path = find_session(workdir)
    if session_path is None:
        return {}, []
    session = json.loads(session_path.read_text())
    findings = session.get("findings", [])
    return session, findings


def loose_key(finding: dict) -> str:
    return "|".join(
        [
            str(finding.get("category", "")),
            str(finding.get("title", "")),
            str(finding.get("evidence", "")),
        ]
    )


def strict_key(finding: dict) -> str:
    if finding.get("rule_id"):
        return "|".join(
            [
                str(finding.get("source_tool", "")),
                str(finding.get("rule_id", "")),
                str(finding.get("location", {}).get("file", "")),
            ]
        )
    return "|".join(
        [
            str(finding.get("category", "")),
            str(finding.get("title", "")),
            str(finding.get("location", {}).get("file", "")),
            str(finding.get("evidence", "")),
        ]
    )


def semgrep_errors(workdir: Path) -> int | None:
    path = workdir / "semgrep.sarif"
    if not path.exists():
        return None
    try:
        sarif = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    count = 0
    for run in sarif.get("runs", []):
        for invocation in run.get("invocations", []):
            for note in invocation.get("toolExecutionNotifications", []):
                if note.get("level") == "error":
                    count += 1
    return count


def run_backend(binary: str, backend: str, apk: str, base: Path, stages: str) -> dict:
    outdir = base / backend
    shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir(parents=True, exist_ok=True)
    timefile = base / f"{backend}.time"
    stage_list = [s for s in stages.split(",") if s]
    if backend not in stage_list:
        stage_list.insert(0, backend)
    cmd = [
        "/usr/bin/time",
        "-v",
        "-o",
        str(timefile),
        binary,
        "analyze",
        apk,
        "--workdir",
        str(outdir),
        "--decompiler",
        backend,
        "--stages",
        ",".join(stage_list),
    ]
    start = time.monotonic()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    elapsed = round(time.monotonic() - start, 3)

    session, findings = load_session(outdir)
    metrics = parse_time(timefile)
    if metrics["elapsed_seconds"] is None:
        metrics["elapsed_seconds"] = elapsed
    tool = "jadx" if backend == "jadx" else "dexdc"
    return {
        "backend": backend,
        "exit_code": proc.returncode,
        "duration_seconds": metrics["elapsed_seconds"],
        "decompiler_seconds": tool_duration(session, tool),
        "peak_rss_mb": metrics["peak_rss_mb"],
        "status": session.get("status"),
        "failed_tools": session.get("failed_tools", []),
        "finding_count": len(findings),
        "findings": findings,
        "semgrep_errors": semgrep_errors(outdir),
        "stdout_tail": proc.stdout[-2000:],
    }


def compare(reference: dict, candidate: dict) -> dict:
    ref = reference["findings"]
    cand = candidate["findings"]
    ref_loose = {loose_key(f) for f in ref}
    cand_loose = {loose_key(f) for f in cand}
    matched = len(ref_loose & cand_loose)
    recall = round(matched / len(ref_loose), 4) if ref_loose else None
    new_only = len(cand_loose - ref_loose)
    strict_ref = {strict_key(f) for f in ref}
    strict_cand = {strict_key(f) for f in cand}
    return {
        "reference_findings": len(ref),
        "candidate_findings": len(cand),
        "matched_by_category_title_evidence": matched,
        "recall": recall,
        "candidate_only": new_only,
        "strict_fingerprint_overlap": len(strict_ref & strict_cand),
    }


def main() -> int:
    args = parse_args()
    if not Path(args.apk).is_file():
        print(f"artifact not found: {args.apk}", file=sys.stderr)
        return 2
    for binary in (args.binary, "jadx", "dex-decompile", "/usr/bin/time"):
        if shutil.which(binary) is None and not Path(binary).is_file():
            print(f"required tool not found: {binary}", file=sys.stderr)
            return 2

    base = Path(args.workdir)
    base.mkdir(parents=True, exist_ok=True)

    reference = run_backend(args.binary, "jadx", args.apk, base, args.stages)
    candidate = run_backend(args.binary, "dexdc", args.apk, base, args.stages)
    comparison = compare(reference, candidate)

    report = {
        "artifact": args.apk,
        "stages": args.stages,
        "reference": {k: v for k, v in reference.items() if k != "findings"},
        "candidate": {k: v for k, v in candidate.items() if k != "findings"},
        "comparison": comparison,
        "acceptance": {
            "recall_ge_95pct": comparison["recall"] is not None and comparison["recall"] >= 0.95,
            "semgrep_parse_errors_lt_5pct": (
                candidate["semgrep_errors"] is None
                or candidate["semgrep_errors"] < max(1, candidate["finding_count"] * 0.05)
            ),
            "export_lt_30s": (
                candidate["decompiler_seconds"] is not None
                and candidate["decompiler_seconds"] < 30
            ),
            "peak_rss_lt_1gb": (
                candidate["peak_rss_mb"] is not None and candidate["peak_rss_mb"] < 1024
            ),
        },
    }

    print(f"reference (jadx): {reference['finding_count']} findings, "
          f"{reference['decompiler_seconds']}s decompiler, {reference['peak_rss_mb']} MB RSS")
    print(f"candidate (dexdc): {candidate['finding_count']} findings, "
          f"{candidate['decompiler_seconds']}s decompiler, {candidate['peak_rss_mb']} MB RSS")
    print(f"recall by category+title+evidence: {comparison['recall']}")
    print("acceptance:")
    for name, ok in report["acceptance"].items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"report: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
