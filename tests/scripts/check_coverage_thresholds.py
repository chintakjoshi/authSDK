"""Enforce package-level coverage thresholds from a coverage JSON report."""

from __future__ import annotations

import json
import sys
from pathlib import Path

THRESHOLDS = {
    "app/core": 95.0,
    "app/services": 90.0,
    "app/routers": 85.0,
}


def _normalize(path: str) -> str:
    """Normalize file paths for platform-independent prefix checks."""
    return path.replace("\\", "/")


def _load_json(path: Path) -> dict:
    """Load coverage JSON payload from disk."""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _package_coverage(report: dict, package_prefix: str) -> tuple[float, int]:
    """Calculate weighted line coverage for a package prefix."""
    files = report.get("files", {})
    matched = [
        payload
        for file_path, payload in files.items()
        if _normalize(file_path).startswith(package_prefix)
    ]
    if not matched:
        return 0.0, 0

    total_statements = sum(int(item["summary"]["num_statements"]) for item in matched)
    total_covered = sum(int(item["summary"]["covered_lines"]) for item in matched)
    if total_statements == 0:
        return 100.0, len(matched)
    return (total_covered / total_statements) * 100.0, len(matched)


def main() -> int:
    """Run threshold checks and print package-level outcomes."""
    if len(sys.argv) != 2:
        print("Usage: python tests/scripts/check_coverage_thresholds.py <coverage-json-path>")
        return 2

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"Coverage report not found: {report_path}")
        return 2

    report = _load_json(report_path)
    failures: list[str] = []

    for package_prefix, threshold in THRESHOLDS.items():
        percentage, file_count = _package_coverage(report, package_prefix)
        print(
            f"{package_prefix}: {percentage:.2f}% (files={file_count}, threshold={threshold:.2f}%)"
        )
        if file_count == 0:
            failures.append(f"{package_prefix}: no files matched prefix")
            continue
        if percentage < threshold:
            failures.append(
                f"{package_prefix}: {percentage:.2f}% is below required {threshold:.2f}%"
            )

    if failures:
        print("\nCoverage threshold failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nCoverage thresholds satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
