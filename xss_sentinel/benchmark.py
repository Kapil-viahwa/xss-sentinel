import argparse
import csv
import json
import re
from pathlib import Path


TEST_ID_PATTERN = re.compile(r"BenchmarkTest\d{5}", re.IGNORECASE)
XSS_CATEGORIES = {"reflected_xss", "dom_xss", "stored_xss", "blind_xss"}


def _normalized_test_id(value: str) -> str | None:
    match = TEST_ID_PATTERN.search(value)
    return f"BenchmarkTest{match.group(0)[-5:]}" if match else None


def load_expected_xss(path: str | Path) -> tuple[dict[str, bool], str | None]:
    expected = {}
    version = None
    with open(path, newline="", encoding="utf-8-sig") as source:
        for row in csv.reader(source):
            if not row:
                continue
            if row[0].lstrip().startswith("#"):
                header = ",".join(row)
                match = re.search(r"Benchmark version:\s*([0-9.]+)", header, re.IGNORECASE)
                if match:
                    version = match.group(1)
                continue
            if len(row) < 4 or row[1].strip().lower() != "xss" or row[3].strip() != "79":
                continue
            test_id = row[0].strip()
            status = row[2].strip().lower()
            if TEST_ID_PATTERN.fullmatch(test_id) and status in {"true", "false"}:
                expected[test_id] = status == "true"
    if not expected:
        raise ValueError("Expected-results file contains no CWE-79 XSS cases.")
    return expected, version


def score_report(report: dict, expected: dict[str, bool], benchmark_version: str | None = None) -> dict:
    covered = set()
    for resource in report.get("resources", []):
        if resource.get("kind") != "page" or resource.get("status_code") is None:
            continue
        if 200 <= int(resource["status_code"]) < 300:
            test_id = _normalized_test_id(resource.get("url", ""))
            if test_id:
                covered.add(test_id)

    detected = set()
    for finding in report.get("findings", []):
        if finding.get("state") != "confirmed" or finding.get("category") not in XSS_CATEGORIES:
            continue
        test_id = _normalized_test_id(finding.get("url") or "")
        if test_id:
            detected.add(test_id)
            covered.add(test_id)

    tested_ids = covered & expected.keys()
    untested_ids = expected.keys() - tested_ids
    tp = sum(1 for test_id in tested_ids if expected[test_id] and test_id in detected)
    fn = sum(1 for test_id in tested_ids if expected[test_id] and test_id not in detected)
    fp = sum(1 for test_id in tested_ids if not expected[test_id] and test_id in detected)
    tn = sum(1 for test_id in tested_ids if not expected[test_id] and test_id not in detected)
    positive_total = tp + fn
    negative_total = fp + tn
    tpr = tp / positive_total if positive_total else None
    fpr = fp / negative_total if negative_total else None
    score = (tpr - fpr) * 100 if tpr is not None and fpr is not None else None
    return {
        "benchmark": "OWASP BenchmarkJava",
        "benchmark_version": benchmark_version,
        "category": "xss",
        "cwe": 79,
        "tp": tp,
        "fn": fn,
        "tn": tn,
        "fp": fp,
        "tested": len(tested_ids),
        "expected": len(expected),
        "untested": len(untested_ids),
        "coverage": len(tested_ids) / len(expected),
        "tpr": tpr,
        "fpr": fpr,
        "score_percent": score,
        "complete": not untested_ids,
        "untested_test_ids": sorted(untested_ids),
        "methodology": "OWASP Benchmark score is TPR minus FPR. Only successfully crawled BenchmarkTest pages are included in confusion-matrix counts; unvisited cases are reported as untested, not silently treated as negatives.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a XSS Sentinel report against OWASP BenchmarkJava CWE-79 cases.")
    parser.add_argument("--report", required=True, help="XSS Sentinel assessment report JSON")
    parser.add_argument("--expected", required=True, help="matching OWASP expectedresults-VERSION.csv")
    parser.add_argument("--output", help="write the score JSON to this path instead of stdout")
    args = parser.parse_args()
    expected, version = load_expected_xss(args.expected)
    with open(args.report, encoding="utf-8") as source:
        report = json.load(source)
    result = score_report(report, expected, version)
    rendered = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
