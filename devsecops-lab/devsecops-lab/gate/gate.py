#!/usr/bin/env python3
"""Security gate: merge scanner reports and decide BLOCK/WARN/IGNORE."""
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
MISSING = "MISSING"


def load_json(path):
    """Load UTF-8 JSON. Missing, unreadable, or malformed reports fail closed."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return MISSING


def F(tool, layer, fid, sev, title, loc, fixable=True):
    sev = (sev or "UNKNOWN").upper()
    return dict(
        tool=tool,
        layer=layer,
        id=fid,
        severity=sev if sev in SEV else "UNKNOWN",
        title=(title or "")[:120],
        location=loc or "",
        fixable=fixable,
    )


def parse_gitleaks(data, policy):
    if not isinstance(data, list):
        raise ValueError("Gitleaks JSON must be an array")
    return [
        F(
            "gitleaks",
            "secrets",
            item.get("RuleID"),
            "CRITICAL",
            item.get("Description"),
            f"{item.get('File')}:{item.get('StartLine')}",
        )
        for item in data
    ]


def parse_semgrep(data, policy):
    if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        raise ValueError("Semgrep JSON must contain a results array")
    severity_map = policy["semgrep_severity_map"]
    return [
        F(
            "semgrep",
            "sast",
            item["check_id"].split(".")[-1],
            severity_map.get(item.get("extra", {}).get("severity"), "MEDIUM"),
            item.get("extra", {}).get("message"),
            f"{item.get('path')}:{item.get('start', {}).get('line')}",
        )
        for item in data.get("results", [])
    ]


def parse_trivy(data, layer):
    if not isinstance(data, dict):
        raise ValueError("Trivy JSON must be an object")
    out = []
    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            out.append(
                F(
                    "trivy",
                    layer,
                    vuln.get("VulnerabilityID"),
                    vuln.get("Severity"),
                    f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')} - {vuln.get('Title', '')}",
                    result.get("Target"),
                    fixable=bool(vuln.get("FixedVersion")),
                )
            )
    return out


def parse_checkov(data, policy):
    overrides = {
        check_id: severity
        for severity, check_ids in policy["checkov_severity_overrides"].items()
        for check_id in check_ids
    }
    blocks = data if isinstance(data, list) else [data]
    out = []
    for block in blocks:
        if not isinstance(block, dict):
            raise ValueError("Checkov JSON entries must be objects")
        results = block.get("results", {}) or {}
        for check in results.get("failed_checks", []) or []:
            check_id = check.get("check_id", "UNKNOWN")
            out.append(
                F(
                    "checkov",
                    "iac",
                    check_id,
                    check.get("severity") or overrides.get(check_id, policy["checkov_default_severity"]),
                    check.get("check_name"),
                    f"{check.get('file_path')} [{check.get('resource')}]",
                )
            )
    return out


def parse_conftest(data, policy):
    if not isinstance(data, list):
        raise ValueError("Conftest JSON must be an array")
    out = []
    for report in data:
        if not isinstance(report, dict):
            raise ValueError("Conftest JSON entries must be objects")
        for key, severity in (("failures", "HIGH"), ("warnings", "MEDIUM")):
            for item in report.get(key, []) or []:
                message = item.get("msg", "")
                finding_id = (
                    message.split(":")[0]
                    if re.match(r"^[A-Z]{2,}\d+:", message)
                    else message[:20]
                )
                out.append(
                    F("conftest", "policy", finding_id, severity, message, report.get("filename"))
                )
    return out


LAYERS = [
    ("gitleaks.json", parse_gitleaks),
    ("semgrep.json", parse_semgrep),
    ("trivy-fs.json", lambda data, policy: parse_trivy(data, "sca")),
    ("checkov.json", parse_checkov),
    ("conftest.json", parse_conftest),
    ("trivy-image.json", lambda data, policy: parse_trivy(data, "image")),
]


def check_exceptions(items, policy, today):
    valid, invalid = [], []
    for exception in items or []:
        if not isinstance(exception, dict):
            invalid.append(({"value": exception}, "exception must be a YAML object"))
            continue
        required = ("id", "scope", "owner", "reason", "created", "expires")
        missing = [key for key in required if not exception.get(key)]
        if missing:
            invalid.append((exception, f"missing fields: {', '.join(missing)}"))
            continue
        try:
            created = dt.date.fromisoformat(str(exception["created"]))
            expires = dt.date.fromisoformat(str(exception["expires"]))
        except (TypeError, ValueError):
            invalid.append((exception, "created/expires must use YYYY-MM-DD"))
            continue
        if created > today:
            invalid.append((exception, f"created date is in the future ({created})"))
        elif expires < created:
            invalid.append((exception, f"expiry {expires} is before created date {created}"))
        elif expires < today:
            invalid.append((exception, f"EXPIRED on {expires}"))
        elif (expires - created).days > policy["max_exception_days"]:
            invalid.append((exception, f"duration exceeds {policy['max_exception_days']} days"))
        else:
            valid.append(exception)
    return valid, invalid


def decide(finding, policy, exceptions):
    # Secrets are never exception-eligible.
    if finding["tool"] in policy["always_block_tools"]:
        return "BLOCK", None
    for exception in exceptions:
        if (
            exception["id"] == finding["id"]
            and exception["scope"].rstrip("/") == finding.get("_scope", "").rstrip("/")
        ):
            return "EXCEPTED", exception
    if finding["severity"] in policy["block_severities"]:
        if (
            finding["tool"] == "trivy"
            and not finding["fixable"]
            and not policy["block_unfixed_vulns"]
        ):
            return "WARN", None
        return "BLOCK", None
    if finding["severity"] in policy["warn_severities"]:
        return "WARN", None
    return "IGNORE", None


def timings(report_dir):
    timing_files = list(Path(report_dir).glob("timing-*.json"))
    if not timing_files:
        return None
    records = [json.loads(path.read_text(encoding="utf-8-sig")) for path in timing_files]
    total = sum(record["seconds"] for record in records)
    wall = max(record["seconds"] for record in records)
    return records, total, wall


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--policy", default="gate/gate-policy.yaml")
    parser.add_argument("--exceptions", default="gate/exceptions.yaml")
    parser.add_argument("--out", default="gate-out")
    parser.add_argument("--expect", choices=["none", "block", "pass", "warn", "error"], default="none")
    parser.add_argument("--today", default=None)
    args = parser.parse_args()

    # Load policy BEFORE using it to validate exceptions or parse scanner reports.
    policy_data = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8-sig")) or {}
    if not isinstance(policy_data, dict):
        parser.error("policy YAML must contain an object")
    policy = policy_data

    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    exception_data = yaml.safe_load(Path(args.exceptions).read_text(encoding="utf-8-sig")) or {}
    if not isinstance(exception_data, dict):
        parser.error("exceptions YAML must contain an object")
    exceptions, invalid_exceptions = check_exceptions(
        exception_data.get("exceptions"), policy, today
    )

    # Reports are stored under reports/<target>/, not directly under reports/.
    report_dir = Path(args.reports) / args.target
    findings, missing_reports = [], []
    for filename, report_parser in LAYERS:
        report_data = load_json(report_dir / filename)
        if report_data == MISSING:
            missing_reports.append(filename)
            continue
        try:
            findings.extend(report_parser(report_data, policy))
        except (KeyError, TypeError, ValueError) as error:
            missing_reports.append(f"{filename} (invalid schema: {error})")

    counts, blocking, warnings, used_exceptions = {}, [], [], []
    for finding in findings:
        finding["_scope"] = f"lab/{args.target}"
        decision, exception = decide(finding, policy, exceptions)
        finding["decision"] = decision
        counts.setdefault(
            finding["layer"], {"BLOCK": 0, "WARN": 0, "EXCEPTED": 0, "IGNORE": 0}
        )[decision] += 1
        if decision == "BLOCK":
            blocking.append(finding)
        elif decision == "WARN":
            warnings.append(finding)
        elif decision == "EXCEPTED":
            used_exceptions.append((finding, exception))

    fail_closed = bool(missing_reports) and bool(policy["fail_closed"])
    # Kết luận 4 trạng thái. Ưu tiên: BLOCK (có finding chặn thật) > ERROR (thiếu/hỏng báo cáo)
    # > WARN (chỉ có cảnh báo) > PASS (sạch). Exit code khi --expect none: PASS/WARN=0, BLOCK=1, ERROR=2.
    if blocking:
        verdict = "BLOCK"
    elif fail_closed:
        verdict = "ERROR"
    elif warnings:
        verdict = "WARN"
    else:
        verdict = "PASS"
    blocked = verdict in ("BLOCK", "ERROR")

    lines = [
        f"### Security gate - `{args.target}`: {verdict}",
        "",
        "| Layer | Block | Warn | Excepted | Ignored |",
        "|---|---:|---:|---:|---:|",
    ]
    for layer, count in sorted(counts.items()):
        lines.append(
            f"| {layer} | {count['BLOCK']} | {count['WARN']} | {count['EXCEPTED']} | {count['IGNORE']} |"
        )
    if missing_reports:
        lines += ["", f"Missing/invalid reports: {', '.join(missing_reports)} (fail-closed -> block: {fail_closed})"]
    if blocking:
        lines += [
            "",
            "**Blocking findings (up to 25):**",
            "",
            "| Severity | Tool | ID | Location | Description |",
            "|---|---|---|---|---|",
        ]
        for finding in sorted(blocking, key=lambda item: SEV.index(item["severity"]))[:25]:
            title = finding["title"].replace("|", "/")
            lines.append(
                f"| {finding['severity']} | {finding['tool']} | {finding['id']} | `" 
                f"{finding['location'][:60]}` | {title[:70]} |"
            )
    if used_exceptions:
        lines += ["", "**Applied exceptions:**"] + [
            f"- {finding['id']} - owner {exception['owner']}, expires {exception['expires']} ({exception.get('ticket', '-')})"
            for finding, exception in used_exceptions
        ]
    if invalid_exceptions:
        lines += ["", "**Invalid/expired exceptions (ignored):**"] + [
            f"- {exception.get('id')} - {reason}" for exception, reason in invalid_exceptions
        ]

    timing_data = timings(report_dir)
    if timing_data:
        records, total, wall = timing_data
        lines += [
            "",
            "**Pipeline timing (seconds):** "
            + ", ".join(
                f"{record['name']}={record['seconds']}" for record in sorted(records, key=lambda item: item["name"])
            ),
            f"- Sequential total: {total}s; parallel wall time (longest job): {wall}s; saved {total - wall}s",
        ]

    summary = "\n".join(lines) + "\n"
    output_dir = Path(args.out) / args.target
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.md").write_text(summary, encoding="utf-8")
    (output_dir / "gate-report.json").write_text(
        json.dumps(
            {
                "target": args.target,
                "verdict": verdict,
                "blocked": blocked,
                "missing": missing_reports,
                "counts": counts,
                "findings": findings,
                "invalid_exceptions": [
                    {"exception": exception, "reason": reason}
                    for exception, reason in invalid_exceptions
                ],
            },
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )
    print(summary)

    miss_txt = "missing/invalid reports: " + ", ".join(missing_reports) if missing_reports else ""
    if args.expect == "block":
        ok = verdict == "BLOCK" and not missing_reports
        print("EXPECT block ->", "OK: real BLOCK finding detected" if ok else f"FAIL: verdict={verdict} {miss_txt}")
    elif args.expect == "pass":
        ok = verdict in ("PASS", "WARN") and not missing_reports
        print("EXPECT pass ->", "OK: target passed with complete reports" if ok else f"FAIL: verdict={verdict} {miss_txt}")
    elif args.expect == "warn":
        ok = verdict == "WARN"
        print("EXPECT warn ->", "OK" if ok else f"FAIL: verdict={verdict}")
    elif args.expect == "error":
        ok = verdict == "ERROR"
        print("EXPECT error ->", "OK" if ok else f"FAIL: verdict={verdict}")
    else:
        ok = verdict in ("PASS", "WARN")
        sys.exit(0 if ok else (2 if verdict == "ERROR" else 1))

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
