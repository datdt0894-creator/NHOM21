#!/usr/bin/env python3
"""Ma trận test cho Security Gate (chỉ cần Python + pyyaml). Chạy: python scripts/selftest.py"""
import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = str(ROOT / "gate" / "gate.py")
V = lambda i, s, fx: {"VulnerabilityID": i, "Severity": s, "PkgName": "p", "InstalledVersion": "1", "FixedVersion": fx}
CK = lambda cid: {"results": {"failed_checks": [{"check_id": cid, "check_name": "x", "file_path": "m.tf", "resource": "r"}]}}
SECRET = [{"RuleID": "github-pat", "File": "app.py", "StartLine": 1, "Description": "PAT"}]


def write(d, **over):
    d.mkdir(parents=True, exist_ok=True)
    rep = {"gitleaks.json": [], "semgrep.json": {"results": []}, "trivy-fs.json": {"Results": []}, "checkov.json": {"results": {"failed_checks": []}},
           "conftest.json": [{"filename": "Dockerfile", "failures": [], "warnings": []}], "trivy-image.json": {"Results": []}}
    rep.update(over)
    for k, v in rep.items():
        if v is not None:
            (d / k).write_text(v if isinstance(v, str) else json.dumps(v))


def exc_file(tmp, name, **kw):
    e = dict(id="CKV_AWS_24", scope="lab/t", owner="a@x", reason="t", created="2026-10-01", expires="2026-12-01"); e.update(kw)
    p = tmp / name; p.write_text("exceptions:\n  - " + json.dumps(e) + "\n"); return str(p)


def main():
    tmp = Path(tempfile.mkdtemp())
    # (tên, báo cáo ghi đè, ngoại lệ, verdict kỳ vọng, exit code kỳ vọng)
    cases = [
        ("PASS  - báo cáo sạch", {}, None, "PASS", 0),
        ("WARN  - chỉ có lỗi MEDIUM", {"checkov.json": CK("CKV_AWS_144")}, None, "WARN", 0),
        ("WARN  - CVE HIGH chưa có bản vá (không chặn)", {"trivy-fs.json": {"Results": [{"Target": "r", "Vulnerabilities": [V("CVE-9", "HIGH", "")]}]}}, None, "WARN", 0),
        ("BLOCK - secret", {"gitleaks.json": SECRET}, None, "BLOCK", 1),
        ("BLOCK - CVE CRITICAL có bản vá", {"trivy-fs.json": {"Results": [{"Target": "r", "Vulnerabilities": [V("CVE-1", "CRITICAL", "2")]}]}}, None, "BLOCK", 1),
        ("BLOCK - SG mở SSH (Checkov CRITICAL)", {"checkov.json": CK("CKV_AWS_24")}, None, "BLOCK", 1),
        ("ERROR - thiếu báo cáo", {"semgrep.json": None, "checkov.json": None}, None, "ERROR", 2),
        ("ERROR - báo cáo JSON hỏng", {"semgrep.json": "{khong phai json"}, None, "ERROR", 2),
        ("ERROR - sai cấu trúc báo cáo", {"gitleaks.json": {"sai": 1}}, None, "ERROR", 2),
        ("PASS  - ngoại lệ hợp lệ (đúng scope, còn hạn)", {"checkov.json": CK("CKV_AWS_24")}, ("ok.yaml", {}), "PASS", 0),
        ("BLOCK - ngoại lệ HẾT HẠN", {"checkov.json": CK("CKV_AWS_24")}, ("exp.yaml", {"expires": "2026-10-15"}), "BLOCK", 1),
        ("BLOCK - ngoại lệ sai scope", {"checkov.json": CK("CKV_AWS_24")}, ("scope.yaml", {"scope": "lab/other"}), "BLOCK", 1),
        ("BLOCK - ngoại lệ thiếu owner", {"checkov.json": CK("CKV_AWS_24")}, ("noowner.yaml", {"owner": ""}), "BLOCK", 1),
        ("BLOCK - ngoại lệ quá 90 ngày", {"checkov.json": CK("CKV_AWS_24")}, ("long.yaml", {"expires": "2027-06-01"}), "BLOCK", 1),
        ("BLOCK - secret KHÔNG miễn trừ được", {"gitleaks.json": SECRET}, ("sec.yaml", {"id": "github-pat"}), "BLOCK", 1),
    ]
    res = []
    for i, (name, over, exc, want_v, want_code) in enumerate(cases):
        t = "t"; d = tmp / f"c{i}"; write(d / t, **over)
        ex = exc_file(tmp, f"e{i}.yaml", **exc[1]) if exc else str(tmp / "none.yaml")
        if not exc: Path(ex).write_text("exceptions: []\n")
        p = subprocess.run([sys.executable, GATE, "--target", t, "--reports", str(d), "--out", str(d / "o"), "--exceptions", ex,
                            "--today", "2026-10-29"], capture_output=True, text=True, cwd=ROOT)
        got = next((x.split(":")[-1].strip() for x in p.stdout.splitlines() if x.startswith("### Security gate")), "?")
        ok = got == want_v and p.returncode == want_code
        res.append(ok)
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<52} verdict={got:<5} exit={p.returncode}" + ("" if ok else f"   (mong đợi {want_v}/{want_code})"))
    print(f"\n{sum(res)}/{len(res)} trường hợp đạt")
    sys.exit(0 if all(res) else 1)


main()
