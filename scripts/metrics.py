#!/usr/bin/env python3
"""Tính precision / recall / dương tính giả từ gate-report.json + nhãn thủ công.

B1: python scripts/metrics.py --init  --report gate-out/vulnerable/gate-report.json   -> tạo docs/triage.csv
B2: mở docs/triage.csv, điền cột `label` (TP hoặc FP) và `seed_id` (SEED-01..12 nếu TP khớp lỗi gieo)
B3: python scripts/metrics.py --triage docs/triage.csv --seeds 12
"""
import argparse, csv, json, sys
from collections import defaultdict

COLS = ["target", "tool", "id", "severity", "decision", "location", "label", "seed_id"]


def init(report, out):
    d = json.load(open(report))
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(COLS)
        for x in d["findings"]:
            if x["decision"] != "IGNORE":
                w.writerow([d["target"], x["tool"], x["id"], x["severity"], x["decision"], x["location"], "", ""])
    print(f"Đã tạo {out}. Hãy điền cột label (TP/FP) và seed_id.")


def calc(path, seeds):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    lab = [r for r in rows if r["label"].strip().upper() in ("TP", "FP")]
    print(f"Đã gán nhãn {len(lab)}/{len(rows)} finding.\n")
    st = defaultdict(lambda: [0, 0])
    for r in lab:
        st[r["tool"]][0 if r["label"].strip().upper() == "TP" else 1] += 1
    print(f"{'Công cụ':<10}{'TP':>5}{'FP':>5}{'Precision':>11}{'FP rate':>9}")
    tp_all = fp_all = 0
    for t, (tp, fp) in sorted(st.items()):
        n = tp + fp; tp_all += tp; fp_all += fp
        print(f"{t:<10}{tp:>5}{fp:>5}{tp/n:>11.0%}{fp/n:>9.0%}")
    if tp_all + fp_all:
        print(f"{'TỔNG':<10}{tp_all:>5}{fp_all:>5}{tp_all/(tp_all+fp_all):>11.0%}{fp_all/(tp_all+fp_all):>9.0%}")
    found = {r["seed_id"].strip() for r in lab if r["label"].strip().upper() == "TP" and r["seed_id"].strip()}
    print(f"\nRecall (lỗi gieo được phát hiện): {len(found)}/{seeds} = {len(found)/seeds:.0%}")
    print("Bỏ sót:", ", ".join(f"SEED-{i:02d}" for i in range(1, seeds + 1) if f"SEED-{i:02d}" not in found) or "không")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", action="store_true"); ap.add_argument("--report")
    ap.add_argument("--triage", default="docs/triage.csv"); ap.add_argument("--seeds", type=int, default=12)
    a = ap.parse_args()
    if a.init:
        if not a.report: sys.exit("--init cần --report")
        init(a.report, a.triage)
    else:
        calc(a.triage, a.seeds)
