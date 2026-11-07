#!/usr/bin/env python3
"""Tạo trang báo cáo HTML tự chứa (không cần mạng) từ gate-out/<target>/gate-report.json.
Chạy: python scripts/report.py [--gate-out gate-out] [--reports reports] [--out gate-out/report.html]"""
import argparse, datetime as dt, json
from html import escape as e
from math import sqrt
from pathlib import Path

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LAYERS = [("secrets", "Secret"), ("sast", "SAST"), ("sca", "SCA"), ("iac", "IaC"), ("policy", "Policy"), ("image", "Image")]


def load(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def bar(v, mx, cls):
    w = 0 if not v else max(2, round(100 * sqrt(v) / sqrt(mx))) if mx else 0
    return f'<div class="track"><div class="fill {cls}" style="width:{w}%"></div></div>'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate-out", default="gate-out"); ap.add_argument("--reports", default="reports")
    ap.add_argument("--out", default=None); ap.add_argument("--targets", nargs="+", default=["vulnerable", "fixed"])
    a = ap.parse_args()
    D = {t: load(Path(a.gate_out) / t / "gate-report.json") for t in a.targets}
    D = {t: d for t, d in D.items() if d}
    if not D:
        raise SystemExit("Không tìm thấy gate-report.json. Chạy gate/gate.py trước.")
    TL = {}
    for t in D:
        ts = [load(p) for p in sorted((Path(a.reports) / t).glob("timing-*.json"))]
        TL[t] = [x for x in ts if x]
    cls = {"vulnerable": "bad", "fixed": "ok"}
    h = []
    # --- thẻ kết luận
    h.append('<section class="cards">')
    for t, d in D.items():
        tot = {k: sum(c[k] for c in d["counts"].values()) for k in ("BLOCK", "WARN", "EXCEPTED", "IGNORE")}
        st = d.get("verdict") or ("BLOCK" if d["blocked"] else "PASS")
        kind = {"PASS": "ok", "WARN": "warn", "BLOCK": "bad", "ERROR": "err"}.get(st, "bad")
        h.append(f'<div class="card {kind}"><div class="lbl">{e(t)}</div><div class="verdict">{st}</div>'
                 f'<div class="sub">{tot["BLOCK"]} chặn · {tot["WARN"]} cảnh báo · {tot["EXCEPTED"]} ngoại lệ'
                 + (f' · thiếu báo cáo: {e(", ".join(d["missing"]))}' if d["missing"] else "") + '</div></div>')
    h.append("</section>")
    # --- chặn theo lớp
    mx = max([c["BLOCK"] for d in D.values() for c in d["counts"].values()] + [1])
    h.append('<section><h2>Số finding bị chặn theo lớp kiểm tra</h2><p class="note">Độ dài thanh theo căn bậc hai để lớp có ít lỗi vẫn nhìn thấy; số thật nằm bên phải.</p><div class="grid">')
    for k, name in LAYERS:
        h.append(f'<div class="row"><div class="rl">{name}</div><div>')
        for t, d in D.items():
            v = d["counts"].get(k, {}).get("BLOCK", 0)
            h.append(f'<div class="line">{bar(v, mx, cls.get(t, "ok"))}<span class="n">{v}</span><span class="t">{e(t)}</span></div>')
        h.append("</div></div>")
    h.append("</div></section>")
    # --- CVE image trước/sau
    sev = {t: {s: sum(1 for f in d["findings"] if f["layer"] == "image" and f["severity"] == s) for s in SEV} for t, d in D.items()}
    mx = max([v for s in sev.values() for v in s.values()] + [1])
    h.append('<section><h2>Lỗ hổng trong container image (trước và sau khắc phục)</h2><div class="grid">')
    for s in SEV:
        h.append(f'<div class="row"><div class="rl">{s}</div><div>')
        for t in D:
            h.append(f'<div class="line">{bar(sev[t][s], mx, cls.get(t, "ok"))}<span class="n">{sev[t][s]}</span><span class="t">{e(t)}</span></div>')
        h.append("</div></div>")
    h.append("</div></section>")
    # --- thời gian
    if any(TL.values()):
        h.append('<section><h2>Thời gian pipeline</h2><table><tr><th>Target</th><th>Lớp</th><th>Giây</th></tr>')
        for t, ts in TL.items():
            for x in sorted(ts, key=lambda x: -x["seconds"]):
                h.append(f'<tr><td>{e(t)}</td><td>{e(x["name"])}</td><td class="r">{x["seconds"]}</td></tr>')
            if ts:
                tot, wall = sum(x["seconds"] for x in ts), max(x["seconds"] for x in ts)
                h.append(f'<tr class="sum"><td>{e(t)}</td><td>Tuần tự {tot}s · song song {wall}s</td><td class="r">tiết kiệm {tot - wall}s ({round(100 * (tot - wall) / tot) if tot else 0}%)</td></tr>')
        h.append("</table></section>")
    # --- bảng finding chặn
    for t, d in D.items():
        bl = sorted((f for f in d["findings"] if f["decision"] == "BLOCK"), key=lambda f: SEV.index(f["severity"]) if f["severity"] in SEV else 9)
        if not bl:
            continue
        h.append(f'<section><h2>Finding chặn release - {e(t)} (hiển thị {min(15, len(bl))}/{len(bl)})</h2><div class="scroll"><table><tr><th>Mức</th><th>Công cụ</th><th>ID</th><th>Vị trí</th><th>Mô tả</th></tr>')
        for f in bl[:15]:
            h.append(f'<tr><td><span class="pill {f["severity"].lower()}">{f["severity"]}</span></td><td>{e(f["tool"])}</td><td>{e(str(f["id"]))}</td><td class="mono">{e(f["location"][-48:])}</td><td>{e(f["title"][:90])}</td></tr>')
        h.append("</table></div></section>")
    # --- ngoại lệ không hợp lệ
    inv = [(t, x) for t, d in D.items() for x in d["invalid_exceptions"]]
    if inv:
        h.append('<section><h2>Ngoại lệ không hợp lệ (bị bỏ qua)</h2><ul>')
        seen = set()
        for t, x in inv:
            k = (x["exception"].get("id"), x["reason"])
            if k not in seen:
                seen.add(k); h.append(f'<li><b>{e(str(k[0]))}</b>: {e(k[1])}</li>')
        h.append("</ul></section>")
    css = """:root{--bg:#f7f8fa;--fg:#1c2430;--mut:#667085;--card:#fff;--bd:#e3e7ee;--bad:#d92d20;--ok:#12805c;--bads:#fee4e2;--oks:#d1fadf;--warn:#b54708;--warns:#fef0c7;--errs:#e4e7ec;--hi:#f79009}
@media(prefers-color-scheme:dark){:root{--bg:#0f141b;--fg:#e6eaf0;--mut:#98a2b3;--card:#171e28;--bd:#2a3442;--bad:#f97066;--ok:#47cd89;--bads:#3b1a18;--oks:#12332a;--warn:#fdb022;--warns:#3a2c08;--errs:#2a3442;--hi:#fdb022}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;padding:24px;max-width:1000px;margin:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}.sub0{color:var(--mut);margin-bottom:20px}
section{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px 18px;margin:16px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;background:none;border:0;padding:0}
.card{border-radius:12px;padding:16px 18px;border:1px solid var(--bd)}.card.bad{background:var(--bads)}.card.ok{background:var(--oks)}
.lbl{color:var(--mut);text-transform:uppercase;font-size:12px;letter-spacing:.06em}.verdict{font-size:28px;font-weight:700}.card.warn{background:var(--warns)}.card.err{background:var(--errs)}.card.warn .verdict{color:var(--warn)}.card.err .verdict{color:var(--mut)}.card.bad .verdict{color:var(--bad)}.card.ok .verdict{color:var(--ok)}.sub{color:var(--mut);font-size:13px}
.note{color:var(--mut);font-size:13px;margin:0 0 8px}.row{display:grid;grid-template-columns:90px 1fr;gap:10px;padding:6px 0;border-top:1px solid var(--bd)}.rl{font-weight:600}
.line{display:flex;align-items:center;gap:8px;margin:2px 0}.track{flex:1;height:10px;background:var(--bd);border-radius:5px;overflow:hidden}.fill{height:100%}.fill.bad{background:var(--bad)}.fill.ok{background:var(--ok)}
.n{width:52px;text-align:right;font-variant-numeric:tabular-nums}.t{width:84px;color:var(--mut);font-size:12px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-top:1px solid var(--bd);vertical-align:top}th{color:var(--mut);font-weight:600}.r{text-align:right}.sum td{font-weight:600}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.pill{padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;background:var(--bd)}.pill.critical{background:var(--bads);color:var(--bad)}.pill.high{color:var(--hi);background:var(--bd)}
footer{color:var(--mut);font-size:12px;margin-top:20px}"""
    html = (f'<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>DevSecOps Gate Report</title><style>{css}</style></head><body><h1>Báo cáo Security Gate</h1>'
            f'<div class="sub0">Đề tài 21 · tạo lúc {dt.datetime.now():%d/%m/%Y %H:%M}</div>{"".join(h)}'
            f'<footer>Sinh tự động bởi scripts/report.py từ gate-report.json</footer></body></html>')
    out = Path(a.out or Path(a.gate_out) / "report.html"); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8"); print("Đã tạo", out)


if __name__ == "__main__":
    main()
