# Thành viên 3 - GitHub Actions và Security Gate: đối chiếu nhiệm vụ

| Nhiệm vụ | Đã làm ở đâu |
|---|---|
| Workflow tự chạy khi push / pull request | `.github/workflows/devsecops.yml` (`on: pull_request`, `push: main`, `workflow_dispatch`) |
| Kết nối công cụ quét (yêu cầu 4, hiện có 6 lớp) | Gitleaks, Semgrep, Trivy (fs + image), Checkov, Conftest/OPA, Syft (SBOM); ký bằng Cosign khi publish |
| Python tổng hợp và chuẩn hoá kết quả | `gate/gate.py`: mỗi công cụ có một parser, chuẩn hoá về (tool, layer, id, severity, location, fixable) |
| Chính sách PASS / WARN / BLOCK / ERROR + ngoại lệ có thời hạn | `gate/gate-policy.yaml`, `gate/exceptions.yaml` (bảng bên dưới) |
| Tóm tắt trên PR, lưu báo cáo | Bình luận PR bằng `gh pr comment`; artifact `gate-output` (summary.md, gate-report.json, report.html) và các `reports-*` |
| Chạy thử, kiểm tra trường hợp chặn / phát hành | `python scripts/selftest.py` (15 trường hợp) + chạy thật trên GitHub (PR đỏ -> xanh) |

## Bốn trạng thái của gate

| Trạng thái | Điều kiện | Exit code | Ý nghĩa với release |
|---|---|---|---|
| **PASS** | Không có finding nào cần chặn hoặc cảnh báo | 0 | Cho phát hành |
| **WARN** | Chỉ có finding MEDIUM, hoặc CVE HIGH/CRITICAL chưa có bản vá | 0 | Cho phát hành, hiện cảnh báo trên PR |
| **BLOCK** | Có finding CRITICAL/HIGH (có bản vá), mọi secret | 1 | Chặn release |
| **ERROR** | Thiếu / hỏng / sai cấu trúc báo cáo của bất kỳ lớp nào (fail-closed) | 2 | Chặn release, vì không đủ bằng chứng để kết luận |

Thứ tự ưu tiên: BLOCK > ERROR > WARN > PASS. Ngoại lệ (`exceptions.yaml`) bắt buộc có id, scope khớp chính xác, owner, reason, created, expires;
tối đa 90 ngày; hết hạn hoặc thiếu trường thì bị bỏ qua; **secret không thể được miễn trừ**.

## Ma trận test (`python scripts/selftest.py`)
PASS (sạch) · WARN (MEDIUM; CVE chưa có bản vá) · BLOCK (secret; CVE CRITICAL; SG mở SSH) · ERROR (thiếu báo cáo; JSON hỏng; sai cấu trúc)
· Ngoại lệ: hợp lệ -> PASS; hết hạn / sai scope / thiếu owner / quá 90 ngày / áp cho secret -> vẫn BLOCK.

## Minh chứng nên nộp ("kết quả chạy pipeline")
1. Ảnh chụp tab Actions: các job quét + job `gate`.
2. Ảnh PR đỏ (BLOCK, `enforce-target.txt` = `vulnerable`) và PR xanh sau khi sửa (`fixed`), kèm bình luận tóm tắt của bot.
3. Artifact `gate-output` (summary.md, gate-report.json, report.html) của hai lần chạy.
4. Kết quả `python scripts/selftest.py` (15/15).
