# Đề tài 21 - Đường ống DevSecOps phát hiện cấu hình sai và lỗ hổng trước triển khai

Repo thực nghiệm gồm: ứng dụng Flask + Terraform mẫu (2 phiên bản `vulnerable` / `fixed`), pipeline GitHub Actions 6 lớp kiểm tra,
security gate theo policy-as-code và cơ chế ngoại lệ có chủ sở hữu, thời hạn.

## Cấu trúc
```
lab/vulnerable/{app,iac}   Bản gieo lỗi có chủ đích (bảng lỗi: docs/seeded-vulns.md)
lab/fixed/{app,iac}        Bản đã khắc phục
policy/dockerfile.rego     OPA/Conftest - policy as code cho Dockerfile
gate/gate-policy.yaml      Ngưỡng chặn / cảnh báo / bỏ qua
gate/exceptions.yaml       Ngoại lệ (owner, reason, created, expires, ticket)
gate/gate.py               Gộp báo cáo -> quyết định gate, summary.md, gate-report.json
.github/workflows/devsecops.yml   Pipeline CI
scripts/run_local.sh       Chạy cục bộ + đo thời gian
docs/                      Bảng lỗi, kế hoạch thực nghiệm, dàn ý báo cáo
```

## Pipeline
| Lớp | Công cụ | Báo cáo máy đọc được |
|---|---|---|
| 1. Secret scanning | Gitleaks | gitleaks.json |
| 2. SAST | Semgrep | semgrep.json |
| 3. SCA (dependency) | Trivy fs | trivy-fs.json |
| 4. IaC scanning | Checkov | checkov.json |
| 5. Policy as code | Conftest (OPA) | conftest.json |
| 6. Container image + SBOM | Trivy image, Syft | trivy-image.json, sbom.spdx.json |
| Gate | gate/gate.py | gate-report.json, summary.md (đăng lên PR) |
| Publish (main) | Cosign | ký image keyless + attest SBOM |

Các scanner luôn thoát mã 0 và chỉ ghi báo cáo; job `gate` quyết định. Các lớp chạy **song song**.

## Logic gate (gate/gate-policy.yaml)
Bốn trạng thái: **PASS** / **WARN** (exit 0, cho phát hành), **BLOCK** (exit 1), **ERROR** (exit 2, thiếu hoặc hỏng báo cáo). Chi tiết: `docs/member3-deliverables.md`.
- **BLOCK**: CRITICAL/HIGH; mọi secret; thiếu báo cáo của bất kỳ lớp nào (fail-closed).
- **WARN**: MEDIUM; CVE HIGH/CRITICAL chưa có bản vá (không làm tê liệt dev; đổi bằng `block_unfixed_vulns`).
- **IGNORE**: LOW/INFO.
- **Ngoại lệ**: bắt buộc id, scope (đúng target), owner, reason, created, expires; tối đa 90 ngày; secret vẫn luôn BLOCK; ngoại lệ sai ngày/quá hạn tự mất hiệu lực và bị báo trong summary.
- `--expect block` chỉ thành công khi có finding BLOCK thật và đủ cả 6 báo cáo; thiếu báo cáo không được tính là bằng chứng phát hiện.

## Chứng minh "commit lỗi bị chặn -> sửa -> vượt" (đúng yêu cầu đề tài)
Job `gate` có bước **cưỡng chế** đọc target từ `gate/enforce-target.txt` (mặc định `fixed`):
1. Tạo nhánh, sửa file thành `vulnerable`, mở PR -> bước cưỡng chế **đỏ** (chụp màn hình + lưu `gate-out`).
2. Commit tiếp theo sửa file thành `fixed` -> pipeline **xanh** (chụp màn hình).
Hai bước kiểm chứng lab (`--expect block` / `--expect pass`) vẫn chạy song song để đối chiếu.

## Trang báo cáo HTML
Sau khi gate chạy xong: `python scripts/report.py` tạo `gate-out/report.html` (mở bằng trình duyệt, không cần mạng): kết luận BLOCKED/PASSED, số lỗi chặn theo lớp,
lỗ hổng image trước/sau, thời gian pipeline, danh sách lỗi chặn. Trên CI, file này nằm trong artifact `gate-output`.

## Số lỗi thật/giả
`python scripts/metrics.py --init --report gate-out/vulnerable/gate-report.json` tạo `docs/triage.csv`; điền cột `label` (TP/FP) và `seed_id`,
rồi `python scripts/metrics.py --triage docs/triage.csv` để ra precision, tỷ lệ dương tính giả theo công cụ và recall trên 12 lỗi gieo.

## Cách chạy
1. Tạo repo GitHub mới, đẩy toàn bộ thư mục này lên nhánh `main`.
2. Mở Pull Request từ nhánh khác -> pipeline chạy, gate đăng tóm tắt lên PR.
3. Job `gate` có hai bước kiểm chứng: bản `vulnerable` **phải bị chặn** (`--expect block`), bản `fixed` **phải vượt** (`--expect pass`).
4. Đo cache: Actions -> *Run workflow* -> `no_cache = true/false`, so sánh thời gian job `image`.
5. Chạy cục bộ: `./scripts/run_local.sh vulnerable` (cần cài các công cụ ở trên).

## Lưu ý quan trọng
- **Đã kiểm thử**: `gate/gate.py` (bằng báo cáo giả lập: chặn, cảnh báo, ngoại lệ hết hạn, fail-closed) và cú pháp YAML của workflow.
  **Chưa chạy thực tế** Semgrep, Trivy và Syft (cần tải rule/CSDL lỗ hổng từ mạng) cũng như GitHub Actions. Đã chạy thật Gitleaks, Checkov, Conftest và gate trên báo cáo thật của chúng. Lần chạy đầu bạn có thể cần chỉnh nhỏ
  (phiên bản action/công cụ, định dạng báo cáo, mapping severity); cứ gửi log lỗi cho mình, mình sẽ sửa cùng bạn.
- Secret trong `lab/vulnerable` là **giả**, nhưng GitHub *push protection* có thể chặn lúc push. Nếu bị chặn, dùng đường link "allow secret" mà GitHub cung cấp
  (đây là dữ liệu giả cho mục đích thực nghiệm).
- CVE thay đổi theo thời gian: bản `fixed` có thể xuất hiện CVE mới trong tương lai; đây là tình huống thật để minh hoạ ngoại lệ có thời hạn.
- Nên ghim các action theo commit SHA và kiểm tra checksum binary tải về khi dùng ngoài môi trường học tập (chuỗi cung ứng).
- Không `terraform apply` thư mục `iac` của bản `vulnerable`.
