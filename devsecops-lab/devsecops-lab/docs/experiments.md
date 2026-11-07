# Kế hoạch thực nghiệm và cách ghi số liệu

1. **Baseline**: chạy pipeline trên PR đầu tiên -> lưu artifact `gate-output` (gate-report.json, summary.md) làm bằng chứng "commit lỗi bị chặn".
2. **Khắc phục**: bản `fixed` vượt gate -> bằng chứng "sửa rồi vượt". (Hoặc tạo commit sửa dần từng nhóm lỗi để thấy gate chuyển trạng thái.)
3. **Tỷ lệ phát hiện / dương tính giả**: điền cột Kết quả trong `seeded-vulns.md`; đếm từ `gate-report.json` (`jq '.findings | group_by(.layer)'`).
4. **Thời gian pipeline**: `timing-*.json` đã được gate.py tổng hợp: tổng tuần tự vs thực tế song song. Lặp tối thiểu 5 lần, lấy trung vị.
5. **Ảnh hưởng cache**: chạy `workflow_dispatch` với `no_cache=true` và `false`, so sánh thời gian job `image` (cache lạnh vs nóng). Cache pip của job sast/iac thấy trong log setup-python.
6. **Ngưỡng gate**: thử `block_severities` = [CRITICAL] / [CRITICAL,HIGH] / thêm MEDIUM và `block_unfixed_vulns` true/false; ghi số lần chặn và số finding "thật" bị bỏ sót -> đề xuất cân bằng tốc độ và độ bao phủ.
7. **Ngoại lệ**: thêm ngoại lệ hợp lệ trong `gate/exceptions.yaml` -> finding chuyển EXCEPTED; để quá hạn / thiếu owner -> bị bỏ qua và báo trong summary.
8. **Trước/sau SBOM & lỗ hổng image**: artifact `reports-image-vulnerable` vs `reports-image-fixed` (sbom.spdx.json, trivy-image.json); so sánh số gói và số CVE theo mức độ.
9. **Chuỗi cung ứng**: sau khi merge vào main, kiểm chứng chữ ký: `cosign verify --certificate-identity-regexp ... --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/<owner>/<repo>/lab-app:<sha>`.
