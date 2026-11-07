# Bảng lỗi gieo cài

Cột "Kết quả" điền sau khi chạy pipeline (Phát hiện / Bỏ sót / Dương tính giả), kèm số liệu từ `gate-report.json`.

| ID | Lỗi gieo | Vị trí | Công cụ kỳ vọng | Mức gate | Cách sửa | Kết quả |
|---|---|---|---|---|---|---|
| SEED-01 | Secret giả (GitHub PAT, Stripe key) | vulnerable/app/app.py | Gitleaks | BLOCK | Đọc từ biến môi trường/secret manager, thu hồi secret | |
| SEED-02 | SQL injection | app.py `/user` | Semgrep | HIGH | Truy vấn tham số hoá | |
| SEED-03 | Command injection (`shell=True`) | app.py `/ping` | Semgrep | HIGH/MEDIUM | Danh sách tham số + kiểm tra đầu vào | |
| SEED-04 | `yaml.load` không an toàn | app.py `/config` | Semgrep, Trivy (PyYAML CVE) | HIGH | `yaml.safe_load`, nâng PyYAML | |
| SEED-05 | `debug=True`, bind 0.0.0.0 | app.py | Semgrep | MEDIUM | debug=False, host qua biến môi trường | |
| SEED-06 | Dependency cũ có CVE (PyYAML 5.3.1, Flask 1.1.2, requests 2.19.1, ...) | requirements.txt | Trivy fs | CRITICAL/HIGH | Nâng phiên bản | |
| SEED-07 | Dockerfile yếu: base cũ, root, ADD, EXPOSE 22, ENV password, thiếu HEALTHCHECK | Dockerfile | Conftest (DF002-DF006), Trivy image | HIGH/MEDIUM | slim + USER non-root + COPY + HEALTHCHECK | |
| SEED-08 | Security group mở SSH/mọi cổng cho 0.0.0.0/0 | iac/main.tf | Checkov (CKV_AWS_24, ...) | CRITICAL | Chỉ 443 từ CIDR nội bộ | |
| SEED-09 | S3 public-read, không mã hoá, không block public access | iac/main.tf | Checkov (CKV_AWS_53-56, ...) | CRITICAL/HIGH | Public access block + SSE-KMS + versioning | |
| SEED-10 | IAM `Action:* Resource:*` | iac/main.tf | Checkov (CKV_AWS_355, ...) | CRITICAL | Least privilege | |
| SEED-11 | RDS public, không mã hoá, mật khẩu hard-code | iac/main.tf | Checkov, Gitleaks (hashicorp-tf-password) | HIGH | private + encrypted + biến sensitive | |
| SEED-12 | CVE trong base image `python:3.8` | image | Trivy image | HIGH/CRITICAL | `python:3.12-slim`, rebuild thường xuyên | |

Gợi ý đo **dương tính giả**: đánh dấu từng finding là thật/giả (cột Kết quả) và tính precision = thật / (thật + giả); tính recall = số lỗi gieo được phát hiện / 12.
