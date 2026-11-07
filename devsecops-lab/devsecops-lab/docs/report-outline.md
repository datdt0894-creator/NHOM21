# Dàn ý báo cáo

1. **Mở đầu**: bối cảnh, câu hỏi nghiên cứu, mục tiêu, phạm vi.
2. **Cơ sở lý thuyết**: shift-left, defense in depth; SAST/SCA/secret/IaC/image scanning; CVSS, exploitability (EPSS/KEV), false positive,
   risk acceptance, policy as code; SBOM (SPDX/CycloneDX), provenance (SLSA), image signing (Sigstore/Cosign), chuỗi cung ứng; cấu hình cloud sai, CIS benchmark, CSA CCM.
3. **Thiết kế pipeline**: sơ đồ 6 lớp + gate, lý do chọn công cụ, mô hình ngưỡng (block/warn/ignore), cơ chế ngoại lệ.
4. **Triển khai**: ứng dụng/IaC mẫu, lỗi gieo cài (bảng), cấu hình workflow, báo cáo máy đọc được, tóm tắt PR.
5. **Thực nghiệm & kết quả**: phát hiện/bỏ sót/dương tính giả, gate chặn rồi cho qua, SBOM & CVE trước/sau, thời gian pipeline (song song, cache), ảnh hưởng ngưỡng.
6. **Thảo luận**: trả lời câu hỏi nghiên cứu (cái gì nên chặn, cái gì chỉ cảnh báo), đánh đổi tốc độ phát hành vs độ bao phủ, hạn chế (phạm vi lỗi, công cụ, CVE thay đổi theo thời gian).
7. **Kết luận & đề xuất**: khuyến nghị cấu hình gate, ngoại lệ, tối ưu thời gian (scan khác biệt trên PR, quét đầy đủ theo lịch).
8. **Phụ lục**: log pipeline, gate-report.json, chính sách, tài liệu tham khảo [18], [19], [23], [49], [50].
