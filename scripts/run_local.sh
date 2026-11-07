#!/usr/bin/env bash
# Chạy cùng các lớp kiểm tra ở máy cục bộ và đo thời gian (tuần tự). Cần: gitleaks, semgrep, trivy, checkov, conftest, syft, docker.
set -u
T=${1:-vulnerable}; R=reports/$T; mkdir -p "$R"
t() { local n=$1; shift; local s=$(date +%s); "$@" || true; echo "{\"name\":\"$n\",\"seconds\":$(( $(date +%s)-s ))}" > "$R/timing-$n.json"; }
t secrets gitleaks dir lab/$T --report-format json --report-path $R/gitleaks.json --redact --exit-code 0
t sast    semgrep scan --config p/python --config p/flask --metrics=off --json --output $R/semgrep.json lab/$T/app
t sca     trivy fs --scanners vuln -f json -o $R/trivy-fs.json lab/$T/app
t iac     bash -c "checkov -d lab/$T/iac --framework terraform -o json --soft-fail > $R/checkov.json"
t policy  bash -c "conftest test lab/$T/app/Dockerfile --parser dockerfile --policy policy --all-namespaces -o json > $R/conftest.json"
t image   bash -c "docker build -t lab-app:$T lab/$T/app && trivy image -f json -o $R/trivy-image.json lab-app:$T && syft lab-app:$T -o spdx-json=$R/sbom.spdx.json"
python3 gate/gate.py --target "$T" --expect none
