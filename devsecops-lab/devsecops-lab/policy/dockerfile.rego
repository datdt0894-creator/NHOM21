# Policy as code (OPA/Conftest) cho Dockerfile. Thông điệp bắt đầu bằng mã "DFxxx:" để gate map ngoại lệ.
package dockerfile

import rego.v1

deny contains msg if {
	some i
	input[i].Cmd == "from"
	val := input[i].Value[0]
	endswith(val, ":latest")
	msg := sprintf("DF001: base image dùng tag ':latest' (%s)", [val])
}

deny contains msg if {
	not has_non_root_user
	msg := "DF002: Dockerfile không có USER non-root (container chạy bằng root)"
}

has_non_root_user if {
	some i
	input[i].Cmd == "user"
	input[i].Value[0] != "root"
	input[i].Value[0] != "0"
}

deny contains msg if {
	some i
	input[i].Cmd == "expose"
	some p in input[i].Value
	port := split(p, "/")[0]
	port == "22"
	msg := "DF003: EXPOSE cổng 22 (SSH) trong container"
}

deny contains msg if {
	some i
	input[i].Cmd == "env"
	v := lower(concat(" ", input[i].Value))
	some kw in ["password", "secret", "token", "api_key"]
	contains(v, kw)
	msg := sprintf("DF004: nghi ngờ secret trong ENV (%s)", [kw])
}

warn contains msg if {
	some i
	input[i].Cmd == "add"
	msg := "DF005: dùng ADD thay vì COPY"
}

warn contains msg if {
	not has_healthcheck
	msg := "DF006: thiếu HEALTHCHECK"
}

has_healthcheck if {
	some i
	input[i].Cmd == "healthcheck"
}
