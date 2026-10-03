GOLANGCI ?= golangci-lint

.PHONY: all lint staticcheck test race fuzz bench coverage e2e demo certgen

# The whole gate: strict lint (all linters), independent staticcheck
# opinion, and the full test suite under the race detector.
all: lint staticcheck test

# Strictest standard lint: every linter enabled. The exclusion list lives in
# .golangci.yml and is deliberately short and documented.
lint:
	$(GOLANGCI) run ./...

# staticcheck with every ST/SA/S check enabled — a second, independent
# opinion (different rule engine than golangci-lint's staticcheck linter).
staticcheck:
	staticcheck -checks=all ./...

test:
	go test ./...

race:
	go test -race ./...

# Ten seconds of the frame-codec fuzzer (run longer for deeper exploration).
fuzz:
	go test -fuzz=FuzzReadFrame -fuzztime=10s ./ws/

bench:
	go test -bench=. -benchmem -run XXX ./ws/

coverage:
	go test -coverprofile=cov.out ./ws/ && go tool cover -func=cov.out | tail -1

# Full end-to-end: Go mTLS/interop test plus the Playwright suite
# (Firefox + Chromium) against the real demo binary.
e2e:
	go test -race ./e2e/
	cd e2e && npx playwright test

certgen:
	go run ./cmd/certgen -dir e2e/certs

demo: certgen
	go run ./cmd/demo
