GOLANGCI ?= golangci-lint

.PHONY: all lint staticcheck test race fuzz bench coverage branchcov e2e demo certgen

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

# Branch coverage. Go's built-in -cover counts statements only; this
# derives per-branch outcomes (if true/false, for entry/exit, switch
# cases) from a count-mode profile with cmd/branchcov, merging the unit
# and e2e suites (the latter via -coverpkg).
branchcov:
	go test -covermode=count -coverprofile=bc-unit.out ./ws/
	go test -covermode=count -coverpkg=./ws -coverprofile=bc-e2e.out ./e2e/
	go run ./cmd/branchcov ws bc-unit.out bc-e2e.out

# Full end-to-end: Go mTLS/interop test plus the Playwright suite
# (Firefox + Chromium) against the real demo binary.
e2e:
	go test -race ./e2e/
	cd e2e && npx playwright test

certgen:
	go run ./cmd/certgen -dir e2e/certs

demo: certgen
	go run ./cmd/demo
