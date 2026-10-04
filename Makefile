GOLANGCI ?= golangci-lint

.PHONY: all gate lint staticcheck test race fuzz bench coverage branchcov mcdc multiver e2e demo certgen

# The whole gate: strict lint (all linters), independent staticcheck
# opinion, and the full test suite under the race detector.
all: lint staticcheck test

# The complete validation gate (AGENTS.md's list plus fuzz and e2e) in one
# command: there is no CI, so this is the check to run before pushing.
gate: all race fuzz bench mcdc branchcov coverage multiver e2e

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
# -run '^$' skips the regular suite (make test already runs it, and
# -fuzz would run it again); the fuzz engine loads the seed corpus from
# testdata/fuzz regardless, so no exploration time is lost.
fuzz:
	go test -fuzz=FuzzReadFrame -fuzztime=10s -run '^$$' ./ws/

bench:
	go test -bench=. -benchmem -run XXX ./ws/

coverage:
	go test -coverprofile=cov.out ./ws/ && go tool cover -func=cov.out | tail -1

# Branch coverage. Go's built-in -cover counts statements only; this
# derives per-branch outcomes (if true/false, for entry/exit, switch
# cases) from a count-mode profile with cmd/branchcov, merging the unit
# and e2e suites (the latter via -coverpkg). -min makes it a real gate:
# the run fails if merged coverage drops below 90% (the current ~94% has
# headroom over the documented structurally-unreachable error branches).
branchcov:
	go test -covermode=count -coverprofile=bc-unit.out ./ws/
	go test -covermode=count -coverpkg=./ws -coverprofile=bc-e2e.out ./e2e/
	go run ./cmd/branchcov -min 90 ws bc-unit.out bc-e2e.out

# MC/DC audit: computes the required independence pairs for every
# compound decision in ws/ and verifies each is traced to a test in
# ws/mcdc_test.go (cmd/mcdc + its registry). Fails on any new or
# untraced compound condition.
mcdc:
	go run ./cmd/mcdc ws

# Multi-toolchain floor check: the library must build and pass its unit
# suite on the oldest supported Go (go.mod's floor; ws.go is vendored by
# copying, so the floor is the oldest Go a vendoring project may run) and
# on each newer release we test with. Toolchains download on first use.
TOOLCHAINS ?= go1.25.0 go1.26.0 go1.27.1
multiver:
	@for tc in $(TOOLCHAINS); do \
		echo "multiver: $$tc"; \
		GOTOOLCHAIN=$$tc go build ./... && \
		GOTOOLCHAIN=$$tc go vet ./ws ./e2e ./cmd/... && \
		GOTOOLCHAIN=$$tc go test -count=1 ./ws || exit 1; \
	done

# Full end-to-end: Go mTLS/interop test plus the Playwright suite
# (Firefox + Chromium) against the real demo binary. npm test runs the
# setup pretest (certgen + demo build, which playwright.config.ts's
# webServer expects at ./.bin/demo) before the browser suite; npm ci is
# idempotent and cheap when node_modules is current.
e2e:
	go test -race ./e2e/
	cd e2e && npm ci && npm test

certgen:
	go run ./cmd/certgen -dir e2e/certs

demo: certgen
	go run ./cmd/demo
