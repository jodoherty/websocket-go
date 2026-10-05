GOLANGCI ?= golangci-lint

.PHONY: all gate lint staticcheck test race fuzz bench coverage branchcov mcdc mut multiver e2e e2e-h2 e2e-h3 e2e-connect demo certgen

# The whole gate: strict lint (all linters), independent staticcheck
# opinion, and the full test suite under the race detector.
all: lint staticcheck test

# The complete validation gate (AGENTS.md's list plus fuzz and e2e) in one
# command: there is no CI, so this is the check to run before pushing.
gate: all race fuzz bench mcdc mut branchcov coverage multiver e2e e2e-connect

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

# Ten seconds per fuzz target (run longer for deeper exploration:
# go test -fuzz=<target> -fuzztime=600s ./ws/). -run '^$' skips the regular
# suite (make test already runs it, and -fuzz would run it again).
FUZZ_TARGETS ?= FuzzReadFrame FuzzSessionRead FuzzRawTraffic FuzzCompressionParams FuzzSubprotocolNegotiation FuzzHandshakeResponse FuzzDialURL
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		echo "fuzz: $$target"; \
		go test -fuzz=$$target -fuzztime=10s -run '^$$' ./ws/ || exit 1; \
	done

# Mutation gate: apply each curated security-relevant mutation to a scratch
# copy of ws/ws.go and require the test suite to kill it. A survivor is a
# real coverage gap (a behavior the suite does not pin); an uncompilable
# mutant is a stale registry entry. The gate first probes that the local
# toolchain can load the module, and fails if every mutant is uncompilable:
# a gate that verifies nothing must never pass. Run verbose for
# per-mutant output: go run ./cmd/mut -v.
MUT_WORKERS ?= 16
mut:
	go run ./cmd/mut -workers $(MUT_WORKERS)

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

# Multi-toolchain check: on the oldest supported Go (go.mod's floor — the
# test suite uses testing/synctest, new in 1.25; ws.go vendored by copying
# works on older Go, since it compiles under the vendoring project's own
# go.mod) and on each newer release we test with, the whole module must
# build, vet, and pass the ws unit suite AND the Go e2e suite (mTLS + Node
# interop) under the race detector. The Playwright browser half is deliberately not
# repeated per toolchain — browsers exercise the protocol, not the Go
# runtime, so it runs once on the default toolchain via the e2e target.
# Toolchains download on first use.
TOOLCHAINS ?= go1.25.0 go1.26.0 go1.27.1
multiver:
	@for tc in $(TOOLCHAINS); do \
		echo "multiver: $$tc"; \
		GOTOOLCHAIN=$$tc go build ./... && \
		GOTOOLCHAIN=$$tc go vet ./ws ./e2e ./cmd/... && \
		GOTOOLCHAIN=$$tc go test -race -count=1 ./ws && \
		GOTOOLCHAIN=$$tc go test -race -count=1 ./e2e || exit 1; \
	done

# Full end-to-end: Go mTLS/interop test plus the Playwright suite
# (Firefox + Chromium) against the real demo binary. npm test runs the
# setup pretest (certgen + demo build, which playwright.config.ts's
# webServer expects at ./.bin/demo) before the browser suite; npm ci is
# idempotent and cheap when node_modules is current.
e2e:
	go test -race ./e2e/
	cd e2e && npm ci && npm test

# Extended-CONNECT (RFC 8441 / RFC 9220) transports, each in its own module
# so the root go.mod stays dependency-free (the multiver gate must still build
# on go1.25.0). e2e-h2 drives a real x/net/http2 server: the stdlib HTTP/2
# client only supports the :protocol pseudo-header on Go 1.27 (issue #53208),
# where x/net/http2 delegates to it, so the client runs on the go1.26
# toolchain, which still ships x/net's own transport, with http2xconnect=1
# (read at package init). e2e-h3 drives a real quic-go HTTP/3 server, which has
# its own extended-CONNECT implementation and runs on the default toolchain.
e2e-h2:
	cd e2e/h2 && GOTOOLCHAIN=go1.26.0 GODEBUG=http2xconnect=1 go test -race -count=1 .
e2e-h3:
	cd e2e/h3 && go test -race -count=1 .
e2e-connect: e2e-h2 e2e-h3

certgen:
	go run ./cmd/certgen -dir e2e/certs

demo: certgen
	go run ./cmd/demo
