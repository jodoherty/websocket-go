// Command mut is a first-party mutation gate for ws/ws.go.
//
// Each mutation in the registry (mutations.go) is a single,
// security-relevant rewrite of one spot in ws/ws.go — an operator flip, a
// bound change, a deleted guard, a constant shift. For every mutation the
// tool copies the ws package into a scratch module, applies exactly that
// rewrite, and runs the full ws test suite:
//
//   - a failing test is a KILLED mutant (the suite catches that bug);
//   - a passing suite is a SURVIVED mutant — the suite would not have
//     caught that bug, which is a test gap. Any surviving non-equivalent
//     mutant fails the gate (exit 1);
//   - a mutant that does not compile is discarded from the verdict (standard
//     mutation-testing practice) and reported as UNCOMPILABLE.
//
// The gate verifies itself before and during the run: a toolchain that
// cannot load the module (for instance, one older than go.mod's go
// directive) fails the gate up front, and a run in which every single
// mutant is uncompilable fails it as well — a gate that verified nothing
// must never pass.
//
// The registry is curated to the library's security invariants — masking,
// size limits, the close-code table, UTF-8, the handshake, the origin gate,
// the compression negotiation, the close state machine — one or two
// mutants per invariant, each carrying the property its survival would
// mean. Equivalent mutants (behaviorally indistinguishable on every
// reachable input) are marked and do not fail the gate.
//
// Usage:
//
//	go run ./cmd/mut             # the whole curated set, parallel workers
//	go run ./cmd/mut -only mask  # only mutations whose name matches
//	go run ./cmd/mut -workers 4 -v
//
// and via the Makefile: `make mut`.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// The three outcomes of testing one mutant against the ws suite.
const (
	statusKilled       = "KILLED"
	statusSurvived     = "SURVIVED"
	statusUncompilable = "UNCOMPILABLE"
)

// The verdict-row rank buckets: surviving non-equivalent mutants (the
// gate's failure case) first, then equivalent survivors, uncompilable
// mutants, and the killed ones.
const (
	rankGap          = 0
	rankEquivalent   = 1
	rankUncompilable = 2
	rankKilled       = 3
)

// Scratch-module permissions and the run's grace timeout: the deadline
// sits past go test's own 4m -timeout so a hung test binary is reported
// by the test runner (a kill), not by the context (which would look like
// an environment failure).
const (
	scratchDirPerm  = 0o700
	scratchFilePerm = 0o600
	mutantRunGrace  = 10 * time.Minute
	envProbeGrace   = 2 * time.Minute
)

type mutation struct {
	Name        string
	Pattern     string // must occur exactly once in ws/ws.go
	Replacement string
	Invariant   string // what the mutant's survival would mean
	Equivalent  bool   // true: behaviorally indistinguishable, by design
}

type result struct {
	mut    mutation
	status string // statusKilled, statusSurvived, statusUncompilable
	detail string
}

func main() {
	workers := flag.Int("workers", runtime.NumCPU(), "parallel scratch-module test runs")
	only := flag.String("only", "", "run only mutations whose name matches this regexp")
	verbose := flag.Bool("v", false, "print each mutant as it finishes")
	flag.Parse()

	checkEnvironment()

	source, err := os.ReadFile("ws/ws.go")
	if err != nil {
		log.Fatalf("read ws/ws.go: %v", err)
	}

	report(runMutants(selectMutants(string(source), *only), *workers, *verbose))
}

// checkEnvironment verifies that the local toolchain can load the module
// before a single mutant runs. testMutant pins GOTOOLCHAIN=local for each
// scratch run, so the probe does the same: a toolchain chain where the
// gate itself runs on one toolchain while the local one is older than
// go.mod's go directive would otherwise classify every mutant as
// UNCOMPILABLE and let the gate pass while verifying nothing. A broken
// environment fails loudly here; the command is trivial (package metadata
// only) and its output is the diagnostic.
func checkEnvironment() {
	ctx, cancel := context.WithTimeout(context.Background(), envProbeGrace)
	cmd := exec.CommandContext(ctx, "go", "list", "./ws")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	combined, err := cmd.CombinedOutput()
	cancel()
	if err != nil {
		log.Fatalf("environment check failed — no mutant can run, so the gate would pass vacuously:\n%s",
			strings.TrimSpace(string(combined)))
	}
}

// selectMutants filters the registry by the -only regexp and validates
// every surviving pattern against the source: each must occur exactly
// once, or the registry entry is stale (the same discipline as
// cmd/mcdc's expr check). An empty regexp matches every name.
func selectMutants(source, only string) []mutation {
	regex, err := regexp.Compile(only)
	if err != nil {
		log.Fatalf("-only: %v", err)
	}
	selected := make([]mutation, 0, len(mutations()))
	for _, mut := range mutations() {
		if !regex.MatchString(mut.Name) {
			continue
		}
		if count := strings.Count(source, mut.Pattern); count != 1 {
			log.Fatalf("mutation %q: pattern occurs %d times, want exactly 1:\n%s",
				mut.Name, count, mut.Pattern)
		}
		selected = append(selected, mut)
	}
	if len(selected) == 0 {
		log.Fatalf("no mutations match -only %q", only)
	}

	return selected
}

// runMutants tests every selected mutant in a parallel pool of scratch
// modules and returns the results in completion order, printing each row
// as it finishes when verbose.
func runMutants(selected []mutation, workers int, verbose bool) []result {
	jobs := make(chan mutation)
	results := make(chan result)
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			for mut := range jobs {
				results <- testMutant(mut)
			}
		})
	}
	go func() {
		for _, mut := range selected {
			jobs <- mut
		}
		close(jobs)
		group.Wait()
		close(results)
	}()

	finished := make([]result, 0, len(selected))
	for res := range results {
		finished = append(finished, res)
		if verbose {
			printRow(res)
		}
	}

	return finished
}

// report prints the ranked verdict table and the summary, and exits
// non-zero when a non-equivalent mutant survived: the suite would not
// have caught that bug.
func report(finished []result) {
	sort.Slice(finished, func(lhs, rhs int) bool {
		rankL, rankR := rank(finished[lhs]), rank(finished[rhs])
		if rankL != rankR {
			return rankL < rankR
		}

		return finished[lhs].mut.Name < finished[rhs].mut.Name
	})

	killed, survived, gaps := 0, 0, 0
	for _, res := range finished {
		printRow(res)
		switch res.status {
		case statusKilled:
			killed++
		case statusSurvived:
			survived++
			if !res.mut.Equivalent {
				gaps++
			}
		}
	}
	uncompilable := len(finished) - killed - survived
	outf("\nmuts: %d total, %d killed, %d survived (%d equivalent), %d uncompilable\n",
		len(finished), killed, survived, survived-gaps, uncompilable)
	if len(finished) > 0 && uncompilable == len(finished) {
		outf("status: FAIL — every mutant is uncompilable; the gate verified nothing " +
			"(broken environment or a fully stale registry)\n")
		os.Exit(1)
	}
	if gaps > 0 {
		outf("status: FAIL — %d surviving non-equivalent mutants are test gaps\n", gaps)
		os.Exit(1)
	}

	outf("status: OK — every non-equivalent mutant is killed by the suite\n")
}

// outf formats to stdout, treating a broken stdout as fatal.
func outf(format string, args ...any) {
	_, err := fmt.Fprintf(os.Stdout, format, args...)
	if err != nil {
		log.Fatalf("write to stdout: %v", err)
	}
}

func rank(res result) int {
	switch {
	case res.status == statusSurvived && !res.mut.Equivalent:
		return rankGap
	case res.status == statusSurvived:
		return rankEquivalent
	case res.status == statusUncompilable:
		return rankUncompilable
	default:
		return rankKilled
	}
}

func printRow(res result) {
	line := fmt.Sprintf("%-12s %-32s %s", res.status, res.mut.Name, res.mut.Invariant)
	if res.detail != "" {
		line += "  [" + res.detail + "]"
	}

	outf("%s\n", line)
}

// testMutant builds the scratch module, applies the rewrite, and runs the
// full ws test suite against it.
func testMutant(mut mutation) result {
	dir, err := os.MkdirTemp("", "mut-")
	if err != nil {
		return result{mut: mut, status: statusUncompilable, detail: err.Error()}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	pkgDir := filepath.Join(dir, "ws")
	err = copyScratchModule(dir, pkgDir, mut)
	if err != nil {
		return result{mut: mut, status: statusUncompilable, detail: err.Error()}
	}

	ctx, cancel := context.WithTimeout(context.Background(), mutantRunGrace)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-timeout=4m", ".")
	cmd.Dir = pkgDir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	combined, err := cmd.CombinedOutput()
	if err == nil {
		return result{mut: mut, status: statusSurvived}
	}
	// A test failure (or a panic/timeout in the test binary) means the
	// mutant broke something observable: killed. Anything else — a compile
	// failure in the mutated source — is discarded from the verdict.
	output := string(combined)
	if strings.Contains(output, "--- FAIL") || strings.Contains(output, "panic") ||
		strings.Contains(output, "test timed out") {
		return result{mut: mut, status: statusKilled}
	}

	return result{mut: mut, status: statusUncompilable, detail: firstNonEmptyLine(output)}
}

// copyScratchModule copies the ws package into pkgDir (writing the module
// file into its parent), applying mut's rewrite to ws.go. The module path
// is the real one: the external ws_test package files import it, and the
// scratch copy must compile them unmodified.
func copyScratchModule(dir, pkgDir string, mut mutation) error {
	err := os.MkdirAll(pkgDir, scratchDirPerm)
	if err != nil {
		return fmt.Errorf("scratch module directory: %w", err)
	}
	goMod := "module github.com/jodoherty/websocket-go\n\ngo 1.25.0\n"
	err = os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), scratchFilePerm)
	if err != nil {
		return fmt.Errorf("scratch module file: %w", err)
	}
	entries, err := os.ReadDir("ws")
	if err != nil {
		return fmt.Errorf("read the ws package: %w", err)
	}
	for _, entry := range entries {
		err = copyOneSource(pkgDir, entry, mut)
		if err != nil {
			return err
		}
	}

	return nil
}

// copyOneSource copies one .go file from ws/ into pkgDir, applying mut's
// rewrite when the file is ws.go. Non-Go entries are skipped. The name is
// reduced to its base and checked for identity with the directory entry
// before any join, so no path component can reach the file APIs.
func copyOneSource(pkgDir string, entry fs.DirEntry, mut mutation) error {
	name := filepath.Base(entry.Name())
	if name != entry.Name() || entry.IsDir() || !strings.HasSuffix(name, ".go") {
		return nil
	}
	// #nosec G304 — name is a checked plain file name from the repo's own ws/ directory
	data, err := os.ReadFile(filepath.Join("ws", name))
	if err != nil {
		return fmt.Errorf("copy %s: %w", name, err)
	}
	if name == "ws.go" {
		data = []byte(strings.Replace(string(data), mut.Pattern, mut.Replacement, 1))
	}
	// #nosec G703 — pkgDir is the fresh scratch directory; name is checked plain
	err = os.WriteFile(filepath.Join(pkgDir, name), data, scratchFilePerm)
	if err != nil {
		return fmt.Errorf("copy %s to the scratch module: %w", name, err)
	}

	return nil
}

func firstNonEmptyLine(out string) string {
	for line := range strings.SplitSeq(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}

	return ""
}
