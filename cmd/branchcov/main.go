// Command branchcov measures branch coverage — the metric the standard
// tooling does not provide (go test -cover counts statements only).
//
// Usage:
//
//	go test -covermode=count -coverprofile=bc.out <pkg>
//	go run ./cmd/branchcov [-min <percent>] <package-dir> bc.out [more.out ...]
//
// With -min, the command exits non-zero when the merged branch coverage is
// below the given percentage, so the Makefile gate can enforce a floor
// instead of merely reporting. Without it the report is informational.
//
// It walks the package's AST and, for every branch point, reports whether
// each outcome was taken, using the basic-block counts from the profile:
//
//   - if:      if-true (the body block was entered) and
//     if-false (the header block was counted more times than the body —
//     the header counts every condition evaluation)
//   - for:     for-entry (the header block was entered; it counts once
//     per loop entry, not per condition evaluation) and
//     for-exit (the body was entered at least once, which implies the
//     loop terminated at least once)
//   - switch:  one outcome per case clause, plus switch-no-match
//     (header evaluations exceed case entries)
//   - select:  one outcome per case clause
//
// Multiple profiles may be given (e.g. one from the unit suite and one
// from the e2e suite with -coverpkg); a branch counts as covered if any
// profile shows it was taken. Test files are excluded: the profile does
// not instrument them (they drive the measurement).
//
// Two genuine limitations, shared with every tool that reads the
// standard profile: operand-level short-circuiting inside a boolean
// expression (a && b) is a single basic block, so which operand was
// skipped is not visible; and break-versus-condition-false loop exits are
// merged — for-exit reports that the loop terminated, not how.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Outcome labels in the report.
const (
	labelIfTrue        = "if-true"
	labelIfFalse       = "if-false"
	labelForEntry      = "for-entry"
	labelForExit       = "for-exit"
	labelCase          = "case"
	labelSwitchNoMatch = "switch-no-match"
)

// Tunables and CLI conventions.
const (
	minArgs     = 3
	exitBadArgs = 2
	exitFailure = 1
	pctPerWhole = 100.0
	// A profile line is "file:start.start,end.end numBlocks count".
	profileFields = 3
	splitN        = 2
	// Scales a (line, col) pair into a single ordering integer; columns
	// are always far below lineScale, so line order dominates.
	lineScale = 100000
)

// outcome is one direction of one branch point.
type outcome struct {
	file    string
	what    string // one of the label* constants
	line    int
	covered bool
}

// block is one basic block from a count-mode coverage profile.
type block struct {
	file      string
	startLine int
	startCol  int
	endLine   int
	endCol    int
	count     int
}

func main() {
	minPct := flag.Float64("min", 0, "fail if branch coverage is below this percentage (default 0 = report only)")
	flag.Parse()
	if flag.NArg() < minArgs {
		printUsage()

		os.Exit(exitBadArgs)
	}

	fset := token.NewFileSet()
	files, err := parsePackages(fset, flag.Arg(0))
	if err != nil {
		fail(err)
	}

	merged, err := mergeProfiles(flag.Args()[1:])
	if err != nil {
		fail(err)
	}

	total, covered, missed := measure(fset, files, mergedBlocks(merged))
	reportErr := report(total, covered, missed)
	if reportErr != nil {
		fail(reportErr)
	}
	if *minPct > 0 && total > 0 {
		percent := pctPerWhole * float64(covered) / float64(total)
		if percent < *minPct {
			fmt.Fprintf(os.Stderr, "branchcov: coverage %.1f%% is below the %.1f%% minimum\n", percent, *minPct)
			os.Exit(exitFailure)
		}
	}
}

func printUsage() {
	_, _ = fmt.Fprintln(os.Stderr, "usage: branchcov [-min <percent>] <package-dir> <count-profile> [more ...]")
}

// parsePackages parses every non-test Go file in dir.
func parsePackages(fset *token.FileSet, dir string) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read package directory: %w", err)
	}
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if parseErr != nil {
			return nil, fmt.Errorf("parse %s: %w", name, parseErr)
		}
		files = append(files, file)
	}

	return files, nil
}

// mergeProfiles reads each count-mode profile and keeps, for every basic
// block, the maximum count across profiles: a block counts as taken if any
// profile took it.
func mergeProfiles(paths []string) (map[string]block, error) {
	merged := make(map[string]block)
	for _, path := range paths {
		blocks, err := loadProfile(path)
		if err != nil {
			return nil, err
		}
		for _, blk := range blocks {
			key := blockKey(blk)
			prev, ok := merged[key]
			if !ok || blk.count > prev.count {
				merged[key] = blk
			}
		}
	}

	return merged, nil
}

func mergedBlocks(merged map[string]block) []block {
	blocks := make([]block, 0, len(merged))
	for _, blk := range merged {
		blocks = append(blocks, blk)
	}

	return blocks
}

// blocksFor selects the blocks that belong to the file named base.
func blocksFor(blocks []block, base string) []block {
	var out []block
	for _, blk := range blocks {
		if filepath.Base(blk.file) == base {
			out = append(out, blk)
		}
	}

	return out
}

// loadProfile parses a count-mode coverage profile.
func loadProfile(path string) ([]block, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is a CLI argument naming the profile to read
	if err != nil {
		return nil, fmt.Errorf("open profile: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	var blocks []block
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blk, ok := parseBlockLine(scanner.Text())
		if ok {
			blocks = append(blocks, blk)
		}
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("read profile: %w", scanner.Err())
	}

	return blocks, nil
}

// parseBlockLine parses one profile line of the form
//
//	file:startLine.startCol,endLine.endCol numBlocks count
func parseBlockLine(line string) (block, bool) {
	if line == "mode: count" || !strings.Contains(line, ":") {
		return block{}, false
	}
	fields := strings.Fields(line)
	if len(fields) != profileFields {
		return block{}, false
	}
	count, err := strconv.Atoi(fields[2])
	if err != nil {
		return block{}, false
	}
	ref := fields[0]
	filePath, boundsPart, found := strings.Cut(ref, ":")
	if !found {
		return block{}, false
	}
	bounds := strings.SplitN(boundsPart, ",", splitN)
	if len(bounds) != splitN {
		return block{}, false
	}
	startLine, startCol, ok := parseLineCol(bounds[0])
	if !ok {
		return block{}, false
	}
	endLine, endCol, ok := parseLineCol(bounds[1])
	if !ok {
		return block{}, false
	}
	blk := block{
		file: filePath, count: count,
		startLine: startLine, startCol: startCol,
		endLine: endLine, endCol: endCol,
	}

	return blk, true
}

// parseLineCol splits "line.col" into its parts.
func parseLineCol(text string) (int, int, bool) {
	parts := strings.SplitN(text, ".", splitN)
	if len(parts) != splitN {
		return 0, 0, false
	}
	lineNum, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	colNum, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}

	return lineNum, colNum, true
}

// measure produces the report data for every branch point in files.
func measure(fset *token.FileSet, files []*ast.File, blocks []block) (int, int, []outcome) {
	var total, covered int
	var missed []outcome
	for _, file := range files {
		name := filepath.Base(fset.File(file.Pos()).Name())
		for _, result := range measureFile(fset, file, blocksFor(blocks, name)) {
			result.file = name
			total++
			if result.covered {
				covered++
			} else {
				missed = append(missed, result)
			}
		}
	}

	return total, covered, missed
}

// measureFile walks one file and produces one outcome per branch direction.
func measureFile(fset *token.FileSet, file *ast.File, blocks []block) []outcome {
	var out []outcome
	ast.Inspect(file, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.IfStmt:
			cond := countAt(fset, blocks, stmt.If)
			body := bodyCount(fset, blocks, stmt.Body)
			out = append(out,
				outcome{what: labelIfTrue, line: lineAt(fset, stmt.Body.Pos()), covered: body > 0},
				outcome{what: labelIfFalse, line: lineAt(fset, stmt.If), covered: cond > body})
		case *ast.ForStmt:
			header := countAt(fset, blocks, stmt.For)
			body := bodyCount(fset, blocks, stmt.Body)
			// The exit outcome is a false evaluation of the condition, which
			// count-mode proves only as a condition evaluation that did not
			// lead into the body (header > body). Body execution alone does
			// not prove it: a body that returns, breaks, or otherwise exits
			// never re-evaluates the condition, so a loop that always leaves
			// through the body has header == body and no proven exit.
			out = append(out,
				outcome{what: labelForEntry, line: lineAt(fset, stmt.For), covered: header > 0},
				outcome{what: labelForExit, line: lineAt(fset, stmt.For), covered: header > body})
		case *ast.SwitchStmt:
			out = append(out, switchOutcomes(fset, blocks, stmt)...)
		case *ast.TypeSwitchStmt:
			out = append(out, typeSwitchOutcomes(fset, blocks, stmt)...)
		case *ast.SelectStmt:
			out = append(out, selectOutcomes(fset, blocks, stmt)...)
		}

		return true
	})

	return out
}

// switchOutcomes covers each case of a value switch, plus no-match when
// there is no default clause (with a default, the default case is that
// outcome).
func switchOutcomes(fset *token.FileSet, blocks []block, stmt *ast.SwitchStmt) []outcome {
	cond := countAt(fset, blocks, stmt.Switch)
	out := make([]outcome, 0, len(stmt.Body.List)+1)
	entries := 0
	for _, clause := range stmt.Body.List {
		count := bodyCount(fset, blocks, clause)
		entries += count
		out = append(out, outcome{
			what: labelCase, line: lineAt(fset, clause.Pos()), covered: count > 0,
		})
	}
	if !hasDefault(stmt.Body.List) {
		out = append(out, outcome{
			what: labelSwitchNoMatch, line: lineAt(fset, stmt.Switch), covered: cond > entries,
		})
	}

	return out
}

// typeSwitchOutcomes covers each case of a type switch, plus no-match when
// there is no default clause.
func typeSwitchOutcomes(fset *token.FileSet, blocks []block, stmt *ast.TypeSwitchStmt) []outcome {
	out := make([]outcome, 0, len(stmt.Body.List)+1)
	entries := 0
	for _, clause := range stmt.Body.List {
		count := bodyCount(fset, blocks, clause)
		entries += count
		out = append(out, outcome{
			what: labelCase, line: lineAt(fset, clause.Pos()), covered: count > 0,
		})
	}
	if !hasDefault(stmt.Body.List) {
		cond := countAt(fset, blocks, stmt.Switch)
		out = append(out, outcome{
			what: labelSwitchNoMatch, line: lineAt(fset, stmt.Switch), covered: cond > entries,
		})
	}

	return out
}

// selectOutcomes covers each case of a select.
func selectOutcomes(fset *token.FileSet, blocks []block, stmt *ast.SelectStmt) []outcome {
	out := make([]outcome, 0, len(stmt.Body.List))
	for _, clause := range stmt.Body.List {
		out = append(out, outcome{
			what: labelCase, line: lineAt(fset, clause.Pos()),
			covered: bodyCount(fset, blocks, clause) > 0,
		})
	}

	return out
}

// report writes the summary and the uncovered outcomes to stdout.
func report(total, covered int, missed []outcome) error {
	var text strings.Builder
	if total == 0 {
		_, _ = fmt.Fprintln(&text, "no branch points found")
	} else {
		percent := pctPerWhole * float64(covered) / float64(total)
		_, _ = fmt.Fprintf(&text, "branch coverage: %d/%d outcomes = %.1f%%\n", covered, total, percent)
		if len(missed) > 0 {
			_, _ = fmt.Fprintf(&text, "%d uncovered outcomes:\n", len(missed))
			for _, result := range missed {
				_, _ = fmt.Fprintf(&text, "  %s:%d  %s\n", result.file, result.line, result.what)
			}
		}
	}
	_, err := os.Stdout.WriteString(text.String())
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	return nil
}

// countAt returns the count of the basic block containing pos: the block
// whose start is at pos, or — since straight-line code before a branch
// joins into the branch's header block — the latest block that contains
// it. Branch headers count every condition evaluation, so the difference
// against the body count is the number of times the branch was not taken.
func countAt(fset *token.FileSet, blocks []block, offset token.Pos) int {
	pos := fset.Position(offset)
	best := -1
	bestCount := 0
	for _, blk := range blocks {
		startBefore := blk.startLine < pos.Line ||
			(blk.startLine == pos.Line && blk.startCol <= pos.Column)
		endAfter := blk.endLine > pos.Line ||
			(blk.endLine == pos.Line && blk.endCol >= pos.Column)
		if !startBefore || !endAfter {
			continue
		}
		order := blk.startLine*lineScale + blk.startCol
		if order > best {
			best = order
			bestCount = blk.count
		}
	}

	return bestCount
}

// bodyCount returns the count of the block that starts at the first
// statement of stmt — where the instrumenter begins a body block.
func bodyCount(fset *token.FileSet, blocks []block, stmt ast.Stmt) int {
	var first ast.Stmt
	switch body := stmt.(type) {
	case *ast.BlockStmt:
		if len(body.List) > 0 {
			first = body.List[0]
		}
	case *ast.CaseClause:
		if len(body.Body) > 0 {
			first = body.Body[0]
		}
	}
	if first == nil {
		return 0
	}

	return countAt(fset, blocks, first.Pos())
}

func lineAt(fset *token.FileSet, offset token.Pos) int {
	return fset.Position(offset).Line
}

// hasDefault reports whether the clause list has a default.
func hasDefault(list []ast.Stmt) bool {
	for _, stmt := range list {
		if clause, ok := stmt.(*ast.CaseClause); ok && clause.List == nil {
			return true
		}
	}

	return false
}

// blockKey identifies a block for cross-profile merging.
func blockKey(blk block) string {
	start := strconv.Itoa(blk.startLine) + "." + strconv.Itoa(blk.startCol)
	end := strconv.Itoa(blk.endLine) + "." + strconv.Itoa(blk.endCol)

	return blk.file + ":" + start + "," + end
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "branchcov:", err)
	os.Exit(exitFailure)
}
