// Command mcdc audits MC/DC (Modified Condition/Decision Coverage,
// DO-178C / ISO 26262) traceability for a package whose tests are
// written to prove the criterion.
//
// MC/DC requires that, for every decision with two or more conditions,
// each condition independently affect the decision's outcome: a pair of
// executions in which only that condition changes, every other
// condition holds, and the decision flips.
//
// Go's coverage profiles are basic-block-granular and record no
// condition values, so the pairs cannot be observed at runtime without
// instrumenting the source (which would also break short-circuit
// semantics). This tool therefore audits the static side of the
// criterion:
//
//  1. It enumerates every compound decision in the package — each &&/||
//     expression with two or more atomic conditions, nested ones
//     included — so a newly written compound condition fails the gate
//     immediately.
//  2. From the boolean structure it computes, for each condition, the
//     requirement of at least one independence pair: two truth
//     assignments differing only in that condition, with the decision
//     flipping between them. Every entry in the registry (registry.go)
//     is re-checked against the actual expression, so a changed
//     expression invalidates its traces.
//  3. Every required pair must be traced to an existing test function
//     and subtest in the package's test files.
//
// The tests themselves are responsible for the runtime half: each
// subtest asserts the observable outcome that only the traced decision
// flip produces (a distinct error, a distinct frame, a distinct status).
// If a pair stops being exercised, its assertion fails.
//
// Usage:
//
//	go run ./cmd/mcdc <package-dir>
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CLI conventions.
const (
	minArgs     = 2
	exitBadArgs = 2
	exitFailure = 1
	// A decision with fewer conditions than this is branch-level.
	minCompoundConds = 2
	// A package rarely has more compound decisions than this; just an
	// initial capacity hint.
	initialDecisionCap = 16
)

// decision is one &&/|| expression with two or more atomic conditions.
type decision struct {
	file  string
	line  int
	expr  string
	conds []string
	node  ast.Node
}

// status is the audit result for one decision (or one stale registry
// entry, with an empty decision).
type status struct {
	decision

	entry    *decisionTrace
	traced   []bool
	problems []string
	stale    bool
}

func main() {
	if len(os.Args) < minArgs {
		printUsage()

		os.Exit(exitBadArgs)
	}

	fset := token.NewFileSet()
	files, err := parsePackages(fset, os.Args[1])
	if err != nil {
		fail(err)
	}

	decisions := make([]decision, 0, initialDecisionCap)
	singleCondition := 0
	for _, file := range files {
		decisions = append(decisions, collectDecisions(fset, file)...)
		singleCondition += countSingleCondition(file)
	}

	results, staleEntries := verify(decisions, testIndex(os.Args[1]))
	reportErr := report(results, staleEntries, singleCondition)
	if reportErr != nil {
		fail(reportErr)
	}
	if hasProblems(results) || hasProblems(staleEntries) {
		os.Exit(exitFailure)
	}
}

func printUsage() {
	_, _ = fmt.Fprintln(os.Stderr, "usage: mcdc <package-dir>")
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

// collectDecisions returns every compound decision in the file, in
// source order.
func collectDecisions(fset *token.FileSet, file *ast.File) []decision {
	name := filepath.Base(fset.File(file.Pos()).Name())
	var decisions []decision
	ast.Inspect(file, func(node ast.Node) bool {
		bin, isBoolOp := asBoolOp(node)
		if !isBoolOp {
			return true
		}
		conds := atomicLeaves(fset, bin)
		if len(conds) < minCompoundConds {
			return true
		}
		decisions = append(decisions, decision{
			file:  name,
			line:  fset.Position(bin.Pos()).Line,
			expr:  normalized(fset, bin),
			conds: conds,
			node:  bin,
		})

		return true
	})

	return decisions
}

// countSingleCondition counts if/for conditions with exactly one
// condition: branch-level decisions with no MC/DC requirement.
func countSingleCondition(file *ast.File) int {
	count := 0
	ast.Inspect(file, func(node ast.Node) bool {
		var cond ast.Expr
		switch stmt := node.(type) {
		case *ast.IfStmt:
			cond = stmt.Cond
		case *ast.ForStmt:
			cond = stmt.Cond
		default:

			return true
		}
		if cond != nil && !hasBoolOp(cond) {
			count++
		}

		return true
	})

	return count
}

// asBoolOp reports whether node is a &&/|| expression.
func asBoolOp(node ast.Node) (*ast.BinaryExpr, bool) {
	bin, ok := node.(*ast.BinaryExpr)
	if !ok || (bin.Op != token.LAND && bin.Op != token.LOR) {
		return nil, false
	}

	return bin, true
}

// atomicLeaves returns the decision's conditions — the maximal
// sub-expressions that are not themselves &&/|| — in source order.
func atomicLeaves(fset *token.FileSet, node ast.Node) []string {
	node = unwrap(node)
	if bin, isBoolOp := asBoolOp(node); isBoolOp {
		leaves := atomicLeaves(fset, bin.X)

		return append(leaves, atomicLeaves(fset, bin.Y)...)
	}

	return []string{normalized(fset, node)}
}

// hasBoolOp reports whether the expression contains && or ||.
func hasBoolOp(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(child ast.Node) bool {
		if _, isBoolOp := asBoolOp(child); isBoolOp {
			found = true

			return false
		}

		return true
	})

	return found
}

// unwrap strips one level of parentheses.
func unwrap(node ast.Node) ast.Node {
	for paren, ok := node.(*ast.ParenExpr); ok; paren, ok = node.(*ast.ParenExpr) {
		node = paren.X
	}

	return node
}

// truth evaluates the decision for a full condition assignment.
func truth(dec decision, vec []bool) bool {
	idx := 0
	var eval func(node ast.Node) bool
	eval = func(node ast.Node) bool {
		node = unwrap(node)
		if bin, isBoolOp := asBoolOp(node); isBoolOp {
			left := eval(bin.X)
			right := eval(bin.Y)
			if bin.Op == token.LAND {
				return left && right
			}

			return left || right
		}
		value := vec[idx]
		idx++

		return value
	}

	return eval(dec.node)
}

// normalized prints the node with whitespace collapsed, so the registry
// can quote expressions without depending on source formatting.
func normalized(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	fprintErr := printer.Fprint(&buf, fset, node)
	if fprintErr != nil {
		fail(fmt.Errorf("print expression: %w", fprintErr))
	}

	return strings.Join(strings.Fields(buf.String()), " ")
}

// testIndex maps every Test function to its t.Run subtest names.
func testIndex(dir string) map[string]map[string]bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail(fmt.Errorf("read test directory: %w", err))
	}
	index := make(map[string]map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, 0)
		if parseErr != nil {
			fail(fmt.Errorf("parse %s: %w", entry.Name(), parseErr))
		}
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(funcDecl.Name.Name, "Test") {
				continue
			}
			index[funcDecl.Name.Name] = collectSubtests(funcDecl)
		}
	}

	return index
}

// collectSubtests returns the t.Run subtest names of one test function.
func collectSubtests(funcDecl *ast.FuncDecl) map[string]bool {
	subtests := make(map[string]bool)
	ast.Inspect(funcDecl, func(node ast.Node) bool {
		name, isSubtest := subtestName(node)
		if isSubtest {
			subtests[name] = true
		}

		return true
	})

	return subtests
}

// subtestName reports whether node is a t.Run("name") call, returning the
// name.
func subtestName(node ast.Node) (string, bool) {
	call, isCall := node.(*ast.CallExpr)
	if !isCall || len(call.Args) == 0 {
		return "", false
	}
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name != "Run" {
		return "", false
	}
	recv, isIdent := sel.X.(*ast.Ident)
	if !isIdent || recv.Name != "t" {
		return "", false
	}
	lit, isLit := call.Args[0].(*ast.BasicLit)
	if !isLit || lit.Kind != token.STRING {
		return "", false
	}

	return lit.Value[1 : len(lit.Value)-1], true
}

// verify joins the source decisions with the registry and checks every
// requirement: a trace per condition, a valid pair per trace, an
// existing test per trace. It returns the per-decision statuses and,
// separately, the registry entries that no longer match any source
// decision.
func verify(decisions []decision, tests map[string]map[string]bool) ([]status, []status) {
	results := make([]status, len(decisions))
	var stale []status
	remaining := make(map[string][]int)
	for i, dec := range decisions {
		results[i] = status{
			decision: dec,
			traced:   make([]bool, len(dec.conds)),
		}
		remaining[dec.expr] = append(remaining[dec.expr], i)
	}

	for _, entry := range registry() {
		candidates, ok := remaining[entry.expr]
		if !ok || len(candidates) == 0 {
			stale = append(stale, status{
				decision: decision{expr: entry.expr},
				stale:    true,
				problems: []string{"registry entry matches no decision in the source"},
			})

			continue
		}
		res := &results[candidates[0]]
		remaining[entry.expr] = candidates[1:]
		res.entry = &entry
		res.problems = append(res.problems, checkConditions(res, entry)...)
		res.problems = append(res.problems, checkPairs(res, entry, tests)...)
	}

	for i := range results {
		res := &results[i]
		if res.entry == nil {
			res.problems = append(res.problems, "decision is not traced in the registry")
		}
	}

	return results, stale
}

// checkConditions verifies the registry lists the decision's actual
// conditions, in order.
func checkConditions(res *status, entry decisionTrace) []string {
	if len(entry.conditions) != len(res.conds) {
		return []string{strconv.Itoa(len(entry.conditions)) + " conditions registered, " +
			strconv.Itoa(len(res.conds)) + " in the source"}
	}
	for i, cond := range entry.conditions {
		if cond != res.conds[i] {
			return []string{"condition " + strconv.Itoa(i) + " registered as " +
				cond + ", source has " + res.conds[i]}
		}
	}

	return nil
}

// checkPairs verifies each registry pair is a genuine independence pair
// for the traced condition of the current expression, and that the
// proving test (and subtest) exists.
func checkPairs(res *status, entry decisionTrace, tests map[string]map[string]bool) []string {
	var problems []string
	for _, pair := range entry.pairs {
		problem := pairProblem(res, pair, tests)
		if problem == "" {
			res.traced[pair.condition] = true

			continue
		}
		problems = append(problems, pairSummary(pair)+": "+problem)
	}
	for i, traced := range res.traced {
		if !traced {
			problems = append(problems, "condition "+strconv.Itoa(i)+" ("+res.conds[i]+
				") has no traced independence pair")
		}
	}

	return problems
}

// pairProblem reports why the pair is not a valid, traced independence
// pair for its condition under the current expression: the assignments
// must differ only in that condition, the decision must flip between
// them, and the proving test (and subtest) must exist.
func pairProblem(res *status, pair pairTrace, tests map[string]map[string]bool) string {
	condCount := len(res.conds)
	if len(pair.from) != condCount || len(pair.to) != condCount ||
		pair.condition < 0 || pair.condition >= condCount {
		return "vector length " + strconv.Itoa(len(pair.from)) +
			" does not match the " + strconv.Itoa(condCount) + " conditions"
	}
	differs := false
	for i := range pair.from {
		if pair.from[i] == pair.to[i] {
			continue
		}
		if i != pair.condition {
			return "assignments differ at condition " + strconv.Itoa(i) +
				", not the traced condition " + strconv.Itoa(pair.condition)
		}
		differs = true
	}
	if !differs {
		return "assignments are identical"
	}
	if truth(res.decision, pair.from) == truth(res.decision, pair.to) {
		return "the decision does not flip between the assignments"
	}

	return testExists(pair, tests)
}

// testExists verifies the proving test and subtest are in the suite.
func testExists(pair pairTrace, tests map[string]map[string]bool) string {
	subtests, ok := tests[pair.test]
	if !ok {
		return "test " + pair.test + " does not exist"
	}
	if pair.subtest != "" && !subtests[pair.subtest] {
		return "subtest " + pair.subtest + " does not exist in " + pair.test
	}

	return ""
}

// pairSummary names a registry entry in the report.
func pairSummary(pair pairTrace) string {
	return pair.test + "/" + pair.subtest + " (condition " +
		strconv.Itoa(pair.condition) + ": " + assignString(pair.from) + " vs " +
		assignString(pair.to) + ")"
}

// assignString renders a truth assignment, one digit per condition.
func assignString(vec []bool) string {
	var builder strings.Builder
	for _, value := range vec {
		if value {
			builder.WriteString("1")
		} else {
			builder.WriteString("0")
		}
	}

	return builder.String()
}

// report writes the audit to stdout.
func report(results []status, stale []status, singleCondition int) error {
	var text strings.Builder
	_, _ = fmt.Fprintf(&text, "MC/DC audit: %d compound decisions\n", len(results))
	traced := 0
	for _, res := range results {
		pairs := 0
		for _, hasPair := range res.traced {
			if hasPair {
				pairs++
			}
		}
		traced += pairs
		_, _ = fmt.Fprintf(&text, "  %s:%d  %s  (%d/%d conditions traced)\n",
			res.file, res.line, res.expr, pairs, len(res.conds))
		for _, problem := range res.problems {
			_, _ = fmt.Fprintf(&text, "    problem: %s\n", problem)
		}
	}
	for _, res := range stale {
		_, _ = fmt.Fprintf(&text, "  registry: %s\n", res.expr)
		_, _ = fmt.Fprintf(&text, "    problem: %s\n", res.problems[0])
	}
	_, _ = fmt.Fprintf(&text, "  %d single-condition decisions (branch-level, no MC/DC requirement)\n", singleCondition)
	if hasProblems(results) || hasProblems(stale) {
		_, _ = fmt.Fprintln(&text, "status: FAIL")
	} else {
		_, _ = fmt.Fprintf(&text, "status: OK (%d required pairs traced to existing tests)\n", traced)
	}
	_, err := os.Stdout.WriteString(text.String())
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	return nil
}

func hasProblems(statuses []status) bool {
	for _, res := range statuses {
		if len(res.problems) > 0 {
			return true
		}
	}

	return false
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "mcdc:", err)
	os.Exit(exitFailure)
}
