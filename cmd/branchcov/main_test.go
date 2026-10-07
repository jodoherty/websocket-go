package main

import (
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestLoopExitNotProvenByBodyCount: this fixture
//
//	func Loop(v bool) {
//		for v {
//			return
//		}
//	}
//
// is called only with Loop(true): the loop condition never evaluates false
// and the body exits via return. Body execution therefore does not prove
// the for-exit outcome, yet a naive counter reports it covered (2/2 =
// 100%). This test reproduces that false positive against a REAL count
// profile and asserts the tool does not claim every outcome proven.
func TestLoopExitNotProvenByBodyCount(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
		if err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("go.mod", "module fixture\n\ngo 1.21\n")
	write("fixture.go", "package fixture\n\n// Loop returns from its body; the condition is never false.\n"+
		"func Loop(v bool) {\n\tfor v {\n\t\treturn\n\t}\n}\n")
	write("fixture_test.go", "package fixture\n\nimport \"testing\"\n\n"+
		"func TestLoop(t *testing.T) { Loop(true) }\n")

	profile := filepath.Join(dir, "cover.out")
	cmd := exec.Command("go", "test", "-count=1", "-covermode=count", //nolint:gosec // fixed args on a temp dir
		"-coverprofile="+profile, ".")
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "GOCACHE="+filepath.Join(dir, ".cache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test on the fixture: %v\n%s", err, out)
	}

	fset := token.NewFileSet()
	files, err := parsePackages(fset, dir)
	if err != nil {
		t.Fatalf("parsePackages: %v", err)
	}
	merged, err := mergeProfiles([]string{profile})
	if err != nil {
		t.Fatalf("mergeProfiles: %v", err)
	}
	total, covered, missed := measure(fset, files, mergedBlocks(merged))
	if covered >= total {
		t.Fatalf("reported %d/%d outcomes covered (100%%), but the loop condition never "+
			"evaluated false and the body exited via return — for-exit is not proven",
			covered, total)
	}
	for _, m := range missed {
		t.Logf("uncovered: %s:%d %s", m.file, m.line, m.what)
	}
}
