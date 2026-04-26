package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGoSumFile_dedupesGoModLine(t *testing.T) {
	dir := t.TempDir()
	sumPath := filepath.Join(dir, "go.sum")
	content := `golang.org/x/text v0.3.0 h1:abc
golang.org/x/text v0.3.0/go.mod h1:def
`
	if err := os.WriteFile(sumPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parseGoSumFile(sumPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 unique module, got %d: %#v", len(got), got)
	}
	want := []string{"golang.org/x/text", "v0.3.0"}
	if got[0].Path != want[0] || got[0].Version != want[1] {
		t.Fatalf("got %#v, want path=%q version=%q", got[0], want[0], want[1])
	}
}

func TestParseGoSumFile_skipsEmptyAndComment(t *testing.T) {
	dir := t.TempDir()
	sumPath := filepath.Join(dir, "go.sum")
	content := `
# comment

rsc.io/quote v1.5.2 h1:zzz
`
	if err := os.WriteFile(sumPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseGoSumFile(sumPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "rsc.io/quote" || got[0].Version != "v1.5.2" {
		t.Fatalf("got %#v", got)
	}
}

func TestParseGoVendorFile_skipsComments(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "modules.txt")
	content := `# golang.org/x/text v0.3.0
## explicit
golang.org/x/text v0.3.0
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseGoVendorFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "golang.org/x/text" || got[0].Version != "v0.3.0" {
		t.Fatalf("got %#v", got)
	}
}

func TestParseGoSumFile_rejectsNonH1(t *testing.T) {
	dir := t.TempDir()
	sumPath := filepath.Join(dir, "go.sum")
	content := `golang.org/x/text v0.3.0 sha256:abc
`
	if err := os.WriteFile(sumPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := parseGoSumFile(sumPath)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hash must start with h1:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseGoSumFile_rejectsShortLine(t *testing.T) {
	dir := t.TempDir()
	sumPath := filepath.Join(dir, "go.sum")
	content := `golang.org/x/text v0.3.0
`
	if err := os.WriteFile(sumPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := parseGoSumFile(sumPath)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "expected module, version, and hash") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseGoVendorFile_rejectsShortLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "modules.txt")
	content := `golang.org/x/text
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := parseGoVendorFile(p)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "expected module path and version") {
		t.Fatalf("unexpected error: %v", err)
	}
}
