package scanner

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestVulnerabilityString(t *testing.T) {
	v := Vulnerability{
		ID: "CVE-2023-1234",
		Package: "golang.org/x/text",
		Version: "v0.3.0",
		Severity: "High",
		Summary: "vulnerability summary",
		Fixed: []string{"v0.3.1", "v0.3.2"},
	}

	expected := "[High] golang.org/x/text@v0.3.0 - CVE-2023-1234"
	if result := v.String(); result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}


func TestCountBySeverity(t *testing.T) {
	vulns := []Vulnerability{
		{Severity: "High"},
		{Severity: "Medium"},
		{Severity: "Low"},
		{Severity: "High"},
		{Severity: "Medium"},
		{Severity: "Low"},
	}

	expected := map[string]int{
		"High":   2,
		"Medium": 2,
		"Low":    2,
	}

	result := CountBySeverity(vulns)
	for severity, want := range expected {
		if got := result[severity]; got != want {
			t.Fatalf("severity %s: got %d, want %d", severity, got, want)
		}
	}

	if len(result) != len(expected) {
		t.Fatalf("result map length: got %d, want %d (result=%v)", len(result), len(expected), result)
	}
}

type fakeScanner struct {
	support bool
	vulns   []Vulnerability
	err     error
	called  int
}

func (f *fakeScanner) Support(path string) bool { return f.support }
func (f *fakeScanner) Scan(ctx context.Context, path string) ([]Vulnerability, error) {
	f.called++
	return f.vulns, f.err
}

func TestScanProject_SkipUnsupported(t *testing.T) {
	ctx := context.Background()

	s1 := &fakeScanner{
		support: false,
		vulns:   []Vulnerability{{ID: "SHOULD_NOT_BE_INCLUDED"}},
	}
	s2 := &fakeScanner{
		support: true,
		vulns:   []Vulnerability{{ID: "OK"}},
	}

	got, err := ScanProject(ctx, "/tmp/project", []Scanner{s1, s2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s1.called != 0 {
		t.Fatalf("unsupported scanner was called %d times, want 0", s1.called)
	}
	if s2.called != 1 {
		t.Fatalf("supported scanner was called %d times, want 1", s2.called)
	}

	want := []Vulnerability{{ID: "OK"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanProject() vulns mismatch: got %#v, want %#v", got, want)
	}
}

func TestScanProject_MergeResults(t *testing.T) {
	ctx := context.Background()

	s1 := &fakeScanner{
		support: true,
		vulns:   []Vulnerability{{ID: "A"}, {ID: "B"}},
	}
	s2 := &fakeScanner{
		support: true,
		vulns:   []Vulnerability{{ID: "C"}},
	}

	got, err := ScanProject(ctx, "/tmp/project", []Scanner{s1, s2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []Vulnerability{{ID: "A"}, {ID: "B"}, {ID: "C"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanProject() vulns mismatch: got %#v, want %#v", got, want)
	}
}

func TestScanProject_ReturnOnFirstError(t *testing.T) {
	ctx := context.Background()

	s1 := &fakeScanner{
		support: true,
		vulns:   []Vulnerability{{ID: "PARTIAL"}},
	}
	s2 := &fakeScanner{
		support: true,
		err:     errors.New("boom"),
	}
	s3 := &fakeScanner{
		support: true,
		vulns:   []Vulnerability{{ID: "SHOULD_NOT_RUN"}},
	}

	got, err := ScanProject(ctx, "/tmp/project", []Scanner{s1, s2, s3})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	want := []Vulnerability{{ID: "PARTIAL"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanProject() vulns mismatch: got %#v, want %#v", got, want)
	}

	if s1.called != 1 || s2.called != 1 {
		t.Fatalf("call counts: s1=%d s2=%d, want 1 and 1", s1.called, s2.called)
	}
	if s3.called != 0 {
		t.Fatalf("scanner after error was called %d times, want 0", s3.called)
	}
}