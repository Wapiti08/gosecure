package scanner

import (
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
		"High": 2,
		"Medium": 2,
		"Low": 2,
	}

	result := CountBySeverity(vulns)
	for severity, count := range result {
		if expected[severity] != count {
			t.Errorf("expected %d for %s, got %d", expected[severity], severity, count)
		}
	}
}