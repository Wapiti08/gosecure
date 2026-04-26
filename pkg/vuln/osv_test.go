package vuln

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOSVVulnChecker_Check_SendsQueryAndParsesResponse(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = b

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"vulns": [
				{
					"id": "GO-2024-0001",
					"summary": "test vuln",
					"affected": [
						{
							"ranges": [
								{ "events": [ { "fixed": "v1.2.3" } ] }
							]
						}
					]
				}
			]
		}`))
	}))
	defer srv.Close()

	c := &OSVVulnChecker{
		Client:  srv.Client(),
		BaseURL: srv.URL,
	}

	vulns, err := c.Check(context.Background(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("method: got %q want %q", gotMethod, http.MethodPost)
	}
	if gotPath != "/v1/query" {
		t.Fatalf("path: got %q want %q", gotPath, "/v1/query")
	}

	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("request body is not json: %v (body=%q)", err, string(gotBody))
	}

	pkg, ok := body["package"].(map[string]any)
	if !ok {
		t.Fatalf("request body missing package: %v", body)
	}
	if pkg["ecosystem"] != "Go" || pkg["name"] != "example.com/mod" {
		t.Fatalf("unexpected package: %v", pkg)
	}
	if body["version"] != "v1.0.0" {
		t.Fatalf("unexpected version: %v", body["version"])
	}

	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %d: %#v", len(vulns), vulns)
	}
	if vulns[0].ID != "GO-2024-0001" {
		t.Fatalf("ID: got %q", vulns[0].ID)
	}
	if vulns[0].Package != "example.com/mod" || vulns[0].Version != "v1.0.0" {
		t.Fatalf("package/version: got %q@%q", vulns[0].Package, vulns[0].Version)
	}
	if !strings.Contains(vulns[0].Summary, "test vuln") {
		t.Fatalf("summary: got %q", vulns[0].Summary)
	}
	if len(vulns[0].Fixed) != 1 || vulns[0].Fixed[0] != "v1.2.3" {
		t.Fatalf("fixed: got %#v", vulns[0].Fixed)
	}
}

