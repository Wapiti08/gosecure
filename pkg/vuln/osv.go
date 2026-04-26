package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Wapiti08/gosecure/pkg/scanner"
)

// OSVVulnChecker queries a vulnerability API (OSV-compatible) for a module@version.
//
// It uses the OSV Query API:
// - POST {BaseURL}/v1/query
// - Body: {"package":{"ecosystem":"Go","name":"<module>"},"version":"<version>"}
type OSVVulnChecker struct {
	Client  *http.Client
	BaseURL string
}

type osvQueryRequest struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}


type osvResponse struct {
	Vulns []struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
		Details string `json:"details"`
		Affected []struct {
			Ranges []struct {
				Events []struct {
					Fixed string `json:"fixed"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	} `json:"vulns"`
}

func (c *OSVVulnChecker) Check(ctx context.Context, module, version string) ([]scanner.Vulnerability, error) {
	// check blank situation
	if c == nil {
		return nil, errors.New("OSVVulnChecker: nil receiver")
	}
	if strings.TrimSpace(module) == "" || strings.TrimSpace(version) == "" {
		return nil, fmt.Errorf("OSVVulnChecker: module and version are required (module=%q version=%q)", module, version)
	}

	// create a client
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	// check baseurl
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.osv.dev"
	}
	// check whether url is valid and parse it to right format
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("OSVVulnChecker: invalid BaseURL %q: %w", c.BaseURL, err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/query"

	
	var reqBody osvQueryRequest
	reqBody.Package.Ecosystem = "Go"
	reqBody.Package.Name = module
	reqBody.Version = version

	// v1/query interface require JSON request body
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("OSVVulnChecker: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("OSVVulnChecker: create request: %w", err)
	}
	// set the header
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSVVulnChecker: request failed: %w", err)
	}
	// close body after finishing request and getting response
	defer resp.Body.Close()
	// check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("OSVVulnChecker: non-2xx response %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	// define parsed response format
	var parsed osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("OSVVulnChecker: decode response: %w", err)
	}

	out := make([]scanner.Vulnerability, 0, len(parsed.Vulns))
	for _, v := range parsed.Vulns {
		summary := v.Summary
		if summary == "" {
			summary = v.Details
		}

		fixedSet := make(map[string]struct{})
		for _, a := range v.Affected {
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						fixedSet[e.Fixed] = struct{}{}
					}
				}
			}
		}
		fixed := make([]string, 0, len(fixedSet))
		for fv := range fixedSet {
			fixed = append(fixed, fv)
		}

		out = append(out, scanner.Vulnerability{
			ID:       v.ID,
			Package:  module,
			Version:  version,
			Severity: "", // TODO: map OSV severity/CVSS to your severity labels
			Summary:  summary,
			Fixed:    fixed,
		})
	}

	return out, nil
}
