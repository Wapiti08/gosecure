package vuln

import (
	"context"
	"errors"
	"net/http"

	"github.com/Wapiti08/gosecure/pkg/scanner"
)

// OSVVulnChecker queries a vulnerability API (OSV-compatible) for a module@version.
// Check is a stub until HTTP request + response mapping is implemented.
type OSVVulnChecker struct {
	Client  *http.Client
	BaseURL string
}

func (c *OSVVulnChecker) Check(ctx context.Context, module, version string) ([]scanner.Vulnerability, error) {
	if c == nil {
		return nil, errors.New("OSVVulnChecker: nil receiver")
	}
	_ = ctx
	_ = module
	_ = version
	// TODO: POST to OSV query API and map to []scanner.Vulnerability
	return nil, nil
}
