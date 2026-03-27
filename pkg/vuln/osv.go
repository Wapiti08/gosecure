package vuln

import (
	"net/http"

	"github.com/Wapiti08/gosecure/pkg/scanner"
)

/*

 */



type OSVVulnChecker struct {
	Client *http.Client
	BaseURL string
}

func (c *OSVVulnChecker) Check(ctx, module, version string) ([]scanner.Vulnerability, error) {
	
}