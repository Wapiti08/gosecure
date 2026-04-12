package vuln

import (
	"context"

	"github.com/Wapiti08/gosecure/pkg/scanner"
)

// CachingChecker wraps a VulnChecker with an in-memory cache (TODO: implement cache layer).
type CachingChecker struct {
	Inner scanner.VulnChecker
}

func (c *CachingChecker) Check(ctx context.Context, module, version string) ([]scanner.Vulnerability, error) {
	if c.Inner == nil {
		return nil, nil
	}
	return c.Inner.Check(ctx, module, version)
}
