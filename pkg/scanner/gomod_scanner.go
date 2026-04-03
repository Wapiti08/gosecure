package scanner

/*
contain the concrete implementation of the Scanner interface for go.mod files
*/
import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/mod/module"
)

// define the covered file layers to contain dependencies
type GoModuleLayer int

const (
	LayerModfile GoModuleLayer = iota // go.mod 
	LayerArtifacts          // vendor/module.txt first, otherwise go.sum
	LayerGolist            // go list -m -json all
)

type GoModScanner struct {
	Vulns VulnChecker
	Layer GoModuleLayer
}


func (s *GoModScanner) Scan(ctx context.Context, root string) ([]Vulnerability, error) {
	/*
	parse go.mod, use gorountine, calls Vulns.Check
	*/

	var all []Vulnerability

	for _, mod := range mods  {
		// match cve information
		vuls, err := VulnChecker(line)
		check(err)
		all = append(all, vuls...)
	}

}

// three-layer data sources
func (s *GoModScanner) collectModules(ctx context.Context, root string) ([]module.Version, error) {


}


func (s *GoModScanner) Support(root string) bool {
	// check for go.mod
	if !hasFile(root, "go.mod") {
		return false
	}

	// switch case to check different layerred files
	switch s.Layer {
	case LayerModfile:
		return true
	case LayerArtifacts:
		return hasFile(root, "vendor/modules.txt") || hasFile(root, "go.sum")
	case LayerGolist:
		// need support to run go
		return true
	default:
		return false
	}
}

func hasFile(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))

	return !os.IsNotExist(err)
}


func check(e error) {
	if e != nil {
		panic(e)
	}
}