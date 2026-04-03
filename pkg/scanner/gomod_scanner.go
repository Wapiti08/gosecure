package scanner

/*
contain the concrete implementation of the Scanner interface for go.mod files
*/
import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
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

	// cover indirect
	IncludeIndirect bool // true = include indirect in go.mod
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

// three-layer data sources - one collection module
func (s *GoModScanner) collectModules(ctx context.Context, root string) ([]module.Version, error) {
	switch s.Layer {
	case LayerModfile:
		return collectFromModfile(root, s.IncludeIndirect)
	case LayerArtifacts:
		if p := filepath.Join(root, "vendor", "modules.txt") {
			return collectFromVendorModulesTxt(p)
		}
		return collectFromGoSum(filepath.Join(root, "go.sum"))
	case LayerGoList:
		return collectFromGoList(ctx, root)
	default:
		return nil, fmt.Errorf("unknown layer: %d", s.Layer)
	}

}


// ----- modfile ------
func collectFromModfile(root string, IncludeIndirect bool) ([]module.Version, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	check(err)

	f, err := modfile.Parse("go.mod", data, nil)
	check(err)

	out := make([]module.Version, 0, len(f.Require))
	for _, r := range f.Require {
		if r == nil {
			continue
		}
		if !IncludeIndirect && r.Indirect {
			continue
		}
		out = append(out, r.Mod)

	}
	return out, nil
}

// ----- vendor / go.sum ------
func collectFromGoSum(path string) ([]module.Version, error) {
	// parse go.sum and remove repetition
}

func collectFromVendorModulesTxt(path string) () {
	// parse modules.txt
}

// ----- go list ------
func collectFromGoList(path string) ([]module.Version, error) {
	// execute command and return the results
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