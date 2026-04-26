package scanner

/*
contain the concrete implementation of the Scanner interface for go.mod files
*/
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// define the covered file layers to contain dependencies
type GoModuleLayer int

const (
	LayerModfile GoModuleLayer = iota // go.mod 
	LayerArtifacts          // vendor/module.txt first, otherwise go.sum
	LayerGoList            // go list -m -json all
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

	// call different parsing logic
	mods, err := s.collectModules(ctx, root)

	check(err)

	for _, mod := range mods  {
		// match cve information
		vuls, err := s.Vulns.Check(ctx, mod.Path, mod.Version)
		check(err)
		all = append(all, vuls...)
	}

	return all, nil
}

// three-layer data sources - one collection module
func (s *GoModScanner) collectModules(ctx context.Context, root string) ([]module.Version, error) {
	switch s.Layer {
	case LayerModfile:
		return collectFromModfile(root, s.IncludeIndirect)
	case LayerArtifacts:
		if hasFile(root, filepath.Join("vendor", "modules.txt")) {
			return collectFromVendorModulesTxt(filepath.Join(root, "vendor", "modules.txt"))
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
	return parseGoSumFile(path)
}

func collectFromVendorModulesTxt(path string) ([]module.Version, error)  {
	// parse modules.txt with modfile
	return parseGoVendorFile(path)
}

// ----- go list ------

type goListModuleJSON struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

func collectFromGoList(ctx context.Context, root string) ([]module.Version, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	cmd.Dir = root

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m -json all: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	seen := make(map[module.Version]struct{})
	// desired output is multiple json-format files
	dec := json.NewDecoder(bytes.NewReader(out))
	// try to read from steaming continously
	for {
		var m goListModuleJSON
		if err := dec.Decode(&m); err != nil {
			// EOF means end of file, without more JSON
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("go list json: %w", err)
		}
		if m.Path == "" || m.Version == "" {
			continue
		}
		if err := module.Check(m.Path, m.Version); err != nil {
			continue
		}
		mv := module.Version{Path: m.Path, Version: m.Version}
		seen[mv] = struct{}{}
	}

	mods := make([]module.Version, 0, len(seen))
	for mv := range seen {
		mods = append(mods, mv)
	}
	return mods, nil
}


func parseGoVendorFile(path string) ([]module.Version, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[module.Version]struct{})
	scn := bufio.NewScanner(f)
	lineNum := 0
	for scn.Scan() {
		lineNum++
		line := strings.TrimSpace(scn.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("vendor/modules.txt:%d: expected module path and version", lineNum)
		}

		modPath, ver := fields[0], fields[1]
		if err := module.Check(modPath, ver); err != nil {
			return nil, fmt.Errorf("vendor/modules.txt:%d: %w", lineNum, err)
		}
		seen[module.Version{Path: modPath, Version: ver}] = struct{}{}
	}
	if err := scn.Err(); err != nil {
		return nil, err
	}
	out := make([]module.Version, 0, len(seen))
	for mv := range seen {
		out = append(out, mv)
	}
	return out, nil
}


// parseGoSumFile reads go.sum and returns unique module.Version entries.
// It merges vX.Y.Z and vX.Y.Z/go.mod lines, skips empty and # comments,
// and requires an h1: checksum on each data line.
func parseGoSumFile(path string) ([]module.Version, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[module.Version]struct{})
	scn := bufio.NewScanner(f)
	lineNum := 0
	for scn.Scan() {
		lineNum++
		line := strings.TrimSpace(scn.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("go.sum:%d: expected module, version, and hash", lineNum)
		}

		modPath, ver, hash := fields[0], fields[1], fields[2]
		if !strings.HasPrefix(hash, "h1:") {
			return nil, fmt.Errorf("go.sum:%d: hash must start with h1:", lineNum)
		}
		ver = strings.TrimSuffix(ver, "/go.mod")
		if ver == "" {
			return nil, fmt.Errorf("go.sum:%d: empty version after normalization", lineNum)
		}
		if err := module.Check(modPath, ver); err != nil {
			return nil, fmt.Errorf("go.sum:%d: %w", lineNum, err)
		}
		seen[module.Version{Path: modPath, Version: ver}] = struct{}{}
	}
	if err := scn.Err(); err != nil {
		return nil, err
	}
	out := make([]module.Version, 0, len(seen))
	for mv := range seen {
		out = append(out, mv)
	}
	return out, nil
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
	case LayerGoList:
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
