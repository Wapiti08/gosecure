package scanner

/*
contain the concrete implementation of the Scanner interface for go.mod files
*/
import (
	"context"
	"os"
)

type GoModScanner struct {
	Vulns VulnChecker
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (s *GoModScanner) Scan(ctx context.Context, root string) ([]Vulnerability, error) {
	/*
	parse go.mod, use gorountine, calls Vulns.Check
	*/

	// concatenate the path

	// read path - steaming/lower memory processing (do not load the whole file)
	f, err := os.Open(path)

	check(err)

	defer f.Close()

	// split data into lines
	library_list := data.split('\n')

	// check 
	for index, lib := range library_list {
		vul, err := VulnCheck(lib)
		check(err)

	}
}


func (s *GoModScanner) Support(root string) bool {
	// check for go.mod
}



