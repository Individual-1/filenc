package filenc

import "github.com/spf13/afero"

// appFs controls what filesystem we are using
var appFs = afero.NewOsFs()

const (
	scryptN      int = 32768
	scryptR      int = 8
	scryptP      int = 1
	scryptKeyLen int = 32
)
