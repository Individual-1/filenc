package filenc

const (
	scryptN      int = 32768
	scryptR      int = 8
	scryptP      int = 1
	scryptKeyLen int = 32

	aeadIVSize   int    = 16
	aeadMacSize  int    = 32
	aeadTagSize  int    = 32
	aeadHashFunc string = "SHA256"
)
