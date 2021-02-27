package filenc

import (
	"fmt"
	"io"
	"syscall"

	"golang.org/x/term"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

// PasswordReader interface is an indirection so we can mock out ReadPassword
type PasswordReader interface {
	ReadPassword() ([]byte, error)
}

// StdInPasswordReader is a blank struct for stdin password reader
type StdInPasswordReader struct {
}

// ReadPassword is a thin wrapper around term ReadPassword for Stdin
func (p StdInPasswordReader) ReadPassword() ([]byte, error) {
	return term.ReadPassword(syscall.Stdin)

}

// Client struct wraps a keyset handle and some config data
type Client struct {
	kh     *keyset.Handle
	config *Config
}

// NewClient wraps withReader and presents an stdin input
func NewClient(configPath string) (*Client, error) {
	pr := StdInPasswordReader{}
	return newClientWithReader(configPath, pr)
}

// newClientWithReader generates a new Client struct with keyset handle and config initialized
func newClientWithReader(configPath string, pr PasswordReader) (*Client, error) {
	c := Client{}

	info, err := appFs.Stat(configPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, fmt.Errorf("config path points to directory")
	}

	f, err := appFs.Open(configPath)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	c.config, err = ParseConfig(data)
	if err != nil {
		return nil, err
	}

	c.kh, err = getKeyset(c.config, pr)

	return &c, nil
}

// Encrypt uses the client's keyset to encrypt the input data and associated data
func (c *Client) Encrypt(data []byte, assocData []byte) ([]byte, error) {
	a, err := aead.New(c.kh)
	if err != nil {
		return nil, err
	}

	return a.Encrypt(data, assocData)
}

// Decrypt uses the client's keyset to decrypt the input data and validate against the associated data
func (c *Client) Decrypt(data []byte, assocData []byte) ([]byte, error) {
	a, err := aead.New(c.kh)
	if err != nil {
		return nil, err
	}

	return a.Decrypt(data, assocData)
}

func retrieveMasterKey(reason string, keyConfig *Config, pr PasswordReader) (tink.AEAD, error) {
	fmt.Println(reason)
	fmt.Print("> ")
	passphrase, err := pr.ReadPassword()
	if err != nil {
		return nil, err
	}

	return getMasterKey(passphrase, keyConfig)
}

func getKeyset(keyConfig *Config, pr PasswordReader) (*keyset.Handle, error) {
	var kh *keyset.Handle
	var mKey tink.AEAD

	_, err := appFs.Stat(keyConfig.KeysetPath)
	if err != nil {
		// File does not exist
		mKey, err = retrieveMasterKey("Enter passphrase", keyConfig, pr)
		if err != nil {
			return nil, err
		}

		kh, err = newKeyset(mKey, keyConfig)
		if err != nil {
			return nil, err
		}

		return kh, nil
	}

	// File does exist
	mKey, err = retrieveMasterKey("Create new passphrase", keyConfig, pr)
	if err != nil {
		return nil, err
	}

	kh, err = loadKeyset(mKey, keyConfig)
	if err != nil {
		return nil, err
	}

	return kh, nil
}
