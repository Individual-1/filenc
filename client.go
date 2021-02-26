package filenc

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

// Client struct wraps a keyset handle and some config data
type Client struct {
	kh     *keyset.Handle
	config *Config
}

// NewClient generates a new Client struct with keyset handle and config initialized
func NewClient(configPath string) (*Client, error) {
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

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	c.config, err = ParseConfig(data)
	if err != nil {
		return nil, err
	}

	c.kh, err = getKeyset(c.config)

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

func retrieveMasterKey(reason string, keyConfig *Config) (tink.AEAD, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(reason)
	fmt.Print("> ")
	passphrase, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	return getMasterKey(passphrase, keyConfig)
}

func getKeyset(keyConfig *Config) (*keyset.Handle, error) {
	var kh *keyset.Handle
	var mKey tink.AEAD

	_, err := appFs.Stat(keyConfig.KeysetPath)
	if err != nil {
		// File does exist
		mKey, err = retrieveMasterKey("Enter passphrase", keyConfig)
		if err != nil {
			return nil, err
		}

		kh, err = loadKeyset(mKey, keyConfig)
		if err != nil {
			return nil, err
		}

		return kh, nil
	}

	// File does not exist
	mKey, err = retrieveMasterKey("Create new passphrase", keyConfig)
	if err != nil {
		return nil, err
	}

	kh, err = newKeyset(mKey, keyConfig)
	if err != nil {
		return nil, err
	}

	return kh, nil
}
