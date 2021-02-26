package filenc

import (
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"golang.org/x/crypto/scrypt"
)

func deriveScryptKey(passphrase []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, scryptKeyLen)
}

// createAESGCMAEAD takes a raw key in and creates an AESGCM AEAD from it
func createAESGCMAEAD(key []byte) (tink.AEAD, error) {
	return subtle.NewAESGCM(key)
}

func getMasterKey(passphrase []byte, keyConfig *Config) (tink.AEAD, error) {
	sKey, err := deriveScryptKey(passphrase, []byte(keyConfig.Salt))
	if err != nil {
		return nil, err
	}

	return createAESGCMAEAD(sKey)
}

func loadKeyset(masterKey tink.AEAD, keyConfig *Config) (*keyset.Handle, error) {
	info, err := appFs.Stat(keyConfig.KeysetPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, fmt.Errorf("keyfile path is a directory")
	}

	fileReader, err := appFs.Open(keyConfig.KeysetPath)
	if err != nil {
		return nil, err
	}

	defer fileReader.Close()

	jsonReader := keyset.NewJSONReader(fileReader)

	return keyset.Read(jsonReader, masterKey)
}

func newKeyset(masterKey tink.AEAD, keyConfig *Config) (*keyset.Handle, error) {
	_, err := appFs.Stat(keyConfig.KeysetPath)
	if err == nil {
		return nil, fmt.Errorf("keypath %s already exists", keyConfig.KeysetPath)
	}

	kh, err := keyset.NewHandle(aead.AES256CTRHMACSHA256KeyTemplate())
	if err != nil {
		return nil, err
	}

	fmt.Printf("Writing keyset to disk: %s\n", keyConfig.KeysetPath)
	keyFile, err := appFs.Create(keyConfig.KeysetPath)
	if err != nil {
		return nil, err
	}

	defer keyFile.Close()

	jsonWriter := keyset.NewJSONWriter(keyFile)

	err = kh.Write(jsonWriter, masterKey)
	if err != nil {
		return nil, err
	}

	return kh, nil
}
