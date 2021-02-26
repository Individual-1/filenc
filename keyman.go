package filenc

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	subtleMac "github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/tink"
	"golang.org/x/crypto/scrypt"
)

func deriveScryptKey(passphrase []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, scryptKeyLen)
}

// Pulled from Tink tests to generate initial AEAD without KMS
func createAEAD(key []byte) (tink.AEAD, error) {
	ctr, err := subtle.NewAESCTR(key, aeadIVSize)
	if err != nil {
		return nil, err
	}

	macKey := make([]byte, aeadMacSize)
	_, err = rand.Read(macKey)
	if err != nil {
		return nil, err
	}

	mac, err := subtleMac.NewHMAC(aeadHashFunc, macKey, uint32(aeadTagSize))
	if err != nil {
		return nil, err
	}

	cipher, err := subtle.NewEncryptThenAuthenticate(ctr, mac, aeadTagSize)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

func getMasterKey(passphrase []byte, keyConfig *Config) (tink.AEAD, error) {
	sKey, err := deriveScryptKey(passphrase, []byte(keyConfig.Salt))
	if err != nil {
		return nil, err
	}

	return createAEAD(sKey)
}

func loadKeyset(masterKey tink.AEAD, keyConfig *Config) (*keyset.Handle, error) {
	info, err := os.Stat(keyConfig.KeysetPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, fmt.Errorf("keyfile path is a directory")
	}

	fileReader, err := os.Open(keyConfig.KeysetPath)
	if err != nil {
		return nil, err
	}

	defer fileReader.Close()

	jsonReader := keyset.NewJSONReader(fileReader)

	return keyset.Read(jsonReader, masterKey)
}

func newKeyset(masterKey tink.AEAD, keyConfig *Config) (*keyset.Handle, error) {
	_, err := os.Stat(keyConfig.KeysetPath)
	if err == nil {
		return nil, fmt.Errorf("keypath %s already exists", keyConfig.KeysetPath)
	}

	kh, err := keyset.NewHandle(aead.AES256CTRHMACSHA256KeyTemplate())
	if err != nil {
		return nil, err
	}

	fmt.Printf("Writing keyset to disk: %s\n", keyConfig.KeysetPath)
	keyFile, err := os.Create(keyConfig.KeysetPath)
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
