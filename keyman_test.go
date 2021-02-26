package filenc

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/spf13/afero"
)

// TODO: Add failure cases
func TestScryptDerivation(t *testing.T) {
	var passphrase []byte = []byte("test_password")
	var salt []byte = []byte("salt")

	decoded, err := base64.StdEncoding.DecodeString("33Y7WoXU+dFSUj2U/y1s00evffKPia9bmzb5/itZyLI=")

	sKey, err := deriveScryptKey(passphrase, salt)
	if err != nil {
		t.Errorf("Failed to derive scrypt key: %s", err.Error())
	}

	if bytes.Compare(sKey, decoded) != 0 {
		t.Errorf("Derived passphrase does not match expected")
	}
}

func TestScryptDerivationMismatch(t *testing.T) {
	passphraseRight := []byte("test_password")
	passphraseWrong := []byte("wrong_password")
	saltRight := []byte("salt")
	saltWrong := []byte("other_salt")

	decoded, err := base64.StdEncoding.DecodeString("33Y7WoXU+dFSUj2U/y1s00evffKPia9bmzb5/itZyLI=")

	sKey, err := deriveScryptKey(passphraseWrong, saltRight)
	if err != nil {
		t.Errorf("Failed to derive scrypt key: %s", err.Error())
	}

	if bytes.Compare(sKey, decoded) == 0 {
		t.Errorf("Derived passphrase matches incorrect value")
	}

	sKey, err = deriveScryptKey(passphraseRight, saltWrong)
	if err != nil {
		t.Errorf("Failed to derive scrypt key: %s", err.Error())
	}

	if bytes.Compare(sKey, decoded) == 0 {
		t.Errorf("Derived passphrase matches incorrect value")
	}
}

func TestRawAESGCMKeyCreation(t *testing.T) {
	passphrase := []byte("test_password")
	salt := []byte("salt")
	data := []byte("test")
	extraData := []byte("extraData")

	sKey, err := deriveScryptKey(passphrase, salt)
	if err != nil {
		t.Errorf("Failed to derive scrypt key: %s", err.Error())
	}

	a, err := createAESGCMAEAD(sKey)
	if err != nil {
		t.Errorf("Failed to generate aead key for manual: %s", err.Error())
	}

	e1, err := a.Encrypt(data, nil)
	if err != nil {
		t.Errorf("Failed to encrypt data with manual key: %s", err.Error())
	}

	d1, err := a.Decrypt(e1, nil)
	if err != nil {
		t.Errorf("Failed to decrypt data with manual key: %s", err.Error())
	}

	if bytes.Compare(d1, data) != 0 {
		t.Errorf("Decrypted data does not match original")
	}

	e2, err := a.Encrypt(data, extraData)
	if err != nil {
		t.Errorf("Failed to encrypt data with manual key: %s", err.Error())
	}

	d2, err := a.Decrypt(e2, extraData)
	if err != nil {
		t.Errorf("Failed to decrypt data with manual key: %s", err.Error())
	}

	if bytes.Compare(d2, data) != 0 {
		t.Errorf("Decrypted data with extra does not match original")
	}
}

func TestKeysetNew(t *testing.T) {
	appFs = afero.NewMemMapFs()
	appFs.MkdirAll("/tmp", 0755)

	c := Config{
		KeysetPath: "/tmp/test",
		Salt:       "salt",
	}

	passphrase := []byte("test_password")
	data := []byte("data")

	a, err := getMasterKey(passphrase, &c)
	if err != nil {
		t.Errorf("Failed to derive master key: %s", err.Error())
	}

	kh1, err := newKeyset(a, &c)
	if err != nil {
		t.Errorf("Failed to generate new keyset: %s", err.Error())
	}

	kh2, err := loadKeyset(a, &c)
	if err != nil {
		t.Errorf("Failed to load generated keyset: %s", err.Error())
	}

	a1, err := aead.New(kh1)
	if err != nil {
		t.Errorf("Failed to generate AEAD for new keyset: %s", err.Error())
	}

	a2, err := aead.New(kh2)
	if err != nil {
		t.Errorf("Failed to generate AEAD for loaded keyset: %s", err.Error())
	}

	e1, err := a1.Encrypt(data, nil)
	if err != nil {
		t.Errorf("Failed to encrypt data with a1: %s", err.Error())
	}

	d1, err := a2.Decrypt(e1, nil)
	if err != nil {
		t.Errorf("Failed to decrypt data with a2: %s", err.Error())
	}

	if bytes.Compare(data, d1) != 0 {
		t.Error("Decrypted data and original do not match")
	}
}

func TestKeysetErrorExists(t *testing.T) {
	appFs = afero.NewMemMapFs()
	appFs.MkdirAll("/tmp", 0755)
	afero.WriteFile(appFs, "/tmp/test", []byte("file"), 0644)

	c := Config{
		KeysetPath: "/tmp/test",
		Salt:       "salt",
	}

	_, err := newKeyset(nil, &c)
	if err == nil {
		t.Error("Expected keypath already exists error")
	}
}

func TestErrorLoadKeyset(t *testing.T) {
	appFs = afero.NewMemMapFs()
	appFs.MkdirAll("/tmp", 0755)

	c := Config{
		KeysetPath: "/tmp/test",
		Salt:       "salt",
	}

	_, err := loadKeyset(nil, &c)
	if err == nil {
		t.Error("Expected keypath doesn't exists error")
	}

	appFs.MkdirAll("/tmp/test", 0755)

	_, err = loadKeyset(nil, &c)
	if err == nil {
		t.Error("Expected keypath is directory error")
	}
}
