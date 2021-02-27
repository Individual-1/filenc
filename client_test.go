package filenc

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/afero"

	"github.com/Individual-1/filenc/mocks"
)

func TestClientError(t *testing.T) {
	AppFs = afero.NewMemMapFs()

	// Test config path doesnt exist
	_, err := NewClient("/tmp/config")
	if err == nil {
		t.Error("Expected config path does not exist error")
	}

	// Test config path is directory
	AppFs.MkdirAll("/tmp/config/", 0755)

	_, err = NewClient("/tmp/config")
	if err == nil {
		t.Error("Expected config path is directory error")
	}

	// Test config doesn't match expected format
	js := []byte(`{"keysetPath": 1234, "salt": 4321`)

	err = afero.WriteFile(AppFs, "/tmp/config/malformed", js, 0644)

	_, err = NewClient("/tmp/config/malformed")
	if err == nil {
		t.Error("Expected config json parse error")
	}

}

func TestClientCrypto(t *testing.T) {
	mockControl := gomock.NewController(t)
	defer mockControl.Finish()

	mockPasswordReader := mocks.NewMockPasswordReader(mockControl)

	AppFs = afero.NewMemMapFs()
	AppFs.MkdirAll("/tmp/", 0755)

	c := Config{
		KeysetPath: "/tmp/test",
		Salt:       "salt",
	}

	f, err := json.Marshal(c)
	if err != nil {
		t.Errorf("Failed to marshal json config: %s", err.Error())
	}

	err = afero.WriteFile(AppFs, "/tmp/config", f, 0644)

	passphrase := []byte("test_password")
	data := []byte("data")

	// Test initial keyset creation
	mockPasswordReader.EXPECT().ReadPassword().Return(passphrase, nil).Times(1)

	client, err := NewClientWithReader("/tmp/config", mockPasswordReader)
	if err != nil {
		t.Errorf("Failed to create new client: %s", err.Error())
	}

	e1, err := client.Encrypt(data, nil)
	if err != nil {
		t.Errorf("Failed to encrypt data: %s", err.Error())
	}

	d1, err := client.Decrypt(e1, nil)
	if err != nil {
		t.Errorf("Failed to decrypt data: %s", err.Error())
	}

	if bytes.Compare(data, d1) != 0 {
		t.Errorf("Decrypted bytes do not match original")
	}

	// Test existing keyset load
	mockPasswordReader.EXPECT().ReadPassword().Return(passphrase, nil).Times(1)

	client2, err := NewClientWithReader("/tmp/config", mockPasswordReader)

	e2, err := client2.Encrypt(data, nil)
	if err != nil {
		t.Errorf("Failed to encrypt data: %s", err.Error())
	}

	d2, err := client2.Decrypt(e2, nil)
	if err != nil {
		t.Errorf("Failed to decrypt data: %s", err.Error())
	}

	if bytes.Compare(data, d2) != 0 {
		t.Errorf("Decrypted bytes do not match original")
	}
}
