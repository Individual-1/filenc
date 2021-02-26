package filenc

import (
	"encoding/json"
)

// Config struct contains configuration info for crypto operations
type Config struct {
	KeysetPath string `json:"keysetPath"`
	Salt       string `json:"salt"`
}

// ParseConfig returns a Config object given a json byte array
func ParseConfig(data []byte) (*Config, error) {
	config := Config{}
	err := json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
