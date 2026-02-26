package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	Crypto    CryptoConfig    `yaml:"crypto"`
	Logging   LogConfig       `yaml:"logging"`
	Operators []OperatorEntry `yaml:"operators"`
}

type ServerConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	TLS       bool   `yaml:"tls"`
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	RateLimit int    `yaml:"rate_limit"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	Path   string `yaml:"path"`
}

type CryptoConfig struct {
	AESKey     string `yaml:"aes_key"`
	XORKey     string `yaml:"xor_key"`
	ServerCert string `yaml:"server_cert"`
	ServerKey  string `yaml:"server_key"`
}

type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// OperatorEntry allows defining operators in the config file
type OperatorEntry struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Role     string `yaml:"role"` // admin, operator, viewer
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:      "0.0.0.0",
			Port:      54321,
			TLS:       false,
			RateLimit: 100,
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			Path:   "data/rtlc2.db",
		},
		Logging: LogConfig{
			Level: "info",
			File:  "",
		},
		Operators: []OperatorEntry{
			{Username: "admin", Password: "", Role: "admin"},
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		os.MkdirAll(dir, 0700)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Validate checks that the configuration is valid and returns errors for any issues.
func (c *Config) Validate() error {
	var errs []string

	// Server validation
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Sprintf("invalid server port: %d (must be 1-65535)", c.Server.Port))
	}
	// TLS validation
	if c.Server.TLS {
		if c.Server.CertFile == "" {
			errs = append(errs, "TLS enabled but cert_file is empty")
		}
		if c.Server.KeyFile == "" {
			errs = append(errs, "TLS enabled but key_file is empty")
		}
	}

	// AES key validation (if set)
	if c.Crypto.AESKey != "" {
		if len(c.Crypto.AESKey) != 64 {
			errs = append(errs, fmt.Sprintf("AES key must be 64 hex characters (32 bytes), got %d", len(c.Crypto.AESKey)))
		}
	}

	// Database path
	if c.Database.Path == "" {
		errs = append(errs, "database path is empty")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
