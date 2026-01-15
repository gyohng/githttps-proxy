package main

import (
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	SelfSigned bool     `yaml:"self_signed"`
	Hosts      []string `yaml:"hosts"`
	ACMEEmail  string   `yaml:"acme_email"`
	CertDir    string   `yaml:"cert_dir"`
	Port       int      `yaml:"port"`
	// ACMEHTTPPort is the port for the HTTP-01 challenge server (default: 80)
	// Set to 0 to disable the built-in challenge server (useful when nginx handles it)
	// Set to another port if nginx proxies /.well-known/acme-challenge/ to this server
	ACMEHTTPPort *int `yaml:"acme_http_port"`
	// Use existing certificate files (e.g., from certbot)
	// If set, takes precedence over self_signed and autocert
	CertFile string `yaml:"cert_file"` // e.g., /etc/letsencrypt/live/domain/fullchain.pem
	KeyFile  string `yaml:"key_file"`  // e.g., /etc/letsencrypt/live/domain/privkey.pem
}

type UserConfig struct {
	Password   string `yaml:"password"`    // plaintext password
	Secret     string `yaml:"secret"`      // bcrypt hash (takes precedence)
	PrivateKey string `yaml:"private_key"` // inline key (takes precedence over keys_dir)
}

type Config struct {
	Listen  string                `yaml:"listen"`
	TLS     TLSConfig             `yaml:"tls"`
	KeysDir string                `yaml:"keys_dir"` // directory to load keys from if not inline
	Users   map[string]UserConfig `yaml:"users"`

	// parsed signers cached per user
	signers map[string]ssh.Signer
}

// common SSH key file extensions to try (in order)
var keyExtensions = []string{"", ".pem", ".key"}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		Listen:  ":8443",
		signers: make(map[string]ssh.Signer),
	}
	cfg.TLS.Port = 443
	cfg.TLS.CertDir = "./certs"

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// pre-parse all private keys
	for username, user := range cfg.Users {
		keyData := user.PrivateKey

		// if no inline key, try loading from keys_dir
		if keyData == "" && cfg.KeysDir != "" {
			var err error
			keyData, err = loadKeyFromDir(cfg.KeysDir, username)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", username, err)
			}
		}

		if keyData == "" {
			return nil, fmt.Errorf("user %q: missing private_key (not inline and not found in keys_dir)", username)
		}

		signer, err := ssh.ParsePrivateKey([]byte(keyData))
		if err != nil {
			return nil, fmt.Errorf("user %q: parse private key: %w", username, err)
		}
		cfg.signers[username] = signer
	}

	return cfg, nil
}

// loadKeyFromDir tries to load a private key from keys_dir/username[.ext]
func loadKeyFromDir(keysDir, username string) (string, error) {
	for _, ext := range keyExtensions {
		keyPath := filepath.Join(keysDir, username+ext)
		data, err := os.ReadFile(keyPath)
		if err == nil {
			return string(data), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("read key file %s: %w", keyPath, err)
		}
	}
	return "", fmt.Errorf("no key file found in %s (tried: %s, %s.pem, %s.key)", keysDir, username, username, username)
}

// Authenticate checks username/password against config
func (c *Config) Authenticate(username, password string) bool {
	user, ok := c.Users[username]
	if !ok {
		// constant-time comparison even for non-existent users to prevent timing attacks
		subtle.ConstantTimeCompare([]byte(password), []byte("dummy-password-for-timing"))
		return false
	}

	// prefer bcrypt secret if present (bcrypt is already constant-time)
	if user.Secret != "" {
		return bcrypt.CompareHashAndPassword([]byte(user.Secret), []byte(password)) == nil
	}

	// fallback to plaintext comparison (constant-time to prevent timing attacks)
	return user.Password != "" && subtle.ConstantTimeCompare([]byte(password), []byte(user.Password)) == 1
}

// GetSigner returns the SSH signer for a user
func (c *Config) GetSigner(username string) (ssh.Signer, bool) {
	s, ok := c.signers[username]
	return s, ok
}

// GetPublicKey returns the public key in authorized_keys format for a user
func (c *Config) GetPublicKey(username string) (string, error) {
	signer, ok := c.signers[username]
	if !ok {
		return "", fmt.Errorf("user %q not found", username)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}

// HashPassword generates a bcrypt hash suitable for the 'secret' field
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
