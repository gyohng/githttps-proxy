package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"
)

const version = "0.1.0"

func main() {
	var (
		configPath = flag.String("config", "config.yaml", "path to config file")
		showHelp   = flag.Bool("help", false, "show help")
		showVer    = flag.Bool("version", false, "show version")
	)

	// subcommands
	pubkeyCmd := flag.NewFlagSet("pubkey", flag.ExitOnError)
	pubkeyUser := pubkeyCmd.String("user", "", "username to show public key for")
	pubkeyConfig := pubkeyCmd.String("config", "config.yaml", "path to config file")

	secretCmd := flag.NewFlagSet("secret", flag.ExitOnError)

	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	keygenUser := keygenCmd.String("user", "", "username for the key (required)")
	keygenType := keygenCmd.String("type", "ed25519", "key type: ed25519, rsa4096, ecdsa384")
	keygenConfig := keygenCmd.String("config", "config.yaml", "path to config file (to detect keys_dir)")

	flag.Parse()

	// handle subcommands
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "pubkey":
			pubkeyCmd.Parse(os.Args[2:])
			runPubkey(*pubkeyConfig, *pubkeyUser)
			return
		case "secret":
			secretCmd.Parse(os.Args[2:])
			runSecret(secretCmd.Args())
			return
		case "keygen":
			keygenCmd.Parse(os.Args[2:])
			runKeygen(*keygenUser, *keygenType, *keygenConfig)
			return
		case "serve":
			// continue to server
			os.Args = append(os.Args[:1], os.Args[2:]...)
			flag.Parse()
		}
	}

	if *showHelp {
		printUsage()
		return
	}

	if *showVer {
		fmt.Printf("githttps-proxy %s\n", version)
		return
	}

	// setup logger
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(log)

	// load config
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	log.Info("starting githttps-proxy", "version", version, "users", len(cfg.Users))

	// create handler
	handler := NewGitHandler(cfg, log)

	// start server
	if err := runServer(cfg, handler, log); err != nil {
		log.Error("server error", "error", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`githttps-proxy - Git HTTPS to SSH proxy

Usage:
  githttps-proxy [flags]              Start the proxy server
  githttps-proxy serve [flags]        Start the proxy server (explicit)
  githttps-proxy pubkey -user NAME    Print public key for a user
  githttps-proxy secret PASSWORD      Generate bcrypt hash for password
  githttps-proxy keygen -user NAME    Generate SSH key pair for a user

Flags:
  -config string    Path to config file (default "config.yaml")
  -help             Show this help
  -version          Show version

Keygen Flags:
  -user string      Username for the key (required)
  -type string      Key type: ed25519 (default), rsa4096, ecdsa384
  -config string    Path to config file to detect keys_dir (default "config.yaml")

Examples:
  githttps-proxy -config /etc/githttps-proxy/config.yaml
  githttps-proxy pubkey -user alice -config config.yaml
  githttps-proxy secret mysecretpassword
  githttps-proxy keygen -user alice
  githttps-proxy keygen -user bob -type rsa4096`)
}

func runPubkey(configPath, username string) {
	if username == "" {
		fmt.Fprintln(os.Stderr, "error: -user is required")
		os.Exit(1)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	pubkey, err := cfg.GetPublicKey(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(pubkey)
}

func runSecret(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: password argument required")
		fmt.Fprintln(os.Stderr, "usage: githttps-proxy secret PASSWORD")
		os.Exit(1)
	}

	hash, err := HashPassword(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(hash)
}

func runKeygen(username, keyType, configPath string) {
	if username == "" {
		fmt.Fprintln(os.Stderr, "error: -user is required")
		fmt.Fprintln(os.Stderr, "usage: githttps-proxy keygen -user USERNAME [-type ed25519|rsa4096|ecdsa384]")
		os.Exit(1)
	}

	// validate key type
	keyType = strings.ToLower(keyType)
	switch keyType {
	case "ed25519", "rsa4096", "ecdsa384":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported key type %q (use ed25519, rsa4096, or ecdsa384)\n", keyType)
		os.Exit(1)
	}

	// generate the key
	privateKeyPEM, publicKeySSH, err := generateSSHKeyPair(keyType, username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating key: %v\n", err)
		os.Exit(1)
	}

	// try to detect keys_dir from config
	var keysDir string
	if data, err := os.ReadFile(configPath); err == nil {
		// simple extraction of keys_dir from config without full parsing
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "keys_dir:") {
				keysDir = strings.TrimSpace(strings.TrimPrefix(line, "keys_dir:"))
				keysDir = strings.Trim(keysDir, `"'`)
				break
			}
		}
	}

	// check if keys_dir exists
	keysDirExists := false
	if keysDir != "" {
		if info, err := os.Stat(keysDir); err == nil && info.IsDir() {
			keysDirExists = true
		}
	}

	if keysDirExists {
		// save to keys directory
		keyPath := filepath.Join(keysDir, username)

		// check if file already exists
		if _, err := os.Stat(keyPath); err == nil {
			fmt.Fprintf(os.Stderr, "error: key file already exists: %s\n", keyPath)
			fmt.Fprintln(os.Stderr, "Remove the existing file first if you want to regenerate.")
			os.Exit(1)
		}

		if err := os.WriteFile(keyPath, []byte(privateKeyPEM), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing key file: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Private key saved to: %s\n", keyPath)
		fmt.Fprintf(os.Stderr, "\nPublic key (add to git host):\n")
		fmt.Print(publicKeySSH)
	} else {
		// print to console with config instructions
		fmt.Fprintf(os.Stderr, "Generated %s key for user %q\n\n", keyType, username)

		fmt.Fprintln(os.Stderr, "=== PRIVATE KEY ===")
		fmt.Fprintln(os.Stderr, "Add this to your config.yaml under the user's private_key field:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "users:\n")
		fmt.Fprintf(os.Stderr, "  %s:\n", username)
		fmt.Fprintf(os.Stderr, "    password: \"YOUR_PASSWORD_HERE\"\n")
		fmt.Fprintf(os.Stderr, "    private_key: |\n")

		// indent the private key for YAML
		for _, line := range strings.Split(strings.TrimSpace(privateKeyPEM), "\n") {
			fmt.Fprintf(os.Stderr, "      %s\n", line)
		}

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "=== PUBLIC KEY ===")
		fmt.Fprintln(os.Stderr, "Add this to your git host (GitHub, GitLab, etc.):")
		fmt.Fprintln(os.Stderr, "")
		fmt.Print(publicKeySSH)

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "TIP: To save keys to a directory, set keys_dir in your config and create the directory.")
	}
}

// generateSSHKeyPair generates an SSH key pair of the specified type
// Returns the private key in PEM format and public key in authorized_keys format
func generateSSHKeyPair(keyType, comment string) (privateKeyPEM, publicKeySSH string, err error) {
	switch keyType {
	case "ed25519":
		return generateED25519Key(comment)
	case "rsa4096":
		return generateRSAKey(4096, comment)
	case "ecdsa384":
		return generateECDSAKey(elliptic.P384(), comment)
	default:
		return "", "", fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func generateED25519Key(comment string) (string, string, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 key: %w", err)
	}

	// convert to SSH format
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", "", fmt.Errorf("create ssh public key: %w", err)
	}

	// marshal private key to OpenSSH format
	pemBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}

	privateKeyPEM := string(pem.EncodeToMemory(pemBlock))
	publicKeySSH := string(ssh.MarshalAuthorizedKey(sshPubKey))

	// add comment to public key
	publicKeySSH = strings.TrimSpace(publicKeySSH) + " " + comment + "\n"

	return privateKeyPEM, publicKeySSH, nil
}

func generateRSAKey(bits int, comment string) (string, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", fmt.Errorf("generate rsa key: %w", err)
	}

	// convert to SSH format
	sshPubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("create ssh public key: %w", err)
	}

	// marshal private key to OpenSSH format
	pemBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}

	privateKeyPEM := string(pem.EncodeToMemory(pemBlock))
	publicKeySSH := string(ssh.MarshalAuthorizedKey(sshPubKey))

	// add comment to public key
	publicKeySSH = strings.TrimSpace(publicKeySSH) + " " + comment + "\n"

	return privateKeyPEM, publicKeySSH, nil
}

func generateECDSAKey(curve elliptic.Curve, comment string) (string, string, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ecdsa key: %w", err)
	}

	// convert to SSH format
	sshPubKey, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("create ssh public key: %w", err)
	}

	// marshal private key to OpenSSH format
	pemBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}

	privateKeyPEM := string(pem.EncodeToMemory(pemBlock))
	publicKeySSH := string(ssh.MarshalAuthorizedKey(sshPubKey))

	// add comment to public key
	publicKeySSH = strings.TrimSpace(publicKeySSH) + " " + comment + "\n"

	return privateKeyPEM, publicKeySSH, nil
}

func runServer(cfg *Config, handler http.Handler, log *slog.Logger) error {
	// determine listen address
	listenAddr := cfg.Listen
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	var srv *http.Server

	if cfg.TLS.Enabled {
		// ensure cert directory exists
		os.MkdirAll(cfg.TLS.CertDir, 0700)

		var tlsConfig *tls.Config

		if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			// use existing certificate files (e.g., from certbot)
			// with hot-reload support when files change
			log.Info("TLS mode: existing certificate (hot-reload enabled)", "cert", cfg.TLS.CertFile, "key", cfg.TLS.KeyFile)

			certLoader := newCertReloader(cfg.TLS.CertFile, cfg.TLS.KeyFile, log)
			if _, err := certLoader.GetCertificate(nil); err != nil {
				return fmt.Errorf("load certificate: %w", err)
			}

			tlsConfig = &tls.Config{
				GetCertificate: certLoader.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			}
		} else if cfg.TLS.SelfSigned {
			log.Info("TLS mode: self-signed certificate")
			hosts := cfg.TLS.Hosts
			if len(hosts) == 0 {
				hosts = []string{"localhost"}
			}

			cert, err := generateSelfSignedCert(hosts, cfg.TLS.CertDir)
			if err != nil {
				return fmt.Errorf("generate self-signed cert: %w", err)
			}

			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		} else {
			// Let's Encrypt
			if len(cfg.TLS.Hosts) == 0 {
				return fmt.Errorf("tls.hosts required for Let's Encrypt (or use tls.self_signed: true)")
			}

			log.Info("TLS mode: Let's Encrypt", "hosts", cfg.TLS.Hosts)

			certManager := &autocert.Manager{
				Cache:      autocert.DirCache(cfg.TLS.CertDir),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(cfg.TLS.Hosts...),
				Email:      cfg.TLS.ACMEEmail,
			}

			tlsConfig = &tls.Config{
				GetCertificate: certManager.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			}

			// start ACME HTTP challenge server
			go func() {
				acmeAddr := ":80"
				log.Info("ACME HTTP-01 challenge server listening", "addr", acmeAddr)
				if err := http.ListenAndServe(acmeAddr, certManager.HTTPHandler(nil)); err != nil {
					log.Error("ACME server error", "error", err)
				}
			}()
		}

		tlsAddr := listenAddr
		if cfg.TLS.Port > 0 {
			_, port, _ := net.SplitHostPort(listenAddr)
			if port == "" || port != strconv.Itoa(cfg.TLS.Port) {
				host, _, _ := net.SplitHostPort(listenAddr)
				if host == "" {
					host = ""
				}
				tlsAddr = net.JoinHostPort(host, strconv.Itoa(cfg.TLS.Port))
			}
		}

		srv = &http.Server{
			Addr:              tlsAddr,
			Handler:           handler,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		go func() {
			log.Info("HTTPS server listening", "addr", tlsAddr)
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Error("HTTPS server error", "error", err)
				os.Exit(1)
			}
		}()
	} else {
		// plain HTTP (for testing or behind reverse proxy)
		srv = &http.Server{
			Addr:              listenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		go func() {
			log.Info("HTTP server listening", "addr", listenAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("HTTP server error", "error", err)
				os.Exit(1)
			}
		}()
	}

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	log.Info("server stopped")
	return nil
}

// certReloader handles hot-reloading of TLS certificates
// It checks file mtime and reloads when changed
type certReloader struct {
	certFile string
	keyFile  string
	log      *slog.Logger

	mu      sync.RWMutex
	cert    *tls.Certificate
	certMod time.Time
	keyMod  time.Time
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) *certReloader {
	return &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
		log:      log,
	}
}

func (cr *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	// check if reload needed
	certStat, err := os.Stat(cr.certFile)
	if err != nil {
		return nil, fmt.Errorf("stat cert file: %w", err)
	}
	keyStat, err := os.Stat(cr.keyFile)
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}

	cr.mu.RLock()
	if cr.cert != nil && certStat.ModTime().Equal(cr.certMod) && keyStat.ModTime().Equal(cr.keyMod) {
		cert := cr.cert
		cr.mu.RUnlock()
		return cert, nil
	}
	cr.mu.RUnlock()

	// reload certificate
	cr.mu.Lock()
	defer cr.mu.Unlock()

	// double-check after acquiring write lock
	if cr.cert != nil && certStat.ModTime().Equal(cr.certMod) && keyStat.ModTime().Equal(cr.keyMod) {
		return cr.cert, nil
	}

	cert, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	cr.cert = &cert
	cr.certMod = certStat.ModTime()
	cr.keyMod = keyStat.ModTime()

	cr.log.Info("TLS certificate reloaded", "cert", cr.certFile)
	return cr.cert, nil
}

func generateSelfSignedCert(hosts []string, certDir string) (tls.Certificate, error) {
	certPath := filepath.Join(certDir, "self-signed.crt")
	keyPath := filepath.Join(certDir, "self-signed.key")

	// check if cert already exists
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return tls.LoadX509KeyPair(certPath, keyPath)
		}
	}

	// generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"githttps-proxy"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	template.DNSNames = append(template.DNSNames, "localhost")
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	// save certificate (readable by owner and group)
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert file: %w", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// save private key (restricted permissions - owner only)
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create key file: %w", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return tls.LoadX509KeyPair(certPath, keyPath)
}
