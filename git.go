package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GitHandler handles Git Smart HTTP protocol requests
type GitHandler struct {
	cfg *Config
	log *slog.Logger
}

func NewGitHandler(cfg *Config, log *slog.Logger) *GitHandler {
	return &GitHandler{cfg: cfg, log: log}
}

// ServeHTTP handles all git requests
func (h *GitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// extract auth
	username, password, ok := r.BasicAuth()
	if !ok || !h.cfg.Authenticate(username, password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// get signer for user
	signer, ok := h.cfg.GetSigner(username)
	if !ok {
		http.Error(w, "no key configured for user", http.StatusInternalServerError)
		return
	}

	// parse SSH target from path
	target, operation, err := ParseSSHTarget(r.URL.Path)
	if err != nil {
		h.log.Error("parse target", "path", r.URL.Path, "error", err)
		http.Error(w, "invalid repository path", http.StatusBadRequest)
		return
	}

	h.log.Info("git request",
		"user", username,
		"target", target.String(),
		"operation", operation,
		"method", r.Method,
	)

	// route to appropriate handler
	switch {
	case strings.HasSuffix(operation, "/info/refs"):
		h.handleInfoRefs(w, r, target, signer)
	case strings.HasSuffix(operation, "/git-upload-pack"):
		h.handleUploadPack(w, r, target, signer)
	case strings.HasSuffix(operation, "/git-receive-pack"):
		h.handleReceivePack(w, r, target, signer)
	case strings.HasSuffix(operation, "/HEAD"):
		h.handleHEAD(w, r, target, signer)
	default:
		http.Error(w, "unsupported operation", http.StatusNotFound)
	}
}

// handleInfoRefs handles GET /info/refs?service=git-upload-pack|git-receive-pack
func (h *GitHandler) handleInfoRefs(w http.ResponseWriter, r *http.Request, target *SSHTarget, signer ssh.Signer) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	service := r.URL.Query().Get("service")
	if service != "git-upload-pack" && service != "git-receive-pack" {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}

	// connect to SSH
	client, err := DialSSH(r.Context(), target.Host, target.User, signer)
	if err != nil {
		h.log.Error("ssh dial", "host", target.Host, "error", err)
		http.Error(w, "failed to connect to git server", http.StatusBadGateway)
		return
	}
	defer client.Close()

	// capture output
	var buf bytes.Buffer
	if err := client.RunGitAdvertiseRefs(r.Context(), service, target.RepoPath, &buf); err != nil {
		h.log.Error("git advertise-refs", "error", err)
		http.Error(w, "git command failed", http.StatusBadGateway)
		return
	}

	// write response in Git Smart HTTP format
	w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
	w.Header().Set("Cache-Control", "no-cache")

	// pkt-line header: # service=git-upload-pack\n
	pktHeader := fmt.Sprintf("# service=%s\n", service)
	w.Write(pktLine(pktHeader))
	w.Write([]byte("0000")) // flush-pkt

	// refs from server
	w.Write(buf.Bytes())
}

// handleUploadPack handles POST /git-upload-pack (clone/fetch)
func (h *GitHandler) handleUploadPack(w http.ResponseWriter, r *http.Request, target *SSHTarget, signer ssh.Signer) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.handleGitCommand(w, r, target, signer, "git-upload-pack", "application/x-git-upload-pack-result")
}

// handleReceivePack handles POST /git-receive-pack (push)
func (h *GitHandler) handleReceivePack(w http.ResponseWriter, r *http.Request, target *SSHTarget, signer ssh.Signer) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.handleGitCommand(w, r, target, signer, "git-receive-pack", "application/x-git-receive-pack-result")
}

// handleGitCommand handles bidirectional git command streaming
func (h *GitHandler) handleGitCommand(w http.ResponseWriter, r *http.Request, target *SSHTarget, signer ssh.Signer, cmd, contentType string) {
	client, err := DialSSH(r.Context(), target.Host, target.User, signer)
	if err != nil {
		h.log.Error("ssh dial", "host", target.Host, "error", err)
		http.Error(w, "failed to connect to git server", http.StatusBadGateway)
		return
	}
	defer client.Close()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")

	// flush headers before streaming
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// bidirectional stream
	if err := client.RunGitCommand(r.Context(), cmd, target.RepoPath, r.Body, w); err != nil {
		h.log.Error("git command", "cmd", cmd, "error", err)
		// can't send error to client if we've already started streaming
		return
	}
}

// handleHEAD handles GET /HEAD for dumb HTTP protocol compatibility
func (h *GitHandler) handleHEAD(w http.ResponseWriter, r *http.Request, target *SSHTarget, signer ssh.Signer) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// for dumb protocol, redirect to smart protocol
	// most modern git clients will use smart protocol anyway
	http.Error(w, "use smart http protocol", http.StatusNotImplemented)
}

// pktLine formats a string as a git pkt-line
func pktLine(s string) []byte {
	length := len(s) + 4
	return []byte(fmt.Sprintf("%04x%s", length, s))
}
