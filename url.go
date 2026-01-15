package main

import (
	"fmt"
	"net/url"
	"strings"
)

// SSHTarget represents a parsed SSH git target
type SSHTarget struct {
	User     string // e.g., "git"
	Host     string // e.g., "github.com"
	RepoPath string // e.g., "owner/repo.git"
}

// ParseSSHTarget extracts SSH connection info from a URL path
// Input formats:
//   - /git@github.com:owner/repo.git/info/refs
//   - /git%40github.com%3Aowner/repo.git/git-upload-pack
//
// Returns the target and the remaining path (git operation)
func ParseSSHTarget(path string) (*SSHTarget, string, error) {
	// strip leading slash
	path = strings.TrimPrefix(path, "/")

	// URL decode the entire path first
	decoded, err := url.PathUnescape(path)
	if err != nil {
		decoded = path // fallback to original if decode fails
	}

	// find the git operation suffix
	var operation string
	for _, op := range []string{"/info/refs", "/git-upload-pack", "/git-receive-pack", "/HEAD"} {
		if idx := strings.Index(decoded, op); idx > 0 {
			operation = decoded[idx:]
			decoded = decoded[:idx]
			break
		}
	}

	// now parse: git@github.com:owner/repo.git
	// or: git@github.com/owner/repo.git (alternate format)

	atIdx := strings.Index(decoded, "@")
	if atIdx < 0 {
		return nil, "", fmt.Errorf("invalid target: missing @ in %q", decoded)
	}

	user := decoded[:atIdx]
	rest := decoded[atIdx+1:]

	// find separator between host and path (: or /)
	var host, repoPath string

	colonIdx := strings.Index(rest, ":")
	slashIdx := strings.Index(rest, "/")

	switch {
	case colonIdx > 0 && (slashIdx < 0 || colonIdx < slashIdx):
		// host:path format (standard SSH)
		host = rest[:colonIdx]
		repoPath = rest[colonIdx+1:]
	case slashIdx > 0:
		// host/path format
		host = rest[:slashIdx]
		repoPath = rest[slashIdx+1:]
	default:
		return nil, "", fmt.Errorf("invalid target: cannot parse host/path from %q", rest)
	}

	// clean up repo path
	repoPath = strings.TrimSuffix(repoPath, "/")

	if host == "" || repoPath == "" {
		return nil, "", fmt.Errorf("invalid target: empty host or repo in %q", decoded)
	}

	// security: validate inputs don't contain shell metacharacters or path traversal
	if err := validateSSHTarget(user, host, repoPath); err != nil {
		return nil, "", err
	}

	return &SSHTarget{
		User:     user,
		Host:     host,
		RepoPath: repoPath,
	}, operation, nil
}

// validateSSHTarget checks for obviously malicious inputs
func validateSSHTarget(user, host, repoPath string) error {
	// user should be simple (typically "git")
	if strings.ContainsAny(user, "$/\\`\";&|<>(){}[]!#") {
		return fmt.Errorf("invalid user: contains forbidden characters")
	}

	// host should be a valid hostname
	if strings.ContainsAny(host, "$/\\`\";&|<>(){}[]!#@") {
		return fmt.Errorf("invalid host: contains forbidden characters")
	}

	// repo path: allow alphanumeric, dash, underscore, dot, slash
	// reject anything that looks like shell injection
	for _, c := range repoPath {
		if !isAllowedRepoChar(c) {
			return fmt.Errorf("invalid repo path: contains forbidden character %q", c)
		}
	}

	// reject path traversal
	if strings.Contains(repoPath, "..") {
		return fmt.Errorf("invalid repo path: path traversal not allowed")
	}

	return nil
}

func isAllowedRepoChar(c rune) bool {
	// allow: a-z A-Z 0-9 - _ . /
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '/'
}

// SSHAddress returns user@host for SSH connection
func (t *SSHTarget) SSHAddress() string {
	return fmt.Sprintf("%s@%s", t.User, t.Host)
}

// String returns the full SSH URL format
func (t *SSHTarget) String() string {
	return fmt.Sprintf("%s@%s:%s", t.User, t.Host, t.RepoPath)
}
