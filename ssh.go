package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient wraps an SSH connection for git operations
type SSHClient struct {
	client *ssh.Client
}

// DialSSH connects to an SSH server using the given signer
// Note: Host key verification is disabled for simplicity. In production,
// consider implementing known_hosts support via ssh.FixedHostKey or ssh.KnownHosts.
func DialSSH(ctx context.Context, host string, user string, signer ssh.Signer) (*SSHClient, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// TODO: For production, implement known_hosts support:
		// - ssh.FixedHostKey(key) for single known host
		// - knownhosts.New(knownHostsPath) from golang.org/x/crypto/ssh/knownhosts
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	// add default port if missing
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "22")
	}

	// dial with context
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}

	// wrap deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	return &SSHClient{
		client: ssh.NewClient(sshConn, chans, reqs),
	}, nil
}

// Close closes the SSH connection
func (c *SSHClient) Close() error {
	return c.client.Close()
}

// RunGitCommand executes a git command (git-upload-pack or git-receive-pack)
// and streams stdin/stdout bidirectionally with the provided readers/writers
func (c *SSHClient) RunGitCommand(ctx context.Context, cmd string, repoPath string, stdin io.Reader, stdout io.Writer) error {
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// set up pipes
	sessionStdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	sessionStdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	// start the command with properly escaped repo path
	fullCmd := fmt.Sprintf("%s '%s'", cmd, shellEscape(repoPath))
	if err := session.Start(fullCmd); err != nil {
		return fmt.Errorf("start %q: %w", fullCmd, err)
	}

	// bidirectional copy with context cancellation
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// stdin -> session (request body to git command)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer sessionStdin.Close()
		_, err := io.Copy(sessionStdin, stdin)
		if err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("copy to stdin: %w", err)
		}
	}()

	// session -> stdout (git command output to response)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stdout, sessionStdout)
		if err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("copy from stdout: %w", err)
		}
	}()

	// wait for command completion or context cancel
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGTERM)
		return ctx.Err()
	case err := <-done:
		wg.Wait()
		if err != nil {
			return fmt.Errorf("command failed: %w", err)
		}
	}

	// check for copy errors
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// RunGitAdvertiseRefs runs git command with --advertise-refs for info/refs endpoint
func (c *SSHClient) RunGitAdvertiseRefs(ctx context.Context, cmd string, repoPath string, stdout io.Writer) error {
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	sessionStdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	// some git servers support --advertise-refs, others need stateless-rpc
	// try the modern approach first
	fullCmd := fmt.Sprintf("%s --advertise-refs '%s'", cmd, shellEscape(repoPath))
	if err := session.Start(fullCmd); err != nil {
		// fallback: just run the command and read initial refs
		session.Close()
		return c.runGitRefsLegacy(ctx, cmd, repoPath, stdout)
	}

	_, err = io.Copy(stdout, sessionStdout)
	if err != nil {
		return fmt.Errorf("copy stdout: %w", err)
	}

	return session.Wait()
}

// runGitRefsLegacy handles servers without --advertise-refs support
func (c *SSHClient) runGitRefsLegacy(ctx context.Context, cmd string, repoPath string, stdout io.Writer) error {
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	sessionStdin, _ := session.StdinPipe()
	sessionStdout, _ := session.StdoutPipe()

	fullCmd := fmt.Sprintf("%s '%s'", cmd, shellEscape(repoPath))
	if err := session.Start(fullCmd); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	// close stdin immediately to get refs
	sessionStdin.Close()

	_, err = io.Copy(stdout, sessionStdout)
	if err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	return session.Wait()
}

// shellEscape escapes a string for safe use inside single quotes in shell commands.
// It replaces single quotes with the sequence: '\” (end quote, escaped quote, start quote)
func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}
