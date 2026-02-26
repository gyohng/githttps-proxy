package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// lfsAuthResponse is the response from `git-lfs-authenticate`
type lfsAuthResponse struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	ExpiresIn int               `json:"expires_in,omitempty"`
}

// lfsCachedAction stores the original upstream URL and auth for an LFS object action
type lfsCachedAction struct {
	Href      string
	Header    map[string]string
	ExpiresAt time.Time
}

// lfsObjectCache maps "host:repo:oid:action" -> cached upstream URL+auth
type lfsObjectCache struct {
	mu    sync.RWMutex
	items map[string]*lfsCachedAction
}

var lfsCache = &lfsObjectCache{
	items: make(map[string]*lfsCachedAction),
}

func lfsCacheKey(target *SSHTarget, oid, action string) string {
	return target.Host + ":" + target.RepoPath + ":" + oid + ":" + action
}

func (c *lfsObjectCache) Put(key string, action *lfsCachedAction) {
	c.mu.Lock()
	c.items[key] = action
	c.mu.Unlock()
}

func (c *lfsObjectCache) Get(key string) (*lfsCachedAction, bool) {
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()
	if ok && !item.ExpiresAt.IsZero() && time.Now().After(item.ExpiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return nil, false
	}
	return item, ok
}

// Sweep removes expired entries (called periodically)
func (c *lfsObjectCache) Sweep() {
	c.mu.Lock()
	now := time.Now()
	for key, item := range c.items {
		if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
			delete(c.items, key)
		}
	}
	c.mu.Unlock()
}

func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			lfsCache.Sweep()
		}
	}()
}

// lfsHTTPClient is a shared HTTP client for LFS proxy requests
var lfsHTTPClient = &http.Client{
	Timeout: 10 * time.Minute,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{},
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// lfsBatchRequest is the LFS batch API request body
type lfsBatchRequest struct {
	Operation string          `json:"operation"`
	Transfers []string        `json:"transfers,omitempty"`
	Ref       json.RawMessage `json:"ref,omitempty"`
	Objects   []lfsBatchObj   `json:"objects"`
	HashAlgo  string          `json:"hash_algo,omitempty"`
}

type lfsBatchObj struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// lfsBatchResponse is the LFS batch API response body
type lfsBatchResponse struct {
	Transfer string              `json:"transfer,omitempty"`
	Objects  []lfsBatchRespObj   `json:"objects"`
	HashAlgo string              `json:"hash_algo,omitempty"`
}

type lfsBatchRespObj struct {
	OID           string                       `json:"oid"`
	Size          int64                        `json:"size"`
	Authenticated *bool                        `json:"authenticated,omitempty"`
	Actions       map[string]*lfsBatchAction   `json:"actions,omitempty"`
	Error         *lfsBatchObjError            `json:"error,omitempty"`
}

type lfsBatchAction struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	ExpiresIn int               `json:"expires_in,omitempty"`
}

type lfsBatchObjError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// handleLFS proxies LFS API requests to the upstream server.
// It uses SSH `git-lfs-authenticate` to obtain temporary HTTPS credentials,
// then forwards the request to the upstream's HTTPS LFS endpoint.
// For batch requests, it rewrites download/upload URLs to point back through the proxy.
func (h *GitHandler) handleLFS(w http.ResponseWriter, r *http.Request, target *SSHTarget, signer ssh.Signer, lfsPath string) {
	h.log.Info("lfs request",
		"target", target.String(),
		"path", lfsPath,
		"method", r.Method,
	)

	// check if this is an object transfer request (cached from a prior batch response)
	if h.tryLFSObjectProxy(w, r, target, lfsPath) {
		return
	}

	// determine LFS operation from the request
	lfsOp := "download"
	var bodyBytes []byte

	if strings.HasSuffix(lfsPath, "/objects/batch") && r.Method == http.MethodPost {
		// read body to determine operation and to forward it
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			h.log.Error("lfs read body", "error", err)
			lfsError(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		var batchReq lfsBatchRequest
		if err := json.Unmarshal(bodyBytes, &batchReq); err == nil && batchReq.Operation != "" {
			lfsOp = batchReq.Operation
		}
	} else if r.Method == http.MethodPut {
		lfsOp = "upload"
	}

	// get LFS auth via SSH
	auth, err := h.lfsAuthenticate(r.Context(), target, signer, lfsOp)
	if err != nil {
		h.log.Error("lfs authenticate", "error", err)
		lfsError(w, "LFS authentication failed", http.StatusBadGateway)
		return
	}

	// build upstream URL
	subPath := strings.TrimPrefix(lfsPath, "/info/lfs")
	upstreamURL := strings.TrimRight(auth.Href, "/") + subPath

	h.log.Info("lfs proxy",
		"upstream", upstreamURL,
		"method", r.Method,
		"operation", lfsOp,
	)

	// create upstream request
	var body io.Reader
	if bodyBytes != nil {
		body = bytes.NewReader(bodyBytes)
	} else if r.Body != nil {
		body = r.Body
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, body)
	if err != nil {
		h.log.Error("lfs create request", "error", err)
		lfsError(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// copy relevant headers
	if ct := r.Header.Get("Content-Type"); ct != "" {
		upstreamReq.Header.Set("Content-Type", ct)
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		upstreamReq.Header.Set("Accept", accept)
	}

	// set auth headers from git-lfs-authenticate
	for key, value := range auth.Header {
		upstreamReq.Header.Set(key, value)
	}

	// forward the request
	resp, err := lfsHTTPClient.Do(upstreamReq)
	if err != nil {
		h.log.Error("lfs upstream request", "error", err)
		lfsError(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// for batch responses, rewrite URLs to point through our proxy
	if strings.HasSuffix(lfsPath, "/objects/batch") && resp.StatusCode == http.StatusOK {
		h.rewriteLFSBatchResponse(w, r, resp, target)
		return
	}

	// for non-batch responses, pass through as-is
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// rewriteLFSBatchResponse rewrites download/upload URLs in a batch response
// to point back through our proxy, and caches the original URLs.
func (h *GitHandler) rewriteLFSBatchResponse(w http.ResponseWriter, r *http.Request, resp *http.Response, target *SSHTarget) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.log.Error("lfs read batch response", "error", err)
		lfsError(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	var batchResp lfsBatchResponse
	if err := json.Unmarshal(respBody, &batchResp); err != nil {
		h.log.Error("lfs parse batch response", "error", err)
		// return raw response if we can't parse it
		for key, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// build the base proxy URL from the incoming request
	scheme := "https"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS == nil {
		scheme = "http"
	}
	// use the Host header from the original request
	proxyBase := fmt.Sprintf("%s://%s/%s/info/lfs/objects", scheme, r.Host, target.String())

	// rewrite each object's action URLs
	for i := range batchResp.Objects {
		obj := &batchResp.Objects[i]
		if obj.Actions == nil {
			continue
		}

		for actionName, action := range obj.Actions {
			if action.Href == "" {
				continue
			}

			// calculate expiration
			var expiresAt time.Time
			if action.ExpiresAt != "" {
				if t, err := time.Parse(time.RFC3339, action.ExpiresAt); err == nil {
					expiresAt = t
				}
			} else if action.ExpiresIn > 0 {
				expiresAt = time.Now().Add(time.Duration(action.ExpiresIn) * time.Second)
			} else {
				// default: expire in 1 hour
				expiresAt = time.Now().Add(1 * time.Hour)
			}

			// cache the original URL + auth
			cacheKey := lfsCacheKey(target, obj.OID, actionName)
			lfsCache.Put(cacheKey, &lfsCachedAction{
				Href:      action.Href,
				Header:    action.Header,
				ExpiresAt: expiresAt,
			})

			// rewrite URL to point through proxy
			action.Href = fmt.Sprintf("%s/%s", proxyBase, obj.OID)
			// clear original auth headers - the client will use its proxy credentials instead
			action.Header = nil

			h.log.Debug("lfs rewrite",
				"oid", obj.OID,
				"action", actionName,
				"proxy_url", action.Href,
			)
		}
	}

	// serialize and send rewritten response
	rewritten, err := json.Marshal(batchResp)
	if err != nil {
		h.log.Error("lfs marshal batch response", "error", err)
		lfsError(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
	w.WriteHeader(http.StatusOK)
	w.Write(rewritten)
}

// tryLFSObjectProxy handles direct object download/upload requests
// by looking up the cached upstream URL from a prior batch response.
// Returns true if the request was handled.
func (h *GitHandler) tryLFSObjectProxy(w http.ResponseWriter, r *http.Request, target *SSHTarget, lfsPath string) bool {
	// match paths like /info/lfs/objects/<oid> (64 hex chars for sha256)
	const objectsPrefix = "/info/lfs/objects/"
	if !strings.HasPrefix(lfsPath, objectsPrefix) {
		return false
	}

	remainder := strings.TrimPrefix(lfsPath, objectsPrefix)

	// skip batch endpoint and verify/lock endpoints
	if strings.Contains(remainder, "/") {
		return false
	}

	oid := remainder
	if len(oid) < 64 {
		return false
	}

	// determine action based on HTTP method
	action := "download"
	if r.Method == http.MethodPut {
		action = "upload"
	}

	cacheKey := lfsCacheKey(target, oid, action)
	cached, ok := lfsCache.Get(cacheKey)
	if !ok {
		h.log.Warn("lfs object cache miss",
			"oid", oid,
			"action", action,
			"target", target.String(),
		)
		return false
	}

	h.log.Info("lfs object proxy",
		"oid", oid[:12]+"...",
		"action", action,
		"upstream", cached.Href,
	)

	// proxy to cached upstream URL
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, cached.Href, r.Body)
	if err != nil {
		h.log.Error("lfs object create request", "error", err)
		lfsError(w, "failed to create upstream request", http.StatusInternalServerError)
		return true
	}

	// set cached auth headers
	for key, value := range cached.Header {
		upstreamReq.Header.Set(key, value)
	}

	// copy content headers for uploads
	if r.Method == http.MethodPut {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			upstreamReq.Header.Set("Content-Type", ct)
		}
		if cl := r.Header.Get("Content-Length"); cl != "" {
			upstreamReq.Header.Set("Content-Length", cl)
		}
	}

	resp, err := lfsHTTPClient.Do(upstreamReq)
	if err != nil {
		h.log.Error("lfs object upstream request", "error", err)
		lfsError(w, "upstream request failed", http.StatusBadGateway)
		return true
	}
	defer resp.Body.Close()

	// pass through response
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return true
}

// lfsAuthenticate runs `git-lfs-authenticate <repo> <operation>` via SSH
// to obtain temporary HTTPS credentials for LFS operations.
func (h *GitHandler) lfsAuthenticate(ctx context.Context, target *SSHTarget, signer ssh.Signer, operation string) (*lfsAuthResponse, error) {
	client, err := DialSSH(ctx, target.Host, target.User, signer)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	session, err := client.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf("git-lfs-authenticate '%s' %s", shellEscape(target.RepoPath), operation)

	var stdout bytes.Buffer
	var stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(cmd); err != nil {
		stderrMsg := strings.TrimSpace(stderr.String())
		if stderrMsg != "" {
			return nil, fmt.Errorf("git-lfs-authenticate failed: %w: %s", err, stderrMsg)
		}
		return nil, fmt.Errorf("git-lfs-authenticate failed: %w", err)
	}

	var auth lfsAuthResponse
	if err := json.Unmarshal(stdout.Bytes(), &auth); err != nil {
		return nil, fmt.Errorf("parse lfs auth response: %w (raw: %s)", err, stdout.String())
	}

	if auth.Href == "" {
		return nil, fmt.Errorf("lfs auth response missing href (raw: %s)", stdout.String())
	}

	return &auth, nil
}

// lfsError sends a properly formatted LFS error response
func lfsError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"message": message,
	})
}
