package adapter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient is the shared transport used by every REST-based adapter
// (Prometheus, Loki, Jaeger's HTTP API, the Kubernetes API server).
//
// Centralising it means auth, TLS policy, timeouts and error formatting behave
// identically across backends — so a 401 from Loki reads the same as a 401 from
// Prometheus, and an operator learns one error format instead of five.
type HTTPClient struct {
	BaseURL string
	Token   string
	client  *http.Client
	// UserAgent identifies lens in backend access logs, which matters when a
	// cluster operator is working out where a burst of queries came from.
	UserAgent string
}

// NewHTTPClient builds a client for one backend.
func NewHTTPClient(baseURL, token string, insecure bool, timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	transport := &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		// A short TLS handshake timeout keeps a black-holed endpoint from
		// eating the entire per-adapter budget.
		TLSHandshakeTimeout: 8 * time.Second,
	}
	if insecure {
		//nolint:gosec // Explicitly opt-in via config; lens warns when enabled.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &HTTPClient{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Token:     token,
		UserAgent: "cncf-lens/" + Version,
		client:    &http.Client{Timeout: timeout, Transport: transport},
	}
}

// Version is stamped at build time via -ldflags.
var Version = "v0.0.2"

// GetJSON performs a GET and decodes the JSON body into out.
func (c *HTTPClient) GetJSON(ctx context.Context, path string, params url.Values, out any) error {
	endpoint := c.BaseURL + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", path, err)
	}
	c.decorate(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return classifyTransportError(c.BaseURL, err)
	}
	defer func() {
		// Drain before close so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return c.httpError(resp, path)
	}

	// Cap the response so a misbehaving or hostile backend cannot exhaust
	// memory on the operator's laptop.
	const maxBody = 64 << 20 // 64 MiB
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBody))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decoding response from %s%s: %w", c.BaseURL, path, err)
	}
	return nil
}

func (c *HTTPClient) decorate(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
}

// httpError turns a non-200 into an actionable message. Generic "unexpected
// status 403" wastes an on-call engineer's time; naming the likely fix does not.
func (c *HTTPClient) httpError(resp *http.Response, path string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	snippet := strings.TrimSpace(string(body))

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s%s: 401 unauthorized — check the backend's token_env or token_file setting", c.BaseURL, path)
	case http.StatusForbidden:
		return fmt.Errorf("%s%s: 403 forbidden — the token is valid but lacks permission for this query", c.BaseURL, path)
	case http.StatusNotFound:
		return fmt.Errorf("%s%s: 404 not found — check the backend `url` points at the API root, not a UI path", c.BaseURL, path)
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return fmt.Errorf("%s%s: backend timed out — try a narrower --since window", c.BaseURL, path)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%s%s: 429 rate limited by the backend", c.BaseURL, path)
	default:
		if snippet != "" {
			return fmt.Errorf("%s%s: HTTP %d: %s", c.BaseURL, path, resp.StatusCode, truncate(snippet, 200))
		}
		return fmt.Errorf("%s%s: HTTP %d", c.BaseURL, path, resp.StatusCode)
	}
}

func classifyTransportError(base string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context deadline exceeded"):
		return fmt.Errorf("%s: timed out — backend unreachable or overloaded", base)
	case strings.Contains(msg, "connection refused"):
		return fmt.Errorf("%s: connection refused — is the service running and port-forwarded?", base)
	case strings.Contains(msg, "no such host"):
		return fmt.Errorf("%s: DNS lookup failed — if this is an in-cluster name, you may need `kubectl port-forward`", base)
	case strings.Contains(msg, "certificate"):
		return fmt.Errorf("%s: TLS verification failed — set `insecure: true` only if you understand the risk", base)
	default:
		return fmt.Errorf("%s: %w", base, err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Ping issues a cheap GET against a health path for HealthCheck implementations.
func (c *HTTPClient) Ping(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	c.decorate(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return classifyTransportError(c.BaseURL, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return c.httpError(resp, path)
	}
	return nil
}
