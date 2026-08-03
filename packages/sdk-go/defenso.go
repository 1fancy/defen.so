// Package defenso is a fail-open Defenso WAF middleware for Go net/http-based
// frameworks (chi, echo, standard net/http; gin via a thin adapter).
//
// Design (mirrors the Node / PHP / Python SDKs):
//   - Fails open. If Defenso is unreachable or slow, the request is allowed.
//   - Policy is cached. Rules are pulled in the background and evaluated
//     locally; the request path never blocks on a network call.
//   - Logs are fire-and-forget. Block events are queued and flushed async.
package defenso

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config controls Defenso middleware behavior.
type Config struct {
	Token         string
	APIURL        string        // defaults to https://app.defen.so/api
	PolicyRefresh time.Duration // defaults to 5m
	Timeout       time.Duration // per policy/log call, defaults to 1s
}

type rule struct {
	id       string
	action   string
	target   string
	category string
	re       *regexp.Regexp
}

type policyResponse struct {
	Version string `json:"version"`
	Rules   []struct {
		ID       string `json:"id"`
		Pattern  string `json:"pattern"`
		Flags    string `json:"flags"`
		Target   string `json:"target"`
		Action   string `json:"action"`
		Category string `json:"category"`
	} `json:"rules"`
}

type client struct {
	cfg    Config
	mu     sync.RWMutex
	rules  []rule
	logMu  sync.Mutex
	queue  []map[string]any
	client *http.Client
}

// Middleware returns a net/http middleware that inspects each request against
// the cached Defenso policy and blocks matches with a 403. It never blocks when
// Defenso is unreachable.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.Token == "" {
		cfg.Token = os.Getenv("DEFENSO_TOKEN")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://app.defen.so/api"
	}
	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	if cfg.PolicyRefresh == 0 {
		cfg.PolicyRefresh = 5 * time.Minute
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = time.Second
	}

	c := &client{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}}
	if cfg.Token != "" {
		go c.refreshLoop()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Token == "" {
				next.ServeHTTP(w, r)
				return
			}
			if m := c.evaluate(r); m != nil && m.action == "block" {
				c.queueLog(m, r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Request blocked by Defenso", "rule": m.id})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (c *client) refreshLoop() {
	for {
		c.refreshOnce()
		time.Sleep(c.cfg.PolicyRefresh)
	}
}

func (c *client) refreshOnce() {
	// Fail open on any error: keep the last-known-good rules.
	defer func() { _ = recover() }()
	req, err := http.NewRequest(http.MethodGet, c.cfg.APIURL+"/policy", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var p policyResponse
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return
	}
	compiled := make([]rule, 0, len(p.Rules))
	for _, r := range p.Rules {
		pat := r.Pattern
		if strings.Contains(r.Flags, "i") {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			continue // skip a bad rule, never fatal
		}
		compiled = append(compiled, rule{id: r.ID, action: r.Action, target: r.Target, category: r.Category, re: re})
	}
	c.mu.Lock()
	c.rules = compiled
	c.mu.Unlock()
}

func (c *client) evaluate(r *http.Request) *rule {
	c.mu.RLock()
	rules := c.rules
	c.mu.RUnlock()
	query := r.URL.RawQuery
	headers := headerString(r)
	for i := range rules {
		var hay string
		switch rules[i].target {
		case "url":
			hay = r.URL.Path
		case "headers":
			hay = headers
		case "query", "":
			hay = query
		default:
			// Body inspection is not done in-process (it would require
			// buffering the request body); skip rather than mis-match a
			// body-target rule against the query string.
			continue
		}
		if hay != "" && rules[i].re.MatchString(hay) {
			return &rules[i]
		}
	}
	return nil
}

func headerString(r *http.Request) string {
	var b strings.Builder
	for k, v := range r.Header {
		b.WriteString(k)
		b.WriteString(":")
		b.WriteString(strings.Join(v, ","))
		b.WriteString(" ")
	}
	return b.String()
}

func (c *client) queueLog(m *rule, r *http.Request) {
	entry := map[string]any{
		"at":      time.Now().Unix(),
		"verdict": map[string]any{"action": "block", "rule": map[string]any{"id": m.id}, "reason": m.category},
		"request": map[string]any{"method": r.Method, "url": r.URL.String(), "ip": clientIP(r)},
	}
	c.logMu.Lock()
	c.queue = append(c.queue, entry)
	var batch []map[string]any
	if len(c.queue) >= 25 {
		batch, c.queue = c.queue, nil
	}
	c.logMu.Unlock()
	if batch != nil {
		go c.flush(batch)
	}
}

func (c *client) flush(batch []map[string]any) {
	defer func() { _ = recover() }()
	body, err := json.Marshal(map[string]any{"logs": batch})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, c.cfg.APIURL+"/attacks/ingest", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.TrimSpace(strings.Split(ip, ",")[0])
	}
	return r.RemoteAddr
}
