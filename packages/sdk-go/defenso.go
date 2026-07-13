// Package defenso is a fail-open Defenso middleware for Go net/http-based frameworks.
//
// Alpha scaffold. Talks to https://app.defen.so/api/policy and .../attacks/ingest.
// Never blocks a request when Defenso is unreachable.
package defenso

import (
	"net/http"
	"os"
)

// Config controls Defenso middleware behavior.
type Config struct {
	Token  string
	APIURL string // defaults to https://app.defen.so
}

// Middleware returns a net/http middleware. Alpha: pass-through.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.Token == "" {
		cfg.Token = os.Getenv("DEFENSO_TOKEN")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://app.defen.so"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: policy check + async attack-log ingest
			next.ServeHTTP(w, r)
		})
	}
}
