package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

type ctxKey int

const requestLoggerKey ctxKey = iota

// withRequestLogger stores a logger enriched with the chi request ID in the
// request context so handlers and downstream LLM calls correlate with
// middleware.Logger access logs.
func withRequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := middleware.GetReqID(r.Context())
			enriched := logger
			if id != "" {
				enriched = logger.With("request_id", id)
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestLoggerKey, enriched)))
		})
	}
}

// requestLogger returns the context-bound logger for a request, falling back
// to the server logger when the middleware did not run (tests).
func requestLogger(r *http.Request, fallback *slog.Logger) *slog.Logger {
	if l, ok := r.Context().Value(requestLoggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return fallback
}
