// Package api implements the HTTP API for mobiscope.
//
// It provides endpoints for LLM provider management, session chat,
// and analysis orchestration. The API is designed to be consumed by
// the embedded web UI and external clients.
package api

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// JSONError writes an error response with the given status code.
func JSONError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: msg, Code: status})
}

// JSONOK writes a success response.
func JSONOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}
