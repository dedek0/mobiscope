package models

import (
	"encoding/json"
	"time"
)

// AnalysisSession represents a complete APK analysis session.
type AnalysisSession struct {
	ID          string        `json:"id"          validate:"required"`
	APKPath     string        `json:"apk_path"    validate:"required"`
	APKHash     string        `json:"apk_hash"`
	PackageName string        `json:"package_name"`
	VersionName string        `json:"version_name"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt *time.Time    `json:"completed_at,omitempty"`
	Status      SessionStatus `json:"status"`
	ToolResults []ToolResult  `json:"tool_results"`
	Findings    []Finding     `json:"findings"`
	Summary     string        `json:"summary,omitempty"`
}

// SessionStatus represents the current status of an analysis session.
type SessionStatus string

const (
	StatusPending   SessionStatus = "pending"
	StatusRunning   SessionStatus = "running"
	StatusCompleted SessionStatus = "completed"
	StatusFailed    SessionStatus = "failed"
)

// ToolResult represents the output of an external analysis tool.
type ToolResult struct {
	ToolName  string          `json:"tool_name"  validate:"required"`
	Version   string          `json:"version"`
	StartedAt time.Time       `json:"started_at"`
	Duration  time.Duration   `json:"duration"`
	ExitCode  int             `json:"exit_code"`
	Output    json.RawMessage `json:"output"`
	Error     string          `json:"error,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for AnalysisSession.
func (s AnalysisSession) MarshalJSON() ([]byte, error) {
	type Alias AnalysisSession
	return json.Marshal(&struct {
		Alias
		StartedAt   string  `json:"started_at"`
		CompletedAt *string `json:"completed_at,omitempty"`
	}{
		Alias:       Alias(s),
		StartedAt:   s.StartedAt.Format(time.RFC3339),
		CompletedAt: timePtrToString(s.CompletedAt),
	})
}

func timePtrToString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}
