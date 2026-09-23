package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// AnalysisSession represents a complete APK analysis session.
type AnalysisSession struct {
	ID              string        `json:"id"          validate:"required"`
	APKPath         string        `json:"apk_path"    validate:"required"`
	APKHash         string        `json:"apk_hash"`
	Platform        Platform      `json:"platform"`
	PackageName     string        `json:"package_name"`
	VersionName     string        `json:"version_name"`
	App             AppInventory  `json:"app,omitempty"`
	SigningCertFP   string        `json:"signing_cert_fp,omitempty"`
	SignatureScheme string        `json:"signature_scheme,omitempty"`
	StartedAt       time.Time     `json:"started_at"`
	CompletedAt     *time.Time    `json:"completed_at,omitempty"`
	Status          SessionStatus `json:"status"`
	ToolResults     []ToolResult  `json:"tool_results"`
	Findings        []Finding     `json:"findings"`
	Summary         string        `json:"summary,omitempty"`
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

// UnmarshalJSON implements custom JSON unmarshaling for AnalysisSession,
// mirroring MarshalJSON's RFC3339 timestamp handling so sessions round-trip.
func (s *AnalysisSession) UnmarshalJSON(data []byte) error {
	type Alias AnalysisSession
	aux := &struct {
		*Alias
		StartedAt   string  `json:"started_at"`
		CompletedAt *string `json:"completed_at"`
	}{Alias: (*Alias)(s)}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if aux.StartedAt != "" {
		t, err := time.Parse(time.RFC3339, aux.StartedAt)
		if err != nil {
			return fmt.Errorf("parsing started_at: %w", err)
		}
		s.StartedAt = t
	}
	if aux.CompletedAt != nil && *aux.CompletedAt != "" {
		t, err := time.Parse(time.RFC3339, *aux.CompletedAt)
		if err != nil {
			return fmt.Errorf("parsing completed_at: %w", err)
		}
		s.CompletedAt = &t
	}
	return nil
}

func timePtrToString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

// AppInventory holds neutral facts about the analyzed app. Findings carry
// risk; these are observations that inform reports without being findings.
type AppInventory struct {
	BundleID     string            `json:"bundle_id,omitempty"`
	VersionName  string            `json:"version_name,omitempty"`
	VersionCode  string            `json:"version_code,omitempty"`
	MinOS        string            `json:"min_os,omitempty"`
	TargetSDK    string            `json:"target_sdk,omitempty"`
	Debuggable   bool              `json:"debuggable,omitempty"`
	Obfuscation  ObfuscationInfo   `json:"obfuscation,omitempty"`
	NativeLibs   []NativeLib       `json:"native_libs,omitempty"`
	Network      NetworkPolicy     `json:"network,omitempty"`
	Entitlements map[string]string `json:"entitlements,omitempty"`
	URLSchemes   []string          `json:"url_schemes,omitempty"`
	Permissions  []string          `json:"permissions,omitempty"`
}

// ObfuscationInfo records code-obfuscation signals and a 0..1 score.
type ObfuscationInfo struct {
	Android    bool     `json:"android,omitempty"`
	IOS        bool     `json:"ios,omitempty"`
	Stripped   bool     `json:"stripped,omitempty"`
	Score      float64  `json:"score,omitempty"`
	Indicators []string `json:"indicators,omitempty"`
}

// NativeLib describes one native binary shipped in the app.
type NativeLib struct {
	Path        string   `json:"path"`
	Kind        string   `json:"kind"` // so | dylib | framework | static_archive | main_binary
	Archs       []string `json:"archs,omitempty"`
	Encrypted   bool     `json:"encrypted,omitempty"`
	InstallName string   `json:"install_name,omitempty"`
	Linked      []string `json:"linked,omitempty"`
	Version     string   `json:"version,omitempty"`
}

// NetworkPolicy summarizes the app's network security posture.
type NetworkPolicy struct {
	Kind               string             `json:"kind"` // network_security_config | NSAppTransportSecurity
	CleartextPermitted bool               `json:"cleartext_permitted,omitempty"`
	LocalNetworkAllow  bool               `json:"local_network_allow,omitempty"`
	Pinned             bool               `json:"pinned,omitempty"`
	Exceptions         []NetworkException `json:"exceptions,omitempty"`
	Raw                string             `json:"raw,omitempty"`
}

// NetworkException is one domain-scoped relaxation of the network policy.
type NetworkException struct {
	Domain             string `json:"domain"`
	IncludesSubdomains bool   `json:"includes_subdomains,omitempty"`
	InsecureHTTPLoads  bool   `json:"insecure_http_loads,omitempty"`
	TLSMinVersion      string `json:"tls_min_version,omitempty"`
}
