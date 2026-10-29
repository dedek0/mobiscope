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
	// FailedTools lists the tools that errored during the run. A non-empty
	// list means the report is partial even when the status is completed.
	FailedTools []string `json:"failed_tools,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	// LLMCostUSD is the cumulative cost of LLM triage for this session (0
	// when triage did not run).
	LLMCostUSD float64 `json:"llm_cost_usd,omitempty"`
}

// SessionStatus represents the current status of an analysis session.
type SessionStatus string

const (
	StatusPending   SessionStatus = "pending"
	StatusRunning   SessionStatus = "running"
	StatusCompleted SessionStatus = "completed"
	// StatusPartial marks a session that finished every stage it could run
	// but at least one tool failed. The report is usable but incomplete.
	StatusPartial SessionStatus = "partial"
	StatusFailed  SessionStatus = "failed"
)

// IsTerminal reports whether the session reached a final state.
func (s SessionStatus) IsTerminal() bool {
	switch s {
	case StatusCompleted, StatusPartial, StatusFailed:
		return true
	case StatusPending, StatusRunning:
		return false
	default:
		return false
	}
}

// ToolResult represents the output of an external analysis tool.
type ToolResult struct {
	ToolName  string          `json:"tool_name"  validate:"required"`
	Version   string          `json:"version"`
	StartedAt time.Time       `json:"started_at"`
	Duration  time.Duration   `json:"-"`
	ExitCode  int             `json:"exit_code"`
	TimedOut  bool            `json:"timed_out,omitempty"`
	Output    json.RawMessage `json:"output"`
	Error     string          `json:"error,omitempty"`
}

// MarshalJSON emits Duration as a human-readable string ("1.234s") instead
// of raw nanoseconds, and never lets an empty or invalid Output break
// serialization of the whole session.
func (tr ToolResult) MarshalJSON() ([]byte, error) {
	type alias ToolResult
	return json.Marshal(&struct {
		alias
		Duration string          `json:"duration"`
		Output   json.RawMessage `json:"output"`
	}{
		alias:    alias(tr),
		Duration: tr.Duration.String(),
		Output:   safeRaw(tr.Output),
	})
}

// safeRaw returns r when it is valid JSON, or JSON null otherwise. RawMessage
// with empty or truncated content makes json.Marshal fail, which would take
// the whole AnalysisSession down with it.
func safeRaw(r json.RawMessage) json.RawMessage {
	if len(r) == 0 || !json.Valid(r) {
		return json.RawMessage("null")
	}
	return r
}

func (tr *ToolResult) UnmarshalJSON(data []byte) error {
	type alias ToolResult
	aux := &struct {
		*alias
		Duration json.RawMessage `json:"duration"`
	}{alias: (*alias)(tr)}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	if len(aux.Duration) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(aux.Duration, &s); err == nil {
		d, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		tr.Duration = d
		return nil
	}
	var n int64
	if err := json.Unmarshal(aux.Duration, &n); err != nil {
		return err
	}
	tr.Duration = time.Duration(n)
	return nil
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
	// URLCount is the total number of generic http(s) URL matches found in
	// scanned sources; URLs is a bounded unique sample (Android only).
	URLCount int      `json:"url_count,omitempty"`
	URLs     []string `json:"urls,omitempty"`
	// SDKs lists the third-party libraries detected in the app.
	SDKs []SDK `json:"sdks,omitempty"`
	// Vulnerabilities lists the known vulnerabilities found for the
	// detected SDKs. It is only populated when the OSV lookup is enabled.
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// SDK is a third-party library detected in the app.
type SDK struct {
	// Name is the human-readable name of the library.
	Name string `json:"name"`
	// Group is the vendor or Maven group id.
	Group string `json:"group,omitempty"`
	// Artifact is the library name inside the group.
	Artifact string `json:"artifact,omitempty"`
	// Version is the detected version, when one could be recovered.
	Version string `json:"version,omitempty"`
	// Package is the full package coordinate, e.g.
	// "com.google.code.gson:gson".
	Package string `json:"package,omitempty"`
	// Evidence is the class or resource that identified the library.
	Evidence string `json:"evidence,omitempty"`
	// Confidence is how sure the detection is.
	Confidence float64 `json:"confidence"`
}

// Vulnerability is a known vulnerability affecting a detected SDK.
type Vulnerability struct {
	// ID is the advisory identifier (for example a GHSA id).
	ID string `json:"id"`
	// Summary is the advisory title.
	Summary string `json:"summary,omitempty"`
	// Severity is the advisory severity, when the database reports one.
	Severity string `json:"severity,omitempty"`
	// Package is the affected package.
	Package string `json:"package"`
	// Version is the affected version, when known.
	Version string `json:"version,omitempty"`
	// FixedIn lists the versions that carry the fix.
	FixedIn []string `json:"fixed_in,omitempty"`
	// Aliases lists the other identifiers of the advisory.
	Aliases []string `json:"aliases,omitempty"`
	// Reference is the advisory URL.
	Reference string `json:"reference,omitempty"`
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

	// Hardening facts. The pointers are nil when the property could not be
	// determined (stripped binary, unusual layout), which is different from
	// "absent".
	PIE         *bool  `json:"pie,omitempty"`
	RELRO       string `json:"relro,omitempty"` // full | partial | none
	NX          *bool  `json:"nx,omitempty"`
	StackCanary *bool  `json:"stack_canary,omitempty"`
	Fortify     *bool  `json:"fortify,omitempty"`
	Stripped    bool   `json:"stripped,omitempty"`
	TextRelocs  bool   `json:"text_relocs,omitempty"`
	HasRPath    bool   `json:"has_rpath,omitempty"`
	// JNIExports lists the Java_* symbols the library exposes.
	JNIExports []string `json:"jni_exports,omitempty"`
	// AntiAnalysis lists the instrumentation and anti-debug markers found
	// in the binary's strings.
	AntiAnalysis []string `json:"anti_analysis,omitempty"`
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
