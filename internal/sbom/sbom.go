// Package sbom renders a CycloneDX software bill of materials from the
// inventory mobiscope collected.
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

// SpecVersion is the CycloneDX spec version the document targets.
const SpecVersion = "1.5"

// Document is a CycloneDX bill of materials.
type Document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata describes the subject of the document.
type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     []Tool     `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

// Tool is a tool that produced the document.
type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Component is one piece of software.
type Component struct {
	Type       string     `json:"type"`
	Group      string     `json:"group,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Scope      string     `json:"scope,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// Hash is a checksum of a component.
type Hash struct {
	Algorithm string `json:"alg"`
	Value     string `json:"content"`
}

// Property is a key/value pair attached to a component.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Build renders the bill of materials for a session.
func Build(session *models.AnalysisSession) *Document {
	doc := &Document{
		BOMFormat:   "CycloneDX",
		SpecVersion: SpecVersion,
		Version:     1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{Vendor: "mobiscope", Name: "mobiscope", Version: "1.0.0"},
			},
		},
		Components: []Component{},
	}

	doc.Metadata.Component = &Component{
		Type:    "application",
		Name:    appName(session),
		Version: session.VersionName,
		Scope:   "required",
		Properties: []Property{
			{Name: "mobiscope:package_name", Value: session.PackageName},
			{Name: "mobiscope:apk_sha256", Value: session.APKHash},
			{Name: "mobiscope:signing_cert", Value: session.SigningCertFP},
		},
	}

	// Third-party libraries.
	for _, sdk := range session.App.SDKs {
		comp := Component{
			Type:    "library",
			Group:   sdk.Group,
			Name:    sdk.Artifact,
			Version: sdk.Version,
			Scope:   "required",
		}
		if comp.Name == "" {
			comp.Name = sdk.Name
		}
		comp.PURL = purl(sdk)
		doc.Components = append(doc.Components, comp)
	}

	// Native libraries.
	for _, lib := range session.App.NativeLibs {
		comp := Component{
			Type:    "library",
			Name:    lib.Path,
			Scope:   "required",
			Version: lib.Version,
		}
		if len(lib.Archs) > 0 {
			comp.Properties = append(comp.Properties, Property{
				Name:  "mobiscope:architectures",
				Value: strings.Join(lib.Archs, ","),
			})
		}
		doc.Components = append(doc.Components, comp)
	}

	return doc
}

// JSON renders the document as indented JSON.
func (d *Document) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding SBOM: %w", err)
	}
	return data, nil
}

// purl renders the package URL of a library.
func purl(sdk models.SDK) string {
	if sdk.Group == "" || sdk.Artifact == "" {
		return ""
	}
	p := "pkg:maven/" + sdk.Group + "/" + sdk.Artifact
	if sdk.Version != "" {
		p += "@" + sdk.Version
	}
	return p
}

// appName returns a display name for the analysed app.
func appName(session *models.AnalysisSession) string {
	if session.PackageName != "" {
		return session.PackageName
	}
	if session.App.BundleID != "" {
		return session.App.BundleID
	}
	return "unknown"
}
