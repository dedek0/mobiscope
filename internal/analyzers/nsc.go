package analyzers

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

// nscPolicy is the structured form of an Android network security config.
type nscPolicy struct {
	// BaseCleartext is set when the base-config explicitly permits cleartext.
	BaseCleartext bool
	// BaseCleartextSet records whether the attribute was present, so a
	// missing attribute is not confused with an explicit false.
	BaseCleartextSet bool
	Domains          []nscDomainPolicy
	Pinned           bool
	PinSets          []nscPinSet
	CustomAnchors    bool
	OverridePins     bool
	DebugOverrides   bool
}

// nscDomainPolicy is one <domain-config>.
type nscDomainPolicy struct {
	Domain             string
	IncludesSubdomains bool
	Cleartext          bool
	CleartextSet       bool
	CustomAnchors      bool
}

// nscPinSet is one <pin-set>.
type nscPinSet struct {
	Domain     string
	Expiration string
}

// XML shapes for a decoded network security config.
type nscXMLConfig struct {
	XMLName xml.Name          `xml:"network-security-config"`
	Base    *nscXMLBase       `xml:"base-config"`
	Domains []nscXMLDomainCfg `xml:"domain-config"`
	Debug   *nscXMLBase       `xml:"debug-overrides"`
}

type nscXMLBase struct {
	Cleartext string         `xml:"cleartextTrafficPermitted,attr"`
	Override  string         `xml:"overridePins,attr"`
	Trust     *nscXMLTrust   `xml:"trust-anchors"`
	PinSets   []nscXMLPinSet `xml:"pin-set"`
}

type nscXMLTrust struct {
	Certificates []nscXMLCert `xml:"certificates"`
}

type nscXMLCert struct {
	Src string `xml:"src,attr"`
}

type nscXMLPinSet struct {
	Expiration string `xml:"expiration,attr"`
	// Override is not a documented pin-set attribute, but it is found in
	// the wild (and in older fixtures); accept it wherever it appears.
	Override string `xml:"overridePins,attr"`
}

type nscXMLDomainCfg struct {
	Cleartext string         `xml:"cleartextTrafficPermitted,attr"`
	Override  string         `xml:"overridePins,attr"`
	Trust     *nscXMLTrust   `xml:"trust-anchors"`
	PinSets   []nscXMLPinSet `xml:"pin-set"`
	Domains   []nscXMLDomain `xml:"domain"`
}

type nscXMLDomain struct {
	IncludeSubdomains string `xml:"includeSubdomains,attr"`
	Name              string `xml:",chardata"`
}

// parseNSCPolicy decodes a network security config from either decoded XML or
// compiled binary XML. resolve is only used for the binary form.
func parseNSCPolicy(data []byte, resolve func(uint32) (string, bool)) (*nscPolicy, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty network security config")
	}
	if len(data) >= 2 && binary.LittleEndian.Uint16(data) == axmlChunkXML {
		root, err := parseAXML(data, resolve)
		if err != nil {
			return nil, err
		}
		return nscPolicyFromAXML(root), nil
	}

	var cfg nscXMLConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decoding network security config: %w", err)
	}
	p := &nscPolicy{}
	if cfg.Base != nil {
		p.BaseCleartext, p.BaseCleartextSet = parseBoolAttr(cfg.Base.Cleartext)
		p.OverridePins = strings.EqualFold(cfg.Base.Override, "true")
		p.CustomAnchors = customTrustAnchors(cfg.Base.Trust)
		p.Pinned = len(cfg.Base.PinSets) > 0
		for _, ps := range cfg.Base.PinSets {
			if strings.EqualFold(ps.Override, "true") {
				p.OverridePins = true
			}
			p.PinSets = append(p.PinSets, nscPinSet{Expiration: ps.Expiration})
		}
	}
	p.DebugOverrides = cfg.Debug != nil
	for _, dc := range cfg.Domains {
		if strings.EqualFold(dc.Override, "true") {
			p.OverridePins = true
		}
		custom := customTrustAnchors(dc.Trust)
		if custom {
			p.CustomAnchors = true
		}
		if len(dc.PinSets) > 0 {
			p.Pinned = true
			// A domain-config without <domain> children applies its
			// pin-set globally; with domains, each domain gets its own
			// entry below.
			if len(dc.Domains) == 0 {
				for _, ps := range dc.PinSets {
					if strings.EqualFold(ps.Override, "true") {
						p.OverridePins = true
					}
					p.PinSets = append(p.PinSets, nscPinSet{Expiration: ps.Expiration})
				}
			}
			for _, ps := range dc.PinSets {
				if strings.EqualFold(ps.Override, "true") {
					p.OverridePins = true
				}
			}
		}
		for _, d := range dc.Domains {
			name := strings.TrimSpace(d.Name)
			if name == "" {
				continue
			}
			domain := nscDomainPolicy{
				Domain:             name,
				IncludesSubdomains: strings.EqualFold(d.IncludeSubdomains, "true"),
				CustomAnchors:      custom,
			}
			domain.Cleartext, domain.CleartextSet = parseBoolAttr(dc.Cleartext)
			for _, ps := range dc.PinSets {
				p.PinSets = append(p.PinSets, nscPinSet{Domain: name, Expiration: ps.Expiration})
			}
			p.Domains = append(p.Domains, domain)
		}
	}
	return p, nil
}

// nscPolicyFromAXML converts a decoded binary-XML tree into an nscPolicy.
func nscPolicyFromAXML(root *axmlNode) *nscPolicy {
	p := &nscPolicy{}
	if root == nil {
		return p
	}
	applyNSCNode(p, root, "")
	return p
}

// applyNSCNode reads the base-config attributes and pin/trust children of one
// node, and recurses into domain-config elements.
func applyNSCNode(p *nscPolicy, node *axmlNode, domain string) {
	if node == nil {
		return
	}
	if attr, ok := node.Attr("cleartextTrafficPermitted"); ok {
		v, set := parseBoolAttr(attr)
		if domain == "" && node.Name == "base-config" {
			p.BaseCleartext, p.BaseCleartextSet = v, set
		}
	}
	if attr, ok := node.Attr("overridePins"); ok && strings.EqualFold(attr, "true") {
		p.OverridePins = true
	}
	for _, child := range node.Children {
		switch child.Name {
		case "trust-anchors":
			if customTrustAnchorsAXML(child) {
				p.CustomAnchors = true
			}
		case "pin-set":
			exp, _ := child.Attr("expiration")
			if override, _ := child.Attr("overridePins"); strings.EqualFold(override, "true") {
				p.OverridePins = true
			}
			p.Pinned = true
			p.PinSets = append(p.PinSets, nscPinSet{Domain: domain, Expiration: exp})
		case "debug-overrides":
			p.DebugOverrides = true
		case "base-config":
			applyNSCNode(p, child, "")
		case "domain-config":
			cleartext, cleartextSet := false, false
			if attr, ok := child.Attr("cleartextTrafficPermitted"); ok {
				cleartext, cleartextSet = parseBoolAttr(attr)
			}
			custom := false
			for _, dc := range child.Children {
				if dc.Name == "trust-anchors" && customTrustAnchorsAXML(dc) {
					custom = true
					p.CustomAnchors = true
				}
			}
			if attr, ok := child.Attr("overridePins"); ok && strings.EqualFold(attr, "true") {
				p.OverridePins = true
			}
			for _, dc := range child.Children {
				if dc.Name != "domain" {
					continue
				}
				name := strings.TrimSpace(dc.Text)
				if name == "" {
					continue
				}
				include, _ := dc.Attr("includeSubdomains")
				p.Domains = append(p.Domains, nscDomainPolicy{
					Domain:             name,
					IncludesSubdomains: strings.EqualFold(include, "true"),
					Cleartext:          cleartext,
					CleartextSet:       cleartextSet,
					CustomAnchors:      custom,
				})
			}
			for _, dc := range child.Children {
				if dc.Name != "pin-set" {
					continue
				}
				exp, _ := dc.Attr("expiration")
				if override, _ := dc.Attr("overridePins"); strings.EqualFold(override, "true") {
					p.OverridePins = true
				}
				p.Pinned = true
				added := false
				for _, d := range child.Children {
					if d.Name == "domain" {
						if name := strings.TrimSpace(d.Text); name != "" {
							p.PinSets = append(p.PinSets, nscPinSet{Domain: name, Expiration: exp})
							added = true
						}
					}
				}
				if !added {
					p.PinSets = append(p.PinSets, nscPinSet{Expiration: exp})
				}
			}
		}
	}
}

// customTrustAnchors reports whether a decoded trust-anchors block lists a
// non-system certificate source.
func customTrustAnchors(t *nscXMLTrust) bool {
	if t == nil {
		return false
	}
	for _, c := range t.Certificates {
		if isCustomAnchorSource(c.Src) {
			return true
		}
	}
	return false
}

// customTrustAnchorsAXML is the binary-XML counterpart of customTrustAnchors.
func customTrustAnchorsAXML(node *axmlNode) bool {
	for _, c := range node.Children {
		if c.Name != "certificates" {
			continue
		}
		src, _ := c.Attr("src")
		if isCustomAnchorSource(src) {
			return true
		}
	}
	return false
}

// isCustomAnchorSource reports whether a certificates src weakens the default
// system trust store.
func isCustomAnchorSource(src string) bool {
	src = strings.TrimSpace(src)
	return src == "user" || src == "*" || strings.HasPrefix(src, "@")
}

func parseBoolAttr(v string) (bool, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return false, false
	}
	return strings.EqualFold(v, "true"), true
}

// nscFindings turns a parsed policy into findings. Only genuine relaxations
// are reported: a stock <trust-anchors><certificates src="system"/></...> is
// the platform default and is not a finding.
func nscFindings(p *nscPolicy, sessionID, file string) []models.Finding {
	if p == nil {
		return nil
	}
	var findings []models.Finding

	if p.BaseCleartext {
		findings = append(findings, nscFinding(sessionID, file,
			"Cleartext traffic permitted",
			"The network security config allows cleartext (HTTP) traffic at the base level.",
			`cleartextTrafficPermitted="true"`,
			models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 1.0))
	}

	for _, d := range p.Domains {
		if !d.Cleartext {
			continue
		}
		scope := d.Domain
		if d.IncludesSubdomains {
			scope = "*." + scope
		}
		findings = append(findings, nscFinding(sessionID, file,
			fmt.Sprintf("Cleartext traffic permitted for %s", scope),
			fmt.Sprintf("The network security config allows unencrypted HTTP for %s.", scope),
			`cleartextTrafficPermitted="true" domain=`+d.Domain,
			models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 0.95))
	}

	if p.CustomAnchors {
		findings = append(findings, nscFinding(sessionID, file,
			"Custom trust anchors configured",
			"Custom trust anchors (src=\"user\" or \"@\") may weaken TLS validation if misconfigured.",
			"trust-anchors src=\"user\"",
			models.CategoryNetworkConfig, models.SeverityMedium, models.SensitivityInternal, 0.8))
	}

	if p.DebugOverrides {
		findings = append(findings, nscFinding(sessionID, file,
			"Network security debug overrides present",
			"debug-overrides applies a relaxed trust configuration to debuggable builds. It does not affect release builds, but it is a sign of a debug configuration that must not ship.",
			"<debug-overrides>",
			models.CategoryNetworkConfig, models.SeverityLow, models.SensitivityInternal, 0.6))
	}

	if p.Pinned {
		findings = append(findings, nscFinding(sessionID, file,
			"Certificate pinning configured (XML)",
			"The app uses network_security_config pin-set for certificate pinning.",
			"<pin-set>",
			models.CategoryPinningIndicator, models.SeverityInfo, models.SensitivityPublic, 1.0))

		if len(p.PinSets) == 0 {
			findings = append(findings, nscFinding(sessionID, file,
				"Certificate pin set has no expiration",
				"The pin-set declares no expiration date, so the pins stay in force forever and a leaked key cannot be rotated out of the app.",
				"<pin-set> without expiration",
				models.CategoryPinningIndicator, models.SeverityInfo, models.SensitivityPublic, 0.8))
		}
		for _, ps := range p.PinSets {
			exp, ok := parsePinExpiration(ps.Expiration)
			if !ok {
				findings = append(findings, nscFinding(sessionID, file,
					"Certificate pin set has no expiration",
					"The pin-set declares no expiration date, so the pins stay in force forever and a leaked key cannot be rotated out of the app.",
					"<pin-set> without expiration"+domainSuffix(ps.Domain),
					models.CategoryPinningIndicator, models.SeverityInfo, models.SensitivityPublic, 0.8))
				continue
			}
			if time.Now().After(exp) {
				findings = append(findings, nscFinding(sessionID, file,
					"Certificate pin set has expired",
					fmt.Sprintf("The pin-set expired on %s; the pinned keys are no longer enforced, so a new certificate is accepted without any code change.", exp.Format("2006-01-02")),
					"expiration=\""+exp.Format("2006-01-02")+"\""+domainSuffix(ps.Domain),
					models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 0.9))
			}
		}
	}

	if p.OverridePins {
		findings = append(findings, nscFinding(sessionID, file,
			"Certificate pinning override enabled",
			"overridePins=\"true\" disables pin enforcement (typically debug builds); never ship it enabled.",
			`overridePins="true"`,
			models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 0.9))
	}

	return findings
}

func domainSuffix(domain string) string {
	if domain == "" {
		return ""
	}
	return " domain=" + domain
}

// parsePinExpiration parses a pin-set expiration value.
func parsePinExpiration(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02", "2006-01-02T15:04:05Z07:00", time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// networkPolicyFromNSC builds the inventory view of a parsed config.
func networkPolicyFromNSC(p *nscPolicy) models.NetworkPolicy {
	policy := models.NetworkPolicy{Kind: "network_security_config"}
	if p == nil {
		return policy
	}
	policy.CleartextPermitted = p.BaseCleartext
	policy.Pinned = p.Pinned
	for _, d := range p.Domains {
		if !d.Cleartext && !d.CustomAnchors {
			continue
		}
		policy.Exceptions = append(policy.Exceptions, models.NetworkException{
			Domain:             d.Domain,
			IncludesSubdomains: d.IncludesSubdomains,
			InsecureHTTPLoads:  d.Cleartext,
		})
		if d.Cleartext {
			policy.CleartextPermitted = true
		}
	}
	return policy
}
