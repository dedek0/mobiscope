package analyzers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	// maxDexStrings bounds how many entries of one DEX string pool are
	// scanned. A hostile file can declare an implausible count.
	maxDexStrings = 500000
	// maxDexFinding caps how many findings one DEX file contributes, so a
	// pathological string pool cannot flood the report.
	maxDexFinding = 500
)

// dexStrings extracts the string pool of a DEX file.
func dexStrings(data []byte) ([]string, error) {
	if len(data) < 0x70 || !bytes.HasPrefix(data, []byte("dex\n")) {
		return nil, fmt.Errorf("not a DEX file")
	}
	stringIDsSize := binary.LittleEndian.Uint32(data[0x38:])
	stringIDsOff := binary.LittleEndian.Uint32(data[0x3c:])
	if stringIDsSize == 0 {
		return nil, nil
	}
	if stringIDsSize > maxDexStrings {
		return nil, fmt.Errorf("implausible string count %d", stringIDsSize)
	}
	if !inRange(len(data), uint64(stringIDsOff), uint64(stringIDsSize)*4) {
		return nil, fmt.Errorf("DEX string table out of range")
	}

	out := make([]string, 0, stringIDsSize)
	for i := uint32(0); i < stringIDsSize; i++ {
		off := binary.LittleEndian.Uint32(data[stringIDsOff+i*4:])
		s, ok := dexStringAt(data, off)
		if ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// scanDEXStrings scans every classes*.dex string pool with the same secret,
// URL, IP, pinning and anti-analysis patterns used for the decompiled tree.
// It closes the gap where semgrep is opt-in and only reads .java files.
func scanDEXStrings(target, sessionID string) ([]models.Finding, ScanAggregate) {
	var findings []models.Finding
	agg := ScanAggregate{}

	a, err := openAPKArchive(target)
	if err != nil {
		return nil, agg
	}
	defer a.close()

	urlSeen := map[string]bool{}
	ipSeen := map[string]bool{}
	emailSeen := map[string]bool{}
	pinSeen := map[string]bool{}

	for _, f := range a.zr.File {
		if !strings.HasPrefix(f.Name, "classes") || !strings.HasSuffix(f.Name, ".dex") {
			continue
		}
		if f.UncompressedSize64 > maxDexBytes {
			continue
		}
		data, err := a.read(f.Name, maxDexBytes)
		if err != nil {
			continue
		}
		stringsPool, err := dexStrings(data)
		if err != nil {
			continue
		}

		fileFindings := 0
		for i, s := range stringsPool {
			if s == "" {
				continue
			}
			line := i + 1
			for _, m := range urlRe.FindAllString(s, -1) {
				agg.URLs.Count++
				u := strings.TrimRight(m, ".,;:!?)]}")
				if !urlSeen[u] && len(urlSeen) < maxURLSamples {
					urlSeen[u] = true
					agg.URLs.URLs = append(agg.URLs.URLs, u)
				}
			}
			for _, m := range ipRe.FindAllString(s, -1) {
				agg.IPCount++
				if !ipSeen[m] && len(ipSeen) < maxIPSamples {
					ipSeen[m] = true
					agg.IPs = append(agg.IPs, m)
				}
			}
			for _, m := range emailRe.FindAllString(s, -1) {
				agg.EmailCount++
				if !emailSeen[m] && len(emailSeen) < maxEmailSamples {
					emailSeen[m] = true
					agg.Emails = append(agg.Emails, m)
				}
			}
			for _, marker := range pinningMarkers {
				n := strings.Count(s, marker)
				if n == 0 {
					continue
				}
				agg.PinningCount += n
				if !pinSeen[marker] {
					pinSeen[marker] = true
					agg.Pinning = append(agg.Pinning, marker)
				}
			}

			if fileFindings >= maxDexFinding {
				continue
			}
			for _, rule := range scanRules {
				if rule.Needle != "" && !strings.Contains(s, rule.Needle) {
					continue
				}
				locs := rule.Re.FindAllStringIndex(s, -1)
				for _, loc := range locs {
					if fileFindings >= maxDexFinding {
						break
					}
					raw := s[loc[0]:loc[1]]
					if rule.Name == privateKeyRuleName && !validPEMBlock(raw) {
						continue
					}
					snippet := raw
					if rule.Redact {
						snippet = redactPEM(raw)
					}
					if len(snippet) > 120 {
						snippet = snippet[:120]
					}
					desc := rule.Description
					if desc == "" {
						desc = fmt.Sprintf("Pattern match for %s in the DEX string pool of %s", rule.Name, f.Name)
					}
					findings = append(findings, models.Finding{
						ID:          models.GenerateID(NameInventory, rule.Category, f.Name, line, snippet),
						SessionID:   sessionID,
						SourceTool:  NameInventory,
						Category:    rule.Category,
						Platform:    models.PlatformAndroid,
						Origin:      OriginApp,
						Title:       rule.Name,
						Description: desc,
						Evidence:    snippet,
						Location:    models.Location{File: f.Name, Line: line, Snippet: snippet},
						Severity:    rule.Severity,
						Sensitivity: rule.Sensitivity,
						Confidence:  0.75,
					})
					fileFindings++
				}
			}
		}
	}

	sortAggregate(&agg)
	return findings, agg
}

// sortAggregate puts the bounded samples in deterministic order.
func sortAggregate(agg *ScanAggregate) {
	sort.Strings(agg.URLs.URLs)
	sort.Strings(agg.IPs)
	sort.Strings(agg.Emails)
	sort.Strings(agg.Pinning)
}
