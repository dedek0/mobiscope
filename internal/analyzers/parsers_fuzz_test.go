package analyzers

import (
	"encoding/json"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
)

func FuzzConvertGitleaksFindings(f *testing.F) {
	f.Add([]byte(`[{"RuleID":"r","Secret":"s","File":"f","StartLine":1,"Match":"m"}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte(`WARN: banner [{"RuleID":"a"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		findings := ConvertGitleaksFindings(data, "fuzz")
		for _, fi := range findings {
			if string(fi.Category) != CategorySecretSafe() {
				t.Fatalf("unexpected category %q", fi.Category)
			}
			if fi.ID == "" {
				t.Fatal("empty finding id")
			}
			if fi.SessionID != "fuzz" {
				t.Fatalf("session id not propagated: %q", fi.SessionID)
			}
		}
	})
}

func FuzzConvertSemgrepFindings(f *testing.F) {
	f.Add([]byte(`{"runs":[{"results":[{"ruleId":"r","level":"error","message":{"text":"m"}}]}]}`))
	f.Add([]byte(`{"runs":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`<xml/>`))
	f.Add([]byte(`{"runs":[{"results":[{"ruleId":"x"}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		findings := ConvertSemgrepFindings(data, "fuzz")
		for _, fi := range findings {
			if fi.ID == "" {
				t.Fatal("empty finding id")
			}
			if fi.Title == "" {
				t.Fatalf("empty title for rule %q", fi.RuleID)
			}
		}
	})
}

func FuzzConvertPlistFindings(f *testing.F) {
	f.Add([]byte(`{"bundle_id":"com.x","ats":{"NSAllowsArbitraryLoads":true}}`))
	f.Add([]byte(`{"ats":{}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		findings := ConvertPlistFindings(data, "fuzz")
		for _, fi := range findings {
			if fi.Category == "" {
				t.Fatal("empty category")
			}
			if fi.Platform != "ios" {
				t.Fatalf("expected ios platform, got %q", fi.Platform)
			}
		}
	})
}

func FuzzExtractJSONArray(f *testing.F) {
	f.Add([]byte(`[1,2]`))
	f.Add([]byte(`banner [1] tail`))
	f.Add([]byte(`no brackets`))
	f.Add([]byte(`[`))
	f.Add([]byte(`]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		raw := extractJSONArray(string(data))
		// Must never panic; when it returns valid JSON it must be an array
		// or object we can attempt to decode.
		if json.Valid(raw) {
			var probe interface{}
			_ = json.Unmarshal(raw, &probe)
		}
	})
}

func FuzzExtractPlistFromBytes(f *testing.F) {
	f.Add([]byte(`GARBAGE<plist><dict><key>k</key><true/></dict></plist>TAIL`))
	f.Add([]byte(``))
	f.Add([]byte(`no plist here`))
	f.Add([]byte(`<plist><dict></dict></plist>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m := extractPlistFromBytes(data)
		_ = m
	})
}

func CategorySecretSafe() string { return string(models.CategorySecret) }
