package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
)

// InventoryIOS performs the iOS counterpart of the Android inventory: ATS,
// entitlements, privacy and obfuscation signals gathered from the extracted
// app bundle. It satisfies pipeline.FindingCollector.
type InventoryIOS struct{}

func NewInventoryIOS() *InventoryIOS { return &InventoryIOS{} }

func (inv *InventoryIOS) Name() string     { return "inventory-ios" }
func (inv *InventoryIOS) Available() error { return nil }

func (inv *InventoryIOS) Run(_ context.Context, _ string, _ string) (models.ToolResult, error) {
	// Pipeline calls Analyze directly for inventory-style analyzers.
	return models.ToolResult{ToolName: inv.Name(), Version: toolVersion}, nil
}

// Analyze returns iOS findings for the extracted app bundle.
func (inv *InventoryIOS) Analyze(workdir string, sessionID string) []models.Finding {
	bundle := appBundleDir(workdir)
	if bundle == "" {
		return nil
	}

	var findings []models.Finding

	infoPath := filepath.Join(bundle, "Info.plist")
	if data, err := os.ReadFile(infoPath); err == nil { //nolint:gosec
		findings = append(findings, ConvertPlistFindings(data, sessionID)...)
	}

	// Entitlements via the CodeSign analyzer's logic.
	cs := NewCodeSign()
	if res, err := cs.Run(context.TODO(), "", workdir); err == nil && res.Output != nil {
		findings = append(findings, ConvertCodeSignFindings(res.Output, sessionID)...)
	}

	// Binary hardening via the MachO analyzer's logic.
	mo := NewMachO()
	if res, err := mo.Run(context.TODO(), "", workdir); err == nil && res.Output != nil {
		findings = append(findings, ConvertMachOFindings(res.Output, sessionID)...)
	}

	// Obfuscation heuristics.
	if o := detectObfuscation(bundle); o != nil {
		f := iosFinding("inventory-ios", models.CategoryObfuscation, "Info.plist", "obfuscation",
			"Obfuscation indicators present",
			fmt.Sprintf("Obfuscation score %.2f (%s)", o.Score, strings.Join(o.Indicators, ", ")),
			models.SeverityInfo, models.SensitivityInternal, 0.6)
		findings = append(findings, withSession(f, sessionID))
	}

	return findings
}

// ObfuscationReport is the structured obfuscation signal set.
type ObfuscationReport struct {
	IOS        bool     `json:"ios"`
	Stripped   bool     `json:"stripped"`
	Score      float64  `json:"score"`
	Indicators []string `json:"indicators"`
}

func detectObfuscation(bundle string) *ObfuscationReport {
	rep := &ObfuscationReport{IOS: true}
	classCount := 0
	mangled := 0

	_ = filepath.WalkDir(bundle, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxScanFileSize*16 {
			return nil
		}
		if !isLikelyMachO(path, filepath.Base(path)) {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return nil
		}
		// ObjC class symbols look like _OBJC_CLASS_$_Foo.
		if strings.Contains(string(data), "_OBJC_CLASS_$_") {
			classCount++
		}
		// Swift mangled names dominate when obfuscated.
		if strings.Contains(string(data), "$s") {
			mangled++
		}
		return nil
	})

	if mangled > 0 && classCount == 0 {
		rep.Indicators = append(rep.Indicators, "swift-mangling-only")
		rep.Score += 0.4
	}
	if classCount > 0 && classCount < 5 {
		rep.Indicators = append(rep.Indicators, "few-objc-classes")
		rep.Score += 0.3
	}
	// Symbol stripping: a main binary with no visible class symbols at all.
	if classCount == 0 && mangled == 0 {
		rep.Stripped = true
		rep.Indicators = append(rep.Indicators, "symbols-stripped")
		rep.Score += 0.5
	}
	if rep.Score > 1.0 {
		rep.Score = 1.0
	}
	if len(rep.Indicators) == 0 {
		return nil
	}
	return rep
}
