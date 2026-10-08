package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	classdumpName = "classdump"
)

var (
	objcClassRe = regexp.MustCompile(`_OBJC_CLASS_\$_([A-Za-z0-9_]+)`)
	swiftMangle = regexp.MustCompile(`\$s[0-9a-z_]+`)
)

// dangerousObjCClasses maps deprecated/insecure ObjC classes to (title,
// severity). Presence in the class dump is a strong signal of usage even
// without source.
var dangerousObjCClasses = map[string]struct {
	category    models.Category
	severity    models.Severity
	sensitivity models.Sensitivity
	title       string
	desc        string
}{
	"UIWebView": {
		models.CategoryCodePattern, models.SeverityHigh, models.SensitivityInternal,
		"Deprecated UIWebView class present",
		"UIWebView is deprecated and has known vulnerabilities (CVE-2021-1879 etc.); migrate to WKWebView.",
	},
	"NSURLConnection": {
		models.CategoryCodePattern, models.SeverityMedium, models.SensitivityInternal,
		"Legacy NSURLConnection class present",
		"NSURLConnection is deprecated and bypasses modern TLS pinning defaults; use NSURLSession.",
	},
	"ASIdentifierManager": {
		models.CategoryPrivacy, models.SeverityMedium, models.SensitivityConfidential,
		"AdTracking class present",
		"ASIdentifierManager enables IDFA tracking; requires ATT consent.",
	},
}

// ClassDump extracts Objective-C and Swift class metadata from Mach-O
// binaries in-process. It reads symbol-like strings rather than invoking
// class-dump(1) (darwin-only), so it runs on Linux.
type ClassDump struct{}

func NewClassDump() *ClassDump { return &ClassDump{} }

func (c *ClassDump) Name() string     { return classdumpName }
func (c *ClassDump) Available() error { return nil }

func (c *ClassDump) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  classdumpName,
		Version:   toolVersion,
		StartedAt: start,
	}

	root := iosSourceRoot(workdir)
	var objcClasses, swiftMangled []string
	var scanned []string

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxScanFileSize*32 {
			return nil
		}
		if !isLikelyMachO(path, filepath.Base(path)) {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		scanned = append(scanned, rel)
		for _, m := range objcClassRe.FindAllStringSubmatch(string(data), -1) {
			objcClasses = appendUnique(objcClasses, m[1])
		}
		for _, m := range swiftMangle.FindAllString(string(data), -1) {
			swiftMangled = appendUnique(swiftMangled, m)
		}
		return nil
	})

	raw, _ := json.Marshal(map[string]interface{}{
		jsonKeyRoot:           root,
		"scanned":             scanned,
		"objc_classes":        objcClasses,
		"swift_mangled":       swiftMangled,
		"objc_class_count":    len(objcClasses),
		"swift_mangled_count": len(swiftMangled),
	})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// classDumpOutput is the JSON shape written by ClassDump.Run.
type classDumpOutput struct {
	ObjcClasses    []string `json:"objc_classes"`
	SwiftMangled   []string `json:"swift_mangled"`
	ObjcClassCount int      `json:"objc_class_count"`
}

// ConvertClassDumpFindings reports dangerous ObjC classes and obfuscation
// signals discovered in the class dump.
func ConvertClassDumpFindings(raw []byte, sessionID string) []models.Finding {
	var out classDumpOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	for _, cls := range out.ObjcClasses {
		risk, ok := dangerousObjCClasses[cls]
		if !ok {
			continue
		}
		f := iosFinding(classdumpName, risk.category, "class-dump", cls,
			risk.title, risk.desc, risk.severity, risk.sensitivity, 0.9)
		findings = append(findings, withSession(f, sessionID))
	}

	// Obfuscation heuristic: a large binary with very few ObjC classes and
	// mostly Swift-mangled symbols is likely obfuscated or stripped.
	if out.ObjcClassCount > 0 && out.ObjcClassCount < 5 && len(out.SwiftMangled) > 20 {
		f := iosFinding(classdumpName, models.CategoryObfuscation, "class-dump", "obfuscation",
			"Possible symbol obfuscation",
			fmt.Sprintf("Only %d ObjC classes in a binary with %d Swift-mangled symbols; classes may be renamed or stripped.",
				out.ObjcClassCount, len(out.SwiftMangled)),
			models.SeverityInfo, models.SensitivityInternal, 0.6)
		findings = append(findings, withSession(f, sessionID))
	}
	if out.ObjcClassCount == 0 && len(out.SwiftMangled) == 0 {
		f := iosFinding(classdumpName, models.CategoryObfuscation, "class-dump", "stripped",
			"No class symbols found",
			"Neither ObjC class names nor Swift mangled symbols are visible; symbol tables appear stripped.",
			models.SeverityInfo, models.SensitivityInternal, 0.7)
		findings = append(findings, withSession(f, sessionID))
	}

	return findings
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
