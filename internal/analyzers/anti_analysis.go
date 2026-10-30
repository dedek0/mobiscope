package analyzers

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	antiAnalysisName = "anti_analysis"

	// maxDexBytes caps how much of one DEX file is parsed.
	maxDexBytes = 64 << 20

	// maxClasses caps how many class names are kept for the obfuscation
	// score.
	maxClasses = 200000
)

// AntiAnalysis inspects the APK for the signals that tell a reviewer the app
// is hardened, instrumented or hiding something: obfuscation, root and
// emulator detection, anti-debugging, runtime instrumentation frameworks and
// dynamic code loading.
//
// The DEX files are read straight out of the archive so the analysis does not
// depend on a decompiler.
type AntiAnalysis struct {
	runner CommandRunner
}

func NewAntiAnalysis() *AntiAnalysis {
	return &AntiAnalysis{runner: &DefaultCommandRunner{}}
}

func NewAntiAnalysisWithRunner(runner CommandRunner) *AntiAnalysis {
	return &AntiAnalysis{runner: runner}
}

func (a *AntiAnalysis) Name() string { return antiAnalysisName }

// Available always succeeds: the analysis is fully in-process.
func (a *AntiAnalysis) Available() error { return nil }

// Phase marks the analyzer as independent: it reads the target artifact
// directly.
func (a *AntiAnalysis) Phase() Phase { return PhaseIndependent }

func (a *AntiAnalysis) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  a.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	summary := a.analyze(target)

	raw, _ := json.Marshal(summary)
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// antiAnalysisSummary is the JSON shape written by AntiAnalysis.Run.
type antiAnalysisSummary struct {
	// ClassCount is the number of classes found across all DEX files.
	ClassCount int `json:"class_count"`
	// ObfuscatedRatio is the share of classes with a one or two character
	// simple name.
	ObfuscatedRatio float64 `json:"obfuscated_ratio"`
	// Obfuscated is true when the ratio crosses the threshold.
	Obfuscated bool `json:"obfuscated"`
	// Toolchain names the obfuscator that was detected.
	Toolchain string `json:"toolchain,omitempty"`
	// Markers lists the anti-analysis signals that were found.
	Markers []antiMarker `json:"markers"`
	// DexFiles lists the DEX files that were inspected.
	DexFiles []string `json:"dex_files,omitempty"`
}

// antiMarker is one anti-analysis signal.
type antiMarker struct {
	// Kind is the concept the marker represents.
	Kind string `json:"kind"`
	// Title is the human-readable name of the signal.
	Title string `json:"title"`
	// Source is the artifact the marker was found in.
	Source string `json:"source"`
	// Evidence is the matched literal.
	Evidence string `json:"evidence"`
	// Severity is the severity the finding should carry.
	Severity models.Severity `json:"severity"`
	// Description explains why the signal matters.
	Description string `json:"description"`
}

// ConvertAntiAnalysisFindings turns the anti-analysis summary into findings.
func ConvertAntiAnalysisFindings(raw []byte, sessionID string) []models.Finding {
	var out antiAnalysisSummary
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	add := func(title, desc, snippet, file string, sev models.Severity, sens models.Sensitivity, conf float64) {
		f := models.Finding{
			ID:          models.GenerateID(antiAnalysisName, models.CategoryAntiAnalysis, file, 0, snippet),
			SessionID:   sessionID,
			SourceTool:  antiAnalysisName,
			Category:    models.CategoryAntiAnalysis,
			Platform:    models.PlatformAndroid,
			Title:       title,
			Description: desc,
			Evidence:    snippet,
			Location:    models.Location{File: file, Line: 0, Snippet: snippet},
			Severity:    sev,
			Sensitivity: sens,
			Confidence:  conf,
		}
		findings = append(findings, f)
	}

	for _, m := range out.Markers {
		add(m.Title, m.Description, m.Evidence, m.Source, m.Severity, models.SensitivityInternal, 0.75)
	}

	if out.Obfuscated {
		add("App is obfuscated",
			fmt.Sprintf("%.0f%% of the classes have a one or two character name, which is the signature of an obfuscated build. Obfuscation raises the cost of a review and is often used to hide the interesting code.",
				out.ObfuscatedRatio*100),
			fmt.Sprintf("ratio=%.2f", out.ObfuscatedRatio), "classes.dex",
			models.SeverityInfo, models.SensitivityInternal, 0.8)
	}
	if out.Toolchain != "" {
		add("Obfuscation toolchain detected",
			fmt.Sprintf("The APK ships artifacts of the %s obfuscator.", out.Toolchain),
			out.Toolchain, "assets/", models.SeverityInfo, models.SensitivityInternal, 0.7)
	}

	return findings
}

// ObfuscationFromRuns extracts the obfuscation facts recorded by the
// anti-analysis stage, for inventory.json. It returns the zero value when the
// stage did not run or produced no usable output.
func ObfuscationFromRuns(results []models.ToolResult) models.ObfuscationInfo {
	for _, r := range results {
		if r.ToolName != antiAnalysisName || len(r.Output) == 0 {
			continue
		}
		var out antiAnalysisSummary
		if err := json.Unmarshal(r.Output, &out); err != nil {
			continue
		}
		info := models.ObfuscationInfo{
			Android: true,
			Score:   out.ObfuscatedRatio,
		}
		if out.ClassCount > 0 {
			info.Indicators = append(info.Indicators, fmt.Sprintf("classes=%d", out.ClassCount))
		}
		if out.Toolchain != "" {
			info.Indicators = append(info.Indicators, "toolchain="+out.Toolchain)
		}
		if out.Obfuscated {
			info.Indicators = append(info.Indicators, fmt.Sprintf("short_class_names=%.0f%%", out.ObfuscatedRatio*100))
		}
		return info
	}
	return models.ObfuscationInfo{}
}

// analyze scans the target archive and returns the summary.
func (a *AntiAnalysis) analyze(target string) antiAnalysisSummary {
	summary := antiAnalysisSummary{}

	zr, err := openZip(target)
	if err != nil {
		return summary
	}
	defer zr.Close()

	var classNames []string
	seenMarker := map[string]bool{}

	for _, f := range zr.File {
		name := f.Name
		isDex := strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex")
		isAsset := strings.HasPrefix(name, "assets/")
		if !isDex && !isAsset {
			continue
		}

		if isAsset {
			if tool := detectObfuscatorAsset(name); tool != "" {
				summary.Toolchain = tool
			}
			// Assets are mostly data (Unity metadata, models, fonts). Scan
			// only payloads that can actually execute, otherwise generic
			// words in a data blob produce instrumentation false positives.
			if !isExecutableAsset(name) {
				continue
			}
		}

		if f.UncompressedSize64 > maxDexBytes {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxDexBytes))
		rc.Close()
		if err != nil {
			continue
		}

		if isDex {
			summary.DexFiles = append(summary.DexFiles, name)
			names, derr := dexClassNames(data)
			if derr == nil {
				classNames = append(classNames, names...)
			}
		}

		for _, marker := range scanAntiAnalysisMarkers(data) {
			key := marker.Kind + "|" + marker.Evidence
			if seenMarker[key] {
				continue
			}
			seenMarker[key] = true
			marker.Source = name
			summary.Markers = append(summary.Markers, marker)
		}
	}

	summary.ClassCount = len(classNames)
	summary.ObfuscatedRatio = obfuscatedRatio(classNames)
	summary.Obfuscated = summary.ObfuscatedRatio >= 0.5 && summary.ClassCount >= 20

	return summary
}

// antiMarkerPattern is one anti-analysis literal.
type antiMarkerPattern struct {
	needle string
	kind   string
	title  string
	sev    models.Severity
	desc   string
}

// antiAnalysisPatterns lists the literals that reveal the anti-analysis
// behaviour. The entries are matched case-insensitively unless the pattern
// is marked case-sensitive.
var antiAnalysisPatterns = []antiMarkerPattern{
	{
		needle: "/system/bin/su", kind: markerRoot, title: titleRootDetected, sev: models.SeverityInfo,
		desc: "The app checks for the su binary, so it is aware of rooted devices.",
	},
	{
		needle: "/system/xbin/su", kind: markerRoot, title: titleRootDetected, sev: models.SeverityInfo,
		desc: "The app checks for the su binary, so it is aware of rooted devices.",
	},
	{
		needle: "com.topjohnwu.magisk", kind: markerRoot, title: "App detects Magisk", sev: models.SeverityInfo,
		desc: "The app looks for Magisk, so it is aware of rooted devices.",
	},
	{
		needle: "com.noshufou.android.su", kind: markerRoot, title: titleRootDetected, sev: models.SeverityInfo,
		desc: "The app looks for a root management app.",
	},
	{
		needle: "test-keys", kind: markerRoot, title: "App checks for a test-signed build", sev: models.SeverityLow,
		desc: "The app inspects the build signature for the test-keys marker, a common root heuristic.",
	},

	{
		needle: "goldfish", kind: markerEmulator, title: titleEmulatorDetected, sev: models.SeverityInfo,
		desc: "The app checks the hardware fingerprint, a standard emulator heuristic.",
	},
	{
		needle: "ranchu", kind: markerEmulator, title: titleEmulatorDetected, sev: models.SeverityInfo,
		desc: "The app checks the hardware fingerprint, a standard emulator heuristic.",
	},
	{
		needle: "sdk_gphone", kind: markerEmulator, title: titleEmulatorDetected, sev: models.SeverityInfo,
		desc: "The app checks the build model, a standard emulator heuristic.",
	},
	{
		needle: "generic_x86", kind: markerEmulator, title: titleEmulatorDetected, sev: models.SeverityInfo,
		desc: "The app checks the build model, a standard emulator heuristic.",
	},
	{
		needle: "ro.kernel.qemu", kind: markerEmulator, title: titleEmulatorDetected, sev: models.SeverityInfo,
		desc: "The app reads the kernel property that identifies a QEMU-based emulator.",
	},
	{
		needle: "ro.hardware", kind: markerEmulator, title: titleEmulatorDetected, sev: models.SeverityInfo,
		desc: "The app inspects the hardware property, a standard emulator heuristic.",
	},

	{
		needle: markerIsDebuggerConnected, kind: markerAntiDebug, title: titleDebuggerDetected, sev: models.SeverityInfo,
		desc: "The app checks whether a debugger is connected.",
	},
	{
		needle: "Debug.isDebuggerConnected", kind: markerAntiDebug, title: titleDebuggerDetected, sev: models.SeverityInfo,
		desc: "The app checks whether a debugger is connected.",
	},
	{
		needle: markerTracerPid, kind: markerAntiDebug, title: titleDebuggerDetected, sev: models.SeverityInfo,
		desc: "The app reads TracerPid from /proc/self/status, the classic anti-debug trick.",
	},
	{
		needle: "/proc/self/status", kind: markerAntiDebug, title: "App inspects its own process status", sev: models.SeverityLow,
		desc: "Reading /proc/self/status is how an app detects a debugger or a tracer.",
	},
	{
		needle: markerAndroidDebug, kind: markerAntiDebug, title: titleDebuggerDetected, sev: models.SeverityInfo,
		desc: "The app uses the Debug class, which is where debugger detection lives.",
	},

	{
		needle: markerFrida, kind: markerFrida, title: titleFridaDetected, sev: models.SeverityHigh,
		desc: "The app references Frida, the most common runtime instrumentation framework for Android.",
	},
	{
		needle: markerXposed, kind: markerXposed, title: titleXposedDetected, sev: models.SeverityHigh,
		desc: "The app references the Xposed framework, which rewrites method calls at runtime.",
	},
	{
		needle: "de.robv.android.xposed", kind: markerXposed, title: titleXposedDetected, sev: models.SeverityHigh,
		desc: "The app references the Xposed framework, which rewrites method calls at runtime.",
	},
	{
		needle: markerSubstrate, kind: markerSubstrate, title: titleSubstrateDetected, sev: models.SeverityHigh,
		desc: "The app references Cydia Substrate, a native hooking framework.",
	},
	{
		needle: "/proc/self/maps", kind: markerAntiDebug, title: "App inspects its own memory maps", sev: models.SeverityLow,
		desc: "Reading the memory map is how an app spots injected libraries.",
	},

	{
		needle: "DexClassLoader", kind: markerDynamicCode, title: titleDynamicCode, sev: models.SeverityMedium,
		desc: "The app loads DEX or JAR files at runtime, which hides code from a static review.",
	},
	{
		needle: "PathClassLoader", kind: markerDynamicCode, title: titleDynamicCode, sev: models.SeverityMedium,
		desc: "The app loads code at runtime from an arbitrary path.",
	},
	{
		needle: "InMemoryDexClassLoader", kind: markerDynamicCode, title: titleDynamicCode, sev: models.SeverityMedium,
		desc: "The app loads DEX code straight from memory, leaving no file to inspect.",
	},
	{
		needle: "dalvik.system.DexClassLoader", kind: markerDynamicCode, title: titleDynamicCode, sev: models.SeverityMedium,
		desc: "The app loads DEX or JAR files at runtime, which hides code from a static review.",
	},
	{
		needle: "System.loadLibrary", kind: "native-code", title: "App loads native libraries at runtime", sev: models.SeverityInfo,
		desc: "The app loads a native library, so part of its behaviour lives outside the Dalvik bytecode.",
	},
	{
		needle: "RegisterNatives", kind: "jni-register", title: "App registers native methods at runtime", sev: models.SeverityMedium,
		desc: "RegisterNatives binds Java methods to native functions dynamically, which hides the Java-to-native call graph from a static review.",
	},
	{
		needle: "Runtime.getRuntime", kind: "runtime-exec", title: "App shells out to a process", sev: models.SeverityMedium,
		desc: "The app spawns external processes, which can execute commands the static review cannot see.",
	},

	{
		needle: "getPackageInfo", kind: markerIntegrity, title: titleIntegrityCheck, sev: models.SeverityInfo,
		desc: "The app reads a package signature, the usual way to detect a repackaged build.",
	},
	{
		needle: "GET_SIGNATURES", kind: markerIntegrity, title: titleIntegrityCheck, sev: models.SeverityInfo,
		desc: "The app reads the signing certificate of an installed package, a repackaging check.",
	},
	{
		needle: "PackageManager", kind: markerIntegrity, title: "App inspects installed packages", sev: models.SeverityInfo,
		desc: "The app queries the package manager, often to check for tampering or for other apps.",
	},
}

// scanAntiAnalysisMarkers looks for the anti-analysis literals in a blob.
func scanAntiAnalysisMarkers(data []byte) []antiMarker {
	lower := bytes.ToLower(data)
	var out []antiMarker
	seen := map[string]bool{}
	for _, p := range antiAnalysisPatterns {
		if seen[p.kind] {
			continue
		}
		needle := []byte(p.needle)
		if bytes.Contains(lower, bytes.ToLower(needle)) {
			seen[p.kind] = true
			out = append(out, antiMarker{
				Kind:        p.kind,
				Title:       p.title,
				Severity:    p.sev,
				Description: p.desc,
				Evidence:    p.needle,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// isExecutableAsset reports whether an asset can carry executable code that
// the anti-analysis string scan should inspect.
func isExecutableAsset(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".dex") || strings.HasSuffix(lower, ".jar") ||
		strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".apk")
}

// detectObfuscatorAsset recognises the artifacts an obfuscator leaves in the
// assets directory.
func detectObfuscatorAsset(name string) string {
	base := strings.ToLower(filepath.Base(name))
	switch {
	case base == "mapping.txt":
		return "R8/ProGuard"
	case strings.HasSuffix(base, ".dg") || strings.Contains(name, "dexguard"):
		return "DexGuard"
	case strings.HasSuffix(base, "allatori.xml"), strings.Contains(name, "allatori"):
		return "Allatori"
	case strings.HasSuffix(base, "stringencryption"):
		return "string encryption"
	case strings.HasSuffix(base, ".ag"):
		return "AndroidGuard"
	}
	return ""
}

// obfuscatedRatio returns the share of class names whose simple name is one
// or two characters long, which is the signature of an obfuscated build.
func obfuscatedRatio(classNames []string) float64 {
	if len(classNames) == 0 {
		return 0
	}
	short := 0
	for _, name := range classNames {
		if isObfuscatedClassName(name) {
			short++
		}
	}
	return float64(short) / float64(len(classNames))
}

// isObfuscatedClassName reports whether a class descriptor looks obfuscated.
func isObfuscatedClassName(descriptor string) bool {
	// Strip the package: Lcom/example/Foo$Bar; -> Foo$Bar
	simple := descriptor
	if idx := strings.LastIndex(simple, "/"); idx >= 0 {
		simple = simple[idx+1:]
	}
	simple = strings.TrimSuffix(strings.TrimPrefix(simple, "L"), ";")
	if simple == "" {
		return false
	}
	// The innermost segment after the last '$'.
	if idx := strings.LastIndex(simple, "$"); idx >= 0 {
		simple = simple[idx+1:]
	}
	if simple == "" || len(simple) > 2 {
		return false
	}
	// Well-known short names that are not a sign of obfuscation.
	switch simple {
	case "R", "R$", "BuildConfig", "R.java", "By":
		return false
	}
	return true
}

// dexClassNames extracts the class names declared in a DEX file.
func dexClassNames(data []byte) ([]string, error) {
	if len(data) < 0x70 || !bytes.HasPrefix(data, []byte("dex\n")) {
		return nil, fmt.Errorf("not a DEX file")
	}

	stringIDsSize := binary.LittleEndian.Uint32(data[0x38:])
	stringIDsOff := binary.LittleEndian.Uint32(data[0x3c:])
	typeIDsSize := binary.LittleEndian.Uint32(data[0x40:])
	typeIDsOff := binary.LittleEndian.Uint32(data[0x44:])
	classDefsSize := binary.LittleEndian.Uint32(data[0x60:])
	classDefsOff := binary.LittleEndian.Uint32(data[0x64:])

	if classDefsSize == 0 || classDefsSize > maxClasses {
		return nil, fmt.Errorf("implausible class count %d", classDefsSize)
	}
	if !inRange(len(data), uint64(stringIDsOff), uint64(stringIDsSize)*4) ||
		!inRange(len(data), uint64(typeIDsOff), uint64(typeIDsSize)*4) ||
		!inRange(len(data), uint64(classDefsOff), uint64(classDefsSize)*32) {
		return nil, fmt.Errorf("DEX table out of range")
	}

	names := make([]string, 0, classDefsSize)
	for i := uint32(0); i < classDefsSize; i++ {
		off := classDefsOff + i*32
		if off+4 > uint32(len(data)) {
			break
		}
		classIdx := binary.LittleEndian.Uint32(data[off:])
		name, ok := dexTypeName(data, stringIDsSize, stringIDsOff, typeIDsSize, typeIDsOff, classIdx)
		if ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// dexTypeName resolves a type index to its descriptor.
func dexTypeName(data []byte, stringIDsSize, stringIDsOff, typeIDsSize, typeIDsOff, typeIdx uint32) (string, bool) {
	if typeIdx >= typeIDsSize {
		return "", false
	}
	descIdxOff := typeIDsOff + typeIdx*4
	if descIdxOff+4 > uint32(len(data)) {
		return "", false
	}
	descIdx := binary.LittleEndian.Uint32(data[descIdxOff:])
	if descIdx >= stringIDsSize {
		return "", false
	}
	strOffOff := stringIDsOff + descIdx*4
	if strOffOff+4 > uint32(len(data)) {
		return "", false
	}
	dataOff := binary.LittleEndian.Uint32(data[strOffOff:])
	if dataOff >= uint32(len(data)) {
		return "", false
	}
	return dexStringAt(data, dataOff)
}

// dexStringAt decodes a MUTF-8 string_data_item at the given offset.
func dexStringAt(data []byte, off uint32) (string, bool) {
	pos := int(off)
	// Skip the ULEB128 utf16_size.
	for i := 0; i < 5; i++ {
		if pos >= len(data) {
			return "", false
		}
		b := data[pos]
		pos++
		if b&0x80 == 0 {
			break
		}
	}
	start := pos
	for pos < len(data) && data[pos] != 0 {
		pos++
	}
	if pos >= len(data) {
		return "", false
	}
	return string(data[start:pos]), true
}

// inRange reports whether off+size fits inside a buffer of the given length.
func inRange(length int, off uint64, size uint64) bool {
	if off > uint64(length) {
		return false
	}
	return off+size <= uint64(length)
}
