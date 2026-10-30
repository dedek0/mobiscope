package analyzers

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	elfName = "elf"

	// maxNativeLibBytes caps how much of one native library is read.
	maxNativeLibBytes = 128 << 20

	// maxNativeLibs caps how many native libraries are inspected per app.
	maxNativeLibs = 400
)

// ELF inspects the native libraries shipped inside an Android APK. The
// libraries are read straight out of the archive so the analysis does not
// depend on apktool or jadx having extracted them.
//
// The checks cover the ELF hardening flags Android expects (PIE, RELRO, NX,
// stack canaries, FORTIFY_SOURCE) plus the native-code signals a mobile
// security review looks for: JNI exports, text relocations, RPATH entries and
// anti-analysis markers.
type ELF struct {
	runner CommandRunner
}

func NewELF() *ELF {
	return &ELF{runner: &DefaultCommandRunner{}}
}

func NewELFWithRunner(runner CommandRunner) *ELF {
	return &ELF{runner: runner}
}

func (e *ELF) Name() string { return elfName }

// Available always succeeds: the analysis is fully in-process.
func (e *ELF) Available() error { return nil }

// Phase marks the analyzer as independent: it reads the target artifact
// directly and does not depend on decompiler output.
func (e *ELF) Phase() Phase { return PhaseIndependent }

func (e *ELF) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  e.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	libs := e.collect(target, workdir)

	raw, _ := json.Marshal(map[string]interface{}{
		jsonKeyRoot:   "lib",
		"native_libs": libs,
	})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// elfOutput is the JSON shape written by ELF.Run.
type elfOutput struct {
	NativeLibs []models.NativeLib `json:"native_libs"`
}

// ConvertELFFindings reports native-code hardening and instrumentation
// findings.
func ConvertELFFindings(raw []byte, sessionID string) []models.Finding {
	var out elfOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	add := func(lib models.NativeLib, title, desc, snippet string, cat models.Category, sev models.Severity, sens models.Sensitivity, conf float64) {
		f := models.Finding{
			ID:          models.GenerateID(elfName, cat, lib.Path, 0, snippet),
			SessionID:   sessionID,
			SourceTool:  elfName,
			Category:    cat,
			Platform:    models.PlatformAndroid,
			Title:       title,
			Description: desc,
			Evidence:    snippet,
			Location:    models.Location{File: lib.Path, Line: 0, Snippet: snippet},
			Severity:    sev,
			Sensitivity: sens,
			Confidence:  conf,
		}
		findings = append(findings, f)
	}

	for _, lib := range out.NativeLibs {
		if lib.PIE != nil && !*lib.PIE {
			add(lib, "Native library is not position-independent",
				fmt.Sprintf("%s is a non-PIE executable; on Android every shipped library must be position-independent, otherwise it is rejected at install time or defeats ASLR.", lib.Path),
				"pie=false", models.CategoryBinaryHardening, models.SeverityHigh, models.SensitivityInternal, 0.9)
		}
		if lib.RELRO == valueNone {
			add(lib, "Native library has no RELRO",
				fmt.Sprintf("%s has no GNU_RELRO segment; the GOT stays writable and is a straightforward overwrite target.", lib.Path),
				"relro=none", models.CategoryBinaryHardening, models.SeverityMedium, models.SensitivityInternal, 0.85)
		}
		if lib.NX != nil && !*lib.NX {
			add(lib, "Native library has an executable stack",
				fmt.Sprintf("%s marks the stack as executable (PT_GNU_STACK with PF_X), which turns a stack overflow into code execution.", lib.Path),
				"nx=disabled", models.CategoryBinaryHardening, models.SeverityHigh, models.SensitivityInternal, 0.9)
		}
		if lib.StackCanary != nil && !*lib.StackCanary {
			add(lib, "Native library has no stack canary",
				fmt.Sprintf("%s does not reference __stack_chk_fail; it was built without stack smashing protection.", lib.Path),
				"canary=absent", models.CategoryBinaryHardening, models.SeverityMedium, models.SensitivityInternal, 0.7)
		}
		if lib.TextRelocs {
			add(lib, "Native library has text relocations",
				fmt.Sprintf("%s requests text relocations (DT_TEXTREL), which is forbidden for Android binaries and weakens the loader.", lib.Path),
				"textrel=1", models.CategoryBinaryHardening, models.SeverityHigh, models.SensitivityInternal, 0.9)
		}
		if lib.HasRPath {
			add(lib, "Native library declares an RPATH/RUNPATH",
				fmt.Sprintf("%s carries an RPATH/RUNPATH entry, so a writable directory on the search path can redirect a library load.", lib.Path),
				"rpath=1", models.CategoryBinaryHardening, models.SeverityMedium, models.SensitivityInternal, 0.7)
		}
		for _, marker := range lib.AntiAnalysis {
			sev := models.SeverityMedium
			switch {
			case strings.Contains(marker, markerFrida), strings.Contains(marker, markerXposed),
				strings.Contains(marker, markerSubstrate):
				sev = models.SeverityHigh
			case strings.Contains(marker, markerRoot), strings.Contains(marker, markerEmulator):
				sev = models.SeverityLow
			}
			add(lib, "Native library contains an anti-analysis marker",
				fmt.Sprintf("%s references %q, a marker for runtime instrumentation, root detection or emulator detection implemented in native code.", lib.Path, marker),
				marker, models.CategoryObfuscation, sev, models.SensitivityInternal, 0.7)
		}
		if lib.Packer != "" {
			add(lib, "Native library is packed",
				fmt.Sprintf("%s carries the signature of %s; the real code is unpacked at runtime and a static review of the .so sees only the stub.", lib.Path, lib.Packer),
				"packer="+lib.Packer, models.CategoryObfuscation, models.SeverityMedium, models.SensitivityInternal, 0.8)
		}
		if lib.Encrypted {
			add(lib, "Native library has high entropy",
				fmt.Sprintf("%s has an entropy of %.2f bits/byte, consistent with encryption or packing; code and strings may be hidden from static analysis.", lib.Path, lib.Entropy),
				fmt.Sprintf("entropy=%.2f", lib.Entropy), models.CategoryObfuscation, models.SeverityMedium, models.SensitivityInternal, 0.7)
		}
	}

	return findings
}

// collect gathers the native libraries of the target. It prefers the
// archive's own lib/ tree and falls back to the extracted session tree.
func (e *ELF) collect(target, workdir string) []models.NativeLib {
	if libs := e.collectFromArchive(target); len(libs) > 0 {
		return libs
	}
	return e.collectFromDir(workdir)
}

// collectFromArchive reads the lib/<abi>/*.so entries straight out of the APK.
func (e *ELF) collectFromArchive(target string) []models.NativeLib {
	zr, err := openZip(target)
	if err != nil {
		return nil
	}
	defer zr.Close()

	var libs []models.NativeLib
	for _, f := range zr.File {
		if len(libs) >= maxNativeLibs {
			break
		}
		name := f.Name
		inLibTree := strings.HasPrefix(name, "lib/")
		inAssets := strings.HasPrefix(name, "assets/")
		if (!inLibTree && !inAssets) || !strings.HasSuffix(name, ".so") {
			continue
		}
		if f.UncompressedSize64 > maxNativeLibBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxNativeLibBytes))
		rc.Close()
		if err != nil {
			continue
		}
		lib := inspectELF(data, name)
		if lib == nil {
			continue
		}
		libs = append(libs, *lib)
	}
	return libs
}

// collectFromDir walks an already extracted tree for shared objects.
func (e *ELF) collectFromDir(workdir string) []models.NativeLib {
	roots := []string{
		filepath.Join(workdir, "apktool", "lib"),
		filepath.Join(workdir, "jadx", "resources", "lib"),
		filepath.Join(workdir, "lib"),
	}

	var libs []models.NativeLib
	for _, root := range roots {
		if !dirExists(root) {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(d.Name(), ".so") {
				return nil
			}
			if len(libs) >= maxNativeLibs {
				return filepath.SkipAll
			}
			data, err := readFileCapped(path, maxNativeLibBytes)
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(workdir, path)
			lib := inspectELF(data, filepath.ToSlash(rel))
			if lib == nil {
				return nil
			}
			libs = append(libs, *lib)
			return nil
		})
		if len(libs) > 0 {
			break
		}
	}
	return libs
}

// inspectELF parses one shared object and returns its hardening profile.
func inspectELF(data []byte, name string) *models.NativeLib {
	if len(data) < 64 || !isELF(data) {
		return nil
	}

	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer f.Close()

	lib := &models.NativeLib{
		Path:  name,
		Kind:  "so",
		Archs: elfArchs(f),
	}

	// PIE: a shared object is ET_DYN; an executable is ET_EXEC. Android
	// requires every shipped binary to be position-independent.
	switch f.Type {
	case elf.ET_DYN:
		yes := true
		lib.PIE = &yes
	case elf.ET_EXEC:
		no := false
		lib.PIE = &no
	default:
		// Relocatable object or unknown type: PIE cannot be determined.
	}

	lib.RELRO = elfRELRO(f)
	lib.NX = elfNX(f)
	lib.StackCanary, lib.Fortify, lib.Stripped = elfSymbols(f)
	lib.TextRelocs, lib.HasRPath = elfDynamicFlags(f)
	lib.Linked = elfNeeded(f)
	lib.JNIExports = elfJNIExports(f)
	lib.AntiAnalysis = elfAntiAnalysis(data)
	lib.SONAME = elfSONAME(f)
	lib.Entropy = byteEntropy(data)
	lib.Packer = detectELFPacker(data)
	// A large, near-uniform binary is the signature of a packer or an
	// encrypted payload. Small libraries can legitimately be compressed.
	if len(data) >= 64*1024 && lib.Entropy >= 7.5 {
		lib.Encrypted = true
	}

	return lib
}

// elfSONAME returns the DT_SONAME declared by the library.
func elfSONAME(f *elf.File) string {
	names, err := f.DynString(elf.DT_SONAME)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// byteEntropy computes the Shannon entropy (bits per byte) of data.
func byteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// elfpPackerSignatures maps a byte pattern to the packer/protector it
// identifies. The patterns are intentionally specific to avoid generic words.
var elfPackerSignatures = []struct {
	needle string
	name   string
}{
	{"upx!", "UPX"},
	{"libjiagu", "360 Jiagu"},
	{"jiagu", "360 Jiagu"},
	{"dexhelper", "Baidu DexHelper"},
	{"libmobisec", "Alibaba Mobisec"},
	{"libsgmain", "Alibaba SecurityGuard"},
	{"libnesec", "NetEase Yidun"},
	{"libexecmain", "Tencent Legu"},
	{"libchaosvmp", "ChaosVMP"},
	{"libddog", "Bangcle"},
	{"libfdog", "Bangcle"},
}

// detectELFPacker names the packer/protector whose signature appears in data.
func detectELFPacker(data []byte) string {
	lower := bytes.ToLower(data)
	for _, sig := range elfPackerSignatures {
		if bytes.Contains(lower, []byte(sig.needle)) {
			return sig.name
		}
	}
	return ""
}

// isELF reports whether data starts with the ELF magic.
func isELF(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
}

// elfArchs maps the ELF machine type to a human-readable architecture.
func elfArchs(f *elf.File) []string {
	switch f.Machine {
	case elf.EM_ARM:
		return []string{"armv7"}
	case elf.EM_AARCH64:
		return []string{"arm64-v8a"}
	case elf.EM_X86_64:
		return []string{"x86_64"}
	case elf.EM_386:
		return []string{"x86"}
	case elf.EM_MIPS:
		return []string{"mips"}
	default:
		return []string{f.Machine.String()}
	}
}

// elfRELRO classifies the RELRO protection of a binary.
func elfRELRO(f *elf.File) string {
	hasRelro := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}
	if !hasRelro {
		return valueNone
	}
	// BIND_NOW (either in DT_FLAGS or as DT_BIND_NOW) means every
	// relocation is resolved at load time, which is full RELRO.
	if vals, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
		return valueFull
	}
	if vals, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_BIND_NOW) != 0 {
				return valueFull
			}
		}
	}
	if vals, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_1_NOW) != 0 {
				return valueFull
			}
		}
	}
	return "partial"
}

// elfNX reports whether the stack is non-executable. A missing PT_GNU_STACK
// means the platform default applies, which on Android is executable, so the
// property is reported as unknown in that case.
func elfNX(f *elf.File) *bool {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			nx := prog.Flags&elf.PF_X == 0
			return &nx
		}
	}
	return nil
}

// elfSymbols inspects the symbol tables for the stack canary and FORTIFY
// markers, and reports whether the binary is stripped.
func elfSymbols(f *elf.File) (canary, fortify *bool, stripped bool) {
	syms, err := f.Symbols()
	if err != nil || len(syms) == 0 {
		// No static symbol table: the binary is stripped. The dynamic
		// table is still worth checking.
		stripped = true
	} else {
		stripped = false
	}

	canaryFound := false
	fortifyFound := false

	inspect := func(list []elf.Symbol) {
		for _, s := range list {
			name := s.Name
			switch {
			case name == "__stack_chk_fail" || name == "__stack_chk_fail_local" ||
				name == "__stack_chk_guard":
				canaryFound = true
			case strings.HasSuffix(name, "_chk") || strings.HasSuffix(name, "_chk_warn"):
				fortifyFound = true
			}
		}
	}

	inspect(syms)
	if dyn, err := f.DynamicSymbols(); err == nil {
		inspect(dyn)
	}

	switch {
	case canaryFound:
		yes := true
		canary = &yes
	case stripped:
		// A stripped binary hides the canary symbol; the absence of
		// evidence is not evidence of absence.
		canary = nil
	default:
		no := false
		canary = &no
	}

	if fortifyFound {
		yes := true
		fortify = &yes
	} else {
		no := false
		fortify = &no
	}

	return canary, fortify, stripped
}

// elfDynamicFlags reports the presence of text relocations and of an
// RPATH/RUNPATH entry.
func elfDynamicFlags(f *elf.File) (textRelocs, hasRPath bool) {
	if vals, err := f.DynValue(elf.DT_TEXTREL); err == nil && len(vals) > 0 {
		textRelocs = true
	}
	if rpath, err := f.DynString(elf.DT_RPATH); err == nil && len(rpath) > 0 {
		hasRPath = true
	}
	if runpath, err := f.DynString(elf.DT_RUNPATH); err == nil && len(runpath) > 0 {
		hasRPath = true
	}
	return textRelocs, hasRPath
}

// elfNeeded returns the shared library dependencies.
func elfNeeded(f *elf.File) []string {
	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil
	}
	sort.Strings(libs)
	return libs
}

// elfJNIExports lists the Java_* symbols the library exports.
func elfJNIExports(f *elf.File) []string {
	var out []string
	collect := func(list []elf.Symbol) {
		for _, s := range list {
			if strings.HasPrefix(s.Name, "Java_") {
				out = append(out, s.Name)
			}
		}
	}
	if dyn, err := f.DynamicSymbols(); err == nil {
		collect(dyn)
	}
	if syms, err := f.Symbols(); err == nil {
		collect(syms)
	}
	sort.Strings(out)
	return dedupeStrings(out)
}

// antiAnalysisMarkers maps a byte pattern to the concept it represents.
var antiAnalysisMarkers = []struct {
	needle string
	label  string
}{
	{markerFrida, markerFrida},
	{"libfrida", markerFrida},
	{markerXposed, markerXposed},
	{"de.robv.android.xposed", markerXposed},
	{markerSubstrate, markerSubstrate},
	{"cydia", "cydia"},
	{"/system/bin/su", markerRoot},
	{"/system/xbin/su", markerRoot},
	{"com.topjohnwu.magisk", markerRoot},
	{"com.noshufou.android.su", markerRoot},
	{"test-keys", markerRoot},
	{"superuser.apk", markerRoot},
	{"ro.debuggable", markerEmulator},
	{"ro.hardware", markerEmulator},
	{"goldfish", markerEmulator},
	{"ranchu", markerEmulator},
	{"sdk_gphone", markerEmulator},
	{"generic_x86", markerEmulator},
	{markerTracerPid, markerAntiDebug},
	{"/proc/self/status", markerAntiDebug},
	{"ptrace", markerAntiDebug},
	{markerIsDebuggerConnected, markerAntiDebug},
	{markerAndroidDebug, markerAntiDebug},
	{"/proc/self/maps", markerAntiDebug},
	{"SIGTRAP", markerAntiDebug},
}

// elfAntiAnalysis scans the binary's printable strings for instrumentation
// and root/emulator detection markers.
func elfAntiAnalysis(data []byte) []string {
	lower := bytes.ToLower(data)
	var found []string
	seen := map[string]bool{}
	for _, marker := range antiAnalysisMarkers {
		if seen[marker.label] {
			continue
		}
		needle := []byte(marker.needle)
		if marker.needle == markerTracerPid || marker.needle == markerIsDebuggerConnected ||
			marker.needle == markerAndroidDebug || marker.needle == "SIGTRAP" {
			// Case-sensitive markers.
			if bytes.Contains(data, needle) {
				seen[marker.label] = true
				found = append(found, marker.label)
			}
			continue
		}
		if bytes.Contains(lower, bytes.ToLower(needle)) {
			seen[marker.label] = true
			found = append(found, marker.label)
		}
	}
	sort.Strings(found)
	return found
}

// NativeLibsFromRuns extracts the native library inventory from the ELF
// stage output, if the stage ran.
func NativeLibsFromRuns(results []models.ToolResult) []models.NativeLib {
	for _, r := range results {
		if r.ToolName != elfName || len(r.Output) == 0 {
			continue
		}
		var out elfOutput
		if err := json.Unmarshal(r.Output, &out); err != nil {
			continue
		}
		return out.NativeLibs
	}
	return nil
}
