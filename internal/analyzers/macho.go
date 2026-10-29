package analyzers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	machoName      = "macho"
	llvmObjdumpBin = "llvm-objdump"
	machoTimeout   = 2 * time.Minute
)

// Mach-O magic numbers.
const (
	mhMagic32  = 0xfeedface
	mhMagic64  = 0xfeedfacf
	mhCigam32  = 0xcefaedfe
	mhCigam64  = 0xcffaedfe
	mhFat      = 0xcafebabe
	mhFat64    = 0xcafebabf
	mhMaxFats  = 16
	mhMaxCmds  = 4096
	mhLoadBias = 0x01000000
)

// Load command identifiers.
const (
	lcLoadDylib      = 0x0c
	lcLoadWeakDylib  = 0x18
	lcReexportDylib  = 0x1f
	lcLoadUpwardDyl  = 0x23
	lcEncryptionInfo = 0x21
	lcEncryption64   = 0x2c
)

// MachO inspects Mach-O binaries in the extracted app for hardening and
// native-code findings. The parsing is fully in-process: no external binary
// is required, so the stage is always available.
type MachO struct {
	runner CommandRunner
}

func NewMachO() *MachO {
	return &MachO{runner: &DefaultCommandRunner{}}
}

func NewMachOWithRunner(runner CommandRunner) *MachO {
	return &MachO{runner: runner}
}

func (m *MachO) Name() string { return machoName }

// Available always succeeds: the analyzer parses Mach-O headers in-process
// and does not shell out to llvm-objdump.
func (m *MachO) Available() error { return nil }

// Phase marks the analyzer as a scanner: it reads the extracted bundle.
func (m *MachO) Phase() Phase { return PhaseScanner }

func (m *MachO) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  m.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	root := iosSourceRoot(workdir)
	var libs []models.NativeLib
	var binaries []string

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		// Native code lives in the bundle root (main executable), Frameworks/
		// and PlugIns/*.appex. Plain resources are skipped.
		base := filepath.Base(rel)
		if strings.Contains(rel, "Frameworks/") || strings.Contains(rel, "PlugIns/") ||
			isLikelyMachO(path, base) {
			if info, err := d.Info(); err == nil && info.Size() <= maxScanFileSize*32 {
				binaries = append(binaries, rel)
				libs = append(libs, inspectBinary(path, rel))
			}
		}
		return nil
	})

	raw, _ := json.Marshal(map[string]interface{}{
		jsonKeyRoot:   root,
		"native_libs": libs,
		"binaries":    binaries,
	})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// machoOutput is the JSON shape written by MachO.Run.
type machoOutput struct {
	NativeLibs []models.NativeLib `json:"native_libs"`
}

// ConvertMachOFindings reports hardening and native-code findings.
func ConvertMachOFindings(raw []byte, sessionID string) []models.Finding {
	var out machoOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	add := func(lib models.NativeLib, title, desc, snippet string, cat models.Category, sev models.Severity, sens models.Sensitivity, conf float64) {
		f := iosFinding(machoName, cat, lib.Path, snippet, title, desc, sev, sens, conf)
		findings = append(findings, withSession(f, sessionID))
	}

	for _, lib := range out.NativeLibs {
		if lib.Encrypted {
			add(lib, "Encrypted binary (FairPlay)",
				fmt.Sprintf("%s is encrypted (LC_ENCRYPTION_INFO cryptid != 0); its body is not statically analyzable.", lib.Path),
				"cryptid!=0", models.CategoryBinaryHardening, models.SeverityInfo, models.SensitivityInternal, 0.9)
		}
		// Only report a missing arm64 slice when the architecture list was
		// actually recovered; an unparseable binary is not evidence of a
		// legacy build.
		if lib.Kind == "main_binary" && len(lib.Archs) > 0 && !containsStr(lib.Archs, "arm64") {
			add(lib, "Missing arm64 slice",
				"Main binary has no arm64 slice; modern iOS devices require it and its absence often indicates a legacy build.",
				"archs="+strings.Join(lib.Archs, ","), models.CategoryBinaryHardening, models.SeverityMedium, models.SensitivityInternal, 0.6)
		}
		if lib.Kind == "static_archive" {
			add(lib, "Static archive shipped in app",
				fmt.Sprintf("%s is a static archive (.a); these should be linked at build time, not shipped.", lib.Path),
				lib.Path, models.CategoryNativeCode, models.SeverityInfo, models.SensitivityInternal, 0.8)
		}
		for _, dep := range lib.Linked {
			low := strings.ToLower(dep)
			if strings.Contains(low, "substrate") || strings.Contains(low, "cycript") || strings.Contains(low, "frida") {
				add(lib, "Links jailbreak tooling library",
					fmt.Sprintf("%s links %s, commonly used for runtime instrumentation.", lib.Path, dep),
					dep, models.CategoryObfuscation, models.SeverityHigh, models.SensitivityConfidential, 0.85)
			}
			if strings.Contains(low, "/privateframeworks/") {
				add(lib, "Links private framework",
					fmt.Sprintf("%s links private framework %s; these are unsupported and can leak data.", lib.Path, dep),
					dep, models.CategoryNativeCode, models.SeverityMedium, models.SensitivityInternal, 0.8)
			}
		}
		if strings.HasPrefix(lib.InstallName, "@rpath") || strings.HasPrefix(lib.InstallName, "@executable_path") {
			add(lib, "Relative install name enables dylib injection",
				fmt.Sprintf("%s uses install name %q which can be hijacked on jailbroken devices.", lib.Path, lib.InstallName),
				lib.InstallName, models.CategoryBinaryHardening, models.SeverityMedium, models.SensitivityInternal, 0.6)
		}
	}

	return findings
}

// isLikelyMachO guesses by filename when the walker is at the bundle root.
func isLikelyMachO(path, base string) bool {
	if strings.HasSuffix(base, ".dylib") || strings.HasSuffix(base, ".a") {
		return true
	}
	// Main executable at the bundle root has no extension.
	if filepath.Ext(base) == "" {
		if f, err := os.Open(path); err == nil {
			var magic [4]byte
			_, _ = f.Read(magic[:])
			f.Close()
			return isMachOMagic(magic)
		}
	}
	return false
}

func isMachOMagic(m [4]byte) bool {
	switch m {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}: // 32-bit BE
		return true
	case [4]byte{0xfe, 0xed, 0xfa, 0xcf}: // 64-bit BE
		return true
	case [4]byte{0xce, 0xfa, 0xed, 0xfe}: // 32-bit LE
		return true
	case [4]byte{0xcf, 0xfa, 0xed, 0xfe}: // 64-bit LE
		return true
	case [4]byte{0xca, 0xfe, 0xba, 0xbe}: // FAT (also Java class; caller disambiguates)
		return true
	case [4]byte{0xca, 0xfe, 0xba, 0xbf}: // FAT 64-bit
		return true
	default:
		return false
	}
}

// inspectBinary extracts a lightweight NativeLib record from a Mach-O file.
// Universal (FAT) binaries are walked slice by slice so the architecture
// list, the encryption flag and the linked dylibs reflect the real slices.
func inspectBinary(path, rel string) models.NativeLib {
	lib := models.NativeLib{
		Path: rel,
		Kind: "main_binary",
	}
	switch {
	case strings.HasSuffix(rel, ".dylib"):
		lib.Kind = "dylib"
	case strings.HasSuffix(rel, ".a"):
		lib.Kind = "static_archive"
	case strings.Contains(rel, ".framework/"):
		lib.Kind = "framework"
	}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return lib
	}
	if len(data) < 32 {
		return lib
	}

	if !isMachOMagic([4]byte{data[0], data[1], data[2], data[3]}) {
		return lib
	}

	if isFAT(data) {
		parseFAT(data, &lib)
	} else {
		arch, enc, dylibs := parseMachOSlice(data, 0)
		if arch != "" {
			lib.Archs = append(lib.Archs, arch)
		}
		lib.Encrypted = enc
		lib.Linked = dedupeStrings(dylibs)
	}

	// A Mach-O install name lives in LC_ID_DYLIB; look for it so the
	// relative-path injection check has data to work with.
	if name := extractInstallName(data); name != "" {
		lib.InstallName = name
	}

	return lib
}

// isFAT reports whether data starts with a FAT (universal) header.
func isFAT(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[:4])
	return magic == mhFat || magic == mhFat64
}

// parseFAT walks the universal-binary container and merges the per-slice
// information into lib.
func parseFAT(data []byte, lib *models.NativeLib) {
	magic := binary.BigEndian.Uint32(data[:4])
	is64 := magic == mhFat64

	nfat := int(binary.BigEndian.Uint32(data[4:8]))
	if nfat <= 0 || nfat > mhMaxFats {
		return
	}

	entrySize := 20
	if is64 {
		entrySize = 32
	}

	off := 8
	for i := 0; i < nfat; i++ {
		if off+entrySize > len(data) {
			break
		}
		var sliceOff int
		if is64 {
			sliceOff = int(binary.BigEndian.Uint64(data[off+8 : off+16]))
		} else {
			sliceOff = int(binary.BigEndian.Uint32(data[off+8 : off+12]))
		}
		if sliceOff < 0 || sliceOff >= len(data) {
			off += entrySize
			continue
		}
		arch, enc, dylibs := parseMachOSlice(data, sliceOff)
		if arch != "" && !containsStr(lib.Archs, arch) {
			lib.Archs = append(lib.Archs, arch)
		}
		if enc {
			lib.Encrypted = true
		}
		lib.Linked = append(lib.Linked, dylibs...)
		off += entrySize
	}
	lib.Linked = dedupeStrings(lib.Linked)
}

// parseMachOSlice parses one Mach-O image at the given offset and returns
// its architecture, whether it is encrypted and the dylibs it links.
func parseMachOSlice(data []byte, base int) (arch string, encrypted bool, dylibs []string) {
	if base < 0 || base+28 > len(data) {
		return "", false, nil
	}

	var order binary.ByteOrder = binary.LittleEndian
	var is64 bool
	switch binary.LittleEndian.Uint32(data[base:]) {
	case mhMagic64:
		is64 = true
	case mhMagic32:
		is64 = false
	case mhCigam64:
		is64, order = true, binary.BigEndian
	case mhCigam32:
		is64, order = false, binary.BigEndian
	default:
		return "", false, nil
	}

	arch = archForCPU(order.Uint32(data[base+4:]))

	ncmds := order.Uint32(data[base+16:])
	if ncmds == 0 || ncmds > mhMaxCmds {
		return arch, false, nil
	}

	hdrSize := 28
	if is64 {
		hdrSize = 32
	}

	off := base + hdrSize
	for i := 0; i < int(ncmds); i++ {
		if off+8 > len(data) {
			break
		}
		cmd := order.Uint32(data[off:])
		cmdsize := int(order.Uint32(data[off+4:]))
		if cmdsize < 8 {
			break
		}
		if off+cmdsize > len(data) {
			break
		}

		switch cmd {
		case lcEncryptionInfo, lcEncryption64:
			if off+20 <= len(data) && order.Uint32(data[off+16:]) != 0 {
				encrypted = true
			}
		case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDyl,
			lcLoadDylib | mhLoadBias, lcLoadWeakDylib | mhLoadBias,
			lcReexportDylib | mhLoadBias, lcLoadUpwardDyl | mhLoadBias:
			// The dylib name offset is relative to the start of the load
			// command and must stay inside it. A crafted command with an
			// out-of-range offset used to panic here.
			if off+12 <= len(data) {
				nameOff := int(order.Uint32(data[off+8:]))
				if nameOff > 0 && nameOff < cmdsize {
					start := off + nameOff
					end := off + cmdsize
					if end > len(data) {
						end = len(data)
					}
					if start < end {
						if idx := indexByte(data[start:end], 0); idx > 0 {
							dylibs = append(dylibs, string(data[start:start+idx]))
						}
					}
				}
			}
		}

		off += cmdsize
	}

	return arch, encrypted, dylibs
}

// extractInstallName returns the install name declared by LC_ID_DYLIB, if
// the binary is a dylib.
func extractInstallName(data []byte) string {
	if len(data) < 28 {
		return ""
	}
	order := binary.ByteOrder(binary.LittleEndian)
	switch order.Uint32(data[:4]) {
	case mhCigam64, mhCigam32:
		order = binary.BigEndian
	}
	cpu := order.Uint32(data[4:12])
	if cpu != 0x0100000c && cpu != 0x0000000c {
		// Only dylibs carry LC_ID_DYLIB; skip the load-command walk for
		// executables.
		return ""
	}
	ncmds := order.Uint32(data[16:20])
	if ncmds == 0 || ncmds > mhMaxCmds {
		return ""
	}
	off := 32
	for i := 0; i < int(ncmds) && off+12 <= len(data); i++ {
		cmd := order.Uint32(data[off:])
		cmdsize := int(order.Uint32(data[off+4:]))
		if cmdsize < 8 || off+cmdsize > len(data) {
			break
		}
		if cmd == 0xd {
			nameOff := int(order.Uint32(data[off+8:]))
			if nameOff > 0 && nameOff < cmdsize {
				start := off + nameOff
				end := off + cmdsize
				if end > len(data) {
					end = len(data)
				}
				if start < end {
					if idx := indexByte(data[start:end], 0); idx > 0 {
						return string(data[start : start+idx])
					}
				}
			}
		}
		off += cmdsize
	}
	return ""
}

// archForCPU maps a Mach-O cpu type to a human-readable architecture.
func archForCPU(cpu uint32) string {
	switch cpu {
	case 0x0100000c: // CPU_TYPE_ARM64
		return "arm64"
	case 0x0200000c: // CPU_TYPE_ARM64_32
		return "arm64_32"
	case 0x0000000c: // CPU_TYPE_ARM
		return "armv7"
	case 0x01000007: // CPU_TYPE_X86_64
		return "x86_64"
	case 0x00000007: // CPU_TYPE_X86
		return "i386"
	default:
		return fmt.Sprintf("cpu_%x", cpu)
	}
}

// dedupeStrings removes duplicates while preserving order.
func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
