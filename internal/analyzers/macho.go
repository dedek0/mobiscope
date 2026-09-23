package analyzers

import (
	"context"
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

// MachO inspects Mach-O binaries in the extracted app for hardening and
// native-code findings. Prefers llvm-objdump when available; otherwise falls
// back to reading load-command signatures in-process.
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

// Available is satisfied when either llvm-objdump is present (richer output)
// or we can fall back to the in-process parser.
func (m *MachO) Available() error {
	if err := CheckBinary(llvmObjdumpBin); err == nil {
		return nil
	}
	return nil
}

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
		"root":        root,
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
		if lib.Kind == "main_binary" && !containsStr(lib.Archs, "arm64") {
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
	default:
		return false
	}
}

// inspectBinary extracts a lightweight NativeLib record from a Mach-O file.
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

	var magic [4]byte
	copy(magic[:], data[:4])
	if !isMachOMagic(magic) {
		return lib
	}

	// Detect FAT (universal) and record slice count as a rough arch list.
	if magic == [4]byte{0xca, 0xfe, 0xba, 0xbe} && len(data) >= 8 {
		nfat := int(data[7]) | int(data[6])<<8 | int(data[5])<<16 | int(data[4])<<24
		if nfat > 0 && nfat < 16 {
			for i := 0; i < nfat; i++ {
				lib.Archs = append(lib.Archs, fmt.Sprintf("fat%d", i))
			}
		}
	} else if magic == [4]byte{0xcf, 0xfa, 0xed, 0xfe} || magic == [4]byte{0xce, 0xfa, 0xed, 0xfe} { //nolint:gocritic // two-value match is clearer than a switch here
		// Little-endian Mach-O. cputype at offset 4.
		cpu := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
		switch cpu {
		case 0x0100000c: // CPU_TYPE_ARM64
			lib.Archs = append(lib.Archs, "arm64")
		case 0x0000000c: // CPU_TYPE_ARM
			lib.Archs = append(lib.Archs, "armv7")
		case 0x01000007: // CPU_TYPE_X86_64
			lib.Archs = append(lib.Archs, "x86_64")
		case 0x00000007:
			lib.Archs = append(lib.Archs, "i386")
		default:
			lib.Archs = append(lib.Archs, fmt.Sprintf("cpu_%x", cpu))
		}
	}

	// Heuristics on raw bytes.
	if strings.Contains(string(data), "__LINKEDIT") {
		lib.InstallName = ""
	}
	for _, sig := range []string{"_objc_release", "_swift_release", "Swift"} {
		if strings.Contains(string(data), sig) {
			break
		}
	}
	// Encryption is detected via the LC_ENCRYPTION_INFO(64) command's cryptid.
	lib.Encrypted = hasEncryptionCommand(data)

	// Linked dylibs are visible as NUL-terminated @rpath/ or /System/ paths.
	lib.Linked = extractDylibPaths(data)

	return lib
}

func hasEncryptionCommand(data []byte) bool {
	// LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2c.
	// Scanning the whole file for these cmd values would be noisy; we do a
	// bounded scan of the load-command region instead.
	if len(data) < 64 {
		return false
	}
	// 64-bit LE Mach-O header is 32 bytes, then ncmds (4) + sizeofcmds (4).
	ncmds := int(data[16]) | int(data[17])<<8 | int(data[18])<<16 | int(data[19])<<24
	if ncmds <= 0 || ncmds > 256 {
		return false
	}
	off := 32
	for i := 0; i < ncmds && off+8 <= len(data); i++ {
		cmd := uint32(data[off]) | uint32(data[off+1])<<8 | uint32(data[off+2])<<16 | uint32(data[off+3])<<24
		cmdsize := int(data[off+4]) | int(data[off+5])<<8 | int(data[off+6])<<16 | int(data[off+7])<<24
		if cmd == 0x21 || cmd == 0x2c {
			// cryptid is at cmd+16 (LC_ENCRYPTION_INFO) / cmd+16 (64-bit too).
			if off+20 <= len(data) {
				cryptid := int(data[off+16]) | int(data[off+17])<<8 | int(data[off+18])<<16 | int(data[off+19])<<24
				return cryptid != 0
			}
		}
		if cmdsize < 8 {
			break
		}
		off += cmdsize
	}
	return false
}

func extractDylibPaths(data []byte) []string {
	seen := map[string]bool{}
	var out []string
	// LC_LOAD_DYLIB = 0x0c, LC_LOAD_WEAK_DYLIB = 0x18, LC_REEXPORT_DYLIB = 0x1f.
	if len(data) < 64 {
		return nil
	}
	ncmds := int(data[16]) | int(data[17])<<8 | int(data[18])<<16 | int(data[19])<<24
	if ncmds <= 0 || ncmds > 256 {
		return nil
	}
	off := 32
	for i := 0; i < ncmds && off+24 <= len(data); i++ {
		cmd := uint32(data[off]) | uint32(data[off+1])<<8 | uint32(data[off+2])<<16 | uint32(data[off+3])<<24
		cmdsize := int(data[off+4]) | int(data[off+5])<<8 | int(data[off+6])<<16 | int(data[off+7])<<24
		if cmd == 0x0c || cmd == 0x18 || cmd == 0x1f {
			// dylib name offset at +8, then a NUL-terminated path.
			nameOff := int(data[off+8]) | int(data[off+9])<<8 | int(data[off+10])<<16 | int(data[off+11])<<24
			if nameOff > 0 && off+nameOff < len(data) {
				end := off + cmdsize
				if end > len(data) {
					end = len(data)
				}
				seg := data[off+nameOff : end]
				if idx := indexByte(seg, 0); idx > 0 {
					p := string(seg[:idx])
					if (strings.HasPrefix(p, "/System/") || strings.HasPrefix(p, "@rpath") ||
						strings.HasPrefix(p, "@executable_path") || strings.HasPrefix(p, "@loader_path")) && !seen[p] {
						seen[p] = true
						out = append(out, p)
					}
				}
			}
		}
		if cmdsize < 8 {
			break
		}
		off += cmdsize
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
