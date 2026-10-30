package analyzers

import (
	"archive/zip"
	"context"
	debugelf "debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildMinimalELF writes a small but structurally valid ELF64 shared object
// so the hardening checks can be exercised without a real toolchain.
func buildMinimalELF(t *testing.T, opts elfFixture) []byte {
	t.Helper()

	const (
		ehSize = 64
		phSize = 56
		dynSz  = 16
	)

	phCount := 1
	if opts.hasGnuStack {
		phCount = 2
	}

	total := ehSize + phCount*phSize
	// One PT_LOAD, one optional PT_GNU_STACK, then room for PT_DYNAMIC.
	data := make([]byte, total+dynSz)

	copy(data[0:4], []byte{0x7f, 'E', 'L', 'F'})
	data[4] = 2                                               // ELFCLASS64
	data[5] = 1                                               // ELFDATA2LSB
	data[6] = 1                                               // EV_CURRENT
	binary.LittleEndian.PutUint16(data[16:], 3)               // e_type = ET_DYN
	binary.LittleEndian.PutUint16(data[18:], 0x3e)            // e_machine = EM_X86_64
	binary.LittleEndian.PutUint32(data[20:], 1)               // e_version
	binary.LittleEndian.PutUint64(data[24:], 0x4000)          // e_entry
	binary.LittleEndian.PutUint64(data[32:], ehSize)          // e_phoff
	binary.LittleEndian.PutUint16(data[52:], ehSize)          // e_ehsize
	binary.LittleEndian.PutUint16(data[54:], phSize)          // e_phentsize
	binary.LittleEndian.PutUint16(data[56:], uint16(phCount)) // e_phnum

	// PT_LOAD: r-x
	ph := ehSize
	binary.LittleEndian.PutUint32(data[ph:], uint32(debugelf.PT_LOAD))
	binary.LittleEndian.PutUint32(data[ph+4:], 4)       // PF_R
	binary.LittleEndian.PutUint64(data[ph+16:], 0x1000) // p_vaddr
	binary.LittleEndian.PutUint64(data[ph+32:], 0x1000) // p_filesz
	binary.LittleEndian.PutUint64(data[ph+40:], 0x1000) // p_memsz

	// PT_GNU_STACK: the flags decide NX.
	if opts.hasGnuStack {
		ph += phSize
		binary.LittleEndian.PutUint32(data[ph:], uint32(debugelf.PT_GNU_STACK))
		flags := uint32(6) // PF_R | PF_W
		if opts.execStack {
			flags |= 1 // PF_X
		}
		binary.LittleEndian.PutUint32(data[ph+4:], flags)
		binary.LittleEndian.PutUint64(data[ph+16:], 0x1000)
		binary.LittleEndian.PutUint64(data[ph+32:], 0x1000)
		binary.LittleEndian.PutUint64(data[ph+40:], 0x1000)
	}

	// A .rodata blob with the marker strings the anti-analysis scan looks
	// for.
	blob := opts.blob
	if blob != "" {
		data = append(data, []byte(blob)...)
	}
	return data
}

type elfFixture struct {
	hasGnuStack bool
	execStack   bool
	blob        string
}

// writeAPKWithLib packs the given files into a zip and returns its path.
func writeAPKWithLib(t *testing.T, files map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.apk")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, data := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return path
}

func TestELF_NotAnELF(t *testing.T) {
	assert.False(t, isELF([]byte("hello")))
	assert.False(t, isELF(nil))
}

func TestELF_CollectFromArchive(t *testing.T) {
	elfData := buildMinimalELF(t, elfFixture{hasGnuStack: true, blob: "frida-agent\x00/system/bin/su\x00"})
	apk := writeAPKWithLib(t, map[string][]byte{
		"lib/arm64-v8a/libdemo.so": elfData,
		"lib/arm64-v8a/notes.txt":  []byte("not a library"),
		"classes.dex":              []byte("dex"),
	})

	e := NewELF()
	result, err := e.Run(context.Background(), apk, t.TempDir())
	require.NoError(t, err)

	libs := NativeLibsFromRuns([]models.ToolResult{result})
	require.Len(t, libs, 1)
	assert.Equal(t, "lib/arm64-v8a/libdemo.so", libs[0].Path)
	assert.Equal(t, "so", libs[0].Kind)
	assert.Equal(t, []string{"x86_64"}, libs[0].Archs)

	// ET_DYN means position-independent.
	require.NotNil(t, libs[0].PIE)
	assert.True(t, *libs[0].PIE)

	// A PT_GNU_STACK without PF_X means the stack is not executable.
	require.NotNil(t, libs[0].NX)
	assert.True(t, *libs[0].NX)

	assert.Contains(t, libs[0].AntiAnalysis, "frida")
	assert.Contains(t, libs[0].AntiAnalysis, "root")
}

func TestELF_ExecutableStackIsDetected(t *testing.T) {
	elfData := buildMinimalELF(t, elfFixture{hasGnuStack: true, execStack: true})
	apk := writeAPKWithLib(t, map[string][]byte{"lib/armeabi-v7a/libbad.so": elfData})

	result, err := NewELF().Run(context.Background(), apk, t.TempDir())
	require.NoError(t, err)

	libs := NativeLibsFromRuns([]models.ToolResult{result})
	require.Len(t, libs, 1)
	require.NotNil(t, libs[0].NX)
	assert.False(t, *libs[0].NX)
}

func TestELF_FindingsForMissingHardening(t *testing.T) {
	lib := models.NativeLib{
		Path:         "lib/arm64-v8a/libbad.so",
		Kind:         "so",
		PIE:          boolPtr(false),
		RELRO:        "none",
		NX:           boolPtr(false),
		StackCanary:  boolPtr(false),
		TextRelocs:   true,
		HasRPath:     true,
		AntiAnalysis: []string{"frida"},
	}

	raw := mustJSON(t, map[string]interface{}{"native_libs": []models.NativeLib{lib}})
	findings := ConvertELFFindings(raw, "sess")

	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
		assert.Equal(t, "elf", f.SourceTool)
		assert.Equal(t, "sess", f.SessionID)
		if f.Title == "Native library contains an anti-analysis marker" {
			assert.Equal(t, models.CategoryObfuscation, f.Category)
		} else {
			assert.Equal(t, models.CategoryBinaryHardening, f.Category)
		}
	}

	assert.True(t, titles["Native library is not position-independent"])
	assert.True(t, titles["Native library has no RELRO"])
	assert.True(t, titles["Native library has an executable stack"])
	assert.True(t, titles["Native library has no stack canary"])
	assert.True(t, titles["Native library has text relocations"])
	assert.True(t, titles["Native library declares an RPATH/RUNPATH"])
}

func TestELF_NoFindingsForHardenedLibrary(t *testing.T) {
	lib := models.NativeLib{
		Path:        "lib/arm64-v8a/libgood.so",
		Kind:        "so",
		PIE:         boolPtr(true),
		RELRO:       "full",
		NX:          boolPtr(true),
		StackCanary: boolPtr(true),
		Fortify:     boolPtr(true),
	}

	raw := mustJSON(t, map[string]interface{}{"native_libs": []models.NativeLib{lib}})
	findings := ConvertELFFindings(raw, "sess")
	assert.Empty(t, findings)
}

func TestELF_AntiAnalysisMarkers(t *testing.T) {
	markers := elfAntiAnalysis([]byte("ptrace\x00TracerPid\x00/system/xbin/su\x00goldfish\x00"))
	assert.Contains(t, markers, "anti-debug")
	assert.Contains(t, markers, "root")
	assert.Contains(t, markers, "emulator")
}

func boolPtr(b bool) *bool { return &b }

// mustJSON marshals v, failing the test on error.
func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}

func TestByteEntropy(t *testing.T) {
	assert.Equal(t, 0.0, byteEntropy(nil))
	assert.Equal(t, 0.0, byteEntropy(make([]byte, 1024)))

	uniform := make([]byte, 4096)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	assert.InDelta(t, 8.0, byteEntropy(uniform), 0.001)
}

func TestDetectELFPacker(t *testing.T) {
	assert.Equal(t, "", detectELFPacker([]byte("ordinary library strings")))
	assert.Equal(t, "UPX", detectELFPacker([]byte("junk UPX! junk")))
	assert.Equal(t, "360 Jiagu", detectELFPacker([]byte("libjiagu.so")))
	assert.Equal(t, "Tencent Legu", detectELFPacker([]byte("libexecmain.so")))
}
