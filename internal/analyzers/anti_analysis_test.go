package analyzers

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildMinimalDEX writes a DEX file with the given class descriptors so the
// class-name extraction and the obfuscation score can be exercised.
func buildMinimalDEX(t *testing.T, classes []string) []byte {
	t.Helper()

	const headerSize = 0x70

	stringData := make([]byte, 0)
	stringOffsets := make([]uint32, 0, len(classes))
	stringIDsOff := uint32(headerSize)
	stringDataOff := uint32(headerSize) + uint32(len(classes))*4

	for _, c := range classes {
		stringOffsets = append(stringOffsets, stringDataOff+uint32(len(stringData)))
		stringData = append(stringData, 0x01) // uleb128 length placeholder
		stringData = append(stringData, []byte(c)...)
		stringData = append(stringData, 0x00)
	}

	typeIDsOff := stringDataOff + uint32(len(stringData))
	classDefsOff := typeIDsOff + uint32(len(classes))*4

	total := int(classDefsOff) + len(classes)*32
	data := make([]byte, total)

	copy(data[0:8], []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(data[0x38:], uint32(len(classes))) // string_ids_size
	binary.LittleEndian.PutUint32(data[0x3c:], stringIDsOff)         // string_ids_off
	binary.LittleEndian.PutUint32(data[0x40:], uint32(len(classes))) // type_ids_size
	binary.LittleEndian.PutUint32(data[0x44:], typeIDsOff)           // type_ids_off
	binary.LittleEndian.PutUint32(data[0x60:], uint32(len(classes))) // class_defs_size
	binary.LittleEndian.PutUint32(data[0x64:], classDefsOff)         // class_defs_off

	for i, off := range stringOffsets {
		binary.LittleEndian.PutUint32(data[stringIDsOff+uint32(i)*4:], off)
	}
	for i := range classes {
		binary.LittleEndian.PutUint32(data[typeIDsOff+uint32(i)*4:], uint32(i))
	}
	for i := range classes {
		off := classDefsOff + uint32(i)*32
		binary.LittleEndian.PutUint32(data[off:], uint32(i)) // class_idx
	}
	copy(data[stringDataOff:], stringData)

	return data
}

func writeAPKWithFiles(t *testing.T, files map[string][]byte) string {
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

func TestAntiAnalysis_NotADex(t *testing.T) {
	_, err := dexClassNames([]byte("not a dex file at all"))
	assert.Error(t, err)
}

func TestAntiAnalysis_ClassNamesExtracted(t *testing.T) {
	dex := buildMinimalDEX(t, []string{
		"Lcom/example/Service;",
		"Lcom/example/Activity;",
	})
	names, err := dexClassNames(dex)
	require.NoError(t, err)
	assert.Equal(t, []string{"Lcom/example/Service;", "Lcom/example/Activity;"}, names)
}

func TestAntiAnalysis_ObfuscatedRatio(t *testing.T) {
	classes := []string{
		"Lcom/example/a;",
		"Lcom/example/b;",
		"Lcom/example/c;",
		"Lcom/example/d;",
		"Lcom/example/RealClassName;",
	}
	ratio := obfuscatedRatio(classes)
	assert.InDelta(t, 0.8, ratio, 0.001)

	// The resource class and BuildConfig are never evidence of obfuscation.
	assert.False(t, isObfuscatedClassName("Lcom/example/R;"))
	assert.False(t, isObfuscatedClassName("Lcom/example/BuildConfig;"))
	assert.False(t, isObfuscatedClassName("Lcom/example/Foo$Bar;"))
	assert.True(t, isObfuscatedClassName("Lcom/example/Foo$a;"))
}

func TestAntiAnalysis_MarkersDetected(t *testing.T) {
	markers := scanAntiAnalysisMarkers([]byte("...check /system/bin/su ... frida-agent ... goldfish ... DexClassLoader ..."))
	kinds := map[string]bool{}
	for _, m := range markers {
		kinds[m.Kind] = true
	}
	assert.True(t, kinds["root"])
	assert.True(t, kinds["frida"])
	assert.True(t, kinds["emulator"])
	assert.True(t, kinds["dynamic-code"])
}

func TestAntiAnalysis_RunOnArchive(t *testing.T) {
	classes := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		classes = append(classes, fmt.Sprintf("Lcom/example/%c;", 'a'+i%26))
	}
	dex := buildMinimalDEX(t, classes)
	// Splice the markers into the DEX payload so the raw scan finds them.
	dex = append(dex, []byte("/system/bin/su\x00frida\x00goldfish\x00")...)

	apk := writeAPKWithFiles(t, map[string][]byte{
		"classes.dex":        dex,
		"assets/mapping.txt": []byte("com.example.Foo -> a.b.c:\n"),
	})

	result, err := NewAntiAnalysis().Run(context.Background(), apk, t.TempDir())
	require.NoError(t, err)

	var summary antiAnalysisSummary
	require.NoError(t, jsonUnmarshal(result.Output, &summary))
	assert.Equal(t, 25, summary.ClassCount)
	assert.InDelta(t, 1.0, summary.ObfuscatedRatio, 0.001)
	assert.Equal(t, "R8/ProGuard", summary.Toolchain)
	require.NotEmpty(t, summary.Markers)

	findings := ConvertAntiAnalysisFindings(result.Output, "sess")
	require.NotEmpty(t, findings)
	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
		assert.Equal(t, models.CategoryAntiAnalysis, f.Category)
		assert.Equal(t, "anti_analysis", f.SourceTool)
	}
	assert.True(t, titles["App detects root"])
	assert.True(t, titles["App detects or uses Frida"])
	assert.True(t, titles["App is obfuscated"])
	assert.True(t, titles["Obfuscation toolchain detected"])
}

// jsonUnmarshal is a small helper so the test reads naturally.
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
