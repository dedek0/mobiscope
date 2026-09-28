package analyzers

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"howett.net/plist"
)

// buildZipFile writes a ZIP with the given entries (name -> content).
func buildZipFile(t *testing.T, path string, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	return path
}

// writePlist writes an XML plist dictionary.
func writePlist(t *testing.T, path string, m map[string]interface{}) string {
	t.Helper()
	data, err := plist.Marshal(m, plist.XMLFormat)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestIPAExtract_Run(t *testing.T) {
	workdir := t.TempDir()
	ipa := buildZipFile(t, filepath.Join(workdir, "app.ipa"), map[string]string{
		"Payload/My App.app/Info.plist":       "<plist><dict/></plist>",
		"Payload/My App.app/MyApp":            "binary",
		"Payload/My App.app/_CodeSignature/x": "sig",
	})

	e := NewIPAExtract()
	res, err := e.Run(context.Background(), ipa, workdir)
	require.NoError(t, err)
	assert.Equal(t, "ipa-extract", res.ToolName)
	assert.NotNil(t, res.Output)

	assert.FileExists(t, filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "My App.app", "Info.plist"))
	assert.Equal(t, filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "My App.app"), AppBundleDir(workdir))
}

func TestIPAExtract_ZipSlipRejected(t *testing.T) {
	workdir := t.TempDir()
	ipa := buildZipFile(t, filepath.Join(workdir, "app.ipa"), map[string]string{
		"Payload/My App.app/Info.plist": "<plist><dict/></plist>",
		"../../etc/evil":                "pwned",
		"/abs/evil":                     "pwned",
	})

	e := NewIPAExtract()
	res, err := e.Run(context.Background(), ipa, workdir)
	require.NoError(t, err)

	findings := ConvertIPAExtractFindings(res.Output, "s")
	assert.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Equal(t, "manifest_issue", string(f.Category))
		assert.Equal(t, "high", string(f.Severity))
	}
	// Nothing escaped the extraction dir.
	assert.NoFileExists(t, "/etc/evil")
}

func TestIPAExtract_TooManyEntries(t *testing.T) {
	workdir := t.TempDir()
	path := filepath.Join(workdir, "app.ipa")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < maxZipEntries+1; i++ {
		w, err := zw.Create(strings.Repeat("a", 3) + string(rune('A'+i%26)))
		require.NoError(t, err)
		_, _ = w.Write([]byte("x"))
	}
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

	e := NewIPAExtract()
	_, err := e.Run(context.Background(), path, workdir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many entries")
}

func TestPlistAnalyzer_ATS(t *testing.T) {
	workdir := t.TempDir()
	bundle := filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "App.app")
	require.NoError(t, os.MkdirAll(bundle, 0o755))
	writePlist(t, filepath.Join(bundle, "Info.plist"), map[string]interface{}{
		"CFBundleIdentifier":         "com.example.app",
		"CFBundleShortVersionString": "1.2.3",
		"CFBundleVersion":            "45",
		"MinimumOSVersion":           "14.0",
		"CFBundleExecutable":         "App",
		"NSAppTransportSecurity": map[string]interface{}{
			"NSAllowsArbitraryLoads": true,
			"NSExceptionDomains": map[string]interface{}{
				"api.example.com": map[string]interface{}{
					"NSExceptionAllowsInsecureHTTPLoads": true,
				},
				"ok.example.com": map[string]interface{}{
					"NSIncludesSubdomains": true,
				},
			},
		},
		"UIFileSharingEnabled": true,
		"CFBundleURLTypes": []interface{}{
			map[string]interface{}{"CFBundleURLSchemes": []interface{}{"https", "myapp"}},
		},
	})

	p := NewPlistAnalyzer()
	res, err := p.Run(context.Background(), "", workdir)
	require.NoError(t, err)

	findings := ConvertPlistFindings(res.Output, "s")
	titles := make([]string, 0, len(findings))
	for _, f := range findings {
		titles = append(titles, f.Title)
	}
	joined := strings.Join(titles, "\n")
	assert.Contains(t, joined, "arbitrary loads allowed")
	assert.Contains(t, joined, "api.example.com")
	assert.NotContains(t, joined, "ok.example.com")
	assert.Contains(t, joined, "file sharing")
	assert.Contains(t, joined, "https")
	assert.NotContains(t, joined, "myapp")
}

func TestConvertPlistFindings_NoATS(t *testing.T) {
	raw := []byte(`{"bundle_id":"com.x","ats":{},"url_schemes":[]}`)
	assert.Empty(t, ConvertPlistFindings(raw, "s"))
}

func TestCodeSign_Entitlements(t *testing.T) {
	workdir := t.TempDir()
	bundle := filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "App.app")
	require.NoError(t, os.MkdirAll(bundle, 0o755))
	writePlist(t, filepath.Join(bundle, "Info.plist"), map[string]interface{}{
		"CFBundleExecutable": "App",
	})
	writePlist(t, filepath.Join(bundle, "entitlements.plist"), map[string]interface{}{
		"get-task-allow": true,
		"com.apple.security.cs.disable-library-validation": true,
		"com.apple.private.security.container-manager":     true,
		"aps-environment": "development",
	})

	c := NewCodeSign()
	res, err := c.Run(context.Background(), "", workdir)
	require.NoError(t, err)

	findings := ConvertCodeSignFindings(res.Output, "s")
	joined := ""
	for _, f := range findings {
		joined += f.Title + "\n"
	}
	assert.Contains(t, joined, "get-task-allow")
	assert.Contains(t, joined, "Library validation disabled")
	assert.Contains(t, joined, "Private entitlement")
	assert.Contains(t, joined, "APNs environment is development")

	for _, f := range findings {
		assert.Equal(t, "entitlement", string(f.Category))
		assert.Equal(t, "ios", string(f.Platform))
	}
}

func TestCodeSign_NoFindingsWhenClean(t *testing.T) {
	raw := []byte(`{"entitlements":{"application-identifier":"TEAM.com.x"}}`)
	assert.Empty(t, ConvertCodeSignFindings(raw, "s"))
}

func TestMachO_DetectsMachOMagic(t *testing.T) {
	assert.True(t, isMachOMagic([4]byte{0xcf, 0xfa, 0xed, 0xfe}))
	assert.True(t, isMachOMagic([4]byte{0xca, 0xfe, 0xba, 0xbe}))
	assert.False(t, isMachOMagic([4]byte{'P', 'K', 3, 4}))
}

func TestMachO_InspectBinary(t *testing.T) {
	workdir := t.TempDir()
	bundle := filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "App.app")
	require.NoError(t, os.MkdirAll(bundle, 0o755))
	writePlist(t, filepath.Join(bundle, "Info.plist"), map[string]interface{}{
		"CFBundleExecutable": "App",
	})

	// Minimal 64-bit LE Mach-O: 32-byte header, then one
	// LC_ENCRYPTION_INFO_64 load command with cryptid=1.
	bin := make([]byte, 256)
	bin[0], bin[1], bin[2], bin[3] = 0xcf, 0xfa, 0xed, 0xfe // MH_MAGIC_64 LE
	bin[4], bin[5], bin[6], bin[7] = 0x0c, 0x00, 0x00, 0x01 // CPU_TYPE_ARM64
	bin[16] = 1                                             // ncmds
	// Load command at offset 32.
	bin[32], bin[33], bin[34], bin[35] = 0x2c, 0, 0, 0 // LC_ENCRYPTION_INFO_64
	bin[36] = 24                                       // cmdsize
	bin[48], bin[49], bin[50], bin[51] = 1, 0, 0, 0    // cryptid = 1
	require.NoError(t, os.WriteFile(filepath.Join(bundle, "App"), bin, 0o600))

	m := NewMachO()
	res, err := m.Run(context.Background(), "", workdir)
	require.NoError(t, err)

	assert.Contains(t, string(res.Output), "arm64")
	assert.Contains(t, string(res.Output), `"encrypted":true`)

	findings := ConvertMachOFindings(res.Output, "s")
	joined := ""
	for _, f := range findings {
		joined += f.Title + "\n"
	}
	assert.Contains(t, joined, "Encrypted binary")
}

func TestStrings_ExtractPrintable(t *testing.T) {
	got := extractPrintable([]byte("ab\x00world this is a longer string\x01cd"))
	assert.Contains(t, got, "world this is a longer string")
	// Runs shorter than 4 chars are dropped.
	assert.NotContains(t, got, "ab")
	assert.NotContains(t, got, "cd")
}

func TestStrings_ConvertFindsSecrets(t *testing.T) {
	raw := []byte(`{"strings":["App.bin|AKIAIOSFODNN7EXAMPLE and more","App.bin|nothing here"]}`)

	findings := ConvertStringsFindings(raw, "s")
	require.NotEmpty(t, findings)
	assert.Equal(t, "secret", string(findings[0].Category))
	assert.Equal(t, "ios", string(findings[0].Platform))
}

func TestInventoryIOS_Analyze(t *testing.T) {
	workdir := t.TempDir()
	bundle := filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "App.app")
	require.NoError(t, os.MkdirAll(bundle, 0o755))
	writePlist(t, filepath.Join(bundle, "Info.plist"), map[string]interface{}{
		"CFBundleIdentifier": "com.x",
		"NSAppTransportSecurity": map[string]interface{}{
			"NSAllowsArbitraryLoads": true,
		},
	})

	inv := NewInventoryIOS()
	findings := inv.Analyze(workdir, "s")
	joined := ""
	for _, f := range findings {
		joined += f.Title + "\n"
	}
	assert.Contains(t, joined, "arbitrary loads")
}

func TestIOSAppInfo(t *testing.T) {
	workdir := t.TempDir()
	bundle := filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "App.app")
	require.NoError(t, os.MkdirAll(bundle, 0o755))
	writePlist(t, filepath.Join(bundle, "Info.plist"), map[string]interface{}{
		"CFBundleIdentifier":         "com.example.app",
		"CFBundleShortVersionString": "2.0",
		"CFBundleVersion":            "9",
		"MinimumOSVersion":           "15.0",
	})

	info := IOSAppInfo(workdir)
	assert.Equal(t, "com.example.app", info.BundleID)
	assert.Equal(t, "2.0", info.VersionName)
	assert.Equal(t, "9", info.VersionCode)
	assert.Equal(t, "15.0", info.MinOS)
	assert.Equal(t, "NSAppTransportSecurity", info.Network.Kind)
}

func TestExtractPlistFromBytes(t *testing.T) {
	body := []byte("GARBAGE<plist version=\"1.0\"><dict><key>get-task-allow</key><true/></dict></plist>TRAILING")
	m := extractPlistFromBytes(body)
	require.NotNil(t, m)
	assert.Equal(t, true, m["get-task-allow"])
}
