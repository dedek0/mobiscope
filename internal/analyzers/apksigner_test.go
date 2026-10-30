package analyzers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseApksignerOutput_ValidV2V3(t *testing.T) {
	out := "Verifies\n" +
		"Verified using v1 scheme (JAR signing): true\n" +
		"Verified using v2 scheme (APK Signature Scheme v2): true\n" +
		"Verified using v3 scheme (APK Signature Scheme v3): true\n" +
		"Signing certificate #1 SHA-256 digest: 0011223344aabbcc\n" +
		"Signer #1 certificate DN: CN=Release, O=Example\n"

	scheme, certFP, signerCount, debug := parseApksignerOutput(out)
	assert.Equal(t, "v3", scheme, "highest verified scheme wins")
	assert.Equal(t, "0011223344aabbcc", certFP)
	assert.Equal(t, "1", signerCount)
	assert.Empty(t, debug)
}

func TestParseApksignerOutput_V2OverridesV1(t *testing.T) {
	out := "Verified using v1 scheme (JAR signing): true\n" +
		"Verified using v2 scheme (APK Signature Scheme v2): true\n" +
		"Signing certificate #1 SHA-256 digest: aabbccdd\n"

	scheme, certFP, _, _ := parseApksignerOutput(out)
	assert.Equal(t, "v2", scheme)
	assert.Equal(t, "aabbccdd", certFP)
}

func TestParseApksignerOutput_V1Only(t *testing.T) {
	out := "Verified using v1 scheme (JAR signing): true\n"
	scheme, certFP, signerCount, debug := parseApksignerOutput(out)
	assert.Equal(t, "v1", scheme)
	assert.Empty(t, certFP)
	// No signer block in the output: the count is unknown, not zero.
	assert.Equal(t, "unknown", signerCount)
	assert.Empty(t, debug)
}

func TestParseApksignerOutput_Malformed(t *testing.T) {
	for _, out := range []string{"", "complete garbage\nno fields here", "\x00\x01\x02"} {
		scheme, certFP, signerCount, debug := parseApksignerOutput(out)
		assert.Empty(t, scheme, "input: %q", out)
		assert.Empty(t, certFP, "input: %q", out)
		// Unparsable output means "unknown", not "0": reporting zero would
		// claim the APK has no signer.
		assert.Equal(t, "unknown", signerCount, "input: %q", out)
		assert.Empty(t, debug, "input: %q", out)
	}
}

func TestParseApksignerOutput_SignerCount(t *testing.T) {
	out := "Signer #1 certificate DN: CN=First\n" +
		"Signer #2 certificate DN: CN=Second\n"
	_, _, signerCount, _ := parseApksignerOutput(out)
	assert.Equal(t, "2", signerCount)
}

// TestParseApksignerOutput_DebugCert asserts debug-signed detection now
// works: the dedicated "Signer #1 certificate DN: ... Debug ..." case is
// matched before any generic handling (previously it was shadowed and
// `debug` was always "").
func TestParseApksignerOutput_DebugCert(t *testing.T) {
	out := "Signer #1 certificate DN: CN=Android Debug, O=Android, C=US\n"
	scheme, _, signerCount, debug := parseApksignerOutput(out)
	assert.Equal(t, "true", debug)
	assert.Equal(t, "1", signerCount)
	assert.Empty(t, scheme)
}

func TestMetaInfHeuristic_SignaturePresent(t *testing.T) {
	path := buildZipFile(t, filepath.Join(t.TempDir(), "signed.apk"), map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
		"META-INF/CERT.RSA":    "certdata",
		"classes.dex":          "dex",
	})

	scheme, certFP, signerCount := metaInfHeuristic(path)
	assert.Equal(t, "v1", scheme)
	assert.Empty(t, certFP)
	assert.Equal(t, "1", signerCount)
}

func TestMetaInfHeuristic_NoSignatures(t *testing.T) {
	path := buildZipFile(t, filepath.Join(t.TempDir(), "unsigned.apk"), map[string]string{
		"classes.dex": "dex",
	})

	scheme, _, signerCount := metaInfHeuristic(path)
	assert.Equal(t, "none", scheme)
	assert.Equal(t, "0", signerCount)
}

func TestMetaInfHeuristic_NotAZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.apk")
	require.NoError(t, os.WriteFile(path, []byte("junk"), 0o600))

	scheme, _, signerCount := metaInfHeuristic(path)
	assert.Equal(t, unknownVersion, scheme)
	assert.Equal(t, "unknown", signerCount)
}

func TestConvertApkSignerFindings(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantCount int
		wantTitle string
		wantSev   models.Severity
	}{
		{
			name:      "debug signed",
			output:    `{"signature_scheme":"v2","signing_cert_fp":"aa","signer_count":"1","debug_signed":true}`,
			wantCount: 1,
			wantTitle: "APK is debug-signed",
			wantSev:   models.SeverityHigh,
		},
		{
			name:      "no signer",
			output:    `{"signature_scheme":"none","signing_cert_fp":"","signer_count":"0","debug_signed":false}`,
			wantCount: 1,
			wantTitle: "APK has no signer",
			wantSev:   models.SeverityHigh,
		},
		{
			name:      "v1 only",
			output:    `{"signature_scheme":"v1","signing_cert_fp":"bb","signer_count":"1","debug_signed":false}`,
			wantCount: 1,
			wantTitle: "APK uses only v1 (JAR) signing",
			wantSev:   models.SeverityMedium,
		},
		{
			name:      "clean v2 release",
			output:    `{"signature_scheme":"v2","signing_cert_fp":"cc","signer_count":"1","debug_signed":false}`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ConvertApkSignerFindings([]byte(tt.output), "sess")
			assert.Len(t, findings, tt.wantCount)
			if tt.wantCount == 0 {
				return
			}
			assert.Equal(t, tt.wantTitle, findings[0].Title)
			assert.Equal(t, tt.wantSev, findings[0].Severity)
			assert.Equal(t, "manifest_issue", string(findings[0].Category))
			assert.Equal(t, "android", string(findings[0].Platform))
			assert.Equal(t, "sess", findings[0].SessionID)
		})
	}
}

func TestConvertApkSignerFindings_InvalidJSON(t *testing.T) {
	assert.Nil(t, ConvertApkSignerFindings([]byte("{not json"), "s"))
}

// writeApksignerStub writes an apksigner shell stub whose body is the given
// script (after the --version shim) and prepends it to PATH.
func writeApksignerStub(t *testing.T, dir, body string, exitCode int) {
	t.Helper()
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then echo 'apksigner 4.0'; exit 0; fi\n" +
		body +
		"\nexit " + itoa(exitCode) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "apksigner"), []byte(script), 0o755))
}

const validVerifyOutput = `Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Signing certificate #1 SHA-256 digest: 0011223344aabbcc
Signer #1 certificate DN: CN=Release, O=Example
`

func TestApkSigner_Run_MockBinarySuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	writeApksignerStub(t, dir, "cat <<'EOF'\n"+validVerifyOutput+"EOF\n", 0)
	withMockBinaries(t, dir)

	target := buildZipFile(t, filepath.Join(dir, "app.apk"), map[string]string{
		"AndroidManifest.xml": "<manifest/>",
	})

	a := NewApkSigner()
	res, err := a.Run(context.Background(), target, t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, res.Error)

	var out apksignerOutput
	require.NoError(t, json.Unmarshal(res.Output, &out))
	assert.Equal(t, "v2", out.SignatureScheme)
	assert.Equal(t, "0011223344aabbcc", out.SigningCertFP)
	assert.Equal(t, "1", out.SignerCount)
	assert.False(t, out.DebugSigned)
}

func TestApkSigner_Run_MockBinaryNonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	// Non-zero exit: Run must degrade to the META-INF heuristic without
	// failing the analyzer (apksigner is fail-soft).
	writeApksignerStub(t, dir, "echo 'ERROR: cannot read apksigner output' >&2\n", 2)
	withMockBinaries(t, dir)

	target := buildZipFile(t, filepath.Join(dir, "app.apk"), map[string]string{
		"AndroidManifest.xml": "<manifest/>",
	})

	a := NewApkSigner()
	res, err := a.Run(context.Background(), target, t.TempDir())
	require.NoError(t, err, "apksigner failure is non-fatal")
	assert.Contains(t, res.Error, "exited with code 2")

	var out apksignerOutput
	require.NoError(t, json.Unmarshal(res.Output, &out))
	assert.Equal(t, "none", out.SignatureScheme, "falls back to META-INF scan")
	assert.Equal(t, "0", out.SignerCount)
}

func TestApkSigner_Run_FallsBackWhenBinaryMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	// PATH without apksigner at all: heuristic path, no error.
	empty := t.TempDir()
	t.Setenv("PATH", empty)

	target := buildZipFile(t, filepath.Join(t.TempDir(), "app.apk"), map[string]string{
		"META-INF/CERT.RSA": "cert",
	})

	a := NewApkSigner()
	res, err := a.Run(context.Background(), target, t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, res.Error)

	var out apksignerOutput
	require.NoError(t, json.Unmarshal(res.Output, &out))
	assert.Equal(t, "v1", out.SignatureScheme)
	assert.Equal(t, "1", out.SignerCount)
}

func TestSigningIdentity_MockBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	writeApksignerStub(t, dir, "cat <<'EOF'\n"+validVerifyOutput+"EOF\n", 0)
	withMockBinaries(t, dir)

	target := buildZipFile(t, filepath.Join(dir, "app.apk"), map[string]string{
		"AndroidManifest.xml": "<manifest/>",
	})

	fp, scheme := SigningIdentity(target)
	assert.Equal(t, "0011223344aabbcc", fp)
	assert.Equal(t, "v2", scheme)
}

func TestAndroidManifestInfo_NetworkOnlyWhenNSCExists(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
  <application android:networkSecurityConfig="@xml/custom_nsc" />
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	info := AndroidManifestInfo(dir)
	assert.Empty(t, info.Network.Kind, "no NSC file means no network inventory claim")

	nscDir := filepath.Join(jadxDir, "res", "xml")
	require.NoError(t, os.MkdirAll(nscDir, 0o755))
	nsc := `<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="system" /></trust-anchors>
  </base-config>
  <domain-config><pin-set><pin digest="SHA-256">abc=</pin></pin-set></domain-config>
</network-security-config>`
	require.NoError(t, os.WriteFile(filepath.Join(nscDir, "custom_nsc.xml"), []byte(nsc), 0o600))

	info = AndroidManifestInfo(dir)
	assert.Equal(t, "network_security_config", info.Network.Kind)
	assert.True(t, info.Network.CleartextPermitted)
	assert.True(t, info.Network.Pinned)
}
