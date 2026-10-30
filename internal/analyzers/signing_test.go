package analyzers

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCertificate generates a self-signed certificate for the signing tests.
func testCertificate(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Release", Organization: []string{"Example"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return der, cert
}

func lp(value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint32(out, uint32(len(value)))
	copy(out[4:], value)
	return out
}

// v2SignerValue builds the value of a v2 signature block for one signer.
func v2SignerValue(certDER []byte) []byte {
	digests := lp(lp([]byte{0x01, 0x02, 0x03}))
	certs := lp(lp(certDER))
	signedData := append(append(digests, certs...), lp(nil)...)

	signer := make([]byte, 0, 3*4+len(signedData)+len(certDER))
	signer = append(signer, lp(signedData)...)
	signer = append(signer, lp([]byte{0x00})...) // signatures
	signer = append(signer, lp([]byte{0x00})...) // public key
	return lp(signer)
}

// writeSignedAPK writes a ZIP with a v2 APK Signing Block inserted before the
// central directory and fixes the EOCD offset.
func writeSignedAPK(t *testing.T, certDER []byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("AndroidManifest.xml")
	require.NoError(t, err)
	_, err = w.Write([]byte(`<manifest package="com.example.signed"/>`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	data := buf.Bytes()
	eocd := bytes.LastIndex(data, []byte("PK\x05\x06"))
	require.Greater(t, eocd, 0)
	cdOffset := int(binary.LittleEndian.Uint32(data[eocd+16:]))

	value := v2SignerValue(certDER)
	pair := make([]byte, 8+4+len(value))
	binary.LittleEndian.PutUint64(pair, uint64(4+len(value)))
	binary.LittleEndian.PutUint32(pair[8:], sigBlockV2)
	copy(pair[12:], value)

	block := make([]byte, 8+len(pair)+8+16)
	binary.LittleEndian.PutUint64(block, uint64(len(block)-8))
	copy(block[8:], pair)
	binary.LittleEndian.PutUint64(block[8+len(pair):], uint64(len(block)-8))
	copy(block[len(block)-16:], apkSigBlockMagic)

	out := make([]byte, 0, len(data)+len(block))
	out = append(out, data[:cdOffset]...)
	out = append(out, block...)
	out = append(out, data[cdOffset:]...)

	newEOCD := bytes.LastIndex(out, []byte("PK\x05\x06"))
	binary.LittleEndian.PutUint32(out[newEOCD+16:], uint32(cdOffset+len(block)))

	path := filepath.Join(t.TempDir(), "signed.apk")
	require.NoError(t, os.WriteFile(path, out, 0o600))
	return path
}

func TestInspectAPKSigningMaterial_V2(t *testing.T) {
	certDER, cert := testCertificate(t)
	path := writeSignedAPK(t, certDER)

	info, err := inspectAPKSigningMaterial(path)
	require.NoError(t, err)
	assert.Equal(t, "v2", info.Scheme)
	assert.Equal(t, 1, info.SignerCount)
	assert.False(t, info.Debug)
	assert.Contains(t, info.CertSubject, "Test Release")
	assert.Equal(t, "RSA", info.KeyAlg)
	assert.Equal(t, 2048, info.KeyBits)

	sum := sha256.Sum256(cert.Raw)
	assert.Equal(t, hex.EncodeToString(sum[:]), info.CertFP)
}

func TestParseSchemeSigners(t *testing.T) {
	certDER, _ := testCertificate(t)
	certs, count := parseSchemeSigners(v2SignerValue(certDER), false)
	assert.Equal(t, 1, count)
	require.Len(t, certs, 1)
	parsed, err := x509.ParseCertificate(certs[0])
	require.NoError(t, err)
	assert.Equal(t, "Test Release", parsed.Subject.CommonName)
}

func TestMetaInfHeuristic_V2(t *testing.T) {
	certDER, cert := testCertificate(t)
	path := writeSignedAPK(t, certDER)

	scheme, certFP, signerCount := metaInfHeuristic(path)
	assert.Equal(t, "v2", scheme)
	assert.NotEmpty(t, certFP)
	sum := sha256.Sum256(cert.Raw)
	assert.Equal(t, hex.EncodeToString(sum[:]), certFP)
	assert.Equal(t, "1", signerCount)
}

func TestConvertApkSignerFindings_CertificateExpiryAndKeySize(t *testing.T) {
	raw := []byte(`{
		"signature_scheme":"v3",
		"signing_cert_fp":"aa",
		"signer_count":"1",
		"cert_not_after":"2020-01-01T00:00:00Z",
		"key_algorithm":"RSA",
		"key_bits":1024
	}`)
	findings := ConvertApkSignerFindings(raw, "s")
	titles := ""
	for _, f := range findings {
		titles += f.Title + "|"
	}
	assert.Contains(t, titles, "Signing certificate has expired")
	assert.Contains(t, titles, "Weak signing key")
}

func TestReadAPKSigningBlock_NoBlock(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("classes.dex")
	require.NoError(t, err)
	_, err = w.Write([]byte("dex"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	path := filepath.Join(t.TempDir(), "plain.apk")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

	pairs, err := readAPKSigningBlock(path)
	require.NoError(t, err)
	assert.Empty(t, pairs)
}
