package analyzers

import (
	"archive/zip"
	"bytes"
	"crypto"
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
	der, cert, _ := testCertificateWithKey(t)
	return der, cert
}

// testCertificateWithKey also returns the private key so a test can produce a
// valid signature.
func testCertificateWithKey(t *testing.T) ([]byte, *x509.Certificate, *rsa.PrivateKey) {
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
	return der, cert, key
}

// lpWithAlg builds a uint32 algorithm id followed by a length-prefixed value.
func lpWithAlg(id uint32, value []byte) []byte {
	out := make([]byte, 8+len(value))
	binary.LittleEndian.PutUint32(out, id)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(value)))
	copy(out[8:], value)
	return out
}

// buildV2Value assembles the value of a v2 ID-value pair for one signer.
func buildV2Value(certDER, publicKeyDER, digest, signature []byte) []byte {
	digests := lp(lpWithAlg(0x0102, digest))
	certs := lp(lp(certDER))
	signedData := append(append(digests, certs...), lp(nil)...)

	signatures := lp(lpWithAlg(0x0102, signature))
	signer := append(lp(signedData), signatures...)
	signer = append(signer, lp(publicKeyDER)...)
	return lp(signer)
}

// buildSigningBlock wraps a v2 value in the APK Signing Block framing.
func buildSigningBlock(value []byte) []byte {
	pair := make([]byte, 8+4+len(value))
	binary.LittleEndian.PutUint64(pair, uint64(4+len(value)))
	binary.LittleEndian.PutUint32(pair[8:], sigBlockV2)
	copy(pair[12:], value)

	block := make([]byte, 8+len(pair)+8+16)
	binary.LittleEndian.PutUint64(block, uint64(len(block)-8))
	copy(block[8:], pair)
	binary.LittleEndian.PutUint64(block[8+len(pair):], uint64(len(block)-8))
	copy(block[len(block)-16:], apkSigBlockMagic)
	return block
}

// testContentDigest recomputes the v2 content digest the same way the
// verifier does.
func testContentDigest(prefix, centralDir, eocd []byte, blockOffset int) []byte {
	var chunkDigests []byte
	chunks := uint32(0)
	add := func(chunk []byte) {
		h := sha256.New()
		h.Write([]byte{0x5a})
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(len(chunk)))
		h.Write(b[:])
		h.Write(chunk)
		chunkDigests = append(chunkDigests, h.Sum(nil)...)
		chunks++
	}
	addSection := func(data []byte) {
		for len(data) > 0 {
			n := len(data)
			if n > 1<<20 {
				n = 1 << 20
			}
			add(data[:n])
			data = data[n:]
		}
	}
	addSection(prefix)
	addSection(centralDir)
	patched := append([]byte(nil), eocd...)
	binary.LittleEndian.PutUint32(patched[16:], uint32(blockOffset))
	addSection(patched)

	h := sha256.New()
	h.Write([]byte{0x5a})
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], chunks)
	h.Write(b[:])
	h.Write(chunkDigests)
	return h.Sum(nil)
}

// writeValidSignedAPK writes an APK with a correctly signed v2 block.
func writeValidSignedAPK(t *testing.T) string {
	t.Helper()
	certDER, _, key := testCertificateWithKey(t)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("AndroidManifest.xml")
	require.NoError(t, err)
	_, err = w.Write([]byte(`<manifest package="com.example.signed"/>`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	data := buf.Bytes()

	eocdIndex := bytes.LastIndex(data, []byte("PK\x05\x06"))
	require.Greater(t, eocdIndex, 0)
	cdOffset := int(binary.LittleEndian.Uint32(data[eocdIndex+16:]))
	eocdOffset := eocdIndex
	prefix := data[:cdOffset]
	centralDir := data[cdOffset:eocdOffset]
	eocd := append([]byte(nil), data[eocdOffset:]...)

	blockOffset := len(prefix)
	digest := testContentDigest(prefix, centralDir, eocd, blockOffset)
	value := buildV2Value(certDER, publicKeyDER, digest, make([]byte, 256))
	block := buildSigningBlock(value)

	// Sign the actual signed data (the digest/signature lengths are now fixed).
	_ = block
	signedData := signedDataFromValue(t, value)
	hash := sha256.Sum256(signedData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	require.NoError(t, err)
	value = buildV2Value(certDER, publicKeyDER, digest, signature)
	block = buildSigningBlock(value)
	require.Equal(t, len(value), len(buildV2Value(certDER, publicKeyDER, digest, make([]byte, 256))))
	_ = block

	finalEOCD := append([]byte(nil), eocd...)
	binary.LittleEndian.PutUint32(finalEOCD[16:], uint32(cdOffset+len(block)))
	out := append([]byte(nil), prefix...)
	out = append(out, block...)
	out = append(out, centralDir...)
	out = append(out, finalEOCD...)

	path := filepath.Join(t.TempDir(), "valid.apk")
	require.NoError(t, os.WriteFile(path, out, 0o600))
	return path
}

// signedDataFromValue extracts the first signer's signed data.
func signedDataFromValue(t *testing.T, value []byte) []byte {
	t.Helper()
	signers, _, ok := readLengthPrefixed(value)
	require.True(t, ok)
	signedData, _, ok := readLengthPrefixed(signers)
	require.True(t, ok)
	return signedData
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

func TestInspectAPKSigningMaterial_VerifiedV2(t *testing.T) {
	path := writeValidSignedAPK(t)
	info, err := inspectAPKSigningMaterial(path)
	require.NoError(t, err)
	assert.Equal(t, "v2", info.Scheme)
	assert.True(t, info.Verified, "verification note: %s", info.Verification)
	assert.Equal(t, "verified", info.Verification)
	assert.Equal(t, 1, info.SignerCount)
	assert.NotEmpty(t, info.CertFP)
}

func TestInspectAPKSigningMaterial_TamperedV2(t *testing.T) {
	path := writeValidSignedAPK(t)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	// Flip a byte in the ZIP content, which is covered by the content digest
	// but not by the central directory.
	data[32] ^= 0xff
	tampered := filepath.Join(t.TempDir(), "tampered.apk")
	require.NoError(t, os.WriteFile(tampered, data, 0o600))

	info, err := inspectAPKSigningMaterial(tampered)
	require.NoError(t, err)
	assert.False(t, info.Verified)
	assert.Equal(t, "digest-mismatch", info.Verification)
}
