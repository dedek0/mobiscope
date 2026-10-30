package analyzers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA-512 for the newer signature algorithms
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"os"
	"strings"
	"time"
)

const (
	// Verification notes stored in the signing output and used by findings.
	verificationVerified       = "verified"
	verificationNoSigners      = "no-signers"
	verificationUnsupported    = "unsupported-signature-algorithm"
	verificationMissingDigest  = "missing-digest"
	verificationInvalidKey     = "invalid-public-key"
	verificationInvalidSig     = "invalid-signature"
	verificationDigestError    = "digest-error"
	verificationDigestMismatch = "digest-mismatch"

	algRSAPSS   = "rsa-pss"
	algRSAPKCS1 = "rsa-pkcs1"
	algECDSA    = "ecdsa"
)

// APK Signature Scheme block ids.
const (
	sigBlockV2          = 0x7109871a
	sigBlockV3          = 0xf05368c0
	sigBlockV31         = 0x1b93ad61
	sigBlockSourceStamp = 0x6dff800d
	proofOfRotationAttr = 0x3ba06f8c
	sigBlockMax         = 64 << 20
	// apkContentChunkSize is the 1 MiB chunk used by the APK content digest.
	apkContentChunkSize = 1 << 20
)

// apkSigningMaterial is what mobiscope can learn from the APK signing
// material without apksigner.
type apkSigningMaterial struct {
	Scheme      string
	CertFP      string
	SignerCount int
	Debug       bool

	CertSubject string
	CertNotFrom time.Time
	CertNotTo   time.Time
	KeyAlg      string
	KeyBits     int

	// Verified is true when the v2/v3 signature and content digest check out.
	// Verification is the reason string (verificationVerified, verificationDigestMismatch,
	// verificationInvalidSig, verificationUnsupported, …).
	Verified     bool
	Verification string
	// Rotation and SourceStamp record the presence of the v3 rotation lineage
	// and the source-stamp block; their cryptographic chains are not checked.
	Rotation    bool
	SourceStamp bool
}

// apkSigningBlock is the parsed APK Signing Block plus the offsets needed to
// recompute the APK content digest.
type apkSigningBlock struct {
	pairs      map[uint32][]byte
	offset     int64 // start of the signing block (end of the content section)
	cdOffset   int64
	eocdOffset int64
	fileSize   int64
	eocd       []byte
}

// inspectAPKSigningMaterial parses the APK Signing Block (v2/v3/v3.1), the
// v1 META-INF block and verifies the v2/v3 signature and content digest. It
// returns an error only when the file is not a readable ZIP; a missing
// signature is reported as Scheme "none".
func inspectAPKSigningMaterial(path string) (apkSigningMaterial, error) {
	zr, err := openZip(path)
	if err != nil {
		return apkSigningMaterial{}, err
	}
	v1Certs := 0
	for _, f := range zr.File {
		name := strings.ToUpper(f.Name)
		if strings.HasPrefix(name, "META-INF/") &&
			(strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC")) {
			v1Certs++
		}
	}
	zr.Close()

	block, err := readAPKSigningBlockInfo(path)
	if err != nil {
		return apkSigningMaterial{}, err
	}

	info := apkSigningMaterial{Scheme: valueNone, SignerCount: v1Certs}
	if v1Certs == 0 {
		info.SignerCount = 0
	}

	for _, candidate := range []struct {
		id     uint32
		scheme string
		v3     bool
	}{
		{sigBlockV31, "v3.1", true},
		{sigBlockV3, "v3", true},
		{sigBlockV2, "v2", false},
	} {
		value, ok := block.pairs[candidate.id]
		if !ok {
			continue
		}
		signers := parseSchemeSignerList(value, candidate.v3)
		if len(signers) == 0 {
			continue
		}
		info.Scheme = candidate.scheme
		info.SignerCount = len(signers)
		if cert := firstParsedCertificate(certificatesFromSigners(signers)); cert != nil {
			applyCertificate(&info, cert)
		}
		info.Rotation = hasRotationProof(signers)
		info.Verified, info.Verification = verifySchemeSigners(path, block, signers)
		if _, ok := block.pairs[sigBlockSourceStamp]; ok {
			info.SourceStamp = true
		}
		break
	}

	if info.Scheme == valueNone && v1Certs > 0 {
		info.Scheme = "v1"
		info.SignerCount = v1Certs
	} else if info.Scheme != valueNone && v1Certs > 0 {
		info.Scheme = "v1+" + info.Scheme
	}
	return info, nil
}

// schemeSigner is one signer of a v2/v3 block.
type schemeSigner struct {
	signedData []byte
	signatures []byte
	publicKey  []byte
	certs      [][]byte
	minSDK     uint32
	maxSDK     uint32
}

// applyCertificate fills the certificate facts used by the findings.
func applyCertificate(info *apkSigningMaterial, cert *x509.Certificate) {
	sum := sha256.Sum256(cert.Raw)
	info.CertFP = hex.EncodeToString(sum[:])
	info.CertSubject = cert.Subject.String()
	info.CertNotFrom = cert.NotBefore
	info.CertNotTo = cert.NotAfter
	info.Debug = strings.Contains(strings.ToLower(cert.Subject.String()), "debug")

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyAlg = "RSA"
		info.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyAlg = "ECDSA"
		if pub.Curve != nil {
			info.KeyBits = pub.Curve.Params().BitSize
		}
	}
}

// firstParsedCertificate parses the first DER certificate in the list.
func firstParsedCertificate(derCerts [][]byte) *x509.Certificate {
	for _, der := range derCerts {
		if len(der) == 0 {
			continue
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			return cert
		}
	}
	return nil
}

// readAPKSigningBlockInfo returns the id→value pairs of the APK Signing Block
// and the offsets needed for digest verification. An absent block is not an
// error: it returns an info with an empty pair map.
func readAPKSigningBlockInfo(path string) (*apkSigningBlock, error) {
	f, err := os.Open(path) //nolint:gosec // path is the operator-supplied artifact
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	info := &apkSigningBlock{pairs: map[uint32][]byte{}, fileSize: size}

	tailLen := int64(64*1024 + 22)
	if tailLen > size {
		tailLen = size
	}
	if tailLen < 22 {
		return info, nil
	}
	tail := make([]byte, tailLen)
	if _, err := f.ReadAt(tail, size-tailLen); err != nil {
		return info, nil
	}
	idx := lastIndex(tail, []byte("PK\x05\x06"))
	if idx < 0 || idx+22 > len(tail) {
		return info, nil
	}
	info.cdOffset = int64(binary.LittleEndian.Uint32(tail[idx+16:]))
	if info.cdOffset < 32 || info.cdOffset > size {
		return info, nil
	}
	commentLen := int64(binary.LittleEndian.Uint16(tail[idx+20:]))
	eocdLen := 22 + commentLen
	info.eocdOffset = size - tailLen + int64(idx)
	if info.eocdOffset < 0 || info.eocdOffset+eocdLen > size {
		return info, nil
	}
	info.eocd = make([]byte, eocdLen)
	if _, err := f.ReadAt(info.eocd, info.eocdOffset); err != nil {
		return info, nil
	}

	footer := make([]byte, 24)
	if _, err := f.ReadAt(footer, info.cdOffset-24); err != nil {
		return info, nil
	}
	if string(footer[8:24]) != apkSigBlockMagic {
		return info, nil
	}
	blockSize := int64(binary.LittleEndian.Uint64(footer))
	total := blockSize + 8
	if blockSize < 24 || total > info.cdOffset || total > sigBlockMax {
		return info, nil
	}
	info.offset = info.cdOffset - total

	block := make([]byte, total)
	if _, err := f.ReadAt(block, info.offset); err != nil {
		return info, nil
	}

	// The block is: uint64 size, id-value pairs, uint64 size, magic.
	limit := len(block) - 24
	for pos := 8; pos+12 <= limit; {
		pairLen := int64(binary.LittleEndian.Uint64(block[pos:]))
		if pairLen < 4 || pos+8+int(pairLen) > limit {
			break
		}
		id := binary.LittleEndian.Uint32(block[pos+8:])
		value := block[pos+12 : pos+8+int(pairLen)]
		if _, exists := info.pairs[id]; !exists {
			info.pairs[id] = value
		}
		pos += 8 + int(pairLen)
	}
	return info, nil
}

// readAPKSigningBlock is the pairs-only view used by the legacy callers.
func readAPKSigningBlock(path string) (map[uint32][]byte, error) {
	info, err := readAPKSigningBlockInfo(path)
	if err != nil {
		return nil, err
	}
	return info.pairs, nil
}

// lastIndex is bytes.LastIndex without importing bytes just for this call.
func lastIndex(haystack, needle []byte) int {
	for i := len(haystack) - len(needle); i >= 0; i-- {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// parseSchemeSignerList walks the signers of a v2/v3 block.
func parseSchemeSignerList(value []byte, v3 bool) []schemeSigner {
	signers, _, ok := readLengthPrefixed(value)
	if !ok {
		return nil
	}

	out := []schemeSigner{}
	buf := signers
	for len(buf) > 0 {
		signedData, rest, ok := readLengthPrefixed(buf)
		if !ok {
			break
		}
		var minSDK, maxSDK uint32
		if v3 {
			// v3 puts the minSdkVersion/maxSdkVersion between the signed
			// data and the signatures.
			if len(rest) < 8 {
				break
			}
			minSDK = binary.LittleEndian.Uint32(rest)
			maxSDK = binary.LittleEndian.Uint32(rest[4:])
			rest = rest[8:]
		}
		signatures, rest, ok := readLengthPrefixed(rest)
		if !ok {
			break
		}
		publicKey, rest, ok := readLengthPrefixed(rest)
		if !ok {
			break
		}
		out = append(out, schemeSigner{
			signedData: signedData,
			signatures: signatures,
			publicKey:  publicKey,
			certs:      certificatesFromSignedData(signedData),
			minSDK:     minSDK,
			maxSDK:     maxSDK,
		})
		buf = rest
	}
	return out
}

// parseSchemeSigners is the legacy cert/count view.
func parseSchemeSigners(value []byte, v3 bool) ([][]byte, int) {
	signers := parseSchemeSignerList(value, v3)
	return certificatesFromSigners(signers), len(signers)
}

// certificatesFromSigners flattens the certificates of every signer.
func certificatesFromSigners(signers []schemeSigner) [][]byte {
	var out [][]byte
	for _, s := range signers {
		out = append(out, s.certs...)
	}
	return out
}

// certificatesFromSignedData extracts the certificate sequence, which follows
// the digests field.
func certificatesFromSignedData(signedData []byte) [][]byte {
	_, rest, ok := readLengthPrefixed(signedData) // digests
	if !ok {
		return nil
	}
	certsSeq, _, ok := readLengthPrefixed(rest)
	if !ok || len(certsSeq) == 0 {
		return nil
	}
	var out [][]byte
	buf := certsSeq
	for len(buf) > 0 {
		cert, rest, ok := readLengthPrefixed(buf)
		if !ok {
			break
		}
		if len(cert) > 0 {
			out = append(out, cert)
		}
		buf = rest
	}
	// Some producers omit the inner length prefix; accept a bare DER blob.
	if len(out) == 0 && certsSeq[0] == 0x30 {
		out = append(out, certsSeq)
	}
	return out
}

// readLengthPrefixed reads a uint32 length followed by that many bytes.
func readLengthPrefixed(buf []byte) ([]byte, []byte, bool) {
	if len(buf) < 4 {
		return nil, nil, false
	}
	n := int(binary.LittleEndian.Uint32(buf))
	if n < 0 || 4+n > len(buf) {
		return nil, nil, false
	}
	return buf[4 : 4+n], buf[4+n:], true
}

// signatureAlgorithm describes one APK Signature Scheme signature algorithm.
type signatureAlgorithm struct {
	id   uint32
	hash crypto.Hash
	kind string
}

// supportedSignatureAlgorithms lists the algorithms this verifier can check.
var supportedSignatureAlgorithms = []signatureAlgorithm{
	{0x0101, crypto.SHA256, algRSAPSS},
	{0x0102, crypto.SHA256, algRSAPKCS1},
	{0x0103, crypto.SHA256, algECDSA},
	{0x0201, crypto.SHA512, algRSAPSS},
	{0x0202, crypto.SHA512, algRSAPKCS1},
	{0x0301, crypto.SHA512, algECDSA},
}

// verifySchemeSigners verifies every signer and returns the verification
// result.
func verifySchemeSigners(path string, block *apkSigningBlock, signers []schemeSigner) (bool, string) {
	if len(signers) == 0 {
		return false, verificationNoSigners
	}
	for _, signer := range signers {
		ok, note := verifySchemeSigner(path, block, signer)
		if !ok {
			return false, note
		}
	}
	return true, verificationVerified
}

// verifySchemeSigner verifies the signature over signedData and the APK
// content digest.
func verifySchemeSigner(path string, block *apkSigningBlock, signer schemeSigner) (bool, string) {
	alg, signature, ok := findSignature(signer.signatures)
	if !ok {
		return false, verificationUnsupported
	}
	expectedDigest, ok := findDigest(signer.signedData, alg.id)
	if !ok {
		return false, verificationMissingDigest
	}

	publicKey, err := x509.ParsePKIXPublicKey(signer.publicKey)
	if err != nil {
		return false, verificationInvalidKey
	}
	hashed := alg.hash.New()
	hashed.Write(signer.signedData)
	digest := hashed.Sum(nil)

	switch alg.kind {
	case algRSAPSS:
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, verificationInvalidKey
		}
		if err := rsa.VerifyPSS(pub, alg.hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return false, verificationInvalidSig
		}
	case algRSAPKCS1:
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, verificationInvalidKey
		}
		if err := rsa.VerifyPKCS1v15(pub, alg.hash, digest, signature); err != nil {
			return false, verificationInvalidSig
		}
	case algECDSA:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, verificationInvalidKey
		}
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return false, verificationInvalidSig
		}
	default:
		return false, verificationUnsupported
	}

	computed, err := apkContentDigest(path, block, alg.hash)
	if err != nil {
		return false, verificationDigestError
	}
	if subtle.ConstantTimeCompare(computed, expectedDigest) != 1 {
		return false, verificationDigestMismatch
	}
	return true, verificationVerified
}

// findSignature returns the first supported signature in a signatures
// sequence.
func findSignature(sequence []byte) (signatureAlgorithm, []byte, bool) {
	buf := sequence
	for len(buf) > 0 {
		if len(buf) < 4 {
			break
		}
		id := binary.LittleEndian.Uint32(buf)
		buf = buf[4:]
		sig, rest, ok := readLengthPrefixed(buf)
		if !ok {
			break
		}
		for _, alg := range supportedSignatureAlgorithms {
			if alg.id == id {
				return alg, sig, true
			}
		}
		buf = rest
	}
	return signatureAlgorithm{}, nil, false
}

// findDigest returns the digest with the requested signature algorithm id.
func findDigest(signedData []byte, id uint32) ([]byte, bool) {
	digests, _, ok := readLengthPrefixed(signedData)
	if !ok {
		return nil, false
	}
	buf := digests
	for len(buf) > 0 {
		if len(buf) < 4 {
			break
		}
		algID := binary.LittleEndian.Uint32(buf)
		buf = buf[4:]
		digest, rest, ok := readLengthPrefixed(buf)
		if !ok {
			break
		}
		if algID == id {
			return digest, true
		}
		buf = rest
	}
	return nil, false
}

// apkContentDigest recomputes the APK Signature Scheme content digest over the
// three sections: file contents before the signing block, the central
// directory, and the EOCD (with the central-directory offset replaced by the
// signing-block offset).
func apkContentDigest(path string, block *apkSigningBlock, h crypto.Hash) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is the operator-supplied artifact
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hasher := h.New()
	var chunkDigests []byte
	var chunks uint32

	addChunk := func(chunk []byte) {
		ch := h.New()
		ch.Write([]byte{0x5a})
		writeUint32(ch, uint32(len(chunk)))
		ch.Write(chunk)
		chunkDigests = append(chunkDigests, ch.Sum(nil)...)
		chunks++
	}
	addSection := func(offset, length int64) error {
		buf := make([]byte, apkContentChunkSize)
		for length > 0 {
			n := int64(len(buf))
			if n > length {
				n = length
			}
			if _, err := f.ReadAt(buf[:n], offset); err != nil {
				return err
			}
			addChunk(buf[:n])
			offset += n
			length -= n
		}
		return nil
	}

	if err := addSection(0, block.offset); err != nil {
		return nil, err
	}
	if err := addSection(block.cdOffset, block.eocdOffset-block.cdOffset); err != nil {
		return nil, err
	}

	eocd := make([]byte, len(block.eocd))
	copy(eocd, block.eocd)
	if len(eocd) >= 20 {
		binary.LittleEndian.PutUint32(eocd[16:], uint32(block.offset))
	}
	for len(eocd) > 0 {
		n := len(eocd)
		if n > apkContentChunkSize {
			n = apkContentChunkSize
		}
		addChunk(eocd[:n])
		eocd = eocd[n:]
	}

	hasher.Write([]byte{0x5a})
	writeUint32(hasher, chunks)
	hasher.Write(chunkDigests)
	return hasher.Sum(nil), nil
}

// writeUint32 writes a little-endian uint32 to a hash.
func writeUint32(h hash.Hash, v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	h.Write(buf[:])
}

// hasRotationProof reports whether a v3 signer carries the proof-of-rotation
// additional attribute. The lineage itself is not validated.
func hasRotationProof(signers []schemeSigner) bool {
	for _, signer := range signers {
		attrs, ok := signedDataAttributes(signer.signedData)
		if !ok {
			continue
		}
		buf := attrs
		for len(buf) > 0 {
			if len(buf) < 4 {
				break
			}
			id := binary.LittleEndian.Uint32(buf)
			buf = buf[4:]
			_, rest, ok := readLengthPrefixed(buf)
			if !ok {
				break
			}
			if id == proofOfRotationAttr {
				return true
			}
			buf = rest
		}
	}
	return false
}

// signedDataAttributes returns the additional-attributes sequence of a v3
// signed-data blob.
func signedDataAttributes(signedData []byte) ([]byte, bool) {
	_, rest, ok := readLengthPrefixed(signedData) // digests
	if !ok {
		return nil, false
	}
	_, rest, ok = readLengthPrefixed(rest) // certificates
	if !ok {
		return nil, false
	}
	// v3 signed data carries minSdkVersion/maxSdkVersion before attributes.
	if len(rest) < 8 {
		return nil, false
	}
	attrs, _, ok := readLengthPrefixed(rest[8:])
	if !ok {
		return nil, false
	}
	return attrs, true
}
