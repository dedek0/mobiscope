package analyzers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"time"
)

// APK Signature Scheme block ids.
const (
	sigBlockV2  = 0x7109871a
	sigBlockV3  = 0xf05368c0
	sigBlockV31 = 0x1b93ad61
	sigBlockMax = 64 << 20
)

// apkSigningMaterial is what mobiscope can learn from the APK signing
// material without apksigner. It is a parse, not a cryptographic
// verification: the v2/v3 digests are not checked here.
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
}

// inspectAPKSigningMaterial parses the APK Signing Block (v2/v3/v3.1) and the
// v1 META-INF block. It returns an error only when the file is not a readable
// ZIP; a missing signature is reported as Scheme "none".
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

	pairs, err := readAPKSigningBlock(path)
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
		value, ok := pairs[candidate.id]
		if !ok {
			continue
		}
		certs, signers := parseSchemeSigners(value, candidate.v3)
		if signers == 0 {
			continue
		}
		info.Scheme = candidate.scheme
		info.SignerCount = signers
		if cert := firstParsedCertificate(certs); cert != nil {
			applyCertificate(&info, cert)
		}
		break
	}

	if info.Scheme == "none" && v1Certs > 0 {
		info.Scheme = "v1"
		info.SignerCount = v1Certs
	} else if info.Scheme != "none" && v1Certs > 0 {
		info.Scheme = "v1+" + info.Scheme
	}
	return info, nil
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

// readAPKSigningBlock returns the id→value pairs of the APK Signing Block. An
// absent block is not an error: it returns an empty map.
func readAPKSigningBlock(path string) (map[uint32][]byte, error) {
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
	tailLen := int64(64*1024 + 22)
	if tailLen > size {
		tailLen = size
	}
	if tailLen < 22 {
		return map[uint32][]byte{}, nil
	}
	tail := make([]byte, tailLen)
	if _, err := f.ReadAt(tail, size-tailLen); err != nil {
		return nil, err
	}
	idx := lastIndex(tail, []byte("PK\x05\x06"))
	if idx < 0 || idx+22 > len(tail) {
		return map[uint32][]byte{}, nil
	}
	cdOffset := int64(binary.LittleEndian.Uint32(tail[idx+16:]))
	if cdOffset < 32 || cdOffset > size {
		return map[uint32][]byte{}, nil
	}

	footer := make([]byte, 24)
	if _, err := f.ReadAt(footer, cdOffset-24); err != nil {
		return map[uint32][]byte{}, nil
	}
	if string(footer[8:24]) != apkSigBlockMagic {
		return map[uint32][]byte{}, nil
	}
	blockSize := int64(binary.LittleEndian.Uint64(footer))
	total := blockSize + 8
	if blockSize < 24 || total > cdOffset || total > sigBlockMax {
		return map[uint32][]byte{}, nil
	}

	block := make([]byte, total)
	if _, err := f.ReadAt(block, cdOffset-total); err != nil {
		return map[uint32][]byte{}, nil
	}

	// The block is: uint64 size, id-value pairs, uint64 size, magic.
	pairs := map[uint32][]byte{}
	limit := len(block) - 24
	for pos := 8; pos+12 <= limit; {
		pairLen := int64(binary.LittleEndian.Uint64(block[pos:]))
		if pairLen < 4 || pos+8+int(pairLen) > limit {
			break
		}
		id := binary.LittleEndian.Uint32(block[pos+8:])
		value := block[pos+12 : pos+8+int(pairLen)]
		if _, exists := pairs[id]; !exists {
			pairs[id] = value
		}
		pos += 8 + int(pairLen)
	}
	return pairs, nil
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

// parseSchemeSigners walks the signers of a v2/v3 block and returns the
// certificate DERs and the signer count.
func parseSchemeSigners(value []byte, v3 bool) ([][]byte, int) {
	signers, _, ok := readLengthPrefixed(value)
	if !ok {
		return nil, 0
	}

	var certs [][]byte
	count := 0
	buf := signers
	for len(buf) > 0 {
		signedData, rest, ok := readLengthPrefixed(buf)
		if !ok {
			break
		}
		if v3 {
			// v3 puts the minSdkVersion/maxSdkVersion between the signed
			// data and the signatures.
			if len(rest) < 8 {
				break
			}
			rest = rest[8:]
		}
		_, rest, ok = readLengthPrefixed(rest) // signatures
		if !ok {
			break
		}
		_, rest, ok = readLengthPrefixed(rest) // public key
		if !ok {
			break
		}
		count++
		if cert := certificateFromSignedData(signedData); len(cert) > 0 {
			certs = append(certs, cert)
		}
		buf = rest
	}
	return certs, count
}

// certificateFromSignedData extracts the first certificate of the
// certificates field, which follows the digests field.
func certificateFromSignedData(signedData []byte) []byte {
	_, rest, ok := readLengthPrefixed(signedData) // digests
	if !ok {
		return nil
	}
	certsSeq, _, ok := readLengthPrefixed(rest)
	if !ok || len(certsSeq) == 0 {
		return nil
	}
	if cert, _, ok := readLengthPrefixed(certsSeq); ok && len(cert) > 0 {
		return cert
	}
	// Some producers omit the inner length prefix; accept a bare DER blob.
	if certsSeq[0] == 0x30 {
		return certsSeq
	}
	return nil
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
