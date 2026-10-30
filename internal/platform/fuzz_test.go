package platform

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
)

// mustZip builds a ZIP archive in memory from the given entry names. Panics
// only for deterministic seed construction errors (a seed that cannot be
// built is a bug in the seed itself).
func mustZip(entries ...string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// hugeDeclaredZip hand-crafts a structurally valid ZIP whose central
// directory declares a 4 GiB-1 uncompressed size while carrying no payload.
// Detect only reads the central directory, so it must handle this without
// trying to inflate anything.
func hugeDeclaredZip(name string) []byte {
	var lh []byte
	lh = append(lh, 'P', 'K', 3, 4)
	lh = binary.LittleEndian.AppendUint16(lh, 20)      // version needed
	lh = binary.LittleEndian.AppendUint16(lh, 0)       // flags
	lh = binary.LittleEndian.AppendUint16(lh, 0)       // method: stored
	lh = binary.LittleEndian.AppendUint16(lh, 0)       // mod time
	lh = binary.LittleEndian.AppendUint16(lh, 0)       // mod date
	lh = binary.LittleEndian.AppendUint32(lh, 0)       // crc32
	lh = binary.LittleEndian.AppendUint32(lh, 0)       // compressed size
	lh = binary.LittleEndian.AppendUint32(lh, 1<<32-1) // declared uncompressed size
	lh = binary.LittleEndian.AppendUint16(lh, uint16(len(name)))
	lh = binary.LittleEndian.AppendUint16(lh, 0) // extra len
	lh = append(lh, name...)

	var cd []byte
	cd = append(cd, 'P', 'K', 1, 2)
	cd = binary.LittleEndian.AppendUint16(cd, 20)      // version made by
	cd = binary.LittleEndian.AppendUint16(cd, 20)      // version needed
	cd = binary.LittleEndian.AppendUint16(cd, 0)       // flags
	cd = binary.LittleEndian.AppendUint16(cd, 0)       // method
	cd = binary.LittleEndian.AppendUint16(cd, 0)       // mod time
	cd = binary.LittleEndian.AppendUint16(cd, 0)       // mod date
	cd = binary.LittleEndian.AppendUint32(cd, 0)       // crc32
	cd = binary.LittleEndian.AppendUint32(cd, 0)       // compressed size
	cd = binary.LittleEndian.AppendUint32(cd, 1<<32-1) // uncompressed size
	cd = binary.LittleEndian.AppendUint16(cd, uint16(len(name)))
	cd = binary.LittleEndian.AppendUint16(cd, 0) // extra len
	cd = binary.LittleEndian.AppendUint16(cd, 0) // comment len
	cd = binary.LittleEndian.AppendUint16(cd, 0) // disk start
	cd = binary.LittleEndian.AppendUint16(cd, 0) // internal attrs
	cd = binary.LittleEndian.AppendUint32(cd, 0) // external attrs
	cd = binary.LittleEndian.AppendUint32(cd, 0) // local header offset
	cd = append(cd, name...)

	var eocd []byte
	eocd = append(eocd, 'P', 'K', 5, 6)
	eocd = binary.LittleEndian.AppendUint16(eocd, 0) // disk number
	eocd = binary.LittleEndian.AppendUint16(eocd, 0) // cd disk
	eocd = binary.LittleEndian.AppendUint16(eocd, 1) // entries on disk
	eocd = binary.LittleEndian.AppendUint16(eocd, 1) // total entries
	eocd = binary.LittleEndian.AppendUint32(eocd, uint32(len(cd)))
	eocd = binary.LittleEndian.AppendUint32(eocd, uint32(len(lh)))
	eocd = binary.LittleEndian.AppendUint16(eocd, 0) // comment len

	return append(append(lh, cd...), eocd...)
}

// FuzzDetect hammers platform.Detect with arbitrary bytes. Seeds cover the
// fixture classes: non-ZIP data, truncated ZIPs, hostile
// entry names, deep nesting and huge declared sizes without payload. The
// seed corpus also runs as a plain unit test via `go test`.
func FuzzDetect(f *testing.F) {
	// Content-based seeds.
	f.Add(mustZip("AndroidManifest.xml", "classes.dex", "res/layout.xml"), byte(0))
	f.Add(mustZip("Payload/My App.app/Info.plist", "Payload/My App.app/MyApp"), byte(0))
	f.Add(mustZip("Payload/Main.app/Info.plist", "Payload/Main.app/PlugIns/Ext.appex/Info.plist"), byte(0))
	// Non-ZIP garbage and empty input.
	f.Add([]byte("this is not a zip"), byte(0))
	f.Add([]byte{}, byte(0))
	// Truncated valid ZIP (cut before/after the local header).
	full := mustZip("AndroidManifest.xml")
	f.Add(full[:4], byte(0))
	f.Add(full[:len(full)/2], byte(0))
	f.Add(full[:len(full)-1], byte(0))
	// Hostile entry names: traversal, absolute paths, backslashes.
	f.Add(mustZip("../../../etc/evil", "/abs/evil", `Payload\..\..\evil.app\Info.plist`), byte(0))
	f.Add(mustZip("a/b/c/d/e/../../../../../../../../etc/passwd"), byte(0))
	// Deep nesting.
	f.Add(mustZip(strings.Repeat("d/", 300)+"AndroidManifest.xml"), byte(0))
	// Huge declared size without payload.
	f.Add(hugeDeclaredZip("AndroidManifest.xml"), byte(0))
	// Content marker plus explicit extension (tiebreaker paths).
	f.Add(mustZip("META-INF/MANIFEST.MF"), byte(1)) // -> .apk
	f.Add(mustZip("readme.txt"), byte(2))           // -> .ipa via extension

	f.Fuzz(func(t *testing.T, data []byte, extSel byte) {
		// Keep iterations cheap so -fuzz stays fast; the standard fuzz
		// engine rarely needs inputs beyond this size for zip parsing.
		if len(data) > 1<<18 {
			t.Skip()
		}

		ext := [...]string{"", ".apk", ".ipa", ".bin"}[int(extSel)%4]
		path := filepath.Join(t.TempDir(), "target"+ext)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("writing seed: %v", err)
		}

		target, err := Detect(path)
		if err != nil {
			// Errors are fine (unrecognized/garbage input); panics are not.
			return
		}

		switch target.Platform {
		case models.PlatformAndroid:
			if target.Format != FormatAPK {
				t.Fatalf("android target must have apk format, got %q", target.Format)
			}
		case models.PlatformIOS:
			if target.Format != FormatIPA {
				t.Fatalf("ios target must have ipa format, got %q", target.Format)
			}
		case models.PlatformUnknown:
			// Detect() rejects unknown platforms with an error, so reaching
			// here with success would be a contract violation.
			t.Fatalf("detect returned platform unknown without error")
		default:
			t.Fatalf("unexpected platform %q", target.Platform)
		}
		if target.Path != path {
			t.Fatalf("target path not propagated: %q", target.Path)
		}
	})
}
