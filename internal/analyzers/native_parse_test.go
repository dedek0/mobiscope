//nolint:errcheck // fixtures write to bytes.Buffer, which cannot fail
package analyzers

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// axmlBuilder assembles the tiny subset of binary XML the parser needs.
type axmlBuilder struct {
	strings []string
	index   map[string]uint32
	nodes   []byte
}

func newAXMLBuilder() *axmlBuilder {
	return &axmlBuilder{index: map[string]uint32{}}
}

func (b *axmlBuilder) str(s string) uint32 {
	if i, ok := b.index[s]; ok {
		return i
	}
	i := uint32(len(b.strings))
	b.strings = append(b.strings, s)
	b.index[s] = i
	return i
}

func (b *axmlBuilder) start(name string, attrs ...axmlTestAttr) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint32(1))          // line
	binary.Write(body, binary.LittleEndian, uint32(0xffffffff)) // comment
	binary.Write(body, binary.LittleEndian, uint32(0xffffffff)) // namespace
	binary.Write(body, binary.LittleEndian, b.str(name))
	binary.Write(body, binary.LittleEndian, uint16(20)) // attributeStart
	binary.Write(body, binary.LittleEndian, uint16(20)) // attributeSize
	binary.Write(body, binary.LittleEndian, uint16(len(attrs)))
	binary.Write(body, binary.LittleEndian, uint16(0)) // idIndex
	binary.Write(body, binary.LittleEndian, uint16(0)) // classIndex
	binary.Write(body, binary.LittleEndian, uint16(0)) // styleIndex
	for _, a := range attrs {
		binary.Write(body, binary.LittleEndian, uint32(0xffffffff)) // namespace
		binary.Write(body, binary.LittleEndian, b.str(a.name))
		raw := uint32(0xffffffff)
		if a.strValue != "" {
			raw = b.str(a.strValue)
		}
		binary.Write(body, binary.LittleEndian, raw)
		binary.Write(body, binary.LittleEndian, uint16(8)) // value size
		binary.Write(body, binary.LittleEndian, uint8(0))  // res0
		binary.Write(body, binary.LittleEndian, a.dataType)
		binary.Write(body, binary.LittleEndian, a.data)
	}
	b.nodes = append(b.nodes, makeChunk(axmlChunkStartElement, body.Bytes())...)
}

func (b *axmlBuilder) end(name string) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint32(1))
	binary.Write(body, binary.LittleEndian, uint32(0xffffffff))
	binary.Write(body, binary.LittleEndian, uint32(0xffffffff))
	binary.Write(body, binary.LittleEndian, b.str(name))
	b.nodes = append(b.nodes, makeChunk(axmlChunkEndElement, body.Bytes())...)
}

func (b *axmlBuilder) build() []byte {
	// Encode the string pool (UTF-8 flag).
	var data bytes.Buffer
	offsets := make([]uint32, len(b.strings))
	for i, s := range b.strings {
		offsets[i] = uint32(data.Len())
		data.WriteByte(byte(len(s)))
		data.WriteString(s)
		data.WriteByte(0)
	}
	pool := new(bytes.Buffer)
	binary.Write(pool, binary.LittleEndian, uint32(len(b.strings)))
	binary.Write(pool, binary.LittleEndian, uint32(0)) // styleCount
	binary.Write(pool, binary.LittleEndian, uint32(0x100))
	binary.Write(pool, binary.LittleEndian, uint32(28+4*len(b.strings)))
	binary.Write(pool, binary.LittleEndian, uint32(0)) // stylesStart
	for _, off := range offsets {
		binary.Write(pool, binary.LittleEndian, off)
	}
	pool.Write(data.Bytes())

	// A string pool carries a 28-byte chunk header (not the generic 8).
	poolChunk := new(bytes.Buffer)
	binary.Write(poolChunk, binary.LittleEndian, uint16(axmlChunkStringPool))
	binary.Write(poolChunk, binary.LittleEndian, uint16(28))
	binary.Write(poolChunk, binary.LittleEndian, uint32(8+pool.Len()))
	poolChunk.Write(pool.Bytes())

	out := poolChunk.Bytes()
	out = append(out, b.nodes...)

	header := new(bytes.Buffer)
	binary.Write(header, binary.LittleEndian, uint16(axmlChunkXML))
	binary.Write(header, binary.LittleEndian, uint16(8))
	binary.Write(header, binary.LittleEndian, uint32(8+len(out)))
	return append(header.Bytes(), out...)
}

type axmlTestAttr struct {
	name     string
	strValue string
	dataType uint8
	data     uint32
}

func makeChunk(typ uint16, body []byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, typ)
	binary.Write(buf, binary.LittleEndian, uint16(8))
	binary.Write(buf, binary.LittleEndian, uint32(8+len(body)))
	buf.Write(body)
	return buf.Bytes()
}

func TestParseAXML_Manifest(t *testing.T) {
	b := newAXMLBuilder()
	b.start("manifest",
		axmlTestAttr{name: "package", strValue: "com.example.binary"},
	)
	b.start("uses-sdk", axmlTestAttr{name: "targetSdkVersion", dataType: axmlTypeIntDec, data: 30})
	b.end("uses-sdk")
	b.start("application", axmlTestAttr{name: "debuggable", dataType: axmlTypeIntBool, data: 1})
	b.start("activity", axmlTestAttr{name: "name", strValue: ".Main"})
	b.end("activity")
	b.end("application")
	b.end("manifest")

	root, err := parseAXML(b.build(), nil)
	require.NoError(t, err)
	m := manifestFromAXML(root)

	assert.Equal(t, "com.example.binary", m.Package)
	assert.Equal(t, "30", m.UsesSDK.TargetSDKVersion)
	assert.True(t, m.Application.Debuggable == "true")
	require.Len(t, m.Application.Activities, 1)
	assert.Equal(t, ".Main", m.Application.Activities[0].Name)

	findings := NewInventory().manifestFindings(m, "s")
	titles := ""
	for _, f := range findings {
		titles += f.Title + "|"
	}
	assert.Contains(t, titles, "debuggable")
}

func TestParseAXML_TargetSDK31SkipsImplicitExport(t *testing.T) {
	b := newAXMLBuilder()
	b.start("manifest",
		axmlTestAttr{name: "package", strValue: "com.example.app"},
	)
	b.start("uses-sdk", axmlTestAttr{name: "targetSdkVersion", dataType: axmlTypeIntDec, data: 32})
	b.end("uses-sdk")
	b.start("application")
	// No android:exported on targetSdk 32: the manifest would not install,
	// so it must not be reported as an implicitly exported surface.
	b.start("activity", axmlTestAttr{name: "name", strValue: ".Missing"})
	b.start("intent-filter")
	b.start("action", axmlTestAttr{name: "name", strValue: "android.intent.action.MAIN"})
	b.end("action")
	b.end("intent-filter")
	b.end("activity")

	b.start("activity", axmlTestAttr{name: "name", strValue: ".Deep"},
		axmlTestAttr{name: "exported", dataType: axmlTypeIntBool, data: 1})
	b.start("intent-filter")
	b.start("action", axmlTestAttr{name: "name", strValue: "android.intent.action.VIEW"})
	b.end("action")
	b.start("category", axmlTestAttr{name: "name", strValue: "android.intent.category.BROWSABLE"})
	b.end("category")
	b.start("data", axmlTestAttr{name: "scheme", strValue: "https"}, axmlTestAttr{name: "host", strValue: "example.com"})
	b.end("data")
	b.end("intent-filter")
	b.end("activity")
	b.end("application")
	b.end("manifest")

	root, err := parseAXML(b.build(), nil)
	require.NoError(t, err)
	m := manifestFromAXML(root)
	findings := NewInventory().manifestFindings(m, "s")
	titles := ""
	for _, f := range findings {
		titles += f.Title + "|"
	}
	assert.NotContains(t, titles, "Implicitly exported")
	assert.Contains(t, titles, "App Link without autoVerify")
}

func TestParseNSCPolicy_BinaryXML(t *testing.T) {
	b := newAXMLBuilder()
	b.start("network-security-config")
	b.start("base-config", axmlTestAttr{name: "cleartextTrafficPermitted", dataType: axmlTypeIntBool, data: 1})
	b.start("trust-anchors")
	b.start("certificates", axmlTestAttr{name: "src", strValue: "user"})
	b.end("certificates")
	b.end("trust-anchors")
	b.end("base-config")
	b.end("network-security-config")

	policy, err := parseNSCPolicy(b.build(), nil)
	require.NoError(t, err)
	assert.True(t, policy.BaseCleartext)
	assert.True(t, policy.CustomAnchors)

	findings := nscFindings(policy, "s", "res/xml/nsc.xml")
	titles := ""
	for _, f := range findings {
		titles += f.Title + "|"
	}
	assert.Contains(t, titles, "Cleartext traffic permitted")
	assert.Contains(t, titles, "Custom trust anchors")
}

func TestInventory_AnalyzeTarget_BinaryManifest(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.apk")

	b := newAXMLBuilder()
	b.start("manifest", axmlTestAttr{name: "package", strValue: "com.example.native"})
	b.start("uses-permission", axmlTestAttr{name: "name", strValue: "android.permission.CAMERA"})
	b.end("uses-permission")
	b.start("application", axmlTestAttr{name: "allowBackup", dataType: axmlTypeIntBool, data: 1})
	b.end("application")
	b.end("manifest")

	f, err := os.Create(target)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	require.NoError(t, err)
	_, err = w.Write(b.build())
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())

	workdir := filepath.Join(dir, "session")
	require.NoError(t, os.MkdirAll(workdir, 0o755))

	inv := NewInventory()
	findings := inv.AnalyzeTarget(target, workdir, "s")
	titles := ""
	for _, f := range findings {
		titles += f.Title + "|"
	}
	assert.Contains(t, titles, "ADB backup allowed")
	assert.Contains(t, titles, "Dangerous permission: android.permission.CAMERA")
}

// makeTestStringPool builds a UTF-8 string-pool chunk.
func makeTestStringPool(values []string) []byte {
	var data bytes.Buffer
	offsets := make([]uint32, len(values))
	for i, s := range values {
		offsets[i] = uint32(data.Len())
		data.WriteByte(byte(len(s)))
		data.WriteString(s)
		data.WriteByte(0)
	}
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint32(len(values)))
	binary.Write(body, binary.LittleEndian, uint32(0))
	binary.Write(body, binary.LittleEndian, uint32(0x100))
	binary.Write(body, binary.LittleEndian, uint32(28+4*len(values)))
	binary.Write(body, binary.LittleEndian, uint32(0))
	for _, off := range offsets {
		binary.Write(body, binary.LittleEndian, off)
	}
	body.Write(data.Bytes())

	chunk := new(bytes.Buffer)
	binary.Write(chunk, binary.LittleEndian, uint16(arscChunkStringPool))
	binary.Write(chunk, binary.LittleEndian, uint16(28))
	binary.Write(chunk, binary.LittleEndian, uint32(8+body.Len()))
	chunk.Write(body.Bytes())
	return chunk.Bytes()
}

// makeTestResourceTable builds a one-entry resources.arsc that maps
// 0x7f010000 to value.
func makeTestResourceTable(value string) []byte {
	pool := makeTestStringPool([]string{value})

	// ResTable_type: header 20, one entry at offset 24.
	typeChunk := new(bytes.Buffer)
	binary.Write(typeChunk, binary.LittleEndian, uint16(arscChunkType))
	binary.Write(typeChunk, binary.LittleEndian, uint16(20))
	binary.Write(typeChunk, binary.LittleEndian, uint32(40))
	typeChunk.WriteByte(1) // type id
	typeChunk.WriteByte(0) // flags
	typeChunk.Write([]byte{0, 0})
	binary.Write(typeChunk, binary.LittleEndian, uint32(1))  // entryCount
	binary.Write(typeChunk, binary.LittleEndian, uint32(24)) // entriesStart
	binary.Write(typeChunk, binary.LittleEndian, uint32(0))  // entry offset
	// ResTable_entry (8) + Res_value (8).
	binary.Write(typeChunk, binary.LittleEndian, uint16(8)) // entry size
	binary.Write(typeChunk, binary.LittleEndian, uint16(0)) // flags
	binary.Write(typeChunk, binary.LittleEndian, uint32(0)) // key
	binary.Write(typeChunk, binary.LittleEndian, uint16(8)) // value size
	typeChunk.WriteByte(0)
	typeChunk.WriteByte(axmlTypeString)
	binary.Write(typeChunk, binary.LittleEndian, uint32(0)) // global string index

	// ResTable_package: header 12, package id 0x7f.
	pkg := new(bytes.Buffer)
	binary.Write(pkg, binary.LittleEndian, uint16(arscChunkPackage))
	binary.Write(pkg, binary.LittleEndian, uint16(12))
	binary.Write(pkg, binary.LittleEndian, uint32(12+typeChunk.Len()))
	binary.Write(pkg, binary.LittleEndian, uint32(0x7f))
	pkg.Write(typeChunk.Bytes())

	table := new(bytes.Buffer)
	n := 12 + len(pool) + pkg.Len()
	binary.Write(table, binary.LittleEndian, uint16(arscChunkTable))
	binary.Write(table, binary.LittleEndian, uint16(12))
	binary.Write(table, binary.LittleEndian, uint32(n))
	binary.Write(table, binary.LittleEndian, uint32(1)) // package count
	table.Write(pool)
	table.Write(pkg.Bytes())

	return table.Bytes()
}

func TestParseResourceTable_ResolvesString(t *testing.T) {
	parsed, err := parseResourceTable(makeTestResourceTable("res/xml/network_security_config.xml"))
	require.NoError(t, err)
	got, ok := parsed.resolve(0x7f010000)
	require.True(t, ok)
	assert.Equal(t, "res/xml/network_security_config.xml", got)
	assert.Equal(t, "@xml/network_security_config", normalizeResourceRef(got))
}

func TestInventory_AnalyzeTarget_ResolvesNSCReference(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.apk")

	b := newAXMLBuilder()
	b.start("manifest", axmlTestAttr{name: "package", strValue: "com.example.ref"})
	b.start("application",
		axmlTestAttr{name: "networkSecurityConfig", dataType: axmlTypeReference, data: 0x7f010000})
	b.end("application")
	b.end("manifest")

	f, err := os.Create(target)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	require.NoError(t, err)
	_, err = w.Write(b.build())
	require.NoError(t, err)
	w, err = zw.Create("resources.arsc")
	require.NoError(t, err)
	_, err = w.Write(makeTestResourceTable("res/xml/nsc.xml"))
	require.NoError(t, err)
	w, err = zw.Create("res/xml/nsc.xml")
	require.NoError(t, err)
	_, err = w.Write([]byte(`<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())

	workdir := filepath.Join(dir, "session")
	require.NoError(t, os.MkdirAll(workdir, 0o755))

	inv := NewInventory()
	findings := inv.AnalyzeTarget(target, workdir, "s")
	titles := ""
	for _, f := range findings {
		titles += f.Title + "|"
	}
	assert.Contains(t, titles, "Cleartext traffic permitted")
	policy, ok := inv.NetworkPolicy()
	require.True(t, ok)
	assert.True(t, policy.CleartextPermitted)
}

// makeTestDEX builds a header-plus-string-pool DEX good enough for the
// string scanner.
func makeTestDEX(t *testing.T, values []string) []byte {
	t.Helper()
	data := make([]byte, 0x70, 0x70+4*len(values)+len(values)*4)
	copy(data, "dex\n035\x00")
	binary.LittleEndian.PutUint32(data[0x38:], uint32(len(values)))
	stringIDsOff := 0x70
	binary.LittleEndian.PutUint32(data[0x3c:], uint32(stringIDsOff))

	dataOff := stringIDsOff + 4*len(values)
	var body bytes.Buffer
	offsets := make([]uint32, len(values))
	for i, s := range values {
		offsets[i] = uint32(body.Len())
		body.WriteByte(byte(len(s)))
		body.WriteString(s)
		body.WriteByte(0)
	}
	ids := make([]byte, 4*len(values))
	for i, off := range offsets {
		binary.LittleEndian.PutUint32(ids[i*4:], uint32(dataOff)+off)
	}
	data = append(data, ids...)
	data = append(data, body.Bytes()...)
	return data
}

func TestDEXStrings(t *testing.T) {
	values := []string{"hello", "https://example.com/x", "AKIAIOSFODNN7EXAMPLE"}
	got, err := dexStrings(makeTestDEX(t, values))
	require.NoError(t, err)
	assert.Equal(t, values, got)
}

func TestScanDEXStrings_FindsSecret(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.apk")
	f, err := os.Create(target)
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	w, err := zw.Create("classes.dex")
	require.NoError(t, err)
	_, err = w.Write(makeTestDEX(t, []string{
		"com/example/Config",
		"AKIAIOSFODNN7EXAMPLE",
		"https://api.example.com/v1",
	}))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())

	findings, agg := scanDEXStrings(target, "s")
	require.Len(t, findings, 1)
	assert.Equal(t, "AWS Access Key", findings[0].Title)
	assert.Equal(t, "classes.dex", findings[0].Location.File)
	assert.Equal(t, "app", findings[0].Origin)
	assert.Equal(t, 1, agg.URLs.Count)
}

func TestSDKByClassPrefix(t *testing.T) {
	assert.Equal(t, "Huawei HMS", SDKByClassPrefix("Lcom/huawei/hms/core/Foo;"))
	assert.Equal(t, "WeChat Open SDK", SDKByClassPrefix("Lcom/tencent/mm/opensdk/openapi/IWXAPI;"))
	assert.Equal(t, "Alipay SDK", SDKByClassPrefix("Lcom/alipay/sdk/app/PayTask;"))
	assert.Equal(t, "Umeng Analytics", SDKByClassPrefix("Lcom/umeng/analytics/MobclickAgent;"))
	assert.Equal(t, "", SDKByClassPrefix("Lcom/example/app/Main;"))
}

func TestOriginForPath(t *testing.T) {
	assert.Equal(t, "sdk:OkHttp", OriginForPath("sources/okhttp3/OkHttpClient.java"))
	assert.Equal(t, "sdk:Gson", OriginForPath("sources/com/google/gson/Gson.java"))
	assert.Equal(t, "app", OriginForPath("sources/com/example/app/Main.java"))
	assert.Equal(t, OriginSDKPrefix+"Firebase Crashlytics", OriginForPath("com/google/firebase/crashlytics/Foo.kt"))
}

func TestMavenVersionsFromArchive(t *testing.T) {
	path := buildZipFile(t, filepath.Join(t.TempDir(), "libs.apk"), map[string]string{
		"META-INF/maven/com.google.firebase/firebase-analytics/pom.properties": "version=21.5.0\nartifactId=firebase-analytics\n",
		"META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties":            "version=4.12.0\r\n",
		"META-INF/maven/not/a/pom.txt":                                         "version=ignored\n",
	})
	versions := mavenVersionsFromArchive(path)
	assert.Equal(t, "21.5.0", versions["com.google.firebase:firebase-analytics"])
	assert.Equal(t, "4.12.0", versions["com.squareup.okhttp3:okhttp"])
	assert.Len(t, versions, 2)
}
