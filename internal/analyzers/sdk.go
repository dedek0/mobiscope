package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const sdkName = "sdk"

// SDK detects the third-party libraries bundled in the app. The detection
// runs over the DEX class names, so it works on an undecoded APK, and the
// version is recovered from the decoded resources when the decompiler ran.
type SDK struct{}

func NewSDK() *SDK {
	return &SDK{}
}

func (s *SDK) Name() string { return sdkName }

// Available always succeeds: the analysis is fully in-process.
func (s *SDK) Available() error { return nil }

// Phase marks the analyzer as independent: it reads the target artifact
// directly.
func (s *SDK) Phase() Phase { return PhaseIndependent }

func (s *SDK) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  s.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	sdks := DetectSDKs(target, workdir)

	raw, _ := json.Marshal(map[string]interface{}{"sdks": sdks})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// sdkOutput is the JSON shape written by SDK.Run.
type sdkOutput struct {
	SDKs []models.SDK `json:"sdks"`
}

// ConvertSDKFindings turns the SDK inventory into informational findings, so
// the inventory shows up in the report next to the other checks.
func ConvertSDKFindings(raw []byte, sessionID string) []models.Finding {
	var out sdkOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	for _, sdk := range out.SDKs {
		version := sdk.Version
		if version == "" {
			version = "unknown version"
		}
		f := models.Finding{
			ID:          models.GenerateID(sdkName, models.CategoryManifestIssue, sdk.Package, 0, sdk.Package),
			SessionID:   sessionID,
			SourceTool:  sdkName,
			Category:    models.CategoryManifestIssue,
			Platform:    models.PlatformAndroid,
			Title:       fmt.Sprintf("Third-party library detected: %s", sdk.Name),
			Description: fmt.Sprintf("The app bundles %s (%s, %s).", sdk.Name, sdk.Package, version),
			Evidence:    sdk.Evidence,
			Location:    models.Location{File: sdk.Evidence, Line: 0, Snippet: sdk.Evidence},
			Severity:    models.SeverityInfo,
			Sensitivity: models.SensitivityPublic,
			Confidence:  sdk.Confidence,
		}
		findings = append(findings, f)
	}
	return findings
}

// sdkSignature describes how a library is recognised.
type sdkSignature struct {
	Name     string
	Group    string
	Artifact string
	// Prefixes are the DEX class-name prefixes that identify the library.
	Prefixes []string
	// VersionResource is a resource name whose value carries the version.
	VersionResource string
}

// sdkSignatures is the curated table of libraries worth reporting.
var sdkSignatures = []sdkSignature{
	{
		Name: "Firebase Analytics", Group: firebaseGroup, Artifact: "firebase-analytics",
		Prefixes: []string{"Lcom/google/firebase/analytics/"},
	},
	{
		Name: "Firebase Crashlytics", Group: firebaseGroup, Artifact: "firebase-crashlytics",
		Prefixes: []string{"Lcom/google/firebase/crashlytics/"},
	},
	{
		Name: "Firebase Database", Group: firebaseGroup, Artifact: "firebase-database",
		Prefixes: []string{"Lcom/google/firebase/database/"},
	},
	{
		Name: "Firebase Auth", Group: firebaseGroup, Artifact: "firebase-auth",
		Prefixes: []string{"Lcom/google/firebase/auth/"},
	},
	{
		Name: "Firebase Messaging", Group: firebaseGroup, Artifact: "firebase-messaging",
		Prefixes: []string{"Lcom/google/firebase/messaging/"},
	},
	{
		Name: "Google Mobile Ads", Group: "com.google.android.gms", Artifact: "play-services-ads",
		Prefixes: []string{"Lcom/google/android/gms/ads/"},
	},
	{
		Name: "Google Play Services Location", Group: "com.google.android.gms", Artifact: "play-services-location",
		Prefixes: []string{"Lcom/google/android/gms/location/"},
	},
	{
		Name: "Facebook SDK", Group: "com.facebook.android", Artifact: "facebook-android-sdk",
		Prefixes: []string{"Lcom/facebook/"}, VersionResource: "com_facebook_app_version",
	},
	{
		Name: "React Native", Group: "com.facebook.react", Artifact: "react-native",
		Prefixes: []string{"Lcom/facebook/react/"},
	},
	{
		Name: "Adjust", Group: "com.adjust.sdk", Artifact: "adjust-android-sdk",
		Prefixes: []string{"Lcom/adjust/sdk/"},
	},
	{
		Name: "AppsFlyer", Group: "com.appsflyer", Artifact: "appsflyer-sdk",
		Prefixes: []string{"Lcom/appsflyer/"},
	},
	{
		Name: "Branch", Group: "io.branch.sdk", Artifact: "branch-android-sdk",
		Prefixes: []string{"Lio/branch/sdk/"},
	},
	{
		Name: "OneSignal", Group: "com.onesignal", Artifact: "onesignal",
		Prefixes: []string{"Lcom/onesignal/"},
	},
	{
		Name: "Segment", Group: "com.segment", Artifact: "analytics-android",
		Prefixes: []string{"Lcom/segment/"},
	},
	{
		Name: "Sentry", Group: "io.sentry", Artifact: "sentry-android",
		Prefixes: []string{"Lio/sentry/"},
	},
	{
		Name: "Bugsnag", Group: "com.bugsnag", Artifact: "bugsnag-android",
		Prefixes: []string{"Lcom/bugsnag/"},
	},
	{
		Name: "Datadog", Group: "com.datadog", Artifact: "dd-sdk-android",
		Prefixes: []string{"Lcom/datadog/"},
	},
	{
		Name: "Crashlytics", Group: "com.crashlytics", Artifact: "crashlytics",
		Prefixes: []string{"Lcom/crashlytics/"},
	},
	{
		Name: "Stripe", Group: "com.stripe", Artifact: "stripe-android",
		Prefixes: []string{"Lcom/stripe/"},
	},
	{
		Name: "OkHttp", Group: "com.squareup.okhttp3", Artifact: "okhttp",
		Prefixes: []string{"Lokhttp3/"},
	},
	{
		Name: "Retrofit", Group: "com.squareup.retrofit2", Artifact: "retrofit",
		Prefixes: []string{"Lretrofit2/"},
	},
	{
		Name: "Okio", Group: "com.squareup.okio", Artifact: "okio",
		Prefixes: []string{"Lokio/"},
	},
	{
		Name: "Picasso", Group: "com.squareup.picasso", Artifact: "picasso",
		Prefixes: []string{"Lcom/squareup/picasso/"},
	},
	{
		Name: "Gson", Group: "com.google.code.gson", Artifact: "gson",
		Prefixes: []string{"Lcom/google/gson/"},
	},
	{
		Name: "Jackson Databind", Group: "com.fasterxml.jackson.core", Artifact: "jackson-databind",
		Prefixes: []string{"Lcom/fasterxml/jackson/databind/"},
	},
	{
		Name: "Glide", Group: "com.github.bumptech.glide", Artifact: "glide",
		Prefixes: []string{"Lcom/bumptech/glide/"},
	},
	{
		Name: "Guava", Group: "com.google.guava", Artifact: "guava",
		Prefixes: []string{"Lcom/google/common/collect/", "Lcom/google/common/base/"},
	},
	{
		Name: "RxJava", Group: "io.reactivex.rxjava2", Artifact: "rxjava",
		Prefixes: []string{"Lio/reactivex/rxjava2/"},
	},
	{
		Name: "Apache Commons IO", Group: "commons-io", Artifact: "commons-io",
		Prefixes: []string{"Lorg/apache/commons/io/"},
	},
	{
		Name: "Cordova", Group: "org.apache.cordova", Artifact: "cordova-android",
		Prefixes: []string{"Lorg/apache/cordova/"},
	},
	{
		Name: "Huawei HMS", Group: "com.huawei.hms", Artifact: "hms-core",
		Prefixes: []string{"Lcom/huawei/hms/", "Lcom/huawei/agconnect/"},
	},
	{
		Name: "WeChat Open SDK", Group: "com.tencent.mm", Artifact: "wechat-sdk-android",
		Prefixes: []string{"Lcom/tencent/mm/opensdk/"},
	},
	{
		Name: "Tencent Bugly", Group: "com.tencent.bugly", Artifact: "bugly",
		Prefixes: []string{"Lcom/tencent/bugly/"},
	},
	{
		Name: "Tencent MMKV", Group: "com.tencent", Artifact: "mmkv",
		Prefixes: []string{"Lcom/tencent/mmkv/"},
	},
	{
		Name: "Alipay SDK", Group: "com.alipay", Artifact: "alipay-sdk",
		Prefixes: []string{"Lcom/alipay/sdk/"},
	},
	{
		Name: "Umeng Analytics", Group: "com.umeng", Artifact: "umeng-common",
		Prefixes: []string{"Lcom/umeng/"},
	},
	{
		Name: "JPush", Group: "cn.jpush", Artifact: "jpush-android",
		Prefixes: []string{"Lcn/jpush/"},
	},
	{
		Name: "Baidu Map", Group: "com.baidu", Artifact: "baidu-map-sdk",
		Prefixes: []string{"Lcom/baidu/mapapi/", "Lcom/baidu/location/"},
	},
	{
		Name: "Google Play Billing", Group: "com.android.billingclient", Artifact: "billing",
		Prefixes: []string{"Lcom/android/billingclient/"},
	},
	{
		Name: "Flutter", Group: "io.flutter", Artifact: "flutter",
		Prefixes: []string{"Lio/flutter/"},
	},
	{
		Name: "Unity", Group: "com.unity3d", Artifact: "unity-runtime",
		Prefixes: []string{"Lcom/unity3d/"},
	},
	{
		Name: "Apache HttpClient", Group: "org.apache.httpcomponents", Artifact: "httpclient",
		Prefixes: []string{"Lorg/apache/http/"},
	},
	{
		Name: "Bouncy Castle", Group: "org.bouncycastle", Artifact: "bcprov",
		Prefixes: []string{"Lorg/bouncycastle/"},
	},
	{
		Name: "SQLCipher", Group: "net.zetetic", Artifact: "sqlcipher-android",
		Prefixes: []string{"Lnet/sqlcipher/"},
	},
	{
		Name: "ZXing", Group: "com.google.zxing", Artifact: "core",
		Prefixes: []string{"Lcom/google/zxing/"},
	},
	{
		Name: "Kotlin Standard Library", Group: "org.jetbrains.kotlin", Artifact: "kotlin-stdlib",
		Prefixes: []string{"Lkotlin/"},
	},
}

// DetectSDKs inspects the DEX files of the target and the decoded resources
// of the session and returns the libraries it recognises.
func DetectSDKs(target, workdir string) []models.SDK {
	classes := dexClassNamesFromArchive(target)

	found := map[string]models.SDK{}
	for _, class := range classes {
		for _, sig := range sdkSignatures {
			if _, ok := found[sig.Name]; ok {
				continue
			}
			for _, prefix := range sig.Prefixes {
				if strings.HasPrefix(class, prefix) {
					found[sig.Name] = models.SDK{
						Name:       sig.Name,
						Group:      sig.Group,
						Artifact:   sig.Artifact,
						Package:    sig.Group + ":" + sig.Artifact,
						Evidence:   class,
						Confidence: 0.9,
					}
					break
				}
			}
		}
	}

	maven := mavenVersionsFromArchive(target)
	resources := resourceVersions(workdir)
	buildConfigs := buildConfigVersions(workdir)
	for name, sdk := range found {
		if v := maven[sdk.Group+":"+sdk.Artifact]; v != "" {
			sdk.Version = v
			found[name] = sdk
			continue
		}
		for _, sig := range sdkSignatures {
			if sig.Name != name || sig.VersionResource == "" {
				continue
			}
			if v, ok := resources[sig.VersionResource]; ok {
				sdk.Version = v
				found[name] = sdk
			}
		}
	}
	for name, sdk := range found {
		if sdk.Version != "" {
			continue
		}
		if v := buildConfigVersionFor(buildConfigs, sdk.Group); v != "" {
			sdk.Version = v
			found[name] = sdk
		}
	}
	for _, sdk := range nativeSDKsFromArchive(target) {
		if _, ok := found[sdk.Name]; !ok {
			found[sdk.Name] = sdk
		}
	}

	out := make([]models.SDK, 0, len(found))
	for _, sdk := range found {
		out = append(out, sdk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// dexClassNamesFromArchive collects the class names of every DEX file in the
// archive.
func dexClassNamesFromArchive(target string) []string {
	zr, err := openZip(target)
	if err != nil {
		return nil
	}
	defer zr.Close()

	var names []string
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "classes") || !strings.HasSuffix(f.Name, ".dex") {
			continue
		}
		if f.UncompressedSize64 > maxDexBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := readAllLimited(rc, maxDexBytes)
		rc.Close()
		if err != nil {
			continue
		}
		classNames, derr := dexClassNames(data)
		if derr == nil {
			names = append(names, classNames...)
		}
	}
	return names
}

// mavenVersionPrefix is where packaged libraries put pom.properties.
const mavenVersionPrefix = "META-INF/maven/"

// mavenVersionsFromArchive recovers group:artifact → version from the
// META-INF/maven/*/pom.properties entries that many libraries ship inside the
// APK. It works without a decompiler and gives --osv an exact version.
func mavenVersionsFromArchive(target string) map[string]string {
	out := map[string]string{}
	zr, err := openZip(target)
	if err != nil {
		return out
	}
	defer zr.Close()

	const maxPomBytes = 1 << 20
	for _, f := range zr.File {
		name := f.Name
		if !strings.HasPrefix(name, mavenVersionPrefix) || !strings.HasSuffix(name, "/pom.properties") {
			continue
		}
		if f.UncompressedSize64 > maxPomBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := readAllLimited(rc, maxPomBytes)
		rc.Close()
		if err != nil {
			continue
		}
		group, artifact := mavenCoordinates(name)
		version := pomProperty(string(data), "version")
		if group != "" && artifact != "" && version != "" {
			out[group+":"+artifact] = version
		}
	}
	return out
}

// mavenCoordinates parses META-INF/maven/<group>/<artifact>/pom.properties.
func mavenCoordinates(name string) (group, artifact string) {
	rest := strings.TrimPrefix(name, mavenVersionPrefix)
	rest = strings.TrimSuffix(rest, "/pom.properties")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return "", ""
	}
	artifact = parts[len(parts)-1]
	group = strings.Join(parts[:len(parts)-1], ".")
	return group, artifact
}

// pomProperty returns the value of a key in a .properties file.
func pomProperty(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		}
	}
	return ""
}

const maxBuildConfigFiles = 2000

var (
	buildConfigPackageRe = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_.]+)`)
	buildConfigVersionRe = regexp.MustCompile(`(?m)\b(?:VERSION|VERSION_NAME|VERSION_STRING)\b\s*(?::\s*String\s*)?[=:]\s*"([^"]+)"`)
)

// buildConfigVersions recovers library versions from decompiled BuildConfig
// classes, mapping the Java package to the VERSION constant.
func buildConfigVersions(workdir string) map[string]string {
	out := map[string]string{}
	scanned := 0
	for _, root := range []string{
		filepath.Join(workdir, "jadx", "sources"),
		filepath.Join(workdir, "jadx"),
	} {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			base := d.Name()
			if base != "BuildConfig.java" && base != "BuildConfig.kt" {
				return nil
			}
			if scanned >= maxBuildConfigFiles {
				return filepath.SkipAll
			}
			data, err := readFileCapped(p, maxManifestBytes)
			if err != nil {
				return nil
			}
			scanned++
			content := string(data)
			pkg := buildConfigPackageRe.FindStringSubmatch(content)
			version := buildConfigVersionRe.FindStringSubmatch(content)
			if pkg == nil || version == nil || !versionLike(version[1]) {
				return nil
			}
			if _, exists := out[pkg[1]]; !exists {
				out[pkg[1]] = version[1]
			}
			return nil
		})
		if len(out) > 0 {
			break
		}
	}
	return out
}

// buildConfigVersionFor finds the longest package prefix that matches an SDK
// group.
func buildConfigVersionFor(versions map[string]string, group string) string {
	if group == "" {
		return ""
	}
	if v, ok := versions[group]; ok {
		return v
	}
	bestPkg, bestVersion := "", ""
	for pkg, version := range versions {
		if !strings.HasPrefix(group, pkg+".") && !strings.HasPrefix(pkg, group+".") {
			continue
		}
		if len(pkg) > len(bestPkg) {
			bestPkg, bestVersion = pkg, version
		}
	}
	return bestVersion
}

// nativeSDKsFromArchive recognises libraries that are only visible as native
// binaries (no DEX classes).
func nativeSDKsFromArchive(target string) []models.SDK {
	zr, err := openZip(target)
	if err != nil {
		return nil
	}
	defer zr.Close()

	specs := []struct {
		name     string
		group    string
		artifact string
		libs     []string
	}{
		{"Flutter", "io.flutter", "flutter", []string{"libflutter.so"}},
		{"Unity", "com.unity3d", "unity-runtime", []string{"libunity.so", "libil2cpp.so"}},
		{"React Native", "com.facebook.react", "react-native", []string{"libreactnativejni.so"}},
		{"Hermes JS Engine", "com.facebook.hermes", "hermes", []string{"libhermes.so"}},
	}

	found := map[string]models.SDK{}
	for _, f := range zr.File {
		base := strings.ToLower(filepath.Base(f.Name))
		for _, spec := range specs {
			if _, exists := found[spec.name]; exists {
				continue
			}
			for _, lib := range spec.libs {
				if base == lib {
					found[spec.name] = models.SDK{
						Name:       spec.name,
						Group:      spec.group,
						Artifact:   spec.artifact,
						Package:    spec.group + ":" + spec.artifact,
						Evidence:   f.Name,
						Confidence: 0.85,
					}
					break
				}
			}
		}
	}

	out := make([]models.SDK, 0, len(found))
	for _, sdk := range found {
		out = append(out, sdk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// resourceVersions reads the decoded string resources of the session and
// returns the values that look like a version.
func resourceVersions(workdir string) map[string]string {
	out := map[string]string{}
	for _, root := range []string{
		filepath.Join(workdir, "apktool", "res", "values", "strings.xml"),
		filepath.Join(workdir, "jadx", "resources", "res", "values", "strings.xml"),
		filepath.Join(workdir, "res", "values", "strings.xml"),
	} {
		data, err := readFileCapped(root, maxManifestBytes)
		if err != nil {
			continue
		}
		for name, value := range parseStringResources(string(data)) {
			if versionLike(value) {
				out[name] = value
			}
		}
		break
	}
	return out
}

// stringResourceRe matches a <string name="…">value</string> element.
var stringResourceRe = regexp.MustCompile(`(?s)<string[^>]*\bname="([^"]+)"[^>]*>(.*?)</string>`)

// parseStringResources extracts the name/value pairs of a decoded
// strings.xml.
func parseStringResources(content string) map[string]string {
	out := map[string]string{}
	for _, m := range stringResourceRe.FindAllStringSubmatch(content, -1) {
		name, value := m[1], strings.TrimSpace(m[2])
		if name == "" {
			continue
		}
		out[name] = value
	}
	return out
}

// versionLike reports whether a value looks like a version number.
func versionLike(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 40 {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

// readAllLimited reads at most limit bytes from r.
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

// SDKsFromRuns extracts the SDK inventory from the sdk stage output, if the
// stage ran.
func SDKsFromRuns(results []models.ToolResult) []models.SDK {
	for _, r := range results {
		if r.ToolName != sdkName || len(r.Output) == 0 {
			continue
		}
		var out sdkOutput
		if err := json.Unmarshal(r.Output, &out); err != nil {
			continue
		}
		return out.SDKs
	}
	return nil
}
