package analyzers

import "strings"

// OriginApp marks a finding as belonging to the application itself rather
// than to a bundled third-party library.
const OriginApp = "app"

// OriginSDKPrefix prefixes the origin of a finding that points into a detected
// third-party library.
const OriginSDKPrefix = "sdk:"

// OriginForPath attributes a decompiled-tree path to the app or to a known
// SDK. The comparison uses the DEX class prefixes from sdkSignatures, mapped
// onto the directory layout the decompilers emit (sources/com/example/…).
func OriginForPath(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	for _, sig := range sdkSignatures {
		for _, prefix := range sig.Prefixes {
			dir := strings.TrimSuffix(strings.TrimPrefix(prefix, "L"), "/")
			if dir == "" {
				continue
			}
			if strings.Contains(p, "/"+dir+"/") || strings.HasPrefix(p, dir+"/") {
				return OriginSDKPrefix + sig.Name
			}
		}
	}
	return OriginApp
}

// SDKByClassPrefix returns the SDK name that owns a DEX class descriptor, or
// "" when the class is not part of a known library.
func SDKByClassPrefix(class string) string {
	for _, sig := range sdkSignatures {
		for _, prefix := range sig.Prefixes {
			if strings.HasPrefix(class, prefix) {
				return sig.Name
			}
		}
	}
	return ""
}
