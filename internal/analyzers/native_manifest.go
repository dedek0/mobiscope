package analyzers

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
)

// apkArchive gives the in-process analyzers direct, read-only access to the
// files inside an APK. It exists so manifest/resources analysis does not
// depend on apktool or jadx.
type apkArchive struct {
	zr  *zip.ReadCloser
	res *resourceTable
}

// openAPKArchive opens the APK and parses resources.arsc once. A missing or
// corrupt resource table is not fatal: references are then left unresolved.
func openAPKArchive(target string) (*apkArchive, error) {
	zr, err := openZip(target)
	if err != nil {
		return nil, err
	}
	a := &apkArchive{zr: zr}
	if data, err := a.read(ResourceTableFile, maxManifestBytes*4); err == nil {
		if table, err := parseResourceTable(data); err == nil {
			a.res = table
		}
	}
	return a, nil
}

// ResourceTableFile is the conventional path of the compiled resource table.
const ResourceTableFile = "resources.arsc"

func (a *apkArchive) close() {
	if a != nil && a.zr != nil {
		_ = a.zr.Close()
	}
}

// entry returns the ZIP entry with the exact name.
func (a *apkArchive) entry(name string) *zip.File {
	if a == nil || a.zr == nil {
		return nil
	}
	for _, f := range a.zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// read returns the contents of an archive entry, capped at limit bytes.
func (a *apkArchive) read(name string, limit int64) ([]byte, error) {
	f := a.entry(name)
	if f == nil {
		return nil, fmt.Errorf("%s not found in APK", name)
	}
	if f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", name, limit)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit))
}

// manifest decodes the AndroidManifest.xml straight from the APK. It accepts
// both the compiled binary-XML form and a plain-XML manifest (synthetic
// fixtures and a few tool-generated archives).
func (a *apkArchive) manifest() (*androidManifest, error) {
	data, err := a.read(AndroidManifestFile, maxManifestBytes)
	if err != nil {
		return nil, err
	}
	if len(data) < 2 || binary.LittleEndian.Uint16(data) != axmlChunkXML {
		return decodeManifest(data)
	}
	node, err := parseAXML(data, a.resolve)
	if err != nil {
		return nil, err
	}
	if node.Name != "manifest" {
		return nil, fmt.Errorf("binary XML root is %q, not manifest", node.Name)
	}
	return manifestFromAXML(node), nil
}

// resolve turns a resource reference into the string value stored in the
// resource table (for example a res/xml/… path).
func (a *apkArchive) resolve(id uint32) (string, bool) {
	if a == nil || a.res == nil {
		return "", false
	}
	return a.res.resolve(id)
}

// file returns the raw contents of a resource path (for example the network
// security config) from inside the APK.
func (a *apkArchive) file(name string, limit int64) ([]byte, bool) {
	data, err := a.read(name, limit)
	return data, err == nil
}

// manifestFromAXML converts the decoded binary-XML tree into the same struct
// encoding/xml produces for a decoded AndroidManifest.xml.
func manifestFromAXML(root *axmlNode) *androidManifest {
	m := &androidManifest{
		Package:      attrValue(root, "package"),
		VersionName:  normalizeResourceRef(attrValue(root, "versionName")),
		VersionCode:  attrValue(root, "versionCode"),
		SharedUserID: attrValue(root, "sharedUserId"),
	}
	if sdk := root.Child("uses-sdk"); sdk != nil {
		m.UsesSDK = usesSDK{
			MinSDKVersion:    attrValue(sdk, "minSdkVersion"),
			TargetSDKVersion: attrValue(sdk, "targetSdkVersion"),
			MaxSDKVersion:    attrValue(sdk, "maxSdkVersion"),
		}
	}

	for _, child := range root.Children {
		switch child.Name {
		case "uses-permission":
			m.UsesPermissions = append(m.UsesPermissions, usesPermission{Name: attrValue(child, "name")})
		case "uses-permission-sdk-23":
			m.UsesPermSDK23 = append(m.UsesPermSDK23, usesPermission{Name: attrValue(child, "name")})
		case "permission":
			m.PermissionDecls = append(m.PermissionDecls, permissionDecl{
				Name:            attrValue(child, "name"),
				ProtectionLevel: attrValue(child, "protectionLevel"),
			})
		case "queries":
			for _, q := range child.Children {
				switch q.Name {
				case "package":
					m.Queries.Packages = append(m.Queries.Packages, struct {
						Name string `xml:"name,attr"`
					}{Name: attrValue(q, "name")})
				case "intent":
					m.Queries.Intent = append(m.Queries.Intent, intentFilterFromNode(q))
				}
			}
		case "application":
			m.Application = applicationFromNode(child)
		}
	}
	return m
}

// applicationFromNode decodes <application> and its components.
func applicationFromNode(node *axmlNode) application {
	app := application{
		Debuggable:            attrValue(node, "debuggable"),
		AllowBackup:           attrValue(node, "allowBackup"),
		UsesCleartextTraffic:  attrValue(node, "usesCleartextTraffic"),
		TestOnly:              attrValue(node, "testOnly"),
		NetworkSecurityConfig: normalizeResourceRef(attrValue(node, "networkSecurityConfig")),
		FullBackupContent:     normalizeResourceRef(attrValue(node, "fullBackupContent")),
		DataExtractionRules:   normalizeResourceRef(attrValue(node, "dataExtractionRules")),
		ExtractNativeLibs:     attrValue(node, "extractNativeLibs"),
		Permission:            attrValue(node, "permission"),
	}
	for _, child := range node.Children {
		switch child.Name {
		case "activity":
			app.Activities = append(app.Activities, componentFromNode(child))
		case "activity-alias":
			app.ActivityAliases = append(app.ActivityAliases, componentFromNode(child))
		case "service":
			app.Services = append(app.Services, componentFromNode(child))
		case "receiver":
			app.Receivers = append(app.Receivers, componentFromNode(child))
		case "provider":
			app.Providers = append(app.Providers, componentFromNode(child))
		}
	}
	return app
}

// componentFromNode decodes one component element.
func componentFromNode(node *axmlNode) component {
	c := component{
		Name:         attrValue(node, "name"),
		Exported:     attrValue(node, "exported"),
		Permission:   attrValue(node, "permission"),
		Process:      attrValue(node, "process"),
		GrantURI:     attrValue(node, "grantUriPermissions"),
		Authorities:  attrValue(node, "authorities"),
		TaskAffinity: attrValue(node, "taskAffinity"),
		ReadPerm:     attrValue(node, "readPermission"),
		WritePerm:    attrValue(node, "writePermission"),
		Enabled:      attrValue(node, "enabled"),
		DirectBoot:   attrValue(node, "directBootAware"),
		Priority:     attrValue(node, "priority"),
		AllowBackup:  attrValue(node, "allowBackup"),
		Multiprocess: attrValue(node, "multiprocess"),
		LaunchMode:   attrValue(node, "launchMode"),
		TaskReparent: attrValue(node, "allowTaskReparenting"),
	}
	for _, child := range node.Children {
		switch child.Name {
		case "intent-filter":
			c.IntentFilters = append(c.IntentFilters, intentFilterFromNode(child))
		case "grant-uri-permission":
			c.GrantURIChildren = append(c.GrantURIChildren, struct{}{})
		}
	}
	return c
}

// intentFilterFromNode decodes an <intent-filter> element.
func intentFilterFromNode(node *axmlNode) intentFilter {
	f := intentFilter{AutoVerify: attrValue(node, "autoVerify")}
	for _, child := range node.Children {
		switch child.Name {
		case "action":
			f.Actions = append(f.Actions, action{Name: attrValue(child, "name")})
		case "category":
			f.Categories = append(f.Categories, category{Name: attrValue(child, "name")})
		case "data":
			f.Data = append(f.Data, dataElem{
				Scheme:     attrValue(child, "scheme"),
				Host:       attrValue(child, "host"),
				Path:       attrValue(child, "path"),
				PathPrefix: attrValue(child, "pathPrefix"),
			})
		}
	}
	return f
}

// attrValue returns an element attribute by local name.
func attrValue(node *axmlNode, name string) string {
	v, _ := node.Attr(name)
	return strings.TrimSpace(v)
}

// normalizeResourceRef turns a resolved resource-table path into the compact
// @xml/… form used by the decoded XML. Values that are already @… or plain
// literals are returned unchanged.
func normalizeResourceRef(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "res/") {
		return value
	}
	dir := path.Dir(value)
	base := strings.TrimSuffix(path.Base(value), path.Ext(value))
	if dir == "res/xml" && base != "" {
		return "@xml/" + base
	}
	kind := strings.TrimPrefix(dir, "res/")
	if kind != "" && base != "" {
		return "@" + kind + "/" + base
	}
	return value
}
