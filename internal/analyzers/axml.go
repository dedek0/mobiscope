package analyzers

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"unicode/utf16"
)

// Android binary XML (AXML) chunk types. The format is documented in
// frameworks/base/include/androidfw/ResourceTypes.h; only the pieces needed to
// read AndroidManifest.xml and the network security config are implemented.
const (
	axmlChunkXML            = 0x0003
	axmlChunkStringPool     = 0x0001
	axmlChunkResourceMap    = 0x0180
	axmlChunkStartNamespace = 0x0100
	axmlChunkEndNamespace   = 0x0101
	axmlChunkStartElement   = 0x0102
	axmlChunkEndElement     = 0x0103
	axmlChunkCDATA          = 0x0104
)

// Res_value data types used by AXML attributes.
const (
	axmlTypeNull      = 0x00
	axmlTypeReference = 0x01
	axmlTypeAttribute = 0x02
	axmlTypeString    = 0x03
	axmlTypeFloat     = 0x04
	axmlTypeIntDec    = 0x10
	axmlTypeIntHex    = 0x11
	axmlTypeIntBool   = 0x12
)

// axmlAttr is one attribute of a decoded binary-XML element.
type axmlAttr struct {
	Namespace string
	Name      string
	Value     string
	// DataType and Data expose the typed value so callers can tell a
	// resolved string reference from an inline integer.
	DataType uint8
	Data     uint32
}

// axmlNode is an element in a decoded binary-XML document.
type axmlNode struct {
	Name     string
	Line     int
	Attrs    []axmlAttr
	Children []*axmlNode
	// Text is the concatenated character data directly inside the element
	// (for example the domain name in <domain>example.com</domain>).
	Text string
}

// Attr returns the value of the attribute with the given local name.
func (n *axmlNode) Attr(name string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, a := range n.Attrs {
		if a.Name == name {
			return a.Value, true
		}
	}
	return "", false
}

// Child returns the first child element with the given name.
func (n *axmlNode) Child(name string) *axmlNode {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// stringPool decodes a ResStringPool chunk.
type stringPool struct {
	values []string
}

// parseStringPool decodes a string-pool chunk. Both the UTF-8 and UTF-16
// encodings aapt can emit are supported.
func parseStringPool(chunk []byte) (*stringPool, error) {
	if len(chunk) < 28 {
		return nil, fmt.Errorf("string pool chunk too small")
	}
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:]))
	if headerSize < 28 || headerSize > len(chunk) {
		return nil, fmt.Errorf("invalid string pool header size %d", headerSize)
	}
	count := int(binary.LittleEndian.Uint32(chunk[8:]))
	flags := binary.LittleEndian.Uint32(chunk[16:])
	stringsStart := int(binary.LittleEndian.Uint32(chunk[20:]))
	utf8Encoded := flags&0x100 != 0

	if count < 0 || count > (len(chunk)-headerSize)/4 {
		return nil, fmt.Errorf("implausible string count %d", count)
	}
	if stringsStart < headerSize || stringsStart > len(chunk) {
		return nil, fmt.Errorf("string data out of range")
	}

	pool := &stringPool{values: make([]string, 0, count)}
	for i := 0; i < count; i++ {
		off := int(binary.LittleEndian.Uint32(chunk[headerSize+i*4:]))
		pos := stringsStart + off
		if pos < 0 || pos >= len(chunk) {
			pool.values = append(pool.values, "")
			continue
		}
		if utf8Encoded {
			pool.values = append(pool.values, decodeUTF8String(chunk[pos:]))
		} else {
			pool.values = append(pool.values, decodeUTF16String(chunk[pos:]))
		}
	}
	return pool, nil
}

// at returns the string at index i, or "" when the index is out of range.
func (p *stringPool) at(i uint32) string {
	if p == nil || int(i) >= len(p.values) {
		return ""
	}
	return p.values[i]
}

// decodeUTF8String reads a UTF-8 string_data_item: one or two length bytes,
// the bytes, and a NUL terminator.
func decodeUTF8String(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	length := int(data[0])
	pos := 1
	if data[0]&0x80 != 0 {
		if len(data) < 2 {
			return ""
		}
		length = ((int(data[0]&0x7f) << 8) | int(data[1]))
		pos = 2
	}
	if length < 0 || pos+length > len(data) {
		return ""
	}
	return string(data[pos : pos+length])
}

// decodeUTF16String reads a UTF-16LE string_data_item.
func decodeUTF16String(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	length := int(binary.LittleEndian.Uint16(data))
	pos := 2
	if length&0x8000 != 0 {
		if len(data) < 4 {
			return ""
		}
		length = ((length & 0x7fff) << 16) | int(binary.LittleEndian.Uint16(data[2:]))
		pos = 4
	}
	if length < 0 || pos+length*2 > len(data) {
		return ""
	}
	units := make([]uint16, length)
	for i := 0; i < length; i++ {
		units[i] = binary.LittleEndian.Uint16(data[pos+i*2:])
	}
	return string(utf16.Decode(units))
}

// parseAXML decodes a binary XML document into a tree. resolve is used to turn
// a resource reference (for example @xml/network_security_config) into a
// string; it may be nil.
func parseAXML(data []byte, resolve func(uint32) (string, bool)) (*axmlNode, error) {
	if len(data) < 8 || binary.LittleEndian.Uint16(data) != axmlChunkXML {
		return nil, fmt.Errorf("not a binary XML document")
	}
	headerSize := int(binary.LittleEndian.Uint16(data[2:]))
	if headerSize < 8 || headerSize > len(data) {
		return nil, fmt.Errorf("invalid binary XML header size %d", headerSize)
	}

	var (
		pool   *stringPool
		resMap []uint32
		stack  []*axmlNode
		root   *axmlNode
	)

	for pos := headerSize; pos+8 <= len(data); {
		chunkType := binary.LittleEndian.Uint16(data[pos:])
		chunkHeader := int(binary.LittleEndian.Uint16(data[pos+2:]))
		chunkSize := int(binary.LittleEndian.Uint32(data[pos+4:]))
		if chunkHeader < 8 || chunkSize < chunkHeader || pos+chunkSize > len(data) {
			return root, fmt.Errorf("invalid chunk at offset %d", pos)
		}
		chunk := data[pos : pos+chunkSize]

		switch chunkType {
		case axmlChunkStringPool:
			p, err := parseStringPool(chunk)
			if err != nil {
				return root, err
			}
			pool = p
		case axmlChunkResourceMap:
			n := (len(chunk) - 8) / 4
			resMap = make([]uint32, n)
			for i := 0; i < n; i++ {
				resMap[i] = binary.LittleEndian.Uint32(chunk[8+i*4:])
			}
		case axmlChunkStartElement:
			node, err := decodeAXMLElement(chunk, pool, resMap, resolve)
			if err != nil {
				return root, err
			}
			if len(stack) == 0 {
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case axmlChunkCDATA:
			// ResXMLTree_cdataExt: node header, ns, data (string ref),
			// typedValue in which a string value carries the same index.
			if len(stack) > 0 && len(chunk) >= 24 {
				text := pool.at(binary.LittleEndian.Uint32(chunk[20:]))
				if text != "" {
					stack[len(stack)-1].Text += text
				}
			}
		case axmlChunkEndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}

		pos += chunkSize
	}

	if root == nil {
		return nil, fmt.Errorf("binary XML has no root element")
	}
	return root, nil
}

// decodeAXMLElement decodes a RES_XML_START_ELEMENT_TYPE chunk.
func decodeAXMLElement(chunk []byte, pool *stringPool, resMap []uint32, resolve func(uint32) (string, bool)) (*axmlNode, error) {
	// ResXMLTree_node is 16 bytes: chunk header, line number and comment.
	if len(chunk) < 16+20 {
		return nil, fmt.Errorf("start-element chunk too small")
	}
	line := int(binary.LittleEndian.Uint32(chunk[8:]))
	body := chunk[16:]
	nameIdx := binary.LittleEndian.Uint32(body[4:])
	name := pool.at(nameIdx)
	if name == "" && int(nameIdx) < len(resMap) {
		name = androidAttributeName(resMap[nameIdx])
	}
	if name == "" {
		return nil, fmt.Errorf("start element without a name")
	}

	attrStart := int(binary.LittleEndian.Uint16(body[8:]))
	attrSize := int(binary.LittleEndian.Uint16(body[10:]))
	attrCount := int(binary.LittleEndian.Uint16(body[12:]))
	if attrSize < 20 {
		attrSize = 20
	}
	if attrStart <= 0 {
		attrStart = 20
	}

	node := &axmlNode{Name: name, Line: line}
	for i := 0; i < attrCount; i++ {
		off := attrStart + i*attrSize
		if off+20 > len(body) {
			break
		}
		a := body[off : off+20]
		nsURI := pool.at(binary.LittleEndian.Uint32(a[0:]))
		attrName := pool.at(binary.LittleEndian.Uint32(a[4:]))
		rawIdx := binary.LittleEndian.Uint32(a[8:])
		dataType := a[15]
		data := binary.LittleEndian.Uint32(a[16:])
		if attrName == "" && int(binary.LittleEndian.Uint32(a[4:])) < len(resMap) {
			attrName = androidAttributeName(resMap[binary.LittleEndian.Uint32(a[4:])])
		}

		value := ""
		switch {
		case rawIdx != 0xffffffff:
			value = pool.at(rawIdx)
		case dataType == axmlTypeString:
			value = pool.at(data)
		case dataType == axmlTypeReference:
			if resolve != nil {
				if v, ok := resolve(data); ok && v != "" {
					value = v
					break
				}
			}
			value = fmt.Sprintf("@0x%08x", data)
		case dataType == axmlTypeIntBool:
			if data != 0 {
				value = boolTrue
			} else {
				value = "false"
			}
		case dataType == axmlTypeIntDec || dataType == axmlTypeIntHex:
			value = strconv.FormatUint(uint64(data), 10)
		case dataType == axmlTypeFloat:
			value = strconv.FormatFloat(float64(data), 'g', -1, 32)
		}

		node.Attrs = append(node.Attrs, axmlAttr{
			Namespace: nsURI,
			Name:      attrName,
			Value:     value,
			DataType:  dataType,
			Data:      data,
		})
	}

	return node, nil
}

// androidAttributeName resolves a framework attribute resource id to its local
// name. Binary XML usually carries the name in the string pool, so this is a
// fallback for obfuscated or stripped manifests. Only the attributes mobiscope
// inspects are listed.
func androidAttributeName(resID uint32) string {
	if name, ok := androidAttributeNames[resID]; ok {
		return name
	}
	return ""
}

// androidAttributeNames maps the android namespace attribute ids (0x0101xxxx)
// that the manifest analysis reads.
var androidAttributeNames = map[uint32]string{
	0x01010003: "name",
	0x01010006: "permission",
	0x01010007: "readPermission",
	0x01010008: "writePermission",
	0x0101000f: "debuggable",
	0x01010010: "exported",
	0x01010011: "process",
	0x01010018: "authorities",
	0x0101001d: "launchMode",
	0x0101001e: "taskAffinity",
	0x0101001f: "allowTaskReparenting",
	0x01010021: "protectionLevel",
	0x01010024: "versionName",
	0x01010025: "versionCode",
	0x01010026: "minSdkVersion",
	0x01010027: "targetSdkVersion",
	0x01010028: "maxSdkVersion",
	0x0101003c: "allowBackup",
	0x0101003d: "enabled",
	0x0101003e: "grantUriPermissions",
	0x01010053: "autoVerify",
	0x01010271: "usesCleartextTraffic",
	0x0101027f: "networkSecurityConfig",
	0x01010280: "fullBackupContent",
	0x01010281: "extractNativeLibs",
	0x010102ed: "dataExtractionRules",
	0x01010527: "testOnly",
	0x0101052a: "directBootAware",
	0x0101052e: "multiprocess",
}
