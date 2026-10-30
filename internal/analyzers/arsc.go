package analyzers

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// Resource table (resources.arsc) chunk types.
const (
	arscChunkTable       = 0x0002
	arscChunkPackage     = 0x0200
	arscChunkType        = 0x0201
	arscChunkTypeSpec    = 0x0202
	arscChunkStringPool  = 0x0001
	arscEntryFlagComplex = 0x0001
	arscTypeFlagSparse   = 0x01
	// arscTypeFlagOffset16 marks a type chunk whose entry offsets are
	// uint16 values stored as offset/4 (aapt2 emits this for large tables).
	arscTypeFlagOffset16 = 0x02
)

// resourceTable maps a resource id to its first string value. It is enough to
// resolve references such as @xml/network_security_config or @string/app_name
// out of an undecoded APK.
type resourceTable struct {
	values map[uint32]string
}

// resolve returns the value for a resource id.
func (t *resourceTable) resolve(id uint32) (string, bool) {
	if t == nil {
		return "", false
	}
	v, ok := t.values[id]
	return v, ok
}

// parseResourceTable decodes resources.arsc. Unsupported or corrupt entries are
// skipped; the parser never trusts a length from the file without checking it
// against the remaining buffer.
func parseResourceTable(data []byte) (*resourceTable, error) {
	if len(data) < 12 || binary.LittleEndian.Uint16(data) != arscChunkTable {
		return nil, fmt.Errorf("not a resource table")
	}
	headerSize := int(binary.LittleEndian.Uint16(data[2:]))
	tableSize := int(binary.LittleEndian.Uint32(data[4:]))
	if headerSize < 12 || headerSize > len(data) {
		return nil, fmt.Errorf("invalid resource table header size %d", headerSize)
	}
	if tableSize > len(data) {
		tableSize = len(data)
	}

	table := &resourceTable{values: map[uint32]string{}}
	var global *stringPool

	for pos := headerSize; pos+8 <= tableSize; {
		chunkType := binary.LittleEndian.Uint16(data[pos:])
		chunkHeader := int(binary.LittleEndian.Uint16(data[pos+2:]))
		chunkSize := int(binary.LittleEndian.Uint32(data[pos+4:]))
		if chunkHeader < 8 || chunkSize < chunkHeader || pos+chunkSize > tableSize {
			return table, fmt.Errorf("invalid resource chunk at offset %d", pos)
		}
		chunk := data[pos : pos+chunkSize]

		switch chunkType {
		case arscChunkStringPool:
			pool, err := parseStringPool(chunk)
			if err == nil {
				global = pool
			}
		case arscChunkPackage:
			parsePackageChunk(chunk, global, table)
		}
		pos += chunkSize
	}
	return table, nil
}

// parsePackageChunk walks one ResTable_package and records the string values of
// its types.
func parsePackageChunk(chunk []byte, global *stringPool, table *resourceTable) {
	if len(chunk) < 12 {
		return
	}
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:]))
	packageID := uint32(chunk[8])
	if headerSize < 12 || headerSize > len(chunk) {
		return
	}

	// typeStrings and keyStrings are offsets relative to the package chunk.
	for pos := headerSize; pos+8 <= len(chunk); {
		chunkType := binary.LittleEndian.Uint16(chunk[pos:])
		chunkHeader := int(binary.LittleEndian.Uint16(chunk[pos+2:]))
		chunkSize := int(binary.LittleEndian.Uint32(chunk[pos+4:]))
		if chunkHeader < 8 || chunkSize < chunkHeader || pos+chunkSize > len(chunk) {
			return
		}
		if chunkType == arscChunkType {
			parseTypeChunk(chunk[pos:pos+chunkSize], packageID, global, table)
		}
		pos += chunkSize
	}
}

// parseTypeChunk decodes one ResTable_type chunk.
func parseTypeChunk(chunk []byte, packageID uint32, global *stringPool, table *resourceTable) {
	// ResTable_type: header (8), id (1), flags (1), reserved (2),
	// entryCount (4), entriesStart (4), config (variable).
	if len(chunk) < 20 {
		return
	}
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:]))
	typeID := uint32(chunk[8])
	flags := chunk[9]
	entryCount := int(binary.LittleEndian.Uint32(chunk[12:]))
	entriesStart := int(binary.LittleEndian.Uint32(chunk[16:]))
	if headerSize < 20 || headerSize > len(chunk) || typeID == 0 {
		return
	}
	if entryCount < 0 || entryCount > 1<<20 {
		return
	}

	if flags&arscTypeFlagSparse != 0 {
		// ResTable_sparseTypeEntry: idx (2), offset/4 (2).
		for i := 0; i < entryCount; i++ {
			off := headerSize + i*4
			if off+4 > len(chunk) {
				return
			}
			idx := uint32(binary.LittleEndian.Uint16(chunk[off:]))
			entryOff := int(binary.LittleEndian.Uint16(chunk[off+2:])) * 4
			recordResourceValue(chunk, entriesStart+entryOff, packageID, typeID, idx, global, table)
		}
		return
	}

	if flags&arscTypeFlagOffset16 != 0 {
		for i := 0; i < entryCount; i++ {
			off := headerSize + i*2
			if off+2 > len(chunk) {
				return
			}
			entryOff := int(binary.LittleEndian.Uint16(chunk[off:])) * 4
			if entryOff == 0xffff*4 {
				continue
			}
			recordResourceValue(chunk, entriesStart+entryOff, packageID, typeID, uint32(i), global, table)
		}
		return
	}

	for i := 0; i < entryCount; i++ {
		off := headerSize + i*4
		if off+4 > len(chunk) {
			return
		}
		entryOff := int(binary.LittleEndian.Uint32(chunk[off:]))
		if entryOff == -1 {
			continue
		}
		recordResourceValue(chunk, entriesStart+entryOff, packageID, typeID, uint32(i), global, table)
	}
}

// recordResourceValue stores the value of one ResTable_entry when it is a
// string. Complex entries (bags) are skipped.
func recordResourceValue(chunk []byte, pos int, packageID, typeID, entryIndex uint32, global *stringPool, table *resourceTable) {
	if pos < 0 || pos+8 > len(chunk) {
		return
	}
	entrySize := int(binary.LittleEndian.Uint16(chunk[pos:]))
	entryFlags := binary.LittleEndian.Uint16(chunk[pos+2:])
	if entryFlags&arscEntryFlagComplex != 0 {
		return
	}
	valuePos := pos + entrySize
	if valuePos < pos || valuePos+8 > len(chunk) {
		return
	}
	dataType := chunk[valuePos+3]
	data := binary.LittleEndian.Uint32(chunk[valuePos+4:])

	var value string
	switch dataType {
	case axmlTypeString:
		value = global.at(data)
	case axmlTypeIntBool:
		if data != 0 {
			value = boolTrue
		} else {
			value = "false"
		}
	case axmlTypeIntDec, axmlTypeIntHex:
		value = strconv.FormatUint(uint64(data), 10)
	}
	if value == "" {
		return
	}

	id := packageID<<24 | typeID<<16 | entryIndex
	if _, exists := table.values[id]; !exists {
		table.values[id] = value
	}
}
