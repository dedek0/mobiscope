package models

import "encoding/json"

// Platform identifies the mobile platform an artifact targets.
type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformUnknown Platform = "unknown"
)

func (p Platform) String() string { return string(p) }

func (p Platform) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(p))
}

func (p *Platform) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch Platform(v) {
	case PlatformAndroid, PlatformIOS, PlatformUnknown, "":
		*p = Platform(v)
		if *p == "" {
			*p = PlatformUnknown
		}
		return nil
	default:
		// Forward-compatible: keep the value rather than failing to parse.
		*p = Platform(v)
		return nil
	}
}
