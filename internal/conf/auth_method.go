package conf

import (
	"encoding/json"
	"fmt"
)

// AuthMethod is an authentication method.
type AuthMethod int

// authentication methods.
const (
	AuthMethodInternal AuthMethod = iota
	AuthMethodHTTP
)

// MarshalJSON implements json.Marshaler.
func (d AuthMethod) MarshalJSON() ([]byte, error) {
	var out string

	switch d {
	case AuthMethodInternal:
		out = "internal"

	default:
		out = "http"
	}

	return json.Marshal(out)
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *AuthMethod) UnmarshalJSON(b []byte) error {
	var in string
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}

	switch in {
	case "internal":
		*d = AuthMethodInternal

	case "http":
		*d = AuthMethodHTTP

	default:
		return fmt.Errorf("invalid authMethod: '%s'", in)
	}

	return nil
}

// UnmarshalEnv implements env.Unmarshaler.
func (d *AuthMethod) UnmarshalEnv(_ string, v string) error {
	return d.UnmarshalJSON([]byte(`"` + v + `"`))
}
