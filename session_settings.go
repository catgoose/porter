package porter

import (
	"encoding/json"
	"time"
)

// SessionSettings holds per-session user preferences keyed by a browser UUID
// cookie. The struct is designed to be stored in a database row; the db tags
// match the expected column names.
type SessionSettings struct {
	// SessionUUID is the unique identifier tying these settings to a browser session.
	SessionUUID string `db:"SessionUUID"`

	// Theme is the UI color scheme (e.g. "light", "dark").
	Theme string `db:"Theme"`

	// Layout is the UI layout mode (e.g. "classic", "app").
	Layout string `db:"Layout"`

	// Extra holds app-specific preferences as key-value pairs. Serializes to
	// JSON for storage. Consumers should use [SessionSettings.GetExtra] and
	// [SessionSettings.SetExtra] for safe access.
	Extra map[string]string `db:"Extra" json:"extra,omitempty"`

	// UpdatedAt tracks when the settings were last modified or touched.
	UpdatedAt time.Time `db:"UpdatedAt"`

	// ID is the database primary key.
	ID int `db:"Id"`
}

// GetExtra returns the value for key, or empty string if not set.
func (s *SessionSettings) GetExtra(key string) string {
	if s.Extra == nil {
		return ""
	}
	return s.Extra[key]
}

// SetExtra sets a key-value pair in Extra, initializing the map if nil.
func (s *SessionSettings) SetExtra(key, value string) {
	if s.Extra == nil {
		s.Extra = make(map[string]string)
	}
	s.Extra[key] = value
}

// MarshalExtra returns the Extra map serialized as a JSON string. Returns
// "{}" when Extra is nil or empty.
func (s *SessionSettings) MarshalExtra() (string, error) {
	if s.Extra == nil {
		return "{}", nil
	}
	b, err := json.Marshal(s.Extra)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalExtra populates the Extra map from a JSON string. An empty string
// or "{}" results in an initialized empty map.
func (s *SessionSettings) UnmarshalExtra(data string) error {
	if data == "" {
		s.Extra = make(map[string]string)
		return nil
	}
	m := make(map[string]string)
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return err
	}
	s.Extra = m
	return nil
}

// Default settings values and layout constants.
const (
	// DefaultTheme is the theme applied to new sessions.
	DefaultTheme = "light"

	// DefaultLayout is the layout applied to new sessions.
	DefaultLayout = "classic"

	// LayoutApp is the alternative "app" layout mode.
	LayoutApp = "app"
)

// NewDefaultSettings returns a SessionSettings with defaults for the given UUID.
func NewDefaultSettings(uuid string) *SessionSettings {
	return &SessionSettings{
		SessionUUID: uuid,
		Theme:       DefaultTheme,
		Layout:      DefaultLayout,
		Extra:       make(map[string]string),
	}
}
