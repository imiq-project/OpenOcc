package main

// EncryptionKey wraps a per-vehicle secret key. Only display/serialize paths
// redact; sql.Scanner/driver.Valuer and encoding/json unmarshal intentionally
// fall through to the default string behaviour so DB round-trips carry the
// real value and test round-trips break loudly rather than silently persisting
// "***".
//
// DO NOT implement Scan / Value / UnmarshalJSON.
type EncryptionKey string

func (k EncryptionKey) String() string               { return "***" }
func (k EncryptionKey) GoString() string             { return "EncryptionKey(***)" }
func (k EncryptionKey) MarshalJSON() ([]byte, error) { return []byte(`"***"`), nil }

// Reveal returns the raw key value. Grep for call sites.
func (k EncryptionKey) Reveal() string { return string(k) }

// GormDataType tells GORM to treat the column as a plain string.
func (EncryptionKey) GormDataType() string { return "string" }
