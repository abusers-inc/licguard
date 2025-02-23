package net

import (
	"encoding/json"
	"time"
)

type License struct {
	expiration_date *time.Time
	extra_data      *json.RawMessage
}

type LicenseKey string

type AdminClient interface {
	CreateLicense(License) (License, *error)
	ExtendLicense(LicenseKey, time.Time) *error
	RevokeLicense(LicenseKey) *error
}
