/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"github.com/google/uuid"
)

type FlavorPartTypes string
type Vendor int

const (
	FlavorPartPlatform   FlavorPartTypes = "PLATFORM"
	FlavorPartOs         FlavorPartTypes = "OS"
	FlavorPartHostUnique FlavorPartTypes = "HOST_UNIQUE"
)

const (
	VendorIntel string = "INTEL"
)

// Feature encapsulates the presence of various Platform security features on the Host hardware
type Feature struct {
	AES_NI *AES_NI      `json:"AES_NI,omitempty"`
	TXT    *TXT         `json:"TXT,omitempty"`
	TPM    *FeatureTPM  `json:"TPM,omitempty"`
	CBNT   *FeatureCBNT `json:"CBNT,omitempty"`
	SUEFI  *SUEFI       `json:"SUEFI,omitempty"`
}
type Hardware struct {
	Vendor         string   `json:"vendor,omitempty"`
	ProcessorInfo  string   `json:"processor_info,omitempty"`
	ProcessorFlags string   `json:"processor_flags,omitempty"`
	Feature        *Feature `json:"feature,omitempty"`
}

type Schema struct {
	Uri string `json:"uri,omitempty"`
}

type Meta struct {
	Schema      *Schema                `json:"schema,omitempty"`
	ID          uuid.UUID              `json:"id"`
	Realm       string                 `json:"realm,omitempty"`
	Description map[string]interface{} `json:"description,omitempty"`
	Vendor      string                 `json:"vendor,omitempty"`
}

type Bios struct {
	BiosName    string `json:"bios_name"`
	BiosVersion string `json:"bios_version"`
}

// CBNT
type FeatureCBNT struct {
	Enabled bool   `json:"enabled,omitempty"`
	Profile string `json:"profile,omitempty"`
}

// TPM
type FeatureTPM struct {
	Enabled  bool     `json:"enabled"`
	Version  string   `json:"version,omitempty"`
	PcrBanks []string `json:"pcr_banks,omitempty"`
}

// TPM
type cm_TPM struct {
	Enabled  bool     `json:"enabled"`
	Version  string   `json:"version,omitempty"`
	PcrBanks []string `json:"pcr_banks,omitempty"`
}

// AES_NI
type AES_NI struct {
	Enabled bool `json:"enabled,omitempty"`
}

// SUEFI
type SUEFI struct {
	Enabled bool `json:"enabled,omitempty"`
}

// SignedFlavorCollection is a list of SignedFlavor objects
type SignedFlavorCollection struct {
	SignedFlavors []SignedFlavor `json:"signed_flavors"`
}

// SignedFlavor combines the Flavor along with the cryptographically signed hash that authenticates its source
type SignedFlavor struct {
	Flavor    Flavor `json:"flavor`
	Signature string `json:"signature"`
}

type Flavor struct {
	// Meta section is mandatory for all Flavor types
	Meta Meta  `json:"meta"`
	Bios *Bios `json:"bios,omitempty"`
	// Hardware section is unique to Platform Flavor type
	Hardware *Hardware `json:"hardware,omitempty"`
	Pcrs     []PCRS    `json:"pcr_logs,omitempty"`
}

type PCRS struct {
	PCR              PCR                `json:"pcr"`         //required
	Measurement      string             `json:"measurement"` //required
	PCRMatches       bool               `json:"pcr_matches,omitempty"`
	EventlogEqual    *EventLogEqual     `json:"eventlog_equals,omitempty"`
	EventlogIncludes []EventLogCreteria `json:"eventlog_includes,omitempty"`
}
type EventLogEqual struct {
	Events      []EventLogCreteria `json:"events"`
	ExcludeTags []string           `json:"exclude_tags"`
}

type FlavorUtil struct {
	HostManifest    *HostManifest `json:"host_manifest"`
	HostInfo        *HostInfo     `json:"host_info"`
	FlavorTemplates *[]FlavorTemplate
}
