/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/google/uuid"

type FlavorTemplate struct {
	ID          uuid.UUID   `json:"id,omitempty" gorm:"primary_key;type:uuid"`
	Label       string      `json:"label"`
	Condition   []string    `json:"condition" sql:"type:text[]"`
	FlavorParts FlavorParts `json:"flavor_parts,omitempty" sql:"type:JSONB"`
}

// swagger:parameters FlavorParts
type FlavorParts struct {
	Platform   *FlavorPart `json:"PLATFORM,omitempty"`
	OS         *FlavorPart `json:"OS,omitempty"`
	Software   *FlavorPart `json:"SOFTWARE,omitempty"`
	HostUnique *FlavorPart `json:"HOST_UNIQUE,omitempty"`
	AssetTag   *FlavorPart `json:"ASSET_TAG,omitempty"`
}

// swagger:parameters FlavorPart
type FlavorPart struct {
	Meta     map[string]interface{} `json:"meta,omitempty"`
	PcrRules []PcrRules             `json:"pcr_rules"`
}

type PcrRules struct {
	Pcr              PCR             `json:"pcr"`
	PcrMatches       *bool           `json:"pcr_matches,omitempty"`
	EventlogEquals   *EventLogEquals `json:"eventlog_equals,omitempty"`
	EventlogIncludes *[]string       `json:"eventlog_includes,omitempty"`
}

//PCR- Tp stpre PCR index with respective PCR bank.
type PCR struct {
	Index int    `json:"index"`
	Bank  string `json:"bank"`
}

//EventLogEquals - To store event log need be equal with specified PCR.
type EventLogEquals struct {
	ExculdingTags []string `json:"excluding_tags,omitempty"`
}

type PcrListRules struct {
	PcrMatches  bool
	PcrEquals   PcrEquals
	PcrIncludes map[string]bool
}

type PcrEquals struct {
	IsPcrEquals   bool
	ExcludingTags map[string]bool
}
