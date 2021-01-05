/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	PCR_INDEX_PREFIX = "pcr_"
)
const (
	PCR0 PcrIndex = iota
	PCR1
	PCR2
	PCR3
	PCR4
	PCR5
	PCR6
	PCR7
	PCR8
	PCR9
	PCR10
	PCR11
	PCR12
	PCR13
	PCR14
	PCR15
	PCR16
	PCR17
	PCR18
	PCR19
	PCR20
	PCR21
	PCR22
	PCR23
	INVALID_INDEX = -1
)

type SHAAlgorithm string
type PcrIndex int

type HostManifest struct {
	AIKCertificate        string      `json:"aik_certificate,omitempty"`
	AssetTagDigest        string      `json:"asset_tag_digest,omitempty"`
	HostInfo              HostInfo    `json:"host_info"`
	PcrManifest           PcrManifest `json:"pcr_manifest"`
	BindingKeyCertificate string      `json:"binding_key_certificate,omitempty"`
	MeasurementXmls       []string    `json:"measurement_xmls,omitempty"`
}

type HostInfo struct {
	OSName              string           `json:"os_name"`
	OSVersion           string           `json:"os_version"`
	BiosVersion         string           `json:"bios_version"`
	VMMName             string           `json:"vmm_name"`
	VMMVersion          string           `json:"vmm_version"`
	ProcessorInfo       string           `json:"processor_info"`
	HostName            string           `json:"host_name"`
	BiosName            string           `json:"bios_name"`
	HardwareUUID        string           `json:"hardware_uuid"`
	ProcessorFlags      string           `json:"process_flags,omitempty"`
	NumberOfSockets     int              `json:"no_of_sockets,string,omitempty"`
	TbootInstalled      bool             `json:"tboot_installed,string,omitempty"`
	IsDockerEnvironment bool             `json:"is_docker_env,string,omitempty"`
	HardwareFeatures    HardwareFeatures `json:"hardware_features"`
	InstalledComponents []string         `json:"installed_components"`
}

type HardwareFeatures struct {
	TXT  *HardwareFeature `json:"TXT"`
	TPM  *TPM             `json:"TPM,omitempty"`
	CBNT *CBNT            `json:"CBNT,omitempty"`
	UEFI *UEFI            `json:"UEFI,omitempty"`
}

type CBNT struct {
	HardwareFeature
	Meta struct {
		Profile string `json:"profile"`
		MSR     string `json:"msr"`
	} `json:"meta"`
}

type HardwareFeature struct {
	Enabled bool `json:"enabled,string"`
}

// TXT
type TXT struct {
	Enabled bool `json:"enabled"`
}
type TPM struct {
	Enabled bool `json:"enabled,string"`
	Meta    struct {
		TPMVersion string `json:"tpm_version,omitempty"`
		PCRBanks   string `json:"pcr_banks,omitempty"`
	} `json:"meta"`
}
type UEFI struct {
	HardwareFeature
	Meta struct {
		SecureBootEnabled bool `json:"secure_boot_enabled,omitempty"`
	} `json:"meta"`
}

type PcrManifest struct {
	Sha1Pcrs       []Pcr             `json:"sha1pcrs"`
	Sha256Pcrs     []Pcr             `json:"sha2pcrs"`
	PcrEventLogMap NewPcrEventLogMap `json:"pcr_event_log_map"`
}

type NewPcr struct {
	PcrIndex int          `json:"index"`
	PcrBank  SHAAlgorithm `json:"bank"`
}

type NewEventLogEntry struct {
	Pcr       NewPcr             `json:"pcr"`
	EventLogs []EventLogCreteria `json:"tpm_events"`
}

type NewPcrEventLogMap struct {
	Sha1EventLogs   []NewEventLogEntry `json:"SHA1"`
	Sha256EventLogs []NewEventLogEntry `json:"SHA256"`
}
type Pcr struct {
	DigestType string       `json:"digest_type"`
	Index      PcrIndex     `json:"index"`
	Value      string       `json:"value"`
	PcrBank    SHAAlgorithm `json:"pcr_bank"`
}
type EventLogCreteria struct {
	TypeID      string   `json:"type_id"`        //oneof-required
	TypeName    string   `json:"type_name"`      //oneof-required
	Tags        []string `json:"tags,omitempty"` //oneof-required
	Measurement string   `json:"measurement"`    //required
}

// String returns the string representation of the PcrIndex
func (pcrIndex PcrIndex) String() string {
	return fmt.Sprintf("pcr_%d", pcrIndex)
}

// Convert the json string value "pcr_N" to PcrIndex
func (pcrIndex *PcrIndex) UnmarshalJSON(pcrBytes []byte) error {
	var jsonValue string
	if err := json.Unmarshal(pcrBytes, &jsonValue); err != nil {
		return err
	}

	index, err := GetPcrIndexFromString(jsonValue)
	if err != nil {
		return err
	}
	*pcrIndex = index
	return err
}

// Parses a string value in either integer form (i.e. "8") or "pcr_N"
// where 'N' is the integer value between 0 and 23.  Ex. "pcr_7".  Returns
// an error if the string is not in the correct format or if the index
// value is not between 0 and 23.
func GetPcrIndexFromString(stringValue string) (PcrIndex, error) {

	intString := stringValue

	if strings.Contains(intString, PCR_INDEX_PREFIX) {
		intString = strings.ReplaceAll(stringValue, PCR_INDEX_PREFIX, "")
	}

	intValue, err := strconv.ParseInt(intString, 0, 64)
	if err != nil {
		return INVALID_INDEX, err
	}

	if intValue < int64(PCR0) || intValue > int64(PCR23) {
		return INVALID_INDEX, err
	}

	return PcrIndex(intValue), err
}
