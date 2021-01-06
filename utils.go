/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	model "github.com/flavor-gen/models"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	Source          = "source"
	Label           = "label"
	IPAddress       = "ip_address"
	BiosName        = "bios_name"
	BiosVersion     = "bios_version"
	OsName          = "os_name"
	OsVersion       = "os_version"
	VmmName         = "vmm_name"
	VmmVersion      = "vmm_version"
	TpmVersion      = "tpm_version"
	HardwareUUID    = "hardware_uuid"
	Comment         = "comment"
	TbootInstalled  = "tboot_installed"
	DigestAlgorithm = "digest_algorithm"
)
const (
	SHA1    model.SHAAlgorithm = "SHA1"
	SHA256  model.SHAAlgorithm = "SHA256"
	SHA384  model.SHAAlgorithm = "SHA384"
	SHA512  model.SHAAlgorithm = "SHA512"
	UNKNOWN model.SHAAlgorithm = "unknown"
)

type PcrManifest model.PcrManifest

// GetPcrEventLog based on pcrbank and index
func (pcrManifest PcrManifest) GetPcrEventLog(pcrBank model.SHAAlgorithm, pcrIndex model.PcrIndex) (*[]model.EventLogCreteria, error) {
	log.Println("utils:GetPcrEventLog() Entering")
	defer log.Println("utils:GetPcrEventLog() Leaving")

	pIndex := int(pcrIndex)
	if pcrBank == "SHA1" {
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha1EventLogs {
			if eventLogEntry.Pcr.PcrIndex == pIndex {
				return &eventLogEntry.EventLogs, nil
			}
		}
	} else if pcrBank == "SHA256" {
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha256EventLogs {
			if eventLogEntry.Pcr.PcrIndex == pIndex {
				return &eventLogEntry.EventLogs, nil
			}
		}
	} else {
		return nil, fmt.Errorf("utils:GetPcrEventLog() Unsupported sha algorithm %s", pcrBank)
	}
	return nil, fmt.Errorf("utils:GetPcrEventLog() Invalid PcrIndex %d", pcrIndex)
}

// GetPcrValue based on pcrbank and index
func (pcrManifest PcrManifest) GetPcrValue(pcrBank model.SHAAlgorithm, pcrIndex model.PcrIndex) (*model.Pcr, error) {
	log.Println("utils:GetPcrValue() Entering")
	defer log.Println("utils:GetPcrValue() Leaving")

	var pcrValue *model.Pcr

	if pcrBank == SHA1 {
		for _, pcr := range pcrManifest.Sha1Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	} else if pcrBank == SHA256 {
		for _, pcr := range pcrManifest.Sha256Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	} else {
		return nil, fmt.Errorf("utils:GetPcrValue() Unsupported sha algorithm %s", pcrBank)
	}

	return pcrValue, nil
}

// GetPcrDetails extracts Pcr values and Event Logs from the HostManifest/PcrManifest and returns
// in a format suitable for inserting into the flavor
func GetPcrDetails(pcrManifest PcrManifest, pcrList map[model.PCR]model.PcrListRules, includeEventLog bool) ([]model.PCRS, error) {
	log.Println("utils:GetPcrDetails() Entering")
	defer log.Println("utils:GetPcrDetails() Leaving")

	var pcrCollection []model.PCRS

	// Pull out the logs for the required PCRs from both banks
	for pcr, rules := range pcrList {

		pIndex := model.PcrIndex(pcr.Index)
		var pcrInfo *model.Pcr
		pcrInfo, err := pcrManifest.GetPcrValue(model.SHAAlgorithm(pcr.Bank), pIndex)
		if err != nil {
			return nil, errors.Wrap(err, "utils:GetPcrDetails() Error in getting pcrInfo")
		}

		log.Println("utils:GetPcrDetails() pcrInfo Index-> ", pcrInfo.Index)

		if pcrInfo != nil {

			var currPcrEx model.PCRS

			currPcrEx.PCR.Index = pcr.Index
			currPcrEx.PCR.Bank = pcr.Bank
			currPcrEx.Measurement = pcrInfo.Value
			currPcrEx.PCRMatches = true

			// Populate Value
			// Event logs if allowed
			if includeEventLog {
				var eventLogEqualEvents []model.EventLogCreteria
				manifestPcrEventLogs, err := pcrManifest.GetPcrEventLog(model.SHAAlgorithm(pcr.Bank), pIndex)

				// Check if returned logset from PCR is nil
				if manifestPcrEventLogs != nil && err == nil {

					// Convert EventLog to flavor format
					for _, manifestEventLog := range *manifestPcrEventLogs {

						if len(manifestEventLog.Tags) == 0 {
							if rules.PcrEquals.IsPcrEquals {
								eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
							}
						}
						for _, tag := range manifestEventLog.Tags {
							if _, ok := rules.PcrIncludes[tag]; ok {
								currPcrEx.EventlogIncludes = append(currPcrEx.EventlogIncludes, manifestEventLog)
							} else if rules.PcrEquals.IsPcrEquals {
								if _, ok := rules.PcrEquals.ExcludingTags[tag]; !ok {
									eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
								}
							}
						}
					}
					if rules.PcrEquals.IsPcrEquals {
						var EventLogExcludes []string
						for excludeTag, _ := range rules.PcrEquals.ExcludingTags {
							EventLogExcludes = append(EventLogExcludes, excludeTag)
						}
						currPcrEx.EventlogEqual = &model.EventLogEqual{
							Events:      eventLogEqualEvents,
							ExcludeTags: EventLogExcludes,
						}
					}
				}
			}

			pcrCollection = append(pcrCollection, currPcrEx)
		}
	}
	// Return map for flavor to use
	return pcrCollection, nil
}

// GetMetaSectionDetails returns the Meta instance from the HostManifest
func GetMetaSectionDetails(hostDetails *model.HostInfo, xmlMeasurement string, flavorPartName model.FlavorPartTypes, vendor string) (*model.Meta, error) {
	log.Println("utils:GetMetaSectionDetails() Entering")
	defer log.Println("utils:GetMetaSectionDetails() Leaving")

	var meta model.Meta
	// Set UUID
	meta.ID = uuid.New()
	meta.Vendor = vendor

	var biosName string
	var biosVersion string
	var osName string
	var osVersion string
	var vmmName string
	var vmmVersion string

	// Set Description
	var description = make(map[string]interface{})

	if hostDetails != nil {
		biosName = strings.TrimSpace(hostDetails.BiosName)
		biosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		description[TbootInstalled] = &hostDetails.TbootInstalled
		vmmName = strings.TrimSpace(hostDetails.VMMName)
		vmmVersion = strings.TrimSpace(hostDetails.VMMVersion)
		osName = strings.TrimSpace(hostDetails.OSName)
		osVersion = strings.TrimSpace(hostDetails.OSVersion)
		description[TpmVersion] = strings.TrimSpace(hostDetails.HardwareFeatures.TPM.Meta.TPMVersion)
	}

	switch flavorPartName {
	case model.FlavorPartPlatform:

		var features = getSupportedHardwareFeatures(hostDetails)
		description[Label] = getLabelFromDetails(meta.Vendor, biosName,
			biosVersion, strings.Join(features, "_"), getCurrentTimeStamp())
		description[BiosName] = biosName
		description[BiosVersion] = biosVersion
		description["flavor_part"] = flavorPartName
		if hostDetails != nil && hostDetails.HostName != "" {
			description[Source] = strings.TrimSpace(hostDetails.HostName)
		}
	case model.FlavorPartOs:
		description[Label] = getLabelFromDetails(meta.Vendor, osName, osVersion,
			vmmName, vmmVersion, getCurrentTimeStamp())
		description[OsName] = osName
		description[OsVersion] = osVersion
		description["flavor_part"] = flavorPartName
		if hostDetails != nil && hostDetails.HostName != "" {
			description[Source] = strings.TrimSpace(hostDetails.HostName)
		}
		if vmmName != "" {
			description[VmmName] = strings.TrimSpace(vmmName)
		}
		if vmmVersion != "" {
			description[VmmVersion] = strings.TrimSpace(vmmVersion)
		}

	case model.FlavorPartHostUnique:
		if hostDetails != nil {
			if hostDetails.HostName != "" {
				description[Source] = strings.TrimSpace(hostDetails.HostName)
			}
			hwuuid, err := uuid.Parse(hostDetails.HardwareUUID)
			if err != nil {
				return nil, errors.Wrap(err, "utils:GetMetaSectionDetails() Error in parsing hardware uuid")
			}
			description[HardwareUUID] = hwuuid.String()
		}
		description[BiosName] = biosName
		description[BiosVersion] = biosVersion
		description[OsName] = osName
		description[OsVersion] = osVersion
		description["flavor_part"] = flavorPartName
		description[Label] = getLabelFromDetails(meta.Vendor, description[HardwareUUID].(string), getCurrentTimeStamp())
	default:
		return nil, nil
	}
	meta.Description = description

	return &meta, nil
}

// getSupportedHardwareFeatures returns a list of hardware features supported by the host from its HostInfo
func getSupportedHardwareFeatures(hostDetails *model.HostInfo) []string {
	log.Println("utils:getSupportedHardwareFeatures() Entering")
	defer log.Println("utils:getSupportedHardwareFeatures() Leaving")

	tpm := "TPM"
	txt := "TXT"
	cbnt := "CBNT"
	suefi := "SUEFI"

	var features []string
	if hostDetails.HardwareFeatures.CBNT != nil && hostDetails.HardwareFeatures.CBNT.Enabled {
		features = append(features, cbnt)
		features = append(features, hostDetails.HardwareFeatures.CBNT.Meta.Profile)
	}

	if hostDetails.HardwareFeatures.TPM.Enabled {
		features = append(features, tpm)
	}

	if hostDetails.HardwareFeatures.TXT != nil && hostDetails.HardwareFeatures.TXT.Enabled {
		features = append(features, txt)
	}

	if hostDetails.HardwareFeatures.UEFI != nil && hostDetails.HardwareFeatures.UEFI.Enabled {
		features = append(features, suefi)
	}

	return features
}

//getPCRListAndRules to get Pcr list and its rules
func getPCRListAndRules(flavorPart *model.FlavorPart, pcrList map[model.PCR]model.PcrListRules) map[model.PCR]model.PcrListRules {
	log.Println("utils:getPCRListAndRules() Entering")
	defer log.Println("utils:getPCRListAndRules() Leaving")

	if flavorPart == nil {
		return pcrList
	}

	if pcrList == nil {
		pcrList = make(map[model.PCR]model.PcrListRules)
	}

	for _, pcrRule := range flavorPart.PcrRules {
		var rulesList model.PcrListRules

		if rules, ok := pcrList[pcrRule.Pcr]; ok {
			rulesList = rules
		}

		if pcrRule.PcrMatches != nil && *pcrRule.PcrMatches {
			rulesList.PcrMatches = true
		}

		if pcrRule.EventlogEquals != nil {

			rulesList.PcrEquals.IsPcrEquals = true

			if pcrRule.EventlogEquals.ExculdingTags != nil {
				rulesList.PcrEquals.ExcludingTags = make(map[string]bool)
				for _, tags := range pcrRule.EventlogEquals.ExculdingTags {
					if _, ok := rulesList.PcrEquals.ExcludingTags[tags]; !ok {
						rulesList.PcrEquals.ExcludingTags[tags] = false
					}
				}
			}
		}

		if pcrRule.EventlogIncludes != nil {
			rulesList.PcrIncludes = make(map[string]bool)

			for _, tags := range *pcrRule.EventlogIncludes {
				if _, ok := rulesList.PcrIncludes[tags]; !ok {
					rulesList.PcrIncludes[tags] = true
				}

			}
		}
		pcrList[pcrRule.Pcr] = rulesList
	}
	log.Println("utils:getPCRListAndRules() pcrList ended ", pcrList)
	return pcrList
}

// getPcrList Helper function to calculate the list of PCRs for the flavor part specified based
// on the version of the TPM hardware.
func getPcrList(flavorPart model.FlavorPartTypes, flavorTemplates *[]model.FlavorTemplate) ([]int, map[model.PCR]model.PcrListRules) {
	log.Println("utils:getPcrList() Entering")
	defer log.Println("utils:getPcrList() Leaving")

	var pcrSet = make(map[int]bool)
	var pcrs []int

	pcrListAndRules := make(map[model.PCR]model.PcrListRules)
	for _, flavorTemplate := range *flavorTemplates {

		switch flavorPart {
		case model.FlavorPartPlatform:
			pcrListAndRules = getPCRListAndRules(flavorTemplate.FlavorParts.Platform, pcrListAndRules)

		case model.FlavorPartOs:
			pcrListAndRules = getPCRListAndRules(flavorTemplate.FlavorParts.OS, pcrListAndRules)

		case model.FlavorPartHostUnique:
			pcrListAndRules = getPCRListAndRules(flavorTemplate.FlavorParts.HostUnique, pcrListAndRules)

		}
	}

	// Convert set back to list
	for pcr := range pcrSet {
		pcrs = append(pcrs, pcr)
	}
	return pcrs, pcrListAndRules
}

//GetBiosSectionDetails method to fill bios section details
func GetBiosSectionDetails(hostDetails *model.HostInfo) *model.Bios {
	log.Println("utils:GetBiosSectionDetails() Entering")
	defer log.Println("utils:GetBiosSectionDetails() Leaving")

	var bios model.Bios
	if hostDetails != nil {
		bios.BiosName = strings.TrimSpace(hostDetails.BiosName)
		bios.BiosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		return &bios
	}
	return nil
}

//UpdateMetaSectionDetails method to fill metasection details
func UpdateMetaSectionDetails(flavorPart model.FlavorPartTypes, newMeta *model.Meta, flavorTemplates *[]model.FlavorTemplate) *model.Meta {
	log.Println("utils:UpdateMetaSectionDetails() Entering")
	defer log.Println("utils:UpdateMetaSectionDetails() Leaving")

	var flavorTemplateID []uuid.UUID

	for _, flavorTemplate := range *flavorTemplates {
		flavorTemplateID = append(flavorTemplateID, flavorTemplate.ID)

		var flavor *model.FlavorPart

		switch flavorPart {
		case model.FlavorPartPlatform:
			flavor = flavorTemplate.FlavorParts.Platform
		case model.FlavorPartOs:
			flavor = flavorTemplate.FlavorParts.OS
		case model.FlavorPartHostUnique:
			flavor = flavorTemplate.FlavorParts.HostUnique
		}

		if flavor != nil {
			newMeta.Description["flavor_template_ids"] = flavorTemplateID
			for key, value := range flavor.Meta {
				newMeta.Description[key] = value
			}
		}
	}
	return newMeta
}

// GetHardwareSectionDetails extracts the host Hardware details from the manifest
func GetHardwareSectionDetails(hostInfo *model.HostInfo) *model.Hardware {
	log.Println("utils:GetHardwareSectionDetails() Entering")
	defer log.Println("utils:GetHardwareSectionDetails() Leaving")

	var hardware model.Hardware
	var feature model.Feature

	if hostInfo != nil {
		// Extract Processor Info
		hardware.ProcessorInfo = strings.TrimSpace(hostInfo.ProcessorInfo)
		hardware.ProcessorFlags = strings.TrimSpace(hostInfo.ProcessorFlags)

		// Set TPM Feature presence
		tpm := model.FeatureTPM{}
		tpm.Enabled = hostInfo.HardwareFeatures.TPM.Enabled
		tpm.Version = hostInfo.HardwareFeatures.TPM.Meta.TPMVersion
		// Split into list
		tpm.PcrBanks = strings.Split(hostInfo.HardwareFeatures.TPM.Meta.PCRBanks, "_")
		feature.TPM = &tpm

		txt := model.TXT{}
		if hostInfo.HardwareFeatures.TXT != nil {
			// Set TXT Feature presence
			txt.Enabled = hostInfo.HardwareFeatures.TXT.Enabled
			feature.TXT = &txt
		}

		cbnt := model.FeatureCBNT{}
		// Set CBNT
		if hostInfo.HardwareFeatures.CBNT != nil {
			cbnt.Enabled = hostInfo.HardwareFeatures.CBNT.Enabled
			cbnt.Profile = hostInfo.HardwareFeatures.CBNT.Meta.Profile
			feature.CBNT = &cbnt
		}

		suefi := model.SUEFI{}
		// Set SUEFI state
		if hostInfo.HardwareFeatures.UEFI != nil {
			suefi.Enabled = hostInfo.HardwareFeatures.UEFI.Enabled
			feature.SUEFI = &suefi
		}

		hardware.Feature = &feature
	}
	return &hardware
}

// GetSignedFlavor is used to sign the flavor
func GetSignedFlavor(unsignedFlavor *model.Flavor, privateKey *rsa.PrivateKey) (*model.SignedFlavor, error) {
	log.Println("utils:GetSignedFlavor() Entering")
	defer log.Println("utils:GetSignedFlavor() Leaving")

	if unsignedFlavor == nil {
		return nil, errors.New("utils:GetSignedFlavor: Flavor content missing")
	}

	signedFlavor, err := NewSignedFlavor(unsignedFlavor, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "utils:GetSignedFlavor: Error while creating signed flavor")
	}

	return signedFlavor, nil
}

// GetSignedFlavorList performs a bulk signing of a list of flavor strings and returns a list of SignedFlavors
func GetSignedFlavorList(flavors []model.Flavor, flavorSigningPrivateKey *rsa.PrivateKey) ([]model.SignedFlavor, error) {
	log.Println("utils:GetSignedFlavorList() Entering")
	defer log.Println("utils:GetSignedFlavorList() Leaving")

	var signedFlavors []model.SignedFlavor

	if flavors != nil {
		// Loop through and sign each flavor
		for _, unsignedFlavor := range flavors {
			var sf *model.SignedFlavor

			sf, err := GetSignedFlavor(&unsignedFlavor, flavorSigningPrivateKey)
			if err != nil {
				return nil, errors.Errorf("utils:GetSignedFlavorList() Error signing flavor collection: %s", err.Error())
			}

			signedFlavors = append(signedFlavors, *sf)
		}
	} else {
		return nil, errors.Errorf("utils:GetSignedFlavorList() Empty flavors list provided")
	}
	return signedFlavors, nil
}

// NewSignedFlavor Provided an existing flavor and a privatekey, create a SignedFlavor
func NewSignedFlavor(flavor *model.Flavor, privateKey *rsa.PrivateKey) (*model.SignedFlavor, error) {
	log.Println("utils:NewSignedFlavor() Entering")
	defer log.Println("utils:NewSignedFlavor() Leaving")

	if flavor == nil {
		return nil, errors.New("utils:NewSignedFlavor() The Flavor must be provided and cannot be nil")
	}

	if privateKey == nil || privateKey.Validate() != nil {
		return nil, errors.New("utils:NewSignedFlavor() Valid private key must be provided and cannot be nil")
	}

	flavorDigest, err := getFlavorDigest(flavor)
	if err != nil {
		return nil, errors.Wrap(err, "utils:NewSignedFlavor() An error occurred while getting flavor digest")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, flavorDigest)
	if err != nil {
		return nil, errors.Wrap(err, "utils:NewSignedFlavor() An error occurred while signing the flavor")
	}

	return &model.SignedFlavor{
		Flavor:    *flavor,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}
