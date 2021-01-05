/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"

	model "github.com/flavor-gen/models"
	"github.com/pkg/errors"
)

type FlavorUtil model.FlavorUtil

// getFlavorPartRaw extracts the details of the flavor part requested.
func (flavorUtil FlavorUtil) getFlavorPartRaw(name model.FlavorPartTypes) ([]model.Flavor, error) {
	log.Println("flavor_create:getFlavorPartRaw() Entering")
	defer log.Println("flavor_create:getFlavorPartRaw() Leaving")

	switch name {
	case model.FlavorPartPlatform:
		return flavorUtil.getPlatformFlavor()
	case model.FlavorPartOs:
		return flavorUtil.getOsFlavor()
	case model.FlavorPartHostUnique:
		return flavorUtil.getHostUniqueFlavor()
	}
	return nil, errors.New("UNKNOWN flavorpart")
}

//create the flavorpart json
func createFlavor(flavorUtil model.FlavorUtil) error {
	log.Println("flavor_create:createFlavor() Entering")
	defer log.Println("flavor_create:createFlavor() Leaving")

	var flavors []model.SignedFlavor

	flavorParts := [3]model.FlavorPartTypes{model.FlavorPartPlatform, model.FlavorPartOs, model.FlavorPartHostUnique}

	flavorSignKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return errors.Wrap(err, "flavor_create:createFlavor() Couldn't generate RSA key, failed to create flavorsinging key")
	}

	for _, flavorPart := range flavorParts {

		unSignedFlavors, err := FlavorUtil(flavorUtil).getFlavorPartRaw(flavorPart)
		if err != nil {
			return errors.Wrapf(err, "flavor_create:createFlavor() Unable to create flavor part %s", flavorPart)
		}
		signedFlavors, err := GetSignedFlavorList(unSignedFlavors, flavorSignKey)
		if err != nil {
			return errors.Wrapf(err, "flavor_create:createFlavor() Failed to create signed flavor %s", flavorPart)
		}

		flavors = append(flavors, signedFlavors...)
	}

	signedFlavorCollection := model.SignedFlavorCollection{
		SignedFlavors: flavors,
	}

	flavorJSON, err := json.Marshal(signedFlavorCollection)
	if err != nil {
		return errors.Wrapf(err, "flavor_create:createFlavor() Couldn't marshal signedflavorCollection")
	}
	flavorPartJSON := string(flavorJSON)
	fmt.Println(flavorPartJSON)
	return nil
}

// getPlatformFlavor Method to create a platform flavor. This method would create a platform flavor that would
// include all the measurements provided from host.
func (flavorUtil FlavorUtil) getPlatformFlavor() ([]model.Flavor, error) {
	log.Println("flavor_create:getPlatformFlavor() Entering")
	defer log.Println("flavor_create:getPlatformFlavor() Leaving")

	errorMessage := "Error during creation of PLATFORM flavor"
	_, platformPcrs := getPcrList(model.FlavorPartPlatform, flavorUtil.FlavorTemplates)

	allPcrDetails, err := GetPcrDetails(PcrManifest(flavorUtil.HostManifest.PcrManifest), platformPcrs, true)
	if err != nil {
		return nil, errors.Wrap(err, "flavor_create:getPlatformFlavor() Error in getting PCR details")
	}

	newMeta, err := GetMetaSectionDetails(flavorUtil.HostInfo, "", model.FlavorPartPlatform, model.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - failed to create meta section details")
	}
	log.Printf("flavor_create:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(model.FlavorPartPlatform, newMeta, flavorUtil.FlavorTemplates)
	if newMeta == nil {
		return nil, errors.New(errorMessage + " - failed to update meta section details")
	}
	log.Println("flavor_create:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newBios := GetBiosSectionDetails(flavorUtil.HostInfo)
	if newBios == nil {
		return nil, errors.New(errorMessage + " - failed to create bios section details")
	}
	log.Println("flavor_create:getPlatformFlavor() New Bios Section: %v", *newBios)

	newHW := GetHardwareSectionDetails(flavorUtil.HostInfo)
	if newHW == nil {
		return nil, errors.New(errorMessage + " - failed to create hardware section details")
	}
	log.Println("flavor_create:getPlatformFlavor() New Hardware Section: %v", *newHW)

	// Assemble the Platform Flavor
	platformFlavor := &model.Flavor{
		Meta:     *newMeta,
		Bios:     newBios,
		Hardware: newHW,
		Pcrs:     allPcrDetails,
	}

	return []model.Flavor{*platformFlavor}, nil
}

// getOsFlavor Returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the OS Trust of a host
func (flavorUtil FlavorUtil) getOsFlavor() ([]model.Flavor, error) {
	log.Println("flavor_create:getOsFlavor() Entering")
	defer log.Println("flavor_create:getOsFlavor() Leaving")

	errorMessage := "Error during creation of OS flavor"
	_, osPcrs := getPcrList(model.FlavorPartOs, flavorUtil.FlavorTemplates)

	allPcrDetails, err := GetPcrDetails(PcrManifest(flavorUtil.HostManifest.PcrManifest), osPcrs, true)
	if err != nil {
		return nil, errors.Wrap(err, "flavor_create:getOsFlavor() Error in getting PCR details")
	}

	newMeta, err := GetMetaSectionDetails(flavorUtil.HostInfo, "", model.FlavorPartOs, model.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - failure in Meta section details")
	}
	log.Println("flavor_create:getOsFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(model.FlavorPartOs, newMeta, flavorUtil.FlavorTemplates)
	if newMeta == nil {
		return nil, errors.New(errorMessage + " - failure in update Meta section details")
	}
	log.Println("flavor_create:getOsFlavor() New Meta Section: %v", *newMeta)

	newBios := GetBiosSectionDetails(flavorUtil.HostInfo)
	if newBios == nil {
		return nil, errors.New(errorMessage + " - failure in bios section details")
	}
	log.Println("flavor_create:getOsFlavor() New Bios Section: %v", *newBios)

	// Assemble the OS Flavor
	osFlavor := &model.Flavor{
		Meta:     *newMeta,
		Bios:     newBios,
		Hardware: nil,
		Pcrs:     allPcrDetails,
	}

	log.Println("flavor_create:getOsFlavor() New OS Flavor: %v", osFlavor)

	return []model.Flavor{*osFlavor}, nil
}

// getHostUniqueFlavor Returns a json document having all the good known PCR values and corresponding event logs that
// can be used for evaluating the unique part of the PCR configurations of a host. These include PCRs/modules getting
// extended to PCRs that would vary from host to host.
func (flavorUtil FlavorUtil) getHostUniqueFlavor() ([]model.Flavor, error) {
	log.Println("flavor_create:getHostUniqueFlavor() Entering")
	defer log.Println("flavor_create:getHostUniqueFlavor() Leaving")

	errorMessage := "Error during creation of Host Unique flavor"
	_, hostUniquePcrs := getPcrList(model.FlavorPartHostUnique, flavorUtil.FlavorTemplates)

	allPcrDetails, err := GetPcrDetails(PcrManifest(flavorUtil.HostManifest.PcrManifest), hostUniquePcrs, true)
	if err != nil {
		return nil, errors.Wrap(err, "flavor_create:getHostUniqueFlavor() Error in getting PCR details")
	}

	newMeta, err := GetMetaSectionDetails(flavorUtil.HostInfo, "", model.FlavorPartHostUnique, model.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" - failure in Meta section details")
	}
	log.Println("flavor_create:getHostUniqueFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(model.FlavorPartHostUnique, newMeta, flavorUtil.FlavorTemplates)
	if newMeta == nil {
		return nil, errors.New(errorMessage + " - failure in update Meta section details")
	}
	log.Println("flavor_create:getHostUniqueFlavor() New Meta Section: %v", *newMeta)

	newBios := GetBiosSectionDetails(flavorUtil.HostInfo)
	if newBios == nil {
		return nil, errors.New(errorMessage + " - failure in bios section details")
	}
	log.Println("flavor_create:getHostUniqueFlavor() New Bios Section: %v", *newBios)

	// Assemble the Host Unique Flavor
	hostUniqueFlavor := &model.Flavor{
		Meta:     *newMeta,
		Bios:     newBios,
		Hardware: nil,
		Pcrs:     allPcrDetails,
	}

	log.Println("flavor_create:getHostUniqueFlavor() New PlatformFlavor: %v", hostUniqueFlavor)

	return []model.Flavor{*hostUniqueFlavor}, nil
}
