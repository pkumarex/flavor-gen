/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"crypto/sha512"
	"encoding/json"
	"log"
	"strings"
	"time"

	model "github.com/flavor-gen/models"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// getLabelFromDetails generates a flavor label string by combining the details
//from separate fields into a single string separated by underscore
func getLabelFromDetails(names ...string) string {
	log.Println("flavor_signing:getLabelFromDetails() Entering")
	defer log.Println("flavor_signing:getLabelFromDetails() Leaving")

	var labels []string
	for _, name := range names {
		labels = append(labels, strings.Join(strings.Fields(name), ""))
	}
	return strings.Join(labels, "_")
}

// getCurrentTimeStamp generates the current time in the required format
func getCurrentTimeStamp() string {
	log.Println("flavor_signing:getCurrentTimeStamp() Entering")
	defer log.Println("flavor_signing:getCurrentTimeStamp() Leaving")

	// Use magical reference date to specify the format
	return time.Now().Format("2006-01-02T15:04:05.999999-07:00")
}

//getFlavorDigest to get digest for flavor
func getFlavorDigest(flavor *model.Flavor) ([]byte, error) {
	log.Println("flavor_signing:getFlavorDigest() Entering")
	defer log.Println("flavor_signing:getFlavorDigest() Leaving")
	// Account for a differences in properties set at runtime
	tempFlavor := *flavor
	tempFlavor.Meta.ID = uuid.Nil

	flavorJSON, err := json.Marshal(tempFlavor)
	if err != nil {
		return nil, errors.Wrap(err, "flavor_signing:getFlavorDigest() An error occurred attempting to convert the flavor to json")
	}

	if flavorJSON == nil || len(flavorJSON) == 0 {
		return nil, errors.New("flavor_signing:getFlavorDigest() The flavor json was not provided")
	}

	hashEntity := sha512.New384()
	_, err = hashEntity.Write(flavorJSON)
	if err != nil {
		return nil, errors.Wrap(err, "flavor_signing:getFlavorDigest() Error creating flavor digest")
	}

	return hashEntity.Sum(nil), nil
}
