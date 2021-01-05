/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package main

var commonDefinitionsSchema = `{
    "$id": "https://intel.com/intel-secl/schemas/common.schema.json",
    "$schema": "http://json-schema.org/draft-07/schema#",
    "definitions": {
        "non_empty_string": {
            "type": "string",
            "minLength": 1
        },
        "pcr": {
            "type": "object",
            "properties": {
                "index": {
                    "$ref": "#/definitions/pcr_index"
                },
                "bank": {
                    "$ref": "#/definitions/digest_algorithm"
                }
            },
            "additionalItems": false,
            "required": [
                "index",
                "bank"
            ]
        },
        "pcr_index": {
            "type": "integer",
            "minimum": 0,
            "maximum": 23
        },
        "digest_algorithm": {
            "type": "string",
            "enum": [
                "SHA1",
                "SHA256",
                "SHA384",
                "SHA512"
            ]
        },
        "tpm_eventlog": {
            "type": "object",
            "properties": {
                "pcr": {
                    "$ref": "#/definitions/pcr"
                },
                "tpm_events": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/tpm_event"
                    }
                }
            },
            "additionalProperties": false
        },
        "tpm_event": {
            "description": "This object is used to define the data contained in a TPM event log entry.",
            "type": "object",
            "properties": {
                "type_id": {
                    "type": "number",
                    "description": "The numeric id provided in the TCG event structure."
                },
                "type_name": {
                    "type": "string",
                    "description": "The event name derived from the event's 'type_id'."
                },
                "tags": {
                    "$ref": "#/definitions/eventlog_tags"
                },
                "measurement": {
                    "description": "The measurement extended to the PCR.",
                    "$ref": "#/definitions/measurement"
                }
            },
            "required": [
                "type_id",
                "measurement"
            ],
            "additionalProperties": false
        },
        "eventlog_tags": {
            "type": "array",
            "items": {
                "$ref": "#definitions/non_empty_string"
            },
            "minItems": 1,
            "description": "One or more descriptive strings regarding the event."
        },
        "measurement": {
            "description": "Hex string value of the measurement between 20 and 64 bytes long (i.e. SHA1 thru SHA512)",
            "type": "string",
            "minLength": 40,
            "maxLength": 128
        },
        "flavor_type": {
            "type": "string",
            "enum": [
                "PLATFORM",
                "OS",
                "SOFTWARE",
                "HOST_UNIQUE",
                "ASSET_TAG"
            ]
        }
    }
}`

var flavorTemplateSchema = `{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://intel.com/intel-secl/schemas/flavor_template.schema.json",
    "title": "flavor_template",
    "type": "object",
    "properties": {
        "id": {
            "type": "string"
        },
        "label": {
            "$ref": "common.schema.json#/definitions/non_empty_string"
        },
        "condition": {
            "description": "An array of 'jsonquery' statements that are used to determine if the template should be executed.",
            "type": "array",
            "items": {
                "type": "string"
            },
            "minLength": 1
        },
        "flavor_parts": {
            "$ref": "#/definitions/flavor_template_map"
        }
    },
    "additionalItems": false,
    "required": [
        "label",
        "condition",
        "flavor_parts"
    ],
    "definitions": {
        "flavor_template_map": {
            "description": "A map of flavor_part name strings to the flavor_template objects",
            "type": "object",
            "additionalProperties": {
                "$ref": "#/definitions/flavor_template"
            }
        },
        "flavor_template": {
            "type": "object",
            "properties": {
                "meta": {
                    "description": "Arbitrary key/value pairs of meta data that will be copied to the flavor's meta/description object.",
                    "type": "object"
                },
                "pcr_rules": {
                    "description": "An array of verification rules that will be applied to a PCR.",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/pcr_rule"
                    },
                    "minItems": 1
                }
            },
            "additionalItems": false,
            "required": [
                "meta",
                "pcr_rules"
            ]
        },
        "pcr_rule": {
            "properties": {
                "pcr": {
                    "description": "The index and bank of the PCR to verify.",
                    "$ref": "common.schema.json#/definitions/pcr"
                },
                "pcr_matches": {
                    "type": "boolean"
                },
                "eventlog_equals": {
                    "description": "Identifies which events in a PCR index/bank to copy to the resulting flavor to enforce the 'PCR Event Includes' verification.",
                    "properties": {
                        "excluding_tags": {
                            "description": "A list of event tags to ignore when comparing the logs for equality.",
                            "$ref": "common.schema.json#/definitions/eventlog_tags"
                        }
                    }
                },
                "eventlog_includes": {
                    "description": "Identifies which event tags in a PCR index/bank to copy to the resulting flavor to enforce a 'PCR Event Equals' verification.",
                    "$ref": "common.schema.json#/definitions/eventlog_tags"
                }
            },
            "additionalProperties": false,
            "required": [
                "pcr"
            ],
            "not": {
                "description": "Don't allow the 'eventlog_equals' and 'eventlog_includes' in the same pcr index/bank.",
                "required": [
                    "eventlog_equals",
                    "eventlog_includes"
                ]
            }
        }
    }
}`
