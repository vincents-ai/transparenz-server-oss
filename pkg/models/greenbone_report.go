// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package models

import "encoding/xml"

// GMPReport represents the XML structure of a Greenbone Management Protocol report.
type GMPReport struct {
	XMLName  xml.Name `xml:"report"`
	ID       string   `xml:"id,attr"`
	FormatID string   `xml:"format_id,attr"`
	Results  struct {
		ResultList []GMPResult `xml:"result"`
	} `xml:"results"`
}

// GMPResult represents a single result entry within a GMP report.
type GMPResult struct {
	ID          string `xml:"id,attr"`
	Name        string `xml:"name"`
	Host        string `xml:"host"`
	Port        string `xml:"port"`
	Severity    string `xml:"severity"`
	QoD         string `xml:"qod"`
	Description string `xml:"description"`
	NVT         struct {
		OID string `xml:"oid,attr"`
		CVE string `xml:"cve"`
	} `xml:"nvt"`
	Threat string `xml:"threat"`
}
