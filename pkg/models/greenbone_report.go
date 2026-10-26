// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
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
