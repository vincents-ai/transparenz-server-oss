// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

// Package jsonutil provides a drop-in replacement for encoding/json
// using jsoniter for ~2x faster serialization/deserialization.
//
// Usage:
//
//	import jsonutil "github.com/vincents-ai/transparenz-server-oss/pkg/util/jsonutil"
//
//	jsonutil.Marshal(v)
//	jsonutil.Unmarshal(data, v)
package jsonutil

import jsoniter "github.com/json-iterator/go"

var (
	// Marshal is a drop-in for json.Marshal.
	Marshal = jsoniter.ConfigCompatibleWithStandardLibrary.Marshal

	// Unmarshal is a drop-in for json.Unmarshal.
	Unmarshal = jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal

	// API is the jsoniter API instance (compatible with encoding/json).
	API = jsoniter.ConfigCompatibleWithStandardLibrary
)
