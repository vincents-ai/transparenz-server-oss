// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

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
