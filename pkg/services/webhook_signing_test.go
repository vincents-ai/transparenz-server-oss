// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSigningSecret_NonEmpty(t *testing.T) {
	secret, err := GenerateSigningSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
}

func TestGenerateSigningSecret_IsHex(t *testing.T) {
	secret, err := GenerateSigningSecret()
	require.NoError(t, err)
	// 32 random bytes encoded as hex = 64 hex chars
	assert.Len(t, secret, 64)
	for _, c := range secret {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"character %q is not a lowercase hex digit", c)
	}
}

func TestGenerateSigningSecret_Unique(t *testing.T) {
	secret1, err1 := GenerateSigningSecret()
	require.NoError(t, err1)

	secret2, err2 := GenerateSigningSecret()
	require.NoError(t, err2)

	// Two calls should produce different secrets (cryptographically random)
	assert.NotEqual(t, secret1, secret2)
}

func TestGenerateSigningSecret_CalledMultipleTimes(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		secret, err := GenerateSigningSecret()
		require.NoError(t, err)
		assert.NotEmpty(t, secret)
		assert.False(t, seen[secret], "duplicate secret generated on iteration %d", i)
		seen[secret] = true
	}
}
