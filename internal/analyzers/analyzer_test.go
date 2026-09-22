package analyzers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCommandRunner_RejectsUnknownBinary(t *testing.T) {
	r := &DefaultCommandRunner{}
	_, err := r.Run(context.Background(), "/bin/ls", nil, 0, nil)
	require.ErrorIs(t, err, ErrBinaryNotAllowed)
}

func TestIsAllowedBinary(t *testing.T) {
	assert.True(t, isAllowedBinary("jadx"))
	assert.True(t, isAllowedBinary("/usr/local/bin/gitleaks"))
	assert.False(t, isAllowedBinary("curl"))
	assert.False(t, isAllowedBinary("/bin/sh"))
}
