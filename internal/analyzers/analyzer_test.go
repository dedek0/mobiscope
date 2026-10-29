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
	assert.True(t, isAllowedBinary("gitleaks"))
	assert.False(t, isAllowedBinary("curl"))
	assert.False(t, isAllowedBinary("/bin/sh"))
	// A path that merely shares an allowed base name is not accepted: the
	// runner only executes bare names resolved through PATH.
	assert.False(t, isAllowedBinary("/usr/local/bin/gitleaks"))
	assert.False(t, isAllowedBinary("./gitleaks"))
	assert.False(t, isAllowedBinary(""))
}

func TestResolveAllowedBinary_RejectsPath(t *testing.T) {
	_, err := resolveAllowedBinary("/bin/ls")
	require.ErrorIs(t, err, ErrBinaryNotAllowed)
}

func TestParseVersionOutput(t *testing.T) {
	assert.Equal(t, "apktool 2.9.3", parseVersionOutput([]byte("apktool 2.9.3\nbuilt from source\n")))
	assert.Equal(t, "unknown", parseVersionOutput([]byte("")))
	assert.Equal(t, "unknown", parseVersionOutput([]byte("\n\n")))
}
