package main

import (
	"testing"

	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/stretchr/testify/assert"
)

func TestClassifyExit_OK(t *testing.T) {
	assert.Equal(t, ExitOK, classifyExit(nil))
}

func TestClassifyExit_CloudBlocked(t *testing.T) {
	assert.Equal(t, ExitProviderBlocked, classifyExit(llm.ErrCloudNotAllowed))
}

func TestClassifyExit_ProviderUnavailable(t *testing.T) {
	assert.Equal(t, ExitProviderBlocked, classifyExit(llm.ErrProviderUnavailable))
}

func TestClassifyExit_GenericError(t *testing.T) {
	assert.Equal(t, ExitError, classifyExit(assert.AnError))
}

func TestFormatSize_Bytes(t *testing.T) {
	assert.Equal(t, "512 B", formatSize(512))
}

func TestFormatSize_KB(t *testing.T) {
	assert.Equal(t, "1.0 KB", formatSize(1024))
}

func TestFormatSize_MB(t *testing.T) {
	assert.Equal(t, "1.0 MB", formatSize(1048576))
}

func TestFormatSize_GB(t *testing.T) {
	assert.Equal(t, "1.0 GB", formatSize(1073741824))
}

func TestFormatSize_Zero(t *testing.T) {
	assert.Equal(t, "-", formatSize(0))
}

func TestExitCodes(t *testing.T) {
	assert.Equal(t, 0, ExitOK)
	assert.Equal(t, 1, ExitError)
	assert.Equal(t, 4, ExitProviderBlocked)
}
