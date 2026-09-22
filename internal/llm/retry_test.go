package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func retryLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestWithRetry_SucceedsFirstTry(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), DefaultRetryConfig(), retryLogger(), "op", func() error {
		calls++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestWithRetry_RetriesThenSucceeds(t *testing.T) {
	calls := 0
	cfg := RetryConfig{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
	err := withRetry(context.Background(), cfg, retryLogger(), "op", func() error {
		calls++
		if calls < 3 {
			return fmt.Errorf("%w: temp", llmtypes.ErrRateLimited)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestWithRetry_DoesNotRetryPermanent(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), DefaultRetryConfig(), retryLogger(), "op", func() error {
		calls++
		return fmt.Errorf("%w: blocked", llmtypes.ErrCloudNotAllowed)
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls)
	assert.True(t, errors.Is(err, llmtypes.ErrCloudNotAllowed))
}

func TestWithRetry_ExhaustsRetries(t *testing.T) {
	calls := 0
	cfg := RetryConfig{MaxRetries: 2, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}
	err := withRetry(context.Background(), cfg, retryLogger(), "op", func() error {
		calls++
		return fmt.Errorf("%w: down", llmtypes.ErrProviderUnavailable)
	})
	require.Error(t, err)
	assert.Equal(t, 3, calls) // 1 + 2 retries
	assert.Contains(t, err.Error(), "failed after 2 retries")
}

func TestWithRetry_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	cfg := RetryConfig{MaxRetries: 5, BaseDelay: time.Hour, MaxDelay: time.Hour}
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	err := withRetry(ctx, cfg, retryLogger(), "op", func() error {
		calls++
		return fmt.Errorf("%w: temp", llmtypes.ErrRateLimited)
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls)
}

func TestIsRetryable(t *testing.T) {
	assert.True(t, isRetryable(fmt.Errorf("%w", llmtypes.ErrRateLimited)))
	assert.True(t, isRetryable(fmt.Errorf("%w", llmtypes.ErrProviderUnavailable)))
	assert.False(t, isRetryable(fmt.Errorf("%w", llmtypes.ErrAuthFailed)))
	assert.False(t, isRetryable(fmt.Errorf("%w", llmtypes.ErrCloudNotAllowed)))
	assert.False(t, isRetryable(fmt.Errorf("%w", llmtypes.ErrModelNotFound)))
	assert.False(t, isRetryable(nil))
}

func TestBackoff(t *testing.T) {
	d1 := backoff(time.Millisecond, time.Second, 1)
	assert.Greater(t, d1, time.Duration(0))
	assert.LessOrEqual(t, d1, time.Millisecond)

	dBig := backoff(time.Second, 2*time.Second, 10)
	assert.LessOrEqual(t, dBig, 2*time.Second)
}
