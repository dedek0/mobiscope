package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

// RetryConfig controls transient-failure retries for LLM calls.
type RetryConfig struct {
	// MaxRetries is the number of additional attempts after the first (0 = no retry).
	MaxRetries int
	// BaseDelay is the first backoff step; it doubles each attempt.
	BaseDelay time.Duration
	// MaxDelay caps a single backoff wait.
	MaxDelay time.Duration
}

// DefaultRetryConfig returns sensible defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 3,
		BaseDelay:  500 * time.Millisecond,
		MaxDelay:   8 * time.Second,
	}
}

// RateLimitError is implemented by errors that carry a server-suggested wait.
type RateLimitError interface {
	error
	RetryAfter() time.Duration
}

// isRetryable reports whether an LLM error is worth retrying: rate limits,
// temporary unavailability and transient network failures. Policy violations
// (cloud blocked, bad auth, unknown model) are permanent.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, llmtypes.ErrCloudNotAllowed) ||
		errors.Is(err, llmtypes.ErrAuthFailed) ||
		errors.Is(err, llmtypes.ErrModelNotFound) ||
		errors.Is(err, llmtypes.ErrCapabilityUnsupported) {
		return false
	}
	return errors.Is(err, llmtypes.ErrRateLimited) ||
		errors.Is(err, llmtypes.ErrProviderUnavailable)
}

// withRetry runs fn, retrying transient failures with exponential backoff and
// jitter. A RateLimitError's RetryAfter hint is honored when present.
func withRetry(ctx context.Context, cfg RetryConfig, logger *slog.Logger, op string, fn func() error) error {
	if cfg.MaxRetries <= 0 {
		return fn()
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 500 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 8 * time.Second
	}

	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := backoff(cfg.BaseDelay, cfg.MaxDelay, attempt)
			var rl RateLimitError
			if errors.As(lastErr, &rl) && rl.RetryAfter() > 0 {
				delay = rl.RetryAfter()
			}
			if logger != nil {
				logger.Warn("retrying llm call",
					"op", op,
					"attempt", attempt,
					"delay", delay.String(),
					"error", lastErr,
				)
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("%s cancelled during retry: %w", op, ctx.Err())
			case <-time.After(delay):
			}
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !isRetryable(lastErr) {
			return lastErr
		}
	}
	return fmt.Errorf("%s failed after %d retries: %w", op, cfg.MaxRetries, lastErr)
}

// backoff returns an exponential delay with jitter, capped at max.
func backoff(base, max time.Duration, attempt int) time.Duration {
	d := base << uint(attempt-1)
	if d > max || d <= 0 {
		d = max
	}
	jitter := time.Duration(rand.Int63n(int64(d/4) + 1)) //nolint:gosec // G404: jitter does not need crypto/rand
	return d/2 + jitter
}
