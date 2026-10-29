package llmtypes

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RateLimitError is implemented by errors that carry a server-suggested wait.
// The retry layer honours the wait instead of guessing a backoff.
type RateLimitError interface {
	error
	RetryAfter() time.Duration
}

// RetryAfterError wraps an error with the wait the server asked for.
type RetryAfterError struct {
	Err  error
	Wait time.Duration
}

func (e *RetryAfterError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("rate limited, retry after %s", e.Wait)
	}
	return e.Err.Error()
}

func (e *RetryAfterError) Unwrap() error { return e.Err }

// RetryAfter returns the wait the server asked for.
func (e *RetryAfterError) RetryAfter() time.Duration { return e.Wait }

// WithRetryAfter attaches a server-suggested wait to an error.
func WithRetryAfter(err error, wait time.Duration) error {
	if err == nil {
		return nil
	}
	return &RetryAfterError{Err: err, Wait: wait}
}

// RateLimited builds a rate-limit error that carries the Retry-After hint
// the server sent, so the retry layer can honour it.
func RateLimited(retryAfter, message string) error {
	wait := ParseRetryAfter(retryAfter)
	msg := strings.TrimSpace(message)

	hint := strings.TrimSpace(retryAfter)
	if hint == "" {
		hint = wait.String()
	}
	switch {
	case msg == "" && hint == "":
		msg = "rate limited"
	case msg == "":
		msg = "rate limited, retry after " + hint
	case hint == "":
		msg = "rate limited: " + msg
	default:
		msg = fmt.Sprintf("rate limited (retry after %s): %s", hint, msg)
	}

	err := fmt.Errorf("%w: %s", ErrRateLimited, msg)
	if wait > 0 {
		return &RetryAfterError{Err: err, Wait: wait}
	}
	return err
}

// ParseRetryAfter reads a Retry-After header value. It accepts both the
// delay-seconds and the HTTP-date forms.
func ParseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := time.Parse(time.RFC1123, value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

// AsRateLimitError extracts the retry hint from an error, if it carries one.
func AsRateLimitError(err error) (RateLimitError, bool) {
	var rl RateLimitError
	if errors.As(err, &rl) {
		return rl, true
	}
	return nil, false
}
