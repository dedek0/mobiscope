# ADR-007: Bounded LLM retries (with router fallback and cache)

## Status

Accepted

## Context

LLM calls fail transiently: 429s, provider restarts, network blips. Triage
walks findings one at a time, so a single dropped connection should not mark a
finding inconclusive — but an unbounded retry loop would stall the batch and,
on metered providers, burn budget. Three mechanisms touch the same call path
(cache, provider routing, retries); their interaction has to be pinned by a
decision rather than by code order.

## Decision

Three cooperating policies, applied in this order to one triage finding
(internal/llm/triage.go -> `triageOne`):

1. **Cache short-circuit (ADR-003).** `CacheKey(provider, model, prompt,
   temperature=0)` is looked up first; a hit applies the stored response with
   no network call, no retry and no cost.
2. **Routing fallback (no sleep).** `Router.Route` picks a provider per
   finding: explicit task provider -> default provider -> auto-detect (local
   providers first in sorted order, cloud only if allowed and the finding is
   not `category=secret`). Policy violations (`ErrCloudNotAllowed`) are
   permanent and never retried.
3. **Retries (`withRetry`, internal/llm/retry.go)** wrap a single `Chat` call:
   - `MaxRetries` = additional attempts, default 3 (`llm.max_retries`,
     validated 0..10); 0 disables retries.
   - The nominal step is `BaseDelay << (attempt-1)` (base from
     `llm.retry_base_delay_ms`, default 500 ms) capped at `MaxDelay` = 8 s
     (hard-coded in cmd/mobiscope/analyze.go); the actual sleep is
      `step/2 + jitter` with jitter in `[0, step/4]` — i.e. 50-75 % of the
      capped step, so successive retries cannot synchronize on one instant.
   - An error implementing `RateLimitError.RetryAfter()` would replace the
     computed delay when positive — but no provider implements that interface
     today: Anthropic/Gemini only embed `retry-after <n>` in the `ErrRateLimited`
     message string, so the computed backoff is what actually runs.
   - Retryable: `ErrRateLimited`, `ErrProviderUnavailable`. Permanent
     (returned immediately): `ErrCloudNotAllowed`, `ErrAuthFailed`,
     `ErrModelNotFound`, `ErrCapabilityUnsupported`, `context.Canceled`,
     `context.DeadlineExceeded`.
   - All attempts share one deadline from `llm.timeout_seconds` (default
     60 s), created outside `withRetry`.

Failure containment: a finding whose retries are exhausted becomes
`inconclusive` with the error in `llm_explanation`; the batch continues.
Routing/policy errors are accumulated by `TriageEngine.Triage` and surface as
process exit code 4.

## Consequences

### Positive

- Worst-case wall time per finding is bounded by `timeout_seconds`, not by
  retries x timeout.
- The `Retry-After` hook is defined and unit-testable even though current
  providers do not exercise it yet; jitter avoids retry storms; permanent
  errors are never wasted on retries.
- One flaky finding cannot fail the run — it degrades to `inconclusive`.
- Repeat runs are free when the cache hits (retry logic never even starts).

### Negative

- Retries re-run the *same* provider: provider switching only happens at
  routing time for the *next* finding, so a rate-limited primary burns the
  full retry budget before the finding goes `inconclusive`.
- `MaxDelay` is hard-coded at the CLI call site; config exposes only base
  delay and timeout, so changing the cap needs a code change.
- The shared deadline means later retries can inherit only milliseconds
  (attempt 4 may effectively run once and fail on context deadline).
- Backoff is not the textbook 2^n full-delay scheme (it sleeps 50-75 % of the
  step), which surprises readers expecting `base * 2^n`.
- Server `Retry-After` hints are ignored in practice (providers stringify
  them into the error message instead of implementing `RateLimitError`).
- Cache, routing and retries compose implicitly; this ADR is the only place
  their ordering is stated.

## References

- internal/llm/retry.go (RetryConfig, withRetry, backoff, isRetryable)
- internal/llm/triage.go (per-call timeout, cache check, inconclusive fallback)
- internal/llm/router.go (fallback chain, privacy policy)
- internal/llm/cache.go (CacheKey/Get/Set — ADR-003)
- cmd/mobiscope/analyze.go (RetryConfig assembly, MaxDelay 8s)
- internal/config/config.go (max_retries, retry_base_delay_ms, timeout_seconds defaults)
- ADR-003: File-based LLM cache with TTL
