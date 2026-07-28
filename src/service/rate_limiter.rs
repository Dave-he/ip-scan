use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Sentinel meaning "no rate limit". Stored in `max_tokens` so the hot path
/// checks once via `is_unlimited()` and then never has to refill.
pub const UNLIMITED: u64 = u64::MAX;

/// High-performance token-bucket rate limiter.
///
/// Uses lock-free atomic counters with CAS loops for both token refill
/// and consumption. The original fixed-window semaphore design caused
/// burst-then-stall behavior; this implementation refills continuously
/// at `max_rate / window_duration` per millisecond for smooth bandwidth
/// utilization.
///
/// In addition to the async `acquire()` (which parks on `tokio::time::sleep`
/// when the bucket is empty), this limiter offers two non-blocking paths:
///
/// * `try_acquire` — returns immediately with true/false.
/// * `try_acquire_batch(n)` — returns the actual count taken, useful when the
///   scanner batches multiple packets per destination and wants one
///   rate-limit decision for the whole batch.
///
/// When `max_rate == 0` (CLI converts the user-facing `--max-rate 0` to
/// `UNLIMITED`), the limiter short-circuits every check to `true` without
/// touching atomics — this is the configuration used to "run full bandwidth".
pub struct RateLimiter {
    tokens: Arc<AtomicU64>,
    refill_rate_per_ms: f64,
    last_refill_ms: Arc<AtomicU64>,
    max_tokens: u64,
    unlimited: bool,
}

impl RateLimiter {
    pub fn new(max_rate: usize, window_duration: Duration) -> Self {
        if max_rate == 0 {
            return Self::unlimited();
        }
        let max_tokens = max_rate as u64;
        let refill_rate_per_ms = max_rate as f64 / window_duration.as_millis().max(1) as f64;
        let now = now_ms();
        RateLimiter {
            tokens: Arc::new(AtomicU64::new(max_tokens)),
            refill_rate_per_ms,
            last_refill_ms: Arc::new(AtomicU64::new(now)),
            max_tokens,
            unlimited: false,
        }
    }

    /// Build an "unlimited" limiter. All acquires succeed instantly.
    pub fn unlimited() -> Self {
        RateLimiter {
            tokens: Arc::new(AtomicU64::new(u64::MAX / 2)),
            refill_rate_per_ms: 0.0,
            last_refill_ms: Arc::new(AtomicU64::new(0)),
            max_tokens: UNLIMITED,
            unlimited: true,
        }
    }

    #[inline]
    fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// Non-blocking single-token acquire. The scanner hot path uses this so
    /// a saturated limiter never parks a Tokio task on `sleep`. Misses
    /// re-queue their `(ip, port)` tuple into a buffered mpsc and the
    /// producer drains it on the next refill tick.
    #[inline]
    pub fn try_acquire(&self) -> bool {
        if self.is_unlimited() {
            return true;
        }
        self.refill_once();
        let current = self.tokens.load(Ordering::Relaxed);
        if current == 0 {
            return false;
        }
        self.tokens
            .compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Take up to `requested` tokens in one CAS loop. Used by the SYN
    /// scanner so a single 64-packet flush per destination is one limiter
    /// decision, not 64.
    #[inline]
    pub fn try_acquire_batch(&self, requested: u64) -> u64 {
        if self.is_unlimited() {
            return requested;
        }
        self.refill_once();
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return 0;
            }
            let take = current.min(requested);
            match self.tokens.compare_exchange_weak(
                current,
                current - take,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return take,
                Err(actual) => current = actual,
            }
        }
    }

    #[inline]
    pub async fn acquire(&self) {
        if self.is_unlimited() {
            return;
        }
        loop {
            if self.try_acquire() {
                return;
            }

            let wait_ms = (1.0 / self.refill_rate_per_ms.max(0.001)).max(1.0) as u64;
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
    }

    /// Refill the bucket based on elapsed millis. Uses Compare-And-Swap on
    /// `last_refill_ms` so concurrent refillers don't double-credit the
    /// elapsed window. Only the first thread to CAS `last_refill_ms`
    /// performs the actual refill; others bail out.
    #[inline]
    fn refill_once(&self) {
        let now = now_ms();
        let last = self.last_refill_ms.load(Ordering::Acquire);
        if now <= last {
            return;
        }
        let elapsed = now - last;
        let new_tokens = (elapsed as f64 * self.refill_rate_per_ms) as u64;
        if new_tokens == 0 {
            return;
        }
        // Atomically claim this refill window. Only the first thread to
        // advance last_refill_ms from `last` to `now` does the actual
        // token adjustment; concurrent callers that lose the CAS bail
        // out without double-crediting.
        if self
            .last_refill_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            let refilled = (current + new_tokens).min(self.max_tokens);
            if self
                .tokens
                .compare_exchange_weak(current, refilled, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    #[inline]
    pub fn available_tokens(&self) -> u64 {
        if self.is_unlimited() {
            return UNLIMITED;
        }
        self.refill_once();
        self.tokens.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn max_rate(&self) -> u64 {
        if self.is_unlimited() {
            return UNLIMITED;
        }
        self.max_tokens
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        RateLimiter {
            tokens: self.tokens.clone(),
            refill_rate_per_ms: self.refill_rate_per_ms,
            last_refill_ms: self.last_refill_ms.clone(),
            max_tokens: self.max_tokens,
            unlimited: self.unlimited,
        }
    }
}

#[inline]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_burst() {
        let limiter = RateLimiter::new(5, Duration::from_millis(100));
        let start = std::time::Instant::now();
        for _ in 0..5 {
            limiter.acquire().await;
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_rate_limiter_waits_for_refill() {
        let limiter = RateLimiter::new(2, Duration::from_millis(80));
        let clone = limiter.clone();
        limiter.acquire().await;
        clone.acquire().await;

        let start = std::time::Instant::now();
        limiter.acquire().await;
        assert!(start.elapsed() >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_rate_limiter_smooth_refill() {
        let limiter = RateLimiter::new(100, Duration::from_millis(100));
        for _ in 0..100 {
            limiter.acquire().await;
        }
        let start = std::time::Instant::now();
        for _ in 0..50 {
            limiter.acquire().await;
        }
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(40));
        assert!(elapsed <= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_rate_limiter_clone_shares_budget() {
        let limiter = RateLimiter::new(10, Duration::from_millis(100));
        let clone = limiter.clone();

        for _ in 0..10 {
            limiter.acquire().await;
        }
        assert_eq!(clone.available_tokens(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_refill_no_lost_updates() {
        // 1000 tokens at 1 token/ms. Consume all, then verify that
        // concurrent refills produce the correct total without lost updates.
        let limiter = RateLimiter::new(1000, Duration::from_millis(1000));
        // Drain all tokens
        for _ in 0..1000 {
            limiter.acquire().await;
        }
        assert_eq!(limiter.available_tokens(), 0);

        // Spawn many concurrent tasks that should all be able to acquire
        // tokens after refill without losing updates.
        let clone = limiter.clone();
        let start = std::time::Instant::now();
        let mut handles = Vec::new();
        for _ in 0..10 {
            let c = clone.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..10 {
                    c.acquire().await;
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // Should have acquired 100 tokens total, taking ~100ms at 1 token/ms
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(80));
    }

    #[test]
    fn test_try_acquire_does_not_block() {
        let limiter = RateLimiter::new(4, Duration::from_secs(1));
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        // After the bucket is drained, try_acquire returns false immediately
        // and the call returns in <50ms — no Tokio sleep.
        let start = std::time::Instant::now();
        assert!(!limiter.try_acquire());
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn test_try_acquire_batch_returns_min() {
        let limiter = RateLimiter::new(8, Duration::from_secs(1));
        assert_eq!(limiter.try_acquire_batch(64), 8);
        assert_eq!(limiter.try_acquire_batch(64), 0);
    }

    #[test]
    fn test_unlimited_limiter_never_blocks() {
        let limiter = RateLimiter::unlimited();
        for _ in 0..10_000 {
            assert!(limiter.try_acquire());
        }
        assert_eq!(limiter.try_acquire_batch(1_000_000), 1_000_000);
    }

    #[test]
    fn test_zero_max_rate_is_treated_as_unlimited() {
        let limiter = RateLimiter::new(0, Duration::from_secs(1));
        assert!(limiter.try_acquire());
        assert_eq!(limiter.max_rate(), UNLIMITED);
    }
}