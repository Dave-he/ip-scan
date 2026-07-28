use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Token-bucket rate limiter with lock-free hot path.
///
/// `max_rate` tokens are added every `window_secs`. When `max_rate == 0` the
/// limiter is effectively unlimited and the acquire path becomes a single
/// relaxed load (no CAS, no atomics on the hot loop).
pub struct RateLimiter {
    /// Current number of tokens in the bucket (CAS-updated).
    tokens: AtomicU64,
    /// Maximum capacity of the bucket (`max_rate` when non-zero).
    capacity: u64,
    /// Tokens added per refill interval (`max_rate` when non-zero).
    refill_amount: u64,
    /// Interval between refills stored as milliseconds.
    refill_interval_ms: u64,
    /// Last refill timestamp (ms since UNIX epoch).
    last_refill_ms: AtomicU64,
    /// True when max_rate == 0 (no-op limiter).
    unlimited: bool,
}

impl RateLimiter {
    /// Build a new rate limiter.
    ///
    /// When `max_rate == 0` the limiter runs in unlimited mode: every
    /// acquire returns immediately without touching the atomics.
    pub fn new(max_rate: usize, window_duration: Duration) -> Self {
        if max_rate == 0 {
            return RateLimiter {
                tokens: AtomicU64::new(0),
                capacity: 0,
                refill_amount: 0,
                refill_interval_ms: 0,
                last_refill_ms: AtomicU64::new(0),
                unlimited: true,
            };
        }

        let capacity = max_rate as u64;
        let now = now_ms();
        RateLimiter {
            tokens: AtomicU64::new(capacity),
            capacity,
            refill_amount: capacity,
            refill_interval_ms: window_duration.as_millis() as u64,
            last_refill_ms: AtomicU64::new(now),
            unlimited: false,
        }
    }

    /// Returns true when this limiter has no rate cap.
    #[inline]
    pub fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// Single-token acquire (async, back-pressure aware).
    #[inline]
    pub async fn acquire(&self) {
        if self.unlimited {
            return;
        }
        loop {
            match self.try_acquire(1) {
                0 => {
                    // No token available right now, yield to let other
                    // progress happen before retrying. Refilling is cheap
                    // and lock-free so we don't need a timer.
                    tokio::task::yield_now().await;
                }
                _ => return,
            }
        }
    }

    /// Try to acquire up to `requested` tokens without blocking.
    /// Returns how many tokens were actually acquired.
    #[inline]
    pub fn try_acquire(&self, requested: u64) -> u64 {
        if self.unlimited {
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

    /// Non-blocking bulk acquisition. Returns the number of tokens taken.
    ///
    /// This is the preferred API for packet dispatch loops because it
    /// amortizes the CAS cost across multiple ports and lets the caller
    /// emit packets back-to-back without per-port synchronization.
    #[inline]
    pub fn try_acquire_batch(&self, requested: u64) -> u64 {
        if self.unlimited {
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

    /// Refill tokens based on elapsed time. Idempotent: multiple concurrent
    /// callers may race but the CAS inside ensures only one performs the
    /// actual top-up.
    #[inline]
    fn refill_once(&self) {
        let now = now_ms();
        let last = self.last_refill_ms.load(Ordering::Relaxed);
        let interval = self.refill_interval_ms;
        if interval == 0 {
            return;
        }
        let elapsed = now.saturating_sub(last);
        if elapsed < interval {
            return;
        }
        // Attempt to claim the refill slot. Losers still observe the new
        // token count on their next load.
        if self
            .last_refill_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // Add tokens; saturating add prevents overflow across very long runs.
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            let new = (current + self.refill_amount).min(self.capacity);
            match self.tokens.compare_exchange_weak(
                current,
                new,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        RateLimiter {
            tokens: AtomicU64::new(self.tokens.load(Ordering::Relaxed)),
            capacity: self.capacity,
            refill_amount: self.refill_amount,
            refill_interval_ms: self.refill_interval_ms,
            last_refill_ms: AtomicU64::new(self.last_refill_ms.load(Ordering::Relaxed)),
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
    async fn test_rate_limiter_unlimited() {
        let limiter = RateLimiter::new(0, Duration::from_secs(1));
        assert!(limiter.is_unlimited());
        assert_eq!(limiter.try_acquire(1_000_000), 1_000_000);
        limiter.acquire().await;
    }

    #[tokio::test]
    async fn test_rate_limiter_burst() {
        let limiter = RateLimiter::new(5, Duration::from_millis(100));
        let start = std::time::Instant::now();
        for _ in 0..5 {
            limiter.acquire().await;
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn test_rate_limiter_batch() {
        let limiter = RateLimiter::new(10, Duration::from_millis(100));
        let got = limiter.try_acquire_batch(3);
        assert_eq!(got, 3);
        let got = limiter.try_acquire_batch(10);
        assert_eq!(got, 7);
        let got = limiter.try_acquire_batch(1);
        assert_eq!(got, 0);
    }
}
