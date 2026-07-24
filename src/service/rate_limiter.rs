use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    max_rate: usize,
    window_duration: Duration,
    last_reset_ms: Arc<AtomicU64>,
}

impl RateLimiter {
    pub fn new(max_rate: usize, window_duration: Duration) -> Self {
        RateLimiter {
            semaphore: Arc::new(Semaphore::new(max_rate)),
            max_rate,
            window_duration,
            last_reset_ms: Arc::new(AtomicU64::new(now_ms())),
        }
    }

    pub async fn acquire(&self) {
        let window_ms = (self.window_duration.as_millis() as u64).max(1);
        loop {
            let now = now_ms();
            let last = self.last_reset_ms.load(Ordering::Acquire);

            if now.saturating_sub(last) >= window_ms
                && self
                    .last_reset_ms
                    .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                let current = self.semaphore.available_permits();
                if current < self.max_rate {
                    self.semaphore.add_permits(self.max_rate - current);
                }
            }

            if let Ok(permit) = self.semaphore.try_acquire() {
                // A token must stay consumed until the next fixed-window refill.
                // Dropping the permit would return it immediately and silently
                // disable rate limiting.
                permit.forget();
                return;
            }

            let last = self.last_reset_ms.load(Ordering::Acquire);
            let wait_ms = last
                .saturating_add(window_ms)
                .saturating_sub(now_ms())
                .max(1);
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        RateLimiter {
            semaphore: self.semaphore.clone(),
            max_rate: self.max_rate,
            window_duration: self.window_duration,
            last_reset_ms: self.last_reset_ms.clone(),
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
    async fn test_rate_limiter_waits_for_next_window_and_shares_clone_budget() {
        let limiter = RateLimiter::new(2, Duration::from_millis(80));
        let clone = limiter.clone();
        limiter.acquire().await;
        clone.acquire().await;

        let start = std::time::Instant::now();
        limiter.acquire().await;
        assert!(start.elapsed() >= Duration::from_millis(60));
    }
}
