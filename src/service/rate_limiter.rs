use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    max_rate: usize,
    window_duration: Duration,
    last_reset_ms: AtomicU64,
}

impl RateLimiter {
    pub fn new(max_rate: usize, window_duration: Duration) -> Self {
        RateLimiter {
            semaphore: Arc::new(Semaphore::new(max_rate)),
            max_rate,
            window_duration,
            last_reset_ms: AtomicU64::new(now_ms()),
        }
    }

    pub async fn acquire(&self) {
        let now = now_ms();
        let last = self.last_reset_ms.load(Ordering::Relaxed);
        let window_ms = self.window_duration.as_millis() as u64;

        if now.saturating_sub(last) >= window_ms {
            if self
                .last_reset_ms
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let current = self.semaphore.available_permits();
                if current < self.max_rate {
                    self.semaphore.add_permits(self.max_rate - current);
                }
            }
        }

        let _ = self.semaphore.acquire().await;
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        RateLimiter {
            semaphore: self.semaphore.clone(),
            max_rate: self.max_rate,
            window_duration: self.window_duration,
            last_reset_ms: AtomicU64::new(self.last_reset_ms.load(Ordering::Relaxed)),
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
}
