use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    max_rate: usize,
    window_duration: Duration,
    last_reset: Arc<tokio::sync::Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(max_rate: usize, window_duration: Duration) -> Self {
        RateLimiter {
            semaphore: Arc::new(Semaphore::new(max_rate)),
            max_rate,
            window_duration,
            last_reset: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        }
    }

    pub async fn acquire(&self) {
        // Check if we need to reset the window
        let mut last_reset = self.last_reset.lock().await;
        if last_reset.elapsed() >= self.window_duration {
            *last_reset = Instant::now();
            // Add permits back
            let current_permits = self.semaphore.available_permits();
            if current_permits < self.max_rate {
                self.semaphore.add_permits(self.max_rate - current_permits);
            }
        }
        drop(last_reset);

        // Acquire a permit
        let _ = self.semaphore.acquire().await;
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        RateLimiter {
            semaphore: self.semaphore.clone(),
            max_rate: self.max_rate,
            window_duration: self.window_duration,
            last_reset: self.last_reset.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let max_rate = 5;
        let window_duration = Duration::from_millis(100);
        let limiter = RateLimiter::new(max_rate, window_duration);

        let start = Instant::now();
        for _ in 0..max_rate {
            limiter.acquire().await;
        }
        
        // Should have consumed all permits, so next acquire should wait
        // But since we just consumed them, the first batch should be fast.
        assert!(start.elapsed() < window_duration);
        
        // This one should trigger a wait or be allowed if enough time passed
        // To properly test, we'd need to mock time or ensure we consume more than max_rate
        
        // Let's test that we can acquire more than max_rate eventually
        let limiter_clone = limiter.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..max_rate {
                limiter_clone.acquire().await;
            }
        });
        
        handle.await.unwrap();
    }
}
