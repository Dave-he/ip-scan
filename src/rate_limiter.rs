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
