//! Simple process-wide request admission control.
//!
//! The scheduler limits concurrent work with a fair Tokio semaphore. Requests
//! that arrive while every slot is occupied wait until a slot is released or
//! the configured timeout expires.

use std::{error::Error, fmt, sync::Arc, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

/// Limits how many scheduled operations may run at the same time.
#[derive(Clone, Debug)]
pub struct RequestScheduler {
    semaphore: Arc<Semaphore>,
    capacity: usize,
    wait_timeout: Duration,
}

impl RequestScheduler {
    /// Creates a scheduler with a fixed concurrency limit and queue wait time.
    ///
    /// A capacity of zero is valid and causes every acquisition to time out
    /// unless the scheduler is closed first.
    pub fn new(capacity: usize, wait_timeout: Duration) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
            wait_timeout,
        }
    }

    /// Waits for a slot and returns a guard that owns it.
    ///
    /// Tokio's semaphore queues waiters fairly. Dropping the returned guard
    /// releases its slot, including when the owning task is cancelled.
    pub async fn acquire(&self) -> Result<RateLimitGuard, RequestSchedulerError> {
        match timeout(self.wait_timeout, self.semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(RateLimitGuard { _permit: permit }),
            Ok(Err(_)) => Err(RequestSchedulerError::Closed),
            Err(_) => Err(RequestSchedulerError::TimedOut),
        }
    }

    /// Prevents future acquisitions and wakes current waiters.
    pub fn close(&self) {
        self.semaphore.close();
    }

    /// Returns the configured maximum number of concurrent operations.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of slots that can be acquired immediately.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Returns the number of slots currently held by guards.
    pub fn active_requests(&self) -> usize {
        self.capacity.saturating_sub(self.available_permits())
    }
}

/// Owns one scheduler slot and releases it automatically when dropped.
#[must_use = "dropping the rate-limit guard immediately releases its scheduler slot"]
#[derive(Debug)]
pub struct RateLimitGuard {
    _permit: OwnedSemaphorePermit,
}

/// Failure to acquire a scheduler slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestSchedulerError {
    /// The configured maximum queue wait elapsed.
    TimedOut,
    /// The scheduler was closed before a slot became available.
    Closed,
}

impl fmt::Display for RequestSchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => {
                formatter.write_str("request timed out while waiting for scheduler capacity")
            }
            Self::Closed => formatter.write_str("request scheduler is closed"),
        }
    }
}

impl Error for RequestSchedulerError {}

#[cfg(test)]
mod tests {
    use super::{RequestScheduler, RequestSchedulerError};
    use std::time::Duration;
    use tokio::time::{Instant, timeout};

    #[tokio::test]
    async fn limits_concurrency_until_a_guard_is_dropped() {
        let scheduler = RequestScheduler::new(1, Duration::from_secs(1));
        let first_guard = match scheduler.acquire().await {
            Ok(guard) => guard,
            Err(error) => panic!("first request should be admitted: {error}"),
        };
        assert_eq!(scheduler.active_requests(), 1);

        let waiting_scheduler = scheduler.clone();
        let waiting_request = tokio::spawn(async move { waiting_scheduler.acquire().await });
        tokio::task::yield_now().await;
        assert!(!waiting_request.is_finished());

        drop(first_guard);
        let second_guard = match timeout(Duration::from_millis(250), waiting_request).await {
            Ok(Ok(Ok(guard))) => guard,
            Ok(Ok(Err(error))) => panic!("waiting request was rejected: {error}"),
            Ok(Err(error)) => panic!("waiting request task failed: {error}"),
            Err(_) => panic!("waiting request did not receive the released slot"),
        };
        assert_eq!(scheduler.active_requests(), 1);

        drop(second_guard);
        assert_eq!(scheduler.available_permits(), scheduler.capacity());
    }

    #[tokio::test]
    async fn times_out_when_capacity_remains_saturated() {
        let wait_timeout = Duration::from_millis(20);
        let scheduler = RequestScheduler::new(1, wait_timeout);
        let _held_guard = match scheduler.acquire().await {
            Ok(guard) => guard,
            Err(error) => panic!("first request should be admitted: {error}"),
        };
        let started = Instant::now();

        let result = scheduler.acquire().await;

        assert!(matches!(result, Err(RequestSchedulerError::TimedOut)));
        assert!(started.elapsed() >= wait_timeout);
    }

    #[tokio::test]
    async fn closing_the_scheduler_rejects_new_requests() {
        let scheduler = RequestScheduler::new(1, Duration::from_secs(1));
        scheduler.close();

        assert!(matches!(
            scheduler.acquire().await,
            Err(RequestSchedulerError::Closed)
        ));
    }
}
