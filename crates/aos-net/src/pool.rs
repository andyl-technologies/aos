//! Per-domain connection pool manager.
//!
//! Manages concurrent connections per host and globally using
//! Tokio semaphores. Each acquired permit is a RAII guard that
//! releases the semaphore slot on drop.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Configuration for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum concurrent connections per host.
    pub max_connections_per_host: usize,
    /// Maximum total concurrent connections across all hosts.
    pub max_total_connections: usize,
    /// How long idle connections are kept alive.
    pub idle_timeout: Duration,
    /// Timeout for establishing new connections.
    pub connect_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 8,
            max_total_connections: 64,
            idle_timeout: Duration::from_secs(90),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Statistics about the connection pool.
///
/// A point-in-time snapshot returned by [`ConnectionPool::stats`].
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Number of active connections per host.
    pub per_host: BTreeMap<String, usize>,
    /// Total number of active connections.
    pub total_active: usize,
    /// Maximum connections configured per host.
    pub max_per_host: usize,
    /// Maximum total connections configured.
    pub max_total: usize,
}

/// A RAII permit that represents an active connection slot.
///
/// When dropped, the connection slot is released back to both the
/// per-host and global semaphores.
pub struct PoolPermit {
    _host_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
    host: String,
    active_counts: Arc<Mutex<BTreeMap<String, usize>>>,
}

impl Drop for PoolPermit {
    fn drop(&mut self) {
        let mut counts = self.active_counts.lock().unwrap();
        if let Some(count) = counts.get_mut(&self.host) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.host);
            }
        }
    }
}

/// Connection pool manager.
///
/// Controls concurrency by limiting the number of simultaneous
/// connections per host and globally. Uses Tokio semaphores for
/// async-friendly blocking.
pub struct ConnectionPool {
    config: PoolConfig,
    global_semaphore: Arc<Semaphore>,
    host_semaphores: Mutex<BTreeMap<String, Arc<Semaphore>>>,
    active_counts: Arc<Mutex<BTreeMap<String, usize>>>,
}

impl ConnectionPool {
    /// Create a new connection pool with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            global_semaphore: Arc::new(Semaphore::new(config.max_total_connections)),
            host_semaphores: Mutex::new(BTreeMap::new()),
            active_counts: Arc::new(Mutex::new(BTreeMap::new())),
            config,
        }
    }

    /// Acquire a permit to connect to a host.
    ///
    /// This will block (async) if the per-host or global connection
    /// limit has been reached. The returned [`PoolPermit`] releases
    /// the slot when dropped. The global permit is always acquired
    /// before the per-host permit so that all callers take locks in a
    /// consistent order.
    ///
    /// # Panics
    ///
    /// Panics if an internal semaphore has been closed. The pool never
    /// closes its semaphores, so this cannot happen in normal use.
    pub async fn acquire(&self, host: &str) -> PoolPermit {
        // Get or create the per-host semaphore.
        let host_sem = {
            let mut sems = self.host_semaphores.lock().unwrap();
            sems.entry(host.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(self.config.max_connections_per_host)))
                .clone()
        };

        // Acquire both permits (global first to prevent deadlock with
        // consistent ordering).
        let global_permit = self
            .global_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("global semaphore closed");

        let host_permit = host_sem
            .acquire_owned()
            .await
            .expect("host semaphore closed");

        // Track active count.
        {
            let mut counts = self.active_counts.lock().unwrap();
            *counts.entry(host.to_string()).or_insert(0) += 1;
        }

        PoolPermit {
            _host_permit: host_permit,
            _global_permit: global_permit,
            host: host.to_string(),
            active_counts: Arc::clone(&self.active_counts),
        }
    }

    /// Get current pool statistics.
    pub fn stats(&self) -> PoolStats {
        let counts = self.active_counts.lock().unwrap();
        let total: usize = counts.values().sum();

        PoolStats {
            per_host: counts.clone(),
            total_active: total,
            max_per_host: self.config.max_connections_per_host,
            max_total: self.config.max_total_connections,
        }
    }

    /// Get the pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }
}

impl std::fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPool")
            .field("config", &self.config)
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_acquire_and_release() {
        let pool = ConnectionPool::new(PoolConfig::default());

        let stats = pool.stats();
        assert_eq!(stats.total_active, 0);

        {
            let _permit = pool.acquire("example.com").await;
            let stats = pool.stats();
            assert_eq!(stats.total_active, 1);
            assert_eq!(stats.per_host.get("example.com"), Some(&1));
        }

        // After drop, counts should be back to 0.
        let stats = pool.stats();
        assert_eq!(stats.total_active, 0);
    }

    #[tokio::test]
    async fn test_per_host_limits() {
        let config = PoolConfig {
            max_connections_per_host: 2,
            max_total_connections: 10,
            ..Default::default()
        };
        let pool = Arc::new(ConnectionPool::new(config));

        let _p1 = pool.acquire("a.com").await;
        let _p2 = pool.acquire("a.com").await;

        // Third acquire for same host would block. Instead, verify
        // we can acquire for a different host.
        let _p3 = pool.acquire("b.com").await;

        let stats = pool.stats();
        assert_eq!(stats.per_host.get("a.com"), Some(&2));
        assert_eq!(stats.per_host.get("b.com"), Some(&1));
        assert_eq!(stats.total_active, 3);
    }

    #[tokio::test]
    async fn test_multiple_hosts() {
        let pool = ConnectionPool::new(PoolConfig::default());

        let _p1 = pool.acquire("host1.com").await;
        let _p2 = pool.acquire("host2.com").await;
        let _p3 = pool.acquire("host3.com").await;

        let stats = pool.stats();
        assert_eq!(stats.total_active, 3);
        assert_eq!(stats.per_host.len(), 3);
    }

    #[test]
    fn test_default_config() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_host, 8);
        assert_eq!(config.max_total_connections, 64);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
    }
}
