//! Remote binary-cache membership checks for producer-side cache generation.
//!
//! The release path uses this module to decide whether a store path can be
//! skipped before doing local closure expansion or NAR compression. The
//! conservative rule is that a narinfo is considered present only when every
//! publishing destination already has the `<hash>.narinfo` object.
//!
//! The [`CacheMembership`] trait is the seam a future bulk membership index
//! (RFC-0195) would replace: callers depend only on `narinfo(hash) -> bool`,
//! not on the per-destination `HEAD` requests [`HeadMembership`] issues today.

use anyhow::Result;
use aos_cache::backend::{self, AuthOptions, CacheBackend};
use async_trait::async_trait;
use futures_util::future::try_join_all;

/// Checks whether store-path narinfos are already visible remotely.
#[async_trait]
pub trait CacheMembership: Send + Sync {
    /// Returns whether `<store_hash>.narinfo` is present on every destination.
    ///
    /// # Errors
    ///
    /// Returns an error when a destination cannot be queried.
    async fn narinfo(&self, store_hash: &str) -> Result<bool>;
}

/// Narinfo membership backed by concurrent `HEAD` requests against upload
/// destinations.
pub struct HeadMembership {
    backends: Vec<Box<dyn CacheBackend>>,
}

impl HeadMembership {
    /// Builds a membership checker for the supplied destination URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if any destination URL cannot be resolved into a
    /// cache backend.
    pub async fn from_urls(urls: &[String], auth: &AuthOptions) -> Result<Self> {
        let mut backends = Vec::with_capacity(urls.len());
        for url in urls {
            backends.push(backend::from_url(url, auth).await?);
        }
        Ok(Self { backends })
    }

    /// Builds a membership checker from already-created backends.
    pub fn new(backends: Vec<Box<dyn CacheBackend>>) -> Self {
        Self { backends }
    }
}

#[async_trait]
impl CacheMembership for HeadMembership {
    async fn narinfo(&self, store_hash: &str) -> Result<bool> {
        if self.backends.is_empty() {
            return Ok(false);
        }
        // Probe every destination concurrently; a narinfo counts as present
        // only when all of them have it (an absence anywhere still needs the
        // upload). `try_join_all` short-circuits on transport errors only.
        let present = try_join_all(self.backends.iter().map(|b| b.has_narinfo(store_hash))).await?;
        Ok(present.iter().all(|&p| p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const HASH: &str = "abc123";

    /// Build a `file://` destination URL, touching `<HASH>.narinfo` when the
    /// destination should report the object present.
    fn dest_url(dir: &TempDir, present: bool) -> String {
        if present {
            std::fs::write(dir.path().join(format!("{HASH}.narinfo")), b"narinfo").unwrap();
        }
        format!("file://{}", dir.path().display())
    }

    #[tokio::test]
    async fn present_only_when_every_destination_has_the_narinfo() {
        let (a, b, c, d) = (
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
        );

        let all_present = HeadMembership::from_urls(
            &[dest_url(&a, true), dest_url(&b, true)],
            &AuthOptions::default(),
        )
        .await
        .unwrap();
        assert!(all_present.narinfo(HASH).await.unwrap());

        let any_absent = HeadMembership::from_urls(
            &[dest_url(&c, true), dest_url(&d, false)],
            &AuthOptions::default(),
        )
        .await
        .unwrap();
        assert!(!any_absent.narinfo(HASH).await.unwrap());
    }

    #[tokio::test]
    async fn no_destinations_is_absent() {
        let empty = HeadMembership::new(Vec::new());
        assert!(!empty.narinfo(HASH).await.unwrap());
    }
}
