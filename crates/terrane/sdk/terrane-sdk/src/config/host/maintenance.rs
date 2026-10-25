//! Parses bounded GC-to-serve reconciliation endpoints without opening sockets.
//!
//! ```toml
//! [host_tier.maintenance]
//! gc_uid = 843
//! max_connections = 8
//! max_requests = 1
//! connection_timeout_ms = 30000
//! request_timeout_ms = 30000
//! [host_tier.maintenance.sockets]
//! public = "/run/terrane-maintenance/public.sock"
//! ```

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;

use super::HostTier;
use crate::config::ConfigError;

/// Selects finite authenticated reconciliation against original serving owners.
///
/// Every configured native domain has funded surface admission and its own
/// explicit protected socket. These
/// inputs select transport resources, never cache rows, descriptors or closure
/// evidence. The serve identity comes from the same host's publisher binding.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maintenance {
    /// Distinct effective UID permitted to request reconciliation.
    pub gc_uid: u32,
    /// Maximum active connections per domain, from one through 1024.
    pub max_connections: usize,
    /// Maximum successful requests per connection, from one through 4096.
    pub max_requests: usize,
    /// Whole connection lifetime, from one through 300000 milliseconds.
    pub connection_timeout_ms: u64,
    /// Whole GC-pass and request deadline, no longer than the connection lifetime.
    pub request_timeout_ms: u64,
    /// Exact domain-to-socket mapping, covering all native host domains.
    pub sockets: BTreeMap<String, String>,
}

impl Maintenance {
    /// Checks complete domain coverage, role separation and finite transport bounds.
    ///
    /// Performs no filesystem, credential, socket or process operations. Native
    /// startup independently authenticates every protected parent and peer.
    ///
    /// # Errors
    /// Rejects absent publisher identity, colliding role identities, incomplete
    /// or unfunded native domains, invalid limits, duplicate or noncanonical paths,
    /// and sockets overlapping native storage or other control endpoints.
    pub fn validate(&self, host: &HostTier) -> Result<(), ConfigError> {
        let publisher = host.publisher.as_ref().ok_or(ConfigError::Invalid(
            "host maintenance requires explicit serving identity",
        ))?;
        publisher.validate()?;
        if self.gc_uid == u32::MAX
            || self.gc_uid == publisher.serve_uid
            || self.gc_uid == publisher.publish_uid
            || !(1..=1024).contains(&self.max_connections)
            || !(1..=4096).contains(&self.max_requests)
            || !(1..=300_000).contains(&self.connection_timeout_ms)
            || !(1..=self.connection_timeout_ms).contains(&self.request_timeout_ms)
            || !(1..=256).contains(&self.sockets.len())
            || self.sockets.keys().ne(host.domains.keys())
            || host.domains.values().any(|domain| {
                domain
                    .cache
                    .as_ref()
                    .is_none_or(|cache| cache.surface_index.is_none())
            })
        {
            return Err(ConfigError::Invalid(
                "host maintenance requires bounded funded native domains and distinct roles",
            ));
        }

        let mut paths = std::collections::BTreeSet::new();
        for socket in self.sockets.values() {
            let path = Path::new(socket);
            if !canonical_socket(socket)
                || paths
                    .iter()
                    .any(|other: &&String| overlaps(path, Path::new(other)))
                || overlaps(path, Path::new(&host.path))
                || overlaps(path, Path::new(&publisher.socket_path))
                || host
                    .quota
                    .as_ref()
                    .is_some_and(|quota| overlaps(path, Path::new(&quota.socket_path)))
                || host.domains.values().any(|domain| {
                    overlaps(path, Path::new(&domain.path))
                        || domain
                            .administrative_root
                            .as_ref()
                            .is_some_and(|root| overlaps(path, Path::new(root)))
                })
            {
                return Err(ConfigError::Invalid(
                    "host maintenance requires disjoint canonical socket paths",
                ));
            }
            paths.insert(socket);
        }
        Ok(())
    }
}

fn canonical_socket(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 107
        && !path.contains('\0')
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
