//! Validates trusted native-owner settings before opening mutable resources.

use crate::publisher_local::client::ClientConfig;
use std::{io, os::unix::ffi::OsStrExt, path::PathBuf};
use terrane::host::cache::{
    CachePolicy, HostDomainLocation, HostReadLimits, PolicyConfig, StateLimits,
};
use terrane_core::chunking::ChunkProfile;

/// Supplies fixed host configuration for one physical cache command owner.
///
/// These settings are not quota, seal, recovery or confinement receipts. Native
/// startup must validate them before opening mutable state, then bind actual
/// authenticated helper observations to the retained configured directories.
pub struct NativeCacheOwnerConfig {
    /// Physical domain root and registered chunk profile, without guest authority.
    pub location: HostDomainLocation,
    /// Explicit additional charged scaffold, when the operator configures one.
    pub administrative_root: Option<PathBuf>,
    /// Authenticated publisher endpoint and fixed role identities.
    pub publisher: ClientConfig,
    /// Protected host-owned quota query endpoint.
    pub quota_socket: PathBuf,
    /// Expected host quota configuration epoch.
    pub quota_epoch: [u8; 16],
    /// Exact charge owner selected in the host helper's fixed partition.
    pub quota_owner: String,
    /// Host-ledger filesystem UUID expected from the authenticated query.
    pub filesystem_uuid: [u8; 16],
    /// Fixed nonzero project assignment for the entire domain owner.
    pub project_id: u32,
    /// Exact configured project hard limit, independently of current usage.
    pub project_hard_limit_bytes: u64,
    /// Exact configured inode hard limit; zero means no inode-specific ceiling.
    pub project_hard_inode_limit: u64,
    /// UID owning ordinary encoded content; it must equal the serving role.
    pub content_uid: u32,
    /// Shared content GID used by serving, collection and publication roles.
    pub content_gid: u32,
    /// Private cache-state GID, excluding the publisher.
    pub state_gid: u32,
    /// Expected finite budget for the helper's entire configured partition.
    pub tier_charge_budget_bytes: u64,
    /// Finite eviction and future-capacity policy.
    pub policy: PolicyConfig,
    /// Operator allocation budget for encoded reads.
    pub reads: HostReadLimits,
    /// Maximum durable policy snapshot size and record count.
    pub state: StateLimits,
    /// Maximum retained entries in one complete native recovery inventory.
    pub inventory_entries: usize,
    /// Maximum queued commands, excluding the physically executing command.
    pub queued_commands: usize,
}

impl NativeCacheOwnerConfig {
    /// Validates scalar, profile, path and role settings without filesystem IO.
    ///
    /// This does not authenticate the helper or inspect kernel identity. The
    /// concrete owner separately checks its actual serving UID and retained
    /// roots before accepting any writable state or body effects.
    ///
    /// # Errors
    /// Rejects noncanonical paths, unsupported profiles, ambiguous role custody,
    /// empty or inconsistent budgets and unbounded request settings.
    pub fn validate(&self) -> io::Result<()> {
        canonical_path(self.location.root())?;
        canonical_path(&self.publisher.socket_path)?;
        canonical_path(&self.quota_socket)?;
        if let Some(root) = &self.administrative_root {
            canonical_path(root)?;
            if root == self.location.root() {
                return Err(invalid("administrative root duplicates the domain root"));
            }
        }
        if self.publisher.socket_path == self.quota_socket {
            return Err(invalid("publisher and quota endpoints must be distinct"));
        }

        let profile = self.location.chunk_profile();
        if self.publisher.chunk_profile_name != "cdc-1m"
            || profile != &ChunkProfile::cdc_1m(profile.seed())
            || !(1..=300_000).contains(&self.publisher.wait_budget_ms)
        {
            return Err(invalid("unsupported profile or publisher wait budget"));
        }
        let roles = &self.publisher.identities;
        if self.content_uid == 0
            || self.content_uid == u32::MAX
            || roles.serve_uid != self.content_uid
            || roles.publish_uid == 0
            || roles.publish_uid == u32::MAX
            || roles.publish_uid == roles.serve_uid
            || matches!(self.content_gid, 0 | u32::MAX)
            || matches!(self.state_gid, 0 | u32::MAX)
            || self.content_gid == self.state_gid
        {
            return Err(invalid("invalid native role or content/state custody"));
        }
        if self.quota_owner.is_empty()
            || self.quota_owner.len() > 256
            || self.quota_owner.chars().any(char::is_control)
        {
            return Err(invalid("invalid host quota owner"));
        }

        if self.project_id == 0
            || self.project_hard_limit_bytes == 0
            || self.project_hard_limit_bytes % 1024 != 0
            || self.project_hard_limit_bytes > self.tier_charge_budget_bytes
            || self.tier_charge_budget_bytes == 0
            || self.policy.capacity == 0
            || self.policy.capacity > self.project_hard_limit_bytes
            || self.reads.max_allocation_bytes == 0
            || self.state.bytes == 0
            || self.state.records == 0
            || self.inventory_entries == 0
            || self.queued_commands == 0
        {
            return Err(invalid(
                "native owner requires finite nonzero resource budgets",
            ));
        }
        CachePolicy::new(self.policy)
            .map_err(|_| invalid("inconsistent native eviction policy"))?;
        Ok(())
    }
}

fn canonical_path(path: &std::path::Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/')
        || bytes.len() == 1
        || bytes.contains(&0)
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(invalid("native owner path must be absolute and canonical"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publisher_local::socket::RoleIdentities;
    use std::time::Duration;

    fn configuration() -> NativeCacheOwnerConfig {
        NativeCacheOwnerConfig {
            location: HostDomainLocation::new(
                "/nonexistent/cache/domain".into(),
                "private:fixture".into(),
                ChunkProfile::cdc_1m([0; 32]),
            )
            .unwrap(),
            administrative_root: None,
            publisher: ClientConfig {
                socket_path: "/nonexistent/runtime/publisher.sock".into(),
                identities: RoleIdentities {
                    serve_uid: 840,
                    publish_uid: 841,
                },
                chunk_profile_name: "cdc-1m".into(),
                wait_budget_ms: 1000,
            },
            quota_socket: "/nonexistent/runtime/quota.sock".into(),
            quota_epoch: [1; 16],
            quota_owner: "fixture".into(),
            filesystem_uuid: [2; 16],
            project_id: 100,
            project_hard_limit_bytes: 1024,
            project_hard_inode_limit: 0,
            content_uid: 840,
            content_gid: 845,
            state_gid: 844,
            tier_charge_budget_bytes: 2048,
            policy: PolicyConfig {
                capacity: 900,
                low_watermark: 500,
                probation_bytes: 100,
                release_grace: Duration::from_secs(30),
                scan_limit: 64,
            },
            reads: HostReadLimits::default(),
            state: StateLimits {
                bytes: 4096,
                records: 32,
            },
            inventory_entries: 128,
            queued_commands: 4,
        }
    }

    #[test]
    fn native_host_cache_config_validation_needs_no_existing_paths() {
        configuration().validate().unwrap();
    }

    #[test]
    fn native_host_cache_config_refuses_ambiguous_custody_and_unfunded_capacity() {
        let mut config = configuration();
        config.publisher.identities.publish_uid = config.content_uid;
        assert!(config.validate().is_err());

        let mut config = configuration();
        config.policy.capacity = config.project_hard_limit_bytes + 1;
        assert!(config.validate().is_err());

        let mut config = configuration();
        config.project_hard_limit_bytes = 1000;
        assert!(config.validate().is_err());

        let mut config = configuration();
        config.state_gid = config.content_gid;
        assert!(config.validate().is_err());

        for path in [
            "/runtime//quota",
            "/runtime/./quota",
            "/runtime/../quota",
            "runtime/quota",
        ] {
            let mut config = configuration();
            config.quota_socket = path.into();
            assert!(config.validate().is_err(), "accepted {path}");
        }
    }
}
