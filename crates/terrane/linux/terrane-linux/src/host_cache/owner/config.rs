//! Validates trusted native-owner settings before opening mutable resources.

use crate::publisher_local::client::ClientConfig;
use std::{io, os::unix::ffi::OsStrExt, path::PathBuf, time::Duration};
use terrane_format::chunking::ChunkProfile;
use terrane_sdk::host::cache::{
    CachePolicy, HostDomainLocation, HostReadLimits, PolicyConfig, StateLimits,
};

/// Bounds derived FUSE metadata separately from ordinary host-cache content.
///
/// These limits grant no disclosure or write authority. Admission additionally
/// requires the actual Running owner, durable funding and native verification.
#[derive(Clone, Copy, Debug)]
pub struct SurfaceIndexPolicy {
    /// Maximum expanded entries in a single canonical projection.
    pub max_entries: u32,
    /// Maximum combined canonical node bodies and their digest keys per request.
    pub max_node_bytes: usize,
    /// Maximum compiled bytes in a single derived index.
    pub max_index_bytes: usize,
    /// Separate cap on synchronized index-inode allocation, including verity data.
    ///
    /// Admission currently uses full project charge as a conservative upper
    /// bound so unlinked indexes retained by old mappings cannot escape this cap.
    /// Other host-cache content can therefore cause an earlier refusal.
    pub capacity_bytes: u64,
    /// Distinct future hold retained until native retirement reconciles the job.
    pub future_hold_bytes: u64,
}

impl SurfaceIndexPolicy {
    pub(crate) fn validate(self, metadata_hold: u64, capacity: u64) -> io::Result<()> {
        let payload = u64::try_from(self.max_index_bytes)
            .map_err(|_| invalid("surface index payload exceeds native accounting"))?;
        let floor = metadata_hold
            .checked_add(payload)
            .ok_or_else(|| invalid("surface index overlap overflows accounting"))?;
        if self.max_entries == 0
            || self.max_node_bytes < 32
            || payload == 0
            || self.capacity_bytes < payload
            || self.capacity_bytes > capacity
            || self.future_hold_bytes < floor
            || self.future_hold_bytes > capacity
        {
            return Err(invalid(
                "surface index policy requires finite funded bounds",
            ));
        }
        Ok(())
    }
}

/// Bounds the payload and logical future hold of one native index repair.
///
/// This policy grants no write permission or allocation guarantee. The physical
/// owner must additionally retain a verified pack, durable source pin and hold,
/// and authenticate actual quota charges before and after the complete command.
#[derive(Clone, Copy, Debug)]
pub struct IndexRepairPolicy {
    /// Maximum exact derived detached-index payload accepted by one command.
    pub max_index_bytes: usize,
    /// Future policy hold retained through physical completion and cleanup.
    ///
    /// This must cover the maximum index payload plus the configured metadata
    /// synchronization hold. That floor describes payload overlap, not native
    /// allocation rounding, directory growth or filesystem metadata overhead.
    /// Actual excess charge faults the command without releasing its custody.
    pub future_hold_bytes: u64,
}

impl IndexRepairPolicy {
    pub(crate) fn validate(self, snapshot_hold: u64, capacity: u64) -> io::Result<()> {
        let payload = u64::try_from(self.max_index_bytes)
            .map_err(|_| invalid("index repair payload budget exceeds native accounting"))?;
        let floor = snapshot_hold
            .checked_add(payload)
            .ok_or_else(|| invalid("index repair payload overlap overflows accounting"))?;
        if payload == 0 || self.future_hold_bytes < floor || self.future_hold_bytes > capacity {
            return Err(invalid(
                "index repair requires a finite funded payload overlap",
            ));
        }
        Ok(())
    }
}

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
    /// Cache-side completion delay matching the trusted publisher configuration.
    ///
    /// The publisher independently enforces its durable retirement deadline.
    /// A premature completion refusal requires recovery; this delay never
    /// supplies final-removal authority. The interval is nonzero and at most
    /// 300 seconds, separate from pin-release grace.
    pub retirement_interval: Duration,
    /// Operator allocation budget for encoded reads.
    pub reads: HostReadLimits,
    /// Maximum durable policy snapshot size and record count.
    pub state: StateLimits,
    /// Maximum retained entries in one complete native recovery inventory.
    pub inventory_entries: usize,
    /// Maximum queued commands, from one through 1024, excluding the active command.
    pub queued_commands: usize,
    /// Operator-selected future policy hold for metadata synchronization and state writes.
    ///
    /// The policy floor is twice the maximum serialized snapshot length for
    /// old/new payload overlap. This is not a bound on filesystem allocation
    /// rounding, inode/directory growth or synchronization metadata. Actual
    /// charged-and-reserved usage is reconciled before acknowledgment; excess
    /// charge faults the operation while retaining its hold and source custody.
    /// The hold is neither measured allocation nor an allocation guarantee.
    pub metadata_sync_hold_bytes: u64,
    /// Optional finite index-repair policy; absence disables index writes.
    ///
    /// Enabling this setting alone cannot authorize repair. Source inspection,
    /// durable pack pinning, actual owner exclusion and fresh authenticated
    /// charge reconciliation remain mandatory. No default repair hold is guessed.
    pub index_repair: Option<IndexRepairPolicy>,
    /// Optional bounded derived-index admission; absence disables surface writes.
    pub surface_index: Option<SurfaceIndexPolicy>,
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
            || !self.project_hard_limit_bytes.is_multiple_of(1024)
            || self.project_hard_limit_bytes > self.tier_charge_budget_bytes
            || self.tier_charge_budget_bytes == 0
            || self.policy.capacity == 0
            || self.policy.capacity > self.project_hard_limit_bytes
            || self.reads.max_allocation_bytes == 0
            || self.state.bytes == 0
            || self.state.records == 0
            || self.inventory_entries == 0
            || !(1..=1024).contains(&self.queued_commands)
            || self.metadata_sync_hold_bytes == 0
            || self.metadata_sync_hold_bytes > self.policy.capacity
            || u64::try_from(self.state.bytes)
                .ok()
                .and_then(|bytes| bytes.checked_mul(2))
                .is_none_or(|overlap| self.metadata_sync_hold_bytes < overlap)
        {
            return Err(invalid(
                "native owner requires finite nonzero resource budgets",
            ));
        }
        crate::publisher_io::NativeRetirementPolicy::new(self.retirement_interval)?;
        CachePolicy::new(self.policy)
            .map_err(|_| invalid("inconsistent native eviction policy"))?;
        if let Some(repair) = self.index_repair {
            repair.validate(self.metadata_sync_hold_bytes, self.policy.capacity)?;
        }
        if let Some(surface) = self.surface_index {
            if !cfg!(feature = "surface-fuse") {
                return Err(invalid("surface index admission requires surface-fuse"));
            }
            surface.validate(self.metadata_sync_hold_bytes, self.policy.capacity)?;
        }
        Ok(())
    }

    /// Selects the configured logical hold for an exact verified index payload.
    ///
    /// This performs no IO and grants no native write or retention authority.
    ///
    /// # Errors
    /// Refuses disabled repair, inconsistent policy, empty derived indexes and
    /// payloads exceeding the operator's finite per-command limit.
    pub(super) fn index_repair_hold(&self, index_bytes: usize) -> io::Result<u64> {
        let repair = self.index_repair.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native index repair is disabled",
            )
        })?;
        repair.validate(self.metadata_sync_hold_bytes, self.policy.capacity)?;
        if index_bytes == 0 || index_bytes > repair.max_index_bytes {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "derived index exceeds configured repair payload policy",
            ));
        }
        Ok(repair.future_hold_bytes)
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
            project_hard_limit_bytes: 65536,
            project_hard_inode_limit: 0,
            content_uid: 840,
            content_gid: 845,
            state_gid: 844,
            tier_charge_budget_bytes: 131072,
            policy: PolicyConfig {
                capacity: 60000,
                low_watermark: 32000,
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
            retirement_interval: Duration::from_secs(30),
            metadata_sync_hold_bytes: 16384,
            index_repair: None,
            surface_index: None,
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

        let mut config = configuration();
        config.queued_commands = 1025;
        assert!(config.validate().is_err());

        for interval in [Duration::ZERO, Duration::from_secs(301)] {
            let mut config = configuration();
            config.retirement_interval = interval;
            assert!(config.validate().is_err());
        }

        let mut config = configuration();
        config.metadata_sync_hold_bytes = config.state.bytes as u64;
        assert!(config.validate().is_err());

        let mut config = configuration();
        config.state.bytes = usize::MAX;
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

    #[test]
    fn native_index_repair_policy_defaults_closed_and_funds_payload_overlap() {
        let mut config = configuration();
        assert_eq!(
            config.index_repair_hold(1024).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        config.index_repair = Some(IndexRepairPolicy {
            max_index_bytes: 8192,
            future_hold_bytes: config.metadata_sync_hold_bytes + 8192,
        });
        config.validate().unwrap();
        assert_eq!(config.index_repair_hold(8192).unwrap(), 24576);
        assert_eq!(
            config.index_repair_hold(8193).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert!(config.index_repair_hold(0).is_err());

        config.index_repair.as_mut().unwrap().future_hold_bytes -= 1;
        assert!(config.validate().is_err());

        config.index_repair = Some(IndexRepairPolicy {
            max_index_bytes: usize::MAX,
            future_hold_bytes: u64::MAX,
        });
        assert!(config.validate().is_err());
    }
}
