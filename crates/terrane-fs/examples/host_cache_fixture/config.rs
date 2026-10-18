//! Constructs explicit finite fixture settings without issuing native authority.

use std::{io, path::PathBuf, time::Duration};
use terrane::host::cache::{HostDomainLocation, HostReadLimits, PolicyConfig, StateLimits};
use terrane_core::chunking::ChunkProfile;
use terrane_fs::{
    host_cache::NativeCacheOwnerConfig,
    publisher_local::{client::ClientConfig, socket::RoleIdentities},
};

/// Fixes the real native project ceiling for each isolated owner.
pub(super) const HARD_LIMIT: u64 = 8 * 1024 * 1024;
/// Funds actual metadata overlap without claiming measured allocation.
pub(super) const HOLD: u64 = 256 * 1024;
/// Selects the explicit host administrative epoch.
pub(super) const EPOCH: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// Bounds untrusted durable policy snapshots.
pub(super) const STATE: StateLimits = StateLimits {
    bytes: 65536,
    records: 64,
};

/// Holds host-selected fixture bindings without granting native authority.
pub(super) struct Inputs {
    pub(super) root: PathBuf,
    pub(super) domain: String,
    pub(super) owner: String,
    pub(super) project: u32,
    pub(super) quota: PathBuf,
    pub(super) publisher: PathBuf,
    pub(super) budget: u64,
    pub(super) uuid: [u8; 16],
}

impl Inputs {
    /// Loads explicit supervisor inputs.
    ///
    /// # Errors
    /// Refuses absent fields, malformed UUIDs and integer overflow.
    pub(super) fn load() -> io::Result<Self> {
        let uuid_text = variable("TERRANE_CACHE_UUID")?;
        if uuid_text.len() != 32 {
            return Err(io::Error::other("invalid explicit filesystem UUID"));
        }
        let mut uuid = [0; 16];
        for (index, value) in uuid.iter_mut().enumerate() {
            let text = uuid_text
                .get(index * 2..index * 2 + 2)
                .ok_or_else(|| io::Error::other("invalid UUID boundary"))?;
            *value = u8::from_str_radix(text, 16).map_err(io::Error::other)?;
        }
        Ok(Self {
            root: variable("TERRANE_CACHE_ROOT")?.into(),
            domain: variable("TERRANE_CACHE_DOMAIN")?,
            owner: variable("TERRANE_CACHE_OWNER")?,
            project: variable("TERRANE_CACHE_PROJECT")?
                .parse()
                .map_err(io::Error::other)?,
            quota: variable("TERRANE_CACHE_QUOTA_SOCKET")?.into(),
            publisher: variable("TERRANE_CACHE_PUBLISHER_SOCKET")?.into(),
            budget: variable("TERRANE_CACHE_BUDGET")?
                .parse()
                .map_err(io::Error::other)?,
            uuid,
        })
    }

    /// Constructs a finite policy for the genuine native factory.
    ///
    /// # Errors
    /// Refuses an invalid physical domain or chunk profile binding.
    pub(super) fn owner_config(&self) -> io::Result<NativeCacheOwnerConfig> {
        Ok(NativeCacheOwnerConfig {
            location: HostDomainLocation::new(
                self.root.clone(),
                self.domain.clone(),
                ChunkProfile::cdc_1m([0; 32]),
            )
            .map_err(io::Error::other)?,
            administrative_root: None,
            publisher: ClientConfig {
                socket_path: self.publisher.clone(),
                identities: RoleIdentities {
                    serve_uid: 840,
                    publish_uid: 841,
                },
                chunk_profile_name: "cdc-1m".into(),
                wait_budget_ms: 10000,
            },
            quota_socket: self.quota.clone(),
            quota_epoch: EPOCH,
            quota_owner: self.owner.clone(),
            filesystem_uuid: self.uuid,
            project_id: self.project,
            project_hard_limit_bytes: HARD_LIMIT,
            project_hard_inode_limit: 0,
            content_uid: 840,
            content_gid: 845,
            state_gid: 844,
            tier_charge_budget_bytes: self.budget,
            policy: PolicyConfig {
                // This case retains two independently funded objects. Its
                // policy remains bounded by the same actual project hard limit.
                capacity: if matches!(
                    self.domain.as_str(),
                    "tenant:publication-manifest-reuse"
                        | "tenant:publication-manifest-reuse-bad-whole"
                ) {
                    HARD_LIMIT
                } else {
                    6 * 1024 * 1024
                },
                low_watermark: 4 * 1024 * 1024,
                probation_bytes: 65536,
                release_grace: Duration::from_secs(30),
                scan_limit: 64,
            },
            reads: HostReadLimits {
                max_allocation_bytes: 2 * 1024 * 1024,
            },
            state: STATE,
            inventory_entries: 128,
            queued_commands: 4,
            metadata_sync_hold_bytes: HOLD,
            index_repair: None,
        })
    }
}

fn variable(name: &str) -> io::Result<String> {
    std::env::var(name).map_err(io::Error::other)
}
