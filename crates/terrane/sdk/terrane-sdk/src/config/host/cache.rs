//! Parses explicit per-domain native cache resources without opening storage.
//!
//! ```toml
//! [host_tier.domains.public.cache]
//! state_gid = 844
//! capacity_bytes = 25165824
//! low_watermark_bytes = 16777216
//! probation_bytes = 65536
//! release_grace_seconds = 30
//! scan_limit = 64
//! max_read_bytes = 2097152
//! state_bytes = 65536
//! state_records = 64
//! inventory_entries = 128
//! queued_commands = 4
//! metadata_sync_hold_bytes = 262144
//! publisher_wait_budget_ms = 10000
//! consumer_lease_seconds = 30
//! [host_tier.domains.public.cache.portable]
//! max_file_bytes = 67108864
//! max_input_bytes = 268435456
//! max_files = 4096
//! max_selected_bytes = 33554432
//! ```

use crate::config::ConfigError;
use serde::Deserialize;

/// Supplies explicit finite resources for one configured native cache domain.
///
/// Omission does not select defaults or permit startup. These resource settings
/// provide no native custody, quota observation, recovery or read authority.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainCache {
    /// Private cache-state group, excluding the publisher's content group.
    pub state_gid: u32,
    /// Maximum measured allocation plus logical future holds in this domain.
    pub capacity_bytes: u64,
    /// Target allocation after high-watermark eviction.
    pub low_watermark_bytes: u64,
    /// Maximum probationary allocation before unread entries are preferred.
    pub probation_bytes: u64,
    /// Protection interval following the final consumer release.
    pub release_grace_seconds: u64,
    /// Maximum queue visits in one eviction attempt.
    pub scan_limit: usize,
    /// Maximum individual encoded read allocation.
    pub max_read_bytes: usize,
    /// Maximum serialized durable policy snapshot length.
    pub state_bytes: usize,
    /// Maximum total records in one durable policy snapshot.
    pub state_records: usize,
    /// Maximum entries in a complete native recovery inventory.
    pub inventory_entries: usize,
    /// Maximum queued physical commands, from one through 1024.
    pub queued_commands: usize,
    /// Logical future hold for metadata and snapshot synchronization.
    pub metadata_sync_hold_bytes: u64,
    /// Optional explicit funded detached-index repair bounds.
    pub index_repair: Option<IndexRepair>,
    /// Publisher request wait, from one through 300000 milliseconds.
    pub publisher_wait_budget_ms: u64,
    /// Consumer grant duration, from one through 300 whole seconds.
    pub consumer_lease_seconds: u64,
    /// Finite complete portable-validation limits.
    pub portable: PortableLimits,
}

/// Bounds one complete portable bucket validation using operator-selected resources.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableLimits {
    /// Maximum bytes read from one existing file.
    pub max_file_bytes: usize,
    /// Maximum sum of distinct input file lengths.
    pub max_input_bytes: usize,
    /// Maximum distinct input files and retained native recipes.
    pub max_files: usize,
    /// Maximum selected key and value bytes retained in the snapshot.
    pub max_selected_bytes: usize,
}

/// Bounds detached-index repair payload and its separate future policy hold.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexRepair {
    /// Maximum derived detached-index payload length.
    pub max_index_bytes: usize,
    /// Explicit future hold covering payload and metadata synchronization overlap.
    pub future_hold_bytes: u64,
}

impl DomainCache {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        let snapshot_overlap = u64::try_from(self.state_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(2));
        if matches!(self.state_gid, 0 | u32::MAX)
            || self.capacity_bytes == 0
            || self.low_watermark_bytes > self.capacity_bytes
            || self.probation_bytes > self.capacity_bytes
            || self.scan_limit == 0
            || self.max_read_bytes == 0
            || self.state_bytes == 0
            || self.state_records == 0
            || self.inventory_entries == 0
            || !(1..=1024).contains(&self.queued_commands)
            || !(1..=300_000).contains(&self.publisher_wait_budget_ms)
            || !(1..=300).contains(&self.consumer_lease_seconds)
            || snapshot_overlap.is_none_or(|overlap| self.metadata_sync_hold_bytes < overlap)
            || self.metadata_sync_hold_bytes > self.capacity_bytes
            || self.portable.max_file_bytes == 0
            || self.portable.max_input_bytes < self.portable.max_file_bytes
            || self.portable.max_files == 0
            || self.portable.max_selected_bytes == 0
        {
            return Err(ConfigError::Invalid(
                "invalid finite native cache resources",
            ));
        }
        if let Some(repair) = self.index_repair {
            let overlap = u64::try_from(repair.max_index_bytes)
                .ok()
                .and_then(|bytes| bytes.checked_add(self.metadata_sync_hold_bytes));
            if repair.max_index_bytes == 0
                || overlap.is_none_or(|floor| repair.future_hold_bytes < floor)
                || repair.future_hold_bytes > self.capacity_bytes
            {
                return Err(ConfigError::Invalid("invalid funded native index repair"));
            }
        }
        Ok(())
    }
}
