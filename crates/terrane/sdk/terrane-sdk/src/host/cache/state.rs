//! Persists bounded pin, reservation, lease and residence records (HOST-29).
//!
//! ```toml
//! version = 1
//! pins = []
//! reservations = []
//! leases = []
//! residences = []
//! ```
//!
//! Manifests, indexes, queues and tree nodes never enter this snapshot. Sealed
//! reads do not access this module. Publication owns its separate verity state.

use crate::store::{ByteRange, LocalFs, StoreErrorKind, StoreFailure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

/// Bounds untrusted state parsing and accepted durable record counts.
#[derive(Clone, Copy, Debug)]
pub struct StateLimits {
    /// Maximum snapshot size before parsing or writing.
    pub bytes: usize,
    /// Maximum combined record count across all categories.
    pub records: usize,
}

/// Holds a durable consumer promise for one canonical content digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRecord {
    /// Unambiguous consumer or exposure lease owner.
    pub owner: String,
    /// Canonical lowercase hexadecimal content digest.
    pub hash: String,
    /// Absolute expiry in Unix seconds, independent of process ticks.
    pub expires: u64,
}

/// Records a durable future-capacity hold before admission writes bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRecord {
    /// Unique reservation token.
    pub id: String,
    /// Account charged for reserved allocation.
    pub owner: String,
    /// Future-capacity budget held for all simultaneous admission copies.
    ///
    /// This is neither measured inode allocation nor a kernel reservation, and
    /// does not guarantee that later allocation or seal enablement succeeds.
    pub bytes: u64,
}

/// Records an owner's durable liveness deadline.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    /// Owner whose pins expire with this lease.
    pub owner: String,
    /// Absolute expiry in Unix seconds.
    pub expires: u64,
}

/// Records one chunk's verified range in a published sealed object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidenceRecord {
    /// Canonical chunk digest.
    pub chunk: String,
    /// Canonical sealed object digest.
    pub object: String,
    /// Plaintext offset within the sealed file.
    pub offset: u64,
    /// Exact verified plaintext length.
    pub length: u64,
}

/// Contains only allowed host policy state, never content lookup indexes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheState {
    version: u32,
    /// Consumer promises acknowledged after durable synchronization.
    pub pins: Vec<PinRecord>,
    /// Future-capacity holds retained until recovery reconciles actual custody.
    pub reservations: Vec<ReservationRecord>,
    /// Owner liveness deadlines used by periodic pin sweeping.
    pub leases: Vec<LeaseRecord>,
    /// Reconstructible chunk-to-sealed-file ranges.
    pub residences: Vec<ResidenceRecord>,
}

impl Default for CacheState {
    fn default() -> Self {
        Self {
            version: 1,
            pins: Vec::new(),
            reservations: Vec::new(),
            leases: Vec::new(),
            residences: Vec::new(),
        }
    }
}

impl CacheState {
    /// Checks the complete snapshot encoding and returns its exact byte length.
    ///
    /// This performs no filesystem effects. Native owners use it before
    /// reserving or synchronizing a multi-step durable state transition.
    ///
    /// # Errors
    /// Refuses invalid records, serialization failures and the configured byte
    /// budget, including snapshots whose record count alone would fit.
    pub fn encoded_len(&self, limits: StateLimits) -> Result<usize, StoreFailure> {
        self.validate(limits)?;
        let text = toml::to_string(self).map_err(|_| capacity())?;
        if text.len() > limits.bytes {
            return Err(capacity());
        }
        Ok(text.len())
    }

    /// Validates bounds and every record before accepting durable state.
    ///
    /// # Errors
    /// Rejects unknown versions, malformed names or digests, duplicate ownership
    /// keys, overflowing ranges and exceeded limits.
    pub fn validate(&self, limits: StateLimits) -> Result<(), StoreFailure> {
        let count = self
            .pins
            .len()
            .checked_add(self.reservations.len())
            .and_then(|count| count.checked_add(self.leases.len()))
            .and_then(|count| count.checked_add(self.residences.len()))
            .ok_or_else(capacity)?;
        if self.version != 1 || count > limits.records {
            return Err(capacity());
        }
        let mut pins = BTreeSet::new();
        for pin in &self.pins {
            if !name(&pin.owner) || !digest(&pin.hash) || !pins.insert((&pin.owner, &pin.hash)) {
                return Err(capacity());
            }
        }
        let mut reservations = BTreeSet::new();
        for reservation in &self.reservations {
            if !name(&reservation.id)
                || !name(&reservation.owner)
                || !reservations.insert(&reservation.id)
            {
                return Err(capacity());
            }
        }
        let mut leases = BTreeSet::new();
        for lease in &self.leases {
            if !name(&lease.owner) || !leases.insert(&lease.owner) {
                return Err(capacity());
            }
        }
        let mut residences = BTreeSet::new();
        for residence in &self.residences {
            if !digest(&residence.chunk)
                || !digest(&residence.object)
                || residence.offset.checked_add(residence.length).is_none()
                || !residences.insert(&residence.chunk)
            {
                return Err(capacity());
            }
        }
        Ok(())
    }

    /// Loads existing policy state without creating or repairing any file.
    ///
    /// Missing state returns `None`; the caller must scan/rebuild before eviction.
    ///
    /// # Errors
    /// Rejects oversized, malformed, symlinked or unsupported state and I/O failures.
    pub async fn load(
        fs: &(impl LocalFs + crate::bucket::BucketBinding),
        directory: &Path,
        limits: StateLimits,
    ) -> Result<Option<Self>, StoreFailure> {
        let path = directory.join("records.toml");
        let metadata = match fs.symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_failure(error)),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > limits.bytes as u64
        {
            return Err(capacity());
        }
        // A file growing after the size check must not cause an unbounded
        // allocation before the closing identity check can reject it.
        let bytes = fs
            .read_range(
                &path,
                ByteRange {
                    start: 0,
                    length: metadata.len(),
                },
            )
            .await
            .map_err(io_failure)?;
        let after = fs.symlink_metadata(&path).await.map_err(io_failure)?;
        if bytes.len() as u64 != metadata.len()
            || bytes.len() > limits.bytes
            || !super::readonly::same_file(&metadata, &after)
        {
            return Err(capacity());
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| capacity())?;
        let state: Self = toml::from_str(text).map_err(|_| capacity())?;
        state.validate(limits)?;
        Ok(Some(state))
    }

    /// Durably replaces policy state before its caller acknowledges a new pin.
    ///
    /// The caller serializes writers. Failure leaves the previous snapshot or a
    /// complete new snapshot, and never permits an unsynchronized pin ACK.
    ///
    /// # Errors
    /// Rejects invalid or oversized snapshots and propagates write/sync failures.
    pub async fn persist(
        &self,
        fs: &(impl LocalFs + crate::bucket::BucketBinding),
        directory: &Path,
        limits: StateLimits,
    ) -> Result<(), StoreFailure> {
        self.validate(limits)?;
        let text = toml::to_string(self).map_err(|_| capacity())?;
        if text.len() > limits.bytes {
            return Err(capacity());
        }
        let random = fs.random_bytes(16).await.map_err(io_failure)?;
        if random.len() != 16 {
            return Err(capacity());
        }
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let temporary = directory.join(format!(".records-{suffix}.tmp"));
        fs.write_new(&temporary, text.as_bytes())
            .await
            .map_err(io_failure)?;
        let metadata = fs.symlink_metadata(&temporary).await.map_err(io_failure)?;
        fs.sync_file_nofollow(&temporary, &metadata)
            .await
            .map_err(io_failure)?;
        fs.rename(&temporary, &directory.join("records.toml"))
            .await
            .map_err(io_failure)?;
        fs.sync_directory(directory).await.map_err(io_failure)?;
        Ok(())
    }

    /// Releases expired leases and pins while returning final-release hashes.
    ///
    /// Callers durably persist this result before applying normal grace/wipe
    /// policy. The result contains only hashes whose last remaining pin expired.
    pub fn sweep_expired(&mut self, now: u64) -> Vec<String> {
        let before: BTreeSet<_> = self.pins.iter().map(|pin| pin.hash.clone()).collect();
        self.leases.retain(|lease| lease.expires > now);
        let owners: BTreeSet<_> = self
            .leases
            .iter()
            .map(|lease| lease.owner.as_str())
            .collect();
        self.pins
            .retain(|pin| pin.expires > now && owners.contains(pin.owner.as_str()));
        let after: BTreeSet<_> = self.pins.iter().map(|pin| pin.hash.clone()).collect();
        before.difference(&after).cloned().collect()
    }
}

fn name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn capacity() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Capacity)
}
fn io_failure(error: std::io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
}
