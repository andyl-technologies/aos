//! Validates pure collector windows and encodes legacy tombstone records.
//!
//! Supplied times are observations, not clock or backend authority. In particular,
//! a stored tombstone timestamp cannot establish local-v1 elapsed deletion age.
//!
//! ```text
//! Tombstone = {1: pack-id, 2: cycle, 3: timestamp, 4: removed, 5: epoch}
//! ```

use alloc::vec::Vec;

use super::{GcError, key};
use crate::{
    cbor::{self, Decoder},
    refs::Retention,
};

/// Validated collection windows measured in seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Windows {
    commit: u64,
    grace: u64,
    deletion: u64,
    retention: u64,
}

impl Windows {
    /// Validates grace, deletion, and default branch retention windows.
    ///
    /// # Errors
    /// Rejects `G <= C`, `D < G`, retention below `G + C`, and overflow.
    pub fn new(commit: u64, grace: u64, deletion: u64, retention: u64) -> Result<Self, GcError> {
        let minimum_retention = grace.checked_add(commit).ok_or(GcError::Exhausted)?;
        if grace <= commit || deletion < grace || retention < minimum_retention {
            return Err(GcError::Window);
        }
        Ok(Self {
            commit,
            grace,
            deletion,
            retention,
        })
    }

    /// Returns the maximum permitted client commit duration.
    pub const fn commit(self) -> u64 {
        self.commit
    }

    /// Returns the mandatory age before tombstoning.
    pub const fn grace(self) -> u64 {
        self.grace
    }

    /// Returns the mandatory age before physical deletion.
    pub const fn deletion(self) -> u64 {
        self.deletion
    }

    /// Returns the inherited ordinary reflog retention duration.
    pub const fn retention(self) -> u64 {
        self.retention
    }

    /// Reports whether an authoritative last-modified timestamp is older than G.
    ///
    /// A future timestamp fails closed rather than wrapping subtraction.
    pub fn sweep_age(self, now: u64, last_modified: u64) -> bool {
        now.checked_sub(last_modified)
            .is_some_and(|age| age > self.grace)
    }

    /// Compares D with supplied backend tombstone-creation observations.
    ///
    /// The caller must supply trustworthy creation evidence. This arithmetic
    /// never qualifies local-v1 monotonic waits or any persisted timestamp.
    pub fn deletion_age(self, now: u64, tombstoned_at: u64) -> bool {
        now.checked_sub(tombstoned_at)
            .is_some_and(|age| age >= self.deletion)
    }

    /// Reports whether a writer may still publish its pending commit.
    pub fn commit_allowed(self, now: u64, first_pack_at: u64) -> bool {
        now.checked_sub(first_pack_at)
            .is_some_and(|age| age <= self.commit)
    }
}

/// The authoritative times used to evaluate one retained reflog record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionTimes {
    /// Time of the current root snapshot.
    pub now: u64,
    /// Timestamp of the immutable commit, used only by TTL retention.
    pub commit: u64,
    /// Timestamp of the reflog entry, used by ordinary GC retention.
    pub reflog: u64,
    /// Expiry of the authoritative root lease, if one exists.
    pub lease_expiry: Option<u64>,
}

/// Reports whether a reflog record is a root under its effective retention.
pub fn retains(retention: Retention, times: RetentionTimes, windows: Windows) -> bool {
    match retention {
        Retention::Forever => true,
        Retention::Lease => times.lease_expiry.is_some_and(|expiry| times.now < expiry),
        Retention::Gc => times
            .now
            .checked_sub(times.reflog)
            .is_none_or(|age| age <= windows.retention),
        Retention::Ttl(duration) => times
            .now
            .checked_sub(times.commit)
            .is_none_or(|age| age <= duration),
    }
}

/// A recoverable physical pack exclusion carrying the collector fencing epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tombstone {
    /// Exact physical pack identifier.
    pub pack: [u8; 16],
    /// Collection cycle that excluded the pack.
    pub cycle: u64,
    /// Recorded tombstone time in Unix seconds, not physical creation authority.
    pub timestamp: u64,
    /// Number of index entries removed by this exclusion.
    pub removed: u64,
    /// Fencing epoch of the collector that published this record.
    pub epoch: u64,
}

impl Tombstone {
    /// Encodes the registered Tombstone map.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        cbor::write_map(&mut bytes, 5);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_bytes(&mut bytes, &self.pack);
        for (key, value) in [
            (2, self.cycle),
            (3, self.timestamp),
            (4, self.removed),
            (5, self.epoch),
        ] {
            cbor::write_uint(&mut bytes, key);
            cbor::write_uint(&mut bytes, value);
        }
        bytes
    }

    /// Decodes the registered Tombstone map, including required fencing epoch.
    ///
    /// # Errors
    /// Rejects noncanonical CBOR, incorrect pack width, missing epoch, and trailing values.
    pub fn decode(bytes: &[u8]) -> Result<Self, GcError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.map(bytes.len())? != 5 {
            return Err(GcError::Schema);
        }
        key(&mut decoder, 1)?;
        let pack = decoder.bytes(16)?.try_into().map_err(|_| GcError::Schema)?;
        key(&mut decoder, 2)?;
        let cycle = decoder.uint()?;
        key(&mut decoder, 3)?;
        let timestamp = decoder.uint()?;
        key(&mut decoder, 4)?;
        let removed = decoder.uint()?;
        key(&mut decoder, 5)?;
        let epoch = decoder.uint()?;
        decoder.finish()?;
        Ok(Self {
            pack,
            cycle,
            timestamp,
            removed,
            epoch,
        })
    }
}

/// Computes a raw BLAKE3-256 integrity pointer for supplied checkpoint bytes.
///
/// The caller must separately validate canonical GcMark bytes. This pointer is
/// a record-integrity observation, not an immutable Index identity.
pub fn checkpoint_digest(bytes: &[u8]) -> crate::identity::Digest {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests;
