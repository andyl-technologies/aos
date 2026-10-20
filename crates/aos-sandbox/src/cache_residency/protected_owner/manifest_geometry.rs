//! Classifies held Cache manifest DATA before semantic decoder allocation.
//!
//! The original initializer must pay the chosen bound before decoding these
//! same held rows. Borrowing a Journal or recognizing Genesis grants no Replay
//! authority. Full canonical, scope, deadline and Native checks still follow.
//! General histories remain explicit and use the separately owned general
//! representation supplier; a failed Genesis classification is never zero.

use super::*;
use aos_sandbox_core::{ResourceDimension, ResourceVector};
use aos_sandbox_protocol::cache_state::ProjectCacheQuotaV1;
use crate::cache_residency::RecoveryError;

/// Borrows the actual raw owners used by one initializer pricing frontier.
pub(crate) struct CacheReplayManifestGeometryV1<'journal> {
    _journal: &'journal Journal,
    state: Option<&'journal Journal>,
    encoded_bytes: usize,
    manifests: usize,
    partition_bound: usize,
    largest_manifest: usize,
    quota_slots: usize,
    largest_quota_slots: usize,
    genesis: bool,
}

impl<'journal> CacheReplayManifestGeometryV1<'journal> {
    /// Samples actual source rows before the existing source manifest decoder.
    ///
    /// # Errors
    /// Refuses invalid decoder limits or unrepresentable geometry arithmetic.
    /// Unsupported or malformed Genesis shape selects General, preserving the
    /// ordinary parser and its original error ordering after admission.
    pub(crate) fn from_source_journal(
        journal: &'journal Journal,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        Self::from_journal(journal, limits, true)
    }

    /// Samples actual authority rows before recovering complete evidence.
    ///
    /// No future state owner is opened or assumed empty at this frontier.
    ///
    /// # Errors
    /// Refuses invalid decoder limits or unrepresentable geometry arithmetic.
    pub(crate) fn from_authority_journal(
        journal: &'journal Journal,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        Self::from_journal(journal, limits, false)
    }

    /// Samples the same authority and actual state before full reconstruction.
    ///
    /// The narrow Genesis path requires no state rows at all. Any retained
    /// suffix or other state row selects General; no history is erased.
    ///
    /// # Errors
    /// Refuses invalid decoder limits or unrepresentable geometry arithmetic.
    pub(crate) fn from_initial_journals(
        authority: &'journal Journal,
        state: &'journal Journal,
        limits: CacheRecoveryLimitsV1,
    ) -> Result<Self, RecoveryError> {
        let mut geometry = Self::from_authority_journal(authority, limits)?;
        geometry.state = Some(state);
        for (_, key, value) in state.all_records() {
            geometry.genesis = false;
            geometry.encoded_bytes = geometry.encoded_bytes.checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(RecoveryError::Capacity)?;
            geometry.partition_bound = geometry.partition_bound.checked_add(1)
                .ok_or(RecoveryError::Capacity)?;
        }
        Ok(geometry)
    }

    fn from_journal(
        journal: &'journal Journal,
        limits: CacheRecoveryLimitsV1,
        source: bool,
    ) -> Result<Self, RecoveryError> {
        let limits = limits.validate()?;
        let mut geometry = Self {
            _journal: journal,
            state: None,
            encoded_bytes: 0,
            manifests: 0,
            partition_bound: 0,
            largest_manifest: 0,
            quota_slots: 0,
            largest_quota_slots: 0,
            genesis: true,
        };
        let prefix = if source {
            super::super::controller_bootstrap::SOURCE_KEY_PREFIX
        } else {
            CACHE_MANIFEST_KEY_PREFIX
        };
        for (namespace, key, value) in journal.all_records() {
            if !source && (namespace != RecordNamespace::DesiredState || !key.starts_with(prefix)) {
                // Evidence recovery likewise ignores non-manifest records.
                // Their already-opened Native owners remain baseline-priced.
                continue;
            }
            geometry.manifests = geometry.manifests.checked_add(1)
                .ok_or(RecoveryError::Capacity)?;
            geometry.encoded_bytes = geometry.encoded_bytes.checked_add(value.len())
                .ok_or(RecoveryError::Capacity)?;
            geometry.largest_manifest = geometry.largest_manifest.max(value.len());
            if namespace != RecordNamespace::DesiredState || !key.starts_with(prefix) {
                geometry.genesis = false;
                continue;
            }

            let borrowed = match borrow_cache_replay_manifest(value, limits) {
                Ok(borrowed) => borrowed,
                Err(_) => {
                    geometry.genesis = false;
                    continue;
                }
            };
            if key.strip_prefix(prefix) != Some(borrowed.partition.digest().as_bytes().as_slice()) {
                geometry.genesis = false;
                continue;
            }
            let projects = match genesis_manifest_project_count(value, limits) {
                Ok(projects) => projects,
                Err(_) => {
                    geometry.genesis = false;
                    continue;
                }
            };
            // A first successful Vec push may allocate four quota carriers.
            let slots = if projects == 0 { 0 } else { projects.max(4) };
            geometry.quota_slots = geometry.quota_slots.checked_add(slots)
                .ok_or(RecoveryError::Capacity)?;
            geometry.largest_quota_slots = geometry.largest_quota_slots.max(slots);
        }
        geometry.partition_bound = geometry.manifests;
        if geometry.manifests == 0 || geometry.manifests > MAXIMUM_CACHE_MANIFESTS {
            geometry.genesis = false;
        }
        Ok(geometry)
    }

    /// Returns complete raw extents for the explicit General representation path.
    pub(crate) const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    /// Bounds partitions reached from manifests and actual retained state rows.
    pub(crate) const fn partition_bound(&self) -> usize {
        self.partition_bound
    }

    /// Prices sequential manifest validation and its retained evidence owners.
    ///
    /// # Errors
    /// Refuses arithmetic overflow. Returns `None` for the General path.
    pub(crate) fn genesis_manifest_validation_bound(&self) -> Result<Option<ResourceVector>, RecoveryError> {
        if !self.genesis {
            return Ok(None);
        }
        // An evidence Vec and the accumulating Arc map can overlap while its
        // IntoIter is consumed; later targets.evidence keeps another full Vec.
        let evidence_slots = self.manifests.max(4);
        let evidence = std::mem::size_of::<CacheResidencyReplayPartitionEvidenceV1>()
            .checked_add(std::mem::size_of::<(ObjectDigest, Arc<CacheResidencyReplayPartitionEvidenceV1>, [usize; 4])>())
            .ok_or(RecoveryError::Capacity)?;
        let memory = self.encoded_bytes.checked_mul(3)
            .and_then(|bytes| bytes.checked_add(evidence_slots.checked_mul(evidence)?.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(self.sequential_decode_memory()?))
            .ok_or(RecoveryError::Capacity)?;
        let entries = evidence_slots.checked_mul(6)
            .and_then(|entries| entries.checked_add(self.largest_quota_slots.checked_mul(6)?))
            .ok_or(RecoveryError::Capacity)?;
        Ok(Some(representation_vector(memory, entries)?))
    }

    /// Prices complete Genesis inventory under the actual absent state suffix.
    ///
    /// # Errors
    /// Refuses arithmetic overflow. Returns `None` unless both actual journals
    /// were sampled together and every manifest has the narrow Genesis shape.
    pub(crate) fn genesis_initial_inventory_bound(&self) -> Result<Option<ResourceVector>, RecoveryError> {
        if !self.genesis || self.state.is_none() {
            return Ok(None);
        }
        let evidence = self.genesis_manifest_validation_bound()?.ok_or(RecoveryError::Capacity)?;
        // Completed inventories keep their actual quota Vecs while the next
        // partition is decoded. The largest current decode and its accounting
        // maps are already included above; these are distinct retained outputs.
        let quotas = self.quota_slots.checked_mul(std::mem::size_of::<ProjectCacheQuotaV1>())
            .and_then(|bytes| bytes.checked_mul(2)).ok_or(RecoveryError::Capacity)?;
        let partition = std::mem::size_of::<CacheRecoveryInventoryV1>()
            .checked_add(std::mem::size_of::<(ObjectDigest, PhysicalPartitionId, [usize; 4])>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(ObjectDigest, CacheAuthorityScopeV1, VerifiedCacheCapabilityV1, [usize; 4])>()))
            .ok_or(RecoveryError::Capacity)?;
        // Two inventory carriers cover old/new complete observations; two
        // more cover current partition/session maps and their Vec growth.
        let memory = self.manifests.checked_mul(partition)
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(quotas))
            // Two moved grouping carriers exist at the original authority frontier.
            .and_then(|bytes| bytes.checked_add(
                aos_sandbox_protocol::cache_state::protected_replay::partition_history_inline_bytes_v1().checked_mul(2)?))
            .ok_or(RecoveryError::Capacity)?;
        let entries = self.manifests.checked_mul(8)
            .and_then(|entries| entries.checked_add(self.quota_slots.checked_mul(2)?))
            .ok_or(RecoveryError::Capacity)?;
        Ok(Some(evidence.checked_add(representation_vector(memory, entries)?)
            .map_err(|_| RecoveryError::Capacity)?))
    }

    fn sequential_decode_memory(&self) -> Option<usize> {
        // One current typed quota Vec plus accounting/projection quota maps
        // coexist with its canonical round-trip bytes. This is the same closed
        // Genesis carrier family used by bundle import, not a generic model/byte.
        let quota = std::mem::size_of::<ProjectCacheQuotaV1>()
            .checked_add(std::mem::size_of::<([u8; 16], ProjectCacheQuotaV1, [usize; 4])>())?;
        self.largest_manifest.checked_mul(4)?
            .checked_add(self.largest_quota_slots.checked_mul(quota)?.checked_mul(3)?)?
            // The complete historical fold moves its same locals across the
            // live authority check in two compiled inline assembly carriers.
            .checked_add(aos_sandbox_protocol::cache_state::recovery::recovery_assembly_inline_bytes_v1().checked_mul(2)?)
    }
}

fn representation_vector(memory: usize, entries: usize) -> Result<ResourceVector, RecoveryError> {
    let memory = u64::try_from(memory).map_err(|_| RecoveryError::Capacity)?;
    let entries = u64::try_from(entries).map_err(|_| RecoveryError::Capacity)?;
    // These are internal decoder/model buffers. Native durability and actual
    // receiving/output obligations have separate original baseline suppliers.
    Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, memory)
        .with(ResourceDimension::MetadataEntries, entries))
}

// One closed manifest/checkpoint preflight serves import and initialization.
pub(in crate::cache_residency) fn genesis_manifest_project_count(
    bytes: &[u8],
    limits: CacheRecoveryLimitsV1,
) -> Result<usize, CacheResidencyProtectedJournalErrorV1> {
    aos_sandbox_protocol::cache_state::replay_evidence::genesis_manifest_project_count(bytes, limits)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
}
