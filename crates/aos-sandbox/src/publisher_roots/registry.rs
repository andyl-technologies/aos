//! Bounded replay and lifecycle transitions for protected root records.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    PublicationRootId, PublicationRootObligationsV1, PublicationRootRecordV1,
    PublicationRootStateV1,
};

/// Reports protected root-registry failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicationRootRegistryError {
    /// A root record contains sentinel, inconsistent, or forged fields.
    #[error("protected publication-root record is invalid")]
    InvalidRecord,
    /// A root generation conflicts with retained history.
    #[error("protected publication-root generation conflicts")]
    GenerationConflict,
    /// The requested root is absent.
    #[error("protected publication root is absent")]
    Absent,
    /// A requested lifecycle transition is illegal.
    #[error("protected publication-root lifecycle transition is invalid")]
    InvalidTransition,
    /// Outstanding permits, catalog entries, uncertain effects, or custody block retirement.
    #[error("protected publication root still has retained obligations")]
    RetirementBlocked,
    /// Configured record capacity is invalid or exhausted.
    #[error("protected publication-root registry capacity is exhausted")]
    Capacity,
    /// A monotone root generation overflowed.
    #[error("protected publication-root generation is exhausted")]
    GenerationExhausted,
    /// A settlement failure latched the registry closed until protected replay.
    #[error("protected publication-root registry is poisoned")]
    Poisoned,
}

/// Holds the complete bounded protected history and current root heads.
#[derive(Clone, Debug)]
pub struct PublicationRootRegistry {
    records: BTreeMap<([u8; 16], u64), PublicationRootRecordV1>,
    heads: BTreeMap<[u8; 16], PublicationRootRecordV1>,
    maximum_records: usize,
    registry_generation: u64,
    registry_digest: ObjectDigest,
    live_custody: BTreeMap<[u8; 16], ObjectDigest>,
    poisoned: bool,
}

/// Commits the complete globally ordered root-registry projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationRootRegistryCheckpointV1 {
    /// Number of protected root successor records applied.
    pub generation: u64,
    /// Digest of every retained root generation in canonical order.
    pub registry_digest: ObjectDigest,
}

/// Retains the exact global registry frontier and selected active root.
///
/// This borrow prevents registry mutation while admission or materialization
/// checks it. Per-root generation and global registry generation are distinct.
#[derive(Debug)]
pub struct CurrentPublicationRoot<'registry> {
    registry: &'registry PublicationRootRegistry,
    root: &'registry super::AuthorizedPublicationRoot<'registry>,
    checkpoint: PublicationRootRegistryCheckpointV1,
}

impl CurrentPublicationRoot<'_> {
    /// Returns the exact selected active root authority.
    #[must_use]
    pub const fn root(&self) -> &super::AuthorizedPublicationRoot<'_> {
        self.root
    }

    /// Returns the global root-registry checkpoint, not a per-root generation.
    #[must_use]
    pub const fn checkpoint(&self) -> PublicationRootRegistryCheckpointV1 {
        self.checkpoint
    }

    /// Rechecks that this borrow still describes the registry's active head.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.registry.checkpoint() == self.checkpoint
            && self
                .registry
                .active(self.root.record().root_id)
                .is_ok_and(|record| {
                    record.record_digest == self.root.record_digest()
                        && record.generation == self.root.generation()
                })
    }
}

impl PublicationRootRegistry {
    /// Replays a complete bounded root registry and validates every chain.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationRootRegistryError`] for invalid capacity, records,
    /// duplicates, gaps, forks, or predecessor mismatches.
    pub fn replay(
        maximum_records: usize,
        records: impl IntoIterator<Item = PublicationRootRecordV1>,
    ) -> Result<Self, PublicationRootRegistryError> {
        if maximum_records == 0 || maximum_records > 65_536 {
            return Err(PublicationRootRegistryError::Capacity);
        }
        let mut all = BTreeMap::new();
        for record in records {
            let record = record.validate()?;
            if all.len() >= maximum_records {
                return Err(PublicationRootRegistryError::Capacity);
            }
            let key = (*record.root_id.as_bytes(), record.generation);
            if all.insert(key, record).is_some() {
                return Err(PublicationRootRegistryError::GenerationConflict);
            }
        }
        let mut heads: BTreeMap<[u8; 16], PublicationRootRecordV1> = BTreeMap::new();
        for ((root_id, generation), record) in &all {
            if *generation > 1 {
                let predecessor = all
                    .get(&(*root_id, generation - 1))
                    .ok_or(PublicationRootRegistryError::GenerationConflict)?;
                record.follows(predecessor)?;
            }
            let replace = heads
                .get(root_id)
                .is_none_or(|current| current.generation < *generation);
            if replace {
                heads.insert(*root_id, record.clone());
            }
        }
        let mut active_scopes = BTreeMap::new();
        for record in heads
            .values()
            .filter(|record| record.state == PublicationRootStateV1::Active)
        {
            let scope = (
                *record.resource.as_bytes(),
                super::model::domain_code(record.domain),
                *record.domain.domain_id().as_bytes(),
            );
            if active_scopes.insert(scope, record.root_id).is_some() {
                return Err(PublicationRootRegistryError::GenerationConflict);
            }
        }
        let registry_generation =
            u64::try_from(all.len()).map_err(|_| PublicationRootRegistryError::Capacity)?;
        let registry_digest = registry_digest(&all);
        Ok(Self {
            records: all,
            heads,
            maximum_records,
            registry_generation,
            registry_digest,
            live_custody: BTreeMap::new(),
            poisoned: false,
        })
    }

    /// Installs a first generation or exactly replays a retained generation.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationRootRegistryError`] for invalid, conflicting,
    /// noninitial, or excessive records.
    pub(crate) fn install_initial(
        &mut self,
        _owner: &crate::publisher_admission::RootRegistryOwnerToken,
        record: PublicationRootRecordV1,
    ) -> Result<PublicationRootRecordV1, PublicationRootRegistryError> {
        self.ensure_healthy()?;
        let record = record.validate()?;
        if record.generation != 1 || record.predecessor_digest.is_some() {
            return Err(PublicationRootRegistryError::GenerationConflict);
        }
        let root = *record.root_id.as_bytes();
        if let Some(existing) = self.heads.get(&root) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(PublicationRootRegistryError::GenerationConflict)
            };
        }
        if self.records.len() >= self.maximum_records {
            return Err(PublicationRootRegistryError::Capacity);
        }
        if self.heads.values().any(|current| {
            current.state == PublicationRootStateV1::Active
                && current.resource == record.resource
                && current.domain == record.domain
        }) {
            return Err(PublicationRootRegistryError::GenerationConflict);
        }
        self.records.insert((root, 1), record.clone());
        self.heads.insert(root, record);
        self.refresh_checkpoint()?;
        self.heads
            .get(&root)
            .cloned()
            .ok_or(PublicationRootRegistryError::GenerationConflict)
    }

    /// Resolves the active head for new-authority pairing.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationRootRegistryError`] when absent or not active.
    pub fn active(
        &self,
        root_id: PublicationRootId,
    ) -> Result<&PublicationRootRecordV1, PublicationRootRegistryError> {
        self.ensure_healthy()?;
        let record = self
            .heads
            .get(root_id.as_bytes())
            .ok_or(PublicationRootRegistryError::Absent)?;
        if record.state != PublicationRootStateV1::Active {
            return Err(PublicationRootRegistryError::InvalidTransition);
        }
        Ok(record)
    }

    /// Retains the exact global checkpoint and one selected active root.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationRootRegistryError`] unless the supplied live root
    /// is the registry's exact current active head.
    pub fn select_current<'registry>(
        &'registry self,
        root: &'registry super::AuthorizedPublicationRoot<'registry>,
    ) -> Result<CurrentPublicationRoot<'registry>, PublicationRootRegistryError> {
        let current = self.active(root.record().root_id)?;
        if current.record_digest != root.record_digest() || current.generation != root.generation()
        {
            return Err(PublicationRootRegistryError::GenerationConflict);
        }
        Ok(CurrentPublicationRoot {
            registry: self,
            root,
            checkpoint: self.checkpoint(),
        })
    }

    /// Starts draining one active root generation.
    ///
    /// Exact replay of an already-draining head is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationRootRegistryError`] for absence, retirement, record
    /// capacity, or generation overflow.
    pub(crate) fn begin_draining(
        &mut self,
        owner: &crate::publisher_admission::RootRegistryOwnerToken,
        root_id: PublicationRootId,
    ) -> Result<PublicationRootRecordV1, PublicationRootRegistryError> {
        self.ensure_healthy()?;
        let current = self
            .heads
            .get(root_id.as_bytes())
            .ok_or(PublicationRootRegistryError::Absent)?
            .clone();
        if current.state == PublicationRootStateV1::Draining {
            return Ok(current);
        }
        if current.state != PublicationRootStateV1::Active {
            return Err(PublicationRootRegistryError::InvalidTransition);
        }
        self.install_successor(owner, current.successor(PublicationRootStateV1::Draining)?)
    }

    /// Retires a drained root only after every obligation and live custody ends.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationRootRegistryError::RetirementBlocked`] while any
    /// permit, catalog entry, uncertain effect, or descriptor custody remains.
    pub(crate) fn retire(
        &mut self,
        owner: &crate::publisher_admission::RootRegistryOwnerToken,
        root_id: PublicationRootId,
        ledger: &crate::publisher_admission::AdmissionLedger,
    ) -> Result<PublicationRootRecordV1, PublicationRootRegistryError> {
        self.ensure_healthy()?;
        let current = self
            .heads
            .get(root_id.as_bytes())
            .ok_or(PublicationRootRegistryError::Absent)?
            .clone();
        if current.state == PublicationRootStateV1::Retired {
            return Ok(current);
        }
        if current.state != PublicationRootStateV1::Draining {
            return Err(PublicationRootRegistryError::InvalidTransition);
        }
        if ledger.root_obligations(root_id).blocks_retirement()
            || self.live_custody.contains_key(root_id.as_bytes())
        {
            return Err(PublicationRootRegistryError::RetirementBlocked);
        }
        self.install_successor(owner, current.successor(PublicationRootStateV1::Retired)?)
    }

    pub(crate) fn retain_custody(
        &mut self,
        root_id: PublicationRootId,
        boot_commitment: ObjectDigest,
    ) -> Result<(), PublicationRootRegistryError> {
        if boot_commitment.as_bytes() == &[0; 32]
            || self.live_custody.contains_key(root_id.as_bytes())
        {
            return Err(PublicationRootRegistryError::GenerationConflict);
        }
        self.live_custody
            .insert(*root_id.as_bytes(), boot_commitment);
        Ok(())
    }

    pub(crate) fn release_custody(
        &mut self,
        root_id: PublicationRootId,
        boot_commitment: ObjectDigest,
    ) -> Result<(), PublicationRootRegistryError> {
        if self.live_custody.get(root_id.as_bytes()) != Some(&boot_commitment) {
            return Err(PublicationRootRegistryError::GenerationConflict);
        }
        self.live_custody.remove(root_id.as_bytes());
        Ok(())
    }

    /// Returns the current head without granting use authority.
    #[must_use]
    pub fn head(&self, root_id: PublicationRootId) -> Option<&PublicationRootRecordV1> {
        if self.poisoned {
            return None;
        }
        self.heads.get(root_id.as_bytes())
    }

    /// Returns the digest of one exact retained generation.
    #[must_use]
    pub fn generation_digest(
        &self,
        root_id: PublicationRootId,
        generation: u64,
    ) -> Option<ObjectDigest> {
        if self.poisoned {
            return None;
        }
        self.records
            .get(&(*root_id.as_bytes(), generation))
            .map(|record| record.record_digest)
    }

    pub(crate) fn has_live_custody(&self, root_id: PublicationRootId) -> bool {
        self.live_custody.contains_key(root_id.as_bytes())
    }

    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Returns the complete global protected registry frontier.
    #[must_use]
    pub const fn checkpoint(&self) -> PublicationRootRegistryCheckpointV1 {
        PublicationRootRegistryCheckpointV1 {
            generation: self.registry_generation,
            registry_digest: self.registry_digest,
        }
    }

    fn install_successor(
        &mut self,
        _owner: &crate::publisher_admission::RootRegistryOwnerToken,
        record: PublicationRootRecordV1,
    ) -> Result<PublicationRootRecordV1, PublicationRootRegistryError> {
        self.ensure_healthy()?;
        if self.records.len() >= self.maximum_records {
            return Err(PublicationRootRegistryError::Capacity);
        }
        let root = *record.root_id.as_bytes();
        self.records
            .insert((root, record.generation), record.clone());
        self.heads.insert(root, record.clone());
        self.refresh_checkpoint()?;
        Ok(record)
    }

    fn refresh_checkpoint(&mut self) -> Result<(), PublicationRootRegistryError> {
        self.registry_generation = u64::try_from(self.records.len())
            .map_err(|_| PublicationRootRegistryError::Capacity)?;
        self.registry_digest = registry_digest(&self.records);
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), PublicationRootRegistryError> {
        if self.poisoned {
            return Err(PublicationRootRegistryError::Poisoned);
        }
        Ok(())
    }
}

pub(crate) fn registry_digest(
    records: &BTreeMap<([u8; 16], u64), PublicationRootRecordV1>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.publisher.root-registry.v1\0");
    digest.update((records.len() as u64).to_be_bytes());
    for record in records.values() {
        digest.update(record.record_digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}
