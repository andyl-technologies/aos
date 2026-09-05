//! Binds observed runtime executions to signed namespace-generation targets.
//!
//! The protected journal retains allocation history, never live descriptor
//! authority:
//!
//! ```text
//! t<sandbox:16><incarnation:16><observed-generation:8> = immutable AOSNST01 record
//! h<sandbox:16><incarnation:16> = observed-generation:8 + target:8 + digest:32
//! ```
//!
//! The first live observation seeds its target from the current signed
//! assignment manifest. Later observed generations advance the target by the
//! same positive delta. A newly allocated target is inert until a current
//! signed manifest names it and the live proof is reacquired and rechecked.

use std::collections::BTreeMap;

use aos_sandbox_core::{IncarnationId, RawPairedClockSample, SandboxId};

use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

use super::generation::{History as RuntimeHistory, Identity};
use super::{CurrentRuntimeGeneration, RuntimeGenerationError};

mod format;
#[cfg(test)]
mod tests;

const NAMESPACE: RecordNamespace = RecordNamespace::NamespaceTarget;
const MAXIMUM_HISTORY: usize = 4096;
const MAXIMUM_BYTES: usize = 2 * 1024 * 1024;

/// Reports corrupt allocation history or a stale live runtime binding.
#[derive(Debug, thiserror::Error)]
pub enum NamespaceTargetError {
    /// Retained target history, its head, or a runtime-generation reference is inconsistent.
    #[error("namespace target history is corrupt")]
    CorruptState,
    /// The live generation is stale or its signed target moved incompatibly.
    #[error("namespace target conflicts with the current runtime or assignment")]
    Conflict,
    /// Fixed history capacity or a namespace-generation counter was exhausted.
    #[error("namespace target capacity is exhausted")]
    Capacity,
    /// Protected runtime-generation validation or liveness failed.
    #[error(transparent)]
    Generation(#[from] RuntimeGenerationError),
    /// Protected journal provenance, health, or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Describes the next signed namespace target required by a live execution.
///
/// This copyable value is an audit proposal, not live authority. The caller
/// must publish an authorized assignment successor, reacquire the current
/// runtime proof, and bind it again before any mount preparation or replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceTargetAdvanceV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    observed_generation: u64,
    observed_audit_digest: [u8; 32],
    target_generation: u64,
    allocation_digest: [u8; 32],
    payload_scope_handle: [u8; 32],
}

impl NamespaceTargetAdvanceV1 {
    /// Returns the sandbox whose assignment must advance.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the unchanged sandbox incarnation.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the controller-local observed runtime generation.
    #[must_use]
    pub const fn observed_generation(self) -> u64 {
        self.observed_generation
    }

    /// Returns the immutable runtime-generation audit digest.
    #[must_use]
    pub const fn observed_audit_digest(self) -> [u8; 32] {
        self.observed_audit_digest
    }

    /// Returns the namespace generation required in the signed successor.
    #[must_use]
    pub const fn target_generation(self) -> u64 {
        self.target_generation
    }

    /// Returns the immutable namespace-allocation audit digest.
    #[must_use]
    pub const fn allocation_digest(self) -> [u8; 32] {
        self.allocation_digest
    }

    /// Returns the live Host scope that the successor plan must grant exactly.
    ///
    /// This opaque handle is not authority and cannot reconstruct descriptors.
    /// Host must retain the same physical execution across the authorized
    /// assignment successor for a RootMount query to use it.
    #[must_use]
    pub const fn payload_scope_handle(self) -> [u8; 32] {
        self.payload_scope_handle
    }
}

/// Retains a live runtime proof whose signed assignment names its allocation.
///
/// Restart cannot reconstruct this value from audit records. Every use must
/// recheck the current runtime generation, allocation head, and signed target.
///
/// ```compile_fail
/// use aos_sandbox::runtime_scope::CurrentNamespaceTarget;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CurrentNamespaceTarget>();
/// ```
pub struct CurrentNamespaceTarget {
    generation: CurrentRuntimeGeneration,
    allocation: Record,
}

impl CurrentNamespaceTarget {
    /// Returns the namespace generation named by current signed authority.
    #[must_use]
    pub const fn target_generation(&self) -> u64 {
        self.allocation.target_generation
    }

    /// Returns the observed runtime generation behind the signed target.
    #[must_use]
    pub const fn observed_generation(&self) -> u64 {
        self.allocation.observed_generation
    }

    /// Returns the immutable allocation audit digest.
    #[must_use]
    pub const fn allocation_digest(&self) -> &[u8; 32] {
        &self.allocation.digest
    }

    /// Borrows the live runtime-generation proof without extending its deadline.
    #[must_use]
    pub const fn runtime_generation(&self) -> &CurrentRuntimeGeneration {
        &self.generation
    }

    pub(crate) fn bind<T>(
        generation: CurrentRuntimeGeneration,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<NamespaceTargetOutcome, NamespaceTargetError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        generation.recheck(journal, clock)?;

        let identity = identity(&generation);
        let signed_target = signed_target(&generation);
        let history = History::load(journal)?;
        let (allocation, changed) = history.select(
            identity,
            generation.generation(),
            *generation.audit_digest(),
            signed_target,
        )?;
        if signed_target > allocation.target_generation {
            return Err(NamespaceTargetError::Conflict);
        }
        if changed {
            generation.recheck(journal, clock)?;
            journal.commit(&allocation.transaction()?)?;
        }

        // A failed post-commit check leaves only an inert allocation. A fresh
        // current proof must bind it again before the target can be used.
        generation.recheck(journal, clock)?;
        if signed_target < allocation.target_generation {
            return Ok(NamespaceTargetOutcome::AdvanceRequired(
                allocation.advance(*generation.scope().observed().payload_scope_handle()),
            ));
        }

        let current = Self {
            generation,
            allocation,
        };
        current.recheck(journal, clock)?;
        Ok(NamespaceTargetOutcome::Current(Box::new(current)))
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), NamespaceTargetError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.generation.recheck(journal, clock)?;
        if identity(&self.generation) != self.allocation.identity
            || self.generation.generation() != self.allocation.observed_generation
            || self.generation.audit_digest() != &self.allocation.observed_audit_digest
            || signed_target(&self.generation) != self.allocation.target_generation
        {
            return Err(NamespaceTargetError::Conflict);
        }
        let history = History::load(journal)?;
        if history.latest.get(&self.allocation.identity) != Some(&self.allocation) {
            return Err(NamespaceTargetError::Conflict);
        }
        self.generation.recheck(journal, clock)?;
        Ok(())
    }
}

/// Reports whether the current assignment already names an allocated target.
pub enum NamespaceTargetOutcome {
    /// The retained live proof and signed assignment agree on the allocation.
    Current(Box<CurrentNamespaceTarget>),
    /// The signed assignment must advance before this allocation can be used.
    AdvanceRequired(NamespaceTargetAdvanceV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    identity: Identity,
    observed_generation: u64,
    observed_audit_digest: [u8; 32],
    target_generation: u64,
    predecessor: [u8; 32],
    digest: [u8; 32],
}

impl Record {
    fn transaction(&self) -> Result<JournalTransaction, NamespaceTargetError> {
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(&self.digest[..16]);
        Ok(JournalTransaction::new(
            transaction_id,
            vec![
                JournalRecord::put(NAMESPACE, self.key(), self.encode()),
                JournalRecord::put(NAMESPACE, head_key(self.identity), self.head()),
            ],
        )?)
    }

    const fn advance(&self, payload_scope_handle: [u8; 32]) -> NamespaceTargetAdvanceV1 {
        NamespaceTargetAdvanceV1 {
            sandbox: SandboxId::from_bytes(self.identity.0),
            incarnation: IncarnationId::from_bytes(self.identity.1),
            observed_generation: self.observed_generation,
            observed_audit_digest: self.observed_audit_digest,
            target_generation: self.target_generation,
            allocation_digest: self.digest,
            payload_scope_handle,
        }
    }
}

#[derive(Default)]
struct History {
    latest: BTreeMap<Identity, Record>,
    count: usize,
}

impl History {
    fn load(journal: &mut Journal) -> Result<Self, NamespaceTargetError> {
        journal.ensure_protected_authority()?;
        let runtimes = RuntimeHistory::load(journal)?;
        let mut history = Self::default();
        let mut heads = BTreeMap::new();
        let mut bytes = 0usize;
        for (index, (key, value)) in journal.records(NAMESPACE).enumerate() {
            bytes = bytes
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(NamespaceTargetError::Capacity)?;
            if index >= MAXIMUM_HISTORY * 2 || bytes > MAXIMUM_BYTES {
                return Err(NamespaceTargetError::Capacity);
            }
            match key.first() {
                Some(b't') => {
                    if history.count >= MAXIMUM_HISTORY {
                        return Err(NamespaceTargetError::Capacity);
                    }
                    let record = Record::decode(value)?;
                    if key != record.key()
                        || runtimes.record_digest(record.identity, record.observed_generation)
                            != Some(record.observed_audit_digest)
                    {
                        return Err(NamespaceTargetError::CorruptState);
                    }
                    history.append(record)?;
                }
                Some(b'h') => {
                    let (identity, head) = format::decode_head(key, value)?;
                    if heads.len() >= MAXIMUM_HISTORY || heads.insert(identity, head).is_some() {
                        return Err(NamespaceTargetError::CorruptState);
                    }
                }
                _ => return Err(NamespaceTargetError::CorruptState),
            }
        }
        if heads.len() != history.latest.len()
            || history.latest.iter().any(|(identity, record)| {
                heads.get(identity)
                    != Some(&(
                        record.observed_generation,
                        record.target_generation,
                        record.digest,
                    ))
            })
        {
            return Err(NamespaceTargetError::CorruptState);
        }
        Ok(history)
    }

    fn append(&mut self, record: Record) -> Result<(), NamespaceTargetError> {
        let previous = self.latest.get(&record.identity);
        if record.predecessor != previous.map_or([0; 32], |record| record.digest) {
            return Err(NamespaceTargetError::CorruptState);
        }
        if let Some(previous) = previous {
            let observed_delta = record
                .observed_generation
                .checked_sub(previous.observed_generation)
                .filter(|delta| *delta > 0)
                .ok_or(NamespaceTargetError::CorruptState)?;
            if previous.target_generation.checked_add(observed_delta)
                != Some(record.target_generation)
            {
                return Err(NamespaceTargetError::CorruptState);
            }
        }
        self.latest.insert(record.identity, record);
        self.count += 1;
        Ok(())
    }

    fn select(
        &self,
        identity: Identity,
        observed_generation: u64,
        observed_audit_digest: [u8; 32],
        signed_target: u64,
    ) -> Result<(Record, bool), NamespaceTargetError> {
        if let Some(previous) = self.latest.get(&identity) {
            if observed_generation == previous.observed_generation {
                if observed_audit_digest != previous.observed_audit_digest {
                    return Err(NamespaceTargetError::Conflict);
                }
                return Ok((previous.clone(), false));
            }
            let observed_delta = observed_generation
                .checked_sub(previous.observed_generation)
                .filter(|delta| *delta > 0)
                .ok_or(NamespaceTargetError::Conflict)?;
            let target_generation = previous
                .target_generation
                .checked_add(observed_delta)
                .ok_or(NamespaceTargetError::Capacity)?;
            return self.new_record(
                identity,
                observed_generation,
                observed_audit_digest,
                target_generation,
                previous.digest,
            );
        }

        self.new_record(
            identity,
            observed_generation,
            observed_audit_digest,
            signed_target,
            [0; 32],
        )
    }

    fn new_record(
        &self,
        identity: Identity,
        observed_generation: u64,
        observed_audit_digest: [u8; 32],
        target_generation: u64,
        predecessor: [u8; 32],
    ) -> Result<(Record, bool), NamespaceTargetError> {
        if self.count >= MAXIMUM_HISTORY {
            return Err(NamespaceTargetError::Capacity);
        }
        let mut record = Record {
            identity,
            observed_generation,
            observed_audit_digest,
            target_generation,
            predecessor,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        Record::decode(&record.encode())?;
        Ok((record, true))
    }
}

fn identity(generation: &CurrentRuntimeGeneration) -> Identity {
    let binding = generation.scope().binding();
    (
        *binding.sandbox().as_bytes(),
        *binding.manifest().manifest().incarnation().as_bytes(),
    )
}

fn signed_target(generation: &CurrentRuntimeGeneration) -> u64 {
    generation
        .scope()
        .binding()
        .manifest()
        .manifest()
        .namespace_generation()
        .get()
}

fn head_key(identity: Identity) -> Vec<u8> {
    let mut key = vec![b'h'];
    key.extend_from_slice(&identity.0);
    key.extend_from_slice(&identity.1);
    key
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), NamespaceTargetError> {
    History::load(journal).map(|_| ())
}
