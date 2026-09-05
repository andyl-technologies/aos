//! Durable numbering of freshly authenticated runtime executions.
//!
//! The protected journal retains audit facts, never reconstructed live pins:
//!
//! ```text
//! g<sandbox:16><incarnation:16><generation:8> = immutable AOSNSG01 record
//! h<sandbox:16><incarnation:16> = latest generation:8 + record digest:32
//! ```
//!
//! Integers are big endian. History is contiguous, hash-linked, and bounded to
//! 4096 records across all identities. Heads must name the latest record. A
//! generation does not attest attachment replay, readiness, or admission.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{RawPairedClockSample, SandboxId};

use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_authority::{
    RuntimeAuthorityError, RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
    binding_in_validated_namespace,
};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

use super::{CurrentRuntimeScope, CurrentRuntimeScopeError};

mod format;
#[cfg(test)]
mod tests;

const NAMESPACE: RecordNamespace = RecordNamespace::RuntimeGeneration;
const MAXIMUM_HISTORY: usize = 4096;
const MAXIMUM_BYTES: usize = 4 * 1024 * 1024;
pub(super) type Identity = ([u8; 16], [u8; 16]);

/// Reports rejected generation history or unavailable current runtime authority.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeGenerationError {
    /// Retained history, its head, or its originating binding is inconsistent.
    #[error("runtime generation history is corrupt")]
    CorruptState,
    /// A scope handle was reused or the retained generation is no longer current.
    #[error("runtime generation conflicts with the current execution")]
    Conflict,
    /// Fixed replay capacity or the monotone generation counter was exhausted.
    #[error("runtime generation capacity is exhausted")]
    Capacity,
    /// Protected journal provenance, health, or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Protected runtime-holder history failed validation.
    #[error(transparent)]
    Authority(#[from] RuntimeAuthorityError),
    /// Fresh authority, fixed-deadline, or retained kernel checks failed.
    #[error(transparent)]
    Scope(#[from] CurrentRuntimeScopeError),
}

/// Retains a fresh runtime proof associated with a durable generation number.
///
/// Only the controller can construct this value, by consuming a real current
/// runtime scope. It cannot be cloned or restored from journal bytes. Its
/// original observation deadline is unchanged. Before use, the controller must
/// recheck both the live proof and the protected generation head. Neither the
/// number nor its digest proves that filesystem attachments have been replayed.
///
/// ```compile_fail
/// use aos_sandbox::runtime_scope::CurrentRuntimeGeneration;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CurrentRuntimeGeneration>();
/// ```
pub struct CurrentRuntimeGeneration {
    scope: CurrentRuntimeScope,
    record: Record,
}

impl CurrentRuntimeGeneration {
    /// Returns this controller's observed execution number within the incarnation.
    ///
    /// This audit sequence is not automatically the signed assignment's
    /// expected namespace generation. Replay must separately bind that target
    /// to the current proof before dispatching any authorized mount operation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.record.generation
    }

    /// Borrows the immutable audit digest, which grants no live authority.
    #[must_use]
    pub const fn audit_digest(&self) -> &[u8; 32] {
        &self.record.digest
    }

    /// Borrows the original current-runtime proof without extending its deadline.
    #[must_use]
    pub const fn scope(&self) -> &CurrentRuntimeScope {
        &self.scope
    }

    pub(crate) fn track<T>(
        scope: CurrentRuntimeScope,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<Self, RuntimeGenerationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        scope.recheck(journal, clock)?;
        let facts = Facts::from_scope(&scope)?;
        let history = History::load(journal)?;
        let (record, changed) = history.select(facts)?;
        if changed {
            scope.recheck(journal, clock)?;
            journal.commit(&record.transaction()?)?;
        }

        // An elapsed deadline or failed post-commit check leaves only inert
        // audit state. A later fresh observation must still replay attachments.
        let current = Self { scope, record };
        current.recheck(journal, clock)?;
        Ok(current)
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), RuntimeGenerationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.scope.recheck(journal, clock)?;
        let history = History::load(journal)?;
        if history.latest.get(&self.record.facts.identity) != Some(&self.record) {
            return Err(RuntimeGenerationError::Conflict);
        }
        // Replay itself consumes time; do not return an expired live proof.
        self.scope.recheck(journal, clock)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Facts {
    pub(super) identity: Identity,
    pub(super) runtime: [u8; 32],
    pub(super) scope: [u8; 32],
    pub(super) pid: u32,
    pub(super) leaf_cgroup: u64,
    pub(super) anchor: u64,
    pub(super) binding_revision: u64,
    pub(super) binding_digest: [u8; 32],
}

impl Facts {
    fn from_scope(scope: &CurrentRuntimeScope) -> Result<Self, RuntimeGenerationError> {
        let binding = scope.binding();
        let observed = scope.observed();
        Ok(Self {
            identity: (
                *binding.sandbox().as_bytes(),
                *binding.manifest().manifest().incarnation().as_bytes(),
            ),
            runtime: *observed.runtime_handle(),
            scope: *observed.payload_scope_handle(),
            pid: observed.process_info().pid(),
            leaf_cgroup: observed
                .process_info()
                .cgroup_id()
                .ok_or(RuntimeGenerationError::Conflict)?,
            anchor: observed.anchor().kernel_id(),
            binding_revision: binding.revision(),
            binding_digest: *binding.digest().as_bytes(),
        })
    }

    fn same_execution(&self, other: &Self) -> bool {
        // The Host preserves its opaque physical scope across independently
        // authorized assignment updates. The assignment-derived runtime alias
        // can therefore change without changing namespaces. The record keeps
        // its original alias/binding for audit; live checks use the fresh pair.
        self.identity == other.identity
            && self.scope == other.scope
            && self.pid == other.pid
            && self.leaf_cgroup == other.leaf_cgroup
            && self.anchor == other.anchor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Record {
    pub(super) facts: Facts,
    pub(super) generation: u64,
    pub(super) predecessor: [u8; 32],
    pub(super) digest: [u8; 32],
}

impl Record {
    pub(super) fn transaction(&self) -> Result<JournalTransaction, RuntimeGenerationError> {
        let mut id = [0; 16];
        id.copy_from_slice(&self.digest[..16]);
        Ok(JournalTransaction::new(
            id,
            vec![
                JournalRecord::put(NAMESPACE, self.key(), self.encode()),
                JournalRecord::put(NAMESPACE, head_key(self.facts.identity), self.head()),
            ],
        )?)
    }
}

#[derive(Default)]
pub(super) struct History {
    latest: BTreeMap<Identity, Record>,
    records: BTreeMap<(Identity, u64), [u8; 32]>,
    scopes: BTreeSet<(Identity, [u8; 32])>,
    count: usize,
}

impl History {
    pub(super) fn load(journal: &mut Journal) -> Result<Self, RuntimeGenerationError> {
        journal.ensure_protected_authority()?;
        // Keep the exclusive journal borrow through all historical lookups.
        RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?;
        let mut history = Self::default();
        let mut heads = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        let mut bytes = 0usize;
        for (index, (key, value)) in journal.records(NAMESPACE).enumerate() {
            bytes = bytes
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(RuntimeGenerationError::Capacity)?;
            if index >= MAXIMUM_HISTORY * 2 || bytes > MAXIMUM_BYTES {
                return Err(RuntimeGenerationError::Capacity);
            }
            match key.first() {
                Some(b'g') => {
                    if history.count >= MAXIMUM_HISTORY {
                        return Err(RuntimeGenerationError::Capacity);
                    }
                    let record = Record::decode(value)?;
                    if key != record.key() {
                        return Err(RuntimeGenerationError::CorruptState);
                    }
                    let facts = &record.facts;
                    let binding_key = (facts.identity.0, facts.binding_revision);
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        bindings.entry(binding_key)
                    {
                        let binding = binding_in_validated_namespace(
                            journal,
                            SandboxId::from_bytes(facts.identity.0),
                            facts.binding_revision,
                        )?;
                        if binding.state() != RuntimeAuthorityStateV1::Bound {
                            return Err(RuntimeGenerationError::CorruptState);
                        }
                        entry.insert((
                            *binding.manifest().manifest().incarnation().as_bytes(),
                            *binding.digest().as_bytes(),
                            aos_sandbox_protocol::semantics::host::runtime_handle_v1(
                                binding.manifest().manifest().incarnation().as_bytes(),
                                binding.manifest().manifest().epoch().get(),
                                binding.assignment_digest().as_bytes(),
                            ),
                        ));
                    }
                    if bindings.get(&binding_key)
                        != Some(&(facts.identity.1, facts.binding_digest, facts.runtime))
                    {
                        return Err(RuntimeGenerationError::CorruptState);
                    }
                    history.append(record)?;
                }
                Some(b'h') => {
                    let (identity, head) = format::decode_head(key, value)?;
                    if heads.len() >= MAXIMUM_HISTORY || heads.insert(identity, head).is_some() {
                        return Err(RuntimeGenerationError::CorruptState);
                    }
                }
                _ => return Err(RuntimeGenerationError::CorruptState),
            }
        }
        if heads.len() != history.latest.len()
            || history.latest.iter().any(|(identity, record)| {
                heads.get(identity) != Some(&(record.generation, record.digest))
            })
        {
            return Err(RuntimeGenerationError::CorruptState);
        }
        Ok(history)
    }

    fn append(&mut self, record: Record) -> Result<(), RuntimeGenerationError> {
        let previous = self.latest.get(&record.facts.identity);
        let expected = previous.map_or(Some(1), |record| record.generation.checked_add(1));
        if Some(record.generation) != expected
            || record.predecessor != previous.map_or([0; 32], |record| record.digest)
            || self
                .records
                .insert((record.facts.identity, record.generation), record.digest)
                .is_some()
            || !self
                .scopes
                .insert((record.facts.identity, record.facts.scope))
        {
            return Err(RuntimeGenerationError::CorruptState);
        }
        self.latest.insert(record.facts.identity, record);
        self.count += 1;
        Ok(())
    }

    pub(super) fn record_digest(&self, identity: Identity, generation: u64) -> Option<[u8; 32]> {
        self.records.get(&(identity, generation)).copied()
    }

    pub(super) fn select(&self, facts: Facts) -> Result<(Record, bool), RuntimeGenerationError> {
        let previous = self.latest.get(&facts.identity);
        if let Some(record) = previous
            && record.facts.same_execution(&facts)
        {
            return Ok((record.clone(), false));
        }
        if self.scopes.contains(&(facts.identity, facts.scope)) {
            return Err(RuntimeGenerationError::Conflict);
        }
        if self.count >= MAXIMUM_HISTORY {
            return Err(RuntimeGenerationError::Capacity);
        }
        let generation = previous
            .map_or(Some(1), |record| record.generation.checked_add(1))
            .ok_or(RuntimeGenerationError::Capacity)?;
        let mut record = Record {
            facts,
            generation,
            predecessor: previous.map_or([0; 32], |record| record.digest),
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        // Keep the write path subject to the same closed-format invariants as
        // restart replay, including reserved kernel identifiers and digests.
        Record::decode(&record.encode())?;
        Ok((record, true))
    }
}

fn head_key(identity: Identity) -> Vec<u8> {
    let mut key = vec![b'h'];
    key.extend_from_slice(&identity.0);
    key.extend_from_slice(&identity.1);
    key
}

/// Validates inert generation history before reconciler effects can run.
///
/// # Errors
///
/// Rejects unprotected or unhealthy storage, inconsistent binding references,
/// malformed history or heads, and exhausted replay bounds.
pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), RuntimeGenerationError> {
    History::load(journal).map(|_| ())
}
