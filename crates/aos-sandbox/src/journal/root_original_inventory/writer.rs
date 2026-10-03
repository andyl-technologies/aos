//! Same-instance named Query preparation, attempted append and actual readback.
//!
//! Preparation parks owner input before fallible checks and the complete coupled
//! candidate before preflight. Commit latches before I/O. Actual cut/TX metadata
//! is parked before row cloning; rows precede decoding and installation checks.
//! Preparation and commit failures permanently disable that candidate while
//! retaining its bytes and any readback. Immutable read checkers do not change
//! captured DATA or latches; their caller must fail the enclosing install/send
//! boundary on any error.

use std::path::Path;

use aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2;

use super::*;
use crate::journal::{
    CacheMutationGateV1, Journal, OriginalRootProtectedReadbackV5, ProtectedAuthorityScope,
    ProtectedJournalAuthority, ProtectedJournalSnapshot, RootSourceGenesisTransitionV1,
    SourceProjectAdmissionTransition, authority_preflight_digest, controller_source_genesis,
    source_tree_genesis, validate_reserved_capacity,
};

/// Borrows the same fixed Mount journal for exact original-root Query6 edges.
pub struct MountOriginalInventoryJournalAuthorityV6<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

/// Retains owned owner input, complete candidate and a one-shot append latch.
#[must_use]
pub struct PreparedOriginalInventoryAppendV6 {
    owners: JournalTransaction,
    snapshot: ProtectedJournalSnapshot,
    root: [u8; 32],
    derived: Option<DerivedAppend>,
    digest: Option<[u8; 32]>,
    preflight_complete: bool,
    attempted: bool,
    failed: bool,
}

/// Retains actual physical Query rows before fallible decoding and installation.
#[must_use]
pub struct OriginalInventoryProtectedReadbackV6 {
    snapshot: ProtectedJournalSnapshot,
    rows: Option<State>,
    graph: Option<RootNativeHeldGraphV2>,
    root: [u8; 32],
    query: [u8; 32],
    transaction: JournalTransaction,
    kind: Kind,
    validated: bool,
}

/// Latches failed preparation without removing its retained candidate.
struct PreparationBoundaryV6<'candidate> {
    candidate: &'candidate mut PreparedOriginalInventoryAppendV6,
    succeeded: bool,
}

impl Drop for PreparationBoundaryV6<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.candidate.failed = true;
        }
    }
}

/// Retains actual append ambiguity until its complete readback is validated.
struct CommitBoundaryV6<'writer, 'journal, 'candidate> {
    writer: &'writer mut MountOriginalInventoryJournalAuthorityV6<'journal>,
    candidate: &'candidate mut PreparedOriginalInventoryAppendV6,
    // Only ambiguity entered in this invocation poisons the Journal. Rejecting
    // reuse of an already successful candidate is not a new physical attempt.
    append_entered: bool,
    succeeded: bool,
}

impl Drop for CommitBoundaryV6<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.candidate.failed = true;
            if self.append_entered {
                self.writer.authority.journal.poisoned = true;
            }
        }
    }
}

impl<'journal> MountOriginalInventoryJournalAuthorityV6<'journal> {
    /// Claims only the current fixed named Query scope through its retained lock.
    ///
    /// # Errors
    /// Rejects unavailable protection/currentness, startup replay or graph debt.
    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        journal.ensure_protected_authority()?;
        let writer = Self {
            authority: ProtectedJournalAuthority {
                journal,
                namespace: RecordNamespace::MountSourceAcquisition,
                scope: ProtectedAuthorityScope::RootOriginalInventoryV6,
            },
        };
        writer.require_current()?;
        writer.authority.validate_root_local_startup_replay_v4()?;
        writer.current_graph()?;
        Ok(writer)
    }

    fn require_current(&self) -> Result<(), JournalError> {
        self.authority.journal.ensure_protected_authority()?;
        self.authority.validate_held_root_owned_at(
            Path::new("/var/lib/aos/sandbox-mount"),
            "mount.journal",
        )?;
        if self.authority.scope != ProtectedAuthorityScope::RootOriginalInventoryV6 {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Returns the complete current graph after all-family and Query rejoin.
    ///
    /// # Errors
    /// Rejects stale fixed storage, unsupported families, invalid graph/debt,
    /// opened bounds or insufficient all-family physical sequence headroom.
    pub fn current_graph(&self) -> Result<RootNativeHeldGraphV2, JournalError> {
        self.require_current()?;
        let journal = &self.authority.journal;

        require_supported_families(&canonical_reservations(&journal.state)?)?;
        super::pending(&journal.state, journal.limits)?;
        crate::journal::root_original_native::pending(&journal.state, journal.limits)?;
        validate_reserved_capacity(
            &journal.state,
            journal.materialized_bytes,
            &[],
            None,
            journal.file.metadata()?.len(),
            journal.committed_transactions,
            journal.limits,
            None,
        )?;
        require_sequence_headroom(&journal.state, journal.next_sequence)?;

        let checked = graph(&journal.state)?;
        self.require_current()?;

        Ok(checked)
    }

    /// Returns the exact current named Query physical cut.
    ///
    /// # Errors
    /// Rejects unavailable currentness, malformed metadata or unfunded debt.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.current_graph()?;
        self.authority.snapshot()
    }

    /// Validates exact current instance, namespace, named scope and sequence.
    ///
    /// # Errors
    /// Rejects stale snapshots and invalid current graph or funding.
    pub fn validate_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.current_graph()?;
        self.authority.validate_mount_source_acquisition_snapshot(snapshot)
    }

    /// Borrows one current namespace40 row after complete graph/floor validation.
    ///
    /// # Errors
    /// Rejects stale storage, malformed retained metadata or insufficient funding.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.current_graph()?;
        self.authority.mount_source_acquisition_get(key)
    }

    /// Checks an actual historical same-instance phase11 origin under this cut.
    ///
    /// # Errors
    /// Rejects replaced instances, wrong origin scope/phase, changed immutable
    /// original rows or Root5 bytes, and any current Query-cut change.
    pub fn validate_original_root_closed_origin_v6(
        &self,
        origin: &OriginalRootProtectedReadbackV5,
    ) -> Result<(), JournalError> {
        let current = self.snapshot()?;
        self.validate_snapshot(&current)?;

        crate::journal::root_original_native::require_original_root_closed_origin_v6(
            origin,
            self.authority.journal,
        )?;

        self.validate_snapshot(&current)
    }

    /// Parks exact admission input before preparing Q1/H plus its own floor.
    ///
    /// # Errors
    /// Rejects occupied custody, nonreservation DATA, changed originals, fences,
    /// limits or headroom. Failed input/candidate remains owned and uncommittable.
    pub fn prepare_reservation(
        &self,
        root: [u8; 32],
        owners: &JournalTransaction,
        slot: &mut Option<PreparedOriginalInventoryAppendV6>,
    ) -> Result<(), JournalError> {
        self.prepare(root, None, owners, slot)
    }

    /// Parks an actual first response and derives status transfer or Complete.
    ///
    /// # Errors
    /// Rejects occupied custody, nonresponse DATA, wrong Query/root association,
    /// old count-one debt, changed originals, fences, limits or headroom.
    pub fn prepare_disposition(
        &self,
        root: [u8; 32],
        query: [u8; 32],
        owners: &JournalTransaction,
        slot: &mut Option<PreparedOriginalInventoryAppendV6>,
    ) -> Result<(), JournalError> {
        self.prepare(root, Some(query), owners, slot)
    }

    fn prepare(
        &self,
        root: [u8; 32],
        disposition: Option<[u8; 32]>,
        owners: &JournalTransaction,
        slot: &mut Option<PreparedOriginalInventoryAppendV6>,
    ) -> Result<(), JournalError> {
        if let Some(existing) = slot.as_mut() {
            existing.failed = true;
            return Err(invalid());
        }

        *slot = Some(PreparedOriginalInventoryAppendV6 {
            owners: owners.clone(),
            snapshot: self.authority.current_snapshot(),
            root,
            derived: None,
            digest: None,
            preflight_complete: false,
            attempted: false,
            failed: false,
        });

        let mut boundary = PreparationBoundaryV6 {
            candidate: slot.as_mut().ok_or_else(invalid)?,
            succeeded: false,
        };
        let candidate = &mut *boundary.candidate;
        let result = (|| {
            self.validate_snapshot(&candidate.snapshot)?;
            let query = changed_query(&candidate.owners)?;
            if disposition.is_some_and(|expected| query != expected) {
                return Err(invalid());
            }

            candidate.derived = Some(derive(
                &self.authority.journal.state,
                &candidate.owners,
                candidate.root,
                query,
                self.authority.journal.limits,
            )?);

            // The complete coupled candidate is retained before any postcheck.
            let derived = candidate.derived.as_ref().ok_or_else(invalid)?;
            if disposition.is_none() != (derived.kind == Kind::Reserved) {
                return Err(invalid());
            }
            validate_derived(
                &self.authority.journal.state,
                derived,
                self.authority.journal.limits,
            )?;
            self.preflight(derived)?;
            self.validate_snapshot(&candidate.snapshot)?;

            candidate.digest = Some(authority_preflight_digest(std::slice::from_ref(
                &derived.transaction,
            )));
            candidate.preflight_complete = true;
            Ok(())
        })();
        boundary.succeeded = result.is_ok();

        result
    }

    fn preflight(&self, derived: &DerivedAppend) -> Result<(), JournalError> {
        let journal = &self.authority.journal;
        let frames = u64::try_from(derived.transaction.records().len())
            .map_err(|_| JournalError::SequenceExhausted)?
            .checked_add(2)
            .ok_or(JournalError::SequenceExhausted)?;
        let next = journal.next_sequence.checked_add(frames)
            .ok_or(JournalError::SequenceExhausted)?;

        require_sequence_headroom(&materialize(&journal.state, &derived.transaction), next)?;
        journal.preflight_with_cache_gate(
            std::slice::from_ref(&derived.transaction),
            None,
            true,
            false,
            None,
            None,
            None,
            Some(edge(derived)),
            CacheMutationGateV1::Ordinary,
        )
    }

    /// Attempts the exact append once and parks actual rows before postchecks.
    ///
    /// # Errors
    /// Rejects failed/unprepared/repeated attempts, occupied readback custody or
    /// stale input. An append/readback error retains candidate and attempted TX;
    /// actual rows, when obtained, remain parked even if later checks fail.
    pub fn commit_prepared(
        &mut self,
        prepared: &mut PreparedOriginalInventoryAppendV6,
        readback: &mut Option<OriginalInventoryProtectedReadbackV6>,
    ) -> Result<(), JournalError> {
        let mut boundary = CommitBoundaryV6 {
            writer: self,
            candidate: prepared,
            append_entered: false,
            succeeded: false,
        };
        let writer = &mut *boundary.writer;
        let prepared = &mut *boundary.candidate;
        let append_entered = &mut boundary.append_entered;
        if prepared.failed
            || prepared.attempted
            || !prepared.preflight_complete
            || readback.is_some()
        {
            prepared.failed = true;
            return Err(invalid());
        }

        let result = (|| {
            writer.validate_snapshot(&prepared.snapshot)?;
            let derived = prepared.derived.as_ref().ok_or_else(invalid)?;
            let digest = authority_preflight_digest(std::slice::from_ref(&derived.transaction));
            if prepared.digest != Some(digest) {
                return Err(invalid());
            }
            writer.preflight(derived)?;

            // This clone is DATA only and precedes I/O. The original exact TX
            // remains in the candidate even if cloning unwinds.
            let transaction = derived.transaction.clone();

            prepared.attempted = true;
            *append_entered = true;
            writer.authority.journal.commit_with_cache_gate(
                &derived.transaction,
                None,
                true,
                false,
                false,
                false,
                false,
                SourceProjectAdmissionTransition::None,
                controller_source_genesis::ControllerSourceGenesisTransition::None,
                source_tree_genesis::SourceGenesisTransitionV1::None,
                RootSourceGenesisTransitionV1::None,
                Some(edge(derived)),
                CacheMutationGateV1::Ordinary,
            )?;

            *readback = Some(OriginalInventoryProtectedReadbackV6 {
                snapshot: writer.authority.current_snapshot(),
                rows: None,
                graph: None,
                root: derived.root,
                query: derived.query,
                transaction,
                kind: derived.kind,
                validated: false,
            });

            let actual = readback.as_mut().ok_or_else(invalid)?;
            // Actual cut/TX metadata is already retained. A failed row clone
            // leaves this partial readback and the real Journal post-state.
            actual.rows = Some(writer.authority.journal.state.clone());
            actual.graph = Some(writer.validate_actual_rows(actual)?);
            actual.validated = true;
            Ok(())
        })();
        boundary.succeeded = result.is_ok();

        result
    }

    fn validate_actual_rows(
        &self,
        actual: &OriginalInventoryProtectedReadbackV6,
    ) -> Result<RootNativeHeldGraphV2, JournalError> {
        self.validate_snapshot(&actual.snapshot)?;
        let journal = &self.authority.journal;
        let rows = actual.rows.as_ref().ok_or_else(invalid)?;
        if &journal.state != rows
            || !journal.transaction_ids.contains(actual.transaction.id())
            || actual.transaction.records().iter().any(|record| {
                journal.get(record.namespace(), record.key()) != record.value()
            })
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        let checked = graph(rows)?;
        root_floor(rows, &checked, actual.root)?.validate_graph(&checked, journal.limits)?;
        let query = checked.legacy().provider_attempts.get(&actual.query)
            .ok_or_else(invalid)?;
        match (actual.kind, &query.state) {
            (Kind::Reserved, ProviderAttemptStateV2::Reserved) if query.revision == 1 => {}
            (
                Kind::NonCompleteConsumed,
                ProviderAttemptStateV2::DispositionConsumed { status, .. },
            )
                if query.revision == 2 && *status != ProviderStatusV2::Complete => {}
            (
                Kind::CompleteConsumed,
                ProviderAttemptStateV2::DispositionConsumed {
                    status: ProviderStatusV2::Complete, ..
                },
            )
                if query.revision == 2 => {}
            _ => return Err(invalid()),
        }
        let floor = pending(rows, journal.limits)?.into_iter()
            .find(|(floor, _)| floor.data().owner_id == actual.query);
        match (actual.kind, floor) {
            (Kind::CompleteConsumed, None) => {}
            (Kind::Reserved | Kind::NonCompleteConsumed, Some((_, root))) if root == actual.root => {}
            _ => return Err(invalid()),
        }

        self.authority.validate_mount_source_acquisition_snapshot(&actual.snapshot)?;
        Ok(checked)
    }

    /// Validates actual current Query readback separately from historical origin.
    ///
    /// # Errors
    /// Rejects undecoded, substituted or stale actual rows, scope, root, Query,
    /// transaction, graph or floor profile, including any later append.
    pub fn validate_readback(
        &self,
        actual: &OriginalInventoryProtectedReadbackV6,
    ) -> Result<(), JournalError> {
        if !actual.validated {
            return Err(invalid());
        }

        let checked = self.validate_actual_rows(actual)?;
        let retained = actual.graph.as_ref().ok_or_else(invalid)?;
        if retained.canonical_records() != checked.canonical_records() {
            return Err(invalid());
        }

        Ok(())
    }
}

fn changed_query(owners: &JournalTransaction) -> Result<[u8; 32], JournalError> {
    let mut query = None;
    for record in owners.records() {
        if record.namespace() != RecordNamespace::MountSourceAcquisition {
            return Err(invalid());
        }
        let decoded = decode_mount_source_state_record_v2(
            record.key(), record.value().ok_or_else(invalid)?,
        ).map_err(|_| invalid())?;
        if let StoredRecordV2::ProviderQueryAttempt { value } = decoded {
            if query.replace(value.attempt_id).is_some() {
                return Err(invalid());
            }
        }
    }
    query.ok_or_else(invalid)
}

fn edge(derived: &DerivedAppend) -> RootOwnerEdge {
    RootOwnerEdge::OriginalInventory {
        root: derived.root,
        query: derived.query,
        kind: derived.kind,
    }
}

impl OriginalInventoryProtectedReadbackV6 {
    /// Borrows validated captured graph DATA for private installation.
    ///
    /// This does not establish fresh physical currentness; the named writer's
    /// `validate_readback` must succeed at the installation boundary.
    ///
    /// # Errors
    /// Rejects a parked readback whose decoding or postchecks did not complete.
    pub fn graph(&self) -> Result<&RootNativeHeldGraphV2, JournalError> {
        if !self.validated {
            return Err(invalid());
        }
        self.graph.as_ref().ok_or_else(invalid)
    }

    /// Returns the original Root association as DATA, never live custody.
    #[must_use]
    pub const fn root_attempt(&self) -> [u8; 32] {
        self.root
    }

    /// Returns the actual Query Attempt identity.
    #[must_use]
    pub const fn query_attempt(&self) -> [u8; 32] {
        self.query
    }

    /// Returns the exact committed owner TX identity for comparison.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        *self.transaction.id()
    }

    /// Returns the captured physical NEXT sequence for diagnostics only.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.snapshot.sequence()
    }
}
