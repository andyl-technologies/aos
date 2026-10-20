//! Binds Source's fixed readonly physical prefix to the sole indexed replay.
//!
//! The same private Source receiving context prepays the owner, captured native
//! extent and every semantic frontier. Physical acquisition, rooted names,
//! canonical parsing/indexing, whole semantic replay and suffix comparison use
//! their existing lower engines. This owner has no writable Journal handoff.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1 as JournalError, CanonicalReplayExtentDataV1,
    CanonicalReplayOriginalV1,
    coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1},
};
use aos_sandbox_core::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{
    ReadOnlyAcquisitionOriginalsV1, ReadOnlyJournalNameWitness, ReadonlyNameArchiveV1,
    FileIdentity, FileIdentityOriginalsV1, CapturedReplayPrefixPostV1,
};
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;
use aos_sandbox_protocol::domain_ledger::{
    protected_names::ProtectedJournalNamesV1,
    readonly::IdempotencyDecisionV1,
    transaction::JournalLimits,
};

use crate::native::semantic::{
    FixedColdNativeStageV1 as _, FixedColdSemanticOriginalV1, SourcePaidReplayErrorV1,
    SourcePaidReplayV1, SourceReplayFundingV1, move_cold_remainder_data_v1,
};
use super::SourceReadonlyReceivingContextV1;

mod query;
use aos_sandbox_ledger_replay::delete_pending::SourceDeletePendingReplayDataV1 as SourceDeletePendingNativeOriginalsV1;

/// Identifies a returned name refusal without replacing its actual raw cause.
#[derive(Debug, thiserror::Error)]
pub(super) enum SourceReadonlyNativeErrorV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("selected readonly name observation {0} refused")]
    Names(u8),
}

#[derive(Clone, Copy)]
enum First { Preparation, InitialNames, Replay, ReplayMetadata, ReplayTail, ReplayNames }

type Semantics = FixedColdSemanticOriginalV1<SourcePaidReplayErrorV1<JournalError>>;

pub(super) struct SourceReadonlyNativeOriginalV1 {
    physical: ReadOnlyAcquisitionOriginalsV1<JournalError>,
    preparation: Option<Result<(), JournalError>>,
    captured_metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<CanonicalReplayExtentDataV1, aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1>>,
    witness: Option<ReadOnlyJournalNameWitness>,
    names: ReadonlyNameArchiveV1<JournalError>,
    initial_names: Option<Result<(), SourceReadonlyNativeErrorV1>>,
    replay: CanonicalReplayOriginalV1,
    index: BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    index_original: CanonicalReplayIndexOriginalsV1,
    semantic: Semantics,
    delete_pending: Option<SourceDeletePendingNativeOriginalsV1>,
    semantic_result: Option<Result<(), JournalError>>,
    replay_entry: Option<Result<(), aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1>>,
    remainder: Option<ColdReplayRemainderDataV1>,
    replay_names: Option<Result<(), SourceReadonlyNativeErrorV1>>,
    entry_identity: FileIdentityOriginalsV1<JournalError>,
    entry_identity_result: Option<Result<(), JournalError>>,
    replay_coordinates: Option<aos_sandbox_journal::replay::NativeReplayCoordinates>,
    captured_prefix: Option<CapturedReplayPrefixPostV1<JournalError>>,
    tail_seek: Option<std::io::Result<u64>>,
    tail: Option<Result<u64, JournalError>>,
    next_sequence: u64,
    entered: bool,
    replay_entered: bool,
    first: Option<First>,
}

impl SourceReadonlyNativeOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            physical: ReadOnlyAcquisitionOriginalsV1::new(), preparation: None,
            captured_metadata: None, extent: None, witness: None, names: ReadonlyNameArchiveV1::new(6),
            initial_names: None, replay: CanonicalReplayOriginalV1::new(),
            index: BTreeMap::new(), index_original: CanonicalReplayIndexOriginalsV1::new(),
            semantic: Semantics::new(), delete_pending: None, semantic_result: None, replay_entry: None, remainder: None,
            replay_names: None, entry_identity: FileIdentityOriginalsV1::new(),
            entry_identity_result: None, replay_coordinates: None, captured_prefix: None,
            tail_seek: None, tail: None, next_sequence: 1, entered: false,
            replay_entered: false, first: None,
        }
    }

    pub(super) fn fixed_receiving_demand_v1<Outer>() -> Option<ResourceVector> {
        let path = super::SIGNER_SOURCE_VIEW;
        let name = aos_sandbox_broker::source_receiving::SOURCE_DOMAIN_JOURNAL_V1;
        let names = ReadonlyNameArchiveV1::<JournalError>::receiving_geometry_v1(6, path)?;
        let names = ResourceVector::ZERO
            .with(D::MemoryBytes, names.memory_bytes)
            .with(D::OpenFiles, names.open_files)
            .with(D::MetadataEntries, names.namespace_entries);
        let semantic = Semantics::fixed_demand_v1().ok()?;
        let ancestors = 4_usize;
        let identity = FileIdentityOriginalsV1::<JournalError>::receiving_footprint_v1()?;
        let post = CapturedReplayPrefixPostV1::<JournalError>::receiving_memory_bytes_v1()?;
        let fixed = std::mem::size_of::<Outer>()
            .checked_add(identity.memory_bytes)?
            .checked_add(post)?
            .checked_add(aos_sandbox_journal::recovery::readonly_tail_receiving_bytes_v1()?)?
            .checked_add(std::mem::size_of::<std::fs::Metadata>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<SourcePaidReplayV1<'_, '_, SourceReadonlyReplayFundingV1<'_, '_, '_>>>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<ColdReplayRemainderDataV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<super::comparison::SourceFixedComparisonV1<'_>>().checked_mul(2)?)?
            .checked_add(3 * ancestors * std::mem::size_of::<std::fs::File>())?
            .checked_add(16 * (path.len() + name.len() + 32))?
            .checked_add(32 * 256)?
            .checked_add(ReadOnlyAcquisitionOriginalsV1::<JournalError>::receiving_construction_bytes_v1()?)?;
        let base = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(fixed).ok()?)
            .with(D::OpenFiles, (3 * ancestors + 6) as u64)
            .with(D::MetadataEntries, (3 * ancestors + 14) as u64);
        base.checked_add(names).ok()?.checked_add(semantic).ok()
    }

    pub(super) fn prepare_captured_source_once(
        &mut self, path: &Path, name: &str, limits: JournalLimits, uid: u32,
        directory_identity: (u64, u64), receiving: &mut SourceReadonlyReceivingContextV1<'_, '_>,
    ) {
        if self.entered { return; }
        self.entered = true;
        self.preparation = Some((|| {
            receiving.require_fixed_named_preparation()?;
            self.physical.prepare_directory_once(path, uid, directory_identity)?;
            aos_sandbox_journal::geometry::validate_native_bounds(limits.into())?;
            self.physical.prepare_files_once(name, uid)?;
            let (directory, file, lock) = self.physical.identities()
                .ok_or(JournalError::ProtectedBoundary)?;
            self.witness = Some(ReadOnlyJournalNameWitness::from_original_parts((
                path.to_owned(), name.to_owned(), uid, directory, file, lock,
            )));
            self.captured_metadata = Some(self.physical.file()
                .ok_or(JournalError::ProtectedBoundary)?.metadata());
            let captured = self.captured_metadata.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?.len();
            self.extent = Some(CanonicalReplayExtentDataV1::new(limits, captured));
            self.extent.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            Ok(())
        })());
        if !matches!(self.preparation, Some(Ok(()))) {
            self.first = Some(First::Preparation);
        }
        // Witness availability is the same physical frontier on both outcomes.
        self.initial_names = self.observe_named_currentness();
        if matches!(self.initial_names, Some(Err(_))) {
            self.first.get_or_insert(First::InitialNames);
        }
    }

    pub(super) fn captured_extent(&self) -> Option<&CanonicalReplayExtentDataV1> {
        if self.first.is_some() || self.replay_entered
            || !matches!(self.preparation, Some(Ok(())))
            || !matches!(self.initial_names, Some(Ok(())))
        {
            return None;
        }
        self.extent.as_ref()?.as_ref().ok()
    }

    pub(super) fn replay_captured_source_once(
        &mut self, receiving: &mut SourceReadonlyReceivingContextV1<'_, '_>,
    ) {
        if self.first.is_some() || self.replay_entered { return; }
        self.replay_entered = true;
        self.semantic_result = Some((|| {
            let extent = self.extent.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            receiving.require_captured_file_end(extent.native_bytes())?;
            let file = self.physical.file().ok_or(JournalError::ProtectedBoundary)?;
            self.entry_identity_result = Some(FileIdentity::of_retaining_v1(file, &mut self.entry_identity));
            let file_identity = self.entry_identity.completed_identity().copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            let metadata = self.entry_identity.completed_metadata().cloned()
                .ok_or(JournalError::ProtectedBoundary)?;
            let cursor = match self.replay.begin_semantic_cursor_with_metadata_once(
                file, extent.limits(), extent.native_bytes(), metadata,
            ) {
                Ok(cursor) => { self.replay_entry = Some(Ok(())); cursor }
                Err(cause) => { self.replay_entry = Some(Err(cause)); return Err(JournalError::ProtectedBoundary); }
            };
            let indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
                cursor, &mut self.index, &mut self.index_original,
            );
            let funding = SourceReadonlyReplayFundingV1 { receiving, delete_pending: &mut self.delete_pending,
                captured_end: extent.native_bytes() };
            let mut paid = SourcePaidReplayV1::new(indexed, funding);
            self.semantic.observe_native_once(&mut paid, file_identity, extent.limits())
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let prefix = paid.completed_prefix().ok_or(JournalError::ProtectedBoundary)?;
            self.replay_coordinates = Some(prefix.coordinates());
            Ok(())
        })());
        if !matches!(self.semantic_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Replay);
        }
        // The exact held-file metadata post is owed even when identity,
        // parser/index, suffix or semantic validation already failed.
        if let (Some(file), Some(Ok(before))) = (self.physical.file(), &self.captured_metadata) {
            self.captured_prefix = Some(CapturedReplayPrefixPostV1::observe(file, before));
        }
        if self.captured_prefix.as_ref().is_none_or(|post| post.failure().is_some()) {
            self.first.get_or_insert(First::ReplayMetadata);
        }
        if self.first.is_none() {
            self.tail = Some((|| {
                let coordinates = self.replay_coordinates.ok_or(JournalError::ProtectedBoundary)?;
                let extent = self.extent.as_ref().and_then(|result| result.as_ref().ok())
                    .copied().ok_or(JournalError::ProtectedBoundary)?;
                let file = self.physical.file().ok_or(JournalError::ProtectedBoundary)?;
                let tail = aos_sandbox_journal::recovery::finish_readonly_replayed_tail_v1(
                    file, extent.native_bytes(), coordinates.durable_end, &mut self.tail_seek,
                ).map_err(JournalError::from)?;
                if coordinates.offset != extent.native_bytes()
                    || coordinates.expected_sequence != coordinates.durable_next_sequence
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                self.next_sequence = coordinates.durable_next_sequence;
                self.remainder = self.semantic.take_remainder_once().map(move_cold_remainder_data_v1);
                self.remainder.as_ref().ok_or(JournalError::ProtectedBoundary)?;
                Ok(tail)
            })());
            if !matches!(self.tail, Some(Ok(_))) { self.first.get_or_insert(First::ReplayTail); }
        }
        self.replay_names = self.observe_named_currentness();
        if matches!(self.replay_names, Some(Err(_))) {
            self.first.get_or_insert(First::ReplayNames);
        }
    }

    pub(super) fn observe_named_currentness(&self)
        -> Option<Result<(), SourceReadonlyNativeErrorV1>>
    {
        Some(self.names.observe(self.witness.as_ref()?, self.physical.file()?)
            .map_err(SourceReadonlyNativeErrorV1::Names))
    }

    pub(super) fn check_named_currentness(&self) -> Result<(), SourceReadonlyNativeErrorV1> {
        self.observe_named_currentness().unwrap_or_else(||
            Err(JournalError::ProtectedBoundary.into()))
    }

    pub(super) fn named_receiving_failure(&self, index: u8) -> Option<&JournalError> {
        self.names.failure_at(index)
    }

    pub(super) fn readback_mut(&mut self) -> Option<&mut Self> {
        if self.first.is_some() || !matches!(self.semantic_result, Some(Ok(())))
            || !matches!(self.replay_names, Some(Ok(()))) || self.remainder.is_none()
        {
            return None;
        }
        Some(self)
    }

    pub(super) fn journal_mut(&mut self) -> &mut Self { self }

    pub(super) fn snapshot_sequence(&self) -> u64 { self.next_sequence }

    pub(super) fn physical_names_v1(&self) -> Result<ProtectedJournalNamesV1, JournalError> {
        let (directory, file, lock) = self.physical.identities()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(ProtectedJournalNamesV1::from_historical_fields(
            directory.physical_pair(), file.physical_pair(), lock.physical_pair(),
        ))
    }

    pub(super) fn state(&self)
        -> Result<&BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>, JournalError>
    {
        self.remainder.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.replay.state().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn admit_source_readonly_purpose(
        &self, receiving: &mut SourceReadonlyReceivingContextV1<'_, '_>,
    ) -> Result<(), JournalError> {
        receiving.before_semantic_replay(self.state()?, None)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Preparation => self.physical.failure().or_else(|| error(&self.captured_metadata))
                .or_else(|| error(&self.extent))
                .or_else(|| error(&self.preparation)),
            First::InitialNames => self.name_failure(&self.initial_names),
            First::Replay => {
                if self.entry_identity.failure().is_some() {
                    return self.entry_identity.failure();
                }
                let selected_native = self.semantic.failure()
                    .and_then(|cause| cause.downcast_ref::<SourcePaidReplayErrorV1<JournalError>>())
                    .is_some_and(|cause| matches!(cause, SourcePaidReplayErrorV1::Native(_)));
                if selected_native {
                    self.replay.failure().or_else(|| self.index_original.failure())
                        .or_else(|| self.semantic.failure()).or_else(|| error(&self.replay_entry)).or_else(|| error(&self.semantic_result))
                } else { self.delete_pending.as_ref().and_then(SourceDeletePendingNativeOriginalsV1::failure)
                    .or_else(|| self.semantic.failure()).or_else(|| self.replay.failure())
                    .or_else(|| error(&self.replay_entry)).or_else(|| error(&self.semantic_result)) }
            }
            First::ReplayMetadata => self.captured_prefix.as_ref().and_then(|post| post.failure()),
            First::ReplayTail => error(&self.tail_seek).or_else(|| error(&self.tail)),
            First::ReplayNames => self.name_failure(&self.replay_names),
        }
    }

    fn name_failure<'cause>(&'cause self,
        returned: &'cause Option<Result<(), SourceReadonlyNativeErrorV1>>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match returned.as_ref()?.as_ref().err()? {
            SourceReadonlyNativeErrorV1::Names(index) => self.names.failure_at(*index)
                .map(|cause| cause as &(dyn Error + 'static)).or_else(|| error(returned)),
            _ => error(returned),
        }
    }
}

// This private adapter lends the same actual receiving context and only the
// named optional D observer; it cannot be supplied by another crate or role.
struct SourceReadonlyReplayFundingV1<'borrow, 'source, 'expected> {
    receiving: &'borrow mut SourceReadonlyReceivingContextV1<'source, 'expected>,
    delete_pending: &'borrow mut Option<SourceDeletePendingNativeOriginalsV1>,
    captured_end: u64,
}

// Both callers keep one canonical preparation body. The existing direct
// context implementation remains the actual history-suffix fixture consumer.
fn prepare_readonly_commit_v1(
    receiving: &mut SourceReadonlyReceivingContextV1<'_, '_>,
    commit: &aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>,
) -> Result<(), SourcePaidReplayErrorV1<JournalError>> {
    let (begin, offset) = commit.begin_position();
    receiving.observe_native_commit(
        commit.transaction(), begin, commit.commit_sequence(), offset,
        commit.coordinates().offset,
    ).map_err(SourcePaidReplayErrorV1::Receiving)?;
    receiving.before_semantic_replay(commit.prior_state(), Some(commit.transaction()))
        .map_err(SourcePaidReplayErrorV1::Receiving)
}

fn prepare_readonly_prefix_v1(
    receiving: &mut SourceReadonlyReceivingContextV1<'_, '_>,
    prefix: &aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>,
) -> Result<(), SourcePaidReplayErrorV1<JournalError>> {
    receiving.before_semantic_replay(prefix.state(), None)
        .map_err(SourcePaidReplayErrorV1::Receiving)?;
    // Preserve the original suffix-before-final-family validation order,
    // including the actual cause selected when both checks refuse.
    let actual = prefix.coordinates();
    receiving.finish_native_replay(actual.durable_next_sequence, actual.durable_end)
        .map_err(SourcePaidReplayErrorV1::Receiving)
}

impl SourceReplayFundingV1 for &mut SourceReadonlyReceivingContextV1<'_, '_> {
    type Error = JournalError;

    fn prepare_commit(&mut self,
        commit: aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1<JournalError>> {
        prepare_readonly_commit_v1(self, &commit)
    }

    fn prepare_prefix(&mut self,
        prefix: aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1<JournalError>> {
        prepare_readonly_prefix_v1(self, &prefix)
    }
}

impl SourceReplayFundingV1 for SourceReadonlyReplayFundingV1<'_, '_, '_> {
    type Error = JournalError;

    fn prepare_commit(&mut self,
        commit: aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1<JournalError>> {
        prepare_readonly_commit_v1(self.receiving, &commit)?;
        if let Some(pending) = self.delete_pending.as_mut() {
            self.receiving.before_delete_current_commit_v3(pending, &commit)
                .map_err(SourcePaidReplayErrorV1::Receiving)?;
            pending.observe_commit(commit).map_err(SourcePaidReplayErrorV1::Receiving)?;
        }
        Ok(())
    }

    fn prepare_prefix(&mut self,
        prefix: aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>,
    ) -> Result<(), SourcePaidReplayErrorV1<JournalError>> {
        prepare_readonly_prefix_v1(self.receiving, &prefix)?;
        if let Some(pending) = self.delete_pending.as_mut() {
            self.receiving.before_delete_current_prefix_v3(pending, &prefix)
                .map_err(SourcePaidReplayErrorV1::Receiving)?;
            pending.finish_prefix(prefix, self.captured_end)
                .map_err(SourcePaidReplayErrorV1::Receiving)?;
        }
        Ok(())
    }
}

impl SourceReadonlyNativeOriginalV1 {
    pub(in crate::signer) fn attach_delete_pending_once(&mut self,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
        purpose: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3,
    ) -> Result<(), JournalError> {
        if self.entered || self.replay_entered || self.delete_pending.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.delete_pending = Some(SourceDeletePendingNativeOriginalsV1::new_for_purpose_v3(query, purpose));
        Ok(())
    }

    pub(in crate::signer) fn delete_pending_native_data_v1(&self,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
        purpose: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3,
    ) -> Result<[u8; 64], aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentDataErrorV1> {
        use aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentDataErrorV1 as E;
        if self.first.is_some() || !matches!(self.semantic_result, Some(Ok(()))) || self.remainder.is_none() {
            return Err(E::Native);
        }
        self.delete_pending.as_ref().ok_or(E::Native)?.proof_for_purpose_v3(query, purpose)
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
