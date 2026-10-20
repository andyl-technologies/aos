//! Runs the sole semantic recipe beside an ordinary held parser and index.
//!
//! This private adapter borrows only an actual indexed cursor and the existing
//! finite history observer. It cannot choose a native owner, import a map,
//! authenticate a challenge or replace an upper role's financial/current gate.

use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1,
};
use aos_sandbox_broker::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalReplayPrefixReadViewV1,
};

use aos_sandbox_core::{ResourceDimension, ResourceVector};

use super::semantic_remainder::DomainSemanticRemainderDataV1;
use super::semantic_replay::*;
use super::*;
use super::source_history as source_original_native;

// Uses the same deny-only DATA selector on portable and Linux builds.
fn is_q04_lower_history_record_v1(record: &JournalRecord) -> bool {
    aos_sandbox_ledger_replay::semantic_recipe::is_q04_lower_history_record_data_v1(record)
}

aos_sandbox_ledger_replay::define_semantic_replay_data_recipe_v1!(retained);

/// Retains actual ordinary semantic work until its original disposal frontier.
pub(super) struct OrdinarySemanticReplayOriginalV1 {
    original: SelectedSemanticReplayOriginalV1<JournalError>,
}

impl OrdinarySemanticReplayOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            original: SelectedSemanticReplayOriginalV1::new(),
        }
    }

    /// Covers the same driver and the two actual short borrowed adapter planes.
    pub(super) fn receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<OrdinaryNativeV1<'_, '_, '_, '_, '_>>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        SelectedSemanticReplayOriginalV1::<JournalError>::fixed_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
            .map_err(Into::into)
    }

    /// Prices immediate replay controls without unused retained family backing.
    pub(super) fn ordinary_receiving_construction_bytes_v1() -> Option<usize> {
        SelectedSemanticReplayOriginalV1::<JournalError>::receiving_construction_bytes_v1()
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<OrdinaryNativeV1<'_, '_, '_, '_, '_>>().checked_mul(2)?
            ))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), ()>>()))
    }

    /// Prices readonly construction without duplicating per-state family pay.
    pub(super) fn readonly_receiving_construction_bytes_v1() -> Result<usize, JournalError> {
        #[cfg(target_os = "linux")]
        let adapter = std::mem::size_of::<CapturedReadonlyNativeV1<'_, '_, '_, '_, '_, '_, '_>>();
        #[cfg(not(target_os = "linux"))]
        let adapter = std::mem::size_of::<OrdinaryNativeV1<'_, '_, '_, '_, '_>>();
        SelectedSemanticReplayOriginalV1::<JournalError>::receiving_construction_bytes_v1()
            .and_then(|bytes| bytes.checked_add(adapter.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<(), ()>>()))
            .ok_or(JournalError::JournalTooLarge)
    }

    /// Keeps actual historical identity and immediate ordinary family disposal.
    pub(super) fn observe_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        challenges: Option<&source_history::SourceOriginalChallengeHistoryViewV5<'_>>,
        #[cfg(target_os = "linux")] history: Option<DeploymentHistoryObserverV1<'_, '_>>,
    ) -> Result<(), ()> {
        let mut native = OrdinaryNativeV1 {
            cursor,
            #[cfg(target_os = "linux")]
            history,
            #[cfg(not(target_os = "linux"))]
            portable_history: std::marker::PhantomData,
        };
        self.original
            .observe_ordinary_once(&mut native, identity, limits, challenges)
    }

    /// Preserves the actual fixed readonly loan at each pre-growth frontier.
    #[cfg(target_os = "linux")]
    pub(super) fn observe_captured_readonly_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        receiving: Option<&mut CapturedReadonlyReceivingContextV1<'_, '_, '_, '_>>,
    ) -> Result<(), ()> {
        let retaining = receiving.as_ref()
            .is_some_and(|receiving| receiving.retains_source_family_originals());
        let mut native = CapturedReadonlyNativeV1 {
            native: OrdinaryNativeV1 { cursor, history: None },
            receiving,
        };
        if retaining {
            self.original.observe_native_once(&mut native, identity, limits)
        } else {
            self.original.observe_ordinary_once(&mut native, identity, limits, None)
        }
    }

    pub(super) fn take_remainder_once(&mut self) -> Option<DomainSemanticRemainderDataV1> {
        let remainder = self.original.take_remainder_once()?;
        Some(DomainSemanticRemainderDataV1 {
            source_challenge_history: remainder.source_challenge_history,
            source_original_replay: remainder.source_original_replay,
            source_history_compacted: remainder.source_history_compacted,
            q04_lower_history_present: remainder.q04_lower_history_present,
        })
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }

    /// Keeps retained readonly's actual deep Source-cause selector intact.
    pub(super) fn source_failure_cause_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.source_failure_cause_v1()
    }

    /// Drops only the reached prospective map before the current native frame.
    pub(super) fn dispose_ordinary_prospective_v1(&mut self) {
        self.original.dispose_ordinary_prospective_v1();
    }

    /// Disposes upper semantic scratch between current and pending native work.
    pub(super) fn into_ordinary_errors(self) -> (Option<JournalError>, Option<JournalError>) {
        self.original.into_ordinary_errors()
    }
}

struct OrdinaryNativeV1<'turn, 'file, 'original, 'observer, 'data> {
    cursor: &'turn mut CanonicalIndexedReplayV1<'file, 'original>,
    #[cfg(target_os = "linux")]
    history: Option<DeploymentHistoryObserverV1<'observer, 'data>>,
    #[cfg(not(target_os = "linux"))]
    portable_history: std::marker::PhantomData<(&'observer (), &'data ())>,
}

fn native_error(cause: CanonicalIndexedReplayErrorV1) -> JournalError {
    match cause {
        CanonicalIndexedReplayErrorV1::Native(cause) => JournalError::from(
            CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause),
        ),
        // The actual index original retains the deeper typed cause. Its real
        // owner moves that error only after current/upper/pending disposal.
        CanonicalIndexedReplayErrorV1::Closed => JournalError::ProtectedBoundary,
    }
}

impl SelectedReplayNativeV1 for OrdinaryNativeV1<'_, '_, '_, '_, '_> {
    type Error = JournalError;

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.advance_once().map_err(native_error)
    }

    fn observe_history_commit_once(&mut self) -> Result<(), Self::Error> {
        #[cfg(target_os = "linux")]
        if let Some(history) = &mut self.history {
            let commit = self
                .cursor
                .current_commit()
                .ok_or(JournalError::ProtectedBoundary)?;
            let (begin_sequence, begin_offset) = commit.begin_position();
            history.observe(
                commit.transaction(),
                begin_sequence,
                commit.commit_sequence(),
                begin_offset,
                commit.coordinates().offset,
                &commit.commit_payload()[4..],
            )?;
        }
        Ok(())
    }

    fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.cursor.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.validate_compaction_once().map_err(native_error)
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        self.cursor
            .register_and_compare_index_once()
            .map_err(native_error)
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.prepare_change_once().map_err(native_error)
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.apply_next_record_once().map_err(native_error)
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        self.cursor
            .finish_commit_accounting_once()
            .map_err(native_error)
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.finish_commit_once().map_err(native_error)
    }

    fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.cursor.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        self.cursor
            .completed_prefix()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(())
    }
}

// This adapter carries only the existing finite, genuine readonly receiving
// context. It does not accept caller-defined hooks, capacity DATA or a payer.
#[cfg(target_os = "linux")]
struct CapturedReadonlyNativeV1<'turn, 'file, 'cursor, 'dispatch, 'borrow, 'original, 'data> {
    native: OrdinaryNativeV1<'turn, 'file, 'cursor, 'static, 'static>,
    receiving: Option<&'turn mut CapturedReadonlyReceivingContextV1<
        'dispatch, 'borrow, 'original, 'data,
    >>,
}

#[cfg(target_os = "linux")]
impl SelectedReplayNativeV1 for CapturedReadonlyNativeV1<'_, '_, '_, '_, '_, '_, '_> {
    type Error = JournalError;

    fn prepare_semantic_commit_once(&mut self) -> Result<(), Self::Error> {
        if let Some(receiving) = &mut self.receiving {
            let commit = self.native.current_commit().ok_or(JournalError::ProtectedBoundary)?;
            let (begin_sequence, begin_offset) = commit.begin_position();
            receiving.observe_native_commit(
                commit.transaction(), begin_sequence, commit.commit_sequence(),
                begin_offset, commit.coordinates().offset,
            )?;
            receiving.before_semantic_replay(commit.prior_state(), Some(commit.transaction()))?;
        }
        Ok(())
    }

    fn prepare_semantic_prefix_once(&mut self) -> Result<(), Self::Error> {
        if let Some(receiving) = &mut self.receiving {
            let prefix = self.native.completed_prefix().ok_or(JournalError::ProtectedBoundary)?;
            receiving.before_semantic_replay(prefix.state(), None)?;
            let coordinates = prefix.coordinates();
            receiving.finish_native_replay(
                coordinates.durable_next_sequence, coordinates.durable_end,
            )?;
        }
        Ok(())
    }

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        self.native.advance_once()
    }

    fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.native.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        self.native.validate_compaction_once()
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        self.native.register_and_compare_index_once()
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        self.native.prepare_change_once()
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        self.native.apply_next_record_once()
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        self.native.finish_commit_accounting_once()
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        self.native.finish_commit_once()
    }

    fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.native.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        self.native.finish_semantic_window_once()
    }
}
