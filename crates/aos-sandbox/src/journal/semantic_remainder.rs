//! Moves the same completed cold DATA into the Domain historical fields.
//!
//! Actual native owners stay in their constructors until this nonallocating
//! handoff succeeds. Domain retains no Source challenge authority; a supplied
//! challenge witness still refuses entry and remains in its original owner.

use std::error::Error;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;

use super::JournalError;
use super::source_history::{
    SourceOriginalChallengeCheckpointV5, replay::SourceOriginalReplayCacheV5,
};

/// Carries historical fields into the actual private Domain Journal constructor.
pub(super) struct DomainSemanticRemainderDataV1 {
    /// Moves exact committed checkpoint bytes without claiming native history.
    pub(super) source_challenge_history: Vec<SourceOriginalChallengeCheckpointV5>,
    /// Keeps the original pending disposition until its real owner closes it.
    pub(super) source_original_replay: SourceOriginalReplayCacheV5,
    /// Preserves whether native replay encountered a compacted prefix.
    pub(super) source_history_compacted: bool,
    /// Preserves the deny-only lower-history provenance bit.
    pub(super) q04_lower_history_present: bool,
}

/// Keeps every moved conversion plane before the native handoff can proceed.
pub(super) struct ColdSemanticRemainderOriginalV1 {
    input: Option<ColdReplayRemainderDataV1>,
    output: Option<DomainSemanticRemainderDataV1>,
    result: Option<Result<(), JournalError>>,
    reentry: Option<JournalError>,
}

impl ColdSemanticRemainderOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            input: None,
            output: None,
            result: None,
            reentry: None,
        }
    }

    /// Prices resident and working representations; conversion allocates nothing.
    pub(super) fn receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded(
                "cold semantic remainder conversion",
            ))?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Leaves a repeated caller's newly supplied input untouched.
    pub(super) fn observe_once(&mut self, supplied: &mut Option<ColdReplayRemainderDataV1>) {
        if self.result.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.input = supplied.take();
        self.result = Some(self.convert());
    }

    fn convert(&mut self) -> Result<(), JournalError> {
        let input = self.input.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if input.original_replay.challenges.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let ColdReplayRemainderDataV1 {
            challenge_history,
            original_replay,
            history_compacted,
            q04_lower_history_present,
        } = self.input.take().ok_or(JournalError::ProtectedBoundary)?;
        self.output = Some(DomainSemanticRemainderDataV1 {
            source_challenge_history: challenge_history,
            source_original_replay: SourceOriginalReplayCacheV5(original_replay),
            source_history_compacted: history_compacted,
            q04_lower_history_present,
        });
        Ok(())
    }

    /// Reports only whether this actual conversion has been attempted.
    pub(super) fn entered(&self) -> bool {
        self.result.is_some()
    }

    /// Requires the same successful conversion and still-retained output.
    pub(super) fn ready(&self) -> bool {
        matches!(self.result, Some(Ok(()))) && self.reentry.is_none() && self.output.is_some()
    }

    /// Moves the completed DATA once; no writer or role capability is created.
    pub(super) fn take_once(&mut self) -> Option<DomainSemanticRemainderDataV1> {
        if !self.ready() {
            return None;
        }
        self.output.take()
    }

    /// Restores the same untaken pair after another required owner is absent.
    pub(super) fn restore_unmoved(&mut self, output: Option<DomainSemanticRemainderDataV1>) {
        self.output = output;
    }

    /// Borrows the original conversion refusal before any repeated-entry marker.
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref())
            .map(|cause| cause as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_ledger_replay::replay::challenge::SourceChallengeReplayWitnessDataV5;
    use std::sync::Arc;

    fn cold() -> ColdReplayRemainderDataV1 {
        ColdReplayRemainderDataV1 {
            challenge_history: Vec::new(),
            original_replay: Default::default(),
            history_compacted: false,
            q04_lower_history_present: true,
        }
    }

    #[test]
    fn a_saved_witness_is_retained_and_never_rebound_to_a_live_identity() {
        let instance = Arc::new(());
        let mut input = cold();
        input.original_replay.pending = true;
        input.original_replay.challenges = Some(
            SourceChallengeReplayWitnessDataV5::retain_rows(&Vec::new(), 0, &instance, 1).unwrap(),
        );
        let mut supplied = Some(input);
        let mut original = ColdSemanticRemainderOriginalV1::new();

        original.observe_once(&mut supplied);

        assert!(supplied.is_none());
        assert!(original.take_once().is_none());
        let retained = original.input.as_ref().unwrap();
        assert!(retained.original_replay.pending);
        assert!(retained.q04_lower_history_present);
        retained
            .original_replay
            .challenges
            .as_ref()
            .unwrap()
            .require_same_identity(&instance, 1)
            .unwrap();
        let first = original.failure().unwrap() as *const dyn Error;
        let mut next = Some(cold());
        original.observe_once(&mut next);
        assert!(next.is_some());
        assert!(std::ptr::addr_eq(first, original.failure().unwrap()));
    }

    #[test]
    fn an_unobserved_destination_is_inert_and_a_pending_cache_stays_pending() {
        let mut original = ColdSemanticRemainderOriginalV1::new();
        assert!(!original.entered());
        assert!(original.take_once().is_none());
        let mut input = cold();
        input.original_replay.pending = true;
        let mut supplied = Some(input);

        original.observe_once(&mut supplied);
        let converted = original.take_once().unwrap();

        assert!(converted.source_original_replay.pending);
        assert!(converted.source_original_replay.challenges.is_none());
        assert!(converted.q04_lower_history_present);
        assert!(original.take_once().is_none());
        assert_eq!(
            ColdSemanticRemainderOriginalV1::receiving_demand_v1()
                .unwrap()
                .get(D::MetadataEntries),
            0
        );
    }
}
