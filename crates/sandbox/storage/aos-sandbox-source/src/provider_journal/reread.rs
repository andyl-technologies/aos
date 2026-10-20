//! Rechecks Source's own held file through the same ordinary replay machinery.
//!
//! Completed backing can only come from that holder's actual cursor. It is
//! immutable comparison data, not a writer or Source grant. The real Source
//! callers still own the protected/challenge bookends and exact full-cache join.

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryHeldJournalV1, CanonicalOrdinaryRereadDataV1,
    CanonicalOrdinaryRereadOriginalV1,
};

use super::original::SourceOriginalChallengeHistoryViewV5;
use super::semantic_replay::{
    SourceReleaseHistoryV1, SourceSemanticRemainderDataV1, SourceSemanticReplayOriginalV1,
};
use super::{JournalAuthorityInstance, JournalError, JournalLimits};

type Held = CanonicalOrdinaryHeldJournalV1<(), JournalAuthorityInstance>;

/// Owns only an actual completed reread and its Source semantic remainder.
pub(super) struct SourceCompletedReplayV1 {
    pub(super) native: CanonicalOrdinaryRereadDataV1,
    pub(super) semantic: SourceSemanticRemainderDataV1,
    pub(super) history: Option<SourceReleaseHistoryV1>,
}

impl SourceCompletedReplayV1 {
    /// Compares complete inert replay backing; physical currentness stays upper.
    pub(super) fn require_same_data(
        &self,
        journal: &super::Journal,
        physical_end: u64,
    ) -> Result<(), JournalError> {
        let actual = journal.native_view();
        let coordinates = self.native.coordinates_data_v1();
        if coordinates.durable_end != physical_end
            || coordinates.durable_next_sequence != actual.next_sequence()
            || coordinates.committed_transactions != actual.committed_transactions()
            || self.native.transaction_ids_data_v1() != actual.transaction_ids()
            || self.native.committed_namespaces_data_v1() != actual.committed_namespaces()
            || self.native.state_data_v1() != actual.state()
            || self.native.materialized_bytes_data_v1() != actual.materialized_bytes()
            || self.native.idempotency_data_v1() != actual.idempotency_index()
            || self.semantic.source_history_compacted != journal.source_history_compacted
            || self.semantic.q04_lower_history_present
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

enum Input<'held> {
    Ordinary(&'held mut Held),
    Captured(&'held Held, u64),
}

/// Covers only new fixed carriers; existing wire/cache copy terms stay separate.
pub(super) fn receiving_control_bytes_data_v1() -> Option<usize> {
    CanonicalOrdinaryRereadOriginalV1::receiving_control_bytes_data_v1()?
        .checked_add(SourceSemanticReplayOriginalV1::receiving_construction_bytes_data_v1()?)?
        .checked_add(std::mem::size_of::<SourceCompletedReplayV1>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<
            Result<SourceCompletedReplayV1, JournalError>,
        >())?
        .checked_add(std::mem::size_of::<Input<'_>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<Option<SourceReleaseHistoryV1>>().checked_mul(2)?)
}

pub(super) fn ordinary(
    held: &mut Held,
    limits: JournalLimits,
    challenges: Option<&SourceOriginalChallengeHistoryViewV5<'_>>,
) -> Result<SourceCompletedReplayV1, JournalError> {
    read(Input::Ordinary(held), limits, challenges)
}

pub(super) fn captured(
    held: &Held,
    length: u64,
    limits: JournalLimits,
    challenges: &SourceOriginalChallengeHistoryViewV5<'_>,
) -> Result<SourceCompletedReplayV1, JournalError> {
    read(Input::Captured(held, length), limits, Some(challenges))
}

fn read(
    input: Input<'_>,
    limits: JournalLimits,
    challenges: Option<&SourceOriginalChallengeHistoryViewV5<'_>>,
) -> Result<SourceCompletedReplayV1, JournalError> {
    let mut native = CanonicalOrdinaryRereadOriginalV1::new();
    let mut semantic = SourceSemanticReplayOriginalV1::new();
    let mut history = match &input {
        Input::Ordinary(_) => None,
        Input::Captured(held, _) => Some(SourceReleaseHistoryV1::new(
            held.read_view_v1().committed_transactions(),
        )),
    };
    let body = (|| {
        let (identity, mut cursor) = match input {
            Input::Ordinary(held) => held.begin_ordinary_reread_once_v1(&mut native),
            Input::Captured(held, length) => native.begin_coordinator_ordinary_once_v1(
                held.read_view_v1().captured_reader(length),
                limits,
            ),
        }
        .map_err(JournalError::from_ordinary_native_v1)?;
        match history.as_mut() {
            Some(history) => semantic.observe_release_once(
                &mut cursor,
                identity,
                limits,
                challenges.ok_or(JournalError::ProtectedBoundary)?,
                history,
            ),
            None => semantic.observe_ordinary_once(&mut cursor, identity, limits, challenges),
        }
        .map_err(|_| JournalError::ProtectedBoundary)?;
        semantic
            .take_remainder_once()
            .ok_or(JournalError::ProtectedBoundary)
    })();

    let native_selected = native.failure().is_some();
    // Preserve the old immediate parser's lexical disposition order on both
    // success and failure. The completed remainder stays separately owned.
    semantic.dispose_ordinary_prospective_v1();
    let current = native.dispose_ordinary_current_once_v1();
    let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
    let pending = native.dispose_ordinary_pending_once_v1();
    match body {
        Ok(remainder) if current.is_ok() && pending.is_ok() => {
            let native = native
                .into_completed_comparison_data_v1()
                .map_err(|original| {
                    drop(original);
                    JournalError::ProtectedBoundary
                })?;
            Ok(SourceCompletedReplayV1 {
                native,
                semantic: remainder,
                history,
            })
        }
        result => {
            let body = result.err().unwrap_or(JournalError::ProtectedBoundary);
            let (index, physical) = match native.into_ordinary_errors_v1() {
                Ok(errors) => errors,
                Err(original) => {
                    drop(original);
                    return Err(body);
                }
            };
            if native_selected {
                if let Some(cause) = index {
                    return Err(cause.into());
                }
                if let Some(cause) = physical {
                    return Err(JournalError::from_ordinary_native_v1(cause));
                }
            }
            if let Some(cause) = upper_native {
                return Err(cause);
            }
            Err(upper_semantic.unwrap_or(body))
        }
    }
}
