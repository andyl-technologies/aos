//! Replays actual coordinator cursors through the sole native/semantic recipes.
//!
//! The input keeps the existing ordinary or selected native borrow and Root
//! invocation fence. Returned maps are opaque completed comparison backing,
//! never a writer, receiving allowance, original challenge or current cut.

use aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorReadCursorV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryRereadDataV1, CanonicalOrdinaryRereadOriginalV1, NativeJournalDataErrorV1,
};

use super::ordinary_semantics::OrdinarySemanticReplayOriginalV1;
use super::*;

pub(super) struct ObservedReplayStateV1 {
    pub(super) durable_end: u64,
    pub(super) next_sequence: u64,
    pub(super) committed_transactions: usize,
    pub(super) committed_records: usize,
    pub(super) native: CanonicalOrdinaryRereadDataV1,
    pub(super) source_challenge_history:
        Vec<source_history::SourceOriginalChallengeCheckpointV5>,
    pub(super) source_original_replay: source_history::replay::SourceOriginalReplayCacheV5,
    pub(super) source_history_compacted: bool,
    #[cfg(target_os = "linux")]
    pub(super) q04_lower_history_present: bool,
}

/// Bounds controls beyond the already priced physical replay payload terms.
pub(super) fn receiving_control_bytes_v1() -> Option<usize> {
    CanonicalOrdinaryRereadOriginalV1::receiving_control_bytes_data_v1()?
        .checked_add(OrdinarySemanticReplayOriginalV1::ordinary_receiving_construction_bytes_v1()?)?
        .checked_add(std::mem::size_of::<Input<'_>>().checked_mul(2)?)?
        // The two complete native and semantic result planes are in the
        // respective shared suppliers. Price only this outer header remainder.
        .checked_add(
            std::mem::size_of::<ObservedReplayStateV1>()
                .checked_sub(std::mem::size_of::<CanonicalOrdinaryRereadDataV1>())?
                .checked_sub(std::mem::size_of::<
                    super::semantic_remainder::DomainSemanticRemainderDataV1,
                >())?
                .checked_mul(2)?,
        )?
        .checked_add(std::mem::size_of::<
            Result<ObservedReplayStateV1, JournalError>,
        >())
}

enum Input<'input> {
    Coordinator(CanonicalCoordinatorReadCursorV1<'input>),
    PublishedBytes(&'input [u8], FileIdentity),
}

fn native_error(cause: NativeJournalDataErrorV1) -> JournalError {
    CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause).into()
}

pub(super) fn replay_coordinator_observed_v1(
    reader: CanonicalCoordinatorReadCursorV1<'_>,
    limits: JournalLimits,
    challenges: Option<&source_history::SourceOriginalChallengeHistoryViewV5<'_>>,
    #[cfg(target_os = "linux")] history: Option<DeploymentHistoryObserverV1<'_, '_>>,
) -> Result<ObservedReplayStateV1, JournalError> {
    replay_input(
        Input::Coordinator(reader),
        limits,
        challenges,
        #[cfg(target_os = "linux")]
        history,
    )
}

pub(super) fn replay_published_bytes_observed_v1(
    bytes: &[u8],
    identity: FileIdentity,
    limits: JournalLimits,
    #[cfg(target_os = "linux")] history: Option<DeploymentHistoryObserverV1<'_, '_>>,
) -> Result<ObservedReplayStateV1, JournalError> {
    replay_input(
        Input::PublishedBytes(bytes, identity),
        limits,
        None,
        #[cfg(target_os = "linux")]
        history,
    )
}

fn replay_input(
    input: Input<'_>,
    limits: JournalLimits,
    challenges: Option<&source_history::SourceOriginalChallengeHistoryViewV5<'_>>,
    #[cfg(target_os = "linux")] history: Option<DeploymentHistoryObserverV1<'_, '_>>,
) -> Result<ObservedReplayStateV1, JournalError> {
    let mut native = CanonicalOrdinaryRereadOriginalV1::new();
    let mut semantic = OrdinarySemanticReplayOriginalV1::new();
    let mut converted = None;
    let body: Result<(), JournalError> = (|| {
        let (identity, mut cursor) = match input {
            Input::Coordinator(reader) => native.begin_coordinator_ordinary_once_v1(reader, limits),
            Input::PublishedBytes(bytes, identity) => {
                native.begin_readback_bytes_ordinary_once_v1(bytes, identity, limits)
            }
        }
        .map_err(native_error)?;
        semantic
            .observe_once(
                &mut cursor,
                identity,
                limits,
                challenges,
                #[cfg(target_os = "linux")]
                history,
            )
            .map_err(|()| JournalError::ProtectedBoundary)?;
        converted = Some(
            semantic
                .take_remainder_once()
                .ok_or(JournalError::ProtectedBoundary)?,
        );
        Ok(())
    })();

    // Preserve the original ordinary frame-error and function-local windows.
    // The successful full native/semantic result stays resident for its upper
    // independently owed comparisons/posts; failed temporary replay is disposed.
    let native_selected = native.failure().is_some();
    semantic.dispose_ordinary_prospective_v1();
    let current = native.dispose_ordinary_current_once_v1();
    let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
    let pending = native.dispose_ordinary_pending_once_v1();
    if let Err(body) = body {
        if let Ok((index, original)) = native.into_ordinary_errors_v1() {
            if native_selected {
                if let Some(cause) = index {
                    return Err(project_idempotency_record_error(cause));
                }
                if let Some(cause) = original {
                    return Err(native_error(cause));
                }
            }
        }
        drop(current);
        drop(pending);
        return Err(upper_native.or(upper_semantic).unwrap_or(body));
    }
    current.map_err(native_error)?;
    pending.map_err(native_error)?;
    let native = match native.into_completed_comparison_data_v1() {
        Ok(native) => native,
        Err(original) => {
            drop(converted.take());
            drop(original);
            return Err(JournalError::ProtectedBoundary);
        }
    };
    let semantic = converted.ok_or(JournalError::ProtectedBoundary)?;
    let coordinates = native.coordinates_data_v1();
    Ok(ObservedReplayStateV1 {
        durable_end: coordinates.durable_end,
        next_sequence: coordinates.durable_next_sequence,
        committed_transactions: coordinates.committed_transactions,
        committed_records: coordinates.committed_records,
        native,
        source_challenge_history: semantic.source_challenge_history,
        source_original_replay: semantic.source_original_replay,
        source_history_compacted: semantic.source_history_compacted,
        #[cfg(target_os = "linux")]
        q04_lower_history_present: semantic.q04_lower_history_present,
    })
}

// Pure fixture DATA may be collected from its already-bounded reader. Actual
// production reads use the guarded coordinator directly, never this adapter.
#[cfg(test)]
pub(super) fn replay_fixture_observed_v1<R: Read + Seek + JournalReadIdentityDataV1>(
    reader: &mut R,
    limits: JournalLimits,
    challenges: Option<&source_history::SourceOriginalChallengeHistoryViewV5<'_>>,
    #[cfg(target_os = "linux")] history: Option<DeploymentHistoryObserverV1<'_, '_>>,
) -> Result<ObservedReplayStateV1, JournalError> {
    reader.seek(SeekFrom::Start(0))?;
    let identity = reader.sample_file_identity_v1()?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    replay_input(
        Input::PublishedBytes(&bytes, identity),
        limits,
        challenges,
        #[cfg(target_os = "linux")]
        history,
    )
}
