//! Controller-owned authenticated Network inventory checkpoint history.
//!
//! Two bounded request/outcome slots and one fixed head retain current,
//! completed, and outstanding state without turning recovered bytes into send
//! or snapshot authority. The existing `latest` key remains byte-for-byte V1
//! until a continuity-clean authenticated success promotes an AOSBRI02 pointer.
//!
//! ```text
//! latest
//! aos.controller.network-inventory.request.{0,1}.v1\0
//! aos.controller.network-inventory.outcome.{0,1}.v1\0
//! aos.controller.network-inventory.head.v1\0
//!
//! slot digest = SHA-256(distinct terminal-NUL domain || slot || u32be(len) || value)
//! ```

use aos_sandbox_protocol::authenticated_session::{
    AuthenticatedNetworkInventoryResultV1,
    checkpoint::{
        NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES,
        NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES, NetworkInventoryCheckpointTerminalErrorV1,
        NetworkInventoryOutcomeCheckpointDraftV1, NetworkInventoryRequestCheckpointDraftV1,
        RecoveredNetworkInventoryCheckpointViewV1,
        RecoveredNetworkInventoryRequestCheckpointViewV1,
        decode_recovered_network_inventory_checkpoint_values_v1,
        decode_recovered_network_inventory_request_checkpoint_value_v1,
    },
};
use sha2::{Digest as _, Sha256};

use super::{
    KEY, ResourceInventoryError, SnapshotDecision, ValidatedNetworkInventory,
    ValidatedResourceInventory, classify_inventory_continuity, controller_state_digest,
};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

mod format;

use format::{
    CheckpointHead, CurrentPointer, HEAD_BYTES, HeadState, POINTER_BYTES, PredecessorIdentity,
    invalid_sequence, next_generation, post_transaction_sequence, slot_digest,
};

const REQUEST_SLOT_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.controller.network-inventory.request-slot.v1\0";
const OUTCOME_SLOT_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.controller.network-inventory.outcome-slot.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller.network-inventory.transaction.v1\0";

const REQUEST_KEYS: [&[u8]; 2] = [
    b"aos.controller.network-inventory.request.0.v1\0",
    b"aos.controller.network-inventory.request.1.v1\0",
];
const OUTCOME_KEYS: [&[u8]; 2] = [
    b"aos.controller.network-inventory.outcome.0.v1\0",
    b"aos.controller.network-inventory.outcome.1.v1\0",
];
const HEAD_KEY: &[u8] = b"aos.controller.network-inventory.head.v1\0";

// Journal payload accounting includes the fixed seven-byte record envelope.
const MAXIMUM_REQUEST_RECORD_PAYLOAD_BYTES: usize = 744;
const MAXIMUM_SLOT_RECORD_PAYLOAD_BYTES: usize = 15_729_109;
const MAXIMUM_HEAD_RECORD_PAYLOAD_BYTES: usize = 392;
const MAXIMUM_RESERVATION_TRANSACTION_BYTES: usize = 1_189;
const MAXIMUM_COMPLETION_TRANSACTION_BYTES: usize = 15_729_501;
const MAXIMUM_PROMOTION_TRANSACTION_BYTES: usize = 15_729_844;
const MAXIMUM_CONSUMPTION_TRANSACTION_BYTES: usize = 392;
const MAXIMUM_LEGACY_NETWORK_VALUE_BYTES: usize = 15_732_836;
const MAXIMUM_MATERIALIZED_GRAPH_BYTES: usize = 31_463_066;

const _: () = assert!(REQUEST_KEYS[0].len() == 46);
const _: () = assert!(REQUEST_KEYS[1].len() == 46);
const _: () = assert!(OUTCOME_KEYS[0].len() == 46);
const _: () = assert!(OUTCOME_KEYS[1].len() == 46);
const _: () = assert!(HEAD_KEY.len() == 41);
const _: () = assert!(1 + REQUEST_KEYS.len() + OUTCOME_KEYS.len() + 1 == 6);
const _: () = assert!(
    MAXIMUM_REQUEST_RECORD_PAYLOAD_BYTES
        == 7 + 46 + NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES
);
const _: () = assert!(
    MAXIMUM_SLOT_RECORD_PAYLOAD_BYTES == 7 + 46 + NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES
);
const _: () = assert!(MAXIMUM_HEAD_RECORD_PAYLOAD_BYTES == 7 + 41 + HEAD_BYTES);
const _: () = assert!(MAXIMUM_SLOT_RECORD_PAYLOAD_BYTES <= 16 * 1024 * 1024);
const _: () = assert!(
    MAXIMUM_RESERVATION_TRANSACTION_BYTES
        == MAXIMUM_REQUEST_RECORD_PAYLOAD_BYTES + (7 + 46) + MAXIMUM_HEAD_RECORD_PAYLOAD_BYTES
);
const _: () = assert!(
    MAXIMUM_COMPLETION_TRANSACTION_BYTES
        == MAXIMUM_SLOT_RECORD_PAYLOAD_BYTES + MAXIMUM_HEAD_RECORD_PAYLOAD_BYTES
);
const _: () = assert!(MAXIMUM_RESERVATION_TRANSACTION_BYTES <= 64 * 1024 * 1024);
const _: () = assert!(MAXIMUM_COMPLETION_TRANSACTION_BYTES <= 64 * 1024 * 1024);
const _: () = assert!(MAXIMUM_PROMOTION_TRANSACTION_BYTES <= 64 * 1024 * 1024);
const _: () = assert!(MAXIMUM_CONSUMPTION_TRANSACTION_BYTES == MAXIMUM_HEAD_RECORD_PAYLOAD_BYTES);
const _: () = assert!(MAXIMUM_CONSUMPTION_TRANSACTION_BYTES <= 64 * 1024 * 1024);
const _: () = assert!(
    MAXIMUM_LEGACY_NETWORK_VALUE_BYTES
        == super::format::FIXED_RECORD_BYTES
            + super::MAXIMUM_QUERY_BYTES
            + super::RESPONSE_BYTES as usize
);
const _: () = assert!(MAXIMUM_LEGACY_NETWORK_VALUE_BYTES <= super::MAXIMUM_RECORD_BYTES);
const _: () = assert!(MAXIMUM_MATERIALIZED_GRAPH_BYTES <= 128 * 1024 * 1024);
const _: () = assert!(
    MAXIMUM_PROMOTION_TRANSACTION_BYTES
        == MAXIMUM_SLOT_RECORD_PAYLOAD_BYTES
            + MAXIMUM_HEAD_RECORD_PAYLOAD_BYTES
            + (7 + KEY.len() + POINTER_BYTES)
            + 2 * (7 + 46)
);
const _: () = assert!(
    MAXIMUM_MATERIALIZED_GRAPH_BYTES
        == (KEY.len() + MAXIMUM_LEGACY_NETWORK_VALUE_BYTES)
            + (46 + NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES)
            + (46 + NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES)
            + (HEAD_KEY.len() + HEAD_BYTES)
);

mod state;

use state::{CurrentSnapshot, RecoveredHistory};
pub(super) use state::{RecoveredCheckpoint, load_history};

/// Owns one protected, exclusively locked journal for live controller checkpoints.
///
/// This facade admits only process-local live drafts. Loading durable history
/// validates its closed graph but never recreates reservation, completion, or
/// replay authority from recovered bytes.
#[doc(hidden)]
pub struct ControllerNetworkInventoryCheckpointOwnerV1 {
    journal: Journal,
}

impl ControllerNetworkInventoryCheckpointOwnerV1 {
    /// Adopts one healthy protected journal with exclusive writer ownership.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceInventoryError`] if the journal lacks protected
    /// storage provenance, is poisoned, or contains invalid Network inventory
    /// checkpoint history.
    pub fn from_exclusive_journal(journal: Journal) -> Result<Self, ResourceInventoryError> {
        journal.ensure_protected_authority()?;
        load_history(&journal)?;

        Ok(Self { journal })
    }

    /// Atomically reserves one fully authenticated live request draft.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceInventoryError`] if protected history is unhealthy or
    /// inconsistent, the request conflicts with its high-water mark, capacity
    /// is exhausted, or retained replay, outstanding, or unconsumed state must
    /// first be resolved by a future recovery owner. Recovery-required states
    /// use the existing [`ResourceInventoryError::Conflict`] category.
    pub fn reserve_live_request(
        &mut self,
        request: NetworkInventoryRequestCheckpointDraftV1,
    ) -> Result<ControllerNetworkInventoryReservationV1, ResourceInventoryError> {
        match reserve_request(&mut self.journal, request)? {
            ReservationDisposition::Reserved(receipt) => {
                Ok(ControllerNetworkInventoryReservationV1 { receipt })
            }
            ReservationDisposition::ExactReplay { .. }
            | ReservationDisposition::Pending
            | ReservationDisposition::RecoveryRequired => Err(ResourceInventoryError::Conflict),
        }
    }

    /// Completes one live reservation and resolves its durable owner state.
    ///
    /// Current success is rechecked before its validated inventory is released.
    /// Every noncurrent result is durably consumed before its classification is
    /// returned, so no unresolved completion receipt escapes this facade.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceInventoryError`] if the reservation and outcome do not
    /// match, the protected journal or controller state changed, persistence is
    /// ambiguous, or the committed result cannot be rechecked or consumed.
    pub fn complete_live_outcome(
        &mut self,
        reservation: ControllerNetworkInventoryReservationV1,
        outcome: NetworkInventoryOutcomeCheckpointDraftV1,
    ) -> Result<ControllerNetworkInventoryCommittedResultV1, ResourceInventoryError> {
        let terminal_error = outcome.terminal_error();
        let completion = complete_outcome(&mut self.journal, reservation.receipt, outcome)?;

        match completion {
            CompletionDisposition::Current(receipt) => {
                if terminal_error.is_some() {
                    return Err(ResourceInventoryError::CorruptState);
                }
                recheck_current_success(&mut self.journal, &receipt)?;
                let ValidatedResourceInventory::Network(inventory) = receipt.inventory else {
                    return Err(ResourceInventoryError::CorruptState);
                };
                Ok(ControllerNetworkInventoryCommittedResultV1 {
                    inner: ControllerNetworkInventoryCommittedResultInnerV1::Current(inventory),
                })
            }
            CompletionDisposition::Stale(receipt) => {
                if terminal_error.is_some() {
                    return Err(ResourceInventoryError::CorruptState);
                }
                consume_completed(&mut self.journal, receipt.token)?;
                Ok(ControllerNetworkInventoryCommittedResultV1 {
                    inner: ControllerNetworkInventoryCommittedResultInnerV1::StaleSuccess,
                })
            }
            CompletionDisposition::Integrity(receipt) => {
                if terminal_error.is_some() {
                    return Err(ResourceInventoryError::CorruptState);
                }
                consume_completed(&mut self.journal, receipt.token)?;
                Ok(ControllerNetworkInventoryCommittedResultV1 {
                    inner:
                        ControllerNetworkInventoryCommittedResultInnerV1::IntegrityRejectedSuccess,
                })
            }
            CompletionDisposition::Terminal(receipt) => {
                let terminal_error = terminal_error.ok_or(ResourceInventoryError::CorruptState)?;
                consume_completed(&mut self.journal, receipt.token)?;
                Ok(ControllerNetworkInventoryCommittedResultV1 {
                    inner: ControllerNetworkInventoryCommittedResultInnerV1::Terminal(
                        terminal_error,
                    ),
                })
            }
        }
    }
}

/// Retains one process-local reservation without exposing its durable identity.
#[doc(hidden)]
pub struct ControllerNetworkInventoryReservationV1 {
    receipt: ReservationReceipt,
}

/// Retains one nonconstructible, fully persisted controller result.
///
/// Its inspection methods return data only. Future channel composition must
/// retain this opaque value to preserve the owner-produced durable binding.
#[doc(hidden)]
pub struct ControllerNetworkInventoryCommittedResultV1 {
    inner: ControllerNetworkInventoryCommittedResultInnerV1,
}

impl ControllerNetworkInventoryCommittedResultV1 {
    /// Returns a nonauthorizing classification of the committed result.
    #[must_use]
    pub const fn kind(&self) -> ControllerNetworkInventoryCommittedResultKindV1 {
        match &self.inner {
            ControllerNetworkInventoryCommittedResultInnerV1::Current(_) => {
                ControllerNetworkInventoryCommittedResultKindV1::Current
            }
            ControllerNetworkInventoryCommittedResultInnerV1::StaleSuccess => {
                ControllerNetworkInventoryCommittedResultKindV1::StaleSuccess
            }
            ControllerNetworkInventoryCommittedResultInnerV1::IntegrityRejectedSuccess => {
                ControllerNetworkInventoryCommittedResultKindV1::IntegrityRejectedSuccess
            }
            ControllerNetworkInventoryCommittedResultInnerV1::Terminal(_) => {
                ControllerNetworkInventoryCommittedResultKindV1::Terminal
            }
        }
    }

    /// Borrows current inventory data without transferring durable authority.
    #[must_use]
    pub const fn current_inventory(&self) -> Option<&ValidatedNetworkInventory> {
        match &self.inner {
            ControllerNetworkInventoryCommittedResultInnerV1::Current(inventory) => Some(inventory),
            ControllerNetworkInventoryCommittedResultInnerV1::StaleSuccess
            | ControllerNetworkInventoryCommittedResultInnerV1::IntegrityRejectedSuccess
            | ControllerNetworkInventoryCommittedResultInnerV1::Terminal(_) => None,
        }
    }

    /// Borrows a terminal classification without transferring durable authority.
    #[must_use]
    pub const fn terminal_error(&self) -> Option<&NetworkInventoryCheckpointTerminalErrorV1> {
        match &self.inner {
            ControllerNetworkInventoryCommittedResultInnerV1::Terminal(error) => Some(error),
            ControllerNetworkInventoryCommittedResultInnerV1::Current(_)
            | ControllerNetworkInventoryCommittedResultInnerV1::StaleSuccess
            | ControllerNetworkInventoryCommittedResultInnerV1::IntegrityRejectedSuccess => None,
        }
    }
}

/// Identifies a committed result without carrying owner-produced authority.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerNetworkInventoryCommittedResultKindV1 {
    /// The outcome installed and rechecked a current Network inventory.
    Current,
    /// The successful outcome became stale during the live exchange.
    StaleSuccess,
    /// Inventory continuity rejected the successful outcome.
    IntegrityRejectedSuccess,
    /// The broker returned one closed signed terminal outcome.
    Terminal,
}

enum ControllerNetworkInventoryCommittedResultInnerV1 {
    Current(ValidatedNetworkInventory),
    StaleSuccess,
    IntegrityRejectedSuccess,
    Terminal(NetworkInventoryCheckpointTerminalErrorV1),
}

/// Separates durable replay, an already-outstanding request, and a new receipt.
enum ReservationDisposition {
    ExactReplay { canonical_outcome_packet: Vec<u8> },
    Pending,
    RecoveryRequired,
    Reserved(ReservationReceipt),
}

/// Binds one process-local reservation to its exact post-commit ABA watermark.
struct ReservationReceipt {
    head: CheckpointHead,
    request_value: Vec<u8>,
    baseline_sequence: u64,
    post_reservation_sequence: u64,
}

/// Binds current snapshot authority to the exact promoted pointer and pair.
struct CurrentSuccessReceipt {
    head: CheckpointHead,
    pointer: CurrentPointer,
    request_value: Vec<u8>,
    outcome_value: Vec<u8>,
    inventory: ValidatedResourceInventory,
}

/// Identifies a retained, noncurrent stale success without snapshot authority.
struct StaleSuccessReceipt {
    token: CompletedPairToken,
}

/// Identifies a retained integrity-rejected success without snapshot authority.
struct IntegritySuccessReceipt {
    token: CompletedPairToken,
}

/// Identifies a retained signed terminal outcome without snapshot authority.
struct TerminalReceipt {
    token: CompletedPairToken,
}

/// Keeps the four completion classes closed without a generic authority receipt.
enum CompletionDisposition {
    Current(CurrentSuccessReceipt),
    Stale(StaleSuccessReceipt),
    Integrity(IntegritySuccessReceipt),
    Terminal(TerminalReceipt),
}

/// Carries exact recovered completion identity only for explicit consumption.
struct CompletedPairToken {
    head: CheckpointHead,
}

/// Reserves one exact live request or returns a no-write classification.
fn reserve_request(
    journal: &mut Journal,
    request: NetworkInventoryRequestCheckpointDraftV1,
) -> Result<ReservationDisposition, ResourceInventoryError> {
    journal.ensure_healthy()?;
    let incoming =
        decode_recovered_network_inventory_request_checkpoint_value_v1(request.exact_value())
            .map_err(|_| ResourceInventoryError::CorruptState)?;
    let history = load_history(journal)?;

    if let Some(packet) = lookup_completed(&history, request.exact_value(), &incoming)? {
        return Ok(ReservationDisposition::ExactReplay {
            canonical_outcome_packet: packet,
        });
    }
    if let Some(checkpoint) = &history.checkpoint {
        if checkpoint.head.state == HeadState::Outstanding {
            if checkpoint.active_request()? == request.exact_value() {
                return Ok(ReservationDisposition::Pending);
            }
            if request_collides(&checkpoint.active_request_view()?, &incoming) {
                return Err(ResourceInventoryError::Conflict);
            }
            return Err(ResourceInventoryError::Conflict);
        }
        if checkpoint.head.state.is_unconsumed_noncurrent() {
            return Ok(ReservationDisposition::RecoveryRequired);
        }
        require_next_request(checkpoint, &incoming)?;
    } else if history
        .legacy_record
        .as_ref()
        .is_some_and(|(record, _)| record.request_id == incoming.request_id())
        || incoming.client_sequence() != 1
    {
        return Err(ResourceInventoryError::Conflict);
    }

    let controller_digest = controller_state_digest(journal)?;
    if controller_digest == [0; 32] {
        return Err(ResourceInventoryError::CorruptState);
    }
    let baseline_sequence = journal.snapshot_sequence();
    if invalid_sequence(baseline_sequence) {
        return Err(ResourceInventoryError::Capacity);
    }
    let post_reservation_sequence = post_transaction_sequence(baseline_sequence, 3)?;
    let (active_slot, generation, current, current_valid, predecessor) = match history.checkpoint {
        Some(checkpoint) => {
            let active_slot = if checkpoint.head.state == HeadState::CompletedCurrentSuccess {
                other_slot(checkpoint.head.active_slot)
            } else if checkpoint.head.state.is_consumed() {
                checkpoint.head.active_slot
            } else {
                return Err(ResourceInventoryError::Conflict);
            };
            let current_valid = checkpoint.current_is_valid_now(controller_digest);
            let predecessor = Some(PredecessorIdentity::new(
                &checkpoint.active_request_view()?,
                checkpoint.head.request_digest,
            )?);
            (
                active_slot,
                next_generation(checkpoint.head.generation)?,
                checkpoint.current,
                current_valid,
                predecessor,
            )
        }
        None => {
            let current = match history.legacy_record {
                Some((record, inventory)) => CurrentSnapshot::Legacy { record, inventory },
                None => CurrentSnapshot::None,
            };
            let current_valid = current.controller_digest() == Some(controller_digest);
            (0, 1, current, current_valid, None)
        }
    };
    let request_digest = slot_digest(
        REQUEST_SLOT_DIGEST_DOMAIN,
        active_slot,
        request.exact_value(),
    )?;
    let replayable_predecessor = matches!(
        current,
        CurrentSnapshot::Authenticated { pointer, .. } if pointer.slot != active_slot
    );
    let head = CheckpointHead::new(
        HeadState::Outstanding,
        active_slot,
        replayable_predecessor,
        current_valid,
        generation,
        post_reservation_sequence,
        baseline_sequence,
        controller_digest,
        &incoming,
        request_digest,
        [0; 32],
        predecessor,
        current.stable_identity(),
    )?;
    let transaction = JournalTransaction::new(
        transaction_id(head),
        vec![
            JournalRecord::put(
                RecordNamespace::NetworkResourceInventory,
                REQUEST_KEYS[active_slot].to_vec(),
                request.exact_value().to_vec(),
            ),
            JournalRecord::delete(
                RecordNamespace::NetworkResourceInventory,
                OUTCOME_KEYS[active_slot].to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::NetworkResourceInventory,
                HEAD_KEY.to_vec(),
                head.encode()?.to_vec(),
            ),
        ],
    )?;
    journal.commit(&transaction)?;
    if journal.snapshot_sequence() != post_reservation_sequence {
        return Err(ResourceInventoryError::CorruptState);
    }
    let recovered = load_history(journal)?
        .checkpoint
        .ok_or(ResourceInventoryError::CorruptState)?;
    if recovered.head != head || recovered.active_request()? != request.exact_value() {
        return Err(ResourceInventoryError::CorruptState);
    }

    Ok(ReservationDisposition::Reserved(ReservationReceipt {
        head,
        request_value: request.exact_value().to_vec(),
        baseline_sequence,
        post_reservation_sequence,
    }))
}

/// Completes an exact live reservation while separating current and noncurrent results.
fn complete_outcome(
    journal: &mut Journal,
    reservation: ReservationReceipt,
    draft: NetworkInventoryOutcomeCheckpointDraftV1,
) -> Result<CompletionDisposition, ResourceInventoryError> {
    journal.ensure_healthy()?;
    let history = load_history(journal)?;
    let checkpoint = history.checkpoint.ok_or(ResourceInventoryError::Conflict)?;
    if checkpoint.head != reservation.head
        || checkpoint.head.state != HeadState::Outstanding
        || checkpoint.active_request()? != reservation.request_value
        || reservation.baseline_sequence != checkpoint.head.reservation_baseline_sequence
        || reservation.post_reservation_sequence != checkpoint.head.expected_journal_sequence
        || reservation.request_value != draft.exact_request_value()
    {
        return Err(ResourceInventoryError::Conflict);
    }
    let recovered = decode_recovered_network_inventory_checkpoint_values_v1(
        draft.exact_request_value(),
        draft.exact_outcome_value(),
    )
    .map_err(|_| ResourceInventoryError::CorruptState)?;
    if recovered.result() != draft.result() {
        return Err(ResourceInventoryError::CorruptState);
    }
    let slot = checkpoint.head.active_slot;
    let outcome_digest = slot_digest(
        OUTCOME_SLOT_DIGEST_DOMAIN,
        slot,
        draft.exact_outcome_value(),
    )?;
    let live_sequence = journal.snapshot_sequence();
    let live_controller_digest = controller_state_digest(journal)?;
    if live_controller_digest == [0; 32] {
        return Err(ResourceInventoryError::CorruptState);
    }

    match draft.result() {
        AuthenticatedNetworkInventoryResultV1::Error(_) => commit_noncurrent(
            journal,
            checkpoint,
            draft,
            outcome_digest,
            HeadState::CompletedTerminal,
            live_sequence,
            live_controller_digest,
        ),
        AuthenticatedNetworkInventoryResultV1::Success(inventory) => {
            let candidate = ValidatedResourceInventory::Network(inventory.clone());
            let state = if live_sequence != reservation.post_reservation_sequence
                || live_controller_digest != checkpoint.head.active_controller_digest
            {
                HeadState::CompletedStaleSuccess
            } else {
                match checkpoint.current.inventory() {
                    None => HeadState::CompletedCurrentSuccess,
                    Some(current) => match classify_inventory_continuity(&current, &candidate) {
                        Ok(SnapshotDecision::Record) => HeadState::CompletedCurrentSuccess,
                        Ok(SnapshotDecision::Unchanged | SnapshotDecision::Replay)
                            if checkpoint.head.current_valid =>
                        {
                            HeadState::CompletedStaleSuccess
                        }
                        Ok(SnapshotDecision::Unchanged | SnapshotDecision::Replay) => {
                            HeadState::CompletedCurrentSuccess
                        }
                        Err(_) => HeadState::CompletedIntegritySuccess,
                    },
                }
            };
            if state == HeadState::CompletedCurrentSuccess {
                commit_current_success(
                    journal,
                    checkpoint,
                    draft,
                    recovered,
                    candidate,
                    outcome_digest,
                    live_sequence,
                )
            } else {
                commit_noncurrent(
                    journal,
                    checkpoint,
                    draft,
                    outcome_digest,
                    state,
                    live_sequence,
                    live_controller_digest,
                )
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_current_success(
    journal: &mut Journal,
    checkpoint: RecoveredCheckpoint,
    draft: NetworkInventoryOutcomeCheckpointDraftV1,
    recovered: RecoveredNetworkInventoryCheckpointViewV1,
    inventory: ValidatedResourceInventory,
    outcome_digest: [u8; 32],
    live_sequence: u64,
) -> Result<CompletionDisposition, ResourceInventoryError> {
    let old_current_slot = match checkpoint.current {
        CurrentSnapshot::Authenticated { pointer, .. } => Some(pointer.slot),
        _ => None,
    };
    let record_count = if old_current_slot.is_some() { 5 } else { 3 };
    let expected_sequence = post_transaction_sequence(live_sequence, record_count)?;
    let request = checkpoint.active_request_view()?;
    let generation = next_generation(checkpoint.head.generation)?;
    let pointer = CurrentPointer::new(
        checkpoint.head.active_slot,
        checkpoint.head.active_controller_digest,
        &request,
        checkpoint.head.request_digest,
        outcome_digest,
        generation,
        checkpoint.head.reservation_baseline_sequence,
    )?;
    let head = checkpoint.head.with_transition(
        HeadState::CompletedCurrentSuccess,
        expected_sequence,
        true,
        pointer.digest,
        outcome_digest,
    )?;
    let mut records = vec![
        JournalRecord::put(
            RecordNamespace::NetworkResourceInventory,
            OUTCOME_KEYS[head.active_slot].to_vec(),
            draft.exact_outcome_value().to_vec(),
        ),
        JournalRecord::put(
            RecordNamespace::NetworkResourceInventory,
            HEAD_KEY.to_vec(),
            head.encode()?.to_vec(),
        ),
        JournalRecord::put(
            RecordNamespace::NetworkResourceInventory,
            KEY.to_vec(),
            pointer.encode()?.to_vec(),
        ),
    ];
    if let Some(old_slot) = old_current_slot {
        records.push(JournalRecord::delete(
            RecordNamespace::NetworkResourceInventory,
            REQUEST_KEYS[old_slot].to_vec(),
        ));
        records.push(JournalRecord::delete(
            RecordNamespace::NetworkResourceInventory,
            OUTCOME_KEYS[old_slot].to_vec(),
        ));
    }
    commit_and_require_head(journal, head, records)?;
    let recovered_checkpoint = load_history(journal)?
        .checkpoint
        .ok_or(ResourceInventoryError::CorruptState)?;
    if recovered_checkpoint.current.stable_identity() != pointer.digest
        || recovered_checkpoint.active_pair_view()?.result() != recovered.result()
    {
        return Err(ResourceInventoryError::CorruptState);
    }
    Ok(CompletionDisposition::Current(CurrentSuccessReceipt {
        head,
        pointer,
        request_value: draft.exact_request_value().to_vec(),
        outcome_value: draft.exact_outcome_value().to_vec(),
        inventory,
    }))
}

fn commit_noncurrent(
    journal: &mut Journal,
    checkpoint: RecoveredCheckpoint,
    draft: NetworkInventoryOutcomeCheckpointDraftV1,
    outcome_digest: [u8; 32],
    state: HeadState,
    live_sequence: u64,
    live_controller_digest: [u8; 32],
) -> Result<CompletionDisposition, ResourceInventoryError> {
    if !matches!(
        state,
        HeadState::CompletedStaleSuccess
            | HeadState::CompletedIntegritySuccess
            | HeadState::CompletedTerminal
    ) {
        return Err(ResourceInventoryError::CorruptState);
    }
    let expected_sequence = post_transaction_sequence(live_sequence, 2)?;
    let current_valid = checkpoint.current_is_valid_now(live_controller_digest);
    let head = checkpoint.head.with_transition(
        state,
        expected_sequence,
        current_valid,
        checkpoint.current.stable_identity(),
        outcome_digest,
    )?;
    commit_and_require_head(
        journal,
        head,
        vec![
            JournalRecord::put(
                RecordNamespace::NetworkResourceInventory,
                OUTCOME_KEYS[head.active_slot].to_vec(),
                draft.exact_outcome_value().to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::NetworkResourceInventory,
                HEAD_KEY.to_vec(),
                head.encode()?.to_vec(),
            ),
        ],
    )?;
    let token = CompletedPairToken { head };
    match state {
        HeadState::CompletedStaleSuccess => {
            Ok(CompletionDisposition::Stale(StaleSuccessReceipt { token }))
        }
        HeadState::CompletedIntegritySuccess => {
            Ok(CompletionDisposition::Integrity(IntegritySuccessReceipt {
                token,
            }))
        }
        HeadState::CompletedTerminal => {
            Ok(CompletionDisposition::Terminal(TerminalReceipt { token }))
        }
        _ => Err(ResourceInventoryError::CorruptState),
    }
}

/// Consumes one exact noncurrent completion without deleting its inspection bytes.
fn consume_completed(
    journal: &mut Journal,
    token: CompletedPairToken,
) -> Result<(), ResourceInventoryError> {
    journal.ensure_healthy()?;
    let history = load_history(journal)?;
    let checkpoint = history.checkpoint.ok_or(ResourceInventoryError::Conflict)?;
    if checkpoint.head != token.head || !checkpoint.head.state.is_unconsumed_noncurrent() {
        return Err(ResourceInventoryError::Conflict);
    }
    checkpoint.active_pair_view()?;
    let controller_digest = controller_state_digest(journal)?;
    let current_valid = checkpoint.current_is_valid_now(controller_digest);
    let state = checkpoint
        .head
        .state
        .consumed()
        .ok_or(ResourceInventoryError::CorruptState)?;
    let live_sequence = journal.snapshot_sequence();
    let expected_sequence = post_transaction_sequence(live_sequence, 1)?;
    let head = checkpoint.head.with_transition(
        state,
        expected_sequence,
        current_valid,
        checkpoint.current.stable_identity(),
        checkpoint.head.outcome_digest,
    )?;
    commit_and_require_head(
        journal,
        head,
        vec![JournalRecord::put(
            RecordNamespace::NetworkResourceInventory,
            HEAD_KEY.to_vec(),
            head.encode()?.to_vec(),
        )],
    )
}

/// Rechecks the exact current-success pointer, head, pair, and controller state.
fn recheck_current_success(
    journal: &mut Journal,
    receipt: &CurrentSuccessReceipt,
) -> Result<(), ResourceInventoryError> {
    journal.ensure_healthy()?;
    let history = load_history(journal)?;
    let checkpoint = history.checkpoint.ok_or(ResourceInventoryError::Conflict)?;
    if receipt.head.state != HeadState::CompletedCurrentSuccess
        || checkpoint.head != receipt.head
        || !checkpoint.head.current_valid
        || checkpoint.head.current_stable_identity != receipt.pointer.digest
    {
        return Err(ResourceInventoryError::Conflict);
    }
    let CurrentSnapshot::Authenticated {
        pointer, recovered, ..
    } = &checkpoint.current
    else {
        return Err(ResourceInventoryError::CorruptState);
    };
    let recovered_inventory = match recovered.result() {
        AuthenticatedNetworkInventoryResultV1::Success(inventory) => {
            ValidatedResourceInventory::Network(inventory.clone())
        }
        AuthenticatedNetworkInventoryResultV1::Error(_) => {
            return Err(ResourceInventoryError::CorruptState);
        }
    };
    if pointer != &receipt.pointer
        || checkpoint.slots[pointer.slot].request.as_deref()
            != Some(receipt.request_value.as_slice())
        || checkpoint.slots[pointer.slot].outcome.as_deref()
            != Some(receipt.outcome_value.as_slice())
        || controller_state_digest(journal)? != receipt.pointer.controller_digest
        || recovered_inventory != receipt.inventory
    {
        return Err(ResourceInventoryError::Conflict);
    }
    Ok(())
}

fn lookup_completed(
    history: &RecoveredHistory,
    request_value: &[u8],
    incoming: &RecoveredNetworkInventoryRequestCheckpointViewV1,
) -> Result<Option<Vec<u8>>, ResourceInventoryError> {
    let Some(checkpoint) = &history.checkpoint else {
        return Ok(None);
    };
    let mut completed = Vec::with_capacity(2);
    if checkpoint.head.state.has_outcome() {
        completed.push((checkpoint.active_request()?, checkpoint.active_outcome()?));
    }
    if let CurrentSnapshot::Authenticated {
        pointer,
        request_value,
        outcome_value,
        ..
    } = &checkpoint.current
        && pointer.slot != checkpoint.head.active_slot
    {
        completed.push((request_value.as_slice(), outcome_value.as_slice()));
    }

    for (retained_request, retained_outcome) in completed {
        let pair = decode_recovered_network_inventory_checkpoint_values_v1(
            retained_request,
            retained_outcome,
        )
        .map_err(|_| ResourceInventoryError::CorruptState)?;
        if same_identity(&pair, incoming) {
            if retained_request != request_value {
                return Err(ResourceInventoryError::Conflict);
            }
            return Ok(Some(pair.exact_outcome_packet().to_vec()));
        }
        if pair_collides(&pair, incoming) {
            return Err(ResourceInventoryError::Conflict);
        }
    }
    if predecessor_collides(checkpoint.head.predecessor, incoming) {
        return Err(ResourceInventoryError::Conflict);
    }
    Ok(None)
}

fn require_next_request(
    checkpoint: &RecoveredCheckpoint,
    incoming: &RecoveredNetworkInventoryRequestCheckpointViewV1,
) -> Result<(), ResourceInventoryError> {
    if checkpoint.head.state.has_outcome() {
        let pair = checkpoint.active_pair_view()?;
        if pair_collides(&pair, incoming) {
            return Err(ResourceInventoryError::Conflict);
        }
    }
    if let CurrentSnapshot::Authenticated {
        pointer, recovered, ..
    } = &checkpoint.current
        && pointer.slot != checkpoint.head.active_slot
    {
        if pair_collides(recovered, incoming)
            || (recovered.session_binding() == incoming.session_binding()
                && recovered.client_sequence() >= incoming.client_sequence())
        {
            return Err(ResourceInventoryError::Conflict);
        }
    }
    if let CurrentSnapshot::Legacy { record, .. } = &checkpoint.current
        && record.request_id == incoming.request_id()
    {
        return Err(ResourceInventoryError::Conflict);
    }
    if predecessor_collides(checkpoint.head.predecessor, incoming) {
        return Err(ResourceInventoryError::Conflict);
    }
    let predecessor = checkpoint.active_request_view()?;
    if predecessor.request_id() == incoming.request_id() {
        return Err(ResourceInventoryError::Conflict);
    }
    let expected_sequence = if predecessor.session_binding() == incoming.session_binding() {
        predecessor
            .client_sequence()
            .checked_add(1)
            .ok_or(ResourceInventoryError::Conflict)?
    } else {
        1
    };
    if incoming.client_sequence() != expected_sequence {
        return Err(ResourceInventoryError::Conflict);
    }
    Ok(())
}

fn predecessor_collides(
    predecessor: Option<PredecessorIdentity>,
    request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
) -> bool {
    predecessor.is_some_and(|predecessor| {
        predecessor.session_binding == request.session_binding()
            && (predecessor.request_id == request.request_id()
                || predecessor.client_sequence >= request.client_sequence())
    })
}

fn commit_and_require_head(
    journal: &mut Journal,
    head: CheckpointHead,
    records: Vec<JournalRecord>,
) -> Result<(), ResourceInventoryError> {
    journal.ensure_healthy()?;
    let transaction = JournalTransaction::new(transaction_id(head), records)?;
    journal.commit(&transaction)?;
    if journal.snapshot_sequence() != head.expected_journal_sequence {
        return Err(ResourceInventoryError::CorruptState);
    }
    let recovered = load_history(journal)?
        .checkpoint
        .ok_or(ResourceInventoryError::CorruptState)?;
    if recovered.head != head {
        return Err(ResourceInventoryError::CorruptState);
    }
    Ok(())
}

fn same_identity(
    completed: &RecoveredNetworkInventoryCheckpointViewV1,
    request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
) -> bool {
    completed.session_binding() == request.session_binding()
        && completed.request_id() == request.request_id()
        && completed.client_sequence() == request.client_sequence()
}

fn pair_collides(
    completed: &RecoveredNetworkInventoryCheckpointViewV1,
    request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
) -> bool {
    completed.session_binding() == request.session_binding()
        && (completed.request_id() == request.request_id()
            || completed.client_sequence() == request.client_sequence())
}

fn request_collides(
    retained: &RecoveredNetworkInventoryRequestCheckpointViewV1,
    request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
) -> bool {
    retained.session_binding() == request.session_binding()
        && (retained.request_id() == request.request_id()
            || retained.client_sequence() == request.client_sequence())
}

fn transaction_id(head: CheckpointHead) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(head.digest)
        .finalize()
        .into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    id
}

const fn other_slot(slot: usize) -> usize {
    1 - slot
}
