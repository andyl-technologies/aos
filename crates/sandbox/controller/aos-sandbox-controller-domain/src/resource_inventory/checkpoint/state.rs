//! Recovery and structural validation for controller Network checkpoints.
//!
//! Recovery accepts only the closed six-key alternating-slot graph. It fully
//! decodes every retained request/outcome pair, validates head and pointer
//! links, and validates sequence high-water against the explicit predecessor
//! tuple. Recovered values remain hostile, nonauthorizing data and never
//! recreate live receipts.

use aos_sandbox_protocol::authenticated_session::{
    AuthenticatedNetworkInventoryResultV1,
    checkpoint::{
        NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES,
        NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES, RecoveredNetworkInventoryCheckpointViewV1,
        RecoveredNetworkInventoryRequestCheckpointViewV1,
        decode_recovered_network_inventory_checkpoint_values_v1,
        decode_recovered_network_inventory_request_checkpoint_value_v1,
    },
};

use super::super::{InventoryDomain, SnapshotRecord};
use super::{
    HEAD_KEY, KEY, OUTCOME_KEYS, OUTCOME_SLOT_DIGEST_DOMAIN, REQUEST_KEYS,
    REQUEST_SLOT_DIGEST_DOMAIN, ResourceInventoryError, SnapshotDecision,
    ValidatedResourceInventory, classify_inventory_continuity,
    format::{CheckpointHead, CurrentPointer, HEAD_BYTES, HeadState, is_pointer, slot_digest},
};
use crate::{Journal, RecordNamespace};

pub(super) struct SlotValues {
    pub(super) request: Option<Vec<u8>>,
    pub(super) outcome: Option<Vec<u8>>,
}

pub(super) enum CurrentSnapshot {
    None,
    Legacy {
        record: SnapshotRecord,
        inventory: ValidatedResourceInventory,
    },
    Authenticated {
        pointer: CurrentPointer,
        request_value: Vec<u8>,
        outcome_value: Vec<u8>,
        recovered: RecoveredNetworkInventoryCheckpointViewV1,
    },
}

impl CurrentSnapshot {
    pub(super) const fn stable_identity(&self) -> [u8; 32] {
        match self {
            Self::None => [0; 32],
            Self::Legacy { record, .. } => record.digest,
            Self::Authenticated { pointer, .. } => pointer.digest,
        }
    }

    pub(super) const fn controller_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::None => None,
            Self::Legacy { record, .. } => Some(record.controller_state_digest),
            Self::Authenticated { pointer, .. } => Some(pointer.controller_digest),
        }
    }

    pub(super) fn inventory(&self) -> Option<ValidatedResourceInventory> {
        match self {
            Self::None => None,
            Self::Legacy { inventory, .. } => Some(inventory.clone()),
            Self::Authenticated { recovered, .. } => match recovered.result() {
                AuthenticatedNetworkInventoryResultV1::Success(inventory) => {
                    Some(ValidatedResourceInventory::Network(inventory.clone()))
                }
                AuthenticatedNetworkInventoryResultV1::Error(_) => None,
            },
        }
    }
}

/// Retains the closed six-key graph without recreating live receipts.
pub(in crate::resource_inventory) struct RecoveredCheckpoint {
    pub(super) head: CheckpointHead,
    pub(super) current: CurrentSnapshot,
    pub(super) slots: [SlotValues; 2],
}

impl RecoveredCheckpoint {
    pub(in crate::resource_inventory) fn current_authority_matches(
        &self,
        stable_identity: [u8; 32],
    ) -> bool {
        self.head.current_valid
            && self.head.current_stable_identity == stable_identity
            && self.current.stable_identity() == stable_identity
    }

    pub(super) fn active_request(&self) -> Result<&[u8], ResourceInventoryError> {
        self.slots[self.head.active_slot]
            .request
            .as_deref()
            .ok_or(ResourceInventoryError::CorruptState)
    }

    pub(super) fn active_outcome(&self) -> Result<&[u8], ResourceInventoryError> {
        self.slots[self.head.active_slot]
            .outcome
            .as_deref()
            .ok_or(ResourceInventoryError::CorruptState)
    }

    pub(super) fn active_request_view(
        &self,
    ) -> Result<RecoveredNetworkInventoryRequestCheckpointViewV1, ResourceInventoryError> {
        decode_recovered_network_inventory_request_checkpoint_value_v1(self.active_request()?)
            .map_err(|_| ResourceInventoryError::CorruptState)
    }

    pub(super) fn active_pair_view(
        &self,
    ) -> Result<RecoveredNetworkInventoryCheckpointViewV1, ResourceInventoryError> {
        decode_recovered_network_inventory_checkpoint_values_v1(
            self.active_request()?,
            self.active_outcome()?,
        )
        .map_err(|_| ResourceInventoryError::CorruptState)
    }

    /// Rechecks retained current authority without coupling it to unrelated journal traffic.
    pub(super) fn current_is_valid_now(&self, controller_digest: [u8; 32]) -> bool {
        self.current_authority_matches(self.current.stable_identity())
            && self.current.controller_digest() == Some(controller_digest)
    }

    pub(super) fn completed_token(
        &self,
    ) -> Result<Option<super::CompletedPairToken>, ResourceInventoryError> {
        if !self.head.state.is_unconsumed_noncurrent() {
            return Ok(None);
        }
        self.active_pair_view()?;
        Ok(Some(super::CompletedPairToken { head: self.head }))
    }
}

pub(in crate::resource_inventory) struct RecoveredHistory {
    pub(in crate::resource_inventory) legacy_record:
        Option<(SnapshotRecord, ValidatedResourceInventory)>,
    pub(in crate::resource_inventory) checkpoint: Option<RecoveredCheckpoint>,
}

pub(in crate::resource_inventory) fn load_history(
    journal: &Journal,
) -> Result<RecoveredHistory, ResourceInventoryError> {
    journal.ensure_healthy()?;
    let mut latest = None;
    let mut head = None;
    let mut request_slots: [Option<Vec<u8>>; 2] = [None, None];
    let mut outcome_slots: [Option<Vec<u8>>; 2] = [None, None];

    for (key, value) in journal.records(RecordNamespace::NetworkResourceInventory) {
        let destination = if key == KEY {
            if value.len() > super::super::MAXIMUM_RECORD_BYTES {
                return Err(ResourceInventoryError::CorruptState);
            }
            &mut latest
        } else if key == HEAD_KEY {
            if value.len() != HEAD_BYTES {
                return Err(ResourceInventoryError::CorruptState);
            }
            &mut head
        } else if key == REQUEST_KEYS[0] {
            if value.len() > NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES {
                return Err(ResourceInventoryError::CorruptState);
            }
            &mut request_slots[0]
        } else if key == REQUEST_KEYS[1] {
            if value.len() > NETWORK_INVENTORY_CHECKPOINT_REQUEST_VALUE_MAXIMUM_BYTES {
                return Err(ResourceInventoryError::CorruptState);
            }
            &mut request_slots[1]
        } else if key == OUTCOME_KEYS[0] {
            if value.len() > NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES {
                return Err(ResourceInventoryError::CorruptState);
            }
            &mut outcome_slots[0]
        } else if key == OUTCOME_KEYS[1] {
            if value.len() > NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES {
                return Err(ResourceInventoryError::CorruptState);
            }
            &mut outcome_slots[1]
        } else {
            return Err(ResourceInventoryError::CorruptState);
        };
        if destination.replace(value.to_vec()).is_some() {
            return Err(ResourceInventoryError::CorruptState);
        }
    }

    let slots = [
        SlotValues {
            request: request_slots[0].take(),
            outcome: outcome_slots[0].take(),
        },
        SlotValues {
            request: request_slots[1].take(),
            outcome: outcome_slots[1].take(),
        },
    ];
    let Some(head_bytes) = head else {
        if slots
            .iter()
            .any(|slot| slot.request.is_some() || slot.outcome.is_some())
        {
            return Err(ResourceInventoryError::CorruptState);
        }
        let Some(latest) = latest else {
            return Ok(RecoveredHistory {
                legacy_record: None,
                checkpoint: None,
            });
        };
        if is_pointer(&latest) {
            return Err(ResourceInventoryError::CorruptState);
        }
        let record = SnapshotRecord::decode(&latest)?;
        if record.domain != InventoryDomain::Network {
            return Err(ResourceInventoryError::CorruptState);
        }
        let inventory = record.validate()?;
        return Ok(RecoveredHistory {
            legacy_record: Some((record, inventory)),
            checkpoint: None,
        });
    };

    let head = CheckpointHead::decode(&head_bytes)?;
    let current = decode_current(latest.as_deref(), &slots)?;
    validate_graph(&head, &current, &slots)?;
    let legacy_record = match &current {
        CurrentSnapshot::Legacy { record, inventory } => Some((record.clone(), inventory.clone())),
        _ => None,
    };
    Ok(RecoveredHistory {
        legacy_record,
        checkpoint: Some(RecoveredCheckpoint {
            head,
            current,
            slots,
        }),
    })
}

fn decode_current(
    latest: Option<&[u8]>,
    slots: &[SlotValues; 2],
) -> Result<CurrentSnapshot, ResourceInventoryError> {
    let Some(latest) = latest else {
        return Ok(CurrentSnapshot::None);
    };
    if !is_pointer(latest) {
        let record = SnapshotRecord::decode(latest)?;
        if record.domain != InventoryDomain::Network {
            return Err(ResourceInventoryError::CorruptState);
        }
        let inventory = record.validate()?;
        return Ok(CurrentSnapshot::Legacy { record, inventory });
    }

    let pointer = CurrentPointer::decode(latest)?;
    let request_value = slots[pointer.slot]
        .request
        .clone()
        .ok_or(ResourceInventoryError::CorruptState)?;
    let outcome_value = slots[pointer.slot]
        .outcome
        .clone()
        .ok_or(ResourceInventoryError::CorruptState)?;
    if slot_digest(REQUEST_SLOT_DIGEST_DOMAIN, pointer.slot, &request_value)?
        != pointer.request_digest
        || slot_digest(OUTCOME_SLOT_DIGEST_DOMAIN, pointer.slot, &outcome_value)?
            != pointer.outcome_digest
    {
        return Err(ResourceInventoryError::CorruptState);
    }
    let recovered =
        decode_recovered_network_inventory_checkpoint_values_v1(&request_value, &outcome_value)
            .map_err(|_| ResourceInventoryError::CorruptState)?;
    if !matches!(
        recovered.result(),
        AuthenticatedNetworkInventoryResultV1::Success(_)
    ) || recovered.session_binding() != pointer.session_binding
        || recovered.request_id() != pointer.request_id
        || recovered.client_sequence() != pointer.client_sequence
    {
        return Err(ResourceInventoryError::CorruptState);
    }
    Ok(CurrentSnapshot::Authenticated {
        pointer,
        request_value,
        outcome_value,
        recovered,
    })
}

fn validate_graph(
    head: &CheckpointHead,
    current: &CurrentSnapshot,
    slots: &[SlotValues; 2],
) -> Result<(), ResourceInventoryError> {
    if head.current_stable_identity != current.stable_identity()
        || (head.current_stable_identity == [0; 32]) != matches!(current, CurrentSnapshot::None)
        || (matches!(current, CurrentSnapshot::None) && head.current_valid)
    {
        return Err(ResourceInventoryError::CorruptState);
    }
    let active = &slots[head.active_slot];
    let request = active
        .request
        .as_deref()
        .ok_or(ResourceInventoryError::CorruptState)?;
    if slot_digest(REQUEST_SLOT_DIGEST_DOMAIN, head.active_slot, request)? != head.request_digest {
        return Err(ResourceInventoryError::CorruptState);
    }
    let request_view = decode_recovered_network_inventory_request_checkpoint_value_v1(request)
        .map_err(|_| ResourceInventoryError::CorruptState)?;
    if request_view.session_binding() != head.session_binding
        || request_view.request_id() != head.request_id
        || request_view.client_sequence() != head.client_sequence
    {
        return Err(ResourceInventoryError::CorruptState);
    }

    if head.state == HeadState::Outstanding {
        if active.outcome.is_some() || head.outcome_digest != [0; 32] {
            return Err(ResourceInventoryError::CorruptState);
        }
    } else {
        let outcome = active
            .outcome
            .as_deref()
            .ok_or(ResourceInventoryError::CorruptState)?;
        if slot_digest(OUTCOME_SLOT_DIGEST_DOMAIN, head.active_slot, outcome)?
            != head.outcome_digest
        {
            return Err(ResourceInventoryError::CorruptState);
        }
        let pair = decode_recovered_network_inventory_checkpoint_values_v1(request, outcome)
            .map_err(|_| ResourceInventoryError::CorruptState)?;
        let success = matches!(
            pair.result(),
            AuthenticatedNetworkInventoryResultV1::Success(_)
        );
        if success
            != matches!(
                head.state,
                HeadState::CompletedCurrentSuccess
                    | HeadState::CompletedStaleSuccess
                    | HeadState::CompletedIntegritySuccess
                    | HeadState::ConsumedStaleSuccess
                    | HeadState::ConsumedIntegritySuccess
            )
        {
            return Err(ResourceInventoryError::CorruptState);
        }
    }

    let current_slot = match current {
        CurrentSnapshot::Authenticated { pointer, .. } => Some(pointer.slot),
        _ => None,
    };
    match head.state {
        HeadState::CompletedCurrentSuccess => {
            let CurrentSnapshot::Authenticated { pointer, .. } = current else {
                return Err(ResourceInventoryError::CorruptState);
            };
            if pointer.slot != head.active_slot
                || pointer.generation != head.generation
                || pointer.reservation_baseline_sequence != head.reservation_baseline_sequence
                || pointer.controller_digest != head.active_controller_digest
                || pointer.request_digest != head.request_digest
                || pointer.outcome_digest != head.outcome_digest
                || !head.current_valid
            {
                return Err(ResourceInventoryError::CorruptState);
            }
        }
        HeadState::Outstanding => {
            let expected_predecessor = current_slot.is_some_and(|slot| slot != head.active_slot);
            if head.replayable_predecessor != expected_predecessor {
                return Err(ResourceInventoryError::CorruptState);
            }
        }
        _ => {
            if head.replayable_predecessor
                || current_slot.is_some_and(|slot| slot == head.active_slot)
            {
                return Err(ResourceInventoryError::CorruptState);
            }
        }
    }

    validate_generation_phase(head, current)?;
    validate_retained_high_water(head, current, &request_view)?;
    validate_completion_class(head, current, request, active.outcome.as_deref())?;

    for (slot_index, slot) in slots.iter().enumerate() {
        let retained = slot_index == head.active_slot || Some(slot_index) == current_slot;
        if !retained && (slot.request.is_some() || slot.outcome.is_some()) {
            return Err(ResourceInventoryError::CorruptState);
        }
        if Some(slot_index) == current_slot && (slot.request.is_none() || slot.outcome.is_none()) {
            return Err(ResourceInventoryError::CorruptState);
        }
    }
    Ok(())
}

/// Validates the owner lifecycle phase relative to the retained authenticated current.
fn validate_generation_phase(
    head: &CheckpointHead,
    current: &CurrentSnapshot,
) -> Result<(), ResourceInventoryError> {
    let base_generation = match current {
        CurrentSnapshot::Authenticated { pointer, .. } => pointer.generation,
        CurrentSnapshot::None | CurrentSnapshot::Legacy { .. } => 0,
    };
    let distance = head
        .generation
        .checked_sub(base_generation)
        .ok_or(ResourceInventoryError::CorruptState)?;
    let valid = match head.state {
        HeadState::CompletedCurrentSuccess => distance == 0,
        HeadState::Outstanding => distance > 0 && distance % 3 == 1,
        HeadState::CompletedStaleSuccess
        | HeadState::CompletedIntegritySuccess
        | HeadState::CompletedTerminal => distance % 3 == 2,
        HeadState::ConsumedStaleSuccess
        | HeadState::ConsumedIntegritySuccess
        | HeadState::ConsumedTerminal => distance > 0 && distance % 3 == 0,
    };
    if !valid {
        return Err(ResourceInventoryError::CorruptState);
    }
    Ok(())
}

fn validate_retained_high_water(
    head: &CheckpointHead,
    current: &CurrentSnapshot,
    request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
) -> Result<(), ResourceInventoryError> {
    if let CurrentSnapshot::Legacy { record, .. } = current
        && record.request_id == request.request_id()
    {
        return Err(ResourceInventoryError::CorruptState);
    }
    let CurrentSnapshot::Authenticated {
        pointer, recovered, ..
    } = current
    else {
        return Ok(());
    };
    if head.state == HeadState::CompletedCurrentSuccess {
        if pointer.generation != head.generation {
            return Err(ResourceInventoryError::CorruptState);
        }
        return Ok(());
    }
    if pointer.generation >= head.generation {
        return Err(ResourceInventoryError::CorruptState);
    }
    let distance = head
        .generation
        .checked_sub(pointer.generation)
        .ok_or(ResourceInventoryError::CorruptState)?;
    if distance <= 3 {
        let Some(predecessor) = head.predecessor else {
            return Err(ResourceInventoryError::CorruptState);
        };
        if predecessor.session_binding != recovered.session_binding()
            || predecessor.request_id != recovered.request_id()
            || predecessor.client_sequence != recovered.client_sequence()
            || predecessor.request_digest != pointer.request_digest
        {
            return Err(ResourceInventoryError::CorruptState);
        }
    }
    if recovered.session_binding() == request.session_binding()
        && (recovered.request_id() == request.request_id()
            || recovered.client_sequence() >= request.client_sequence())
    {
        return Err(ResourceInventoryError::CorruptState);
    }
    if let Some(predecessor) = head.predecessor
        && predecessor.session_binding == recovered.session_binding()
        && predecessor.request_id == recovered.request_id()
        && predecessor.client_sequence == recovered.client_sequence()
        && predecessor.request_digest != pointer.request_digest
    {
        return Err(ResourceInventoryError::CorruptState);
    }
    Ok(())
}

fn validate_completion_class(
    head: &CheckpointHead,
    current: &CurrentSnapshot,
    request: &[u8],
    outcome: Option<&[u8]>,
) -> Result<(), ResourceInventoryError> {
    if matches!(
        head.state,
        HeadState::Outstanding | HeadState::CompletedCurrentSuccess
    ) {
        return Ok(());
    }
    let outcome = outcome.ok_or(ResourceInventoryError::CorruptState)?;
    let pair = decode_recovered_network_inventory_checkpoint_values_v1(request, outcome)
        .map_err(|_| ResourceInventoryError::CorruptState)?;
    let AuthenticatedNetworkInventoryResultV1::Success(candidate) = pair.result() else {
        return if matches!(
            head.state,
            HeadState::CompletedTerminal | HeadState::ConsumedTerminal
        ) {
            Ok(())
        } else {
            Err(ResourceInventoryError::CorruptState)
        };
    };
    let candidate = ValidatedResourceInventory::Network(candidate.clone());
    let continuity = current
        .inventory()
        .map(|inventory| classify_inventory_continuity(&inventory, &candidate));
    match head.state {
        HeadState::CompletedIntegritySuccess | HeadState::ConsumedIntegritySuccess => {
            if continuity.is_some_and(|result| result.is_err()) {
                Ok(())
            } else {
                Err(ResourceInventoryError::CorruptState)
            }
        }
        HeadState::CompletedStaleSuccess | HeadState::ConsumedStaleSuccess => {
            let owner_frame_count = if head.state == HeadState::CompletedStaleSuccess {
                9
            } else {
                12
            };
            let uninterrupted_sequence = head
                .reservation_baseline_sequence
                .checked_add(owner_frame_count)
                .ok_or(ResourceInventoryError::CorruptState)?;
            let unchanged = continuity.is_some_and(|result| {
                matches!(
                    result,
                    Ok(SnapshotDecision::Unchanged | SnapshotDecision::Replay)
                )
            });
            if head.expected_journal_sequence != uninterrupted_sequence
                || (head.current_valid && unchanged)
            {
                Ok(())
            } else {
                Err(ResourceInventoryError::CorruptState)
            }
        }
        HeadState::CompletedTerminal | HeadState::ConsumedTerminal => {
            Err(ResourceInventoryError::CorruptState)
        }
        HeadState::Outstanding | HeadState::CompletedCurrentSuccess => Ok(()),
    }
}
