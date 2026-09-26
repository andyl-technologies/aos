//! Fixed controller Network Inventory checkpoint records.
//!
//! `AOSBRI02` is the 224-byte authenticated-current pointer kept under the
//! historical `latest` key. `AOSBIH01` is the 344-byte alternating-slot head:
//!
//! ```text
//! AOSBRI02 (224 bytes)
//!   0..8    magic                 104..136 request-slot digest
//!   8       state                 136..168 outcome-slot digest
//!   9       Network domain        168..176 generation
//!   10      slot                  176..184 reservation baseline
//!   11..16  reserved              184..192 reserved
//!   16..48  controller digest     192..224 pointer digest
//!   48..80  session binding
//!   80..96  request ID
//!   96..104 client sequence
//!
//! AOSBIH01 (344 bytes)
//!   0..8    magic                 72..104  active session binding
//!   8..10   version               104..120 active request ID
//!   10      state                 120..128 active client sequence
//!   11      active slot           128..160 active request-slot digest
//!   12      replay predecessor    160..192 active outcome-slot digest
//!   13      current-valid flags   192..224 predecessor session binding
//!   14..16  reserved              224..240 predecessor request ID
//!   16..24  generation
//!   24..32  expected sequence
//!   32..40  reservation baseline
//!   40..72  captured controller digest
//!                              240..248 predecessor client sequence
//!                              248..280 predecessor request-slot digest
//!                              280..312 current stable identity
//!                              312..344 head digest
//!
//! pointer digest = SHA-256(pointer-domain || u32be(192) || pointer prefix)
//! head digest    = SHA-256(head-domain || u32be(312) || head prefix)
//! ```
//!
//! Head states are closed: 1 outstanding, 2 current success, 3 stale success,
//! 4 integrity-rejected success, 5 terminal, and 6..8 the consumed forms of
//! states 3..5. Generation records the owner lifecycle phase relative to the
//! authenticated current pointer; journal-sequence deltas record exact owner
//! transaction widths and intervening traffic only for reservation ABA checks,
//! never lasting current authority. Reserved bytes and every other state, slot,
//! flag, or impossible lifecycle reject.
//!
//! These codecs establish structural integrity only. Durable provenance and
//! live controller authority remain properties of the enclosing owner state.

use aos_sandbox_protocol::authenticated_session::checkpoint::RecoveredNetworkInventoryRequestCheckpointViewV1;
use sha2::{Digest as _, Sha256};

use super::ResourceInventoryError;

const POINTER_MAGIC: &[u8; 8] = b"AOSBRI02";
const POINTER_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.resource-inventory.v2\0";
const POINTER_STATE: u8 = 1;
const NETWORK_DOMAIN: u8 = 2;
const POINTER_PREFIX_BYTES: usize = 192;
pub(super) const POINTER_BYTES: usize = 224;

const HEAD_MAGIC: &[u8; 8] = b"AOSBIH01";
const HEAD_VERSION: u16 = 1;
const HEAD_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller.network-inventory.head.v1\0";
const HEAD_PREFIX_BYTES: usize = 312;
pub(super) const HEAD_BYTES: usize = 344;

const OUTSTANDING: u8 = 1;
const COMPLETED_CURRENT_SUCCESS: u8 = 2;
const COMPLETED_STALE_SUCCESS: u8 = 3;
const COMPLETED_INTEGRITY_SUCCESS: u8 = 4;
const COMPLETED_TERMINAL: u8 = 5;
const CONSUMED_STALE_SUCCESS: u8 = 6;
const CONSUMED_INTEGRITY_SUCCESS: u8 = 7;
const CONSUMED_TERMINAL: u8 = 8;

const CURRENT_VALID: u8 = 1;

const _: () = assert!(POINTER_BYTES == 224);
const _: () = assert!(HEAD_BYTES == 344);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HeadState {
    Outstanding,
    CompletedCurrentSuccess,
    CompletedStaleSuccess,
    CompletedIntegritySuccess,
    CompletedTerminal,
    ConsumedStaleSuccess,
    ConsumedIntegritySuccess,
    ConsumedTerminal,
}

impl HeadState {
    fn decode(value: u8) -> Result<Self, ResourceInventoryError> {
        match value {
            OUTSTANDING => Ok(Self::Outstanding),
            COMPLETED_CURRENT_SUCCESS => Ok(Self::CompletedCurrentSuccess),
            COMPLETED_STALE_SUCCESS => Ok(Self::CompletedStaleSuccess),
            COMPLETED_INTEGRITY_SUCCESS => Ok(Self::CompletedIntegritySuccess),
            COMPLETED_TERMINAL => Ok(Self::CompletedTerminal),
            CONSUMED_STALE_SUCCESS => Ok(Self::ConsumedStaleSuccess),
            CONSUMED_INTEGRITY_SUCCESS => Ok(Self::ConsumedIntegritySuccess),
            CONSUMED_TERMINAL => Ok(Self::ConsumedTerminal),
            _ => Err(ResourceInventoryError::CorruptState),
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Outstanding => OUTSTANDING,
            Self::CompletedCurrentSuccess => COMPLETED_CURRENT_SUCCESS,
            Self::CompletedStaleSuccess => COMPLETED_STALE_SUCCESS,
            Self::CompletedIntegritySuccess => COMPLETED_INTEGRITY_SUCCESS,
            Self::CompletedTerminal => COMPLETED_TERMINAL,
            Self::ConsumedStaleSuccess => CONSUMED_STALE_SUCCESS,
            Self::ConsumedIntegritySuccess => CONSUMED_INTEGRITY_SUCCESS,
            Self::ConsumedTerminal => CONSUMED_TERMINAL,
        }
    }

    pub(super) const fn has_outcome(self) -> bool {
        !matches!(self, Self::Outstanding)
    }

    pub(super) const fn is_unconsumed_noncurrent(self) -> bool {
        matches!(
            self,
            Self::CompletedStaleSuccess | Self::CompletedIntegritySuccess | Self::CompletedTerminal
        )
    }

    pub(super) const fn is_consumed(self) -> bool {
        matches!(
            self,
            Self::ConsumedStaleSuccess | Self::ConsumedIntegritySuccess | Self::ConsumedTerminal
        )
    }

    pub(super) const fn consumed(self) -> Option<Self> {
        match self {
            Self::CompletedStaleSuccess => Some(Self::ConsumedStaleSuccess),
            Self::CompletedIntegritySuccess => Some(Self::ConsumedIntegritySuccess),
            Self::CompletedTerminal => Some(Self::ConsumedTerminal),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CurrentPointer {
    pub(super) slot: usize,
    pub(super) controller_digest: [u8; 32],
    pub(super) session_binding: [u8; 32],
    pub(super) request_id: [u8; 16],
    pub(super) client_sequence: u64,
    pub(super) request_digest: [u8; 32],
    pub(super) outcome_digest: [u8; 32],
    pub(super) generation: u64,
    pub(super) reservation_baseline_sequence: u64,
    pub(super) digest: [u8; 32],
}

impl CurrentPointer {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ResourceInventoryError> {
        if bytes.len() != POINTER_BYTES
            || bytes.get(..8) != Some(POINTER_MAGIC.as_slice())
            || bytes.get(8) != Some(&POINTER_STATE)
            || bytes.get(9) != Some(&NETWORK_DOMAIN)
            || bytes.get(11..16) != Some([0_u8; 5].as_slice())
            || bytes.get(184..192) != Some([0_u8; 8].as_slice())
        {
            return Err(ResourceInventoryError::CorruptState);
        }
        let pointer = Self {
            slot: decode_slot(bytes[10])?,
            controller_digest: take_array(bytes, 16)?,
            session_binding: take_array(bytes, 48)?,
            request_id: take_array(bytes, 80)?,
            client_sequence: u64::from_be_bytes(take_array(bytes, 96)?),
            request_digest: take_array(bytes, 104)?,
            outcome_digest: take_array(bytes, 136)?,
            generation: u64::from_be_bytes(take_array(bytes, 168)?),
            reservation_baseline_sequence: u64::from_be_bytes(take_array(bytes, 176)?),
            digest: take_array(bytes, 192)?,
        };
        pointer.validate()?;
        if pointer.encode()? != bytes {
            return Err(ResourceInventoryError::CorruptState);
        }
        Ok(pointer)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        slot: usize,
        controller_digest: [u8; 32],
        request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
        request_digest: [u8; 32],
        outcome_digest: [u8; 32],
        generation: u64,
        reservation_baseline_sequence: u64,
    ) -> Result<Self, ResourceInventoryError> {
        let mut pointer = Self {
            slot,
            controller_digest,
            session_binding: request.session_binding(),
            request_id: request.request_id(),
            client_sequence: request.client_sequence(),
            request_digest,
            outcome_digest,
            generation,
            reservation_baseline_sequence,
            digest: [0; 32],
        };
        pointer.digest = fixed_digest(POINTER_DIGEST_DOMAIN, &pointer.prefix()?)?;
        pointer.validate()?;
        Ok(pointer)
    }

    fn validate(self) -> Result<(), ResourceInventoryError> {
        if self.slot > 1
            || self.controller_digest == [0; 32]
            || self.session_binding == [0; 32]
            || self.request_id == [0; 16]
            || invalid_sequence(self.client_sequence)
            || self.request_digest == [0; 32]
            || self.outcome_digest == [0; 32]
            || invalid_sequence(self.generation)
            || invalid_sequence(self.reservation_baseline_sequence)
            || self.digest == [0; 32]
        {
            return Err(ResourceInventoryError::CorruptState);
        }
        Ok(())
    }

    fn prefix(self) -> Result<[u8; POINTER_PREFIX_BYTES], ResourceInventoryError> {
        let mut bytes = [0_u8; POINTER_PREFIX_BYTES];
        bytes[..8].copy_from_slice(POINTER_MAGIC);
        bytes[8] = POINTER_STATE;
        bytes[9] = NETWORK_DOMAIN;
        bytes[10] = encode_slot(self.slot)?;
        bytes[16..48].copy_from_slice(&self.controller_digest);
        bytes[48..80].copy_from_slice(&self.session_binding);
        bytes[80..96].copy_from_slice(&self.request_id);
        bytes[96..104].copy_from_slice(&self.client_sequence.to_be_bytes());
        bytes[104..136].copy_from_slice(&self.request_digest);
        bytes[136..168].copy_from_slice(&self.outcome_digest);
        bytes[168..176].copy_from_slice(&self.generation.to_be_bytes());
        bytes[176..184].copy_from_slice(&self.reservation_baseline_sequence.to_be_bytes());
        Ok(bytes)
    }

    pub(super) fn encode(self) -> Result<[u8; POINTER_BYTES], ResourceInventoryError> {
        self.validate()?;
        let prefix = self.prefix()?;
        if fixed_digest(POINTER_DIGEST_DOMAIN, &prefix)? != self.digest {
            return Err(ResourceInventoryError::CorruptState);
        }
        let mut bytes = [0_u8; POINTER_BYTES];
        bytes[..POINTER_PREFIX_BYTES].copy_from_slice(&prefix);
        bytes[POINTER_PREFIX_BYTES..].copy_from_slice(&self.digest);
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PredecessorIdentity {
    pub(super) session_binding: [u8; 32],
    pub(super) request_id: [u8; 16],
    pub(super) client_sequence: u64,
    pub(super) request_digest: [u8; 32],
}

impl PredecessorIdentity {
    pub(super) fn new(
        request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
        request_digest: [u8; 32],
    ) -> Result<Self, ResourceInventoryError> {
        let predecessor = Self {
            session_binding: request.session_binding(),
            request_id: request.request_id(),
            client_sequence: request.client_sequence(),
            request_digest,
        };
        predecessor.validate()?;
        Ok(predecessor)
    }

    fn validate(self) -> Result<(), ResourceInventoryError> {
        if self.session_binding == [0; 32]
            || self.request_id == [0; 16]
            || invalid_sequence(self.client_sequence)
            || self.request_digest == [0; 32]
        {
            return Err(ResourceInventoryError::CorruptState);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CheckpointHead {
    pub(super) state: HeadState,
    pub(super) active_slot: usize,
    pub(super) replayable_predecessor: bool,
    pub(super) current_valid: bool,
    pub(super) generation: u64,
    pub(super) expected_journal_sequence: u64,
    pub(super) reservation_baseline_sequence: u64,
    pub(super) active_controller_digest: [u8; 32],
    pub(super) session_binding: [u8; 32],
    pub(super) request_id: [u8; 16],
    pub(super) client_sequence: u64,
    pub(super) request_digest: [u8; 32],
    pub(super) outcome_digest: [u8; 32],
    pub(super) predecessor: Option<PredecessorIdentity>,
    pub(super) current_stable_identity: [u8; 32],
    pub(super) digest: [u8; 32],
}

impl CheckpointHead {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ResourceInventoryError> {
        if bytes.len() != HEAD_BYTES
            || bytes.get(..8) != Some(HEAD_MAGIC.as_slice())
            || bytes.get(8..10) != Some(HEAD_VERSION.to_be_bytes().as_slice())
            || bytes.get(14..16) != Some([0_u8; 2].as_slice())
        {
            return Err(ResourceInventoryError::CorruptState);
        }
        let replayable_predecessor = decode_bool(bytes[12])?;
        if bytes[13] & !CURRENT_VALID != 0 {
            return Err(ResourceInventoryError::CorruptState);
        }
        let head = Self {
            state: HeadState::decode(bytes[10])?,
            active_slot: decode_slot(bytes[11])?,
            replayable_predecessor,
            current_valid: bytes[13] & CURRENT_VALID != 0,
            generation: u64::from_be_bytes(take_array(bytes, 16)?),
            expected_journal_sequence: u64::from_be_bytes(take_array(bytes, 24)?),
            reservation_baseline_sequence: u64::from_be_bytes(take_array(bytes, 32)?),
            active_controller_digest: take_array(bytes, 40)?,
            session_binding: take_array(bytes, 72)?,
            request_id: take_array(bytes, 104)?,
            client_sequence: u64::from_be_bytes(take_array(bytes, 120)?),
            request_digest: take_array(bytes, 128)?,
            outcome_digest: take_array(bytes, 160)?,
            predecessor: decode_predecessor(bytes)?,
            current_stable_identity: take_array(bytes, 280)?,
            digest: take_array(bytes, 312)?,
        };
        head.validate()?;
        if head.encode()? != bytes {
            return Err(ResourceInventoryError::CorruptState);
        }
        Ok(head)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        state: HeadState,
        active_slot: usize,
        replayable_predecessor: bool,
        current_valid: bool,
        generation: u64,
        expected_journal_sequence: u64,
        reservation_baseline_sequence: u64,
        active_controller_digest: [u8; 32],
        request: &RecoveredNetworkInventoryRequestCheckpointViewV1,
        request_digest: [u8; 32],
        outcome_digest: [u8; 32],
        predecessor: Option<PredecessorIdentity>,
        current_stable_identity: [u8; 32],
    ) -> Result<Self, ResourceInventoryError> {
        let mut head = Self {
            state,
            active_slot,
            replayable_predecessor,
            current_valid,
            generation,
            expected_journal_sequence,
            reservation_baseline_sequence,
            active_controller_digest,
            session_binding: request.session_binding(),
            request_id: request.request_id(),
            client_sequence: request.client_sequence(),
            request_digest,
            outcome_digest,
            predecessor,
            current_stable_identity,
            digest: [0; 32],
        };
        head.digest = fixed_digest(HEAD_DIGEST_DOMAIN, &head.prefix()?)?;
        head.validate()?;
        Ok(head)
    }

    fn validate(self) -> Result<(), ResourceInventoryError> {
        if self.active_slot > 1
            || invalid_sequence(self.generation)
            || invalid_sequence(self.expected_journal_sequence)
            || invalid_sequence(self.reservation_baseline_sequence)
            || self.expected_journal_sequence <= self.reservation_baseline_sequence
            || self.active_controller_digest == [0; 32]
            || self.session_binding == [0; 32]
            || self.request_id == [0; 16]
            || invalid_sequence(self.client_sequence)
            || self.request_digest == [0; 32]
            || (self.outcome_digest == [0; 32]) == self.state.has_outcome()
            || self.digest == [0; 32]
            || (self.replayable_predecessor && self.state != HeadState::Outstanding)
            || (self.current_valid && self.current_stable_identity == [0; 32])
            || !self.valid_predecessor()
            || !self.valid_journal_phase()
        {
            return Err(ResourceInventoryError::CorruptState);
        }
        Ok(())
    }

    fn valid_predecessor(self) -> bool {
        if self.state == HeadState::CompletedCurrentSuccess {
            match (self.generation, self.predecessor) {
                (2, None) => return self.client_sequence == 1,
                (4.., Some(_)) => {}
                _ => return false,
            }
        }
        let initial_lifecycle = match self.state {
            HeadState::Outstanding => self.generation == 1,
            HeadState::CompletedCurrentSuccess => false,
            HeadState::CompletedStaleSuccess
            | HeadState::CompletedIntegritySuccess
            | HeadState::CompletedTerminal => self.generation == 2,
            HeadState::ConsumedStaleSuccess
            | HeadState::ConsumedIntegritySuccess
            | HeadState::ConsumedTerminal => self.generation == 3,
        };
        let Some(predecessor) = self.predecessor else {
            return initial_lifecycle && self.client_sequence == 1;
        };
        if initial_lifecycle
            || predecessor.validate().is_err()
            || predecessor.request_id == self.request_id
        {
            return false;
        }
        let expected_sequence = if predecessor.session_binding == self.session_binding {
            predecessor.client_sequence.checked_add(1)
        } else {
            Some(1)
        };
        expected_sequence == Some(self.client_sequence)
    }

    fn valid_journal_phase(self) -> bool {
        let Some(distance) = self
            .expected_journal_sequence
            .checked_sub(self.reservation_baseline_sequence)
        else {
            return false;
        };
        match self.state {
            HeadState::Outstanding => distance == 5,
            HeadState::CompletedCurrentSuccess => matches!(distance, 10 | 12),
            HeadState::CompletedIntegritySuccess => distance == 9,
            HeadState::CompletedStaleSuccess | HeadState::CompletedTerminal => {
                distance == 9 || distance >= 12
            }
            HeadState::ConsumedStaleSuccess
            | HeadState::ConsumedIntegritySuccess
            | HeadState::ConsumedTerminal => distance == 12 || distance >= 15,
        }
    }

    fn prefix(self) -> Result<[u8; HEAD_PREFIX_BYTES], ResourceInventoryError> {
        let mut bytes = [0_u8; HEAD_PREFIX_BYTES];
        bytes[..8].copy_from_slice(HEAD_MAGIC);
        bytes[8..10].copy_from_slice(&HEAD_VERSION.to_be_bytes());
        bytes[10] = self.state.code();
        bytes[11] = encode_slot(self.active_slot)?;
        bytes[12] = u8::from(self.replayable_predecessor);
        bytes[13] = u8::from(self.current_valid);
        bytes[16..24].copy_from_slice(&self.generation.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.expected_journal_sequence.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.reservation_baseline_sequence.to_be_bytes());
        bytes[40..72].copy_from_slice(&self.active_controller_digest);
        bytes[72..104].copy_from_slice(&self.session_binding);
        bytes[104..120].copy_from_slice(&self.request_id);
        bytes[120..128].copy_from_slice(&self.client_sequence.to_be_bytes());
        bytes[128..160].copy_from_slice(&self.request_digest);
        bytes[160..192].copy_from_slice(&self.outcome_digest);
        if let Some(predecessor) = self.predecessor {
            predecessor.validate()?;
            bytes[192..224].copy_from_slice(&predecessor.session_binding);
            bytes[224..240].copy_from_slice(&predecessor.request_id);
            bytes[240..248].copy_from_slice(&predecessor.client_sequence.to_be_bytes());
            bytes[248..280].copy_from_slice(&predecessor.request_digest);
        }
        bytes[280..312].copy_from_slice(&self.current_stable_identity);
        Ok(bytes)
    }

    pub(super) fn encode(self) -> Result<[u8; HEAD_BYTES], ResourceInventoryError> {
        self.validate()?;
        let prefix = self.prefix()?;
        if fixed_digest(HEAD_DIGEST_DOMAIN, &prefix)? != self.digest {
            return Err(ResourceInventoryError::CorruptState);
        }
        let mut bytes = [0_u8; HEAD_BYTES];
        bytes[..HEAD_PREFIX_BYTES].copy_from_slice(&prefix);
        bytes[HEAD_PREFIX_BYTES..].copy_from_slice(&self.digest);
        Ok(bytes)
    }

    pub(super) fn with_transition(
        self,
        state: HeadState,
        expected_journal_sequence: u64,
        current_valid: bool,
        current_stable_identity: [u8; 32],
        outcome_digest: [u8; 32],
    ) -> Result<Self, ResourceInventoryError> {
        let mut head = Self {
            state,
            replayable_predecessor: false,
            current_valid,
            generation: next_generation(self.generation)?,
            expected_journal_sequence,
            outcome_digest,
            current_stable_identity,
            digest: [0; 32],
            ..self
        };
        head.digest = fixed_digest(HEAD_DIGEST_DOMAIN, &head.prefix()?)?;
        head.validate()?;
        Ok(head)
    }
}

pub(super) fn is_pointer(bytes: &[u8]) -> bool {
    bytes.get(..8) == Some(POINTER_MAGIC.as_slice())
}

pub(super) fn slot_digest(
    domain: &[u8],
    slot: usize,
    value: &[u8],
) -> Result<[u8; 32], ResourceInventoryError> {
    let slot = encode_slot(slot)?;
    let length = u32::try_from(value.len()).map_err(|_| ResourceInventoryError::Capacity)?;
    let digest: [u8; 32] = Sha256::new()
        .chain_update(domain)
        .chain_update([slot])
        .chain_update(length.to_be_bytes())
        .chain_update(value)
        .finalize()
        .into();
    if digest == [0; 32] {
        return Err(ResourceInventoryError::CorruptState);
    }
    Ok(digest)
}

fn fixed_digest(domain: &[u8], prefix: &[u8]) -> Result<[u8; 32], ResourceInventoryError> {
    let length = u32::try_from(prefix.len()).map_err(|_| ResourceInventoryError::Capacity)?;
    let digest: [u8; 32] = Sha256::new()
        .chain_update(domain)
        .chain_update(length.to_be_bytes())
        .chain_update(prefix)
        .finalize()
        .into();
    if digest == [0; 32] {
        return Err(ResourceInventoryError::CorruptState);
    }
    Ok(digest)
}

pub(super) fn post_transaction_sequence(
    before: u64,
    record_count: usize,
) -> Result<u64, ResourceInventoryError> {
    let frame_count = u64::try_from(record_count)
        .map_err(|_| ResourceInventoryError::Capacity)?
        .checked_add(2)
        .ok_or(ResourceInventoryError::Capacity)?;
    let after = before
        .checked_add(frame_count)
        .ok_or(ResourceInventoryError::Capacity)?;
    if invalid_sequence(after) {
        return Err(ResourceInventoryError::Capacity);
    }
    Ok(after)
}

pub(super) fn next_generation(generation: u64) -> Result<u64, ResourceInventoryError> {
    let generation = generation
        .checked_add(1)
        .ok_or(ResourceInventoryError::Capacity)?;
    if invalid_sequence(generation) {
        return Err(ResourceInventoryError::Capacity);
    }
    Ok(generation)
}

pub(super) const fn invalid_sequence(value: u64) -> bool {
    value == 0 || value == u64::MAX
}

fn encode_slot(slot: usize) -> Result<u8, ResourceInventoryError> {
    u8::try_from(slot)
        .ok()
        .filter(|value| *value <= 1)
        .ok_or(ResourceInventoryError::CorruptState)
}

fn decode_slot(slot: u8) -> Result<usize, ResourceInventoryError> {
    if slot <= 1 {
        Ok(usize::from(slot))
    } else {
        Err(ResourceInventoryError::CorruptState)
    }
}

fn decode_bool(value: u8) -> Result<bool, ResourceInventoryError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ResourceInventoryError::CorruptState),
    }
}

fn decode_predecessor(bytes: &[u8]) -> Result<Option<PredecessorIdentity>, ResourceInventoryError> {
    let session_binding = take_array(bytes, 192)?;
    let request_id = take_array(bytes, 224)?;
    let client_sequence = u64::from_be_bytes(take_array(bytes, 240)?);
    let request_digest = take_array(bytes, 248)?;
    if session_binding == [0; 32]
        && request_id == [0; 16]
        && client_sequence == 0
        && request_digest == [0; 32]
    {
        return Ok(None);
    }
    let predecessor = PredecessorIdentity {
        session_binding,
        request_id,
        client_sequence,
        request_digest,
    };
    predecessor.validate()?;
    Ok(Some(predecessor))
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ResourceInventoryError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ResourceInventoryError::CorruptState)
}
