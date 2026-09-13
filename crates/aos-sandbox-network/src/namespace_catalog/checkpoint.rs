//! Durable owner checkpoint records for authenticated Network inventory.
//!
//! The owner atomically retains an exact request value, exact outcome value,
//! and small cross-link head. Live drafts alone may enter the write path;
//! recovery parses hostile durable bytes into a non-authorizing view and keeps
//! only the head in the catalog object.

use aos_sandbox::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_protocol::authenticated_session::{
    AuthenticatedNetworkInventoryResultV1,
    checkpoint::{
        NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES,
        NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES, NetworkInventoryCheckpointDraftError,
        NetworkInventoryCheckpointTerminalErrorV1, NetworkInventoryOutcomeCheckpointDraftV1,
        NetworkInventoryRequestCheckpointDraftV1,
        decode_recovered_network_inventory_checkpoint_values_v1,
    },
};
use sha2::{Digest as _, Sha256};

use super::{NetworkNamespaceCatalogError, NetworkNamespaceCatalogV1};

pub(super) const REQUEST_KEY: &[u8] = b"aos.network.inventory-bsa.request.v1\0";
pub(super) const OUTCOME_KEY: &[u8] = b"aos.network.inventory-bsa.outcome.v1\0";
pub(super) const HEAD_KEY: &[u8] = b"aos.network.inventory-bsa.head.v1\0";

const REQUEST_RECORD_DOMAIN: &[u8] = b"aos.sandbox.network.inventory-bsa-request-record.v1\0";
const OUTCOME_RECORD_DOMAIN: &[u8] = b"aos.sandbox.network.inventory-bsa-outcome-record.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.network.inventory-bsa-transaction.v1\0";
const HEAD_MAGIC: &[u8; 8] = b"AOSNIH01";
const HEAD_VERSION: u16 = 1;
const HEAD_BYTES: usize = 136;

const _: () = assert!(REQUEST_KEY.len() == 37);
const _: () = assert!(OUTCOME_KEY.len() == 37);
const _: () = assert!(HEAD_KEY.len() == 34);
const _: () = assert!(HEAD_BYTES == 136);

/// Keeps owner-only failures precise without widening the public catalog error.
#[derive(Debug, thiserror::Error)]
pub(super) enum InventoryBsaCheckpointError {
    #[error("authenticated Network inventory checkpoint journal failure")]
    Journal(#[from] aos_sandbox::JournalError),
    #[error("authenticated Network inventory checkpoint catalog failure")]
    Catalog(#[from] NetworkNamespaceCatalogError),
    #[error("authenticated Network inventory checkpoint draft failure")]
    Draft(#[from] NetworkInventoryCheckpointDraftError),
    #[error("authenticated Network inventory checkpoint is corrupt")]
    Corrupt,
    #[error("authenticated Network inventory checkpoint equivocation")]
    Equivocation,
    #[error("authenticated Network inventory changed before commit")]
    InventoryChanged,
    #[error("authenticated Network inventory terminal outcome lacks owner cause")]
    InvalidTerminalCause,
}

/// Retains the small, exact materialized cross-link for one completed exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InventoryBsaCheckpointHeadV1 {
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
    request_value_digest: [u8; 32],
    outcome_value_digest: [u8; 32],
}

impl InventoryBsaCheckpointHeadV1 {
    fn new(
        session_binding: [u8; 32],
        request_id: [u8; 16],
        client_sequence: u64,
        request_value_digest: [u8; 32],
        outcome_value_digest: [u8; 32],
    ) -> Result<Self, InventoryBsaCheckpointError> {
        let head = Self {
            session_binding,
            request_id,
            client_sequence,
            request_value_digest,
            outcome_value_digest,
        };
        head.validate()?;
        Ok(head)
    }

    fn decode(bytes: &[u8]) -> Result<Self, InventoryBsaCheckpointError> {
        if bytes.len() != HEAD_BYTES
            || bytes.get(..8) != Some(HEAD_MAGIC.as_slice())
            || bytes.get(8..10) != Some(HEAD_VERSION.to_be_bytes().as_slice())
            || bytes.get(10..16) != Some([0_u8; 6].as_slice())
        {
            return Err(InventoryBsaCheckpointError::Corrupt);
        }

        let head = Self {
            session_binding: take_array(bytes, 16)?,
            request_id: take_array(bytes, 48)?,
            client_sequence: u64::from_be_bytes(take_array(bytes, 64)?),
            request_value_digest: take_array(bytes, 72)?,
            outcome_value_digest: take_array(bytes, 104)?,
        };
        head.validate()?;
        if head.encode().as_slice() != bytes {
            return Err(InventoryBsaCheckpointError::Corrupt);
        }
        Ok(head)
    }

    fn encode(self) -> [u8; HEAD_BYTES] {
        let mut bytes = [0_u8; HEAD_BYTES];
        bytes[..8].copy_from_slice(HEAD_MAGIC);
        bytes[8..10].copy_from_slice(&HEAD_VERSION.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.session_binding);
        bytes[48..64].copy_from_slice(&self.request_id);
        bytes[64..72].copy_from_slice(&self.client_sequence.to_be_bytes());
        bytes[72..104].copy_from_slice(&self.request_value_digest);
        bytes[104..136].copy_from_slice(&self.outcome_value_digest);
        bytes
    }

    fn validate(self) -> Result<(), InventoryBsaCheckpointError> {
        if self.session_binding == [0; 32]
            || self.request_id == [0; 16]
            || self.client_sequence == 0
            || self.client_sequence == u64::MAX
            || self.request_value_digest == [0; 32]
            || self.outcome_value_digest == [0; 32]
        {
            return Err(InventoryBsaCheckpointError::Corrupt);
        }
        Ok(())
    }

    fn same_identity(self, other: Self) -> bool {
        self.session_binding == other.session_binding
            && self.request_id == other.request_id
            && self.client_sequence == other.client_sequence
    }

    fn collides(self, other: Self) -> bool {
        self.session_binding == other.session_binding
            && (self.request_id == other.request_id
                || self.client_sequence == other.client_sequence)
    }
}

/// Classifies the future owner transaction without exposing recovered send authority.
#[allow(
    dead_code,
    reason = "production traffic-to-owner wiring remains intentionally absent"
)]
enum InventoryBsaCheckpointCommitV1 {
    Recorded,
    ExactReplay { retained_outcome: Vec<u8> },
}

/// Separates a durable miss from exact replay without granting send authority.
#[allow(
    dead_code,
    reason = "production traffic-to-owner wiring remains intentionally absent"
)]
enum InventoryBsaCheckpointLookupV1 {
    Miss,
    ExactReplay { canonical_outcome_packet: Vec<u8> },
}

pub(super) fn is_key(key: &[u8]) -> bool {
    matches!(key, REQUEST_KEY | OUTCOME_KEY | HEAD_KEY)
}

pub(super) fn recover(
    journal: &Journal,
) -> Result<Option<InventoryBsaCheckpointHeadV1>, InventoryBsaCheckpointError> {
    journal.ensure_healthy()?;
    let request = journal.get(RecordNamespace::NetworkResourceInventory, REQUEST_KEY);
    let outcome = journal.get(RecordNamespace::NetworkResourceInventory, OUTCOME_KEY);
    let head = journal.get(RecordNamespace::NetworkResourceInventory, HEAD_KEY);
    let (request, outcome, head) = match (request, outcome, head) {
        (None, None, None) => return Ok(None),
        (Some(request), Some(outcome), Some(head)) => (request, outcome, head),
        _ => return Err(InventoryBsaCheckpointError::Corrupt),
    };
    let decoded_head = InventoryBsaCheckpointHeadV1::decode(head)?;
    let recovered = decode_recovered_network_inventory_checkpoint_values_v1(request, outcome)
        .map_err(|_| InventoryBsaCheckpointError::Corrupt)?;
    let request_digest = record_digest(REQUEST_RECORD_DOMAIN, request)?;
    let outcome_digest = record_digest(OUTCOME_RECORD_DOMAIN, outcome)?;
    if decoded_head.session_binding != recovered.session_binding()
        || decoded_head.request_id != recovered.request_id()
        || decoded_head.client_sequence != recovered.client_sequence()
        || decoded_head.request_value_digest != request_digest
        || decoded_head.outcome_value_digest != outcome_digest
    {
        return Err(InventoryBsaCheckpointError::Corrupt);
    }

    Ok(Some(decoded_head))
}

impl NetworkNamespaceCatalogV1 {
    /// Looks up exact retained request bytes without observing or mutating resources.
    #[allow(
        dead_code,
        reason = "production traffic-to-owner wiring remains intentionally absent"
    )]
    fn lookup_inventory_bsa_checkpoint(
        &self,
        request: &NetworkInventoryRequestCheckpointDraftV1,
    ) -> Result<InventoryBsaCheckpointLookupV1, InventoryBsaCheckpointError> {
        self.journal.ensure_healthy()?;
        let Some(expected_head) = self.checkpoint_head else {
            return Ok(InventoryBsaCheckpointLookupV1::Miss);
        };
        let recovered_head = recover(&self.journal)?.ok_or(InventoryBsaCheckpointError::Corrupt)?;
        if recovered_head != expected_head {
            return Err(InventoryBsaCheckpointError::Corrupt);
        }

        let retained_request = self
            .journal
            .get(RecordNamespace::NetworkResourceInventory, REQUEST_KEY)
            .ok_or(InventoryBsaCheckpointError::Corrupt)?;
        let retained_outcome = self
            .journal
            .get(RecordNamespace::NetworkResourceInventory, OUTCOME_KEY)
            .ok_or(InventoryBsaCheckpointError::Corrupt)?;
        let recovered = decode_recovered_network_inventory_checkpoint_values_v1(
            retained_request,
            retained_outcome,
        )
        .map_err(|_| InventoryBsaCheckpointError::Corrupt)?;
        let same_identity = expected_head.session_binding == request.session_binding()
            && expected_head.request_id == request.request_id()
            && expected_head.client_sequence == request.client_sequence();
        if same_identity && retained_request == request.exact_value() {
            return Ok(InventoryBsaCheckpointLookupV1::ExactReplay {
                canonical_outcome_packet: recovered.exact_outcome_packet().to_vec(),
            });
        }
        if expected_head.session_binding == request.session_binding()
            && (expected_head.request_id == request.request_id()
                || expected_head.client_sequence == request.client_sequence())
        {
            return Err(InventoryBsaCheckpointError::Equivocation);
        }

        Ok(InventoryBsaCheckpointLookupV1::Miss)
    }

    /// Atomically retains one live authenticated exchange for the future owner path.
    #[allow(
        dead_code,
        reason = "production traffic-to-owner wiring remains intentionally absent"
    )]
    fn commit_inventory_bsa_checkpoint(
        &mut self,
        draft: NetworkInventoryOutcomeCheckpointDraftV1,
    ) -> Result<InventoryBsaCheckpointCommitV1, InventoryBsaCheckpointError> {
        self.journal.ensure_healthy()?;
        let request_value = draft.exact_request_value();
        let outcome_value = draft.exact_outcome_value();
        let request_digest = record_digest(REQUEST_RECORD_DOMAIN, request_value)?;
        let outcome_digest = record_digest(OUTCOME_RECORD_DOMAIN, outcome_value)?;
        let head = InventoryBsaCheckpointHeadV1::new(
            draft.session_binding(),
            draft.request_id(),
            draft.client_sequence(),
            request_digest,
            outcome_digest,
        )?;

        if let Some(existing) = self.checkpoint_head {
            let recovered = recover(&self.journal)?.ok_or(InventoryBsaCheckpointError::Corrupt)?;
            if recovered != existing {
                return Err(InventoryBsaCheckpointError::Corrupt);
            }
            if existing.same_identity(head) {
                let retained_request = self
                    .journal
                    .get(RecordNamespace::NetworkResourceInventory, REQUEST_KEY)
                    .ok_or(InventoryBsaCheckpointError::Corrupt)?;
                let retained_outcome = self
                    .journal
                    .get(RecordNamespace::NetworkResourceInventory, OUTCOME_KEY)
                    .ok_or(InventoryBsaCheckpointError::Corrupt)?;
                if retained_request != request_value || retained_outcome != outcome_value {
                    return Err(InventoryBsaCheckpointError::Equivocation);
                }
                return Ok(InventoryBsaCheckpointCommitV1::ExactReplay {
                    retained_outcome: retained_outcome.to_vec(),
                });
            }
            if existing.collides(head) {
                return Err(InventoryBsaCheckpointError::Equivocation);
            }
        }

        match (draft.result(), draft.terminal_error()) {
            (AuthenticatedNetworkInventoryResultV1::Success(expected), None) => {
                if draft.expired_on_first_admission() {
                    return Err(InventoryBsaCheckpointError::InvalidTerminalCause);
                }
                let current_bytes = self.inventory_resources()?;
                if current_bytes != draft.exact_outcome_body() {
                    return Err(InventoryBsaCheckpointError::InventoryChanged);
                }
                let current = aos_sandbox_protocol::decode_network_resource_inventory_response(
                    &current_bytes,
                    draft.maximum_response_bytes(),
                )
                .map_err(|_| NetworkNamespaceCatalogError::InvalidInventory)?;
                if &current != expected {
                    return Err(InventoryBsaCheckpointError::InventoryChanged);
                }
            }
            (
                AuthenticatedNetworkInventoryResultV1::Error(_),
                Some(NetworkInventoryCheckpointTerminalErrorV1::DeadlineExpired),
            ) if draft.expired_on_first_admission() => {}
            (
                AuthenticatedNetworkInventoryResultV1::Error(_),
                Some(NetworkInventoryCheckpointTerminalErrorV1::ResourceExhausted),
            ) if !draft.expired_on_first_admission() => {
                let current_bytes = self.inventory_resources()?;
                if !draft.success_exceeds_response_ceiling(&current_bytes)? {
                    return Err(InventoryBsaCheckpointError::InvalidTerminalCause);
                }
            }
            // No protected owner-produced observation-failure token exists in
            // this source-only tranche, so IntegrityFailure cannot be committed.
            _ => return Err(InventoryBsaCheckpointError::InvalidTerminalCause),
        }

        let transaction = JournalTransaction::new(
            transaction_id(head),
            vec![
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    REQUEST_KEY.to_vec(),
                    request_value.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    OUTCOME_KEY.to_vec(),
                    outcome_value.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    HEAD_KEY.to_vec(),
                    head.encode().to_vec(),
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.checkpoint_head = Some(head);

        Ok(InventoryBsaCheckpointCommitV1::Recorded)
    }
}

fn record_digest(domain: &[u8], value: &[u8]) -> Result<[u8; 32], InventoryBsaCheckpointError> {
    let length = u32::try_from(value.len()).map_err(|_| InventoryBsaCheckpointError::Corrupt)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(digest.finalize().into())
}

fn transaction_id(head: InventoryBsaCheckpointHeadV1) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update(head.session_binding);
    digest.update(head.request_id);
    digest.update(head.client_sequence.to_be_bytes());
    digest.update(head.request_value_digest);
    digest.update(head.outcome_value_digest);
    let digest: [u8; 32] = digest.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    id
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], InventoryBsaCheckpointError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(InventoryBsaCheckpointError::Corrupt)
}

const _: () = assert!(
    NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES + NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES
        == 16_777_968
);
