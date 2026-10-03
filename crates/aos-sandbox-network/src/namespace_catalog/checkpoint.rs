//! Durable two-phase owner checkpoint for authenticated Network inventory.
//!
//! The protected catalog owns a single exact exchange. Its namespace admits
//! only these canonical graphs:
//!
//! ```text
//! Empty
//! request.v2 + AOSNIH02(Outstanding)
//! request.v2 + outcome.v2 + AOSNIH02(Completed)
//! ```
//!
//! Reserving a live request creates the Outstanding graph before catalog
//! observation. Completing that exact private reservation creates the
//! Completed replay graph. Recovery parses hostile durable bytes without
//! recreating reservation or response-send authority.

use aos_proto::aos::sandbox::local::v1::InventoryNetworkResourcesResponse;
use aos_sandbox::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES,
    authenticated_session::{
        AuthenticatedNetworkInventoryResultV1,
        checkpoint::{
            NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES,
            NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES, NetworkInventoryCheckpointDraftError,
            NetworkInventoryCheckpointTerminalErrorV1, NetworkInventoryOutcomeCheckpointDraftV1,
            NetworkInventoryRequestCheckpointDraftV1,
            decode_recovered_network_inventory_checkpoint_values_v1,
            decode_recovered_network_inventory_request_checkpoint_value_v1,
        },
    },
    decode_network_resource_inventory_response,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    MAXIMUM_JOURNAL_RECORD_BYTES, MAXIMUM_JOURNAL_TRANSACTION_BYTES, NetworkNamespaceCatalogError,
    NetworkNamespaceCatalogV1,
};

pub(super) const REQUEST_KEY: &[u8] = b"aos.network.inventory-bsa.request.v2\0";
pub(super) const OUTCOME_KEY: &[u8] = b"aos.network.inventory-bsa.outcome.v2\0";
pub(super) const HEAD_KEY: &[u8] = b"aos.network.inventory-bsa.head.v2\0";

const REQUEST_RECORD_DOMAIN: &[u8] = b"aos.sandbox.network.inventory-bsa-request-record.v2\0";
const OUTCOME_RECORD_DOMAIN: &[u8] = b"aos.sandbox.network.inventory-bsa-outcome-record.v2\0";
const RESERVE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.network.inventory-bsa-reserve-transaction.v2\0";
const COMPLETE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.network.inventory-bsa-complete-transaction.v2\0";
const CATALOG_PROJECTION_DOMAIN: &[u8] =
    b"aos.sandbox.network.inventory-bsa-catalog-projection.v2\0";
const HEAD_MAGIC: &[u8; 8] = b"AOSNIH02";
const HEAD_VERSION: u16 = 2;
const HEAD_BYTES: usize = 136;
const JOURNAL_RECORD_FRAMING_BYTES: usize = 7;

const _: () = assert!(REQUEST_KEY.len() == 37);
const _: () = assert!(OUTCOME_KEY.len() == 37);
const _: () = assert!(HEAD_KEY.len() == 34);
const _: () = assert!(HEAD_BYTES == 136);

/// Reports owner-only authenticated Network inventory checkpoint failure.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum BrokerNetworkInventoryCheckpointErrorV1 {
    /// The protected namespace journal failed validation or publication.
    #[error("authenticated Network inventory checkpoint journal failure")]
    Journal(#[from] aos_sandbox::JournalError),
    /// The protected namespace catalog failed observation or revalidation.
    #[error("authenticated Network inventory checkpoint catalog failure")]
    Catalog(#[from] NetworkNamespaceCatalogError),
    /// The live authenticated checkpoint evidence was inconsistent.
    #[error("authenticated Network inventory checkpoint draft failure")]
    Draft(#[from] NetworkInventoryCheckpointDraftError),
    /// Durable checkpoint bytes violate the exact closed format.
    #[error("authenticated Network inventory checkpoint is corrupt")]
    Corrupt,
    /// A retained request identity was reused with different exact evidence.
    #[error("authenticated Network inventory checkpoint equivocation")]
    Equivocation,
    /// A live request is not the required initial sequence-one exchange.
    #[error("authenticated Network inventory checkpoint request is not initial")]
    InvalidInitialRequest,
    /// The protected inventory changed between causal observation and commit.
    #[error("authenticated Network inventory changed before commit")]
    InventoryChanged,
    /// A terminal outcome lacks its exact purpose-specific owner cause.
    #[error("authenticated Network inventory terminal outcome lacks owner cause")]
    InvalidTerminalCause,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum InventoryBsaCheckpointStateV2 {
    Outstanding = 1,
    Completed = 2,
}

impl InventoryBsaCheckpointStateV2 {
    fn decode(value: u8) -> Result<Self, BrokerNetworkInventoryCheckpointErrorV1> {
        match value {
            1 => Ok(Self::Outstanding),
            2 => Ok(Self::Completed),
            _ => Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt),
        }
    }
}

/// Retains the fixed cross-link for one reserved or completed exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InventoryBsaCheckpointHeadV2 {
    state: InventoryBsaCheckpointStateV2,
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
    request_value_digest: [u8; 32],
    outcome_value_digest: [u8; 32],
}

impl InventoryBsaCheckpointHeadV2 {
    fn outstanding(
        request: &NetworkInventoryRequestCheckpointDraftV1,
    ) -> Result<Self, BrokerNetworkInventoryCheckpointErrorV1> {
        Self::new(
            InventoryBsaCheckpointStateV2::Outstanding,
            request.session_binding(),
            request.request_id(),
            request.client_sequence(),
            record_digest(REQUEST_RECORD_DOMAIN, request.exact_value())?,
            [0; 32],
        )
    }

    fn completed(
        reservation: &BrokerNetworkInventoryReservationV1,
        outcome_value: &[u8],
    ) -> Result<Self, BrokerNetworkInventoryCheckpointErrorV1> {
        Self::new(
            InventoryBsaCheckpointStateV2::Completed,
            reservation.head.session_binding,
            reservation.head.request_id,
            reservation.head.client_sequence,
            reservation.head.request_value_digest,
            record_digest(OUTCOME_RECORD_DOMAIN, outcome_value)?,
        )
    }

    fn new(
        state: InventoryBsaCheckpointStateV2,
        session_binding: [u8; 32],
        request_id: [u8; 16],
        client_sequence: u64,
        request_value_digest: [u8; 32],
        outcome_value_digest: [u8; 32],
    ) -> Result<Self, BrokerNetworkInventoryCheckpointErrorV1> {
        let head = Self {
            state,
            session_binding,
            request_id,
            client_sequence,
            request_value_digest,
            outcome_value_digest,
        };
        head.validate()?;
        Ok(head)
    }

    fn decode(bytes: &[u8]) -> Result<Self, BrokerNetworkInventoryCheckpointErrorV1> {
        if bytes.len() != HEAD_BYTES
            || bytes.get(..8) != Some(HEAD_MAGIC.as_slice())
            || bytes.get(8..10) != Some(HEAD_VERSION.to_be_bytes().as_slice())
            || bytes.get(11..16) != Some([0_u8; 5].as_slice())
        {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
        }
        let head = Self {
            state: InventoryBsaCheckpointStateV2::decode(bytes[10])?,
            session_binding: take_array(bytes, 16)?,
            request_id: take_array(bytes, 48)?,
            client_sequence: u64::from_be_bytes(take_array(bytes, 64)?),
            request_value_digest: take_array(bytes, 72)?,
            outcome_value_digest: take_array(bytes, 104)?,
        };
        head.validate()?;
        if head.encode().as_slice() != bytes {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
        }
        Ok(head)
    }

    fn encode(self) -> [u8; HEAD_BYTES] {
        let mut bytes = [0_u8; HEAD_BYTES];
        bytes[..8].copy_from_slice(HEAD_MAGIC);
        bytes[8..10].copy_from_slice(&HEAD_VERSION.to_be_bytes());
        bytes[10] = self.state as u8;
        bytes[16..48].copy_from_slice(&self.session_binding);
        bytes[48..64].copy_from_slice(&self.request_id);
        bytes[64..72].copy_from_slice(&self.client_sequence.to_be_bytes());
        bytes[72..104].copy_from_slice(&self.request_value_digest);
        bytes[104..136].copy_from_slice(&self.outcome_value_digest);
        bytes
    }

    fn validate(self) -> Result<(), BrokerNetworkInventoryCheckpointErrorV1> {
        let outcome_shape_is_valid = match self.state {
            InventoryBsaCheckpointStateV2::Outstanding => self.outcome_value_digest == [0; 32],
            InventoryBsaCheckpointStateV2::Completed => self.outcome_value_digest != [0; 32],
        };
        if self.session_binding == [0; 32]
            || self.request_id == [0; 16]
            || self.client_sequence != 1
            || self.request_value_digest == [0; 32]
            || !outcome_shape_is_valid
        {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
        }
        Ok(())
    }

    fn same_identity(self, other: Self) -> bool {
        self.session_binding == other.session_binding
            && self.request_id == other.request_id
            && self.client_sequence == other.client_sequence
    }
}

/// Holds unique live authority to complete one newly reserved request.
#[doc(hidden)]
pub struct BrokerNetworkInventoryReservationV1 {
    head: InventoryBsaCheckpointHeadV2,
    request_value: Vec<u8>,
}

/// Classifies reservation without recreating live authority from durable state.
#[doc(hidden)]
pub enum BrokerNetworkInventoryReservationDispositionV1 {
    /// A new request is durable and carries its unique completion authority.
    Reserved(BrokerNetworkInventoryReservationV1),
    /// The exact request is already outstanding and requires recovery handling.
    Pending,
    /// The exact request is already complete and requires recovery handling.
    ExactCompleted,
}

/// Holds an owner-produced available catalog observation and its reservation.
#[doc(hidden)]
pub struct BrokerNetworkInventoryAvailableObservationV1 {
    reservation: BrokerNetworkInventoryReservationV1,
    canonical_catalog_body: Vec<u8>,
    catalog_projection_digest: [u8; 32],
}

impl BrokerNetworkInventoryAvailableObservationV1 {
    /// Encodes the observation with one authenticated broker process ID.
    ///
    /// Only `broker_instance_id` is replaced. The boot ID, journal sequence,
    /// catalog generation, and ordered resource set remain owner-observed.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerNetworkInventoryCheckpointErrorV1`] if the ID is zero
    /// or the retained owner observation cannot be reproduced.
    pub fn canonical_body_with_broker_instance_id(
        &self,
        broker_instance_id: [u8; 16],
    ) -> Result<Vec<u8>, BrokerNetworkInventoryCheckpointErrorV1> {
        if broker_instance_id == [0; 16] {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
        }
        let mut response =
            InventoryNetworkResourcesResponse::decode_from_slice(&self.canonical_catalog_body)
                .map_err(|_| BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
        response.broker_instance_id = broker_instance_id.to_vec();
        let bytes = response.encode_to_vec();
        if catalog_projection_digest(&bytes)? != self.catalog_projection_digest {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
        }
        Ok(bytes)
    }
}

/// Holds a causal catalog-unavailable observation and its reservation.
#[doc(hidden)]
pub struct BrokerNetworkInventoryUnavailableObservationV1 {
    reservation: BrokerNetworkInventoryReservationV1,
    cause: InventoryUnavailableCauseV1,
    currentness: CatalogCurrentnessV1,
}

/// Classifies the owner-produced outcomes of a reserved catalog observation.
#[doc(hidden)]
pub enum BrokerNetworkInventoryObservationDispositionV1 {
    /// The complete catalog was observed after durable reservation.
    Available(BrokerNetworkInventoryAvailableObservationV1),
    /// A namespace-pin or inventory-encoding failure prevented observation.
    Unavailable(BrokerNetworkInventoryUnavailableObservationV1),
}

/// Carries the exact causal authority accepted by outcome completion.
#[doc(hidden)]
pub enum BrokerNetworkInventoryOutcomeCauseV1 {
    /// An available observation authorizes Success or ResourceExhausted only.
    Available(BrokerNetworkInventoryAvailableObservationV1),
    /// A causal observation failure authorizes IntegrityFailure only.
    Unavailable(BrokerNetworkInventoryUnavailableObservationV1),
    /// First-admission expiration authorizes DeadlineExpired without observation.
    DeadlineExpired(BrokerNetworkInventoryReservationV1),
}

impl BrokerNetworkInventoryOutcomeCauseV1 {
    /// Consumes an unobserved reservation as a proposed expiration cause.
    ///
    /// Completion still requires the authenticated draft to prove that the
    /// request was expired on first admission and returned exact DeadlineExpired.
    #[must_use]
    pub fn deadline_expired(reservation: BrokerNetworkInventoryReservationV1) -> Self {
        Self::DeadlineExpired(reservation)
    }
}

impl From<BrokerNetworkInventoryObservationDispositionV1> for BrokerNetworkInventoryOutcomeCauseV1 {
    fn from(observation: BrokerNetworkInventoryObservationDispositionV1) -> Self {
        match observation {
            BrokerNetworkInventoryObservationDispositionV1::Available(value) => {
                Self::Available(value)
            }
            BrokerNetworkInventoryObservationDispositionV1::Unavailable(value) => {
                Self::Unavailable(value)
            }
        }
    }
}

/// Retains the live post-commit permit rechecked before each future send retry.
#[doc(hidden)]
pub struct BrokerNetworkInventoryOutcomeReceiptV1 {
    completed_head: InventoryBsaCheckpointHeadV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryUnavailableCauseV1 {
    NamespacePin,
    InvalidInventory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogCurrentnessV1 {
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    catalog_generation: u64,
    journal_sequence: u64,
}

impl CatalogCurrentnessV1 {
    fn capture(catalog: &NetworkNamespaceCatalogV1) -> Self {
        Self {
            kernel_boot_id: catalog.kernel_boot_id,
            broker_instance_id: catalog.broker_instance_id,
            catalog_generation: catalog.generation,
            journal_sequence: catalog.journal.snapshot_sequence(),
        }
    }
}

pub(super) fn is_key(key: &[u8]) -> bool {
    matches!(key, REQUEST_KEY | OUTCOME_KEY | HEAD_KEY)
}

pub(super) fn recover(
    journal: &Journal,
) -> Result<Option<InventoryBsaCheckpointHeadV2>, BrokerNetworkInventoryCheckpointErrorV1> {
    journal.ensure_healthy()?;
    let request = journal.get(RecordNamespace::NetworkResourceInventory, REQUEST_KEY);
    let outcome = journal.get(RecordNamespace::NetworkResourceInventory, OUTCOME_KEY);
    let head = journal.get(RecordNamespace::NetworkResourceInventory, HEAD_KEY);
    match (request, outcome, head) {
        (None, None, None) => Ok(None),
        (Some(request), None, Some(head)) => recover_outstanding(request, head).map(Some),
        (Some(request), Some(outcome), Some(head)) => {
            recover_completed(request, outcome, head).map(Some)
        }
        _ => Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt),
    }
}

fn recover_outstanding(
    request: &[u8],
    head: &[u8],
) -> Result<InventoryBsaCheckpointHeadV2, BrokerNetworkInventoryCheckpointErrorV1> {
    let decoded_head = InventoryBsaCheckpointHeadV2::decode(head)?;
    if decoded_head.state != InventoryBsaCheckpointStateV2::Outstanding {
        return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
    }
    let recovered = decode_recovered_network_inventory_request_checkpoint_value_v1(request)
        .map_err(|_| BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
    if decoded_head.session_binding != recovered.session_binding()
        || decoded_head.request_id != recovered.request_id()
        || decoded_head.client_sequence != recovered.client_sequence()
        || decoded_head.request_value_digest != record_digest(REQUEST_RECORD_DOMAIN, request)?
    {
        return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
    }
    Ok(decoded_head)
}

fn recover_completed(
    request: &[u8],
    outcome: &[u8],
    head: &[u8],
) -> Result<InventoryBsaCheckpointHeadV2, BrokerNetworkInventoryCheckpointErrorV1> {
    let decoded_head = InventoryBsaCheckpointHeadV2::decode(head)?;
    if decoded_head.state != InventoryBsaCheckpointStateV2::Completed {
        return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
    }
    let recovered = decode_recovered_network_inventory_checkpoint_values_v1(request, outcome)
        .map_err(|_| BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
    if decoded_head.session_binding != recovered.session_binding()
        || decoded_head.request_id != recovered.request_id()
        || decoded_head.client_sequence != recovered.client_sequence()
        || decoded_head.request_value_digest != record_digest(REQUEST_RECORD_DOMAIN, request)?
        || decoded_head.outcome_value_digest != record_digest(OUTCOME_RECORD_DOMAIN, outcome)?
    {
        return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
    }
    Ok(decoded_head)
}

impl NetworkNamespaceCatalogV1 {
    /// Durably reserves one live authenticated initial Inventory request.
    ///
    /// Exact outstanding and completed replays return classifications without
    /// a live receipt. They require future recovery authority and cannot enter
    /// catalog observation or completion through this API.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerNetworkInventoryCheckpointErrorV1`] for a request whose
    /// client sequence is not one, unhealthy or corrupt journal state, request
    /// equivocation, or publication failure.
    #[doc(hidden)]
    pub fn reserve_initial_authenticated_inventory_request(
        &mut self,
        request: NetworkInventoryRequestCheckpointDraftV1,
    ) -> Result<
        BrokerNetworkInventoryReservationDispositionV1,
        BrokerNetworkInventoryCheckpointErrorV1,
    > {
        self.journal.ensure_healthy()?;
        if request.client_sequence() != 1 {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::InvalidInitialRequest);
        }
        let next_head = InventoryBsaCheckpointHeadV2::outstanding(&request)?;

        if let Some(existing) = self.checkpoint_head {
            let recovered =
                recover(&self.journal)?.ok_or(BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
            if recovered != existing {
                return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
            }
            let retained_request = self
                .journal
                .get(RecordNamespace::NetworkResourceInventory, REQUEST_KEY)
                .ok_or(BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
            if existing.same_identity(next_head) {
                if retained_request != request.exact_value() {
                    return Err(BrokerNetworkInventoryCheckpointErrorV1::Equivocation);
                }
                return Ok(match existing.state {
                    InventoryBsaCheckpointStateV2::Outstanding => {
                        BrokerNetworkInventoryReservationDispositionV1::Pending
                    }
                    InventoryBsaCheckpointStateV2::Completed => {
                        BrokerNetworkInventoryReservationDispositionV1::ExactCompleted
                    }
                });
            }
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Equivocation);
        }

        let transaction = JournalTransaction::new(
            transaction_id(RESERVE_TRANSACTION_DOMAIN, next_head),
            vec![
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    REQUEST_KEY.to_vec(),
                    request.exact_value().to_vec(),
                ),
                JournalRecord::delete(
                    RecordNamespace::NetworkResourceInventory,
                    OUTCOME_KEY.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    HEAD_KEY.to_vec(),
                    next_head.encode().to_vec(),
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.checkpoint_head = Some(next_head);

        Ok(BrokerNetworkInventoryReservationDispositionV1::Reserved(
            BrokerNetworkInventoryReservationV1 {
                head: next_head,
                request_value: request.exact_value().to_vec(),
            },
        ))
    }

    /// Observes the protected catalog after consuming a live reservation.
    ///
    /// Namespace-pin and canonical inventory failures become purpose-limited
    /// unavailable tokens. Journal, durable-state, and other catalog failures
    /// remain errors and grant no IntegrityFailure authority.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerNetworkInventoryCheckpointErrorV1`] if the reservation
    /// is no longer the exact durable Outstanding graph or observation fails
    /// for a cause that must not authorize an IntegrityFailure response.
    #[doc(hidden)]
    pub fn observe_reserved_inventory(
        &self,
        reservation: BrokerNetworkInventoryReservationV1,
    ) -> Result<
        BrokerNetworkInventoryObservationDispositionV1,
        BrokerNetworkInventoryCheckpointErrorV1,
    > {
        self.validate_live_reservation(&reservation)?;
        let currentness = CatalogCurrentnessV1::capture(self);
        match self.inventory_resources() {
            Ok(canonical_catalog_body) => {
                let catalog_projection_digest = catalog_projection_digest(&canonical_catalog_body)?;
                Ok(BrokerNetworkInventoryObservationDispositionV1::Available(
                    BrokerNetworkInventoryAvailableObservationV1 {
                        reservation,
                        canonical_catalog_body,
                        catalog_projection_digest,
                    },
                ))
            }
            Err(NetworkNamespaceCatalogError::NamespacePin(_)) => {
                Ok(BrokerNetworkInventoryObservationDispositionV1::Unavailable(
                    BrokerNetworkInventoryUnavailableObservationV1 {
                        reservation,
                        cause: InventoryUnavailableCauseV1::NamespacePin,
                        currentness,
                    },
                ))
            }
            Err(NetworkNamespaceCatalogError::InvalidInventory) => {
                Ok(BrokerNetworkInventoryObservationDispositionV1::Unavailable(
                    BrokerNetworkInventoryUnavailableObservationV1 {
                        reservation,
                        cause: InventoryUnavailableCauseV1::InvalidInventory,
                        currentness,
                    },
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Completes one exact live reservation with its causal owner evidence.
    ///
    /// Success and ResourceExhausted require an available catalog token and an
    /// exact re-observation of every catalog field except the authenticated
    /// broker process ID. IntegrityFailure requires an unavailable token minted
    /// only for NamespacePin or InvalidInventory. DeadlineExpired never observes
    /// the catalog and must reproduce first-admission expiration.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerNetworkInventoryCheckpointErrorV1`] if the reservation,
    /// outcome, terminal cause, catalog re-observation, or durable commit fails.
    /// No outcome receipt is exposed on failure.
    #[doc(hidden)]
    pub fn commit_initial_authenticated_inventory_outcome(
        &mut self,
        cause: BrokerNetworkInventoryOutcomeCauseV1,
        draft: NetworkInventoryOutcomeCheckpointDraftV1,
    ) -> Result<BrokerNetworkInventoryOutcomeReceiptV1, BrokerNetworkInventoryCheckpointErrorV1>
    {
        let reservation = match cause {
            BrokerNetworkInventoryOutcomeCauseV1::Available(observation) => {
                self.validate_available_outcome(&observation, &draft)?;
                observation.reservation
            }
            BrokerNetworkInventoryOutcomeCauseV1::Unavailable(observation) => {
                self.validate_unavailable_outcome(&observation, &draft)?;
                observation.reservation
            }
            BrokerNetworkInventoryOutcomeCauseV1::DeadlineExpired(reservation) => {
                validate_deadline_outcome(&draft)?;
                reservation
            }
        };
        self.validate_live_reservation(&reservation)?;
        validate_outcome_identity(&reservation, &draft)?;

        let completed_head =
            InventoryBsaCheckpointHeadV2::completed(&reservation, draft.exact_outcome_value())?;
        let transaction = JournalTransaction::new(
            transaction_id(COMPLETE_TRANSACTION_DOMAIN, completed_head),
            vec![
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    OUTCOME_KEY.to_vec(),
                    draft.exact_outcome_value().to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    HEAD_KEY.to_vec(),
                    completed_head.encode().to_vec(),
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.checkpoint_head = Some(completed_head);

        Ok(BrokerNetworkInventoryOutcomeReceiptV1 { completed_head })
    }

    /// Rechecks a live committed outcome receipt before a future send attempt.
    ///
    /// The receipt remains borrowable so the future private channel can recheck
    /// the same permit before each retry. Recovery never recreates this receipt.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerNetworkInventoryCheckpointErrorV1`] if the journal is
    /// unhealthy or the exact Completed graph is no longer current.
    #[doc(hidden)]
    pub fn recheck_initial_authenticated_inventory_outcome(
        &self,
        receipt: &BrokerNetworkInventoryOutcomeReceiptV1,
    ) -> Result<(), BrokerNetworkInventoryCheckpointErrorV1> {
        self.journal.ensure_healthy()?;
        let recovered =
            recover(&self.journal)?.ok_or(BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
        if self.checkpoint_head != Some(receipt.completed_head)
            || recovered != receipt.completed_head
            || recovered.state != InventoryBsaCheckpointStateV2::Completed
        {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
        }
        Ok(())
    }

    fn validate_live_reservation(
        &self,
        reservation: &BrokerNetworkInventoryReservationV1,
    ) -> Result<(), BrokerNetworkInventoryCheckpointErrorV1> {
        self.journal.ensure_healthy()?;
        let recovered =
            recover(&self.journal)?.ok_or(BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
        let retained_request = self
            .journal
            .get(RecordNamespace::NetworkResourceInventory, REQUEST_KEY)
            .ok_or(BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
        if reservation.head.state != InventoryBsaCheckpointStateV2::Outstanding
            || self.checkpoint_head != Some(reservation.head)
            || recovered != reservation.head
            || retained_request != reservation.request_value
        {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::Corrupt);
        }
        Ok(())
    }

    fn validate_available_outcome(
        &self,
        observation: &BrokerNetworkInventoryAvailableObservationV1,
        draft: &NetworkInventoryOutcomeCheckpointDraftV1,
    ) -> Result<(), BrokerNetworkInventoryCheckpointErrorV1> {
        self.validate_live_reservation(&observation.reservation)?;
        if draft.expired_on_first_admission() {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::InvalidTerminalCause);
        }
        let current_bytes = self.inventory_resources()?;
        if catalog_projection_digest(&current_bytes)? != observation.catalog_projection_digest {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::InventoryChanged);
        }

        match (draft.result(), draft.terminal_error()) {
            (AuthenticatedNetworkInventoryResultV1::Success(candidate), None)
                if candidate.broker_instance_id() != &[0; 16]
                    && catalog_projection_digest(draft.exact_outcome_body())?
                        == observation.catalog_projection_digest =>
            {
                Ok(())
            }
            (
                AuthenticatedNetworkInventoryResultV1::Error(_),
                Some(NetworkInventoryCheckpointTerminalErrorV1::ResourceExhausted),
            ) if draft.success_exceeds_response_ceiling(&current_bytes)? => Ok(()),
            _ => Err(BrokerNetworkInventoryCheckpointErrorV1::InvalidTerminalCause),
        }
    }

    fn validate_unavailable_outcome(
        &self,
        observation: &BrokerNetworkInventoryUnavailableObservationV1,
        draft: &NetworkInventoryOutcomeCheckpointDraftV1,
    ) -> Result<(), BrokerNetworkInventoryCheckpointErrorV1> {
        self.validate_live_reservation(&observation.reservation)?;
        if CatalogCurrentnessV1::capture(self) != observation.currentness
            || draft.expired_on_first_admission()
            || !matches!(
                draft.terminal_error(),
                Some(NetworkInventoryCheckpointTerminalErrorV1::IntegrityFailure)
            )
        {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::InvalidTerminalCause);
        }

        let current_cause = match self.inventory_resources() {
            Err(NetworkNamespaceCatalogError::NamespacePin(_)) => {
                InventoryUnavailableCauseV1::NamespacePin
            }
            Err(NetworkNamespaceCatalogError::InvalidInventory) => {
                InventoryUnavailableCauseV1::InvalidInventory
            }
            Ok(_) => return Err(BrokerNetworkInventoryCheckpointErrorV1::InventoryChanged),
            Err(error) => return Err(error.into()),
        };
        if current_cause != observation.cause {
            return Err(BrokerNetworkInventoryCheckpointErrorV1::InventoryChanged);
        }
        Ok(())
    }
}

fn validate_deadline_outcome(
    draft: &NetworkInventoryOutcomeCheckpointDraftV1,
) -> Result<(), BrokerNetworkInventoryCheckpointErrorV1> {
    if draft.expired_on_first_admission()
        && matches!(
            draft.terminal_error(),
            Some(NetworkInventoryCheckpointTerminalErrorV1::DeadlineExpired)
        )
    {
        Ok(())
    } else {
        Err(BrokerNetworkInventoryCheckpointErrorV1::InvalidTerminalCause)
    }
}

fn validate_outcome_identity(
    reservation: &BrokerNetworkInventoryReservationV1,
    draft: &NetworkInventoryOutcomeCheckpointDraftV1,
) -> Result<(), BrokerNetworkInventoryCheckpointErrorV1> {
    if reservation.request_value != draft.exact_request_value()
        || reservation.head.session_binding != draft.session_binding()
        || reservation.head.request_id != draft.request_id()
        || reservation.head.client_sequence != draft.client_sequence()
        || reservation.head.request_value_digest
            != record_digest(REQUEST_RECORD_DOMAIN, draft.exact_request_value())?
    {
        return Err(BrokerNetworkInventoryCheckpointErrorV1::Equivocation);
    }
    Ok(())
}

fn catalog_projection_digest(
    bytes: &[u8],
) -> Result<[u8; 32], BrokerNetworkInventoryCheckpointErrorV1> {
    decode_network_resource_inventory_response(bytes, MAXIMUM_RESPONSE_BYTES)
        .map_err(|_| BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
    let mut response = InventoryNetworkResourcesResponse::decode_from_slice(bytes)
        .map_err(|_| BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
    response.broker_instance_id = vec![0; 16];
    record_digest(CATALOG_PROJECTION_DOMAIN, &response.encode_to_vec())
}

fn record_digest(
    domain: &[u8],
    value: &[u8],
) -> Result<[u8; 32], BrokerNetworkInventoryCheckpointErrorV1> {
    let length =
        u32::try_from(value.len()).map_err(|_| BrokerNetworkInventoryCheckpointErrorV1::Corrupt)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(digest.finalize().into())
}

fn transaction_id(domain: &[u8], head: InventoryBsaCheckpointHeadV2) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(head.encode());
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
) -> Result<[u8; N], BrokerNetworkInventoryCheckpointErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(BrokerNetworkInventoryCheckpointErrorV1::Corrupt)
}

const REQUEST_PUT_MAXIMUM_BYTES: usize = JOURNAL_RECORD_FRAMING_BYTES
    + REQUEST_KEY.len()
    + NETWORK_INVENTORY_REQUEST_RECORD_MAXIMUM_BYTES;
const OUTCOME_PUT_MAXIMUM_BYTES: usize = JOURNAL_RECORD_FRAMING_BYTES
    + OUTCOME_KEY.len()
    + NETWORK_INVENTORY_OUTCOME_RECORD_MAXIMUM_BYTES;
const OUTCOME_DELETE_BYTES: usize = JOURNAL_RECORD_FRAMING_BYTES + OUTCOME_KEY.len();
const HEAD_PUT_BYTES: usize = JOURNAL_RECORD_FRAMING_BYTES + HEAD_KEY.len() + HEAD_BYTES;
const RESERVE_TRANSACTION_MAXIMUM_BYTES: usize =
    REQUEST_PUT_MAXIMUM_BYTES + OUTCOME_DELETE_BYTES + HEAD_PUT_BYTES;
const COMPLETE_TRANSACTION_MAXIMUM_BYTES: usize = OUTCOME_PUT_MAXIMUM_BYTES + HEAD_PUT_BYTES;

const _: () = assert!(OUTCOME_PUT_MAXIMUM_BYTES == MAXIMUM_JOURNAL_RECORD_BYTES);
const _: () = assert!(RESERVE_TRANSACTION_MAXIMUM_BYTES <= MAXIMUM_JOURNAL_TRANSACTION_BYTES);
const _: () = assert!(COMPLETE_TRANSACTION_MAXIMUM_BYTES <= MAXIMUM_JOURNAL_TRANSACTION_BYTES);
