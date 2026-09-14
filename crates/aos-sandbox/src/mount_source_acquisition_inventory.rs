//! Records exact, complete Mount source-acquisition inventory observations.
//!
//! A one-shot Mount 2.0 query negotiates the closed source-acquisition feature,
//! accepts no authorization artifacts or ancillary descriptors, and validates
//! the complete lossless public projection before recording it. The controller
//! stores only one `latest` `AOSCSI01` record in its protected journal. Durable
//! bytes remain nonauthorizing and cannot reconstruct provider sessions, source
//! descriptors, or permission for a later effect.
//!
//! Fresh query IDs rely on the operating system CSPRNG's 122 random UUID bits.
//! The latest snapshot rejects reuse of its current ID; globally retaining every
//! historical query ID is deferred to a separately bounded audit-history format.

use std::os::fd::OwnedFd;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerMethod, Feature, InventoryMountSourceAcquisitionsRequest,
    InventoryMountSourceAcquisitionsResponse, MountSourceAcquisitionPhase,
    MountSourceAcquisitionRecord, RequestHeader,
};
use aos_sandbox_core::{FeatureRef, ObjectDigest, ProtocolId, ProtocolVersion};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::session::MOUNT_SOURCE_ACQUISITION_FEATURE_NAMESPACE;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    ValidatedMountSourceAcquisitionInventory, decode_mount_source_acquisition_inventory_request,
    decode_mount_source_acquisition_inventory_response, decode_response_envelope,
    decode_server_hello, encode_unauthed_request_envelope,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::mount_attempt::{MountAttemptError, mount_controller_state_digest};
use crate::mount_observation_state::MountJournalObservationIdentityV1;
use crate::mount_preparation::transport;
use crate::mount_preparation::{
    MountCatalogPreparationError, MountServiceIdentity, ServiceExecution, request_id,
};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

mod format;

const NAMESPACE: RecordNamespace = RecordNamespace::MountSourceAcquisitionInventory;
const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(2, 0);
const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS;
const RESPONSE_BYTES: u32 = 15 * 1024 * 1024;
const QUERY_WINDOW_NANOSECONDS: u64 = 10_000_000_000;
const MAXIMUM_QUERY_BYTES: usize = 4 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024 - 1024;
const KEY: &[u8] = b"latest";
const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.mount-source-acquisition-inventory.transaction.v1\0";

/// Reports whether a validated source-acquisition snapshot committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountSourceAcquisitionInventorySnapshotOutcomeV1 {
    /// The exact query and response became the latest durable observation.
    Recorded,
    /// Equivalent current evidence was already durable.
    Replay,
}

/// Reports malformed, stale, or unavailable source-acquisition observation state.
#[derive(Debug, thiserror::Error)]
pub enum MountSourceAcquisitionInventoryError {
    /// A durable record or decoded response violates the closed snapshot schema.
    #[error("Mount source-acquisition inventory state is corrupt")]
    CorruptState,
    /// A request identity, monotonic snapshot, or current-state check conflicts.
    #[error("Mount source-acquisition inventory conflicts with durable state")]
    Conflict,
    /// A bounded controller-state digest cannot represent the current journal.
    #[error("Mount source-acquisition inventory capacity is exhausted")]
    Capacity,
    /// The response's kernel-nominated subject mismatches configured Mount policy.
    #[error("Mount response subject does not match configured Mount policy")]
    MountIdentity,
    /// Mount rejected the inventory request.
    #[error(
        "Mount rejected the source-acquisition inventory request with {code:?} (retryable: {retryable})"
    )]
    BrokerRejected {
        /// Closed broker error code.
        code: aos_proto::aos::sandbox::local::v1::BrokerErrorCode,
        /// Whether an independently fresh query may succeed later.
        retryable: bool,
    },
    /// Negotiated envelopes or source rows failed protocol validation.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// Kernel record-subject validation or packet transfer failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Configured service-subject or cgroup correlation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// The bounded Mount exchange could not be prepared or completed in time.
    #[error(transparent)]
    Preparation(#[from] MountCatalogPreparationError),
    /// Protected journal provenance, health, or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Owns one connected channel for a complete source-acquisition inventory query.
///
/// The connection carries no operation descriptors. Its kernel-nominated
/// subjects constrain the configured Mount process but do not independently
/// authenticate the syscall writer.
pub struct MountSourceAcquisitionInventoryClient {
    socket: DescriptorSubjectSocket,
    expected_mount: MountServiceIdentity,
}

impl MountSourceAcquisitionInventoryClient {
    /// Connects to Mount's configured filesystem socket before querying.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or unavailable socket, inactive service cgroup, or
    /// unavailable kernel credential and pidfd reporting.
    pub fn connect(
        path: &Path,
        expected_mount: MountServiceIdentity,
    ) -> Result<Self, MountSourceAcquisitionInventoryError> {
        expected_mount.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::connect(path)?,
            expected_mount,
        })
    }

    /// Configures an exclusively owned connected Mount channel before querying.
    ///
    /// The supplied descriptor is the transport socket, not an operation
    /// descriptor; the protocol exchange accepts no ancillary descriptors.
    ///
    /// # Errors
    ///
    /// Rejects an inactive service cgroup, incompatible socket, or unavailable
    /// kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_mount: MountServiceIdentity,
    ) -> Result<Self, MountSourceAcquisitionInventoryError> {
        expected_mount.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_mount,
        })
    }

    fn query(mut self) -> Result<QuerySuccess, MountSourceAcquisitionInventoryError> {
        let now = transport::boottime()?;
        let request_deadline = now
            .checked_add(QUERY_WINDOW_NANOSECONDS)
            .ok_or(MountSourceAcquisitionInventoryError::CorruptState)?;
        let request_id = request_id()?;
        let request_body = InventoryMountSourceAcquisitionsRequest {
            header: Some(RequestHeader {
                protocol_major: CARRIER_VERSION.major().into(),
                protocol_minor: CARRIER_VERSION.minor().into(),
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: request_deadline,
                maximum_response_bytes: RESPONSE_BYTES,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
        .encode_to_vec();
        let request = decode_inventory_request_body(&request_body)?;
        let packet =
            encode_unauthed_request_envelope(ProtocolId::MountBroker, METHOD, &request_body)?;
        let required_feature = source_acquisition_feature()?;
        let hello = BrokerClientHello {
            protocol_major: CARRIER_VERSION.major().into(),
            protocol_minor: CARRIER_VERSION.minor().into(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: vec![Feature {
                namespace: MOUNT_SOURCE_ACQUISITION_FEATURE_NAMESPACE.to_owned(),
                major: 1,
                minor: 0,
                ..Default::default()
            }],
            maximum_response_bytes: RESPONSE_BYTES,
            required_methods: vec![METHOD.into()],
            ..Default::default()
        };
        let deadline = transport::exchange_deadline(request_deadline)?;

        transport::send(&mut self.socket, &hello.encode_to_vec(), deadline)?;
        let response = transport::receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            deadline,
        )?;
        let (hello_bytes, subject, hello_descriptors) = response.into_parts();
        if !hello_descriptors.is_empty() {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }
        let mount =
            ServiceExecution::new(&self.expected_mount, subject).map_err(map_service_error)?;
        let session = decode_server_hello(
            &hello_bytes,
            ProtocolId::MountBroker,
            Audience::AUDIENCE_NODE_CONTROLLER,
            CARRIER_VERSION,
            std::slice::from_ref(&required_feature),
            &[METHOD],
            RESPONSE_BYTES,
        )?;
        session.validate_header(&request)?;
        let decoded = session.decode_request(&packet, 0)?;
        if decoded.authorization().is_some()
            || !decoded.descriptors().is_empty()
            || decoded.body() != request_body.as_slice()
        {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }

        mount
            .recheck(&self.expected_mount)
            .map_err(map_service_error)?;
        transport::send(&mut self.socket, &packet, deadline)?;
        let response = transport::receive(&mut self.socket, RESPONSE_BYTES as usize, deadline)?;
        mount
            .validate_response(&self.expected_mount, response.subject())
            .map_err(map_service_error)?;
        let envelope = decode_response_envelope(
            response.payload(),
            request.request_id(),
            METHOD,
            &[],
            response.descriptors().len(),
            session.maximum_response_bytes(),
            request.maximum_response_bytes(),
        )?;
        if let Some(error) = envelope.error() {
            return Err(MountSourceAcquisitionInventoryError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            });
        }
        if !envelope.descriptors().is_empty() || !response.descriptors().is_empty() {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }
        let response_body = envelope.body().to_vec();
        decode_inventory_response_body(&response_body, &request)?;
        transport::check_deadline(deadline)?;

        Ok(QuerySuccess {
            request_body,
            response_body,
        })
    }
}

/// Retains the latest exact validated Mount source-acquisition inventory.
///
/// The public projection remains nonauthorizing and contains no source file
/// descriptor, provider session, or raw protected Mount row.
pub struct DurableMountSourceAcquisitionInventorySnapshotV1 {
    record: SnapshotRecord,
    inventory: ValidatedMountSourceAcquisitionInventory,
    outcome: MountSourceAcquisitionInventorySnapshotOutcomeV1,
}

impl DurableMountSourceAcquisitionInventorySnapshotV1 {
    /// Returns whether this exact snapshot was recorded or replayed.
    #[must_use]
    pub const fn outcome(&self) -> MountSourceAcquisitionInventorySnapshotOutcomeV1 {
        self.outcome
    }

    /// Returns the unique request identity used for this query.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete versioned `AOSCSI01` record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Returns SHA-256 of the exact canonical Mount response body.
    #[must_use]
    pub const fn response_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.response_digest)
    }

    /// Returns the protected controller state observed before the query.
    #[must_use]
    pub const fn controller_state_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.controller_state_digest)
    }

    /// Returns the exact controller and Mount journal boundary of this snapshot.
    #[must_use]
    pub const fn observation_identity(&self) -> MountJournalObservationIdentityV1 {
        MountJournalObservationIdentityV1::new(
            self.record.controller_state_digest,
            *self.inventory.kernel_boot_id(),
            *self.inventory.broker_instance_id(),
            self.inventory.journal_sequence(),
        )
    }

    /// Borrows the complete structurally validated lossless public inventory.
    #[must_use]
    pub const fn inventory(&self) -> &ValidatedMountSourceAcquisitionInventory {
        &self.inventory
    }

    pub(crate) fn recheck(
        &self,
        journal: &mut Journal,
    ) -> Result<(), MountSourceAcquisitionInventoryError> {
        let history = SnapshotHistory::load(journal)?;
        if history.record.as_ref().map(|value| &value.0) != Some(&self.record)
            || current_controller_state_digest(journal)? != self.record.controller_state_digest
        {
            return Err(MountSourceAcquisitionInventoryError::Conflict);
        }
        Ok(())
    }
}

struct QuerySuccess {
    request_body: Vec<u8>,
    response_body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotRecord {
    request_id: [u8; 16],
    controller_state_digest: [u8; 32],
    response_digest: [u8; 32],
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    digest: [u8; 32],
}

impl SnapshotRecord {
    fn from_query(
        controller_state_digest: [u8; 32],
        request_body: Vec<u8>,
        response_body: Vec<u8>,
    ) -> Result<
        (Self, ValidatedMountSourceAcquisitionInventory),
        MountSourceAcquisitionInventoryError,
    > {
        let request = decode_inventory_request_body(&request_body)?;
        let inventory = decode_inventory_response_body(&response_body, &request)?;
        let mut record = Self {
            request_id: *request.request_id(),
            controller_state_digest,
            response_digest: Sha256::digest(&response_body).into(),
            request_body,
            response_body,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate()?;
        Ok((record, inventory))
    }

    fn encoded_len(&self) -> usize {
        format::FIXED_RECORD_BYTES
            .saturating_add(self.request_body.len())
            .saturating_add(self.response_body.len())
    }

    fn validate(
        &self,
    ) -> Result<ValidatedMountSourceAcquisitionInventory, MountSourceAcquisitionInventoryError>
    {
        let exact_response_digest: [u8; 32] = Sha256::digest(&self.response_body).into();
        if self.request_id == [0; 16]
            || self.controller_state_digest == [0; 32]
            || self.response_digest == [0; 32]
            || self.request_body.is_empty()
            || self.request_body.len() > MAXIMUM_QUERY_BYTES
            || self.response_body.is_empty()
            || self.response_body.len() > RESPONSE_BYTES as usize
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
            || exact_response_digest != self.response_digest
        {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }

        let request = decode_inventory_request_body(&self.request_body)?;
        if request.request_id() != &self.request_id {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }
        decode_inventory_response_body(&self.response_body, &request)
            .map_err(|_| MountSourceAcquisitionInventoryError::CorruptState)
    }

    fn transaction(&self) -> Result<JournalTransaction, MountSourceAcquisitionInventoryError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| MountSourceAcquisitionInventoryError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(NAMESPACE, KEY.to_vec(), self.encode())],
        )?)
    }
}

struct SnapshotHistory {
    record: Option<(SnapshotRecord, ValidatedMountSourceAcquisitionInventory)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotDecision {
    Replay,
    Unchanged,
    Record,
}

impl SnapshotHistory {
    fn load(journal: &mut Journal) -> Result<Self, MountSourceAcquisitionInventoryError> {
        journal.ensure_protected_authority()?;
        let mut record = None;

        for (key, value) in journal.records(NAMESPACE) {
            if record.is_some() || key != KEY || value.len() > MAXIMUM_RECORD_BYTES {
                return Err(MountSourceAcquisitionInventoryError::CorruptState);
            }
            let decoded = SnapshotRecord::decode(value)?;
            let inventory = decoded.validate()?;
            record = Some((decoded, inventory));
        }

        Ok(Self { record })
    }

    fn outcome(
        &self,
        candidate: &SnapshotRecord,
        inventory: &ValidatedMountSourceAcquisitionInventory,
    ) -> Result<SnapshotDecision, MountSourceAcquisitionInventoryError> {
        let Some((current, current_inventory)) = &self.record else {
            return Ok(SnapshotDecision::Record);
        };
        if current == candidate {
            return Ok(SnapshotDecision::Replay);
        }
        if current.request_id == candidate.request_id
            || inventory.journal_sequence() < current_inventory.journal_sequence()
            || (inventory.broker_instance_id() == current_inventory.broker_instance_id()
                && inventory.kernel_boot_id() != current_inventory.kernel_boot_id())
        {
            return Err(MountSourceAcquisitionInventoryError::Conflict);
        }
        if inventory.journal_sequence() == current_inventory.journal_sequence() {
            let same_broker_incarnation = inventory.kernel_boot_id()
                == current_inventory.kernel_boot_id()
                && inventory.broker_instance_id() == current_inventory.broker_instance_id();
            let exact_response = candidate.response_digest == current.response_digest
                && candidate.response_body == current.response_body;
            let clean_broker_restart = inventory.broker_instance_id()
                != current_inventory.broker_instance_id()
                && same_acquisition_rows(inventory, current_inventory);

            if !(same_broker_incarnation && exact_response || clean_broker_restart) {
                return Err(MountSourceAcquisitionInventoryError::Conflict);
            }
        }
        validate_inventory_successor(current_inventory, inventory)?;
        if current.controller_state_digest == candidate.controller_state_digest
            && same_inventory(inventory, current_inventory)
        {
            return Ok(SnapshotDecision::Unchanged);
        }

        Ok(SnapshotDecision::Record)
    }
}

/// Queries Mount and atomically records the latest exact source-acquisition snapshot.
///
/// The journal must have been opened through a protected opener. Controller
/// state is digested before the query and checked again before commit.
///
/// # Errors
///
/// Returns [`MountSourceAcquisitionInventoryError`] for unsafe journal
/// provenance, stale controller state, invalid transport identity, malformed or
/// nonmonotonic inventory, bounded-capacity failure, or failed durability.
pub(crate) fn record_snapshot(
    journal: &mut Journal,
    client: MountSourceAcquisitionInventoryClient,
) -> Result<DurableMountSourceAcquisitionInventorySnapshotV1, MountSourceAcquisitionInventoryError>
{
    journal.ensure_protected_authority()?;
    let history = SnapshotHistory::load(journal)?;
    let observed_controller_state = current_controller_state_digest(journal)?;
    let success = client.query()?;
    if current_controller_state_digest(journal)? != observed_controller_state {
        return Err(MountSourceAcquisitionInventoryError::Conflict);
    }
    let (record, inventory) = SnapshotRecord::from_query(
        observed_controller_state,
        success.request_body,
        success.response_body,
    )?;

    persist_snapshot(journal, history, record, inventory)
}

fn persist_snapshot(
    journal: &mut Journal,
    history: SnapshotHistory,
    record: SnapshotRecord,
    inventory: ValidatedMountSourceAcquisitionInventory,
) -> Result<DurableMountSourceAcquisitionInventorySnapshotV1, MountSourceAcquisitionInventoryError>
{
    let (record, inventory, outcome) = match history.outcome(&record, &inventory)? {
        SnapshotDecision::Replay => (
            record,
            inventory,
            MountSourceAcquisitionInventorySnapshotOutcomeV1::Replay,
        ),
        SnapshotDecision::Unchanged => {
            let (current, current_inventory) = history
                .record
                .ok_or(MountSourceAcquisitionInventoryError::CorruptState)?;
            (
                current,
                current_inventory,
                MountSourceAcquisitionInventorySnapshotOutcomeV1::Replay,
            )
        }
        SnapshotDecision::Record => {
            journal.commit(&record.transaction()?)?;
            (
                record,
                inventory,
                MountSourceAcquisitionInventorySnapshotOutcomeV1::Recorded,
            )
        }
    };
    let committed = SnapshotHistory::load(journal)?;
    if committed.record.as_ref().map(|value| &value.0) != Some(&record) {
        return Err(MountSourceAcquisitionInventoryError::CorruptState);
    }

    Ok(DurableMountSourceAcquisitionInventorySnapshotV1 {
        record,
        inventory,
        outcome,
    })
}

fn validate_inventory_successor(
    current: &ValidatedMountSourceAcquisitionInventory,
    candidate: &ValidatedMountSourceAcquisitionInventory,
) -> Result<(), MountSourceAcquisitionInventoryError> {
    let mut candidate_rows = candidate.acquisitions().iter().peekable();

    for current_row in current.acquisitions() {
        while candidate_rows
            .peek()
            .is_some_and(|row| row.acquisition_id() < current_row.acquisition_id())
        {
            candidate_rows.next();
        }
        let candidate_row = candidate_rows
            .next_if(|row| row.acquisition_id() == current_row.acquisition_id())
            .ok_or(MountSourceAcquisitionInventoryError::Conflict)?;
        validate_row_successor(current_row, candidate_row)?;
    }

    Ok(())
}

fn validate_row_successor(
    current: &aos_sandbox_protocol::ValidatedMountSourceAcquisitionRecord,
    candidate: &aos_sandbox_protocol::ValidatedMountSourceAcquisitionRecord,
) -> Result<(), MountSourceAcquisitionInventoryError> {
    if candidate.revision() < current.revision()
        || (candidate.revision() == current.revision()
            && candidate.wire_record() != current.wire_record())
    {
        return Err(MountSourceAcquisitionInventoryError::Conflict);
    }
    if candidate.revision() == current.revision() {
        return Ok(());
    }

    let current_wire = current.wire_record();
    let candidate_wire = candidate.wire_record();
    if candidate.record_digest() == current.record_digest()
        || !phase_is_successor(current_wire, candidate_wire)
        || immutable_acquisition_changed(current_wire, candidate_wire)
        || current_wire.release.as_option().is_some()
            && current_wire.release != candidate_wire.release
        || current_wire.fault.as_option().is_some() && current_wire.fault != candidate_wire.fault
        || !generation_is_successor(
            current_wire.provider_route_generation,
            candidate_wire.provider_route_generation,
            &[current_wire.provider_route_digest.as_slice()],
            &[candidate_wire.provider_route_digest.as_slice()],
        )
        || !generation_is_successor(
            current_wire.provider_authority_generation,
            candidate_wire.provider_authority_generation,
            &[current_wire.provider_authority_digest.as_slice()],
            &[candidate_wire.provider_authority_digest.as_slice()],
        )
        || !generation_is_successor(
            current_wire.provider_key_generation,
            candidate_wire.provider_key_generation,
            &[
                current_wire.provider_key_id.as_slice(),
                current_wire.provider_public_key_digest.as_slice(),
            ],
            &[
                candidate_wire.provider_key_id.as_slice(),
                candidate_wire.provider_public_key_digest.as_slice(),
            ],
        )
        || !generation_is_successor(
            current_wire.provider_resource_generation,
            candidate_wire.provider_resource_generation,
            &[
                current_wire.provider_resource_id.as_slice(),
                current_wire.provider_resource_digest.as_slice(),
                current_wire.provider_proof_digest.as_slice(),
            ],
            &[
                candidate_wire.provider_resource_id.as_slice(),
                candidate_wire.provider_resource_digest.as_slice(),
                candidate_wire.provider_proof_digest.as_slice(),
            ],
        )
        || !generation_is_successor(
            current_wire.provider_catalog_generation,
            candidate_wire.provider_catalog_generation,
            &[current_wire.provider_catalog_digest.as_slice()],
            &[candidate_wire.provider_catalog_digest.as_slice()],
        )
        || !generation_is_successor(
            current_wire.provider_selection_generation,
            candidate_wire.provider_selection_generation,
            &[current_wire.provider_selection_digest.as_slice()],
            &[candidate_wire.provider_selection_digest.as_slice()],
        )
        || populated_source_evidence_changed(current_wire, candidate_wire)
    {
        return Err(MountSourceAcquisitionInventoryError::Conflict);
    }

    Ok(())
}

fn immutable_acquisition_changed(
    current: &MountSourceAcquisitionRecord,
    candidate: &MountSourceAcquisitionRecord,
) -> bool {
    current.acquisition_id != candidate.acquisition_id
        || current.acquire != candidate.acquire
        || current.assignment != candidate.assignment
        || current.prospective_mount_template_digest != candidate.prospective_mount_template_digest
        || current.source_binding_digest != candidate.source_binding_digest
        || current.provider_route_id != candidate.provider_route_id
        || current.provider_authority_id != candidate.provider_authority_id
        || current.resource_namespace_digest != candidate.resource_namespace_digest
}

/// Freezes the entire Acquire evidence projection after Mount has custody.
///
/// Pending retries may replace their query attempt and signing session. Once
/// resource evidence is populated, however, every field which identifies or
/// proves that source must remain byte-for-byte stable through consumption and
/// teardown.
fn populated_source_evidence_changed(
    current: &MountSourceAcquisitionRecord,
    candidate: &MountSourceAcquisitionRecord,
) -> bool {
    if current.source_realization_handle.is_empty() {
        return false;
    }

    current.provider_route_id != candidate.provider_route_id
        || current.provider_route_generation != candidate.provider_route_generation
        || current.provider_route_digest != candidate.provider_route_digest
        || current.provider_authority_id != candidate.provider_authority_id
        || current.provider_authority_generation != candidate.provider_authority_generation
        || current.provider_authority_digest != candidate.provider_authority_digest
        || current.provider_key_id != candidate.provider_key_id
        || current.provider_key_generation != candidate.provider_key_generation
        || current.provider_public_key_digest != candidate.provider_public_key_digest
        || current.resource_namespace_digest != candidate.resource_namespace_digest
        || current.provider_acquire_request_digest != candidate.provider_acquire_request_digest
        || current.provider_acquire_status_digest != candidate.provider_acquire_status_digest
        || current.provider_resource_id != candidate.provider_resource_id
        || current.provider_resource_generation != candidate.provider_resource_generation
        || current.provider_resource_digest != candidate.provider_resource_digest
        || current.provider_catalog_generation != candidate.provider_catalog_generation
        || current.provider_catalog_digest != candidate.provider_catalog_digest
        || current.provider_selection_generation != candidate.provider_selection_generation
        || current.provider_selection_digest != candidate.provider_selection_digest
        || current.proof_class != candidate.proof_class
        || current.provider_proof_digest != candidate.provider_proof_digest
        || current.lease_id != candidate.lease_id
        || current.signed_lease_digest != candidate.signed_lease_digest
        || current.lease_issued_seconds != candidate.lease_issued_seconds
        || current.lease_expires_seconds != candidate.lease_expires_seconds
        || current.source_realization_handle != candidate.source_realization_handle
        || current.source_physical_proof_digest != candidate.source_physical_proof_digest
        || current.source_kernel_boot_id != candidate.source_kernel_boot_id
        || current.source_device != candidate.source_device
        || current.source_inode != candidate.source_inode
        || current.source_unique_mount_id != candidate.source_unique_mount_id
        || current.descriptor_commitment != candidate.descriptor_commitment
}

fn generation_is_successor(
    current_generation: u64,
    candidate_generation: u64,
    current_identity: &[&[u8]],
    candidate_identity: &[&[u8]],
) -> bool {
    candidate_generation >= current_generation
        && (candidate_generation != current_generation || current_identity == candidate_identity)
}

fn phase_is_successor(
    current: &MountSourceAcquisitionRecord,
    candidate: &MountSourceAcquisitionRecord,
) -> bool {
    use MountSourceAcquisitionPhase as Phase;

    let current_phase = current.phase.as_known();
    let candidate_phase = candidate.phase.as_known();
    if current_phase == candidate_phase {
        return !matches!(
            current_phase,
            Some(
                Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
            )
        );
    }
    if current_phase == Some(Phase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED) {
        return !current.source_realization_handle.is_empty()
            && matches!(
                candidate_phase,
                Some(
                    Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                        | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                )
            );
    }

    matches!(
        (current_phase, candidate_phase),
        (
            Some(Phase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY),
            Some(
                Phase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
            )
        ) | (
            Some(Phase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED),
            Some(
                Phase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
            )
        ) | (
            Some(Phase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE),
            Some(
                Phase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
            )
        ) | (
            Some(Phase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED),
            Some(
                Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
                    | Phase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
            )
        ) | (
            Some(Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING),
            Some(Phase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED)
        )
    )
}

fn same_inventory(
    left: &ValidatedMountSourceAcquisitionInventory,
    right: &ValidatedMountSourceAcquisitionInventory,
) -> bool {
    left.kernel_boot_id() == right.kernel_boot_id()
        && left.broker_instance_id() == right.broker_instance_id()
        && left.journal_sequence() == right.journal_sequence()
        && same_acquisition_rows(left, right)
}

fn same_acquisition_rows(
    left: &ValidatedMountSourceAcquisitionInventory,
    right: &ValidatedMountSourceAcquisitionInventory,
) -> bool {
    left.acquisitions().len() == right.acquisitions().len()
        && left
            .acquisitions()
            .iter()
            .zip(right.acquisitions())
            .all(|(left, right)| left.wire_record() == right.wire_record())
}

fn current_controller_state_digest(
    journal: &mut Journal,
) -> Result<[u8; 32], MountSourceAcquisitionInventoryError> {
    match mount_controller_state_digest(journal) {
        Ok(digest) => Ok(digest),
        Err(MountAttemptError::Capacity) => Err(MountSourceAcquisitionInventoryError::Capacity),
        Err(MountAttemptError::Journal(error)) => {
            Err(MountSourceAcquisitionInventoryError::Journal(error))
        }
        Err(_) => Err(MountSourceAcquisitionInventoryError::CorruptState),
    }
}

pub(crate) fn validate_namespace(
    journal: &mut Journal,
) -> Result<(), MountSourceAcquisitionInventoryError> {
    SnapshotHistory::load(journal).map(|_| ())
}

fn decode_inventory_request_body(
    bytes: &[u8],
) -> Result<ValidatedHeader, MountSourceAcquisitionInventoryError> {
    if bytes.len() > MAXIMUM_QUERY_BYTES {
        return Err(MountSourceAcquisitionInventoryError::CorruptState);
    }
    let decoded = InventoryMountSourceAcquisitionsRequest::decode_from_slice(bytes)
        .map_err(|_| MountSourceAcquisitionInventoryError::CorruptState)?;
    if decoded.encode_to_vec() != bytes {
        return Err(MountSourceAcquisitionInventoryError::CorruptState);
    }
    let deadline = decoded
        .header
        .as_option()
        .map(|header| header.deadline_boottime_nanoseconds)
        .and_then(|value| value.checked_sub(1))
        .ok_or(MountSourceAcquisitionInventoryError::CorruptState)?;
    let peer = synthetic_credentials();
    let request = decode_mount_source_acquisition_inventory_request(
        bytes,
        peer,
        PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        deadline,
    )
    .map_err(|_| MountSourceAcquisitionInventoryError::CorruptState)?;
    if request.protocol_version() != CARRIER_VERSION
        || request.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || request.maximum_response_bytes() != RESPONSE_BYTES
    {
        return Err(MountSourceAcquisitionInventoryError::CorruptState);
    }
    Ok(request)
}

fn decode_inventory_response_body(
    bytes: &[u8],
    request: &ValidatedHeader,
) -> Result<ValidatedMountSourceAcquisitionInventory, MountSourceAcquisitionInventoryError> {
    let wire = InventoryMountSourceAcquisitionsResponse::decode_from_slice(bytes)
        .map_err(|_| MountSourceAcquisitionInventoryError::CorruptState)?;
    if wire.encode_to_vec() != bytes {
        return Err(MountSourceAcquisitionInventoryError::CorruptState);
    }
    decode_mount_source_acquisition_inventory_response(bytes, request).map_err(Into::into)
}

fn source_acquisition_feature() -> Result<FeatureRef, MountSourceAcquisitionInventoryError> {
    FeatureRef::new(MOUNT_SOURCE_ACQUISITION_FEATURE_NAMESPACE, 1, 0)
        .map_err(|_| MountSourceAcquisitionInventoryError::CorruptState)
}

fn synthetic_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    }
}

fn map_service_error(error: MountCatalogPreparationError) -> MountSourceAcquisitionInventoryError {
    match error {
        MountCatalogPreparationError::MountIdentity => {
            MountSourceAcquisitionInventoryError::MountIdentity
        }
        other => MountSourceAcquisitionInventoryError::Preparation(other),
    }
}
