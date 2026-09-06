//! Authenticates, records, and reconciles Mount destination-slot inventories.
//!
//! The controller stores only the latest complete protocol 1.3 snapshot. Each
//! record binds the exact query and response to the complete controller state
//! that existed before the query. Reconciliation compares one current logical
//! slot with that fresh evidence and returns a descriptive next action; it does
//! not grant broker authority or retain a namespace descriptor.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerMethod, DestinationSlotLifecycle,
    InventoryDestinationSlotsRequest, RequestHeader,
};
use aos_sandbox_core::{ObjectDigest, OperationId, ProtocolId, ProtocolVersion};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedDestinationSlotInventory,
    ValidatedDestinationSlotInventoryRecord, ValidatedHeader,
    decode_destination_slot_inventory_request, decode_destination_slot_inventory_response,
    decode_response_envelope, decode_server_hello, encode_unauthed_request_envelope,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::attachment_slot_state::{
    AttachmentSlotPresenceV1, DurableAttachmentSlotV1, creation_operation, recheck_current,
};
use crate::mount_attempt::{MountAttemptError, mount_controller_state_digest};
use crate::mount_preparation::transport;
use crate::mount_preparation::{
    MountCatalogPreparationError, MountServiceIdentity, ServiceExecution, request_id,
};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

mod format;

const NAMESPACE: RecordNamespace = RecordNamespace::DestinationSlotInventory;
const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 3);
const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS;
const RESPONSE_BYTES: u32 = 15 * 1024 * 1024;
const QUERY_WINDOW_NANOSECONDS: u64 = 10_000_000_000;
const MAXIMUM_QUERY_BYTES: usize = 4 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024 - 1024;
const KEY: &[u8] = b"latest";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.destination-slot-inventory.transaction.v1\0";

/// Reports whether an authenticated destination-slot snapshot committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationSlotInventorySnapshotOutcomeV1 {
    /// The authenticated query and complete response became durable.
    Recorded,
    /// The exact same query and response were already durable.
    Replay,
}

/// Describes the next safe destination-slot operation implied by fresh evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationSlotReconciliationActionV1 {
    /// No broker row exists for a logically available slot.
    Materialize {
        /// The logical creation operation to reuse for broker idempotency.
        operation_id: OperationId,
    },
    /// The broker durably admitted materialization but has not reached ready.
    ResumeMaterialize {
        /// The original logical creation operation.
        operation_id: OperationId,
    },
    /// The broker slot is physically ready for exact-bound Mount operations.
    Ready {
        /// The broker record digest identifying the ready resource.
        resource_digest: ObjectDigest,
    },
    /// A released logical slot still has incomplete broker materialization.
    ResumeMaterializeForReap {
        /// The original logical creation operation.
        operation_id: OperationId,
        /// The logical release operation that must reap the resulting resource.
        reap_operation_id: OperationId,
    },
    /// A released logical slot has a ready broker resource that must be reaped.
    Reap {
        /// The logical release operation to reuse for broker idempotency.
        operation_id: OperationId,
        /// The exact ready broker record digest fenced by the reap.
        expected_resource_digest: ObjectDigest,
    },
    /// The broker durably admitted the exact logical release operation.
    ResumeReap {
        /// The logical release operation.
        operation_id: OperationId,
    },
    /// Logical and physical slot state are both terminal.
    Released,
}

/// Owns one connected channel for a complete destination-slot inventory query.
pub struct DestinationSlotInventoryClient {
    socket: DescriptorSubjectSocket,
    expected_mount: MountServiceIdentity,
}

impl DestinationSlotInventoryClient {
    /// Configures an exclusively owned connected Mount channel before querying.
    ///
    /// The hello and response writers are authenticated through kernel record
    /// subjects against the configured service UID, GID, and retained cgroup.
    ///
    /// # Errors
    ///
    /// Rejects an inactive service cgroup, an incompatible socket, or
    /// unavailable kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_mount: MountServiceIdentity,
    ) -> Result<Self, MountAttemptError> {
        expected_mount.cgroup.validate_current()?;
        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_mount,
        })
    }

    fn query(mut self) -> Result<QuerySuccess, MountAttemptError> {
        let now = transport::boottime().map_err(MountAttemptError::Preparation)?;
        let request_deadline =
            now.checked_add(QUERY_WINDOW_NANOSECONDS)
                .ok_or(MountAttemptError::Preparation(
                    MountCatalogPreparationError::Deadline,
                ))?;
        let request_id = request_id().map_err(MountAttemptError::Preparation)?;
        let request_body = InventoryDestinationSlotsRequest {
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
        let hello = BrokerClientHello {
            protocol_major: CARRIER_VERSION.major().into(),
            protocol_minor: CARRIER_VERSION.minor().into(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            maximum_response_bytes: RESPONSE_BYTES,
            required_methods: vec![METHOD.into()],
            ..Default::default()
        };
        let deadline = transport::exchange_deadline(request_deadline)
            .map_err(MountAttemptError::Preparation)?;

        transport::send(&mut self.socket, &hello.encode_to_vec(), deadline)
            .map_err(MountAttemptError::Preparation)?;
        let response = transport::receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            deadline,
        )
        .map_err(MountAttemptError::Preparation)?;
        let (hello_bytes, subject, _) = response.into_parts();
        let mount =
            ServiceExecution::new(&self.expected_mount, subject).map_err(map_service_error)?;
        let session = decode_server_hello(
            &hello_bytes,
            ProtocolId::MountBroker,
            Audience::AUDIENCE_NODE_CONTROLLER,
            CARRIER_VERSION,
            &[],
            &[METHOD],
            RESPONSE_BYTES,
        )?;
        session.validate_header(&request)?;
        let decoded = session.decode_request(&packet, 0)?;
        if decoded.authorization().is_some() || decoded.body() != request_body.as_slice() {
            return Err(aos_sandbox_protocol::ProtocolValidationError::InvalidField(
                "destination-slot inventory request packet",
            )
            .into());
        }

        mount
            .recheck(&self.expected_mount)
            .map_err(map_service_error)?;
        transport::send(&mut self.socket, &packet, deadline)
            .map_err(MountAttemptError::Preparation)?;
        let response = transport::receive(&mut self.socket, RESPONSE_BYTES as usize, deadline)
            .map_err(MountAttemptError::Preparation)?;
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
            return Err(MountAttemptError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            });
        }
        let response_body = envelope.body().to_vec();
        let inventory = decode_destination_slot_inventory_response(
            &response_body,
            request.maximum_response_bytes(),
        )?;
        transport::check_deadline(deadline).map_err(MountAttemptError::Preparation)?;

        Ok(QuerySuccess {
            request_body,
            response_body,
            inventory,
        })
    }
}

/// Retains the latest exact authenticated destination-slot inventory.
///
/// The response is complete broker state but remains non-authorizing. A caller
/// must reconcile it with current logical state before preparing any effect.
pub struct DurableDestinationSlotInventorySnapshotV1 {
    record: SnapshotRecord,
    inventory: ValidatedDestinationSlotInventory,
    outcome: DestinationSlotInventorySnapshotOutcomeV1,
}

impl DurableDestinationSlotInventorySnapshotV1 {
    /// Returns whether the exact snapshot was newly recorded or replayed.
    #[must_use]
    pub const fn outcome(&self) -> DestinationSlotInventorySnapshotOutcomeV1 {
        self.outcome
    }

    /// Returns the unique request identity used for this inventory query.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete versioned snapshot record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Returns the digest of controller state observed before the query.
    #[must_use]
    pub const fn controller_state_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.controller_state_digest)
    }

    /// Borrows the complete validated broker inventory.
    #[must_use]
    pub const fn inventory(&self) -> &ValidatedDestinationSlotInventory {
        &self.inventory
    }

    fn recheck(&self, journal: &mut Journal) -> Result<(), MountAttemptError> {
        let history = SnapshotHistory::load(journal)?;
        if history.record.as_ref().map(|value| &value.0) != Some(&self.record)
            || mount_controller_state_digest(journal)? != self.record.controller_state_digest
        {
            return Err(MountAttemptError::Conflict);
        }
        Ok(())
    }
}

/// Retains one current logical slot beside its fresh broker classification.
///
/// The value carries no live namespace descriptor and does not authorize the
/// returned action. Dispatch preparation must recheck its durable inputs and
/// acquire current signed assignment authority independently.
pub struct CurrentDestinationSlotReconciliationV1 {
    slot: DurableAttachmentSlotV1,
    snapshot: DurableDestinationSlotInventorySnapshotV1,
    action: DestinationSlotReconciliationActionV1,
}

impl CurrentDestinationSlotReconciliationV1 {
    /// Borrows the exact current logical slot used for comparison.
    #[must_use]
    pub const fn slot(&self) -> &DurableAttachmentSlotV1 {
        &self.slot
    }

    /// Borrows the exact fresh broker snapshot used for comparison.
    #[must_use]
    pub const fn snapshot(&self) -> &DurableDestinationSlotInventorySnapshotV1 {
        &self.snapshot
    }

    /// Returns the descriptive next action.
    #[must_use]
    pub const fn action(&self) -> DestinationSlotReconciliationActionV1 {
        self.action
    }

    pub(crate) fn recheck(&self, journal: &mut Journal) -> Result<(), MountAttemptError> {
        recheck_current(journal, &self.slot).map_err(|_| MountAttemptError::Conflict)?;
        self.snapshot.recheck(journal)?;

        let creation =
            creation_operation(journal, &self.slot).map_err(|_| MountAttemptError::CorruptState)?;
        let resource = matching_resource(&self.slot, &self.snapshot.inventory)?;
        if let Some(resource) = resource {
            validate_binding(&self.slot, resource)?;
            if resource.materialization().operation_id() != creation.as_bytes() {
                return Err(MountAttemptError::Conflict);
            }
        }
        if classify(&self.slot, creation, resource)? != self.action {
            return Err(MountAttemptError::Conflict);
        }
        Ok(())
    }
}

struct QuerySuccess {
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    inventory: ValidatedDestinationSlotInventory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotRecord {
    request_id: [u8; 16],
    controller_state_digest: [u8; 32],
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    digest: [u8; 32],
}

impl SnapshotRecord {
    fn from_query(
        controller_state_digest: [u8; 32],
        request_body: Vec<u8>,
        response_body: Vec<u8>,
    ) -> Result<(Self, ValidatedDestinationSlotInventory), MountAttemptError> {
        let request = decode_inventory_request_body(&request_body)?;
        let inventory = decode_destination_slot_inventory_response(
            &response_body,
            request.maximum_response_bytes(),
        )?;
        let mut record = Self {
            request_id: *request.request_id(),
            controller_state_digest,
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

    fn validate(&self) -> Result<ValidatedDestinationSlotInventory, MountAttemptError> {
        if self.request_id == [0; 16]
            || self.controller_state_digest == [0; 32]
            || self.request_body.is_empty()
            || self.request_body.len() > MAXIMUM_QUERY_BYTES
            || self.response_body.is_empty()
            || self.response_body.len() > RESPONSE_BYTES as usize
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
        {
            return Err(MountAttemptError::CorruptState);
        }

        let request = decode_inventory_request_body(&self.request_body)?;
        if request.request_id() != &self.request_id {
            return Err(MountAttemptError::CorruptState);
        }
        decode_destination_slot_inventory_response(
            &self.response_body,
            request.maximum_response_bytes(),
        )
        .map_err(|_| MountAttemptError::CorruptState)
    }

    fn transaction(&self) -> Result<JournalTransaction, MountAttemptError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| MountAttemptError::CorruptState)?;
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
    record: Option<(SnapshotRecord, ValidatedDestinationSlotInventory)>,
}

impl SnapshotHistory {
    fn load(journal: &mut Journal) -> Result<Self, MountAttemptError> {
        journal.ensure_healthy()?;
        let mut record = None;

        for (key, value) in journal.records(NAMESPACE) {
            if record.is_some() || key != KEY || value.len() > MAXIMUM_RECORD_BYTES {
                return Err(MountAttemptError::CorruptState);
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
        inventory: &ValidatedDestinationSlotInventory,
    ) -> Result<Option<DestinationSlotInventorySnapshotOutcomeV1>, MountAttemptError> {
        let Some((current, current_inventory)) = &self.record else {
            return Ok(None);
        };
        if current == candidate {
            return Ok(Some(DestinationSlotInventorySnapshotOutcomeV1::Replay));
        }
        if current.request_id == candidate.request_id
            || inventory.journal_sequence() < current_inventory.journal_sequence()
            || (inventory.journal_sequence() == current_inventory.journal_sequence()
                && inventory.slots() != current_inventory.slots())
            || (inventory.broker_instance_id() == current_inventory.broker_instance_id()
                && inventory.kernel_boot_id() != current_inventory.kernel_boot_id())
        {
            return Err(MountAttemptError::Conflict);
        }
        Ok(None)
    }
}

pub(crate) fn record_snapshot(
    journal: &mut Journal,
    client: DestinationSlotInventoryClient,
) -> Result<DurableDestinationSlotInventorySnapshotV1, MountAttemptError> {
    let history = SnapshotHistory::load(journal)?;
    let observed_controller_state = mount_controller_state_digest(journal)?;
    let success = client.query()?;
    if mount_controller_state_digest(journal)? != observed_controller_state {
        return Err(MountAttemptError::Conflict);
    }
    let (record, inventory) = SnapshotRecord::from_query(
        observed_controller_state,
        success.request_body,
        success.response_body,
    )?;
    if inventory != success.inventory {
        return Err(MountAttemptError::CorruptState);
    }

    let outcome = match history.outcome(&record, &inventory)? {
        Some(outcome) => outcome,
        None => {
            journal.commit(&record.transaction()?)?;
            DestinationSlotInventorySnapshotOutcomeV1::Recorded
        }
    };
    let committed = SnapshotHistory::load(journal)?;
    if committed.record.as_ref().map(|value| &value.0) != Some(&record) {
        return Err(MountAttemptError::CorruptState);
    }

    Ok(DurableDestinationSlotInventorySnapshotV1 {
        record,
        inventory,
        outcome,
    })
}

pub(crate) fn reconcile_current(
    journal: &mut Journal,
    slot: DurableAttachmentSlotV1,
    snapshot: DurableDestinationSlotInventorySnapshotV1,
) -> Result<CurrentDestinationSlotReconciliationV1, MountAttemptError> {
    recheck_current(journal, &slot).map_err(|_| MountAttemptError::Conflict)?;
    snapshot.recheck(journal)?;

    let creation_operation =
        creation_operation(journal, &slot).map_err(|_| MountAttemptError::CorruptState)?;
    let resource = matching_resource(&slot, &snapshot.inventory)?;
    if let Some(resource) = resource {
        validate_binding(&slot, resource)?;
        if resource.materialization().operation_id() != creation_operation.as_bytes() {
            return Err(MountAttemptError::Conflict);
        }
    }

    let action = classify(&slot, creation_operation, resource)?;

    recheck_current(journal, &slot).map_err(|_| MountAttemptError::Conflict)?;
    snapshot.recheck(journal)?;
    Ok(CurrentDestinationSlotReconciliationV1 {
        slot,
        snapshot,
        action,
    })
}

pub(crate) fn matching_resource<'a>(
    slot: &DurableAttachmentSlotV1,
    inventory: &'a ValidatedDestinationSlotInventory,
) -> Result<Option<&'a ValidatedDestinationSlotInventoryRecord>, MountAttemptError> {
    let mut matching = inventory
        .slots()
        .iter()
        .filter(|resource| resource.destination_slot_id() == slot.slot_id().as_bytes());
    let resource = matching.next();
    if matching.next().is_some() {
        return Err(MountAttemptError::Conflict);
    }
    Ok(resource)
}

fn validate_binding(
    slot: &DurableAttachmentSlotV1,
    resource: &ValidatedDestinationSlotInventoryRecord,
) -> Result<(), MountAttemptError> {
    if resource.fence().sandbox_id() != slot.sandbox().as_bytes()
        || resource.fence().incarnation_id() != slot.incarnation().as_bytes()
        || resource.namespace_generation() != slot.namespace_generation()
        || resource.sandbox_spec() != slot.sandbox_spec()
    {
        return Err(MountAttemptError::Conflict);
    }
    Ok(())
}

fn classify(
    slot: &DurableAttachmentSlotV1,
    creation_operation: OperationId,
    resource: Option<&ValidatedDestinationSlotInventoryRecord>,
) -> Result<DestinationSlotReconciliationActionV1, MountAttemptError> {
    match (slot.presence(), resource.map(|value| value.lifecycle())) {
        (AttachmentSlotPresenceV1::Available, None) => {
            Ok(DestinationSlotReconciliationActionV1::Materialize {
                operation_id: creation_operation,
            })
        }
        (
            AttachmentSlotPresenceV1::Available,
            Some(DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING),
        ) => Ok(DestinationSlotReconciliationActionV1::ResumeMaterialize {
            operation_id: creation_operation,
        }),
        (
            AttachmentSlotPresenceV1::Available,
            Some(DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY),
        ) => Ok(DestinationSlotReconciliationActionV1::Ready {
            resource_digest: ObjectDigest::from_bytes(
                *resource
                    .ok_or(MountAttemptError::CorruptState)?
                    .resource_digest(),
            ),
        }),
        (AttachmentSlotPresenceV1::Released, None) => {
            Ok(DestinationSlotReconciliationActionV1::Released)
        }
        (
            AttachmentSlotPresenceV1::Released,
            Some(DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING),
        ) => Ok(
            DestinationSlotReconciliationActionV1::ResumeMaterializeForReap {
                operation_id: creation_operation,
                reap_operation_id: slot.operation_id(),
            },
        ),
        (
            AttachmentSlotPresenceV1::Released,
            Some(DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY),
        ) => Ok(DestinationSlotReconciliationActionV1::Reap {
            operation_id: slot.operation_id(),
            expected_resource_digest: ObjectDigest::from_bytes(
                *resource
                    .ok_or(MountAttemptError::CorruptState)?
                    .resource_digest(),
            ),
        }),
        (
            AttachmentSlotPresenceV1::Released,
            Some(DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING),
        ) => {
            validate_reap_operation(slot, resource.ok_or(MountAttemptError::CorruptState)?)?;
            Ok(DestinationSlotReconciliationActionV1::ResumeReap {
                operation_id: slot.operation_id(),
            })
        }
        (
            AttachmentSlotPresenceV1::Released,
            Some(DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED),
        ) => {
            validate_reap_operation(slot, resource.ok_or(MountAttemptError::CorruptState)?)?;
            Ok(DestinationSlotReconciliationActionV1::Released)
        }
        _ => Err(MountAttemptError::Conflict),
    }
}

fn validate_reap_operation(
    slot: &DurableAttachmentSlotV1,
    resource: &ValidatedDestinationSlotInventoryRecord,
) -> Result<(), MountAttemptError> {
    if resource
        .reap()
        .is_none_or(|reap| reap.operation().operation_id() != slot.operation_id().as_bytes())
    {
        return Err(MountAttemptError::Conflict);
    }
    Ok(())
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), MountAttemptError> {
    SnapshotHistory::load(journal).map(|_| ())
}

fn decode_inventory_request_body(bytes: &[u8]) -> Result<ValidatedHeader, MountAttemptError> {
    if bytes.len() > MAXIMUM_QUERY_BYTES {
        return Err(MountAttemptError::CorruptState);
    }
    let decoded = InventoryDestinationSlotsRequest::decode_from_slice(bytes)
        .map_err(|_| MountAttemptError::CorruptState)?;
    let deadline = decoded
        .header
        .as_option()
        .map(|header| header.deadline_boottime_nanoseconds)
        .and_then(|value| value.checked_sub(1))
        .ok_or(MountAttemptError::CorruptState)?;
    let peer = synthetic_credentials();
    let request = decode_destination_slot_inventory_request(
        bytes,
        peer,
        PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        deadline,
    )
    .map_err(|_| MountAttemptError::CorruptState)?;
    if request.protocol_version() != CARRIER_VERSION
        || request.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || request.maximum_response_bytes() != RESPONSE_BYTES
    {
        return Err(MountAttemptError::CorruptState);
    }
    Ok(request)
}

fn synthetic_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    }
}

fn map_service_error(error: MountCatalogPreparationError) -> MountAttemptError {
    match error {
        MountCatalogPreparationError::MountIdentity => MountAttemptError::MountIdentity,
        other => MountAttemptError::Preparation(other),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Descriptor, DestinationSlotInventoryRecord,
        DestinationSlotReapCorrelation, InventoryDestinationSlotsResponse, MountAssignmentBinding,
        MountOperationCorrelation,
    };
    use aos_sandbox_core::{AttachmentSlotId, IncarnationId, Revision, SandboxId};

    use super::*;
    use crate::attachment_slot_state::{AttachmentSlotMutationV1, commit_for_test};
    use crate::{
        EffectFailure, EffectObservation, EffectPlan, EffectReceipt, JournalLimits, Reconciler,
        ReconcilerError, SingleNodeEffectExecutor,
    };

    const SLOT_ID: [u8; 16] = [1; 16];
    const SANDBOX_ID: [u8; 16] = [2; 16];
    const INCARNATION_ID: [u8; 16] = [3; 16];
    const NAMESPACE_GENERATION: u64 = 4;
    const CREATE_OPERATION: [u8; 16] = [11; 16];
    const RELEASE_OPERATION: [u8; 16] = [12; 16];
    const RESOURCE_DIGEST: [u8; 32] = [70; 32];

    struct NoEffects;

    impl SingleNodeEffectExecutor for NoEffects {
        fn observe(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            panic!("destination-slot inventory tests must not observe effects")
        }

        fn apply(
            &mut self,
            _: OperationId,
            _: u32,
            _: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            panic!("destination-slot inventory tests must not apply effects")
        }
    }

    fn test_journal() -> (tempfile::TempDir, Journal) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            JournalLimits::default(),
            std::fs::metadata(directory.path()).unwrap().uid(),
        )
        .unwrap()
        .0;
        (directory, journal)
    }

    fn query(request_byte: u8) -> Vec<u8> {
        InventoryDestinationSlotsRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 3,
                request_id: vec![request_byte; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: RESPONSE_BYTES,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn response(
        sequence: u64,
        boot_byte: u8,
        instance_byte: u8,
        slots: Vec<DestinationSlotInventoryRecord>,
    ) -> Vec<u8> {
        InventoryDestinationSlotsResponse {
            kernel_boot_id: vec![boot_byte; 16],
            journal_sequence: sequence,
            slots,
            broker_instance_id: vec![instance_byte; 16],
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn proto_descriptor(value: &aos_sandbox_core::ObjectDescriptor) -> Descriptor {
        Descriptor {
            media_type: value.media_type().as_str().to_owned(),
            sha256: value.digest().as_bytes().to_vec(),
            encoded_size: value.encoded_size(),
            ..Default::default()
        }
    }

    fn create_slot(journal: &mut Journal) -> DurableAttachmentSlotV1 {
        let mutation = AttachmentSlotMutationV1::new(
            AttachmentSlotPresenceV1::Available,
            AttachmentSlotId::from_bytes(SLOT_ID),
            Revision::new(1),
            OperationId::from_bytes(CREATE_OPERATION),
            ObjectDigest::from_bytes([21; 32]),
            None,
        )
        .unwrap();
        commit_for_test(
            journal,
            &mutation,
            SandboxId::from_bytes(SANDBOX_ID),
            IncarnationId::from_bytes(INCARNATION_ID),
            NAMESPACE_GENERATION,
        )
        .unwrap()
        .0
    }

    fn release_slot(
        journal: &mut Journal,
        created: &DurableAttachmentSlotV1,
    ) -> DurableAttachmentSlotV1 {
        let mutation = AttachmentSlotMutationV1::new(
            AttachmentSlotPresenceV1::Released,
            AttachmentSlotId::from_bytes(SLOT_ID),
            Revision::new(2),
            OperationId::from_bytes(RELEASE_OPERATION),
            ObjectDigest::from_bytes([22; 32]),
            Some(created.record_digest()),
        )
        .unwrap();
        commit_for_test(
            journal,
            &mutation,
            SandboxId::from_bytes(SANDBOX_ID),
            IncarnationId::from_bytes(INCARNATION_ID),
            NAMESPACE_GENERATION,
        )
        .unwrap()
        .0
    }

    fn resource(
        slot: &DurableAttachmentSlotV1,
        lifecycle: DestinationSlotLifecycle,
    ) -> DestinationSlotInventoryRecord {
        let physical =
            lifecycle != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING;
        let reaping = matches!(
            lifecycle,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING
                | DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED
        );
        DestinationSlotInventoryRecord {
            binding: Some(MountAssignmentBinding {
                fence: Some(AssignmentFence {
                    sandbox_id: SANDBOX_ID.to_vec(),
                    incarnation_id: INCARNATION_ID.to_vec(),
                    assignment_epoch: 5,
                    desired_generation: 6,
                    assignment_digest: vec![7; 32],
                    ..Default::default()
                })
                .into(),
                namespace_generation: NAMESPACE_GENERATION,
                ..Default::default()
            })
            .into(),
            destination_slot_id: SLOT_ID.to_vec(),
            sandbox_spec: Some(proto_descriptor(slot.sandbox_spec())).into(),
            lifecycle: lifecycle.into(),
            resource_kernel_boot_id: vec![8; 16],
            materialization: Some(MountOperationCorrelation {
                operation_id: CREATE_OPERATION.to_vec(),
                request_digest: vec![30; 32],
                ..Default::default()
            })
            .into(),
            reap: reaping
                .then(|| DestinationSlotReapCorrelation {
                    operation: Some(MountOperationCorrelation {
                        operation_id: RELEASE_OPERATION.to_vec(),
                        request_digest: vec![31; 32],
                        ..Default::default()
                    })
                    .into(),
                    expected_resource_digest: vec![32; 32],
                    ..Default::default()
                })
                .into(),
            slot_device: physical.then_some(40),
            slot_inode: physical.then_some(41),
            anchor_unique_mount_id: physical.then_some(42),
            resource_digest: RESOURCE_DIGEST.to_vec(),
            ..Default::default()
        }
    }

    fn decoded_resource(
        slot: &DurableAttachmentSlotV1,
        lifecycle: DestinationSlotLifecycle,
    ) -> ValidatedDestinationSlotInventoryRecord {
        let inventory = decode_destination_slot_inventory_response(
            &response(1, 8, 9, vec![resource(slot, lifecycle)]),
            RESPONSE_BYTES,
        )
        .unwrap();
        inventory.slots()[0].clone()
    }

    fn snapshot(
        request_byte: u8,
        sequence: u64,
        boot_byte: u8,
        instance_byte: u8,
        slots: Vec<DestinationSlotInventoryRecord>,
    ) -> (SnapshotRecord, ValidatedDestinationSlotInventory) {
        SnapshotRecord::from_query(
            [20; 32],
            query(request_byte),
            response(sequence, boot_byte, instance_byte, slots),
        )
        .unwrap()
    }

    fn durable_snapshot(
        journal: &mut Journal,
        slots: Vec<DestinationSlotInventoryRecord>,
    ) -> DurableDestinationSlotInventorySnapshotV1 {
        let controller_state = mount_controller_state_digest(journal).unwrap();
        let (record, inventory) =
            SnapshotRecord::from_query(controller_state, query(15), response(1, 8, 9, slots))
                .unwrap();
        journal.commit(&record.transaction().unwrap()).unwrap();
        DurableDestinationSlotInventorySnapshotV1 {
            record,
            inventory,
            outcome: DestinationSlotInventorySnapshotOutcomeV1::Recorded,
        }
    }

    #[test]
    fn snapshot_codec_is_closed_and_self_authenticating() {
        let (record, _) = snapshot(1, 2, 3, 4, Vec::new());
        let encoded = record.encode();
        assert_eq!(SnapshotRecord::decode(&encoded).unwrap(), record);

        for offset in [0, 8, 9, 10, 20, 64, encoded.len() - 1] {
            let mut corrupt = encoded.clone();
            corrupt[offset] ^= 1;
            assert!(SnapshotRecord::decode(&corrupt).is_err());
        }
        assert!(SnapshotRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(SnapshotRecord::decode(&trailing).is_err());
    }

    #[test]
    fn snapshot_history_rejects_rollback_and_equivocation() {
        let (current, current_inventory) = snapshot(1, 5, 3, 4, Vec::new());
        let history = SnapshotHistory {
            record: Some((current.clone(), current_inventory)),
        };
        assert_eq!(
            history
                .outcome(&current, &current.validate().unwrap())
                .unwrap(),
            Some(DestinationSlotInventorySnapshotOutcomeV1::Replay)
        );

        let (rollback, rollback_inventory) = snapshot(2, 4, 3, 4, Vec::new());
        assert!(history.outcome(&rollback, &rollback_inventory).is_err());

        let (same_request, same_request_inventory) = snapshot(1, 6, 3, 4, Vec::new());
        assert!(
            history
                .outcome(&same_request, &same_request_inventory)
                .is_err()
        );

        let (changed_boot, changed_boot_inventory) = snapshot(2, 6, 5, 4, Vec::new());
        assert!(
            history
                .outcome(&changed_boot, &changed_boot_inventory)
                .is_err()
        );

        let (_directory, mut journal) = test_journal();
        let slot = create_slot(&mut journal);
        let changed_row = resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        let (equivocation, equivocation_inventory) = snapshot(2, 5, 3, 4, vec![changed_row]);
        assert!(
            history
                .outcome(&equivocation, &equivocation_inventory)
                .is_err()
        );

        let (successor, successor_inventory) = snapshot(2, 6, 5, 6, Vec::new());
        assert_eq!(
            history.outcome(&successor, &successor_inventory).unwrap(),
            None
        );
    }

    #[test]
    fn controller_state_change_invalidates_snapshot() {
        let (_directory, mut journal) = test_journal();
        let snapshot = durable_snapshot(&mut journal, Vec::new());
        snapshot.recheck(&mut journal).unwrap();

        create_slot(&mut journal);
        assert!(matches!(
            snapshot.recheck(&mut journal),
            Err(MountAttemptError::Conflict)
        ));
    }

    #[test]
    fn available_slot_action_matrix_is_exact() {
        let (_directory, mut journal) = test_journal();
        let slot = create_slot(&mut journal);
        let operation = OperationId::from_bytes(CREATE_OPERATION);
        assert_eq!(
            classify(&slot, operation, None).unwrap(),
            DestinationSlotReconciliationActionV1::Materialize {
                operation_id: operation
            }
        );

        let materializing = decoded_resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING,
        );
        assert_eq!(
            classify(&slot, operation, Some(&materializing)).unwrap(),
            DestinationSlotReconciliationActionV1::ResumeMaterialize {
                operation_id: operation
            }
        );

        let ready = decoded_resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        assert_eq!(
            classify(&slot, operation, Some(&ready)).unwrap(),
            DestinationSlotReconciliationActionV1::Ready {
                resource_digest: ObjectDigest::from_bytes(RESOURCE_DIGEST)
            }
        );

        for lifecycle in [
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED,
        ] {
            let invalid = decoded_resource(&slot, lifecycle);
            assert!(classify(&slot, operation, Some(&invalid)).is_err());
        }
    }

    #[test]
    fn released_slot_action_matrix_is_exact() {
        let (_directory, mut journal) = test_journal();
        let created = create_slot(&mut journal);
        let slot = release_slot(&mut journal, &created);
        let creation = OperationId::from_bytes(CREATE_OPERATION);
        let release = OperationId::from_bytes(RELEASE_OPERATION);
        assert_eq!(
            classify(&slot, creation, None).unwrap(),
            DestinationSlotReconciliationActionV1::Released
        );

        let materializing = decoded_resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_MATERIALIZING,
        );
        assert_eq!(
            classify(&slot, creation, Some(&materializing)).unwrap(),
            DestinationSlotReconciliationActionV1::ResumeMaterializeForReap {
                operation_id: creation,
                reap_operation_id: release,
            }
        );

        let ready = decoded_resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        assert_eq!(
            classify(&slot, creation, Some(&ready)).unwrap(),
            DestinationSlotReconciliationActionV1::Reap {
                operation_id: release,
                expected_resource_digest: ObjectDigest::from_bytes(RESOURCE_DIGEST),
            }
        );

        let reaping = decoded_resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING,
        );
        assert_eq!(
            classify(&slot, creation, Some(&reaping)).unwrap(),
            DestinationSlotReconciliationActionV1::ResumeReap {
                operation_id: release
            }
        );

        let released = decoded_resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED,
        );
        assert_eq!(
            classify(&slot, creation, Some(&released)).unwrap(),
            DestinationSlotReconciliationActionV1::Released
        );
    }

    #[test]
    fn reconciliation_retains_exact_current_slot_and_snapshot() {
        let (_directory, mut journal) = test_journal();
        let slot = create_slot(&mut journal);
        let row = resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        let snapshot = durable_snapshot(&mut journal, vec![row]);
        let snapshot_digest = snapshot.record_digest();

        let reconciliation = reconcile_current(&mut journal, slot.clone(), snapshot).unwrap();
        assert_eq!(reconciliation.slot(), &slot);
        assert_eq!(reconciliation.snapshot().record_digest(), snapshot_digest);
        assert_eq!(
            reconciliation.action(),
            DestinationSlotReconciliationActionV1::Ready {
                resource_digest: ObjectDigest::from_bytes(RESOURCE_DIGEST),
            }
        );
    }

    #[test]
    fn reconciliation_rejects_binding_and_operation_substitution() {
        let (_directory, mut journal) = test_journal();
        let slot = create_slot(&mut journal);
        let mut substituted = resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        substituted
            .binding
            .as_option_mut()
            .unwrap()
            .namespace_generation += 1;
        let snapshot = durable_snapshot(&mut journal, vec![substituted]);
        assert!(matches!(
            reconcile_current(&mut journal, slot.clone(), snapshot),
            Err(MountAttemptError::Conflict)
        ));

        let (_directory, mut journal) = test_journal();
        let slot = create_slot(&mut journal);
        let mut substituted = resource(
            &slot,
            DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
        );
        substituted
            .materialization
            .as_option_mut()
            .unwrap()
            .operation_id = vec![99; 16];
        let snapshot = durable_snapshot(&mut journal, vec![substituted]);
        assert!(matches!(
            reconcile_current(&mut journal, slot, snapshot),
            Err(MountAttemptError::Conflict)
        ));
    }

    #[test]
    fn malformed_namespace_blocks_reconciler_startup() {
        let (_directory, mut journal) = test_journal();
        journal
            .commit(
                &JournalTransaction::new(
                    [90; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DestinationSlotInventory,
                        KEY.to_vec(),
                        b"corrupt".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        let mut reconciler = Reconciler::new(journal, NoEffects);
        assert!(matches!(
            reconciler.ownership_gate(OperationId::from_bytes([91; 16])),
            Err(ReconcilerError::DestinationSlotInventory(_))
        ));
    }
}
