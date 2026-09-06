//! Authenticates and durably records complete Mount resource inventories.
//!
//! Inventory is queried over a one-shot Mount session and accepted only from
//! the pinned service execution that wrote both the hello and response. The
//! controller keeps the exact validated query and response as its latest
//! durable observation. Its controller-state commitment also covers durable
//! attachment verification. This snapshot is evidence for later reconciliation;
//! it does not recreate descriptor authority or prove attachment readiness.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerMethod, InventoryMountsRequest, RequestHeader,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId, ProtocolVersion};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedHeader, ValidatedMountInventory,
    decode_mount_inventory_request, decode_mount_inventory_response, decode_response_envelope,
    decode_server_hello, encode_unauthed_request_envelope,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::completion::CompletionHistory;
use super::{History as AttemptHistory, MountAttemptError};
use crate::mount_preparation::transport;
use crate::mount_preparation::{
    MountCatalogPreparationError, MountServiceIdentity, ServiceExecution, request_id,
};
use crate::runtime_scope::validate_namespace_target_namespace;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

mod format;
mod reconciliation;

pub(crate) use reconciliation::reconcile_current;
pub use reconciliation::{
    CurrentMountInventoryReconciliationV1, MountAttemptInventoryObservationV1,
    MountAttemptInventoryStatusV1,
};

const NAMESPACE: RecordNamespace = RecordNamespace::MountInventory;
const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);
const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES;
const RESPONSE_BYTES: u32 = 15 * 1024 * 1024;
const QUERY_WINDOW_NANOSECONDS: u64 = 10_000_000_000;
const MAXIMUM_QUERY_BYTES: usize = 4 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024 - 1024;
const KEY: &[u8] = b"latest";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.mount-inventory.transaction.v1\0";
const CONTROLLER_STATE_DOMAIN: &[u8] = b"aos.sandbox.mount-inventory.controller-state.v4\0";

/// Reports whether an authenticated inventory snapshot committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountInventorySnapshotOutcomeV1 {
    /// The authenticated query and complete response became durable.
    Recorded,
    /// The exact same query and response were already durable.
    Replay,
}

/// Owns one connected channel for a complete Mount resource inventory query.
pub struct MountInventoryClient {
    socket: DescriptorSubjectSocket,
    expected_mount: MountServiceIdentity,
}

impl MountInventoryClient {
    /// Configures an exclusively owned connected Mount channel before querying.
    ///
    /// The actual hello and response writers are authenticated through kernel
    /// record subjects against the configured service UID, GID, and retained
    /// cgroup. Listener credentials do not establish service identity under
    /// socket activation.
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
        let request_body = InventoryMountsRequest {
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
                "Mount inventory request packet",
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
        let inventory =
            decode_mount_inventory_response(&response_body, request.maximum_response_bytes())?;
        transport::check_deadline(deadline).map_err(MountAttemptError::Preparation)?;

        Ok(QuerySuccess {
            request_body,
            response_body,
            inventory,
        })
    }
}

/// Retains the latest exact authenticated Mount inventory after durable commit.
///
/// The response is a complete broker resource-table observation. It remains
/// non-authorizing after restart and must be compared with current controller
/// intent and a fresh live namespace proof before any follow-up effect.
pub struct DurableMountInventorySnapshotV1 {
    record: SnapshotRecord,
    inventory: ValidatedMountInventory,
    outcome: MountInventorySnapshotOutcomeV1,
}

impl DurableMountInventorySnapshotV1 {
    /// Returns whether the exact snapshot was newly recorded or replayed.
    #[must_use]
    pub const fn outcome(&self) -> MountInventorySnapshotOutcomeV1 {
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

    /// Returns the exact attempt/completion set observed before the query.
    #[must_use]
    pub const fn controller_state_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.controller_state_digest)
    }

    /// Borrows the complete validated Mount resource inventory.
    #[must_use]
    pub const fn inventory(&self) -> &ValidatedMountInventory {
        &self.inventory
    }

    pub(crate) fn recheck(&self, journal: &mut Journal) -> Result<(), MountAttemptError> {
        let history = SnapshotHistory::load(journal)?;
        if history.record.as_ref().map(|value| &value.0) != Some(&self.record)
            || controller_state_digest(journal)? != self.record.controller_state_digest
        {
            return Err(MountAttemptError::Conflict);
        }
        Ok(())
    }
}

struct QuerySuccess {
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    inventory: ValidatedMountInventory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SnapshotRecord {
    pub(super) request_id: [u8; 16],
    pub(super) controller_state_digest: [u8; 32],
    pub(super) request_body: Vec<u8>,
    pub(super) response_body: Vec<u8>,
    pub(super) digest: [u8; 32],
}

impl SnapshotRecord {
    fn from_query(
        controller_state_digest: [u8; 32],
        request_body: Vec<u8>,
        response_body: Vec<u8>,
    ) -> Result<(Self, ValidatedMountInventory), MountAttemptError> {
        let request = decode_inventory_request_body(&request_body)?;
        let inventory =
            decode_mount_inventory_response(&response_body, request.maximum_response_bytes())?;
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

    fn key(&self) -> Vec<u8> {
        KEY.to_vec()
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
            vec![JournalRecord::put(NAMESPACE, self.key(), self.encode())],
        )?)
    }

    fn encoded_len(&self) -> usize {
        format::FIXED_RECORD_BYTES
            .saturating_add(self.request_body.len())
            .saturating_add(self.response_body.len())
    }

    fn validate(&self) -> Result<ValidatedMountInventory, MountAttemptError> {
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
        decode_mount_inventory_response(&self.response_body, request.maximum_response_bytes())
            .map_err(|_| MountAttemptError::CorruptState)
    }
}

struct SnapshotHistory {
    record: Option<(SnapshotRecord, ValidatedMountInventory)>,
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
            if decoded.key() != key {
                return Err(MountAttemptError::CorruptState);
            }
            let inventory = decoded.validate()?;
            record = Some((decoded, inventory));
        }

        Ok(Self { record })
    }

    fn outcome(
        &self,
        candidate: &SnapshotRecord,
        inventory: &ValidatedMountInventory,
    ) -> Result<Option<MountInventorySnapshotOutcomeV1>, MountAttemptError> {
        let Some((current, current_inventory)) = &self.record else {
            return Ok(None);
        };
        if current == candidate {
            return Ok(Some(MountInventorySnapshotOutcomeV1::Replay));
        }
        if current.request_id == candidate.request_id
            || inventory.journal_sequence() < current_inventory.journal_sequence()
            || (inventory.journal_sequence() == current_inventory.journal_sequence()
                && inventory.mounts() != current_inventory.mounts())
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
    client: MountInventoryClient,
) -> Result<DurableMountInventorySnapshotV1, MountAttemptError> {
    let history = SnapshotHistory::load(journal)?;
    let observed_controller_state = controller_state_digest(journal)?;
    let success = client.query()?;
    if controller_state_digest(journal)? != observed_controller_state {
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
            MountInventorySnapshotOutcomeV1::Recorded
        }
    };
    let committed = SnapshotHistory::load(journal)?;
    if committed.record.as_ref().map(|value| &value.0) != Some(&record) {
        return Err(MountAttemptError::CorruptState);
    }

    Ok(DurableMountInventorySnapshotV1 {
        record,
        inventory,
        outcome,
    })
}

pub(crate) fn validate_namespace(journal: &mut Journal) -> Result<(), MountAttemptError> {
    SnapshotHistory::load(journal).map(|_| ())
}

pub(crate) fn controller_state_digest(
    journal: &mut Journal,
) -> Result<[u8; 32], MountAttemptError> {
    validate_namespace_target_namespace(journal)?;
    crate::attachment_state::validate_namespace(journal)
        .map_err(|_| MountAttemptError::CorruptState)?;
    crate::attachment_verification::validate_namespace(journal)
        .map_err(|_| MountAttemptError::CorruptState)?;
    let attempts = AttemptHistory::load(journal)?;
    let completions = CompletionHistory::load(journal)?;
    let target_count = u32::try_from(journal.records(RecordNamespace::NamespaceTarget).count())
        .map_err(|_| MountAttemptError::Capacity)?;
    let attempt_count =
        u32::try_from(attempts.records.len()).map_err(|_| MountAttemptError::Capacity)?;
    let completion_count =
        u32::try_from(completions.records.len()).map_err(|_| MountAttemptError::Capacity)?;
    let attachment_count =
        u32::try_from(journal.records(RecordNamespace::AttachmentDesired).count())
            .map_err(|_| MountAttemptError::Capacity)?;
    let verification_count = u32::try_from(
        journal
            .records(RecordNamespace::AttachmentVerification)
            .count(),
    )
    .map_err(|_| MountAttemptError::Capacity)?;
    let mut digest = Sha256::new();
    digest.update(CONTROLLER_STATE_DOMAIN);
    digest.update(target_count.to_be_bytes());
    for (key, value) in journal.records(RecordNamespace::NamespaceTarget) {
        digest.update(
            u32::try_from(key.len())
                .map_err(|_| MountAttemptError::Capacity)?
                .to_be_bytes(),
        );
        digest.update(key);
        digest.update(
            u32::try_from(value.len())
                .map_err(|_| MountAttemptError::Capacity)?
                .to_be_bytes(),
        );
        digest.update(value);
    }
    digest.update(attempt_count.to_be_bytes());
    for (request_id, record) in attempts.records {
        digest.update(b"attempt\0");
        digest.update(request_id);
        digest.update(record.digest);
    }
    digest.update(completion_count.to_be_bytes());
    for (request_id, record) in completions.records {
        digest.update(b"completion\0");
        digest.update(request_id);
        digest.update(record.digest);
    }
    digest.update(attachment_count.to_be_bytes());
    for (key, value) in journal.records(RecordNamespace::AttachmentDesired) {
        digest.update(
            u32::try_from(key.len())
                .map_err(|_| MountAttemptError::Capacity)?
                .to_be_bytes(),
        );
        digest.update(key);
        digest.update(
            u32::try_from(value.len())
                .map_err(|_| MountAttemptError::Capacity)?
                .to_be_bytes(),
        );
        digest.update(value);
    }
    digest.update(verification_count.to_be_bytes());
    for (key, value) in journal.records(RecordNamespace::AttachmentVerification) {
        digest.update(
            u32::try_from(key.len())
                .map_err(|_| MountAttemptError::Capacity)?
                .to_be_bytes(),
        );
        digest.update(key);
        digest.update(
            u32::try_from(value.len())
                .map_err(|_| MountAttemptError::Capacity)?
                .to_be_bytes(),
        );
        digest.update(value);
    }
    Ok(digest.finalize().into())
}

fn decode_inventory_request_body(bytes: &[u8]) -> Result<ValidatedHeader, MountAttemptError> {
    if bytes.len() > MAXIMUM_QUERY_BYTES {
        return Err(MountAttemptError::CorruptState);
    }
    let decoded = InventoryMountsRequest::decode_from_slice(bytes)
        .map_err(|_| MountAttemptError::CorruptState)?;
    let deadline = decoded
        .header
        .as_option()
        .map(|header| header.deadline_boottime_nanoseconds)
        .and_then(|value| value.checked_sub(1))
        .ok_or(MountAttemptError::CorruptState)?;
    let peer = synthetic_credentials();
    let request = decode_mount_inventory_request(
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
        AssignmentFence, Descriptor, InventoryMountResourcesResponse, MountAssignmentBinding,
        MountAttributes, MountInventoryRecord, MountLifecycle, MountRecipe, MountSourceConsistency,
    };

    use super::*;
    use crate::JournalLimits;

    fn query(request_byte: u8) -> Vec<u8> {
        InventoryMountsRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 2,
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

    fn response(sequence: u64, boot_byte: u8, instance_byte: u8) -> Vec<u8> {
        InventoryMountResourcesResponse {
            kernel_boot_id: vec![boot_byte; 16],
            broker_instance_id: vec![instance_byte; 16],
            journal_sequence: sequence,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn response_with_released_mount(sequence: u64, boot_byte: u8, instance_byte: u8) -> Vec<u8> {
        let binding = MountAssignmentBinding {
            fence: Some(AssignmentFence {
                sandbox_id: vec![1; 16],
                incarnation_id: vec![2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: vec![5; 32],
                ..Default::default()
            })
            .into(),
            namespace_generation: 6,
            ..Default::default()
        };
        let recipe = MountRecipe {
            attachment_id: vec![7; 16],
            destination_slot_id: vec![8; 16],
            view_revision: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![9; 32],
                encoded_size: 10,
                ..Default::default()
            })
            .into(),
            source_generation: 11,
            resource_attachment_generation: 12,
            source_view_id: vec![13; 16],
            source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                .into(),
            attributes: Some(MountAttributes {
                read_only: true,
                no_exec: true,
                no_suid: true,
                no_device: true,
                no_atime: true,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        InventoryMountResourcesResponse {
            kernel_boot_id: vec![boot_byte; 16],
            broker_instance_id: vec![instance_byte; 16],
            journal_sequence: sequence,
            mounts: vec![MountInventoryRecord {
                mount_handle: vec![12; 32],
                resource_revision: 13,
                binding: Some(binding).into(),
                recipe: Some(recipe).into(),
                lifecycle: MountLifecycle::MOUNT_LIFECYCLE_RELEASED.into(),
                resource_kernel_boot_id: vec![boot_byte; 16],
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn snapshot(
        request_byte: u8,
        sequence: u64,
        boot_byte: u8,
        instance_byte: u8,
    ) -> (SnapshotRecord, ValidatedMountInventory) {
        SnapshotRecord::from_query(
            [20; 32],
            query(request_byte),
            response(sequence, boot_byte, instance_byte),
        )
        .unwrap()
    }

    fn journal() -> (tempfile::TempDir, Journal) {
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

    #[test]
    fn snapshot_codec_preserves_one_exact_complete_inventory() {
        let (record, inventory) = snapshot(1, 2, 3, 4);
        let encoded = record.encode();
        let decoded = SnapshotRecord::decode(&encoded).unwrap();

        assert_eq!(decoded, record);
        assert_eq!(decoded.validate().unwrap(), inventory);
        assert_eq!(encoded.len(), record.encoded_len());
        assert_eq!(record.key(), KEY);
    }

    #[test]
    fn snapshot_codec_rejects_every_changed_or_truncated_byte() {
        let (record, _) = snapshot(1, 2, 3, 4);
        let encoded = record.encode();

        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(
                SnapshotRecord::decode(&changed).is_err(),
                "changed byte {index}"
            );
            assert!(
                SnapshotRecord::decode(&encoded[..index]).is_err(),
                "length {index}"
            );
        }
    }

    #[test]
    fn snapshot_history_rejects_rollback_and_same_sequence_equivocation() {
        let (current, current_inventory) = snapshot(1, 10, 3, 4);
        let history = SnapshotHistory {
            record: Some((current, current_inventory)),
        };
        let (rollback, rollback_inventory) = snapshot(2, 9, 3, 5);
        let (equivocation, equivocation_inventory) =
            SnapshotRecord::from_query([20; 32], query(3), response_with_released_mount(10, 3, 5))
                .unwrap();
        let (cross_boot_process, cross_boot_inventory) = snapshot(4, 11, 6, 4);

        assert!(matches!(
            history.outcome(&rollback, &rollback_inventory),
            Err(MountAttemptError::Conflict)
        ));
        assert!(matches!(
            history.outcome(&equivocation, &equivocation_inventory),
            Err(MountAttemptError::Conflict)
        ));
        assert!(matches!(
            history.outcome(&cross_boot_process, &cross_boot_inventory),
            Err(MountAttemptError::Conflict)
        ));
    }

    #[test]
    fn snapshot_history_accepts_fresh_process_observation_at_same_sequence() {
        let (current, current_inventory) = snapshot(1, 10, 3, 4);
        let history = SnapshotHistory {
            record: Some((current, current_inventory)),
        };
        let (candidate, inventory) = snapshot(2, 10, 3, 5);

        assert_eq!(history.outcome(&candidate, &inventory).unwrap(), None);
    }

    #[test]
    fn durable_snapshot_reloads_and_corruption_fails_closed() {
        let (_directory, mut journal) = journal();
        let (record, inventory) = snapshot(1, 2, 3, 4);
        journal.commit(&record.transaction().unwrap()).unwrap();

        let loaded = SnapshotHistory::load(&mut journal).unwrap();
        assert_eq!(loaded.record, Some((record.clone(), inventory)));

        let mut corrupt = record.encode();
        corrupt[0] ^= 1;
        journal
            .commit(
                &JournalTransaction::new(
                    [9; 16],
                    vec![JournalRecord::put(NAMESPACE, KEY.to_vec(), corrupt)],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            validate_namespace(&mut journal),
            Err(MountAttemptError::CorruptState)
        ));
    }

    #[test]
    fn changed_controller_attempt_namespace_invalidates_the_snapshot() {
        let (_directory, mut journal) = journal();
        let controller_state = controller_state_digest(&mut journal).unwrap();
        let (record, inventory) =
            SnapshotRecord::from_query(controller_state, query(1), response(2, 3, 4)).unwrap();
        journal.commit(&record.transaction().unwrap()).unwrap();
        let snapshot = DurableMountInventorySnapshotV1 {
            record,
            inventory,
            outcome: MountInventorySnapshotOutcomeV1::Recorded,
        };
        snapshot.recheck(&mut journal).unwrap();

        let attempt = crate::mount_attempt::tests::record();
        journal.commit(&attempt.transaction().unwrap()).unwrap();

        assert!(snapshot.recheck(&mut journal).is_err());
    }

    #[test]
    fn snapshot_rejects_a_recomputed_zero_controller_state() {
        let (mut record, _) = snapshot(1, 2, 3, 4);
        record.controller_state_digest = [0; 32];
        record.digest = record.compute_digest();

        assert!(matches!(
            record.validate(),
            Err(MountAttemptError::CorruptState)
        ));
    }
}
