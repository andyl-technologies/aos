//! Shared, nonauthorizing carrier for Controller observations of Mount inventories.
//!
//! ```text
//! kind-magic[8] | complete:1 | flags:1 | reserved:2 | request-id:16 |
//! controller-state:32 | request-bytes:4 | response-bytes:4 |
//! request | response | SHA-256(kind-domain || preceding bytes):32
//! ```
//!
//! Each inventory kind owns its wire identity, typed decoder, journal namespace,
//! and same-sequence conflict rule. This module only retains the common bounded
//! framing and durable replay order; a snapshot never grants Mount authority.

use std::marker::PhantomData;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerClientHello, BrokerMethod};
use aos_sandbox_core::{ProtocolId, ProtocolVersion};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::ValidatedHeader;
use aos_sandbox_protocol::{
    decode_response_envelope, decode_server_hello, encode_unauthed_request_envelope,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::mount_attempt::MountAttemptError;
use crate::mount_preparation::transport;
use crate::mount_preparation::{
    MountCatalogPreparationError, MountServiceIdentity, ServiceExecution,
};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const COMPLETE: u8 = 1;
const PREFIX_BYTES: usize = 68;
const DIGEST_BYTES: usize = 32;
const FIXED_RECORD_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;
const MAXIMUM_QUERY_BYTES: usize = 4 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 15 * 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024 - 1024;
const KEY: &[u8] = b"latest";
const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(2, 0);

/// Supplies one inventory's distinct wire and replay policy to the shared carrier.
pub(crate) trait InventorySnapshotKind: Clone + Eq + std::fmt::Debug {
    type Inventory: Clone + PartialEq;

    const MAGIC: &'static [u8; 8];
    const DIGEST_DOMAIN: &'static [u8];
    const TRANSACTION_DOMAIN: &'static [u8];
    const NAMESPACE: RecordNamespace;
    const METHOD: BrokerMethod;
    const REQUEST_PACKET_FIELD: &'static str;
    fn decode_request(bytes: &[u8]) -> Result<ValidatedHeader, MountAttemptError>;
    fn decode_response(
        bytes: &[u8],
        maximum_bytes: u32,
    ) -> Result<Self::Inventory, MountAttemptError>;
    fn journal_sequence(inventory: &Self::Inventory) -> u64;
    fn broker_instance_id(inventory: &Self::Inventory) -> &[u8; 16];
    fn kernel_boot_id(inventory: &Self::Inventory) -> &[u8; 16];
    fn same_sequence_equivocates(candidate: &Self::Inventory, current: &Self::Inventory) -> bool;
}

/// Carries one validated complete response with its exact wire bodies.
pub(crate) struct QuerySuccess<Inventory> {
    pub(crate) request_body: Vec<u8>,
    pub(crate) response_body: Vec<u8>,
    pub(crate) inventory: Inventory,
}

/// Performs the common one-shot Mount handshake and complete inventory query.
///
/// # Errors
///
/// Rejects invalid request framing, changed Mount identity, incomplete or
/// rejected replies, expired deadlines, and invalid typed inventories.
pub(crate) fn query_mount_inventory<Kind: InventorySnapshotKind>(
    socket: &mut DescriptorSubjectSocket,
    expected_mount: &MountServiceIdentity,
    request_body: Vec<u8>,
) -> Result<QuerySuccess<Kind::Inventory>, MountAttemptError> {
    let request = Kind::decode_request(&request_body)?;
    let request_deadline = request.deadline_boottime_nanoseconds();
    let packet =
        encode_unauthed_request_envelope(ProtocolId::MountBroker, Kind::METHOD, &request_body)?;
    let hello = BrokerClientHello {
        protocol_major: CARRIER_VERSION.major().into(),
        protocol_minor: CARRIER_VERSION.minor().into(),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        maximum_response_bytes: MAXIMUM_RESPONSE_BYTES as u32,
        required_methods: vec![Kind::METHOD.into()],
        ..Default::default()
    };
    let deadline =
        transport::exchange_deadline(request_deadline).map_err(MountAttemptError::Preparation)?;

    transport::send(socket, &hello.encode_to_vec(), deadline)
        .map_err(MountAttemptError::Preparation)?;
    let response = transport::receive(
        socket,
        aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
        deadline,
    )
    .map_err(MountAttemptError::Preparation)?;
    let (hello_bytes, subject, _) = response.into_parts();
    let mount = ServiceExecution::new(expected_mount, subject).map_err(map_service_error)?;
    let session = decode_server_hello(
        &hello_bytes,
        ProtocolId::MountBroker,
        Audience::AUDIENCE_NODE_CONTROLLER,
        CARRIER_VERSION,
        &[],
        &[Kind::METHOD],
        MAXIMUM_RESPONSE_BYTES as u32,
    )?;
    session.validate_header(&request)?;
    let decoded = session.decode_request(&packet, 0)?;
    if decoded.authorization().is_some() || decoded.body() != request_body.as_slice() {
        return Err(aos_sandbox_protocol::ProtocolValidationError::InvalidField(
            Kind::REQUEST_PACKET_FIELD,
        )
        .into());
    }

    mount.recheck(expected_mount).map_err(map_service_error)?;
    transport::send(socket, &packet, deadline).map_err(MountAttemptError::Preparation)?;
    let response = transport::receive(socket, MAXIMUM_RESPONSE_BYTES, deadline)
        .map_err(MountAttemptError::Preparation)?;
    mount
        .validate_response(expected_mount, response.subject())
        .map_err(map_service_error)?;
    let envelope = decode_response_envelope(
        response.payload(),
        request.request_id(),
        Kind::METHOD,
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
    let inventory = Kind::decode_response(&response_body, request.maximum_response_bytes())?;
    transport::check_deadline(deadline).map_err(MountAttemptError::Preparation)?;

    Ok(QuerySuccess {
        request_body,
        response_body,
        inventory,
    })
}

fn map_service_error(error: MountCatalogPreparationError) -> MountAttemptError {
    match error {
        MountCatalogPreparationError::MountIdentity => MountAttemptError::MountIdentity,
        other => MountAttemptError::Preparation(other),
    }
}

/// Retains one exact query and complete response in its inventory-specific namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotRecord<Kind: InventorySnapshotKind> {
    pub(crate) request_id: [u8; 16],
    pub(crate) controller_state_digest: [u8; 32],
    pub(crate) request_body: Vec<u8>,
    pub(crate) response_body: Vec<u8>,
    pub(crate) digest: [u8; 32],
    kind: PhantomData<Kind>,
}

impl<Kind: InventorySnapshotKind> SnapshotRecord<Kind> {
    /// Binds a typed, complete inventory reply to the exact query and state cut.
    ///
    /// # Errors
    ///
    /// Rejects invalid request or response bodies and unbounded records.
    pub(crate) fn from_query(
        controller_state_digest: [u8; 32],
        request_body: Vec<u8>,
        response_body: Vec<u8>,
    ) -> Result<(Self, Kind::Inventory), MountAttemptError> {
        let request = Kind::decode_request(&request_body)?;
        let inventory = Kind::decode_response(&response_body, request.maximum_response_bytes())?;
        let mut record = Self {
            request_id: *request.request_id(),
            controller_state_digest,
            request_body,
            response_body,
            digest: [0; 32],
            kind: PhantomData,
        };
        record.digest = record.compute_digest();
        record.validate()?;
        Ok((record, inventory))
    }

    pub(crate) fn key(&self) -> Vec<u8> {
        KEY.to_vec()
    }

    /// Constructs the inventory-specific durable replacement transaction.
    ///
    /// # Errors
    ///
    /// Rejects invalid transaction framing or journal capacity.
    pub(crate) fn transaction(&self) -> Result<JournalTransaction, MountAttemptError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(Kind::TRANSACTION_DOMAIN)
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| MountAttemptError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                Kind::NAMESPACE,
                self.key(),
                self.encode(),
            )],
        )?)
    }

    pub(crate) fn encoded_len(&self) -> usize {
        FIXED_RECORD_BYTES
            .saturating_add(self.request_body.len())
            .saturating_add(self.response_body.len())
    }

    /// Revalidates the complete stored query and typed inventory.
    ///
    /// # Errors
    ///
    /// Rejects malformed or overlong records, mismatched digests, and bad bodies.
    pub(crate) fn validate(&self) -> Result<Kind::Inventory, MountAttemptError> {
        if self.request_id == [0; 16]
            || self.controller_state_digest == [0; 32]
            || self.request_body.is_empty()
            || self.request_body.len() > MAXIMUM_QUERY_BYTES
            || self.response_body.is_empty()
            || self.response_body.len() > MAXIMUM_RESPONSE_BYTES
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
        {
            return Err(MountAttemptError::CorruptState);
        }

        let request = Kind::decode_request(&self.request_body)?;
        if request.request_id() != &self.request_id {
            return Err(MountAttemptError::CorruptState);
        }
        Kind::decode_response(&self.response_body, request.maximum_response_bytes())
            .map_err(|_| MountAttemptError::CorruptState)
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(Kind::MAGIC);
        bytes.push(COMPLETE);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.controller_state_digest);
        bytes.extend_from_slice(
            &u32::try_from(self.request_body.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.response_body.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.request_body);
        bytes.extend_from_slice(&self.response_body);
        bytes
    }

    pub(crate) fn compute_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(Kind::DIGEST_DOMAIN)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    /// Decodes a complete, kind-specific record without accepting trailing bytes.
    ///
    /// # Errors
    ///
    /// Rejects foreign framing, bad lengths, and changed digest bytes.
    pub(crate) fn decode(mut bytes: &[u8]) -> Result<Self, MountAttemptError> {
        if bytes.len() < FIXED_RECORD_BYTES || take::<8>(&mut bytes)? != *Kind::MAGIC {
            return Err(MountAttemptError::CorruptState);
        }
        if take::<1>(&mut bytes)? != [COMPLETE]
            || take::<1>(&mut bytes)? != [0]
            || take::<2>(&mut bytes)? != [0; 2]
        {
            return Err(MountAttemptError::CorruptState);
        }

        let request_id = take(&mut bytes)?;
        let controller_state_digest = take(&mut bytes)?;
        let request_bytes = length(&mut bytes)?;
        let response_bytes = length(&mut bytes)?;
        let variable_bytes = request_bytes
            .checked_add(response_bytes)
            .ok_or(MountAttemptError::CorruptState)?;
        if bytes.len() != variable_bytes.saturating_add(DIGEST_BYTES) {
            return Err(MountAttemptError::CorruptState);
        }
        let record = Self {
            request_id,
            controller_state_digest,
            request_body: take_vec(&mut bytes, request_bytes)?,
            response_body: take_vec(&mut bytes, response_bytes)?,
            digest: take(&mut bytes)?,
            kind: PhantomData,
        };
        if !bytes.is_empty() || record.compute_digest() != record.digest {
            return Err(MountAttemptError::CorruptState);
        }
        Ok(record)
    }
}

/// Records whether the candidate is new, an exact replay, or unchanged inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotDecision {
    Replay,
    Unchanged,
    Record,
}

/// Holds at most one complete, authenticated snapshot from an inventory journal.
pub(crate) struct SnapshotHistory<Kind: InventorySnapshotKind> {
    pub(crate) record: Option<(SnapshotRecord<Kind>, Kind::Inventory)>,
}

impl<Kind: InventorySnapshotKind> SnapshotHistory<Kind> {
    /// Loads the sole complete row for this inventory namespace.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, foreign, malformed, or untyped rows.
    pub(crate) fn load(journal: &mut Journal) -> Result<Self, MountAttemptError> {
        journal.ensure_healthy()?;
        let mut record = None;

        for (key, value) in journal.records(Kind::NAMESPACE) {
            if record.is_some() || key != KEY || value.len() > MAXIMUM_RECORD_BYTES {
                return Err(MountAttemptError::CorruptState);
            }
            let decoded = SnapshotRecord::<Kind>::decode(value)?;
            if decoded.key() != key {
                return Err(MountAttemptError::CorruptState);
            }
            let inventory = decoded.validate()?;
            record = Some((decoded, inventory));
        }

        Ok(Self { record })
    }

    /// Classifies an exact replay, unchanged observation, or new snapshot.
    ///
    /// # Errors
    ///
    /// Rejects request reuse, sequence rollback, or kind-specific equivocation.
    pub(crate) fn outcome(
        &self,
        candidate: &SnapshotRecord<Kind>,
        inventory: &Kind::Inventory,
    ) -> Result<SnapshotDecision, MountAttemptError> {
        let Some((current, current_inventory)) = &self.record else {
            return Ok(SnapshotDecision::Record);
        };
        if current == candidate {
            return Ok(SnapshotDecision::Replay);
        }
        if current.request_id == candidate.request_id
            || Kind::journal_sequence(inventory) < Kind::journal_sequence(current_inventory)
            || Kind::same_sequence_equivocates(inventory, current_inventory)
            || (Kind::broker_instance_id(inventory) == Kind::broker_instance_id(current_inventory)
                && Kind::kernel_boot_id(inventory) != Kind::kernel_boot_id(current_inventory))
        {
            return Err(MountAttemptError::Conflict);
        }
        if current.controller_state_digest == candidate.controller_state_digest
            && current_inventory == inventory
        {
            return Ok(SnapshotDecision::Unchanged);
        }

        Ok(SnapshotDecision::Record)
    }
}

/// Persists a new observation or reloads an exact replay after the decision.
///
/// # Errors
///
/// Rejects conflicting history, commit failure, or failed post-commit readback.
pub(crate) fn persist_snapshot<Kind: InventorySnapshotKind>(
    journal: &mut Journal,
    history: SnapshotHistory<Kind>,
    record: SnapshotRecord<Kind>,
    inventory: Kind::Inventory,
) -> Result<(SnapshotRecord<Kind>, Kind::Inventory, bool), MountAttemptError> {
    let (record, inventory, recorded) = match history.outcome(&record, &inventory)? {
        SnapshotDecision::Replay => (record, inventory, false),
        SnapshotDecision::Unchanged => {
            let (current, current_inventory) =
                history.record.ok_or(MountAttemptError::CorruptState)?;
            (current, current_inventory, false)
        }
        SnapshotDecision::Record => {
            journal.commit(&record.transaction()?)?;
            (record, inventory, true)
        }
    };
    let committed = SnapshotHistory::<Kind>::load(journal)?;
    if committed.record.as_ref().map(|value| &value.0) != Some(&record) {
        return Err(MountAttemptError::CorruptState);
    }

    Ok((record, inventory, recorded))
}

fn length(bytes: &mut &[u8]) -> Result<usize, MountAttemptError> {
    usize::try_from(u32::from_be_bytes(take(bytes)?)).map_err(|_| MountAttemptError::CorruptState)
}

fn take_vec(bytes: &mut &[u8], length: usize) -> Result<Vec<u8>, MountAttemptError> {
    let (prefix, remaining) = bytes
        .split_at_checked(length)
        .ok_or(MountAttemptError::CorruptState)?;
    *bytes = remaining;
    Ok(prefix.to_vec())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], MountAttemptError> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(MountAttemptError::CorruptState)?;
    let value = prefix
        .try_into()
        .map_err(|_| MountAttemptError::CorruptState)?;
    *bytes = remaining;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination_slot_inventory::DestinationSlotInventoryKind;
    use crate::mount_attempt::MountResourceInventoryKind;

    fn assert_golden<Kind: InventorySnapshotKind>(expected: &str) {
        let mut record = SnapshotRecord::<Kind> {
            request_id: [0x11; 16],
            controller_state_digest: [0x22; 32],
            request_body: b"q".to_vec(),
            response_body: b"rs".to_vec(),
            digest: [0; 32],
            kind: PhantomData,
        };
        record.digest = record.compute_digest();
        let encoded = record.encode();
        let actual = encoded
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert_eq!(actual, expected);
        assert_eq!(SnapshotRecord::<Kind>::decode(&encoded).unwrap(), record);
    }

    #[test]
    fn mount_resource_snapshot_wire_golden() {
        assert_golden::<MountResourceInventoryKind>(concat!(
            "414f534d544930310100000011111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0000000100000002717273757abae6867c128e65f4192ca7c5ee556a81434f1d06727437dff988f9f04d8e",
        ));
    }

    #[test]
    fn destination_slot_snapshot_wire_golden() {
        assert_golden::<DestinationSlotInventoryKind>(concat!(
            "414f5344534930310100000011111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0000000100000002717273f1ce41af3cd69a822bedae4cc74621d018a79cd35623acf763cffca5750cf304",
        ));
    }
}
