//! Authenticates and durably records Storage and Network resource inventories.
//!
//! Each query uses an independent one-shot protocol 1.2 session and accepts a
//! response only from the configured live broker execution. The controller
//! records the exact request and complete response in a domain-specific latest
//! snapshot:
//!
//! ```text
//! controller state + authenticated query + complete broker response
//!     -> continuity checks
//!     -> durable Storage or Network latest-snapshot record
//! ```
//!
//! These snapshots are observation evidence. They carry no descriptor or
//! effect authority, and catalog projection must recheck that both snapshots
//! still postdate the same current controller state.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerErrorCode, BrokerMethod, InventoryNetworksRequest,
    InventoryStorageRequest, RequestHeader,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId, ProtocolVersion};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    ValidatedNetworkInventory, ValidatedStorageInventory,
    decode_network_resource_inventory_request, decode_network_resource_inventory_response,
    decode_response_envelope, decode_server_hello, decode_storage_resource_inventory_request,
    decode_storage_resource_inventory_response, encode_unauthed_request_envelope,
};
use buffa::Message as _;
use rand::{TryRngCore as _, rngs::OsRng};
use rustix::event::{PollFd, PollFlags, poll};
use sha2::{Digest as _, Sha256};

use crate::mount_attempt::{MountAttemptError, mount_controller_state_digest};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

mod format;

const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);
const RESPONSE_BYTES: u32 = 15 * 1024 * 1024;
const QUERY_WINDOW_NANOSECONDS: u64 = 10_000_000_000;
const MAXIMUM_QUERY_BYTES: usize = 4 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024 - 1024;
const KEY: &[u8] = b"latest";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.resource-inventory.transaction.v1\0";
const CONTROLLER_STATE_DOMAIN: &[u8] = b"aos.sandbox.resource-inventory.controller-state.v1\0";

/// Reports whether an authenticated broker snapshot committed or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceInventorySnapshotOutcomeV1 {
    /// The authenticated query and complete response became durable.
    Recorded,
    /// The exact same query and response were already durable.
    Replay,
}

/// Pins one expected inventory broker independently of all socket replies.
pub struct ResourceInventoryServiceIdentity {
    /// Required kernel-authorized service UID.
    pub uid: u32,
    /// Required kernel-authorized service GID.
    pub gid: u32,
    /// Retained exact service cgroup selected by deployment configuration.
    pub cgroup: RetainedCgroupAnchor,
}

/// Owns one connected channel for a complete Storage resource query.
pub struct StorageResourceInventoryClient {
    inner: ResourceInventoryClient,
}

impl StorageResourceInventoryClient {
    /// Configures an exclusively owned Storage channel before querying.
    ///
    /// The hello and response writers are authenticated through kernel record
    /// subjects against the configured UID, GID, and retained exact cgroup.
    ///
    /// # Errors
    ///
    /// Rejects an inactive service cgroup, an incompatible socket, or
    /// unavailable kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_storage: ResourceInventoryServiceIdentity,
    ) -> Result<Self, ResourceInventoryError> {
        Ok(Self {
            inner: ResourceInventoryClient::from_connected(
                fd,
                expected_storage,
                InventoryDomain::Storage,
            )?,
        })
    }
}

/// Owns one connected channel for a complete Network resource query.
pub struct NetworkResourceInventoryClient {
    inner: ResourceInventoryClient,
}

impl NetworkResourceInventoryClient {
    /// Configures an exclusively owned Network channel before querying.
    ///
    /// The hello and response writers are authenticated through kernel record
    /// subjects against the configured UID, GID, and retained exact cgroup.
    ///
    /// # Errors
    ///
    /// Rejects an inactive service cgroup, an incompatible socket, or
    /// unavailable kernel credential and pidfd reporting.
    pub fn from_connected(
        fd: OwnedFd,
        expected_network: ResourceInventoryServiceIdentity,
    ) -> Result<Self, ResourceInventoryError> {
        Ok(Self {
            inner: ResourceInventoryClient::from_connected(
                fd,
                expected_network,
                InventoryDomain::Network,
            )?,
        })
    }
}

/// Retains the latest exact authenticated Storage resource inventory.
pub struct DurableStorageResourceInventorySnapshotV1 {
    record: SnapshotRecord,
    inventory: ValidatedStorageInventory,
    outcome: ResourceInventorySnapshotOutcomeV1,
}

impl DurableStorageResourceInventorySnapshotV1 {
    /// Returns whether the exact snapshot was newly recorded or replayed.
    #[must_use]
    pub const fn outcome(&self) -> ResourceInventorySnapshotOutcomeV1 {
        self.outcome
    }

    /// Returns the unique request identity used for this query.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete versioned snapshot record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Returns the controller state observed immediately before the query.
    #[must_use]
    pub const fn controller_state_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.controller_state_digest)
    }

    /// Borrows the complete validated Storage inventory.
    #[must_use]
    pub const fn inventory(&self) -> &ValidatedStorageInventory {
        &self.inventory
    }

    /// Rechecks that this is the latest snapshot of unchanged controller state.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceInventoryError`] when durable history is corrupt, a
    /// newer Storage snapshot replaced this one, or catalog-relevant controller
    /// state changed after the query.
    pub fn recheck(&self, journal: &mut Journal) -> Result<(), ResourceInventoryError> {
        recheck_snapshot(journal, &self.record)
    }
}

/// Retains the latest exact authenticated Network resource inventory.
pub struct DurableNetworkResourceInventorySnapshotV1 {
    record: SnapshotRecord,
    inventory: ValidatedNetworkInventory,
    outcome: ResourceInventorySnapshotOutcomeV1,
}

impl DurableNetworkResourceInventorySnapshotV1 {
    /// Returns whether the exact snapshot was newly recorded or replayed.
    #[must_use]
    pub const fn outcome(&self) -> ResourceInventorySnapshotOutcomeV1 {
        self.outcome
    }

    /// Returns the unique request identity used for this query.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }

    /// Returns the digest of the complete versioned snapshot record.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Returns the controller state observed immediately before the query.
    #[must_use]
    pub const fn controller_state_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.controller_state_digest)
    }

    /// Borrows the complete validated Network inventory.
    #[must_use]
    pub const fn inventory(&self) -> &ValidatedNetworkInventory {
        &self.inventory
    }

    /// Rechecks that this is the latest snapshot of unchanged controller state.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceInventoryError`] when durable history is corrupt, a
    /// newer Network snapshot replaced this one, or catalog-relevant controller
    /// state changed after the query.
    pub fn recheck(&self, journal: &mut Journal) -> Result<(), ResourceInventoryError> {
        recheck_snapshot(journal, &self.record)
    }
}

/// Reports rejected, stale, or corrupt resource-inventory evidence.
#[derive(Debug, thiserror::Error)]
pub enum ResourceInventoryError {
    /// A retained snapshot or its protected cross-reference is inconsistent.
    #[error("resource inventory history is corrupt")]
    CorruptState,
    /// A request identity or broker continuity observation conflicts with history.
    #[error("resource inventory conflicts with durable history")]
    Conflict,
    /// A fixed record-count or byte ceiling is exhausted.
    #[error("resource inventory capacity is exhausted")]
    Capacity,
    /// Kernel randomness for a fresh request identity is unavailable.
    #[error("resource inventory request entropy is unavailable")]
    EntropyUnavailable,
    /// The bounded query deadline elapsed or overflowed.
    #[error("resource inventory deadline elapsed or clock is invalid")]
    Deadline,
    /// A response came from an execution other than the configured broker.
    #[error("resource inventory response does not match the pinned broker service")]
    ServiceIdentity,
    /// The broker rejected or could not complete the request.
    #[error(
        "resource inventory broker rejected the request with {code:?} (retryable: {retryable})"
    )]
    BrokerRejected {
        /// Closed broker error code.
        code: BrokerErrorCode,
        /// Whether the same semantics may succeed on a later query.
        retryable: bool,
    },
    /// Negotiation, request binding, or the response body failed validation.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// Kernel record-subject validation or packet transfer failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Kernel service identity or cgroup validation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// Protected journal provenance, health, or durability failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A polling syscall failed.
    #[error("resource inventory I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
}

struct ResourceInventoryClient {
    socket: DescriptorSubjectSocket,
    expected_service: ResourceInventoryServiceIdentity,
    domain: InventoryDomain,
}

impl ResourceInventoryClient {
    fn from_connected(
        fd: OwnedFd,
        expected_service: ResourceInventoryServiceIdentity,
        domain: InventoryDomain,
    ) -> Result<Self, ResourceInventoryError> {
        expected_service.cgroup.validate_current()?;

        Ok(Self {
            socket: DescriptorSubjectSocket::from_owned(fd)?,
            expected_service,
            domain,
        })
    }

    fn query(mut self) -> Result<QuerySuccess, ResourceInventoryError> {
        let now = boottime()?;
        let request_deadline = now
            .checked_add(QUERY_WINDOW_NANOSECONDS)
            .ok_or(ResourceInventoryError::Deadline)?;
        let request_id = request_id()?;
        let request_body = self.domain.request_body(request_id, request_deadline);
        let request = self.domain.decode_request(&request_body)?;
        let packet = encode_unauthed_request_envelope(
            self.domain.protocol(),
            self.domain.method(),
            &request_body,
        )?;
        let hello = BrokerClientHello {
            protocol_major: CARRIER_VERSION.major().into(),
            protocol_minor: CARRIER_VERSION.minor().into(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            maximum_response_bytes: RESPONSE_BYTES,
            required_methods: vec![self.domain.method().into()],
            ..Default::default()
        };
        let deadline = exchange_deadline(request_deadline)?;

        send(&mut self.socket, &hello.encode_to_vec(), deadline)?;
        let response = receive(
            &mut self.socket,
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
            deadline,
        )?;
        let (hello_bytes, subject, _) = response.into_parts();
        let service = ServiceExecution::new(&self.expected_service, subject)?;
        let session = decode_server_hello(
            &hello_bytes,
            self.domain.protocol(),
            Audience::AUDIENCE_NODE_CONTROLLER,
            CARRIER_VERSION,
            &[],
            &[self.domain.method()],
            RESPONSE_BYTES,
        )?;
        session.validate_header(&request)?;
        let decoded = session.decode_request(&packet, 0)?;
        if decoded.authorization().is_some() || decoded.body() != request_body.as_slice() {
            return Err(
                ProtocolValidationError::InvalidField("resource inventory request packet").into(),
            );
        }

        service.recheck(&self.expected_service)?;
        send(&mut self.socket, &packet, deadline)?;
        let response = receive(&mut self.socket, RESPONSE_BYTES as usize, deadline)?;
        service.validate_response(&self.expected_service, response.subject())?;
        let envelope = decode_response_envelope(
            response.payload(),
            request.request_id(),
            self.domain.method(),
            &[],
            response.descriptors().len(),
            session.maximum_response_bytes(),
            request.maximum_response_bytes(),
        )?;
        if let Some(error) = envelope.error() {
            return Err(ResourceInventoryError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            });
        }
        let response_body = envelope.body().to_vec();
        let inventory = self
            .domain
            .decode_response(&response_body, request.maximum_response_bytes())?;
        check_deadline(deadline)?;

        Ok(QuerySuccess {
            domain: self.domain,
            request_body,
            response_body,
            inventory,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum InventoryDomain {
    Storage = 1,
    Network = 2,
}

impl InventoryDomain {
    fn from_byte(value: u8) -> Result<Self, ResourceInventoryError> {
        match value {
            1 => Ok(Self::Storage),
            2 => Ok(Self::Network),
            _ => Err(ResourceInventoryError::CorruptState),
        }
    }

    const fn protocol(self) -> ProtocolId {
        match self {
            Self::Storage => ProtocolId::StorageBroker,
            Self::Network => ProtocolId::NetworkBroker,
        }
    }

    const fn method(self) -> BrokerMethod {
        match self {
            Self::Storage => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            Self::Network => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        }
    }

    const fn namespace(self) -> RecordNamespace {
        match self {
            Self::Storage => RecordNamespace::StorageResourceInventory,
            Self::Network => RecordNamespace::NetworkResourceInventory,
        }
    }

    fn request_body(self, request_id: [u8; 16], deadline: u64) -> Vec<u8> {
        let header = Some(RequestHeader {
            protocol_major: CARRIER_VERSION.major().into(),
            protocol_minor: CARRIER_VERSION.minor().into(),
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes: RESPONSE_BYTES,
            ..Default::default()
        })
        .into();

        match self {
            Self::Storage => InventoryStorageRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
            Self::Network => InventoryNetworksRequest {
                header,
                ..Default::default()
            }
            .encode_to_vec(),
        }
    }

    fn decode_request(self, bytes: &[u8]) -> Result<ValidatedHeader, ResourceInventoryError> {
        if bytes.len() > MAXIMUM_QUERY_BYTES {
            return Err(ResourceInventoryError::CorruptState);
        }
        let deadline = match self {
            Self::Storage => InventoryStorageRequest::decode_from_slice(bytes)
                .ok()
                .and_then(|request| {
                    request
                        .header
                        .as_option()
                        .map(|header| header.deadline_boottime_nanoseconds)
                }),
            Self::Network => InventoryNetworksRequest::decode_from_slice(bytes)
                .ok()
                .and_then(|request| {
                    request
                        .header
                        .as_option()
                        .map(|header| header.deadline_boottime_nanoseconds)
                }),
        }
        .and_then(|value| value.checked_sub(1))
        .ok_or(ResourceInventoryError::CorruptState)?;
        let peer = synthetic_credentials();
        let policy = PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        let header = match self {
            Self::Storage => {
                decode_storage_resource_inventory_request(bytes, peer, policy, deadline)
            }
            Self::Network => {
                decode_network_resource_inventory_request(bytes, peer, policy, deadline)
            }
        }
        .map_err(|_| ResourceInventoryError::CorruptState)?;
        if header.protocol_version() != CARRIER_VERSION
            || header.audience() != Audience::AUDIENCE_NODE_CONTROLLER
            || header.maximum_response_bytes() != RESPONSE_BYTES
        {
            return Err(ResourceInventoryError::CorruptState);
        }

        Ok(header)
    }

    fn decode_response(
        self,
        bytes: &[u8],
        maximum_response_bytes: u32,
    ) -> Result<ValidatedResourceInventory, ProtocolValidationError> {
        match self {
            Self::Storage => {
                decode_storage_resource_inventory_response(bytes, maximum_response_bytes)
                    .map(ValidatedResourceInventory::Storage)
            }
            Self::Network => {
                decode_network_resource_inventory_response(bytes, maximum_response_bytes)
                    .map(ValidatedResourceInventory::Network)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ValidatedResourceInventory {
    Storage(ValidatedStorageInventory),
    Network(ValidatedNetworkInventory),
}

impl ValidatedResourceInventory {
    const fn domain(&self) -> InventoryDomain {
        match self {
            Self::Storage(_) => InventoryDomain::Storage,
            Self::Network(_) => InventoryDomain::Network,
        }
    }

    const fn journal_sequence(&self) -> u64 {
        match self {
            Self::Storage(inventory) => inventory.journal_sequence(),
            Self::Network(inventory) => inventory.journal_sequence(),
        }
    }

    const fn catalog_generation(&self) -> u64 {
        match self {
            Self::Storage(inventory) => inventory.catalog_generation(),
            Self::Network(inventory) => inventory.catalog_generation(),
        }
    }

    const fn kernel_boot_id(&self) -> &[u8; 16] {
        match self {
            Self::Storage(inventory) => inventory.kernel_boot_id(),
            Self::Network(inventory) => inventory.kernel_boot_id(),
        }
    }

    const fn broker_instance_id(&self) -> &[u8; 16] {
        match self {
            Self::Storage(inventory) => inventory.broker_instance_id(),
            Self::Network(inventory) => inventory.broker_instance_id(),
        }
    }

    fn resources_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Storage(left), Self::Storage(right)) => left.workspaces() == right.workspaces(),
            (Self::Network(left), Self::Network(right)) => left.networks() == right.networks(),
            _ => false,
        }
    }
}

struct QuerySuccess {
    domain: InventoryDomain,
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    inventory: ValidatedResourceInventory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotRecord {
    domain: InventoryDomain,
    request_id: [u8; 16],
    controller_state_digest: [u8; 32],
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    digest: [u8; 32],
}

impl SnapshotRecord {
    fn from_query(
        domain: InventoryDomain,
        controller_state_digest: [u8; 32],
        request_body: Vec<u8>,
        response_body: Vec<u8>,
    ) -> Result<(Self, ValidatedResourceInventory), ResourceInventoryError> {
        let request = domain.decode_request(&request_body)?;
        let inventory = domain
            .decode_response(&response_body, request.maximum_response_bytes())
            .map_err(|_| ResourceInventoryError::CorruptState)?;
        let mut record = Self {
            domain,
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

    fn validate(&self) -> Result<ValidatedResourceInventory, ResourceInventoryError> {
        if self.request_id == [0; 16]
            || self.controller_state_digest == [0; 32]
            || self.request_body.is_empty()
            || self.request_body.len() > MAXIMUM_QUERY_BYTES
            || self.response_body.is_empty()
            || self.response_body.len() > RESPONSE_BYTES as usize
            || self.encoded_len() > MAXIMUM_RECORD_BYTES
            || self.compute_digest() != self.digest
        {
            return Err(ResourceInventoryError::CorruptState);
        }

        let request = self.domain.decode_request(&self.request_body)?;
        if request.request_id() != &self.request_id {
            return Err(ResourceInventoryError::CorruptState);
        }
        self.domain
            .decode_response(&self.response_body, request.maximum_response_bytes())
            .map_err(|_| ResourceInventoryError::CorruptState)
    }

    fn transaction(&self) -> Result<JournalTransaction, ResourceInventoryError> {
        let mut transaction_id: [u8; 16] = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update([self.domain as u8])
            .chain_update(self.digest)
            .finalize()[..16]
            .try_into()
            .map_err(|_| ResourceInventoryError::CorruptState)?;
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }

        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                self.domain.namespace(),
                KEY.to_vec(),
                self.encode(),
            )],
        )?)
    }
}

struct SnapshotHistory {
    record: Option<(SnapshotRecord, ValidatedResourceInventory)>,
}

impl SnapshotHistory {
    fn load(
        journal: &mut Journal,
        domain: InventoryDomain,
    ) -> Result<Self, ResourceInventoryError> {
        journal.ensure_healthy()?;
        let mut record = None;

        for (key, value) in journal.records(domain.namespace()) {
            if record.is_some() || key != KEY || value.len() > MAXIMUM_RECORD_BYTES {
                return Err(ResourceInventoryError::CorruptState);
            }
            let decoded = SnapshotRecord::decode(value)?;
            if decoded.domain != domain {
                return Err(ResourceInventoryError::CorruptState);
            }
            let inventory = decoded.validate()?;
            record = Some((decoded, inventory));
        }

        Ok(Self { record })
    }

    fn outcome(
        &self,
        candidate: &SnapshotRecord,
        inventory: &ValidatedResourceInventory,
    ) -> Result<Option<ResourceInventorySnapshotOutcomeV1>, ResourceInventoryError> {
        if candidate.domain != inventory.domain() {
            return Err(ResourceInventoryError::CorruptState);
        }
        let Some((current, current_inventory)) = &self.record else {
            return Ok(None);
        };
        if current == candidate {
            return Ok(Some(ResourceInventorySnapshotOutcomeV1::Replay));
        }
        if current.request_id == candidate.request_id
            || inventory.journal_sequence() < current_inventory.journal_sequence()
            || inventory.catalog_generation() < current_inventory.catalog_generation()
            || (inventory.journal_sequence() == current_inventory.journal_sequence()
                && (inventory.catalog_generation() != current_inventory.catalog_generation()
                    || !inventory.resources_equal(current_inventory)))
            || (inventory.catalog_generation() == current_inventory.catalog_generation()
                && !inventory.resources_equal(current_inventory))
            || (inventory.broker_instance_id() == current_inventory.broker_instance_id()
                && inventory.kernel_boot_id() != current_inventory.kernel_boot_id())
        {
            return Err(ResourceInventoryError::Conflict);
        }

        Ok(None)
    }
}

pub(crate) fn record_storage_snapshot(
    journal: &mut Journal,
    client: StorageResourceInventoryClient,
) -> Result<DurableStorageResourceInventorySnapshotV1, ResourceInventoryError> {
    let recorded = record_snapshot(journal, client.inner)?;
    let ValidatedResourceInventory::Storage(inventory) = recorded.inventory else {
        return Err(ResourceInventoryError::CorruptState);
    };

    Ok(DurableStorageResourceInventorySnapshotV1 {
        record: recorded.record,
        inventory,
        outcome: recorded.outcome,
    })
}

pub(crate) fn record_network_snapshot(
    journal: &mut Journal,
    client: NetworkResourceInventoryClient,
) -> Result<DurableNetworkResourceInventorySnapshotV1, ResourceInventoryError> {
    let recorded = record_snapshot(journal, client.inner)?;
    let ValidatedResourceInventory::Network(inventory) = recorded.inventory else {
        return Err(ResourceInventoryError::CorruptState);
    };

    Ok(DurableNetworkResourceInventorySnapshotV1 {
        record: recorded.record,
        inventory,
        outcome: recorded.outcome,
    })
}

fn record_snapshot(
    journal: &mut Journal,
    client: ResourceInventoryClient,
) -> Result<RecordedSnapshot, ResourceInventoryError> {
    let domain = client.domain;
    let history = SnapshotHistory::load(journal, domain)?;
    let observed_controller_state = controller_state_digest(journal)?;
    let success = client.query()?;
    if success.domain != domain || controller_state_digest(journal)? != observed_controller_state {
        return Err(ResourceInventoryError::Conflict);
    }
    let (record, inventory) = SnapshotRecord::from_query(
        domain,
        observed_controller_state,
        success.request_body,
        success.response_body,
    )?;
    if inventory != success.inventory {
        return Err(ResourceInventoryError::CorruptState);
    }

    let outcome = match history.outcome(&record, &inventory)? {
        Some(outcome) => outcome,
        None => {
            journal.commit(&record.transaction()?)?;
            ResourceInventorySnapshotOutcomeV1::Recorded
        }
    };
    let committed = SnapshotHistory::load(journal, domain)?;
    if committed.record.as_ref().map(|value| &value.0) != Some(&record) {
        return Err(ResourceInventoryError::CorruptState);
    }

    Ok(RecordedSnapshot {
        record,
        inventory,
        outcome,
    })
}

struct RecordedSnapshot {
    record: SnapshotRecord,
    inventory: ValidatedResourceInventory,
    outcome: ResourceInventorySnapshotOutcomeV1,
}

fn recheck_snapshot(
    journal: &mut Journal,
    snapshot: &SnapshotRecord,
) -> Result<(), ResourceInventoryError> {
    let history = SnapshotHistory::load(journal, snapshot.domain)?;
    if history.record.as_ref().map(|value| &value.0) != Some(snapshot)
        || controller_state_digest(journal)? != snapshot.controller_state_digest
    {
        return Err(ResourceInventoryError::Conflict);
    }

    Ok(())
}

pub(crate) fn validate_namespaces(journal: &mut Journal) -> Result<(), ResourceInventoryError> {
    SnapshotHistory::load(journal, InventoryDomain::Storage)?;
    SnapshotHistory::load(journal, InventoryDomain::Network)?;

    Ok(())
}

fn controller_state_digest(journal: &mut Journal) -> Result<[u8; 32], ResourceInventoryError> {
    let mount_state_digest = match mount_controller_state_digest(journal) {
        Ok(digest) => Ok(digest),
        Err(MountAttemptError::Capacity) => Err(ResourceInventoryError::Capacity),
        Err(MountAttemptError::Journal(error)) => Err(ResourceInventoryError::Journal(error)),
        Err(_) => Err(ResourceInventoryError::CorruptState),
    }?;
    let namespaces = [
        RecordNamespace::DesiredState,
        RecordNamespace::Operation,
        RecordNamespace::Effect,
        RecordNamespace::Idempotency,
        RecordNamespace::OwnershipGate,
        RecordNamespace::AuthorityPublication,
        RecordNamespace::PublisherAuthority,
        RecordNamespace::PublisherPolicy,
        RecordNamespace::PublisherIngress,
        RecordNamespace::RuntimeAuthority,
        RecordNamespace::RuntimeGeneration,
        RecordNamespace::NamespaceTarget,
        RecordNamespace::MountAttempt,
        RecordNamespace::MountCompletion,
        RecordNamespace::MountInventory,
        RecordNamespace::AttachmentDesired,
        RecordNamespace::AttachmentVerification,
        RecordNamespace::FilesystemViewRevision,
        RecordNamespace::AttachmentSlot,
        RecordNamespace::SandboxSpec,
        RecordNamespace::MountDestinationSlot,
        RecordNamespace::DestinationSlotInventory,
        RecordNamespace::DestinationSlotAttempt,
        RecordNamespace::DestinationSlotCompletion,
        RecordNamespace::HostCatalogReconciliation,
    ];
    let mut digest = Sha256::new();
    digest.update(CONTROLLER_STATE_DOMAIN);
    digest.update(mount_state_digest);

    for namespace in namespaces {
        digest.update([namespace as u8]);
        let record_count = u32::try_from(journal.records(namespace).count())
            .map_err(|_| ResourceInventoryError::Capacity)?;
        digest.update(record_count.to_be_bytes());

        for (key, value) in journal.records(namespace) {
            digest.update(
                u32::try_from(key.len())
                    .map_err(|_| ResourceInventoryError::Capacity)?
                    .to_be_bytes(),
            );
            digest.update(key);
            digest.update(
                u32::try_from(value.len())
                    .map_err(|_| ResourceInventoryError::Capacity)?
                    .to_be_bytes(),
            );
            digest.update(value);
        }
    }

    Ok(digest.finalize().into())
}

fn request_id() -> Result<[u8; 16], ResourceInventoryError> {
    let mut request_id = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut request_id)
        .map_err(|_| ResourceInventoryError::EntropyUnavailable)?;
    request_id[6] = (request_id[6] & 0x0f) | 0x40;
    request_id[8] = (request_id[8] & 0x3f) | 0x80;

    Ok(request_id)
}

fn synthetic_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    }
}

struct ServiceExecution {
    subject: KernelAuthorizedRecordSubject,
    info: PidFdInfo,
}

impl ServiceExecution {
    fn new(
        expected: &ResourceInventoryServiceIdentity,
        subject: KernelAuthorizedRecordSubject,
    ) -> Result<Self, ResourceInventoryError> {
        let info = validate_service_subject(expected, &subject)?;

        Ok(Self { subject, info })
    }

    fn recheck(
        &self,
        expected: &ResourceInventoryServiceIdentity,
    ) -> Result<PidFdInfo, ResourceInventoryError> {
        let fresh = validate_service_subject(expected, &self.subject)?;
        if !same_process(fresh, self.info) {
            return Err(ResourceInventoryError::ServiceIdentity);
        }

        Ok(fresh)
    }

    fn validate_response(
        &self,
        expected: &ResourceInventoryServiceIdentity,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), ResourceInventoryError> {
        let before = self.recheck(expected)?;
        let response = validate_service_subject(expected, subject)?;
        let after = self.recheck(expected)?;
        if !same_process(before, response) || !same_process(after, response) {
            return Err(ResourceInventoryError::ServiceIdentity);
        }

        Ok(())
    }
}

fn validate_service_subject(
    expected: &ResourceInventoryServiceIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<PidFdInfo, ResourceInventoryError> {
    let credentials = subject.credentials();
    if credentials.uid() != expected.uid
        || credentials.gid() != expected.gid
        || !subject.is_alive()?
    {
        return Err(ResourceInventoryError::ServiceIdentity);
    }

    Ok(expected.cgroup.verify_exact_membership(subject.pidfd())?)
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

fn boottime() -> Result<u64, ResourceInventoryError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| ResourceInventoryError::Deadline)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| ResourceInventoryError::Deadline)?;

    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(ResourceInventoryError::Deadline)
}

fn exchange_deadline(request: u64) -> Result<u64, ResourceInventoryError> {
    let now = boottime()?;
    if now >= request {
        return Err(ResourceInventoryError::Deadline);
    }

    Ok(request.min(
        now.checked_add(QUERY_WINDOW_NANOSECONDS)
            .ok_or(ResourceInventoryError::Deadline)?,
    ))
}

fn check_deadline(deadline: u64) -> Result<(), ResourceInventoryError> {
    if boottime()? >= deadline {
        return Err(ResourceInventoryError::Deadline);
    }

    Ok(())
}

fn send(
    socket: &mut DescriptorSubjectSocket,
    bytes: &[u8],
    deadline: u64,
) -> Result<(), ResourceInventoryError> {
    loop {
        check_deadline(deadline)?;
        match socket.send(bytes) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::OUT, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive(
    socket: &mut DescriptorSubjectSocket,
    maximum_bytes: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, ResourceInventoryError> {
    loop {
        check_deadline(deadline)?;
        match socket.receive(maximum_bytes, 0) {
            Ok(record) => return Ok(record),
            Err(SeqpacketError::WouldBlock) => wait(socket, PollFlags::IN, deadline)?,
            Err(SeqpacketError::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait(
    socket: &DescriptorSubjectSocket,
    events: PollFlags,
    deadline: u64,
) -> Result<(), ResourceInventoryError> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(ResourceInventoryError::Deadline)?;
    let timeout = rustix::event::Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)
            .map_err(|_| ResourceInventoryError::Deadline)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)
            .map_err(|_| ResourceInventoryError::Deadline)?,
    };
    let mut descriptors = [PollFd::from_borrowed_fd(socket.as_fd()?, events)];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(ResourceInventoryError::Deadline),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Descriptor, InventoryNetworkResourcesResponse,
        InventoryStorageResourcesResponse, NetworkNamespaceInventoryRecord, NetworkState,
        StorageWorkspaceInventoryRecord,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::JournalLimits;

    fn journal() -> (TempDir, Journal) {
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

    fn fence(handle: u8) -> AssignmentFence {
        AssignmentFence {
            sandbox_id: vec![handle; 16],
            incarnation_id: vec![handle + 1; 16],
            assignment_epoch: 2,
            desired_generation: 3,
            assignment_digest: vec![handle + 2; 32],
            ..Default::default()
        }
    }

    fn storage_response(
        request_handle: u8,
        boot: u8,
        instance: u8,
        journal_sequence: u64,
        catalog_generation: u64,
    ) -> Vec<u8> {
        InventoryStorageResourcesResponse {
            kernel_boot_id: vec![boot; 16],
            journal_sequence,
            catalog_generation,
            workspaces: vec![StorageWorkspaceInventoryRecord {
                workspace_handle: vec![request_handle; 32],
                fence: Some(fence(request_handle)).into(),
                root_image: Some(Descriptor {
                    media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                    sha256: vec![request_handle + 3; 32],
                    encoded_size: 4,
                    ..Default::default()
                })
                .into(),
                resource_kernel_boot_id: vec![boot; 16],
                root_device: u64::from(request_handle),
                root_inode: u64::from(request_handle) + 10,
                dataset_guid: u64::from(request_handle) + 20,
                uid_range_start: u32::from(request_handle) * 65_536,
                uid_range_size: 65_536,
                resource_digest: vec![request_handle + 4; 32],
                ..Default::default()
            }],
            broker_instance_id: vec![instance; 16],
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn network_response(
        request_handle: u8,
        boot: u8,
        instance: u8,
        journal_sequence: u64,
        catalog_generation: u64,
    ) -> Vec<u8> {
        InventoryNetworkResourcesResponse {
            kernel_boot_id: vec![boot; 16],
            journal_sequence,
            catalog_generation,
            networks: vec![NetworkNamespaceInventoryRecord {
                network_handle: vec![request_handle; 32],
                fence: Some(fence(request_handle)).into(),
                resource_kernel_boot_id: vec![boot; 16],
                namespace_device: u64::from(request_handle),
                namespace_inode: u64::from(request_handle) + 10,
                state: NetworkState::NETWORK_STATE_DEFAULT_DROP.into(),
                lease_generation: 0,
                fail_stop_boottime_nanoseconds: 0,
                resource_digest: vec![request_handle + 3; 32],
                ..Default::default()
            }],
            broker_instance_id: vec![instance; 16],
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn record(
        domain: InventoryDomain,
        request_id: u8,
        controller_state_digest: [u8; 32],
        response_body: Vec<u8>,
    ) -> (SnapshotRecord, ValidatedResourceInventory) {
        SnapshotRecord::from_query(
            domain,
            controller_state_digest,
            domain.request_body([request_id; 16], 2),
            response_body,
        )
        .unwrap()
    }

    #[test]
    fn records_round_trip_in_distinct_domains() {
        let (storage, storage_inventory) = record(
            InventoryDomain::Storage,
            1,
            [20; 32],
            storage_response(1, 9, 12, 10, 11),
        );
        let (network, network_inventory) = record(
            InventoryDomain::Network,
            2,
            [20; 32],
            network_response(1, 9, 13, 10, 11),
        );

        assert_eq!(SnapshotRecord::decode(&storage.encode()).unwrap(), storage);
        assert_eq!(SnapshotRecord::decode(&network.encode()).unwrap(), network);
        assert_eq!(storage_inventory.domain(), InventoryDomain::Storage);
        assert_eq!(network_inventory.domain(), InventoryDomain::Network);
    }

    #[test]
    fn record_codec_rejects_every_changed_or_truncated_byte() {
        let (record, _) = record(
            InventoryDomain::Storage,
            1,
            [20; 32],
            storage_response(1, 9, 12, 10, 11),
        );
        let encoded = record.encode();

        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(SnapshotRecord::decode(&changed).is_err(), "byte {index}");
        }
        for length in 0..encoded.len() {
            assert!(
                SnapshotRecord::decode(&encoded[..length]).is_err(),
                "length {length}"
            );
        }
    }

    #[test]
    fn storage_history_rejects_rollback_and_same_generation_mutation() {
        let (_directory, mut journal) = journal();
        let state = controller_state_digest(&mut journal).unwrap();
        let (current, current_inventory) = record(
            InventoryDomain::Storage,
            1,
            state,
            storage_response(1, 9, 12, 10, 11),
        );
        journal.commit(&current.transaction().unwrap()).unwrap();
        let history = SnapshotHistory::load(&mut journal, InventoryDomain::Storage).unwrap();

        let (rollback, rollback_inventory) = record(
            InventoryDomain::Storage,
            2,
            state,
            storage_response(1, 9, 13, 9, 10),
        );
        assert!(matches!(
            history.outcome(&rollback, &rollback_inventory),
            Err(ResourceInventoryError::Conflict)
        ));

        let (mutated, mutated_inventory) = record(
            InventoryDomain::Storage,
            3,
            state,
            storage_response(2, 9, 13, 11, 11),
        );
        assert!(matches!(
            history.outcome(&mutated, &mutated_inventory),
            Err(ResourceInventoryError::Conflict)
        ));
        assert_eq!(current_inventory.catalog_generation(), 11);
    }

    #[test]
    fn network_history_allows_restart_but_rejects_instance_crossing_boots() {
        let (_directory, mut journal) = journal();
        let state = controller_state_digest(&mut journal).unwrap();
        let (current, _) = record(
            InventoryDomain::Network,
            1,
            state,
            network_response(1, 9, 12, 10, 11),
        );
        journal.commit(&current.transaction().unwrap()).unwrap();
        let history = SnapshotHistory::load(&mut journal, InventoryDomain::Network).unwrap();

        let (restart, restart_inventory) = record(
            InventoryDomain::Network,
            2,
            state,
            network_response(1, 9, 13, 10, 11),
        );
        assert_eq!(history.outcome(&restart, &restart_inventory).unwrap(), None);

        let (cross_boot, cross_boot_inventory) = record(
            InventoryDomain::Network,
            3,
            state,
            network_response(1, 10, 12, 11, 12),
        );
        assert!(matches!(
            history.outcome(&cross_boot, &cross_boot_inventory),
            Err(ResourceInventoryError::Conflict)
        ));
    }

    #[test]
    fn request_reuse_and_cross_domain_storage_fail_closed() {
        let (_directory, mut journal) = journal();
        let state = controller_state_digest(&mut journal).unwrap();
        let (current, _) = record(
            InventoryDomain::Storage,
            1,
            state,
            storage_response(1, 9, 12, 10, 11),
        );
        journal.commit(&current.transaction().unwrap()).unwrap();
        let history = SnapshotHistory::load(&mut journal, InventoryDomain::Storage).unwrap();
        let (reused, reused_inventory) = record(
            InventoryDomain::Storage,
            1,
            state,
            storage_response(1, 9, 13, 11, 12),
        );
        assert!(matches!(
            history.outcome(&reused, &reused_inventory),
            Err(ResourceInventoryError::Conflict)
        ));

        let transaction = JournalTransaction::new(
            [30; 16],
            vec![JournalRecord::put(
                RecordNamespace::NetworkResourceInventory,
                KEY.to_vec(),
                current.encode(),
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        assert!(matches!(
            validate_namespaces(&mut journal),
            Err(ResourceInventoryError::CorruptState)
        ));
    }

    #[test]
    fn newer_durable_snapshot_invalidates_an_older_snapshot() {
        let (_directory, mut journal) = journal();
        let state = controller_state_digest(&mut journal).unwrap();
        let (first_record, first_inventory) = record(
            InventoryDomain::Storage,
            1,
            state,
            storage_response(1, 9, 12, 10, 11),
        );
        journal
            .commit(&first_record.transaction().unwrap())
            .unwrap();
        let ValidatedResourceInventory::Storage(first_inventory) = first_inventory else {
            panic!("expected Storage inventory")
        };
        let first = DurableStorageResourceInventorySnapshotV1 {
            record: first_record,
            inventory: first_inventory,
            outcome: ResourceInventorySnapshotOutcomeV1::Recorded,
        };
        first.recheck(&mut journal).unwrap();

        let (second, _) = record(
            InventoryDomain::Storage,
            2,
            state,
            storage_response(2, 9, 12, 11, 12),
        );
        journal.commit(&second.transaction().unwrap()).unwrap();

        assert!(matches!(
            first.recheck(&mut journal),
            Err(ResourceInventoryError::Conflict)
        ));
    }

    #[test]
    fn any_controller_state_change_invalidates_the_snapshot() {
        let (_directory, mut journal) = journal();
        let state = controller_state_digest(&mut journal).unwrap();
        let (record, inventory) = record(
            InventoryDomain::Network,
            1,
            state,
            network_response(1, 9, 12, 10, 11),
        );
        journal.commit(&record.transaction().unwrap()).unwrap();
        let ValidatedResourceInventory::Network(inventory) = inventory else {
            panic!("expected Network inventory")
        };
        let snapshot = DurableNetworkResourceInventorySnapshotV1 {
            record,
            inventory,
            outcome: ResourceInventorySnapshotOutcomeV1::Recorded,
        };
        snapshot.recheck(&mut journal).unwrap();

        journal
            .commit(
                &JournalTransaction::new(
                    [31; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        b"changed".to_vec(),
                        b"state".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(matches!(
            snapshot.recheck(&mut journal),
            Err(ResourceInventoryError::Conflict)
        ));
    }
}
