//! Protected Network namespace catalog and authoritative inventory producer.
//!
//! The catalog accepts only exact committed preparation results paired with
//! their retained portable assignments. Each current-boot publication is
//! checked against the fixed typed namespace pin before it enters a separate
//! append-only journal. Its canonical durable record format is:
//!
//! ```text
//! {"version":1,"record":{...}}
//! ```
//!
//! Rows from earlier Linux boots remain durable collision evidence but are not
//! current resources and therefore do not enter inventory. This initial
//! catalog publishes only default-drop namespaces; lease and retirement state
//! require later existing-resource effects and fresh typed observation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(test)]
use std::os::fd::AsFd as _;
use std::os::fd::OwnedFd;
#[cfg(test)]
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, InventoryNetworkResourcesResponse, NetworkNamespaceInventoryRecord,
    NetworkState,
};
use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::{BrokerAssignment, ObjectDigest};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::pidfd::NamespaceKind;
use aos_sandbox_protocol::{
    MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS, MAXIMUM_RESPONSE_BYTES,
    decode_network_resource_inventory_response,
};
use buffa::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{CommittedNetworkResultV1, NetworkCatalogBindingV1, ResolvedNetworkPreparationV1};

const NAMESPACE_JOURNAL_FILE: &str = "network-namespaces.journal";
const NAMESPACE_PIN_ROOT: &str = "/run/aos/sandbox-pins/netns";
const HEAD_KEY: &[u8] = b"aos.network.namespace.head.v1\0";
const RECORD_KEY_PREFIX: &[u8] = b"aos.network.namespace.v1\0";
const RECORD_FORMAT_VERSION: u16 = 1;
const RESOURCE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.namespace-resource.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.network.namespace-transaction.v1\0";
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024;

/// Reports protected namespace-catalog validation or publication failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkNamespaceCatalogError {
    /// The protected journal failed validation, locking, or publication.
    #[error("network namespace journal failure: {0}")]
    Journal(#[from] aos_sandbox::JournalError),
    /// Trusted inputs do not describe one exact current namespace.
    #[error("network namespace publication input is incomplete or inconsistent")]
    InvalidCandidate,
    /// Durable catalog bytes violate the closed record schema.
    #[error("network namespace catalog record is corrupt")]
    CorruptRecord,
    /// A retained request, assignment, handle, or physical identity conflicts.
    #[error("network namespace catalog identity conflicts with retained state")]
    IdentityConflict,
    /// The bounded namespace catalog has no remaining publication slots.
    #[error("network namespace catalog is exhausted")]
    ResourceExhausted,
    /// The fixed namespace pin is absent, redirected, mistyped, or replaced.
    #[error("network namespace pin validation failed: {0}")]
    NamespacePin(String),
    /// An internally encoded inventory violated its public wire contract.
    #[error("network namespace inventory encoding is invalid")]
    InvalidInventory,
}

/// Carries an exact committed default-drop namespace and portable assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkNamespacePublicationV1 {
    request_id: [u8; 16],
    preparation: NetworkCatalogBindingV1,
    network_handle: [u8; 32],
    assignment: BrokerAssignment,
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    result_digest: ObjectDigest,
}

impl NetworkNamespacePublicationV1 {
    pub(crate) fn from_committed(
        result: CommittedNetworkResultV1,
        resolution: &ResolvedNetworkPreparationV1,
        assignment: BrokerAssignment,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        if result.request_id() == [0; 16]
            || result.network_handle() != *resolution.reserved_network_handle()
            || result.preparation() != resolution.binding()
            || result.kernel_boot_id() == [0; 16]
            || result.namespace_device() == 0
            || result.namespace_inode() == 0
            || result.result_digest().as_bytes() == &[0; 32]
        {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }

        Ok(Self {
            request_id: result.request_id(),
            preparation: result.preparation(),
            network_handle: result.network_handle(),
            assignment,
            kernel_boot_id: result.kernel_boot_id(),
            namespace_device: result.namespace_device(),
            namespace_inode: result.namespace_inode(),
            result_digest: result.result_digest(),
        })
    }
}

/// Classifies publication of one exact committed namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkNamespaceCatalogOutcomeV1 {
    /// A new current default-drop namespace became authoritative.
    Published,
    /// The exact current publication was already durable.
    Replay,
}

/// Owns the durable namespace table and fixed namespace-pin resolution root.
pub struct NetworkNamespaceCatalogV1 {
    journal: Journal,
    pin_root: PinRoot,
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    generation: u64,
    records: BTreeMap<[u8; 32], NamespaceRecordV1>,
}

impl NetworkNamespaceCatalogV1 {
    /// Opens protected state and the fixed root-owned namespace pin root.
    ///
    /// Empty state receives a durable generation-one head. Every retained
    /// current-boot row must reproduce a live Network `nsfs` descriptor before
    /// the catalog becomes available.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError`] for unsafe filesystem state,
    /// journal failure, corrupt retained identity, or a missing, changed, or
    /// incorrectly typed current-boot pin.
    pub fn open_root_owned(state_directory: &Path) -> Result<Self, NetworkNamespaceCatalogError> {
        let (journal, _) = Journal::open_protected_at(
            state_directory,
            NAMESPACE_JOURNAL_FILE,
            namespace_journal_limits(),
        )?;
        let pin_root = PinRoot::open_kernel(Path::new(NAMESPACE_PIN_ROOT), 0)?;
        let kernel_boot_id = KernelBootId::current()
            .map_err(|error| NetworkNamespaceCatalogError::NamespacePin(error.to_string()))?
            .into_bytes();
        let broker_instance_id = broker_instance_id()?;

        Self::recover(journal, pin_root, kernel_boot_id, broker_instance_id)
    }

    #[cfg(test)]
    fn open_for_test(
        state_directory: &Path,
        pin_directory: &Path,
        kernel_boot_id: [u8; 16],
        broker_instance_id: [u8; 16],
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        let (journal, _) = Journal::open(
            state_directory.join(NAMESPACE_JOURNAL_FILE),
            namespace_journal_limits(),
        )?;
        let owner = fs::symlink_metadata(pin_directory)
            .map_err(|error| NetworkNamespaceCatalogError::NamespacePin(error.to_string()))?
            .uid();
        let pin_root = PinRoot::open_filesystem(pin_directory, owner)?;

        Self::recover(journal, pin_root, kernel_boot_id, broker_instance_id)
    }

    fn recover(
        mut journal: Journal,
        pin_root: PinRoot,
        kernel_boot_id: [u8; 16],
        broker_instance_id: [u8; 16],
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        if kernel_boot_id == [0; 16] || broker_instance_id == [0; 16] {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }

        let mut head = None;
        let mut records = BTreeMap::new();
        for (key, value) in journal.records(RecordNamespace::NetworkResourceInventory) {
            if key == HEAD_KEY {
                if head.replace(decode_head(value)?).is_some() {
                    return Err(NetworkNamespaceCatalogError::CorruptRecord);
                }
                continue;
            }

            let handle = decode_record_key(key)?;
            let record = decode_record(value)?;
            if record.network_handle != handle || records.insert(handle, record).is_some() {
                return Err(NetworkNamespaceCatalogError::CorruptRecord);
            }
        }

        let generation = match head {
            Some(head) => {
                let expected = records
                    .values()
                    .map(|record| record.catalog_generation)
                    .max()
                    .unwrap_or(1);
                if head.generation != expected {
                    return Err(NetworkNamespaceCatalogError::CorruptRecord);
                }
                head.generation
            }
            None if records.is_empty() => initialize_head(&mut journal)?,
            None => return Err(NetworkNamespaceCatalogError::CorruptRecord),
        };

        validate_record_set(&records)?;
        for record in records
            .values()
            .filter(|record| record.kernel_boot_id == kernel_boot_id)
        {
            pin_root.verify_record(record)?;
        }

        Ok(Self {
            journal,
            pin_root,
            kernel_boot_id,
            broker_instance_id,
            generation,
            records,
        })
    }

    /// Returns the current protected namespace-catalog generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Publishes an exact committed namespace after reopening its fixed pin.
    ///
    /// Only current-boot default-drop creation results are accepted. A stale
    /// committed result cannot refresh a row into a later boot; that requires a
    /// new typed observation from a future lifecycle helper.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError`] when the result is stale, its
    /// pin is missing, mistyped, or physically different, a retained identity
    /// conflicts, generation overflows, or durable publication fails.
    pub fn publish(
        &mut self,
        publication: NetworkNamespacePublicationV1,
    ) -> Result<NetworkNamespaceCatalogOutcomeV1, NetworkNamespaceCatalogError> {
        if publication.kernel_boot_id != self.kernel_boot_id {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }
        let pin = self.pin_root.observe(&publication.network_handle)?;
        if (pin.device, pin.inode) != (publication.namespace_device, publication.namespace_inode) {
            return Err(NetworkNamespaceCatalogError::NamespacePin(
                "pin device/inode identity disagrees with committed result".to_owned(),
            ));
        }

        if let Some(existing) = self.records.get(&publication.network_handle) {
            if existing.matches_publication(&publication) {
                return Ok(NetworkNamespaceCatalogOutcomeV1::Replay);
            }
            return Err(NetworkNamespaceCatalogError::IdentityConflict);
        }

        let assignment = AssignmentWire::from(publication.assignment);
        if self.records.values().any(|record| {
            record.request_id == publication.request_id
                || record.assignment.assignment_pair() == assignment.assignment_pair()
                || (record.kernel_boot_id == self.kernel_boot_id
                    && (record.namespace_device, record.namespace_inode) == (pin.device, pin.inode))
        }) {
            return Err(NetworkNamespaceCatalogError::IdentityConflict);
        }
        if self.records.len() >= MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS {
            return Err(NetworkNamespaceCatalogError::ResourceExhausted);
        }

        let catalog_generation = next_generation(self.generation)?;
        let mut record = NamespaceRecordV1 {
            catalog_generation,
            request_id: publication.request_id,
            preparation: CatalogBindingWire::from(publication.preparation),
            result_digest: *publication.result_digest.as_bytes(),
            network_handle: publication.network_handle,
            assignment,
            kernel_boot_id: publication.kernel_boot_id,
            namespace_device: publication.namespace_device,
            namespace_inode: publication.namespace_inode,
            lifecycle: NamespaceLifecycleV1::DefaultDrop,
            lease_generation: 0,
            fail_stop_boottime_nanoseconds: 0,
            resource_digest: [0; 32],
        };
        record.refresh_digest()?;
        record.validate()?;
        self.commit(record)?;

        Ok(NetworkNamespaceCatalogOutcomeV1::Published)
    }

    /// Encodes one complete, current-boot, physically revalidated inventory.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError`] when retained state conflicts,
    /// a current pin changed or is no longer a Network namespace, or the
    /// encoded protobuf violates the bounded authoritative-inventory contract.
    pub fn inventory_resources(&self) -> Result<Vec<u8>, NetworkNamespaceCatalogError> {
        validate_record_set(&self.records)?;
        let mut networks = Vec::new();
        for record in self
            .records
            .values()
            .filter(|record| record.kernel_boot_id == self.kernel_boot_id)
        {
            self.pin_root.verify_record(record)?;
            networks.push(record.inventory_record());
        }

        let response = InventoryNetworkResourcesResponse {
            kernel_boot_id: self.kernel_boot_id.to_vec(),
            journal_sequence: self.journal.snapshot_sequence(),
            catalog_generation: self.generation,
            networks,
            broker_instance_id: self.broker_instance_id.to_vec(),
            ..Default::default()
        };
        let bytes = response.encode_to_vec();
        decode_network_resource_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES)
            .map_err(|_| NetworkNamespaceCatalogError::InvalidInventory)?;

        Ok(bytes)
    }

    fn commit(&mut self, record: NamespaceRecordV1) -> Result<(), NetworkNamespaceCatalogError> {
        let head = CatalogHeadV1 {
            generation: record.catalog_generation,
        };
        let transaction = JournalTransaction::new(
            transaction_id(record.request_id, record.catalog_generation),
            vec![
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    HEAD_KEY.to_vec(),
                    encode_head(&head)?,
                ),
                JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    record_key(&record.network_handle),
                    encode_record(&record)?,
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.generation = record.catalog_generation;
        self.records.insert(record.network_handle, record);

        Ok(())
    }
}

enum PinRoot {
    Kernel(BeneathRoot),
    #[cfg(test)]
    Filesystem {
        descriptor: OwnedFd,
        expected_owner: u32,
    },
}

#[derive(Clone, Copy)]
struct PinIdentity {
    device: u64,
    inode: u64,
}

impl PinRoot {
    fn open_kernel(path: &Path, expected_owner: u32) -> Result<Self, NetworkNamespaceCatalogError> {
        let descriptor = open_pin_root(path, expected_owner)?;
        let root = BeneathRoot::from_owned(descriptor)
            .map_err(|error| NetworkNamespaceCatalogError::NamespacePin(error.to_string()))?;
        Ok(Self::Kernel(root))
    }

    #[cfg(test)]
    fn open_filesystem(
        path: &Path,
        expected_owner: u32,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        let descriptor = open_pin_root(path, expected_owner)?;
        Ok(Self::Filesystem {
            descriptor,
            expected_owner,
        })
    }

    fn observe(&self, handle: &[u8; 32]) -> Result<PinIdentity, NetworkNamespaceCatalogError> {
        let component = encode_hex(handle);
        match self {
            Self::Kernel(root) => {
                let namespace = root
                    .open_namespace(Path::new(&component), NamespaceKind::Network)
                    .map_err(|error| {
                        NetworkNamespaceCatalogError::NamespacePin(error.to_string())
                    })?;
                let identity = namespace.identity();
                if identity.device == 0 || identity.inode == 0 {
                    return Err(NetworkNamespaceCatalogError::NamespacePin(
                        "namespace pin has a reserved physical identity".to_owned(),
                    ));
                }
                Ok(PinIdentity {
                    device: identity.device,
                    inode: identity.inode,
                })
            }
            #[cfg(test)]
            Self::Filesystem {
                descriptor,
                expected_owner,
            } => {
                let pin = rustix::fs::openat(
                    descriptor.as_fd(),
                    component,
                    rustix::fs::OFlags::PATH
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(pin_error)?;
                let metadata = rustix::fs::fstat(&pin).map_err(pin_error)?;
                if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                    != rustix::fs::FileType::RegularFile
                    || metadata.st_uid != *expected_owner
                    || metadata.st_mode & 0o022 != 0
                    || metadata.st_dev == 0
                    || metadata.st_ino == 0
                {
                    return Err(NetworkNamespaceCatalogError::NamespacePin(
                        "test pin is not the required owned regular file".to_owned(),
                    ));
                }
                Ok(PinIdentity {
                    device: metadata.st_dev,
                    inode: metadata.st_ino,
                })
            }
        }
    }

    fn verify_record(
        &self,
        record: &NamespaceRecordV1,
    ) -> Result<(), NetworkNamespaceCatalogError> {
        let pin = self.observe(&record.network_handle)?;
        if (pin.device, pin.inode) != (record.namespace_device, record.namespace_inode) {
            return Err(NetworkNamespaceCatalogError::NamespacePin(
                "namespace pin device/inode identity changed".to_owned(),
            ));
        }
        Ok(())
    }
}

fn open_pin_root(
    path: &Path,
    expected_owner: u32,
) -> Result<OwnedFd, NetworkNamespaceCatalogError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(pin_error)?;
    let metadata = rustix::fs::fstat(&descriptor).map_err(pin_error)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
        || metadata.st_uid != expected_owner
        || metadata.st_mode & 0o022 != 0
    {
        return Err(NetworkNamespaceCatalogError::NamespacePin(
            "pin root is not an owner-controlled real directory".to_owned(),
        ));
    }
    Ok(descriptor)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogHeadV1 {
    generation: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogBindingWire {
    generation: u64,
    digest: [u8; 32],
}

impl CatalogBindingWire {
    fn validate(self) -> Result<(), NetworkNamespaceCatalogError> {
        if self.generation == 0 || self.digest == [0; 32] {
            Err(NetworkNamespaceCatalogError::CorruptRecord)
        } else {
            Ok(())
        }
    }
}

impl From<NetworkCatalogBindingV1> for CatalogBindingWire {
    fn from(value: NetworkCatalogBindingV1) -> Self {
        Self {
            generation: value.generation(),
            digest: *value.digest().as_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AssignmentWire {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

impl AssignmentWire {
    const fn assignment_pair(self) -> ([u8; 16], [u8; 16]) {
        (self.sandbox_id, self.incarnation_id)
    }

    fn validate(self) -> Result<(), NetworkNamespaceCatalogError> {
        if self.sandbox_id == [0; 16]
            || self.incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
        {
            Err(NetworkNamespaceCatalogError::CorruptRecord)
        } else {
            Ok(())
        }
    }

    fn proto(self) -> AssignmentFence {
        AssignmentFence {
            sandbox_id: self.sandbox_id.to_vec(),
            incarnation_id: self.incarnation_id.to_vec(),
            assignment_epoch: self.assignment_epoch,
            desired_generation: self.desired_generation,
            assignment_digest: self.assignment_digest.to_vec(),
            ..Default::default()
        }
    }
}

impl From<BrokerAssignment> for AssignmentWire {
    fn from(value: BrokerAssignment) -> Self {
        Self {
            sandbox_id: *value.sandbox().as_bytes(),
            incarnation_id: *value.incarnation().as_bytes(),
            assignment_epoch: value.epoch().get(),
            desired_generation: value.desired_generation().get(),
            assignment_digest: *value.digest().as_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NamespaceLifecycleV1 {
    DefaultDrop,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamespaceRecordV1 {
    catalog_generation: u64,
    request_id: [u8; 16],
    preparation: CatalogBindingWire,
    result_digest: [u8; 32],
    network_handle: [u8; 32],
    assignment: AssignmentWire,
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    lifecycle: NamespaceLifecycleV1,
    lease_generation: u64,
    fail_stop_boottime_nanoseconds: u64,
    resource_digest: [u8; 32],
}

impl NamespaceRecordV1 {
    fn validate(&self) -> Result<(), NetworkNamespaceCatalogError> {
        if self.catalog_generation < 2
            || self.request_id == [0; 16]
            || self.result_digest == [0; 32]
            || self.network_handle == [0; 32]
            || self.kernel_boot_id == [0; 16]
            || self.namespace_device == 0
            || self.namespace_inode == 0
            || self.lease_generation != 0
            || self.fail_stop_boottime_nanoseconds != 0
            || self.resource_digest == [0; 32]
        {
            return Err(NetworkNamespaceCatalogError::CorruptRecord);
        }
        self.preparation.validate()?;
        self.assignment.validate()?;
        if self.compute_digest()? != self.resource_digest {
            return Err(NetworkNamespaceCatalogError::CorruptRecord);
        }
        Ok(())
    }

    fn refresh_digest(&mut self) -> Result<(), NetworkNamespaceCatalogError> {
        self.resource_digest = [0; 32];
        self.resource_digest = self.compute_digest()?;
        Ok(())
    }

    fn compute_digest(&self) -> Result<[u8; 32], NetworkNamespaceCatalogError> {
        let mut preimage = self.clone();
        preimage.resource_digest = [0; 32];
        let bytes = serde_json::to_vec(&preimage)
            .map_err(|_| NetworkNamespaceCatalogError::CorruptRecord)?;
        let mut digest = Sha256::new();
        digest.update(RESOURCE_DIGEST_DOMAIN);
        digest.update(bytes);
        Ok(digest.finalize().into())
    }

    fn matches_publication(&self, publication: &NetworkNamespacePublicationV1) -> bool {
        self.request_id == publication.request_id
            && self.preparation == CatalogBindingWire::from(publication.preparation)
            && self.result_digest == *publication.result_digest.as_bytes()
            && self.network_handle == publication.network_handle
            && self.assignment == AssignmentWire::from(publication.assignment)
            && self.kernel_boot_id == publication.kernel_boot_id
            && self.namespace_device == publication.namespace_device
            && self.namespace_inode == publication.namespace_inode
            && matches!(self.lifecycle, NamespaceLifecycleV1::DefaultDrop)
            && self.lease_generation == 0
            && self.fail_stop_boottime_nanoseconds == 0
    }

    fn inventory_record(&self) -> NetworkNamespaceInventoryRecord {
        NetworkNamespaceInventoryRecord {
            network_handle: self.network_handle.to_vec(),
            fence: Some(self.assignment.proto()).into(),
            resource_kernel_boot_id: self.kernel_boot_id.to_vec(),
            namespace_device: self.namespace_device,
            namespace_inode: self.namespace_inode,
            state: NetworkState::NETWORK_STATE_DEFAULT_DROP.into(),
            lease_generation: self.lease_generation,
            fail_stop_boottime_nanoseconds: self.fail_stop_boottime_nanoseconds,
            resource_digest: self.resource_digest.to_vec(),
            ..Default::default()
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeadEnvelopeV1 {
    version: u16,
    head: CatalogHeadV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordEnvelopeV1 {
    version: u16,
    record: NamespaceRecordV1,
}

fn initialize_head(journal: &mut Journal) -> Result<u64, NetworkNamespaceCatalogError> {
    let head = CatalogHeadV1 { generation: 1 };
    let transaction = JournalTransaction::new(
        genesis_transaction_id(),
        vec![JournalRecord::put(
            RecordNamespace::NetworkResourceInventory,
            HEAD_KEY.to_vec(),
            encode_head(&head)?,
        )],
    )?;
    journal.commit(&transaction)?;
    Ok(head.generation)
}

fn encode_head(head: &CatalogHeadV1) -> Result<Vec<u8>, NetworkNamespaceCatalogError> {
    serde_json::to_vec(&HeadEnvelopeV1 {
        version: RECORD_FORMAT_VERSION,
        head: head.clone(),
    })
    .map_err(|_| NetworkNamespaceCatalogError::CorruptRecord)
}

fn decode_head(bytes: &[u8]) -> Result<CatalogHeadV1, NetworkNamespaceCatalogError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkNamespaceCatalogError::CorruptRecord);
    }
    let envelope: HeadEnvelopeV1 =
        serde_json::from_slice(bytes).map_err(|_| NetworkNamespaceCatalogError::CorruptRecord)?;
    if envelope.version != RECORD_FORMAT_VERSION || encode_head(&envelope.head)? != bytes {
        return Err(NetworkNamespaceCatalogError::CorruptRecord);
    }
    Ok(envelope.head)
}

fn encode_record(record: &NamespaceRecordV1) -> Result<Vec<u8>, NetworkNamespaceCatalogError> {
    let bytes = serde_json::to_vec(&RecordEnvelopeV1 {
        version: RECORD_FORMAT_VERSION,
        record: record.clone(),
    })
    .map_err(|_| NetworkNamespaceCatalogError::CorruptRecord)?;
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkNamespaceCatalogError::CorruptRecord);
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<NamespaceRecordV1, NetworkNamespaceCatalogError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkNamespaceCatalogError::CorruptRecord);
    }
    let envelope: RecordEnvelopeV1 =
        serde_json::from_slice(bytes).map_err(|_| NetworkNamespaceCatalogError::CorruptRecord)?;
    if envelope.version != RECORD_FORMAT_VERSION || encode_record(&envelope.record)? != bytes {
        return Err(NetworkNamespaceCatalogError::CorruptRecord);
    }
    envelope.record.validate()?;
    Ok(envelope.record)
}

fn validate_record_set(
    records: &BTreeMap<[u8; 32], NamespaceRecordV1>,
) -> Result<(), NetworkNamespaceCatalogError> {
    if records.len() > MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS {
        return Err(NetworkNamespaceCatalogError::CorruptRecord);
    }

    let mut requests = BTreeSet::new();
    let mut assignments = BTreeSet::new();
    let mut physical_namespaces = BTreeSet::new();
    for (handle, record) in records {
        record.validate()?;
        if handle != &record.network_handle
            || !requests.insert(record.request_id)
            || !assignments.insert(record.assignment.assignment_pair())
            || !physical_namespaces.insert((
                record.kernel_boot_id,
                record.namespace_device,
                record.namespace_inode,
            ))
        {
            return Err(NetworkNamespaceCatalogError::IdentityConflict);
        }
    }
    Ok(())
}

fn record_key(handle: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(RECORD_KEY_PREFIX.len() + handle.len());
    key.extend_from_slice(RECORD_KEY_PREFIX);
    key.extend_from_slice(handle);
    key
}

fn decode_record_key(key: &[u8]) -> Result<[u8; 32], NetworkNamespaceCatalogError> {
    key.strip_prefix(RECORD_KEY_PREFIX)
        .and_then(|bytes| bytes.try_into().ok())
        .filter(|handle: &[u8; 32]| *handle != [0; 32])
        .ok_or(NetworkNamespaceCatalogError::CorruptRecord)
}

fn next_generation(generation: u64) -> Result<u64, NetworkNamespaceCatalogError> {
    generation
        .checked_add(1)
        .ok_or(NetworkNamespaceCatalogError::CorruptRecord)
}

fn transaction_id(request_id: [u8; 16], generation: u64) -> [u8; 16] {
    transaction_digest(&[&request_id, &generation.to_be_bytes()])
}

fn genesis_transaction_id() -> [u8; 16] {
    transaction_digest(&[b"genesis"])
}

fn transaction_digest(parts: &[&[u8]]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    for part in parts {
        digest.update(part);
    }
    let digest: [u8; 32] = digest.finalize().into();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    transaction_id
}

fn broker_instance_id() -> Result<[u8; 16], NetworkNamespaceCatalogError> {
    let bytes = fs::read("/proc/sys/kernel/random/uuid")
        .map_err(|error| NetworkNamespaceCatalogError::NamespacePin(error.to_string()))?;
    KernelBootId::parse(&bytes)
        .map(KernelBootId::into_bytes)
        .map_err(|error| NetworkNamespaceCatalogError::NamespacePin(error.to_string()))
}

fn pin_error(error: rustix::io::Errno) -> NetworkNamespaceCatalogError {
    NetworkNamespaceCatalogError::NamespacePin(error.to_string())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

const fn namespace_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 512 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_RECORD_BYTES,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: MAXIMUM_RECORD_BYTES * 2,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_RECORD_BYTES
            * (MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS + 1),
        maximum_materialized_records: MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS + 1,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::PathBuf;

    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};
    use aos_sandbox_protocol::ValidatedNetworkInventory;
    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        _directory: TempDir,
        state_directory: PathBuf,
        pin_directory: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = TempDir::new().unwrap();
            let state_directory = directory.path().join("state");
            let pin_directory = directory.path().join("pins");
            fs::create_dir(&state_directory).unwrap();
            fs::create_dir(&pin_directory).unwrap();
            Self {
                _directory: directory,
                state_directory,
                pin_directory,
            }
        }

        fn open(
            &self,
            kernel_boot_id: [u8; 16],
        ) -> Result<NetworkNamespaceCatalogV1, NetworkNamespaceCatalogError> {
            NetworkNamespaceCatalogV1::open_for_test(
                &self.state_directory,
                &self.pin_directory,
                kernel_boot_id,
                [91; 16],
            )
        }

        fn pin_path(&self, handle: u8) -> PathBuf {
            self.pin_directory.join(encode_hex(&[handle; 32]))
        }

        fn create_pin(&self, handle: u8) {
            fs::File::create(self.pin_path(handle)).unwrap();
        }

        fn publication(
            &self,
            handle: u8,
            assignment_marker: u8,
            kernel_boot_id: [u8; 16],
        ) -> NetworkNamespacePublicationV1 {
            let metadata = fs::metadata(self.pin_path(handle)).unwrap();
            NetworkNamespacePublicationV1 {
                request_id: [handle.wrapping_add(10); 16],
                preparation: ResolvedNetworkPreparationV1::new(
                    u64::from(handle) + 10,
                    [handle; 32],
                    ObjectDigest::from_bytes([handle.wrapping_add(20); 32]),
                    Vec::new(),
                )
                .unwrap()
                .binding(),
                network_handle: [handle; 32],
                assignment: assignment(assignment_marker),
                kernel_boot_id,
                namespace_device: metadata.dev(),
                namespace_inode: metadata.ino(),
                result_digest: ObjectDigest::from_bytes([handle.wrapping_add(30); 32]),
            }
        }
    }

    fn assignment(marker: u8) -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([marker; 16]),
            IncarnationId::from_bytes([marker.wrapping_add(1); 16]),
            AssignmentEpoch::new(u64::from(marker) + 1),
            DesiredGeneration::new(u64::from(marker) + 2),
            ObjectDigest::from_bytes([marker.wrapping_add(2); 32]),
        )
        .unwrap()
    }

    fn inventory(catalog: &NetworkNamespaceCatalogV1) -> ValidatedNetworkInventory {
        decode_network_resource_inventory_response(
            &catalog.inventory_resources().unwrap(),
            MAXIMUM_RESPONSE_BYTES,
        )
        .unwrap()
    }

    #[test]
    fn initializes_publishes_replays_and_recovers_exact_inventory() {
        let fixture = Fixture::new();
        fixture.create_pin(1);
        let mut catalog = fixture.open([81; 16]).unwrap();
        let publication = fixture.publication(1, 1, [81; 16]);

        assert_eq!(catalog.generation(), 1);
        assert!(inventory(&catalog).networks().is_empty());
        assert_eq!(
            catalog.publish(publication).unwrap(),
            NetworkNamespaceCatalogOutcomeV1::Published
        );
        assert_eq!(
            catalog.publish(publication).unwrap(),
            NetworkNamespaceCatalogOutcomeV1::Replay
        );

        let snapshot = inventory(&catalog);
        assert_eq!(snapshot.kernel_boot_id(), &[81; 16]);
        assert_eq!(snapshot.broker_instance_id(), &[91; 16]);
        assert_eq!(snapshot.catalog_generation(), 2);
        assert_eq!(snapshot.networks().len(), 1);
        let network = &snapshot.networks()[0];
        assert_eq!(network.network_handle(), &[1; 32]);
        assert_eq!(network.fence().sandbox_id(), &[1; 16]);
        assert_eq!(
            network.namespace_path(),
            format!("{NAMESPACE_PIN_ROOT}/{}", encode_hex(&[1; 32]))
        );
        assert_eq!(network.state(), NetworkState::NETWORK_STATE_DEFAULT_DROP);
        assert_eq!(network.lease_generation(), 0);

        let mut substituted = publication;
        substituted.result_digest = ObjectDigest::from_bytes([99; 32]);
        assert!(matches!(
            catalog.publish(substituted),
            Err(NetworkNamespaceCatalogError::IdentityConflict)
        ));

        drop(catalog);
        let recovered = fixture.open([81; 16]).unwrap();
        assert_eq!(inventory(&recovered), snapshot);
    }

    #[test]
    fn stale_boot_rows_are_retained_but_omitted_without_refresh() {
        let fixture = Fixture::new();
        fixture.create_pin(1);
        let mut catalog = fixture.open([81; 16]).unwrap();
        catalog
            .publish(fixture.publication(1, 1, [81; 16]))
            .unwrap();
        drop(catalog);

        fs::remove_file(fixture.pin_path(1)).unwrap();
        let mut current_boot = fixture.open([82; 16]).unwrap();
        assert_eq!(current_boot.generation(), 2);
        assert!(inventory(&current_boot).networks().is_empty());

        fixture.create_pin(1);
        assert!(matches!(
            current_boot.publish(fixture.publication(1, 1, [81; 16])),
            Err(NetworkNamespaceCatalogError::InvalidCandidate)
        ));
    }

    #[test]
    fn changed_pin_and_committed_identity_mismatch_fail_closed() {
        let fixture = Fixture::new();
        fixture.create_pin(1);
        let mut catalog = fixture.open([81; 16]).unwrap();
        let publication = fixture.publication(1, 1, [81; 16]);
        catalog.publish(publication).unwrap();

        let original = fixture.pin_directory.join("original-pin");
        fs::rename(fixture.pin_path(1), original).unwrap();
        fixture.create_pin(1);
        assert!(matches!(
            catalog.inventory_resources(),
            Err(NetworkNamespaceCatalogError::NamespacePin(_))
        ));
        drop(catalog);
        assert!(matches!(
            fixture.open([81; 16]),
            Err(NetworkNamespaceCatalogError::NamespacePin(_))
        ));

        let second = Fixture::new();
        second.create_pin(2);
        let mut catalog = second.open([81; 16]).unwrap();
        let mut mismatched = second.publication(2, 2, [81; 16]);
        mismatched.namespace_inode = mismatched.namespace_inode.wrapping_add(1);
        assert!(matches!(
            catalog.publish(mismatched),
            Err(NetworkNamespaceCatalogError::NamespacePin(_))
        ));
    }

    #[test]
    fn retained_assignment_and_physical_identity_cannot_be_rebound() {
        let fixture = Fixture::new();
        fixture.create_pin(1);
        fs::hard_link(fixture.pin_path(1), fixture.pin_path(2)).unwrap();
        fixture.create_pin(3);
        let mut catalog = fixture.open([81; 16]).unwrap();
        catalog
            .publish(fixture.publication(1, 1, [81; 16]))
            .unwrap();

        assert!(matches!(
            catalog.publish(fixture.publication(2, 2, [81; 16])),
            Err(NetworkNamespaceCatalogError::IdentityConflict)
        ));
        assert!(matches!(
            catalog.publish(fixture.publication(3, 1, [81; 16])),
            Err(NetworkNamespaceCatalogError::IdentityConflict)
        ));
    }

    #[test]
    fn production_pin_observer_rejects_an_ordinary_file() {
        let fixture = Fixture::new();
        fixture.create_pin(1);
        let owner = fs::symlink_metadata(&fixture.pin_directory).unwrap().uid();
        let root = PinRoot::open_kernel(&fixture.pin_directory, owner).unwrap();

        assert!(matches!(
            root.observe(&[1; 32]),
            Err(NetworkNamespaceCatalogError::NamespacePin(_))
        ));
    }

    #[test]
    fn catalog_head_and_pin_root_protection_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        let (mut journal, _) = Journal::open(
            fixture.state_directory.join(NAMESPACE_JOURNAL_FILE),
            namespace_journal_limits(),
        )
        .unwrap();
        let head = CatalogHeadV1 { generation: 2 };
        let transaction = JournalTransaction::new(
            [71; 16],
            vec![JournalRecord::put(
                RecordNamespace::NetworkResourceInventory,
                HEAD_KEY.to_vec(),
                encode_head(&head).unwrap(),
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        drop(journal);

        assert!(matches!(
            fixture.open([81; 16]),
            Err(NetworkNamespaceCatalogError::CorruptRecord)
        ));

        let unsafe_root = Fixture::new();
        fs::set_permissions(
            &unsafe_root.pin_directory,
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(matches!(
            unsafe_root.open([81; 16]),
            Err(NetworkNamespaceCatalogError::NamespacePin(_))
        ));
    }
}
