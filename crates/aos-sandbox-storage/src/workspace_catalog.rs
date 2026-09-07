//! Protected Storage workspace catalog and authoritative inventory producer.
//!
//! The catalog owns a separate append-only journal and resolves every live
//! workspace through a root-owned pin directory. Its durable record format is
//! canonical versioned JSON:
//!
//! ```text
//! {"version":1,"record":{...}}
//! ```
//!
//! A catalog head fixes the trusted subordinate-identity pool and advances by
//! one for each publication or retirement. Workspace records retain creation
//! and retirement correlations permanently, so opaque handles, dataset GUIDs,
//! assignment incarnations, and identity ranges cannot be recycled through a
//! restart. Inventory includes only active records from the current Linux boot
//! whose fixed handle-derived root pin still has the committed device/inode
//! identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::fd::{AsFd as _, OwnedFd};
#[cfg(test)]
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Descriptor, InventoryStorageResourcesResponse, StorageWorkspaceInventoryRecord,
};
use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::model::{IdentityProfile, SandboxSpec};
use aos_sandbox_core::{
    BrokerAssignment, CanonicalAssignmentManifestV1, DescriptorRole, MediaType, NodeId,
    ObjectDescriptor, ObjectDigest, PortableMediaType, descriptor_for_bytes, encode_sandbox_spec,
    validate_descriptor_role,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::{
    MAXIMUM_RESPONSE_BYTES, MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS,
    MINIMUM_HOST_IDENTITY_RANGE, decode_storage_resource_inventory_response,
};
use buffa::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CatalogBindingV1, CatalogPlanV1, CommittedStorageResultV1, ResolvedCatalogCommitmentV1,
};

const WORKSPACE_JOURNAL_FILE: &str = "storage-workspaces.journal";
const WORKSPACE_PIN_ROOT: &str = "/run/aos/sandbox-pins/workspaces";
const HEAD_KEY: &[u8] = b"aos.storage.workspace.head.v1\0";
const RECORD_KEY_PREFIX: &[u8] = b"aos.storage.workspace.v1\0";
const RECORD_FORMAT_VERSION: u16 = 1;
const RESOURCE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-resource.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-transaction.v1\0";
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024;

/// Reports protected workspace-catalog validation or publication failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageWorkspaceCatalogError {
    /// The protected journal failed validation, locking, or publication.
    #[error("storage workspace journal failure: {0}")]
    Journal(#[from] aos_sandbox::JournalError),
    /// Trusted inputs do not describe one complete workspace publication.
    #[error("storage workspace publication input is incomplete or inconsistent")]
    InvalidCandidate,
    /// Durable catalog bytes violate the closed record schema.
    #[error("storage workspace catalog record is corrupt")]
    CorruptRecord,
    /// A retained identity would be rebound, overlapped, or equivocated.
    #[error("storage workspace catalog identity conflicts with retained state")]
    IdentityConflict,
    /// The configured subordinate-identity pool has no suitable unused range.
    #[error("storage workspace subordinate-identity pool is exhausted")]
    IdentityExhausted,
    /// The fixed workspace pin is absent, redirected, or has changed identity.
    #[error("storage workspace pin validation failed: {0}")]
    RootPin(String),
    /// An internally encoded inventory exceeded or violated its wire contract.
    #[error("storage workspace inventory encoding is invalid")]
    InvalidInventory,
}

/// Defines the trusted host subordinate-identity allocation envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageIdentityPoolV1 {
    range_start: u32,
    range_size: u32,
}

impl StorageIdentityPoolV1 {
    /// Constructs a finite allocation envelope outside the host system range.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError::InvalidCandidate`] when the
    /// start or size is below the minimum private-userns range, or the end
    /// cannot be represented by the inventory protocol.
    pub fn new(range_start: u32, range_size: u32) -> Result<Self, StorageWorkspaceCatalogError> {
        if range_start < MINIMUM_HOST_IDENTITY_RANGE
            || range_size < MINIMUM_HOST_IDENTITY_RANGE
            || range_start.checked_add(range_size).is_none()
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        Ok(Self {
            range_start,
            range_size,
        })
    }

    /// Returns the first allocatable host identity.
    #[must_use]
    pub const fn range_start(self) -> u32 {
        self.range_start
    }

    /// Returns the total number of allocatable identities.
    #[must_use]
    pub const fn range_size(self) -> u32 {
        self.range_size
    }

    fn end(self) -> Result<u32, StorageWorkspaceCatalogError> {
        self.range_start
            .checked_add(self.range_size)
            .ok_or(StorageWorkspaceCatalogError::InvalidCandidate)
    }
}

/// Carries a creation result bound to its authenticated portable assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageWorkspacePublicationV1 {
    operation_id: [u8; 16],
    request_catalog: CatalogBindingV1,
    result_catalog: CatalogBindingV1,
    result_digest: ObjectDigest,
    workspace_handle: [u8; 32],
    dataset_guid: u64,
    assignment: BrokerAssignment,
    root_image: ObjectDescriptor,
    identity_range_size: u32,
}

impl StorageWorkspacePublicationV1 {
    pub(crate) fn from_committed(
        result: CommittedStorageResultV1,
        request_catalog: &ResolvedCatalogCommitmentV1,
        assignment: BrokerAssignment,
        node: NodeId,
        manifest: &CanonicalAssignmentManifestV1,
        sandbox_spec: &SandboxSpec,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let workspace_handle = result
            .storage_handle()
            .ok_or(StorageWorkspaceCatalogError::InvalidCandidate)?;
        let dataset_guid = result
            .object_guid()
            .filter(|guid| *guid != 0)
            .ok_or(StorageWorkspaceCatalogError::InvalidCandidate)?;
        if result.immutable_version_handle().is_some()
            || !matches!(
                request_catalog.plan(),
                CatalogPlanV1::CreateWorkspace { .. } | CatalogPlanV1::Clone { .. }
            )
            || result.catalog().generation() <= request_catalog.generation()
            || manifest
                .broker_assignment()
                .map_err(|_| StorageWorkspaceCatalogError::InvalidCandidate)?
                != assignment
            || manifest.manifest().node() != node
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }

        let encoded_specification = encode_sandbox_spec(sandbox_spec);
        let specification_media_type =
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned())
                .map_err(|_| StorageWorkspaceCatalogError::InvalidCandidate)?;
        let specification_descriptor =
            descriptor_for_bytes(specification_media_type, &encoded_specification);
        let manifest = manifest.manifest();
        if &specification_descriptor != manifest.sandbox_spec()
            || sandbox_spec.root_view() != manifest.root_view()
            || sandbox_spec.environment() != manifest.environment()
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        validate_root_image(manifest.root_view())?;
        let IdentityProfile::PrivateUserns { id_range_size, .. } = sandbox_spec.identity_profile()
        else {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        };
        let identity_range_size = id_range_size.get();
        if identity_range_size < MINIMUM_HOST_IDENTITY_RANGE {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }

        Ok(Self {
            operation_id: result.operation_id(),
            request_catalog: request_catalog.binding(),
            result_catalog: result.catalog(),
            result_digest: result.result_digest(),
            workspace_handle,
            dataset_guid,
            assignment,
            root_image: manifest.root_view().clone(),
            identity_range_size,
        })
    }
}

/// Carries an exact committed dataset destruction into catalog retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageWorkspaceRetirementV1 {
    operation_id: [u8; 16],
    request_catalog: CatalogBindingV1,
    result_catalog: CatalogBindingV1,
    result_digest: ObjectDigest,
    workspace_handle: [u8; 32],
    dataset_guid: u64,
}

impl StorageWorkspaceRetirementV1 {
    pub(crate) fn from_committed(
        result: CommittedStorageResultV1,
        request_catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let CatalogPlanV1::DestroyDataset { dataset } = request_catalog.plan() else {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        };
        if result.storage_handle() != Some(dataset.storage_handle())
            || result.immutable_version_handle().is_some()
            || result.object_guid().is_some()
            || result.catalog().generation() <= request_catalog.generation()
        {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        Ok(Self {
            operation_id: result.operation_id(),
            request_catalog: request_catalog.binding(),
            result_catalog: result.catalog(),
            result_digest: result.result_digest(),
            workspace_handle: dataset.storage_handle(),
            dataset_guid: dataset.guid(),
        })
    }
}

/// Reports the durable effect of one exact catalog request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageWorkspaceCatalogOutcomeV1 {
    /// A new launchable workspace row became current.
    Published,
    /// An exact active workspace acquired a verified pin for a later boot.
    Refreshed,
    /// A live row became a permanent non-inventory tombstone.
    Retired,
    /// The exact requested state was already durable.
    Replay,
}

/// Owns the durable workspace table and its fixed root-pin resolution root.
pub struct StorageWorkspaceCatalogV1 {
    journal: Journal,
    pin_root: PinRoot,
    identity_pool: StorageIdentityPoolV1,
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    generation: u64,
    records: BTreeMap<[u8; 32], WorkspaceRecordV1>,
}

impl StorageWorkspaceCatalogV1 {
    /// Opens protected catalog state and the fixed root-owned workspace pin root.
    ///
    /// Empty state is initialized with a durable generation-one head that fixes
    /// `identity_pool`. Existing current-boot rows must reproduce every pinned
    /// directory identity before the catalog becomes available.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] for an unsafe directory,
    /// journal failure, changed pool configuration, corrupt retained row, or
    /// missing/replaced same-boot root pin.
    pub fn open_root_owned(
        state_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let (journal, _) = Journal::open_protected_at(
            state_directory,
            WORKSPACE_JOURNAL_FILE,
            workspace_journal_limits(),
        )?;
        let pin_root = PinRoot::open(Path::new(WORKSPACE_PIN_ROOT), 0)?;
        let kernel_boot_id = KernelBootId::current()
            .map_err(|error| StorageWorkspaceCatalogError::RootPin(error.to_string()))?
            .into_bytes();
        let broker_instance_id = broker_instance_id()?;
        Self::recover(
            journal,
            pin_root,
            identity_pool,
            kernel_boot_id,
            broker_instance_id,
        )
    }

    #[cfg(test)]
    fn open_for_test(
        state_directory: &Path,
        pin_directory: &Path,
        identity_pool: StorageIdentityPoolV1,
        kernel_boot_id: [u8; 16],
        broker_instance_id: [u8; 16],
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        let (journal, _) = Journal::open(
            state_directory.join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )?;
        let owner = fs::symlink_metadata(pin_directory)
            .map_err(|error| StorageWorkspaceCatalogError::RootPin(error.to_string()))?
            .uid();
        let pin_root = PinRoot::open(pin_directory, owner)?;
        Self::recover(
            journal,
            pin_root,
            identity_pool,
            kernel_boot_id,
            broker_instance_id,
        )
    }

    fn recover(
        mut journal: Journal,
        pin_root: PinRoot,
        identity_pool: StorageIdentityPoolV1,
        kernel_boot_id: [u8; 16],
        broker_instance_id: [u8; 16],
    ) -> Result<Self, StorageWorkspaceCatalogError> {
        if kernel_boot_id == [0; 16] || broker_instance_id == [0; 16] {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }

        let mut head = None;
        let mut records = BTreeMap::new();
        for (key, value) in journal.records(RecordNamespace::StorageResourceInventory) {
            if key == HEAD_KEY {
                if head.replace(decode_head(value)?).is_some() {
                    return Err(StorageWorkspaceCatalogError::CorruptRecord);
                }
                continue;
            }
            let handle = decode_record_key(key)?;
            let record = decode_record(value)?;
            if record.workspace_handle != handle || records.insert(handle, record).is_some() {
                return Err(StorageWorkspaceCatalogError::CorruptRecord);
            }
        }

        let generation = match head {
            Some(head) => {
                let expected_generation = records
                    .values()
                    .map(|record| record.catalog_generation)
                    .max()
                    .unwrap_or(1);
                if head.identity_pool != IdentityPoolWire::from(identity_pool)
                    || head.generation != expected_generation
                {
                    return Err(StorageWorkspaceCatalogError::CorruptRecord);
                }
                head.generation
            }
            None if records.is_empty() => initialize_head(&mut journal, identity_pool)?,
            None => return Err(StorageWorkspaceCatalogError::CorruptRecord),
        };

        validate_record_set(&records, identity_pool)?;
        for record in records
            .values()
            .filter(|record| record.is_active() && record.kernel_boot_id == kernel_boot_id)
        {
            pin_root.verify_record(record)?;
        }

        Ok(Self {
            journal,
            pin_root,
            identity_pool,
            kernel_boot_id,
            broker_instance_id,
            generation,
            records,
        })
    }

    /// Returns the current protected catalog generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Publishes or refreshes a committed workspace after verifying its fixed pin.
    ///
    /// The catalog allocates the first unused contiguous range from its trusted
    /// pool. Retained ranges, including retired tombstones, are never reused.
    /// An exact active row from an earlier boot keeps its range and advances to
    /// the newly observed current-boot pin.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] for an invalid pin, identity
    /// collision, exhausted allocation pool, generation overflow, or durable
    /// journal failure.
    pub fn publish(
        &mut self,
        publication: StorageWorkspacePublicationV1,
    ) -> Result<StorageWorkspaceCatalogOutcomeV1, StorageWorkspaceCatalogError> {
        if let Some(existing) = self.records.get(&publication.workspace_handle) {
            let pin = self.pin_root.observe(&publication.workspace_handle)?;
            if existing.matches_publication(&publication, pin, self.kernel_boot_id) {
                return Ok(StorageWorkspaceCatalogOutcomeV1::Replay);
            }
            if existing.kernel_boot_id != self.kernel_boot_id
                && existing.matches_durable_publication(&publication)
            {
                if self.current_boot_pin_is_claimed(pin) {
                    return Err(StorageWorkspaceCatalogError::IdentityConflict);
                }
                let catalog_generation = next_generation(self.generation)?;
                let mut refreshed = existing.clone();
                refreshed.catalog_generation = catalog_generation;
                refreshed.kernel_boot_id = self.kernel_boot_id;
                refreshed.root_device = pin.device;
                refreshed.root_inode = pin.inode;
                refreshed.refresh_digest()?;
                refreshed.validate()?;
                self.commit(refreshed, publication.operation_id)?;
                return Ok(StorageWorkspaceCatalogOutcomeV1::Refreshed);
            }
            return Err(StorageWorkspaceCatalogError::IdentityConflict);
        }
        let assignment = AssignmentWire::from(publication.assignment);
        if self.records.values().any(|record| {
            record.creation_operation_id == publication.operation_id
                || record.dataset_guid == publication.dataset_guid
                || (
                    record.assignment.sandbox_id,
                    record.assignment.incarnation_id,
                ) == (assignment.sandbox_id, assignment.incarnation_id)
        }) {
            return Err(StorageWorkspaceCatalogError::IdentityConflict);
        }

        let pin = self.pin_root.observe(&publication.workspace_handle)?;
        if self.current_boot_pin_is_claimed(pin) {
            return Err(StorageWorkspaceCatalogError::IdentityConflict);
        }
        let (uid_range_start, uid_range_size) = self.allocate(publication.identity_range_size)?;
        let catalog_generation = next_generation(self.generation)?;
        let mut record = WorkspaceRecordV1 {
            catalog_generation,
            workspace_handle: publication.workspace_handle,
            creation_operation_id: publication.operation_id,
            request_catalog: CatalogBindingWire::from(publication.request_catalog),
            result_catalog: CatalogBindingWire::from(publication.result_catalog),
            result_digest: *publication.result_digest.as_bytes(),
            assignment,
            root_image: ObjectDescriptorWire::from_runtime(&publication.root_image)?,
            kernel_boot_id: self.kernel_boot_id,
            root_device: pin.device,
            root_inode: pin.inode,
            dataset_guid: publication.dataset_guid,
            uid_range_start,
            uid_range_size,
            lifecycle: WorkspaceLifecycleV1::Active,
            resource_digest: [0; 32],
        };
        record.refresh_digest()?;
        record.validate()?;
        self.commit(record, publication.operation_id)?;
        Ok(StorageWorkspaceCatalogOutcomeV1::Published)
    }

    /// Retires one exact destroyed workspace after proving its fixed pin is absent.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] when the handle/GUID does not
    /// name the active row, the pin still exists, the retirement conflicts
    /// with retained operation identity, or publication fails.
    pub fn retire(
        &mut self,
        retirement: StorageWorkspaceRetirementV1,
    ) -> Result<StorageWorkspaceCatalogOutcomeV1, StorageWorkspaceCatalogError> {
        self.pin_root.require_absent(&retirement.workspace_handle)?;
        let existing = self
            .records
            .get(&retirement.workspace_handle)
            .ok_or(StorageWorkspaceCatalogError::IdentityConflict)?;
        if let WorkspaceLifecycleV1::Retired {
            operation_id,
            request_catalog,
            result_catalog,
            result_digest,
        } = existing.lifecycle
        {
            if operation_id == retirement.operation_id
                && request_catalog == CatalogBindingWire::from(retirement.request_catalog)
                && result_catalog == CatalogBindingWire::from(retirement.result_catalog)
                && result_digest == *retirement.result_digest.as_bytes()
            {
                return Ok(StorageWorkspaceCatalogOutcomeV1::Replay);
            }
            return Err(StorageWorkspaceCatalogError::IdentityConflict);
        }
        if existing.dataset_guid != retirement.dataset_guid
            || retirement.request_catalog.generation() < existing.result_catalog.generation
            || self.records.values().any(|record| {
                record.creation_operation_id == retirement.operation_id
                    || record.retirement_operation_id() == Some(retirement.operation_id)
            })
        {
            return Err(StorageWorkspaceCatalogError::IdentityConflict);
        }

        let catalog_generation = next_generation(self.generation)?;
        let mut record = existing.clone();
        record.catalog_generation = catalog_generation;
        record.lifecycle = WorkspaceLifecycleV1::Retired {
            operation_id: retirement.operation_id,
            request_catalog: CatalogBindingWire::from(retirement.request_catalog),
            result_catalog: CatalogBindingWire::from(retirement.result_catalog),
            result_digest: *retirement.result_digest.as_bytes(),
        };
        record.refresh_digest()?;
        record.validate()?;
        self.commit(record, retirement.operation_id)?;
        Ok(StorageWorkspaceCatalogOutcomeV1::Retired)
    }

    /// Encodes one complete, current-boot, physically revalidated inventory.
    ///
    /// # Errors
    ///
    /// Returns [`StorageWorkspaceCatalogError`] when a live pin changed, the
    /// internal record set no longer validates, or the encoded protobuf fails
    /// the public bounded authoritative-inventory contract.
    pub fn inventory_resources(&self) -> Result<Vec<u8>, StorageWorkspaceCatalogError> {
        validate_record_set(&self.records, self.identity_pool)?;
        let mut workspaces = Vec::new();
        for record in self
            .records
            .values()
            .filter(|record| record.is_active() && record.kernel_boot_id == self.kernel_boot_id)
        {
            self.pin_root.verify_record(record)?;
            workspaces.push(record.inventory_record()?);
        }
        let response = InventoryStorageResourcesResponse {
            kernel_boot_id: self.kernel_boot_id.to_vec(),
            journal_sequence: self.journal.snapshot_sequence(),
            catalog_generation: self.generation,
            workspaces,
            broker_instance_id: self.broker_instance_id.to_vec(),
            ..Default::default()
        };
        let bytes = response.encode_to_vec();
        decode_storage_resource_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES)
            .map_err(|_| StorageWorkspaceCatalogError::InvalidInventory)?;
        Ok(bytes)
    }

    fn allocate(&self, requested_size: u32) -> Result<(u32, u32), StorageWorkspaceCatalogError> {
        if requested_size < MINIMUM_HOST_IDENTITY_RANGE {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        let pool_end = self.identity_pool.end()?;
        let mut ranges = self
            .records
            .values()
            .map(|record| -> Result<_, StorageWorkspaceCatalogError> {
                Ok((record.uid_range_start, record.uid_range_end()?))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ranges.sort_unstable();

        let mut candidate = self.identity_pool.range_start;
        for (start, end) in ranges {
            let candidate_end = candidate
                .checked_add(requested_size)
                .ok_or(StorageWorkspaceCatalogError::IdentityExhausted)?;
            if candidate_end <= start && candidate_end <= pool_end {
                return Ok((candidate, requested_size));
            }
            if candidate < end {
                candidate = end;
            }
        }
        if candidate
            .checked_add(requested_size)
            .is_some_and(|end| end <= pool_end)
        {
            Ok((candidate, requested_size))
        } else {
            Err(StorageWorkspaceCatalogError::IdentityExhausted)
        }
    }

    fn current_boot_pin_is_claimed(&self, pin: PinIdentity) -> bool {
        self.records
            .values()
            .filter(|record| record.is_active() && record.kernel_boot_id == self.kernel_boot_id)
            .any(|record| (record.root_device, record.root_inode) == (pin.device, pin.inode))
    }

    fn commit(
        &mut self,
        record: WorkspaceRecordV1,
        operation_id: [u8; 16],
    ) -> Result<(), StorageWorkspaceCatalogError> {
        let head = CatalogHeadV1 {
            generation: record.catalog_generation,
            identity_pool: IdentityPoolWire::from(self.identity_pool),
        };
        let transaction = JournalTransaction::new(
            transaction_id(operation_id, record.catalog_generation),
            vec![
                JournalRecord::put(
                    RecordNamespace::StorageResourceInventory,
                    HEAD_KEY.to_vec(),
                    encode_head(&head)?,
                ),
                JournalRecord::put(
                    RecordNamespace::StorageResourceInventory,
                    record_key(&record.workspace_handle),
                    encode_record(&record)?,
                ),
            ],
        )?;
        self.journal.commit(&transaction)?;
        self.generation = record.catalog_generation;
        self.records.insert(record.workspace_handle, record);
        Ok(())
    }
}

struct PinRoot {
    descriptor: OwnedFd,
    expected_owner: u32,
}

#[derive(Clone, Copy)]
struct PinIdentity {
    device: u64,
    inode: u64,
}

impl PinRoot {
    fn open(path: &Path, expected_owner: u32) -> Result<Self, StorageWorkspaceCatalogError> {
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
            return Err(StorageWorkspaceCatalogError::RootPin(
                "pin root is not an owner-controlled real directory".to_owned(),
            ));
        }
        Ok(Self {
            descriptor,
            expected_owner,
        })
    }

    fn observe(&self, handle: &[u8; 32]) -> Result<PinIdentity, StorageWorkspaceCatalogError> {
        let component = encode_hex(handle);
        let descriptor = rustix::fs::openat(
            self.descriptor.as_fd(),
            component,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(pin_error)?;
        let metadata = rustix::fs::fstat(&descriptor).map_err(pin_error)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
            || metadata.st_uid != self.expected_owner
            || metadata.st_mode & 0o022 != 0
            || metadata.st_dev == 0
            || metadata.st_ino == 0
        {
            return Err(StorageWorkspaceCatalogError::RootPin(
                "pin is not the required owned directory".to_owned(),
            ));
        }
        Ok(PinIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        })
    }

    fn verify_record(
        &self,
        record: &WorkspaceRecordV1,
    ) -> Result<(), StorageWorkspaceCatalogError> {
        let pin = self.observe(&record.workspace_handle)?;
        if (pin.device, pin.inode) != (record.root_device, record.root_inode) {
            return Err(StorageWorkspaceCatalogError::RootPin(
                "pin device/inode identity changed".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_absent(&self, handle: &[u8; 32]) -> Result<(), StorageWorkspaceCatalogError> {
        let component = encode_hex(handle);
        match rustix::fs::openat(
            self.descriptor.as_fd(),
            component,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Ok(_) => Err(StorageWorkspaceCatalogError::RootPin(
                "retired workspace pin still exists".to_owned(),
            )),
            Err(error) => Err(pin_error(error)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityPoolWire {
    range_start: u32,
    range_size: u32,
}

impl From<StorageIdentityPoolV1> for IdentityPoolWire {
    fn from(value: StorageIdentityPoolV1) -> Self {
        Self {
            range_start: value.range_start,
            range_size: value.range_size,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogHeadV1 {
    generation: u64,
    identity_pool: IdentityPoolWire,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogBindingWire {
    generation: u64,
    digest: [u8; 32],
}

impl CatalogBindingWire {
    fn validate(self) -> Result<(), StorageWorkspaceCatalogError> {
        if self.generation == 0 || self.digest == [0; 32] {
            Err(StorageWorkspaceCatalogError::CorruptRecord)
        } else {
            Ok(())
        }
    }
}

impl From<CatalogBindingV1> for CatalogBindingWire {
    fn from(value: CatalogBindingV1) -> Self {
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

impl AssignmentWire {
    fn validate(self) -> Result<(), StorageWorkspaceCatalogError> {
        if self.sandbox_id == [0; 16]
            || self.incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
        {
            Err(StorageWorkspaceCatalogError::CorruptRecord)
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectDescriptorWire {
    media_type: String,
    digest: [u8; 32],
    encoded_size: u64,
}

impl ObjectDescriptorWire {
    fn from_runtime(value: &ObjectDescriptor) -> Result<Self, StorageWorkspaceCatalogError> {
        validate_root_image(value)?;
        Ok(Self {
            media_type: value.media_type().as_str().to_owned(),
            digest: *value.digest().as_bytes(),
            encoded_size: value.encoded_size(),
        })
    }

    fn to_runtime(&self) -> Result<ObjectDescriptor, StorageWorkspaceCatalogError> {
        let media_type = MediaType::new(self.media_type.clone())
            .map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)?;
        let descriptor = ObjectDescriptor::new(
            media_type,
            ObjectDigest::from_bytes(self.digest),
            self.encoded_size,
        );
        validate_root_image(&descriptor)
            .map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)?;
        Ok(descriptor)
    }

    fn proto(&self) -> Result<Descriptor, StorageWorkspaceCatalogError> {
        let descriptor = self.to_runtime()?;
        Ok(Descriptor {
            media_type: descriptor.media_type().as_str().to_owned(),
            sha256: descriptor.digest().as_bytes().to_vec(),
            encoded_size: descriptor.encoded_size(),
            ..Default::default()
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum WorkspaceLifecycleV1 {
    Active,
    Retired {
        operation_id: [u8; 16],
        request_catalog: CatalogBindingWire,
        result_catalog: CatalogBindingWire,
        result_digest: [u8; 32],
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceRecordV1 {
    catalog_generation: u64,
    workspace_handle: [u8; 32],
    creation_operation_id: [u8; 16],
    request_catalog: CatalogBindingWire,
    result_catalog: CatalogBindingWire,
    result_digest: [u8; 32],
    assignment: AssignmentWire,
    root_image: ObjectDescriptorWire,
    kernel_boot_id: [u8; 16],
    root_device: u64,
    root_inode: u64,
    dataset_guid: u64,
    uid_range_start: u32,
    uid_range_size: u32,
    lifecycle: WorkspaceLifecycleV1,
    resource_digest: [u8; 32],
}

impl WorkspaceRecordV1 {
    fn validate(&self) -> Result<(), StorageWorkspaceCatalogError> {
        if self.catalog_generation == 0
            || self.workspace_handle == [0; 32]
            || self.creation_operation_id == [0; 16]
            || self.result_digest == [0; 32]
            || self.kernel_boot_id == [0; 16]
            || self.root_device == 0
            || self.root_inode == 0
            || self.dataset_guid == 0
            || self.uid_range_start == 0
            || self.uid_range_size < MINIMUM_HOST_IDENTITY_RANGE
            || self.uid_range_end().is_err()
            || self.resource_digest == [0; 32]
        {
            return Err(StorageWorkspaceCatalogError::CorruptRecord);
        }
        self.request_catalog.validate()?;
        self.result_catalog.validate()?;
        if self.result_catalog.generation <= self.request_catalog.generation {
            return Err(StorageWorkspaceCatalogError::CorruptRecord);
        }
        self.assignment.validate()?;
        self.root_image.to_runtime()?;
        if let WorkspaceLifecycleV1::Retired {
            operation_id,
            request_catalog,
            result_catalog,
            result_digest,
        } = self.lifecycle
        {
            if operation_id == [0; 16]
                || operation_id == self.creation_operation_id
                || result_digest == [0; 32]
                || result_catalog.generation <= request_catalog.generation
            {
                return Err(StorageWorkspaceCatalogError::CorruptRecord);
            }
            request_catalog.validate()?;
            result_catalog.validate()?;
        }
        if self.compute_digest()? != self.resource_digest {
            return Err(StorageWorkspaceCatalogError::CorruptRecord);
        }
        Ok(())
    }

    const fn is_active(&self) -> bool {
        matches!(self.lifecycle, WorkspaceLifecycleV1::Active)
    }

    const fn retirement_operation_id(&self) -> Option<[u8; 16]> {
        match self.lifecycle {
            WorkspaceLifecycleV1::Active => None,
            WorkspaceLifecycleV1::Retired { operation_id, .. } => Some(operation_id),
        }
    }

    fn uid_range_end(&self) -> Result<u32, StorageWorkspaceCatalogError> {
        self.uid_range_start
            .checked_add(self.uid_range_size)
            .ok_or(StorageWorkspaceCatalogError::CorruptRecord)
    }

    fn refresh_digest(&mut self) -> Result<(), StorageWorkspaceCatalogError> {
        self.resource_digest = [0; 32];
        self.resource_digest = self.compute_digest()?;
        Ok(())
    }

    fn compute_digest(&self) -> Result<[u8; 32], StorageWorkspaceCatalogError> {
        let mut preimage = self.clone();
        preimage.resource_digest = [0; 32];
        let bytes = serde_json::to_vec(&preimage)
            .map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)?;
        let mut digest = Sha256::new();
        digest.update(RESOURCE_DIGEST_DOMAIN);
        digest.update(bytes);
        Ok(digest.finalize().into())
    }

    fn matches_publication(
        &self,
        publication: &StorageWorkspacePublicationV1,
        pin: PinIdentity,
        kernel_boot_id: [u8; 16],
    ) -> bool {
        self.matches_durable_publication(publication)
            && self.kernel_boot_id == kernel_boot_id
            && (self.root_device, self.root_inode) == (pin.device, pin.inode)
    }

    fn matches_durable_publication(&self, publication: &StorageWorkspacePublicationV1) -> bool {
        self.is_active()
            && self.creation_operation_id == publication.operation_id
            && self.request_catalog == CatalogBindingWire::from(publication.request_catalog)
            && self.result_catalog == CatalogBindingWire::from(publication.result_catalog)
            && self.result_digest == *publication.result_digest.as_bytes()
            && self.assignment == AssignmentWire::from(publication.assignment)
            && self
                .root_image
                .to_runtime()
                .is_ok_and(|root| root == publication.root_image)
            && self.dataset_guid == publication.dataset_guid
            && self.uid_range_size == publication.identity_range_size
    }

    fn inventory_record(
        &self,
    ) -> Result<StorageWorkspaceInventoryRecord, StorageWorkspaceCatalogError> {
        Ok(StorageWorkspaceInventoryRecord {
            workspace_handle: self.workspace_handle.to_vec(),
            fence: Some(self.assignment.proto()).into(),
            root_image: Some(self.root_image.proto()?).into(),
            resource_kernel_boot_id: self.kernel_boot_id.to_vec(),
            root_device: self.root_device,
            root_inode: self.root_inode,
            dataset_guid: self.dataset_guid,
            uid_range_start: self.uid_range_start,
            uid_range_size: self.uid_range_size,
            resource_digest: self.resource_digest.to_vec(),
            ..Default::default()
        })
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
    record: WorkspaceRecordV1,
}

fn initialize_head(
    journal: &mut Journal,
    identity_pool: StorageIdentityPoolV1,
) -> Result<u64, StorageWorkspaceCatalogError> {
    let head = CatalogHeadV1 {
        generation: 1,
        identity_pool: IdentityPoolWire::from(identity_pool),
    };
    let transaction = JournalTransaction::new(
        genesis_transaction_id(identity_pool),
        vec![JournalRecord::put(
            RecordNamespace::StorageResourceInventory,
            HEAD_KEY.to_vec(),
            encode_head(&head)?,
        )],
    )?;
    journal.commit(&transaction)?;
    Ok(head.generation)
}

fn encode_head(head: &CatalogHeadV1) -> Result<Vec<u8>, StorageWorkspaceCatalogError> {
    serde_json::to_vec(&HeadEnvelopeV1 {
        version: RECORD_FORMAT_VERSION,
        head: head.clone(),
    })
    .map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)
}

fn decode_head(bytes: &[u8]) -> Result<CatalogHeadV1, StorageWorkspaceCatalogError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(StorageWorkspaceCatalogError::CorruptRecord);
    }
    let envelope: HeadEnvelopeV1 =
        serde_json::from_slice(bytes).map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)?;
    if envelope.version != RECORD_FORMAT_VERSION || encode_head(&envelope.head)? != bytes {
        return Err(StorageWorkspaceCatalogError::CorruptRecord);
    }
    Ok(envelope.head)
}

fn encode_record(record: &WorkspaceRecordV1) -> Result<Vec<u8>, StorageWorkspaceCatalogError> {
    let bytes = serde_json::to_vec(&RecordEnvelopeV1 {
        version: RECORD_FORMAT_VERSION,
        record: record.clone(),
    })
    .map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)?;
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(StorageWorkspaceCatalogError::CorruptRecord);
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<WorkspaceRecordV1, StorageWorkspaceCatalogError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(StorageWorkspaceCatalogError::CorruptRecord);
    }
    let envelope: RecordEnvelopeV1 =
        serde_json::from_slice(bytes).map_err(|_| StorageWorkspaceCatalogError::CorruptRecord)?;
    if envelope.version != RECORD_FORMAT_VERSION || encode_record(&envelope.record)? != bytes {
        return Err(StorageWorkspaceCatalogError::CorruptRecord);
    }
    envelope.record.validate()?;
    Ok(envelope.record)
}

fn validate_record_set(
    records: &BTreeMap<[u8; 32], WorkspaceRecordV1>,
    identity_pool: StorageIdentityPoolV1,
) -> Result<(), StorageWorkspaceCatalogError> {
    if records.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS {
        return Err(StorageWorkspaceCatalogError::CorruptRecord);
    }
    let pool_end = identity_pool.end()?;
    let mut operations = BTreeSet::new();
    let mut dataset_guids = BTreeSet::new();
    let mut assignments = BTreeSet::new();
    let mut physical_pins = BTreeSet::new();
    let mut ranges = Vec::with_capacity(records.len());
    for (handle, record) in records {
        record.validate()?;
        if handle != &record.workspace_handle
            || !operations.insert(record.creation_operation_id)
            || record
                .retirement_operation_id()
                .is_some_and(|operation| !operations.insert(operation))
            || !dataset_guids.insert(record.dataset_guid)
            || !assignments.insert((
                record.assignment.sandbox_id,
                record.assignment.incarnation_id,
            ))
            || record.uid_range_start < identity_pool.range_start
            || record.uid_range_end()? > pool_end
            || (record.is_active()
                && !physical_pins.insert((
                    record.kernel_boot_id,
                    record.root_device,
                    record.root_inode,
                )))
        {
            return Err(StorageWorkspaceCatalogError::IdentityConflict);
        }
        ranges.push((record.uid_range_start, record.uid_range_end()?));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(StorageWorkspaceCatalogError::IdentityConflict);
    }
    Ok(())
}

fn validate_root_image(value: &ObjectDescriptor) -> Result<(), StorageWorkspaceCatalogError> {
    if value.digest().as_bytes() == &[0; 32] || value.encoded_size() == 0 {
        return Err(StorageWorkspaceCatalogError::InvalidCandidate);
    }
    validate_descriptor_role(DescriptorRole::SandboxRootView, value)
        .map_err(|_| StorageWorkspaceCatalogError::InvalidCandidate)?;
    Ok(())
}

fn record_key(handle: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(RECORD_KEY_PREFIX.len() + handle.len());
    key.extend_from_slice(RECORD_KEY_PREFIX);
    key.extend_from_slice(handle);
    key
}

fn decode_record_key(key: &[u8]) -> Result<[u8; 32], StorageWorkspaceCatalogError> {
    key.strip_prefix(RECORD_KEY_PREFIX)
        .and_then(|bytes| bytes.try_into().ok())
        .filter(|handle: &[u8; 32]| *handle != [0; 32])
        .ok_or(StorageWorkspaceCatalogError::CorruptRecord)
}

fn next_generation(generation: u64) -> Result<u64, StorageWorkspaceCatalogError> {
    generation
        .checked_add(1)
        .ok_or(StorageWorkspaceCatalogError::CorruptRecord)
}

fn transaction_id(operation_id: [u8; 16], generation: u64) -> [u8; 16] {
    transaction_digest(&[&operation_id, &generation.to_be_bytes()])
}

fn genesis_transaction_id(identity_pool: StorageIdentityPoolV1) -> [u8; 16] {
    transaction_digest(&[
        &identity_pool.range_start.to_be_bytes(),
        &identity_pool.range_size.to_be_bytes(),
    ])
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

fn broker_instance_id() -> Result<[u8; 16], StorageWorkspaceCatalogError> {
    let bytes = fs::read("/proc/sys/kernel/random/uuid")
        .map_err(|error| StorageWorkspaceCatalogError::RootPin(error.to_string()))?;
    KernelBootId::parse(&bytes)
        .map(KernelBootId::into_bytes)
        .map_err(|error| StorageWorkspaceCatalogError::RootPin(error.to_string()))
}

fn pin_error(error: rustix::io::Errno) -> StorageWorkspaceCatalogError {
    StorageWorkspaceCatalogError::RootPin(error.to_string())
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

const fn workspace_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 512 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_RECORD_BYTES,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 2,
        maximum_transaction_bytes: MAXIMUM_RECORD_BYTES * 2,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_RECORD_BYTES
            * (MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS + 1),
        maximum_materialized_records: MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS + 1,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::PathBuf;

    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};
    use aos_sandbox_protocol::ValidatedStorageInventory;
    use tempfile::TempDir;

    use super::*;

    const RANGE_SIZE: u32 = MINIMUM_HOST_IDENTITY_RANGE;

    struct Fixture {
        _directory: TempDir,
        state_directory: PathBuf,
        pin_directory: PathBuf,
        identity_pool: StorageIdentityPoolV1,
    }

    impl Fixture {
        fn new(range_count: u32) -> Self {
            let directory = TempDir::new().unwrap();
            let state_directory = directory.path().join("state");
            let pin_directory = directory.path().join("pins");
            fs::create_dir(&state_directory).unwrap();
            fs::create_dir(&pin_directory).unwrap();

            Self {
                _directory: directory,
                state_directory,
                pin_directory,
                identity_pool: StorageIdentityPoolV1::new(
                    RANGE_SIZE,
                    RANGE_SIZE.checked_mul(range_count).unwrap(),
                )
                .unwrap(),
            }
        }

        fn open(
            &self,
            kernel_boot_id: [u8; 16],
        ) -> Result<StorageWorkspaceCatalogV1, StorageWorkspaceCatalogError> {
            StorageWorkspaceCatalogV1::open_for_test(
                &self.state_directory,
                &self.pin_directory,
                self.identity_pool,
                kernel_boot_id,
                [91; 16],
            )
        }

        fn pin_path(&self, handle: u8) -> PathBuf {
            self.pin_directory.join(encode_hex(&[handle; 32]))
        }

        fn create_pin(&self, handle: u8) {
            fs::create_dir(self.pin_path(handle)).unwrap();
        }
    }

    fn binding(generation: u64, marker: u8) -> CatalogBindingV1 {
        CatalogBindingV1::from_publisher(generation, ObjectDigest::from_bytes([marker; 32]))
            .unwrap()
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

    fn root_image(marker: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([marker; 32]),
            u64::from(marker) + 1,
        )
    }

    fn publication(handle: u8) -> StorageWorkspacePublicationV1 {
        StorageWorkspacePublicationV1 {
            operation_id: [handle.wrapping_add(10); 16],
            request_catalog: binding(u64::from(handle) + 10, handle.wrapping_add(20)),
            result_catalog: binding(u64::from(handle) + 11, handle.wrapping_add(21)),
            result_digest: ObjectDigest::from_bytes([handle.wrapping_add(22); 32]),
            workspace_handle: [handle; 32],
            dataset_guid: u64::from(handle) + 100,
            assignment: assignment(handle),
            root_image: root_image(handle.wrapping_add(30)),
            identity_range_size: RANGE_SIZE,
        }
    }

    fn retirement(handle: u8) -> StorageWorkspaceRetirementV1 {
        StorageWorkspaceRetirementV1 {
            operation_id: [handle.wrapping_add(100); 16],
            request_catalog: binding(u64::from(handle) + 30, handle.wrapping_add(40)),
            result_catalog: binding(u64::from(handle) + 31, handle.wrapping_add(41)),
            result_digest: ObjectDigest::from_bytes([handle.wrapping_add(42); 32]),
            workspace_handle: [handle; 32],
            dataset_guid: u64::from(handle) + 100,
        }
    }

    fn inventory(catalog: &StorageWorkspaceCatalogV1) -> ValidatedStorageInventory {
        decode_storage_resource_inventory_response(
            &catalog.inventory_resources().unwrap(),
            MAXIMUM_RESPONSE_BYTES,
        )
        .unwrap()
    }

    #[test]
    fn initializes_publishes_replays_and_recovers_exact_inventory() {
        let fixture = Fixture::new(3);
        fixture.create_pin(1);
        let mut catalog = fixture.open([81; 16]).unwrap();

        assert_eq!(catalog.generation(), 1);
        assert!(inventory(&catalog).workspaces().is_empty());
        assert_eq!(
            catalog.publish(publication(1)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Published
        );
        assert_eq!(catalog.generation(), 2);
        assert_eq!(
            catalog.publish(publication(1)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Replay
        );

        let snapshot = inventory(&catalog);
        assert_eq!(snapshot.kernel_boot_id(), &[81; 16]);
        assert_eq!(snapshot.broker_instance_id(), &[91; 16]);
        assert_eq!(snapshot.catalog_generation(), 2);
        assert_eq!(snapshot.workspaces().len(), 1);
        let workspace = &snapshot.workspaces()[0];
        assert_eq!(workspace.workspace_handle(), &[1; 32]);
        assert_eq!(workspace.dataset_guid(), 101);
        assert_eq!(workspace.uid_range_start(), RANGE_SIZE);
        assert_eq!(workspace.uid_range_size(), RANGE_SIZE);
        assert_eq!(workspace.fence().sandbox_id(), &[1; 16]);

        drop(catalog);
        let recovered = fixture.open([81; 16]).unwrap();
        assert_eq!(recovered.generation(), 2);
        assert_eq!(inventory(&recovered), snapshot);
    }

    #[test]
    fn allocates_first_fit_without_reusing_retired_ranges() {
        let fixture = Fixture::new(4);
        fixture.create_pin(1);
        fixture.create_pin(2);
        fixture.create_pin(3);
        let mut catalog = fixture.open([81; 16]).unwrap();

        assert_eq!(
            catalog.publish(publication(1)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Published
        );
        assert_eq!(
            catalog.publish(publication(2)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Published
        );
        assert_eq!(
            inventory(&catalog).workspaces()[1].uid_range_start(),
            RANGE_SIZE * 2
        );

        fs::remove_dir(fixture.pin_path(1)).unwrap();
        assert_eq!(
            catalog.retire(retirement(1)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Retired
        );
        assert_eq!(
            catalog.retire(retirement(1)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Replay
        );
        assert_eq!(
            catalog.publish(publication(3)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Published
        );

        let snapshot = inventory(&catalog);
        assert_eq!(snapshot.catalog_generation(), 5);
        assert_eq!(snapshot.workspaces().len(), 2);
        assert_eq!(snapshot.workspaces()[0].workspace_handle(), &[2; 32]);
        assert_eq!(snapshot.workspaces()[0].uid_range_start(), RANGE_SIZE * 2);
        assert_eq!(snapshot.workspaces()[1].workspace_handle(), &[3; 32]);
        assert_eq!(snapshot.workspaces()[1].uid_range_start(), RANGE_SIZE * 3);

        drop(catalog);
        let recovered = fixture.open([81; 16]).unwrap();
        assert_eq!(inventory(&recovered), snapshot);
    }

    #[test]
    fn stale_boot_rows_are_omitted_until_an_exact_pin_refresh() {
        let fixture = Fixture::new(2);
        fixture.create_pin(1);
        let mut catalog = fixture.open([81; 16]).unwrap();
        catalog.publish(publication(1)).unwrap();
        drop(catalog);

        fs::rename(
            fixture.pin_path(1),
            fixture.pin_directory.join("retained-old-pin"),
        )
        .unwrap();
        let current_boot = fixture.open([82; 16]).unwrap();
        assert_eq!(current_boot.generation(), 2);
        assert!(inventory(&current_boot).workspaces().is_empty());
        drop(current_boot);

        fixture.create_pin(1);
        let mut current_boot = fixture.open([82; 16]).unwrap();
        assert_eq!(
            current_boot.publish(publication(1)).unwrap(),
            StorageWorkspaceCatalogOutcomeV1::Refreshed
        );
        let snapshot = inventory(&current_boot);
        assert_eq!(snapshot.catalog_generation(), 3);
        assert_eq!(snapshot.workspaces().len(), 1);
        assert_eq!(snapshot.workspaces()[0].uid_range_start(), RANGE_SIZE);
        assert_eq!(
            snapshot.workspaces()[0].resource_kernel_boot_id(),
            &[82; 16]
        );
    }

    #[test]
    fn changed_or_writable_pins_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new(2);
        fixture.create_pin(1);
        let mut catalog = fixture.open([81; 16]).unwrap();
        catalog.publish(publication(1)).unwrap();

        let original = fixture.pin_directory.join("original-pin");
        fs::rename(fixture.pin_path(1), &original).unwrap();
        fixture.create_pin(1);
        assert!(matches!(
            catalog.inventory_resources(),
            Err(StorageWorkspaceCatalogError::RootPin(_))
        ));
        drop(catalog);
        assert!(matches!(
            fixture.open([81; 16]),
            Err(StorageWorkspaceCatalogError::RootPin(_))
        ));

        fs::remove_dir(fixture.pin_path(1)).unwrap();
        fs::rename(original, fixture.pin_path(1)).unwrap();
        fs::set_permissions(fixture.pin_path(1), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            fixture.open([81; 16]),
            Err(StorageWorkspaceCatalogError::RootPin(_))
        ));
    }

    #[test]
    fn identity_conflicts_exhaustion_and_live_retirement_are_rejected() {
        let fixture = Fixture::new(2);
        fixture.create_pin(1);
        fixture.create_pin(2);
        fixture.create_pin(3);
        let mut catalog = fixture.open([81; 16]).unwrap();
        let first = publication(1);
        catalog.publish(first.clone()).unwrap();

        let mut rebound = publication(2);
        rebound.assignment = BrokerAssignment::new(
            first.assignment.sandbox(),
            first.assignment.incarnation(),
            AssignmentEpoch::new(99),
            DesiredGeneration::new(100),
            ObjectDigest::from_bytes([101; 32]),
        )
        .unwrap();
        assert!(matches!(
            catalog.publish(rebound),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));
        catalog.publish(publication(2)).unwrap();
        assert!(matches!(
            catalog.publish(publication(3)),
            Err(StorageWorkspaceCatalogError::IdentityExhausted)
        ));
        assert!(matches!(
            catalog.retire(retirement(1)),
            Err(StorageWorkspaceCatalogError::RootPin(_))
        ));

        fs::remove_dir(fixture.pin_path(1)).unwrap();
        let mut wrong_dataset = retirement(1);
        wrong_dataset.dataset_guid += 1;
        assert!(matches!(
            catalog.retire(wrong_dataset),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));
        let mut stale_catalog = retirement(1);
        stale_catalog.request_catalog = binding(10, 102);
        stale_catalog.result_catalog = binding(11, 103);
        assert!(matches!(
            catalog.retire(stale_catalog),
            Err(StorageWorkspaceCatalogError::IdentityConflict)
        ));
    }

    #[test]
    fn catalog_head_fixes_pool_and_rejects_impossible_empty_generation() {
        let fixture = Fixture::new(2);
        let catalog = fixture.open([81; 16]).unwrap();
        drop(catalog);

        let different_pool = StorageIdentityPoolV1::new(RANGE_SIZE * 2, RANGE_SIZE * 2).unwrap();
        assert!(matches!(
            StorageWorkspaceCatalogV1::open_for_test(
                &fixture.state_directory,
                &fixture.pin_directory,
                different_pool,
                [81; 16],
                [91; 16],
            ),
            Err(StorageWorkspaceCatalogError::CorruptRecord)
        ));

        let corrupt_fixture = Fixture::new(2);
        let (mut journal, _) = Journal::open(
            corrupt_fixture.state_directory.join(WORKSPACE_JOURNAL_FILE),
            workspace_journal_limits(),
        )
        .unwrap();
        let head = CatalogHeadV1 {
            generation: 2,
            identity_pool: IdentityPoolWire::from(corrupt_fixture.identity_pool),
        };
        let transaction = JournalTransaction::new(
            [71; 16],
            vec![JournalRecord::put(
                RecordNamespace::StorageResourceInventory,
                HEAD_KEY.to_vec(),
                encode_head(&head).unwrap(),
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        drop(journal);

        assert!(matches!(
            corrupt_fixture.open([81; 16]),
            Err(StorageWorkspaceCatalogError::CorruptRecord)
        ));
    }
}
