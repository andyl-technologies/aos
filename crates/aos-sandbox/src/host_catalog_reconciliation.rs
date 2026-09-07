//! Projects complete broker inventories into a crash-recoverable Host catalog.
//!
//! Projection joins four independently authenticated snapshots with the
//! controller's complete protected current-assignment set. The resulting
//! catalog follows an explicit durable effect protocol:
//!
//! ```text
//! fresh Storage + Network + Mount + destination-slot snapshots
//!     -> exact current-assignment projection
//!     -> durable pending catalog
//!     -> authenticated Host 1.4 publication
//!     -> durable confirmed current catalog
//! ```
//!
//! A pending catalog is never replaced by another projection. After an
//! indeterminate publication attempt, recovery must send the exact same bytes
//! until Host confirms either publication or replay. Catalog entries carry no
//! effect authority; Host still requires a separately signed, leased launch
//! plan whose assignment and resource selectors match the published rows.

use aos_proto::aos::sandbox::local::v1::DestinationSlotLifecycle;
use aos_sandbox_core::{ObjectDescriptor, ObjectDigest};
use aos_sandbox_protocol::{
    ATTACHMENT_ANCHOR_PIN_PREFIX, AttachmentAnchorCatalogEntry, CatalogAssignment,
    CatalogIdentityAllocation, HostCatalogSnapshot, HostCatalogSnapshotError, NetworkCatalogEntry,
    ValidatedAssignmentFence, ValidatedDestinationSlotInventory, ValidatedMountInventory,
    ValidatedNetworkInventory, ValidatedStorageInventory, WorkspaceCatalogEntry,
};
use sha2::{Digest as _, Sha256};

use crate::host_catalog_publication::{
    HostCatalogPublicationClient, HostCatalogPublicationDraftV1, HostCatalogPublicationError,
};
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityError, RuntimeAuthorityLimits,
    RuntimeAuthorityStateV1, RuntimeAuthorityStore,
};
use crate::{
    DurableDestinationSlotInventorySnapshotV1, DurableNetworkResourceInventorySnapshotV1,
    DurableStorageResourceInventorySnapshotV1, Journal, JournalError, JournalRecord,
    JournalTransaction, RecordNamespace,
};

const MAGIC: &[u8; 8] = b"AOSHCR01";
const VERSION: u16 = 1;
const PENDING_KEY: &[u8] = b"pending";
const CURRENT_KEY: &[u8] = b"current";
const FIXED_RECORD_BYTES: usize = 272;
const JOURNAL_RECORD_BYTES: usize = 16 * 1024 * 1024;
const JOURNAL_RECORD_HEADER_BYTES: usize = 7;
const MAXIMUM_RECORD_VALUE_BYTES: usize =
    JOURNAL_RECORD_BYTES - JOURNAL_RECORD_HEADER_BYTES - PENDING_KEY.len();
const MAXIMUM_DURABLE_CATALOG_BYTES: usize = MAXIMUM_RECORD_VALUE_BYTES - FIXED_RECORD_BYTES;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.host-catalog-reconciliation.record.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.host-catalog-reconciliation.transaction.v1\0";

/// Describes whether catalog reconciliation needs Host publication.
pub enum HostCatalogReconciliationV1 {
    /// The exact projected resources are already the confirmed current catalog.
    Current(DurableCurrentHostCatalogV1),
    /// A successor became durable and must be published or exactly replayed.
    Publish(DurablePendingHostCatalogV1),
}

/// Retains one exact catalog whose Host effect is durably pending.
pub struct DurablePendingHostCatalogV1 {
    record: CatalogRecord,
}

impl DurablePendingHostCatalogV1 {
    /// Returns the nonzero Host catalog generation to publish.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.record.catalog.generation()
    }

    /// Borrows the complete canonical catalog bytes.
    #[must_use]
    pub fn canonical_catalog(&self) -> &[u8] {
        &self.record.canonical_catalog
    }

    /// Returns the SHA-256 commitment Host must acknowledge.
    #[must_use]
    pub const fn catalog_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.catalog_digest)
    }

    /// Borrows the validated projected catalog.
    #[must_use]
    pub const fn catalog(&self) -> &HostCatalogSnapshot {
        &self.record.catalog
    }
}

/// Retains the latest controller-confirmed Host catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCurrentHostCatalogV1 {
    record: CatalogRecord,
}

impl DurableCurrentHostCatalogV1 {
    /// Returns the nonzero confirmed Host catalog generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.record.catalog.generation()
    }

    /// Borrows the exact canonical bytes confirmed by Host.
    #[must_use]
    pub fn canonical_catalog(&self) -> &[u8] {
        &self.record.canonical_catalog
    }

    /// Returns the exact catalog digest confirmed by Host.
    #[must_use]
    pub const fn catalog_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.catalog_digest)
    }

    /// Borrows the validated current catalog.
    #[must_use]
    pub const fn catalog(&self) -> &HostCatalogSnapshot {
        &self.record.catalog
    }
}

/// Reports stale evidence, incomplete joins, or durable catalog failure.
#[derive(Debug, thiserror::Error)]
pub enum HostCatalogReconciliationError {
    /// An earlier catalog effect must be resolved before another projection.
    #[error("a Host catalog publication is already durably pending")]
    PendingPublication,
    /// Authenticated inventories do not describe one mutually current boot/state.
    #[error("Host catalog inventory evidence is stale or inconsistent")]
    InventoryConflict,
    /// A previously published current assignment temporarily lacks complete resources.
    #[error("a current Host catalog assignment has incomplete launch resources")]
    IncompleteResources,
    /// Current controller state or broker rows violate exact projection invariants.
    #[error("Host catalog projection state is corrupt or ambiguous")]
    CorruptState,
    /// The confirmed generation cannot advance without overflowing.
    #[error("Host catalog generation is exhausted")]
    GenerationExhausted,
    /// The exact canonical catalog cannot fit in one protected journal record.
    #[error("projected Host catalog exceeds durable controller bounds")]
    Capacity,
    /// The shared strict catalog schema rejected projected rows.
    #[error("projected Host catalog is invalid: {0}")]
    Catalog(#[from] HostCatalogSnapshotError),
    /// Protected runtime-assignment history failed validation.
    #[error("current runtime authority failed: {0}")]
    RuntimeAuthority(#[from] RuntimeAuthorityError),
    /// Storage or Network snapshot currentness failed.
    #[error("broker resource inventory failed: {0}")]
    ResourceInventory(#[from] crate::ResourceInventoryError),
    /// Mount snapshot currentness failed.
    #[error("Mount inventory failed: {0}")]
    MountInventory(#[from] crate::MountAttemptError),
    /// Attachment readiness evidence failed validation.
    #[error("attachment verification failed: {0}")]
    AttachmentVerification(#[from] crate::AttachmentVerificationError),
    /// Sandbox specification state failed validation.
    #[error("sandbox specification failed: {0}")]
    SandboxSpec(#[from] crate::SandboxSpecStateError),
    /// Authenticated Host publication failed or remained indeterminate.
    #[error("Host catalog publication failed: {0}")]
    Publication(#[from] HostCatalogPublicationError),
    /// The protected journal rejected recovery or a state transition.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum CatalogRecordState {
    Pending = 1,
    Current = 2,
}

impl CatalogRecordState {
    fn from_byte(value: u8) -> Result<Self, HostCatalogReconciliationError> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Current),
            _ => Err(HostCatalogReconciliationError::CorruptState),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogRecord {
    state: CatalogRecordState,
    controller_state_digest: [u8; 32],
    inventory_digests: [[u8; 32]; 4],
    prior_catalog_digest: Option<[u8; 32]>,
    canonical_catalog: Vec<u8>,
    catalog: HostCatalogSnapshot,
    catalog_digest: [u8; 32],
    digest: [u8; 32],
}

impl CatalogRecord {
    fn pending(
        controller_state_digest: ObjectDigest,
        inventory_digests: [ObjectDigest; 4],
        prior: Option<&CatalogRecord>,
        catalog: HostCatalogSnapshot,
    ) -> Result<Self, HostCatalogReconciliationError> {
        let canonical_catalog = catalog.encode()?;
        if canonical_catalog.len() > MAXIMUM_DURABLE_CATALOG_BYTES {
            return Err(HostCatalogReconciliationError::Capacity);
        }
        let catalog_digest = Sha256::digest(&canonical_catalog).into();
        let mut record = Self {
            state: CatalogRecordState::Pending,
            controller_state_digest: *controller_state_digest.as_bytes(),
            inventory_digests: inventory_digests.map(|digest| *digest.as_bytes()),
            prior_catalog_digest: prior.map(|record| record.catalog_digest),
            canonical_catalog,
            catalog,
            catalog_digest,
            digest: [0; 32],
        };
        record.digest = record.compute_digest();
        record.validate()?;

        Ok(record)
    }

    fn into_current(mut self) -> Result<Self, HostCatalogReconciliationError> {
        self.state = CatalogRecordState::Current;
        self.digest = self.compute_digest();
        self.validate()?;

        Ok(self)
    }

    fn key(&self) -> &'static [u8] {
        match self.state {
            CatalogRecordState::Pending => PENDING_KEY,
            CatalogRecordState::Current => CURRENT_KEY,
        }
    }

    fn encoded_len(&self) -> usize {
        FIXED_RECORD_BYTES.saturating_add(self.canonical_catalog.len())
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(RECORD_DOMAIN);
        digest.update([self.state as u8]);
        digest.update(self.controller_state_digest);
        for inventory_digest in self.inventory_digests {
            digest.update(inventory_digest);
        }
        digest.update([u8::from(self.prior_catalog_digest.is_some())]);
        digest.update(self.prior_catalog_digest.unwrap_or([0; 32]));
        digest.update((self.canonical_catalog.len() as u64).to_be_bytes());
        digest.update(&self.canonical_catalog);
        digest.finalize().into()
    }

    fn validate(&self) -> Result<(), HostCatalogReconciliationError> {
        if self.controller_state_digest == [0; 32]
            || self.inventory_digests.contains(&[0; 32])
            || self.prior_catalog_digest == Some([0; 32])
            || (self.catalog.generation() == 1) != self.prior_catalog_digest.is_none()
            || self.canonical_catalog.is_empty()
            || self.encoded_len() > MAXIMUM_RECORD_VALUE_BYTES
            || Sha256::digest(&self.canonical_catalog).as_slice() != self.catalog_digest
            || self.catalog != HostCatalogSnapshot::decode_canonical(&self.canonical_catalog)?
            || self.compute_digest() != self.digest
        {
            return Err(HostCatalogReconciliationError::CorruptState);
        }

        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(self.state as u8);
        bytes.push(u8::from(self.prior_catalog_digest.is_some()));
        bytes.extend_from_slice(&self.controller_state_digest);
        for digest in self.inventory_digests {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.prior_catalog_digest.unwrap_or([0; 32]));
        bytes.extend_from_slice(&(self.canonical_catalog.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.canonical_catalog);
        bytes.extend_from_slice(&self.catalog_digest);
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, HostCatalogReconciliationError> {
        if bytes.len() < FIXED_RECORD_BYTES || bytes.len() > MAXIMUM_RECORD_VALUE_BYTES {
            return Err(HostCatalogReconciliationError::CorruptState);
        }

        let mut bytes = bytes;
        if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
            return Err(HostCatalogReconciliationError::CorruptState);
        }
        let state = CatalogRecordState::from_byte(take::<1>(&mut bytes)?[0])?;
        let prior_present = match take::<1>(&mut bytes)?[0] {
            0 => false,
            1 => true,
            _ => return Err(HostCatalogReconciliationError::CorruptState),
        };
        let controller_state_digest = take(&mut bytes)?;
        let mut inventory_digests = [[0; 32]; 4];
        for digest in &mut inventory_digests {
            *digest = take(&mut bytes)?;
        }
        let prior_catalog_digest = take(&mut bytes)?;
        let prior_catalog_digest = prior_present.then_some(prior_catalog_digest);
        let catalog_length = u32::from_be_bytes(take(&mut bytes)?) as usize;
        if catalog_length == 0 || catalog_length > MAXIMUM_DURABLE_CATALOG_BYTES {
            return Err(HostCatalogReconciliationError::CorruptState);
        }
        let canonical_catalog = bytes
            .get(..catalog_length)
            .ok_or(HostCatalogReconciliationError::CorruptState)?
            .to_vec();
        bytes = bytes
            .get(catalog_length..)
            .ok_or(HostCatalogReconciliationError::CorruptState)?;
        let catalog_digest = take(&mut bytes)?;
        let digest = take(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(HostCatalogReconciliationError::CorruptState);
        }
        let catalog = HostCatalogSnapshot::decode_canonical(&canonical_catalog)?;
        let record = Self {
            state,
            controller_state_digest,
            inventory_digests,
            prior_catalog_digest,
            canonical_catalog,
            catalog,
            catalog_digest,
            digest,
        };
        record.validate()?;

        Ok(record)
    }

    fn transaction(&self) -> Result<JournalTransaction, HostCatalogReconciliationError> {
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(
            &Sha256::new()
                .chain_update(TRANSACTION_DOMAIN)
                .chain_update(self.digest)
                .finalize()[..16],
        );
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }

        Ok(JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::HostCatalogReconciliation,
                self.key().to_vec(),
                self.encode(),
            )],
        )?)
    }

    fn completion_transaction(&self) -> Result<JournalTransaction, HostCatalogReconciliationError> {
        let current = self.clone().into_current()?;
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(
            &Sha256::new()
                .chain_update(TRANSACTION_DOMAIN)
                .chain_update(b"complete")
                .chain_update(current.digest)
                .finalize()[..16],
        );
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }

        Ok(JournalTransaction::new(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::HostCatalogReconciliation,
                    CURRENT_KEY.to_vec(),
                    current.encode(),
                ),
                JournalRecord::delete(
                    RecordNamespace::HostCatalogReconciliation,
                    PENDING_KEY.to_vec(),
                ),
            ],
        )?)
    }
}

#[derive(Default)]
struct CatalogHistory {
    pending: Option<CatalogRecord>,
    current: Option<CatalogRecord>,
}

impl CatalogHistory {
    fn load(journal: &mut Journal) -> Result<Self, HostCatalogReconciliationError> {
        journal.ensure_healthy()?;
        let mut history = Self::default();

        for (key, value) in journal.records(RecordNamespace::HostCatalogReconciliation) {
            let record = CatalogRecord::decode(value)?;
            if key != record.key() {
                return Err(HostCatalogReconciliationError::CorruptState);
            }
            let target = match record.state {
                CatalogRecordState::Pending => &mut history.pending,
                CatalogRecordState::Current => &mut history.current,
            };
            if target.replace(record).is_some() {
                return Err(HostCatalogReconciliationError::CorruptState);
            }
        }

        if let Some(current) = &history.current
            && current.state != CatalogRecordState::Current
        {
            return Err(HostCatalogReconciliationError::CorruptState);
        }
        if let Some(pending) = &history.pending {
            let expected_generation = history
                .current
                .as_ref()
                .map_or(Some(1), |current| {
                    current.catalog.generation().checked_add(1)
                })
                .ok_or(HostCatalogReconciliationError::CorruptState)?;
            let expected_prior = history
                .current
                .as_ref()
                .map(|current| current.catalog_digest);
            if pending.state != CatalogRecordState::Pending
                || pending.catalog.generation() != expected_generation
                || pending.prior_catalog_digest != expected_prior
            {
                return Err(HostCatalogReconciliationError::CorruptState);
            }
        }

        Ok(history)
    }
}

struct ProjectedWorkspace {
    handle: [u8; 32],
    assignment: CatalogAssignment,
    root_image: ObjectDescriptor,
    root_directory: String,
    device: u64,
    inode: u64,
    uid_range_start: u32,
    uid_range_size: u32,
    attachment_handles: Vec<[u8; 32]>,
}

struct ProjectedNetwork {
    handle: [u8; 32],
    assignment: CatalogAssignment,
    namespace_path: String,
    device: u64,
    inode: u64,
}

struct ProjectedAnchor {
    handle: [u8; 32],
    assignment: CatalogAssignment,
    namespace_generation: u64,
    device: u64,
    inode: u64,
    mount_id: u64,
}

#[derive(Default)]
struct ProjectedRows {
    workspaces: Vec<ProjectedWorkspace>,
    networks: Vec<ProjectedNetwork>,
    anchors: Vec<ProjectedAnchor>,
}

/// Prepares an exact successor catalog from mutually current durable snapshots.
pub(crate) fn prepare(
    journal: &mut Journal,
    storage: DurableStorageResourceInventorySnapshotV1,
    network: DurableNetworkResourceInventorySnapshotV1,
    mounts: crate::mount_attempt::DurableMountInventorySnapshotV1,
    destinations: DurableDestinationSlotInventorySnapshotV1,
) -> Result<HostCatalogReconciliationV1, HostCatalogReconciliationError> {
    let history = CatalogHistory::load(journal)?;
    if history.pending.is_some() {
        return Err(HostCatalogReconciliationError::PendingPublication);
    }

    storage.recheck(journal)?;
    network.recheck(journal)?;
    mounts.recheck(journal)?;
    destinations.recheck(journal)?;
    if storage.controller_state_digest() != network.controller_state_digest()
        || !same_boot(
            storage.inventory(),
            network.inventory(),
            mounts.inventory(),
            destinations.inventory(),
        )
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }

    let bindings = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
        .current_bindings()?;
    crate::sandbox_spec_state::validate_namespace(journal)?;
    let rows = collect_rows(
        journal,
        &bindings,
        storage.inventory(),
        network.inventory(),
        mounts.inventory(),
        destinations.inventory(),
        history.current.as_ref().map(|record| &record.catalog),
    )?;
    let current_generation = history
        .current
        .as_ref()
        .map(|record| record.catalog.generation());
    if let Some(current) = &history.current {
        let unchanged =
            materialize_catalog(current.catalog.generation(), &rows, Some(&current.catalog))?;
        if unchanged == current.catalog {
            return Ok(HostCatalogReconciliationV1::Current(
                DurableCurrentHostCatalogV1 {
                    record: current.clone(),
                },
            ));
        }
    }
    let generation = current_generation
        .map_or(Some(1), |generation| generation.checked_add(1))
        .ok_or(HostCatalogReconciliationError::GenerationExhausted)?;
    let catalog = materialize_catalog(
        generation,
        &rows,
        history.current.as_ref().map(|record| &record.catalog),
    )?;
    let pending = CatalogRecord::pending(
        storage.controller_state_digest(),
        [
            storage.record_digest(),
            network.record_digest(),
            mounts.record_digest(),
            destinations.record_digest(),
        ],
        history.current.as_ref(),
        catalog,
    )?;
    journal.commit(&pending.transaction()?)?;

    let committed = CatalogHistory::load(journal)?;
    if committed.pending.as_ref() != Some(&pending) {
        return Err(HostCatalogReconciliationError::CorruptState);
    }

    Ok(HostCatalogReconciliationV1::Publish(
        DurablePendingHostCatalogV1 { record: pending },
    ))
}

/// Recovers an exact pending Host effect without reconstructing its inputs.
pub(crate) fn recover_pending(
    journal: &mut Journal,
) -> Result<Option<DurablePendingHostCatalogV1>, HostCatalogReconciliationError> {
    Ok(CatalogHistory::load(journal)?
        .pending
        .map(|record| DurablePendingHostCatalogV1 { record }))
}

/// Publishes one durable pending catalog and commits Host confirmation.
pub(crate) fn dispatch(
    journal: &mut Journal,
    pending: DurablePendingHostCatalogV1,
    client: HostCatalogPublicationClient,
    deadline_boottime_nanoseconds: u64,
) -> Result<DurableCurrentHostCatalogV1, HostCatalogReconciliationError> {
    let history = CatalogHistory::load(journal)?;
    if history.pending.as_ref() != Some(&pending.record) {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    let draft = HostCatalogPublicationDraftV1::new(
        pending.record.canonical_catalog.clone(),
        pending.record.catalog.generation(),
    )?;
    if draft.expected_digest().as_bytes() != &pending.record.catalog_digest {
        return Err(HostCatalogReconciliationError::CorruptState);
    }

    let _status = client.publish(&draft, deadline_boottime_nanoseconds)?;
    journal.commit(&pending.record.completion_transaction()?)?;

    let committed = CatalogHistory::load(journal)?;
    let current = committed
        .current
        .ok_or(HostCatalogReconciliationError::CorruptState)?;
    if committed.pending.is_some()
        || current.catalog_digest != pending.record.catalog_digest
        || current.catalog != pending.record.catalog
    {
        return Err(HostCatalogReconciliationError::CorruptState);
    }

    Ok(DurableCurrentHostCatalogV1 { record: current })
}

pub(crate) fn validate_namespace(
    journal: &mut Journal,
) -> Result<(), HostCatalogReconciliationError> {
    CatalogHistory::load(journal).map(|_| ())
}

fn collect_rows(
    journal: &mut Journal,
    bindings: &[RuntimeAuthorityBindingV1],
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    mounts: &ValidatedMountInventory,
    destinations: &ValidatedDestinationSlotInventory,
    previous: Option<&HostCatalogSnapshot>,
) -> Result<ProjectedRows, HostCatalogReconciliationError> {
    let mut rows = ProjectedRows::default();

    for binding in bindings
        .iter()
        .filter(|binding| binding.state() == RuntimeAuthorityStateV1::Bound)
    {
        let assignment = binding.manifest().manifest();
        let workspace = unique_matching(storage.workspaces(), |workspace| {
            fence_matches_binding(workspace.fence(), binding)
        })?;
        let network_row = unique_matching(network.networks(), |network| {
            network.is_launchable() && fence_matches_binding(network.fence(), binding)
        })?;
        let previously_published = previous.is_some_and(|catalog| {
            catalog.workspaces().iter().any(|workspace| {
                catalog_assignment_matches_binding(workspace.assignment(), binding)
            })
        });
        let (Some(workspace), Some(network_row)) = (workspace, network_row) else {
            if previously_published {
                return Err(HostCatalogReconciliationError::IncompleteResources);
            }
            continue;
        };
        if workspace.root_image() != assignment.root_view() {
            return Err(HostCatalogReconciliationError::CorruptState);
        }

        let Some(specification) = crate::sandbox_spec_state::get_in_validated_namespace(
            journal,
            assignment.sandbox_spec(),
        )?
        else {
            return Err(HostCatalogReconciliationError::CorruptState);
        };
        let anchor = ready_anchor(
            binding,
            specification.spec().attachment_slots(),
            destinations,
        )?;
        if !specification.spec().attachment_slots().is_empty() && anchor.is_none() {
            if previously_published {
                return Err(HostCatalogReconciliationError::IncompleteResources);
            }
            continue;
        }
        let attachment_handles =
            match crate::attachment_verification::verified_handles_for_current_assignment(
                journal, binding, mounts,
            ) {
                Ok(handles) => handles,
                Err(crate::AttachmentVerificationError::NotVerifiable) if !previously_published => {
                    continue;
                }
                Err(crate::AttachmentVerificationError::NotVerifiable) => {
                    return Err(HostCatalogReconciliationError::IncompleteResources);
                }
                Err(error) => return Err(error.into()),
            };
        let catalog_assignment = catalog_assignment(binding)?;

        rows.workspaces.push(ProjectedWorkspace {
            handle: *workspace.workspace_handle(),
            assignment: catalog_assignment,
            root_image: workspace.root_image().clone(),
            root_directory: workspace.root_directory().to_owned(),
            device: workspace.root_device(),
            inode: workspace.root_inode(),
            uid_range_start: workspace.uid_range_start(),
            uid_range_size: workspace.uid_range_size(),
            attachment_handles,
        });
        rows.networks.push(ProjectedNetwork {
            handle: *network_row.network_handle(),
            assignment: catalog_assignment,
            namespace_path: network_row.namespace_path().to_owned(),
            device: network_row.namespace_device(),
            inode: network_row.namespace_inode(),
        });
        if let Some(anchor) = anchor {
            rows.anchors.push(ProjectedAnchor {
                handle: *anchor.handle(),
                assignment: catalog_assignment,
                namespace_generation: anchor.namespace_generation(),
                device: anchor.directory_device(),
                inode: anchor.directory_inode(),
                mount_id: anchor.unique_mount_id(),
            });
        }
    }

    rows.workspaces.sort_unstable_by_key(|row| row.handle);
    rows.networks.sort_unstable_by_key(|row| row.handle);
    rows.anchors.sort_unstable_by_key(|row| row.handle);
    if has_duplicate_handles(&rows.workspaces, |row| row.handle)
        || has_duplicate_handles(&rows.networks, |row| row.handle)
        || has_duplicate_handles(&rows.anchors, |row| row.handle)
    {
        return Err(HostCatalogReconciliationError::CorruptState);
    }

    if let Some(previous) = previous {
        for workspace in previous.workspaces() {
            let retained = rows.workspaces.iter().any(|candidate| {
                candidate.handle == *workspace.handle()
                    && candidate.assignment.sandbox_id() == workspace.assignment().sandbox_id()
                    && candidate.assignment.incarnation_id()
                        == workspace.assignment().incarnation_id()
            });
            let incarnation_still_current = bindings.iter().any(|binding| {
                binding.state() == RuntimeAuthorityStateV1::Bound
                    && catalog_incarnation_matches_binding(workspace.assignment(), binding)
            });
            if !retained && incarnation_still_current {
                return Err(HostCatalogReconciliationError::IncompleteResources);
            }
        }
    }

    Ok(rows)
}

fn materialize_catalog(
    generation: u64,
    rows: &ProjectedRows,
    previous: Option<&HostCatalogSnapshot>,
) -> Result<HostCatalogSnapshot, HostCatalogReconciliationError> {
    let workspaces = rows
        .workspaces
        .iter()
        .map(|row| {
            Ok(WorkspaceCatalogEntry::new(
                row.handle,
                row.assignment,
                row.root_image.clone(),
                row.root_directory.clone(),
                row.device,
                row.inode,
                CatalogIdentityAllocation::new(
                    row.uid_range_start,
                    row.uid_range_size,
                    generation,
                )?,
                row.attachment_handles.clone(),
            )?)
        })
        .collect::<Result<Vec<_>, HostCatalogReconciliationError>>()?;
    let networks = rows
        .networks
        .iter()
        .map(|row| {
            NetworkCatalogEntry::new(
                row.handle,
                row.assignment,
                row.namespace_path.clone(),
                row.device,
                row.inode,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = rows
        .anchors
        .iter()
        .map(|row| {
            AttachmentAnchorCatalogEntry::new(
                row.handle,
                row.assignment,
                row.namespace_generation,
                attachment_anchor_path(row.assignment, row.namespace_generation),
                row.device,
                row.inode,
                row.mount_id,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut tombstones = previous.map_or_else(Vec::new, |catalog| {
        catalog.retired_identity_allocations().to_vec()
    });
    if let Some(previous) = previous {
        for workspace in previous.workspaces() {
            let retained = rows.workspaces.iter().any(|candidate| {
                candidate.handle == *workspace.handle()
                    && candidate.assignment.sandbox_id() == workspace.assignment().sandbox_id()
                    && candidate.assignment.incarnation_id()
                        == workspace.assignment().incarnation_id()
            });
            if !retained {
                tombstones.push(workspace.identity());
            }
        }
    }
    tombstones.sort_unstable();
    tombstones.dedup();

    Ok(HostCatalogSnapshot::new(generation, workspaces, networks)?
        .with_attachment_anchors(anchors)?
        .with_retired_identity_allocations(tombstones)?)
}

fn ready_anchor<'a>(
    binding: &RuntimeAuthorityBindingV1,
    required_slots: &[aos_sandbox_core::AttachmentSlotId],
    inventory: &'a ValidatedDestinationSlotInventory,
) -> Result<
    Option<&'a aos_sandbox_protocol::ValidatedAttachmentAnchorInventoryRecord>,
    HostCatalogReconciliationError,
> {
    let assignment = binding.manifest().manifest();
    let slots = inventory
        .slots()
        .iter()
        .filter(|slot| {
            slot.namespace_generation() == assignment.namespace_generation().get()
                && fence_matches_binding(slot.fence(), binding)
        })
        .collect::<Vec<_>>();
    if slots.iter().any(|slot| {
        slot.sandbox_spec() != assignment.sandbox_spec()
            || required_slots
                .binary_search_by_key(slot.destination_slot_id(), |slot| *slot.as_bytes())
                .is_err()
    }) {
        return Err(HostCatalogReconciliationError::CorruptState);
    }
    if slots.len() != required_slots.len()
        || slots.iter().any(|slot| {
            slot.lifecycle() != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY
                || slot.resource_kernel_boot_id() != inventory.kernel_boot_id()
        })
    {
        return Ok(None);
    }
    if required_slots.is_empty() {
        let unexpected_anchor = inventory.attachment_anchors().iter().any(|anchor| {
            anchor.sandbox_id() == assignment.sandbox().as_bytes()
                && anchor.incarnation_id() == assignment.incarnation().as_bytes()
                && anchor.namespace_generation() == assignment.namespace_generation().get()
        });
        if unexpected_anchor {
            return Err(HostCatalogReconciliationError::CorruptState);
        }
        return Ok(None);
    }

    let anchors = inventory.attachment_anchors().iter().filter(|anchor| {
        anchor.sandbox_id() == assignment.sandbox().as_bytes()
            && anchor.incarnation_id() == assignment.incarnation().as_bytes()
            && anchor.namespace_generation() == assignment.namespace_generation().get()
            && anchor.resource_kernel_boot_id() == inventory.kernel_boot_id()
    });
    Ok(exactly_one(anchors))
}

fn unique_matching<T>(
    values: &[T],
    predicate: impl Fn(&T) -> bool,
) -> Result<Option<&T>, HostCatalogReconciliationError> {
    let mut matching = values.iter().filter(|value| predicate(value));
    let first = matching.next();
    if matching.next().is_some() {
        return Err(HostCatalogReconciliationError::CorruptState);
    }

    Ok(first)
}

fn exactly_one<T>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn fence_matches_binding(
    fence: &ValidatedAssignmentFence,
    binding: &RuntimeAuthorityBindingV1,
) -> bool {
    let assignment = binding.manifest().manifest();
    fence.sandbox_id() == assignment.sandbox().as_bytes()
        && fence.incarnation_id() == assignment.incarnation().as_bytes()
        && fence.assignment_epoch() == assignment.epoch().get()
        && fence.desired_generation() == assignment.desired_generation().get()
        && fence.assignment_digest() == binding.assignment_digest().as_bytes()
}

fn catalog_assignment_matches_binding(
    catalog: CatalogAssignment,
    binding: &RuntimeAuthorityBindingV1,
) -> bool {
    let assignment = binding.manifest().manifest();
    catalog.sandbox_id() == assignment.sandbox().as_bytes()
        && catalog.incarnation_id() == assignment.incarnation().as_bytes()
        && catalog.assignment_epoch() == assignment.epoch().get()
        && catalog.desired_generation() == assignment.desired_generation().get()
        && catalog.assignment_digest() == binding.assignment_digest().as_bytes()
}

fn catalog_incarnation_matches_binding(
    catalog: CatalogAssignment,
    binding: &RuntimeAuthorityBindingV1,
) -> bool {
    let assignment = binding.manifest().manifest();
    catalog.sandbox_id() == assignment.sandbox().as_bytes()
        && catalog.incarnation_id() == assignment.incarnation().as_bytes()
}

fn catalog_assignment(
    binding: &RuntimeAuthorityBindingV1,
) -> Result<CatalogAssignment, HostCatalogReconciliationError> {
    let assignment = binding.manifest().manifest();
    Ok(CatalogAssignment::new(
        *assignment.sandbox().as_bytes(),
        *assignment.incarnation().as_bytes(),
        assignment.epoch().get(),
        assignment.desired_generation().get(),
        *binding.assignment_digest().as_bytes(),
    )?)
}

fn same_boot(
    storage: &ValidatedStorageInventory,
    network: &ValidatedNetworkInventory,
    mounts: &ValidatedMountInventory,
    destinations: &ValidatedDestinationSlotInventory,
) -> bool {
    storage.kernel_boot_id() == network.kernel_boot_id()
        && storage.kernel_boot_id() == mounts.kernel_boot_id()
        && storage.kernel_boot_id() == destinations.kernel_boot_id()
}

fn attachment_anchor_path(assignment: CatalogAssignment, namespace_generation: u64) -> String {
    format!(
        "{ATTACHMENT_ANCHOR_PIN_PREFIX}{}/{}/{namespace_generation:016x}",
        encode_hex(assignment.sandbox_id()),
        encode_hex(assignment.incarnation_id()),
    )
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

fn has_duplicate_handles<T>(values: &[T], handle: impl Fn(&T) -> [u8; 32]) -> bool {
    values
        .windows(2)
        .any(|pair| handle(&pair[0]) == handle(&pair[1]))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], HostCatalogReconciliationError> {
    let value = bytes
        .get(..N)
        .ok_or(HostCatalogReconciliationError::CorruptState)?
        .try_into()
        .map_err(|_| HostCatalogReconciliationError::CorruptState)?;
    *bytes = bytes
        .get(N..)
        .ok_or(HostCatalogReconciliationError::CorruptState)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Descriptor, InventoryDestinationSlotsResponse,
        InventoryMountResourcesResponse, InventoryNetworkResourcesResponse,
        InventoryStorageResourcesResponse, NetworkNamespaceInventoryRecord, NetworkState,
        StorageWorkspaceInventoryRecord,
    };
    use aos_sandbox_core::model::{AssignmentManifestV1, SandboxAncestry};
    use aos_sandbox_core::{
        AssignmentEpoch, CanonicalAssignmentManifestV1, DesiredGeneration, FeatureRef,
        IncarnationId, MediaType, NamespaceGeneration, NodeId, PortableMediaType, ProjectId,
        ResourceDimension, ResourceVector, SandboxId,
    };
    use aos_sandbox_protocol::{
        decode_destination_slot_inventory_response_for_version, decode_mount_inventory_response,
        decode_network_resource_inventory_response, decode_storage_resource_inventory_response,
    };
    use buffa::Message as _;
    use tempfile::TempDir;

    use super::*;

    fn descriptor(byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            u64::from(byte),
        )
    }

    fn assignment(byte: u8) -> CatalogAssignment {
        CatalogAssignment::new([byte; 16], [byte + 1; 16], 3, 4, [byte + 2; 32]).unwrap()
    }

    fn current_binding(
        spec: ObjectDescriptor,
        root_view: ObjectDescriptor,
        desired_generation: u64,
    ) -> RuntimeAuthorityBindingV1 {
        let sandbox = SandboxId::from_bytes([7; 16]);
        let manifest = AssignmentManifestV1::new(
            sandbox,
            ProjectId::from_bytes([8; 16]),
            SandboxAncestry::new(sandbox, Vec::new()).unwrap(),
            IncarnationId::from_bytes([9; 16]),
            NodeId::from_bytes([10; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(desired_generation),
            NamespaceGeneration::new(5),
            spec,
            descriptor_for(PortableMediaType::Policy, 11),
            descriptor_for(PortableMediaType::Environment, 12),
            root_view,
            Vec::new(),
            ObjectDigest::from_bytes([13; 32]),
            ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 4096),
            vec![FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap()],
        )
        .unwrap();

        crate::runtime_authority::binding_for_catalog_test(
            CanonicalAssignmentManifestV1::new(manifest),
            RuntimeAuthorityStateV1::Bound,
        )
    }

    fn descriptor_for(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            u64::from(byte),
        )
    }

    fn workspace(byte: u8, generation: u64, range_start: u32) -> WorkspaceCatalogEntry {
        WorkspaceCatalogEntry::new(
            [byte; 32],
            assignment(byte),
            descriptor(byte),
            format!(
                "{}{}",
                aos_sandbox_protocol::WORKSPACE_PIN_PREFIX,
                encode_hex(&[byte; 32])
            ),
            u64::from(byte),
            u64::from(byte + 1),
            CatalogIdentityAllocation::new(range_start, 65_536, generation).unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    fn network(byte: u8) -> NetworkCatalogEntry {
        NetworkCatalogEntry::new(
            [byte; 32],
            assignment(byte),
            format!(
                "{}{}",
                aos_sandbox_protocol::NETWORK_PIN_PREFIX,
                encode_hex(&[byte; 32])
            ),
            u64::from(byte + 2),
            u64::from(byte + 3),
        )
        .unwrap()
    }

    fn record(state: CatalogRecordState, generation: u64) -> CatalogRecord {
        let catalog = HostCatalogSnapshot::new(
            generation,
            vec![workspace(7, generation, 65_536)],
            vec![network(7)],
        )
        .unwrap();
        let mut record = CatalogRecord::pending(
            ObjectDigest::from_bytes([8; 32]),
            [
                ObjectDigest::from_bytes([9; 32]),
                ObjectDigest::from_bytes([10; 32]),
                ObjectDigest::from_bytes([11; 32]),
                ObjectDigest::from_bytes([12; 32]),
            ],
            None,
            catalog,
        )
        .unwrap();
        if state == CatalogRecordState::Current {
            record = record.into_current().unwrap();
        }
        record
    }

    fn projection_inventories(
        binding: &RuntimeAuthorityBindingV1,
    ) -> (
        ValidatedStorageInventory,
        ValidatedNetworkInventory,
        ValidatedMountInventory,
        ValidatedDestinationSlotInventory,
    ) {
        let assignment = binding.manifest().manifest();
        let fence = AssignmentFence {
            sandbox_id: assignment.sandbox().as_bytes().to_vec(),
            incarnation_id: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: binding.assignment_digest().as_bytes().to_vec(),
            ..Default::default()
        };
        let workspace_handle = [21; 32];
        let storage = InventoryStorageResourcesResponse {
            kernel_boot_id: vec![30; 16],
            broker_instance_id: vec![31; 16],
            journal_sequence: 7,
            catalog_generation: 8,
            workspaces: vec![StorageWorkspaceInventoryRecord {
                workspace_handle: workspace_handle.to_vec(),
                fence: Some(fence.clone()).into(),
                root_image: Some(Descriptor {
                    media_type: assignment.root_view().media_type().as_str().to_owned(),
                    sha256: assignment.root_view().digest().as_bytes().to_vec(),
                    encoded_size: assignment.root_view().encoded_size(),
                    ..Default::default()
                })
                .into(),
                resource_kernel_boot_id: vec![30; 16],
                root_device: 40,
                root_inode: 41,
                dataset_guid: 42,
                uid_range_start: 65_536,
                uid_range_size: 65_536,
                resource_digest: vec![43; 32],
                ..Default::default()
            }],
            ..Default::default()
        };
        let network_handle = [22; 32];
        let network = InventoryNetworkResourcesResponse {
            kernel_boot_id: vec![30; 16],
            broker_instance_id: vec![32; 16],
            journal_sequence: 9,
            catalog_generation: 10,
            networks: vec![NetworkNamespaceInventoryRecord {
                network_handle: network_handle.to_vec(),
                fence: Some(fence).into(),
                resource_kernel_boot_id: vec![30; 16],
                namespace_device: 50,
                namespace_inode: 51,
                state: NetworkState::NETWORK_STATE_DEFAULT_DROP.into(),
                resource_digest: vec![52; 32],
                ..Default::default()
            }],
            ..Default::default()
        };
        let mounts = InventoryMountResourcesResponse {
            kernel_boot_id: vec![30; 16],
            broker_instance_id: vec![33; 16],
            journal_sequence: 11,
            ..Default::default()
        };
        let destinations = InventoryDestinationSlotsResponse {
            kernel_boot_id: vec![30; 16],
            broker_instance_id: vec![34; 16],
            journal_sequence: 12,
            ..Default::default()
        };

        (
            decode_storage_resource_inventory_response(&storage.encode_to_vec(), 15 * 1024 * 1024)
                .unwrap(),
            decode_network_resource_inventory_response(&network.encode_to_vec(), 15 * 1024 * 1024)
                .unwrap(),
            decode_mount_inventory_response(&mounts.encode_to_vec(), 15 * 1024 * 1024).unwrap(),
            decode_destination_slot_inventory_response_for_version(
                &destinations.encode_to_vec(),
                15 * 1024 * 1024,
                aos_sandbox_core::ProtocolVersion::new(1, 5),
            )
            .unwrap(),
        )
    }

    #[test]
    fn catalog_record_round_trips_and_rejects_corruption() {
        for state in [CatalogRecordState::Pending, CatalogRecordState::Current] {
            let record = record(state, 1);
            let encoded = record.encode();
            assert_eq!(CatalogRecord::decode(&encoded).unwrap(), record);

            for index in [0, 10, 15, encoded.len() - 1] {
                let mut changed = encoded.clone();
                changed[index] ^= 1;
                assert!(CatalogRecord::decode(&changed).is_err());
            }
        }
    }

    #[test]
    fn durable_catalog_ceiling_reserves_complete_journal_framing() {
        assert_eq!(
            MAXIMUM_DURABLE_CATALOG_BYTES
                + FIXED_RECORD_BYTES
                + JOURNAL_RECORD_HEADER_BYTES
                + PENDING_KEY.len(),
            JOURNAL_RECORD_BYTES
        );
        assert_eq!(PENDING_KEY.len(), CURRENT_KEY.len());
    }

    #[test]
    fn catalog_history_rejects_a_pending_record_with_an_unrelated_predecessor() {
        let directory = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            crate::JournalLimits::default(),
        )
        .unwrap();
        let current = record(CatalogRecordState::Current, 1);
        journal.commit(&current.transaction().unwrap()).unwrap();

        let unrelated_catalog =
            HostCatalogSnapshot::new(1, vec![workspace(8, 1, 131_072)], vec![network(8)]).unwrap();
        let unrelated = CatalogRecord::pending(
            ObjectDigest::from_bytes([21; 32]),
            [
                ObjectDigest::from_bytes([22; 32]),
                ObjectDigest::from_bytes([23; 32]),
                ObjectDigest::from_bytes([24; 32]),
                ObjectDigest::from_bytes([25; 32]),
            ],
            None,
            unrelated_catalog,
        )
        .unwrap()
        .into_current()
        .unwrap();
        let successor_catalog =
            HostCatalogSnapshot::new(2, vec![workspace(7, 2, 65_536)], vec![network(7)]).unwrap();
        let pending = CatalogRecord::pending(
            ObjectDigest::from_bytes([31; 32]),
            [
                ObjectDigest::from_bytes([32; 32]),
                ObjectDigest::from_bytes([33; 32]),
                ObjectDigest::from_bytes([34; 32]),
                ObjectDigest::from_bytes([35; 32]),
            ],
            Some(&unrelated),
            successor_catalog,
        )
        .unwrap();
        journal.commit(&pending.transaction().unwrap()).unwrap();

        assert!(matches!(
            CatalogHistory::load(&mut journal),
            Err(HostCatalogReconciliationError::CorruptState)
        ));
    }

    #[test]
    fn successor_retires_removed_allocations_and_preserves_tombstones() {
        let retired = CatalogIdentityAllocation::new(196_608, 65_536, 1).unwrap();
        let previous = HostCatalogSnapshot::new(
            2,
            vec![workspace(7, 2, 65_536), workspace(8, 2, 131_072)],
            vec![network(7), network(8)],
        )
        .unwrap()
        .with_retired_identity_allocations(vec![retired])
        .unwrap();
        let rows = ProjectedRows {
            workspaces: vec![ProjectedWorkspace {
                handle: [7; 32],
                assignment: assignment(7),
                root_image: descriptor(7),
                root_directory: format!(
                    "{}{}",
                    aos_sandbox_protocol::WORKSPACE_PIN_PREFIX,
                    encode_hex(&[7; 32])
                ),
                device: 7,
                inode: 8,
                uid_range_start: 65_536,
                uid_range_size: 65_536,
                attachment_handles: Vec::new(),
            }],
            networks: vec![ProjectedNetwork {
                handle: [7; 32],
                assignment: assignment(7),
                namespace_path: format!(
                    "{}{}",
                    aos_sandbox_protocol::NETWORK_PIN_PREFIX,
                    encode_hex(&[7; 32])
                ),
                device: 9,
                inode: 10,
            }],
            anchors: Vec::new(),
        };

        let successor = materialize_catalog(3, &rows, Some(&previous)).unwrap();
        assert_eq!(successor.workspaces()[0].identity().catalog_generation(), 3);
        assert_eq!(
            successor.retired_identity_allocations(),
            &[
                CatalogIdentityAllocation::new(131_072, 65_536, 2).unwrap(),
                retired,
            ]
        );
    }

    #[test]
    fn unchanged_projection_reproduces_exact_current_bytes() {
        let current =
            HostCatalogSnapshot::new(2, vec![workspace(7, 2, 65_536)], vec![network(7)]).unwrap();
        let rows = ProjectedRows {
            workspaces: vec![ProjectedWorkspace {
                handle: [7; 32],
                assignment: assignment(7),
                root_image: descriptor(7),
                root_directory: format!(
                    "{}{}",
                    aos_sandbox_protocol::WORKSPACE_PIN_PREFIX,
                    encode_hex(&[7; 32])
                ),
                device: 7,
                inode: 8,
                uid_range_start: 65_536,
                uid_range_size: 65_536,
                attachment_handles: Vec::new(),
            }],
            networks: vec![ProjectedNetwork {
                handle: [7; 32],
                assignment: assignment(7),
                namespace_path: format!(
                    "{}{}",
                    aos_sandbox_protocol::NETWORK_PIN_PREFIX,
                    encode_hex(&[7; 32])
                ),
                device: 9,
                inode: 10,
            }],
            anchors: Vec::new(),
        };

        assert_eq!(
            materialize_catalog(2, &rows, Some(&current)).unwrap(),
            current
        );
    }

    #[test]
    fn exact_current_assignment_projects_complete_broker_resources() {
        let directory = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            crate::JournalLimits::default(),
        )
        .unwrap();
        let spec = crate::sandbox_spec_state::slot_spec_publication_for_test(Vec::new(), 61);
        let spec_descriptor = spec.descriptor().clone();
        crate::sandbox_spec_state::commit(&mut journal, spec).unwrap();
        let root_view = descriptor_for(PortableMediaType::View, 62);
        let binding = current_binding(spec_descriptor, root_view.clone(), 4);
        let (storage, network, mounts, destinations) = projection_inventories(&binding);

        let rows = collect_rows(
            &mut journal,
            std::slice::from_ref(&binding),
            &storage,
            &network,
            &mounts,
            &destinations,
            None,
        )
        .unwrap();
        let catalog = materialize_catalog(1, &rows, None).unwrap();

        assert_eq!(catalog.workspaces().len(), 1);
        assert_eq!(catalog.networks().len(), 1);
        assert!(catalog.attachment_anchors().is_empty());
        assert_eq!(catalog.workspaces()[0].root_image(), &root_view);
        assert_eq!(catalog.workspaces()[0].handle(), &[21; 32]);
        assert_eq!(catalog.networks()[0].handle(), &[22; 32]);
        assert!(catalog.workspaces()[0].attachment_handles().is_empty());
    }

    #[test]
    fn published_current_assignment_cannot_disappear_on_incomplete_inventory() {
        let directory = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            crate::JournalLimits::default(),
        )
        .unwrap();
        let spec = crate::sandbox_spec_state::slot_spec_publication_for_test(Vec::new(), 71);
        let spec_descriptor = spec.descriptor().clone();
        crate::sandbox_spec_state::commit(&mut journal, spec).unwrap();
        let binding = current_binding(
            spec_descriptor,
            descriptor_for(PortableMediaType::View, 72),
            4,
        );
        let (storage, network, mounts, destinations) = projection_inventories(&binding);
        let current_rows = collect_rows(
            &mut journal,
            std::slice::from_ref(&binding),
            &storage,
            &network,
            &mounts,
            &destinations,
            None,
        )
        .unwrap();
        let current = materialize_catalog(1, &current_rows, None).unwrap();
        let empty_storage = InventoryStorageResourcesResponse {
            kernel_boot_id: vec![30; 16],
            broker_instance_id: vec![31; 16],
            journal_sequence: 8,
            catalog_generation: 9,
            ..Default::default()
        };
        let empty_storage = decode_storage_resource_inventory_response(
            &empty_storage.encode_to_vec(),
            15 * 1024 * 1024,
        )
        .unwrap();

        assert!(matches!(
            collect_rows(
                &mut journal,
                std::slice::from_ref(&binding),
                &empty_storage,
                &network,
                &mounts,
                &destinations,
                Some(&current),
            ),
            Err(HostCatalogReconciliationError::IncompleteResources)
        ));
    }

    #[test]
    fn assignment_successor_waits_for_resources_before_retiring_its_incarnation() {
        let directory = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            crate::JournalLimits::default(),
        )
        .unwrap();
        let spec = crate::sandbox_spec_state::slot_spec_publication_for_test(Vec::new(), 81);
        let spec_descriptor = spec.descriptor().clone();
        crate::sandbox_spec_state::commit(&mut journal, spec).unwrap();
        let root_view = descriptor_for(PortableMediaType::View, 82);
        let prior_binding = current_binding(spec_descriptor.clone(), root_view.clone(), 4);
        let (storage, network, mounts, destinations) = projection_inventories(&prior_binding);
        let current_rows = collect_rows(
            &mut journal,
            std::slice::from_ref(&prior_binding),
            &storage,
            &network,
            &mounts,
            &destinations,
            None,
        )
        .unwrap();
        let current = materialize_catalog(1, &current_rows, None).unwrap();
        let successor_binding = current_binding(spec_descriptor, root_view, 5);

        assert!(matches!(
            collect_rows(
                &mut journal,
                std::slice::from_ref(&successor_binding),
                &storage,
                &network,
                &mounts,
                &destinations,
                Some(&current),
            ),
            Err(HostCatalogReconciliationError::IncompleteResources)
        ));
    }

    #[test]
    fn durable_pending_catalog_advances_only_after_confirmation_commit() {
        let directory = TempDir::new().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            crate::JournalLimits::default(),
        )
        .unwrap();
        let pending = record(CatalogRecordState::Pending, 1);
        journal.commit(&pending.transaction().unwrap()).unwrap();

        let recovered = CatalogHistory::load(&mut journal).unwrap();
        assert_eq!(recovered.pending.as_ref(), Some(&pending));
        assert!(recovered.current.is_none());
        let recovered_pending = recover_pending(&mut journal).unwrap().unwrap();
        assert_eq!(recovered_pending.generation(), pending.catalog.generation());
        assert_eq!(
            recovered_pending.canonical_catalog(),
            pending.canonical_catalog
        );

        journal
            .commit(&pending.completion_transaction().unwrap())
            .unwrap();
        let recovered = CatalogHistory::load(&mut journal).unwrap();
        assert!(recovered.pending.is_none());
        assert_eq!(
            recovered.current.unwrap().catalog_digest,
            pending.catalog_digest
        );
    }
}
