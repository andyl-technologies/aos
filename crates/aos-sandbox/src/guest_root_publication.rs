//! Protected controller reservation for guest-root publication.
//!
//! Storage inventory names a workspace, but cannot authorize a population
//! effect. This record fixes one effect operation before the controller sends
//! method 31. After a crash, the controller reuses the same operation and
//! requires a fresh authenticated inventory proof before accepting readiness.
//!
//! ```text
//! AOSGRR01 | operation[16] | sandbox[16] | incarnation[16]
//!          | epoch:u64be | generation:u64be | assignment_digest[32]
//!          | workspace_handle[32] | creation_operation[16]
//!          | dataset_guid:u64be | root_image_digest[32]
//!          | package_binding[32] | root_tree_digest[32]
//!          | initial_inventory_digest[32] | sha256[32]
//! ```

use std::collections::BTreeSet;

use aos_sandbox_agent::guest_root_publication::{
    CONCRETE_GUEST_FEATURE_MASK_V1, GuestRootPublicationProofV1,
};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, NodeId, OperationId, ProtocolId,
    ProtocolVersion, SandboxId,
};
use aos_sandbox_protocol::semantics::CanonicalStorageGuestRootArgumentsV1;
use aos_sandbox_protocol::storage_inventory::ValidatedStorageWorkspace;
use sha2::{Digest as _, Sha256};

use crate::publication::AuthorityPublicationStore;
use crate::{
    DurableStorageResourceInventorySnapshotV1, Journal, JournalRecord, JournalTransaction,
    RecordNamespace,
};

const MAGIC: &[u8; 8] = b"AOSGRR01";
const BODY_BYTES: usize = 8 + 16 + 16 + 16 + 8 + 8 + 32 + 32 + 16 + 8 + 32 + 32 + 32 + 32;
const VALUE_BYTES: usize = BODY_BYTES + 32;

/// Pins the immutable package identity supplied by deployment credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestRootTemplatePinsV1 {
    package_binding: [u8; 32],
    root_tree_digest: [u8; 32],
}

impl GuestRootTemplatePinsV1 {
    /// Validates nonzero, independently provisioned template digests.
    ///
    /// # Errors
    ///
    /// Rejects an absent package or tree digest.
    pub fn new(
        package_binding: [u8; 32],
        root_tree_digest: [u8; 32],
    ) -> Result<Self, GuestRootPublicationErrorV1> {
        if package_binding == [0; 32] || root_tree_digest == [0; 32] {
            return Err(GuestRootPublicationErrorV1::InvalidPins);
        }
        Ok(Self {
            package_binding,
            root_tree_digest,
        })
    }

    /// Returns the pinned package-closure binding.
    #[must_use]
    pub const fn package_binding(self) -> [u8; 32] {
        self.package_binding
    }

    /// Returns the pinned complete template-tree digest.
    #[must_use]
    pub const fn root_tree_digest(self) -> [u8; 32] {
        self.root_tree_digest
    }
}

/// Retains one immutable, journal-backed workspace publication operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestRootPublicationReservationV1 {
    operation: OperationId,
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    epoch: u64,
    generation: u64,
    assignment_digest: [u8; 32],
    workspace_handle: [u8; 32],
    creation_operation: [u8; 16],
    dataset_guid: u64,
    root_image_digest: [u8; 32],
    pins: GuestRootTemplatePinsV1,
    initial_inventory_digest: [u8; 32],
}

/// Carries a fresh independent Storage plan and the exact current lease.
pub struct GuestRootPublicationPlanDraftV1 {
    plan: BrokerAuthorizationPlan,
    lease: Vec<u8>,
    lease_signature: Vec<u8>,
}

impl GuestRootPublicationPlanDraftV1 {
    /// Moves the plan and lease into the controller's protected signing owner.
    #[must_use]
    pub fn into_parts(self) -> (BrokerAuthorizationPlan, Vec<u8>, Vec<u8>) {
        (self.plan, self.lease, self.lease_signature)
    }
}

impl GuestRootPublicationReservationV1 {
    /// Returns the stable effect operation reused after ambiguous dispatch.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the selected workspace handle.
    #[must_use]
    pub const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    /// Returns the operation that created the selected workspace.
    #[must_use]
    pub const fn creation_operation(&self) -> [u8; 16] {
        self.creation_operation
    }

    /// Returns the immutable template pins bound to this reservation.
    #[must_use]
    pub const fn pins(&self) -> GuestRootTemplatePinsV1 {
        self.pins
    }

    /// Returns the reserved assignment's sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        SandboxId::from_bytes(self.sandbox)
    }

    /// Returns the request fence bound to the selected current assignment.
    #[must_use]
    pub const fn assignment_fence(&self) -> ([u8; 16], u64, u64, [u8; 32]) {
        (
            self.incarnation,
            self.epoch,
            self.generation,
            self.assignment_digest,
        )
    }

    /// Checks a signed method-31 response before fresh inventory readback.
    ///
    /// # Errors
    ///
    /// Rejects any foreign workspace, assignment, dataset, or template pin.
    pub fn verify_response_proof(
        &self,
        proof: GuestRootPublicationProofV1,
    ) -> Result<(), GuestRootPublicationErrorV1> {
        if proof.sandbox != self.sandbox
            || proof.incarnation != self.incarnation
            || proof.assignment_epoch != self.epoch
            || proof.assignment_digest != self.assignment_digest
            || proof.creation_operation != self.creation_operation
            || proof.workspace_handle != self.workspace_handle
            || proof.dataset_guid != self.dataset_guid
            || proof.root_image_digest != self.root_image_digest
            || proof.package_binding != self.pins.package_binding
            || proof.root_tree_digest != self.pins.root_tree_digest
            || proof.feature_mask != CONCRETE_GUEST_FEATURE_MASK_V1
        {
            return Err(GuestRootPublicationErrorV1::ProofMismatch);
        }
        Ok(())
    }

    /// Returns the initially authenticated inventory record digest.
    #[must_use]
    pub const fn initial_inventory_digest(&self) -> [u8; 32] {
        self.initial_inventory_digest
    }

    fn from_workspace(
        operation: OperationId,
        workspace: &ValidatedStorageWorkspace,
        pins: GuestRootTemplatePinsV1,
        inventory_digest: [u8; 32],
    ) -> Self {
        let fence = workspace.fence();
        Self {
            operation,
            sandbox: *fence.sandbox_id(),
            incarnation: *fence.incarnation_id(),
            epoch: fence.assignment_epoch(),
            generation: fence.desired_generation(),
            assignment_digest: *fence.assignment_digest(),
            workspace_handle: *workspace.workspace_handle(),
            creation_operation: *workspace.creation_operation_id(),
            dataset_guid: workspace.dataset_guid(),
            root_image_digest: *workspace.root_image().digest().as_bytes(),
            pins,
            initial_inventory_digest: inventory_digest,
        }
    }

    fn matches_workspace(&self, workspace: &ValidatedStorageWorkspace) -> bool {
        let fence = workspace.fence();
        self.sandbox == *fence.sandbox_id()
            && self.incarnation == *fence.incarnation_id()
            && self.epoch == fence.assignment_epoch()
            && self.generation == fence.desired_generation()
            && self.assignment_digest == *fence.assignment_digest()
            && self.workspace_handle == *workspace.workspace_handle()
            && self.creation_operation == *workspace.creation_operation_id()
            && self.dataset_guid == workspace.dataset_guid()
            && self.root_image_digest == *workspace.root_image().digest().as_bytes()
    }

    /// Checks a fresh authenticated Storage inventory row against this record.
    ///
    /// # Errors
    ///
    /// Rejects a replaced workspace or a foreign physical proof. An absent
    /// proof is reported as false and never establishes readiness.
    pub fn readback_matches(
        &self,
        workspace: &ValidatedStorageWorkspace,
    ) -> Result<bool, GuestRootPublicationErrorV1> {
        if !self.matches_workspace(workspace) {
            return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
        }
        let Some(proof) = workspace.guest_root_publication_proof() else {
            return Ok(false);
        };
        verify_proof(workspace, proof, self.pins)?;
        Ok(true)
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(VALUE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(&self.sandbox);
        bytes.extend_from_slice(&self.incarnation);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.assignment_digest);
        bytes.extend_from_slice(&self.workspace_handle);
        bytes.extend_from_slice(&self.creation_operation);
        bytes.extend_from_slice(&self.dataset_guid.to_be_bytes());
        bytes.extend_from_slice(&self.root_image_digest);
        bytes.extend_from_slice(&self.pins.package_binding);
        bytes.extend_from_slice(&self.pins.root_tree_digest);
        bytes.extend_from_slice(&self.initial_inventory_digest);
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, GuestRootPublicationErrorV1> {
        if bytes.len() != VALUE_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(GuestRootPublicationErrorV1::Corrupt);
        }
        let checksum: [u8; 32] = Sha256::digest(&bytes[..BODY_BYTES]).into();
        if bytes[BODY_BYTES..] != checksum {
            return Err(GuestRootPublicationErrorV1::Corrupt);
        }
        let field = |offset: usize| -> Result<[u8; 16], GuestRootPublicationErrorV1> {
            bytes[offset..offset + 16]
                .try_into()
                .map_err(|_| GuestRootPublicationErrorV1::Corrupt)
        };
        let digest = |offset: usize| -> Result<[u8; 32], GuestRootPublicationErrorV1> {
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| GuestRootPublicationErrorV1::Corrupt)
        };
        let number = |offset: usize| -> Result<u64, GuestRootPublicationErrorV1> {
            Ok(u64::from_be_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .map_err(|_| GuestRootPublicationErrorV1::Corrupt)?,
            ))
        };
        let reservation = Self {
            operation: OperationId::from_bytes(field(8)?),
            sandbox: field(24)?,
            incarnation: field(40)?,
            epoch: number(56)?,
            generation: number(64)?,
            assignment_digest: digest(72)?,
            workspace_handle: digest(104)?,
            creation_operation: field(136)?,
            dataset_guid: number(152)?,
            root_image_digest: digest(160)?,
            pins: GuestRootTemplatePinsV1::new(digest(192)?, digest(224)?)
                .map_err(|_| GuestRootPublicationErrorV1::Corrupt)?,
            initial_inventory_digest: digest(256)?,
        };
        if key != reservation.workspace_handle
            || reservation.operation.as_bytes() == &[0; 16]
            || reservation.operation.as_bytes() == &reservation.creation_operation
            || reservation.sandbox == [0; 16]
            || reservation.incarnation == [0; 16]
            || reservation.epoch == 0
            || reservation.generation == 0
            || reservation.assignment_digest == [0; 32]
            || reservation.creation_operation == [0; 16]
            || reservation.dataset_guid == 0
            || reservation.root_image_digest == [0; 32]
            || reservation.initial_inventory_digest == [0; 32]
        {
            return Err(GuestRootPublicationErrorV1::Corrupt);
        }
        Ok(reservation)
    }
}

/// Reports why protected guest-root publication cannot advance.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootPublicationErrorV1 {
    /// Deployment omitted or corrupted a required immutable package pin.
    #[error("guest-root template pins are invalid")]
    InvalidPins,
    /// The protected controller record is malformed.
    #[error("guest-root reservation is corrupt")]
    Corrupt,
    /// A newer assignment or physical workspace replaced the reserved one.
    #[error("guest-root workspace or assignment changed")]
    WorkspaceChanged,
    /// A physically reported root does not match the independently pinned template.
    #[error("guest-root physical proof does not match protected inputs")]
    ProofMismatch,
    /// The protected journal or current authority is unavailable.
    #[error("guest-root publication authority is unavailable")]
    Unavailable,
    /// Fresh physical inventory requires a separately authorized Storage31 effect.
    #[error("guest-root publication requires an independently authorized Storage31 effect")]
    PublicationRequired,
}

/// Reserves the first current workspace lacking a verified guest root.
///
/// A returned operation is durable before any broker request is sent. A
/// matching prior reservation is reused byte-for-byte after restart. Proofs
/// in the inventory are observations only; they are checked against deployment
/// pins but are not used to authorize a new effect.
///
/// # Errors
///
/// Rejects stale inventory, malformed reservations, changed workspaces,
/// mismatched physical proofs, or journal failure.
pub(crate) fn reserve_first_guest_root_v1(
    journal: &mut Journal,
    snapshot: &DurableStorageResourceInventorySnapshotV1,
    node: NodeId,
    pins: GuestRootTemplatePinsV1,
) -> Result<Option<GuestRootPublicationReservationV1>, GuestRootPublicationErrorV1> {
    let Some(selection) = select_first_guest_root_data_v3(journal, snapshot, node, Some(pins), false)? else {
        return Ok(None);
    };
    if let Some(reservation) = selection.existing_reservation_data_v3() {
        return Ok(Some(reservation));
    }
    let assembly = selection.assemble_new_data_v3(OperationId::new(), OperationId::new().into_bytes())?;
    journal.commit(assembly.transaction_v3())
        .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    Ok(Some(assembly.reservation_data_v3()))
}

/// Checks the current reservation selector without issuing a guest-root effect.
///
/// The genuine Maintenance borrower prepays complete C semantic models and
/// retains its exact signed Storage snapshot. Inspection follows the same
/// assignment/lease/proof checks, refusing before operation or transaction
/// construction. An absent physical row cannot settle a retained reservation.
///
/// # Errors
/// Refuses required31, stale inventory, malformed reservations, missing pins,
/// changed current assignment/lease or an independently mismatched root proof.
pub(crate) fn require_no_guest_root_publication_v2(
    journal: &mut Journal,
    snapshot: &DurableStorageResourceInventorySnapshotV1,
    node: NodeId,
    pins: Option<GuestRootTemplatePinsV1>,
) -> Result<(), GuestRootPublicationErrorV1> {
    match select_first_guest_root_data_v3(journal, snapshot, node, pins, true)? {
        None => Ok(()),
        Some(_) => Err(GuestRootPublicationErrorV1::PublicationRequired),
    }
}

fn select_first_guest_root_data_v3<'snapshot>(
    journal: &mut Journal,
    snapshot: &'snapshot DurableStorageResourceInventorySnapshotV1,
    node: NodeId,
    pins: Option<GuestRootTemplatePinsV1>,
    require_present: bool,
) -> Result<Option<GuestRootPublicationSelectionDataV3<'snapshot>>, GuestRootPublicationErrorV1> {
    snapshot
        .recheck(journal)
        .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    let used_operations = require_reservation_history_data_v2(
        journal, snapshot.inventory(), require_present)?;
    for workspace in snapshot.inventory().workspaces() {
        let pins = pins.ok_or(GuestRootPublicationErrorV1::InvalidPins)?;
        let sandbox = SandboxId::from_bytes(*workspace.fence().sandbox_id());
        let current = AuthorityPublicationStore::new(journal)
            .current(sandbox)
            .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?
            .ok_or(GuestRootPublicationErrorV1::Unavailable)?;
        let assignment = current
            .manifest()
            .broker_assignment()
            .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
        let fence = workspace.fence();
        if current.manifest().manifest().node() != node
            || assignment.sandbox().as_bytes() != fence.sandbox_id()
            || assignment.incarnation().as_bytes() != fence.incarnation_id()
            || assignment.epoch().get() != fence.assignment_epoch()
            || assignment.desired_generation().get() != fence.desired_generation()
            || assignment.digest().as_bytes() != fence.assignment_digest()
            || current.lease().lease().assignment().sandbox() != assignment.sandbox()
            || current.lease().lease().assignment().incarnation() != assignment.incarnation()
            || current.lease().lease().assignment().epoch() != assignment.epoch()
            || current.lease().lease().assignment().digest() != assignment.digest()
            || current.lease().lease().node() != node
        {
            return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
        }
        if let Some(proof) = workspace.guest_root_publication_proof() {
            if let Some(value) = journal.get(
                RecordNamespace::GuestRootPublication,
                workspace.workspace_handle(),
            ) {
                let existing =
                    GuestRootPublicationReservationV1::decode(workspace.workspace_handle(), value)?;
                if existing.pins != pins || !existing.matches_workspace(workspace) {
                    return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
                }
            }
            verify_proof(workspace, proof, pins)?;
            continue;
        }

        let key = workspace.workspace_handle();
        if let Some(value) = journal.get(RecordNamespace::GuestRootPublication, key) {
            let pending = GuestRootPublicationReservationV1::decode(key, value)?;
            if pending.pins != pins || !pending.matches_workspace(workspace) {
                return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
            }
            return Ok(Some(GuestRootPublicationSelectionDataV3 {
                selected: GuestRootSelectionDataV3::Existing(pending),
                used_operations,
            }));
        }
        return Ok(Some(GuestRootPublicationSelectionDataV3 {
            selected: GuestRootSelectionDataV3::New {
                workspace,
                pins,
                inventory_digest: *snapshot.record_digest().as_bytes(),
            },
            used_operations,
        }));
    }
    Ok(None)
}

/// Holds only the canonical selector's passive reservation/workspace DATA.
///
/// This value grants no entropy, append, Root flight or Storage effect. Its
/// private construction shares every current assignment, lease, pin and
/// reservation-roster check with the ordinary selector above.
pub(crate) struct GuestRootPublicationSelectionDataV3<'snapshot> {
    selected: GuestRootSelectionDataV3<'snapshot>,
    used_operations: BTreeSet<[u8; 16]>,
}

enum GuestRootSelectionDataV3<'snapshot> {
    Existing(GuestRootPublicationReservationV1),
    New {
        workspace: &'snapshot ValidatedStorageWorkspace,
        pins: GuestRootTemplatePinsV1,
        inventory_digest: [u8; 32],
    },
}

impl GuestRootPublicationSelectionDataV3<'_> {
    pub(crate) fn existing_reservation_data_v3(&self) -> Option<GuestRootPublicationReservationV1> {
        match self.selected {
            GuestRootSelectionDataV3::Existing(reservation) => Some(reservation),
            GuestRootSelectionDataV3::New { .. } => None,
        }
    }

    /// Assembles bytes only after the actual owner has paid and sampled entropy.
    pub(crate) fn assemble_new_data_v3(
        self,
        operation: OperationId,
        transaction_id: [u8; 16],
    ) -> Result<GuestRootPublicationAssemblyDataV3, GuestRootPublicationErrorV1> {
        let GuestRootSelectionDataV3::New { workspace, pins, inventory_digest } = self.selected else {
            return Err(GuestRootPublicationErrorV1::Corrupt);
        };
        if operation.as_bytes() == &[0; 16]
            || transaction_id == [0; 16]
            || operation.as_bytes() == &transaction_id
            || self.used_operations.contains(operation.as_bytes())
            || operation.as_bytes() == workspace.creation_operation_id()
        {
            return Err(GuestRootPublicationErrorV1::Unavailable);
        }
        let reservation = GuestRootPublicationReservationV1::from_workspace(
            operation, workspace, pins, inventory_digest);
        let record = JournalRecord::put(
            RecordNamespace::GuestRootPublication,
            workspace.workspace_handle().to_vec(),
            reservation.encode(),
        );
        let transaction = JournalTransaction::new(transaction_id, vec![record])
            .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
        Ok(GuestRootPublicationAssemblyDataV3 { reservation, transaction })
    }
}

/// Owns the exact canonical new-reservation transaction, without a payer.
pub(crate) struct GuestRootPublicationAssemblyDataV3 {
    reservation: GuestRootPublicationReservationV1,
    transaction: JournalTransaction,
}

impl GuestRootPublicationAssemblyDataV3 {
    /// Covers the bounded record and co-live canonical construction backing.
    pub(crate) fn construction_demand_data_v3() -> Result<aos_sandbox_core::ResourceVector, crate::JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<JournalRecord>()))
            .and_then(|bytes| bytes.checked_add(VALUE_BYTES.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(32))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(crate::JournalError::JournalTooLarge)?;
        Ok(aos_sandbox_core::ResourceVector::ZERO
            .with(aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
    }

    pub(crate) fn reservation_data_v3(&self) -> GuestRootPublicationReservationV1 {
        self.reservation
    }

    pub(crate) fn transaction_v3(&self) -> &JournalTransaction {
        &self.transaction
    }

    /// Refuses another transaction or a reservation written since selection.
    pub(crate) fn require_transaction_v3(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::JournalError> {
        if transaction != &self.transaction
            || controller.get(RecordNamespace::GuestRootPublication,
                &self.reservation.workspace_handle).is_some()
        {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

/// Selects the actual held Maintenance snapshot without issuing an operation.
///
/// Missing physical rows retain reservation debt. A prior operation is reused
/// unchanged; a new selection can only assemble passive bytes and must still
/// cross the genuine owner's paid entropy and canonical native append kernel.
pub(crate) fn select_maintenance_guest_root_data_v3<'snapshot>(
    journal: &mut Journal,
    snapshot: &'snapshot DurableStorageResourceInventorySnapshotV1,
    node: NodeId,
    pins: Option<GuestRootTemplatePinsV1>,
) -> Result<Option<GuestRootPublicationSelectionDataV3<'snapshot>>, GuestRootPublicationErrorV1> {
    select_first_guest_root_data_v3(journal, snapshot, node, pins, true)
}

fn require_reservation_history_data_v2(
    journal: &Journal,
    inventory: &aos_sandbox_protocol::ValidatedStorageInventory,
    require_present: bool,
) -> Result<BTreeSet<[u8; 16]>, GuestRootPublicationErrorV1> {
    let mut used_operations = BTreeSet::new();
    for (key, value) in journal.records(RecordNamespace::GuestRootPublication) {
        let existing = GuestRootPublicationReservationV1::decode(key, value)?;
        if !used_operations.insert(*existing.operation.as_bytes()) {
            return Err(GuestRootPublicationErrorV1::Corrupt);
        }
        if require_present && !inventory.workspaces().iter().any(|workspace| {
            workspace.workspace_handle() == &existing.workspace_handle
        }) {
            // Absence cannot settle retained reservation debt. Any deletion or
            // cleanup requires its own actual current authorization and owner.
            return Err(GuestRootPublicationErrorV1::PublicationRequired);
        }
    }
    Ok(used_operations)
}

/// Borrows an exact current reservation/workspace relation as comparison DATA.
///
/// This value has no lease, native currentness, Root permit or financial owner.
/// Both native endpoints still authenticate the actual current C/Source and
/// signed Session Inventory while their paid originals remain held.
pub(crate) struct ReservedGuestRootWorkspaceDataV2<'inventory> {
    reservation: GuestRootPublicationReservationV1,
    workspace: &'inventory ValidatedStorageWorkspace,
    arguments: CanonicalStorageGuestRootArgumentsV1,
}

impl ReservedGuestRootWorkspaceDataV2<'_> {
    pub(crate) fn reservation_v2(&self) -> &GuestRootPublicationReservationV1 {
        &self.reservation
    }

    pub(crate) fn workspace_v2(&self) -> &ValidatedStorageWorkspace {
        self.workspace
    }

    pub(crate) fn arguments_v2(&self) -> &CanonicalStorageGuestRootArgumentsV1 {
        &self.arguments
    }
}

/// Joins the exact protected record to current assignment and signed workspace DATA.
///
/// The caller independently owns native current C, enrolled node and verified
/// current assignment/lease. This recipe shares the sole reservation decoder
/// and complete reservation roster scan; it performs no IO or mutation.
pub(crate) fn reserved_guest_root_workspace_data_v2<'inventory>(
    journal: &Journal,
    manifest: &aos_sandbox_core::CanonicalAssignmentManifestV1,
    inventory: &'inventory aos_sandbox_protocol::ValidatedStorageInventory,
    reservation_bytes: &[u8],
    enrolled_node: NodeId,
) -> Result<ReservedGuestRootWorkspaceDataV2<'inventory>, GuestRootPublicationErrorV1> {
    require_reservation_history_data_v2(journal, inventory, true)?;
    let reservation = current_guest_root_reservation_data_v2(journal, reservation_bytes)?;
    let assignment = manifest.broker_assignment()
        .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    if manifest.manifest().node() != enrolled_node
        || assignment.sandbox().as_bytes() != &reservation.sandbox
        || assignment.incarnation().as_bytes() != &reservation.incarnation
        || assignment.epoch().get() != reservation.epoch
        || assignment.desired_generation().get() != reservation.generation
        || assignment.digest().as_bytes() != &reservation.assignment_digest
    {
        return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
    }
    let mut workspaces = inventory.workspaces().iter().filter(|workspace| {
        workspace.fence().sandbox_id() == &reservation.sandbox
    });
    let workspace = workspaces.next().ok_or(GuestRootPublicationErrorV1::Unavailable)?;
    if workspaces.next().is_some() || !reservation.matches_workspace(workspace) {
        return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
    }
    if let Some(proof) = workspace.guest_root_publication_proof() {
        reservation.verify_response_proof(proof)?;
    }
    let arguments = CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
        assignment, reservation.operation.into_bytes(), reservation.workspace_handle,
        reservation.creation_operation,
    ).map_err(|_| GuestRootPublicationErrorV1::WorkspaceChanged)?;
    Ok(ReservedGuestRootWorkspaceDataV2 { reservation, workspace, arguments })
}

pub(crate) fn current_guest_root_reservation_data_v2(
    journal: &Journal,
    reservation_bytes: &[u8],
) -> Result<GuestRootPublicationReservationV1, GuestRootPublicationErrorV1> {
    let mut records = journal.records(RecordNamespace::GuestRootPublication)
        .filter(|(_, value)| *value == reservation_bytes);
    let (key, value) = records.next().ok_or(GuestRootPublicationErrorV1::Unavailable)?;
    if records.next().is_some() {
        return Err(GuestRootPublicationErrorV1::Corrupt);
    }
    GuestRootPublicationReservationV1::decode(key, value)
}

/// Derives a new Storage-only grant from the reserved operation and live lease.
///
/// The prior workspace-creation template supplies only pinned policy and
/// ownership-authority semantics. Its deadline and Create grant are never
/// copied into this method-31 plan.
///
/// # Errors
///
/// Rejects a changed reservation, assignment, node, template, or lease, or
/// an invalid fresh interval or Storage argument commitment.
pub(crate) fn prepare_guest_root_plan_v1(
    journal: &mut Journal,
    reservation: &GuestRootPublicationReservationV1,
    node: NodeId,
    now_seconds: i64,
) -> Result<GuestRootPublicationPlanDraftV1, GuestRootPublicationErrorV1> {
    let stored = journal
        .get(
            RecordNamespace::GuestRootPublication,
            &reservation.workspace_handle,
        )
        .ok_or(GuestRootPublicationErrorV1::Unavailable)?;
    if GuestRootPublicationReservationV1::decode(&reservation.workspace_handle, stored)?
        != *reservation
    {
        return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
    }
    let current = AuthorityPublicationStore::new(journal)
        .current(reservation.sandbox())
        .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?
        .ok_or(GuestRootPublicationErrorV1::Unavailable)?;
    let manifest = current.manifest();
    let assignment = manifest
        .broker_assignment()
        .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    let lease = current.lease().lease();
    if manifest.manifest().node() != node
        || assignment.sandbox().as_bytes() != &reservation.sandbox
        || assignment.incarnation().as_bytes() != &reservation.incarnation
        || assignment.epoch().get() != reservation.epoch
        || assignment.desired_generation().get() != reservation.generation
        || assignment.digest().as_bytes() != &reservation.assignment_digest
        || lease.assignment().sandbox() != assignment.sandbox()
        || lease.assignment().incarnation() != assignment.incarnation()
        || lease.assignment().epoch() != assignment.epoch()
        || lease.assignment().digest() != assignment.digest()
        || lease.node() != node
        || now_seconds < lease.authority_issued_seconds()
    {
        return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
    }
    let expires_seconds = now_seconds
        .checked_add(30)
        .ok_or(GuestRootPublicationErrorV1::Unavailable)?
        .min(lease.authority_expires_seconds());
    if expires_seconds <= now_seconds {
        return Err(GuestRootPublicationErrorV1::Unavailable);
    }
    let template = current
        .templates()
        .iter()
        .find(|candidate| candidate.audience() == BrokerAudience::Storage)
        .ok_or(GuestRootPublicationErrorV1::Unavailable)?;
    let parent = template.plan();
    if parent.assignment() != assignment
        || parent.node() != node
        || parent.protocol() != ProtocolId::StorageBroker
        || parent.protocol_version() != ProtocolVersion::new(1, 0)
    {
        return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
    }
    let arguments = CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
        assignment,
        *reservation.operation.as_bytes(),
        reservation.workspace_handle,
        reservation.creation_operation,
    )
    .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    let grant = BrokerGrant::new(
        aos_sandbox_core::BrokerVerb::StoragePopulateGuestRoot,
        aos_sandbox_core::BrokerGrantTarget::Assignment,
        arguments.argument_commitment(),
        4096,
        0,
    )
    .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Storage,
        ProtocolId::StorageBroker,
        ProtocolVersion::new(1, 0),
        assignment,
        node,
        parent.ownership_authority().clone(),
        vec![grant],
        parent.policy_commitment(),
        parent.revocation_scope(),
        now_seconds,
        expires_seconds,
        Vec::new(),
    )
    .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    Ok(GuestRootPublicationPlanDraftV1 {
        plan,
        lease: current.lease().canonical_lease().to_vec(),
        lease_signature: current.lease().canonical_signature().to_vec(),
    })
}

/// Requires a new authenticated Storage snapshot to contain the matching root.
///
/// # Errors
///
/// Rejects a stale snapshot, missing or changed workspace, foreign proof, or
/// changed protected reservation.
pub(crate) fn verify_guest_root_readback_v1(
    journal: &mut Journal,
    snapshot: &DurableStorageResourceInventorySnapshotV1,
    reservation: &GuestRootPublicationReservationV1,
) -> Result<bool, GuestRootPublicationErrorV1> {
    snapshot
        .recheck(journal)
        .map_err(|_| GuestRootPublicationErrorV1::Unavailable)?;
    let stored = journal
        .get(
            RecordNamespace::GuestRootPublication,
            &reservation.workspace_handle,
        )
        .ok_or(GuestRootPublicationErrorV1::Unavailable)?;
    if GuestRootPublicationReservationV1::decode(&reservation.workspace_handle, stored)?
        != *reservation
    {
        return Err(GuestRootPublicationErrorV1::WorkspaceChanged);
    }
    let workspace = snapshot
        .inventory()
        .workspaces()
        .iter()
        .find(|workspace| workspace.workspace_handle() == &reservation.workspace_handle)
        .ok_or(GuestRootPublicationErrorV1::WorkspaceChanged)?;
    reservation.readback_matches(workspace)
}

fn verify_proof(
    workspace: &ValidatedStorageWorkspace,
    proof: GuestRootPublicationProofV1,
    pins: GuestRootTemplatePinsV1,
) -> Result<(), GuestRootPublicationErrorV1> {
    let fence = workspace.fence();
    if proof.sandbox != *fence.sandbox_id()
        || proof.incarnation != *fence.incarnation_id()
        || proof.assignment_epoch != fence.assignment_epoch()
        || proof.assignment_digest != *fence.assignment_digest()
        || proof.creation_operation != *workspace.creation_operation_id()
        || proof.workspace_handle != *workspace.workspace_handle()
        || proof.dataset_guid != workspace.dataset_guid()
        || proof.root_image_digest != *workspace.root_image().digest().as_bytes()
        || proof.package_binding != pins.package_binding
        || proof.root_tree_digest != pins.root_tree_digest
        || proof.feature_mask != CONCRETE_GUEST_FEATURE_MASK_V1
    {
        return Err(GuestRootPublicationErrorV1::ProofMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse;
    use buffa::Message as _;
    use aos_sandbox_agent::guest_root_publication::{
        CONCRETE_GUEST_FEATURE_MASK_V1, GuestRootPublicationProofV1,
    };
    use aos_sandbox_core::OperationId;

    use super::{
        GuestRootPublicationErrorV1, GuestRootPublicationReservationV1, GuestRootTemplatePinsV1,
    };

    fn reservation() -> GuestRootPublicationReservationV1 {
        GuestRootPublicationReservationV1 {
            operation: OperationId::from_bytes([1; 16]),
            sandbox: [2; 16],
            incarnation: [3; 16],
            epoch: 4,
            generation: 5,
            assignment_digest: [6; 32],
            workspace_handle: [7; 32],
            creation_operation: [8; 16],
            dataset_guid: 9,
            root_image_digest: [10; 32],
            pins: GuestRootTemplatePinsV1::new([11; 32], [12; 32]).unwrap(),
            initial_inventory_digest: [13; 32],
        }
    }

    #[test]
    fn reservation_is_fixed_and_workspace_keyed() {
        let reservation = reservation();
        let bytes = reservation.encode();
        assert_eq!(
            GuestRootPublicationReservationV1::decode(&[7; 32], &bytes).unwrap(),
            reservation
        );
        assert!(matches!(
            GuestRootPublicationReservationV1::decode(&[9; 32], &bytes),
            Err(GuestRootPublicationErrorV1::Corrupt)
        ));
        let mut tampered = bytes;
        tampered[160] ^= 1;
        assert!(matches!(
            GuestRootPublicationReservationV1::decode(&[7; 32], &tampered),
            Err(GuestRootPublicationErrorV1::Corrupt)
        ));
    }

    #[test]
    fn method_response_requires_independent_template_pins() {
        let reservation = reservation();
        let mut proof = GuestRootPublicationProofV1 {
            sandbox: reservation.sandbox,
            incarnation: reservation.incarnation,
            assignment_epoch: reservation.epoch,
            assignment_digest: reservation.assignment_digest,
            creation_operation: reservation.creation_operation,
            workspace_handle: reservation.workspace_handle,
            dataset_guid: reservation.dataset_guid,
            root_image_digest: reservation.root_image_digest,
            package_binding: reservation.pins.package_binding,
            root_tree_digest: reservation.pins.root_tree_digest,
            feature_mask: CONCRETE_GUEST_FEATURE_MASK_V1,
        };
        assert!(reservation.verify_response_proof(proof).is_ok());
        proof.root_tree_digest[0] ^= 1;
        assert!(matches!(
            reservation.verify_response_proof(proof),
            Err(GuestRootPublicationErrorV1::ProofMismatch)
        ));
    }

    fn inspection_fixture(
        retained: Option<GuestRootPublicationReservationV1>,
    ) -> (tempfile::TempDir, crate::Journal, crate::DurableStorageResourceInventorySnapshotV1) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = std::fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = crate::Journal::open_protected_at_uid(
            directory.path(), "controller.journal", crate::JournalLimits::default(), owner,
        ).unwrap();
        if let Some(retained) = retained {
            let record = crate::JournalRecord::put(
                crate::RecordNamespace::GuestRootPublication,
                retained.workspace_handle.to_vec(), retained.encode(),
            );
            let transaction = crate::JournalTransaction::new([19; 16], vec![record]).unwrap();
            journal.commit(&transaction).unwrap();
        }
        let response = InventoryStorageResourcesResponse {
            kernel_boot_id: vec![20; 16],
            broker_instance_id: vec![21; 16],
            journal_sequence: 1,
            catalog_generation: 1,
            ..Default::default()
        };
        let snapshot = crate::resource_inventory::record_storage_snapshot_bytes_for_test(
            &mut journal, [22; 16], response.encode_to_vec(),
        ).unwrap();
        (directory, journal, snapshot)
    }

    #[test]
    fn no_effect_inspection_preserves_the_current_snapshot_and_native_file() {
        let (directory, mut journal, snapshot) = inspection_fixture(None);
        let before = journal.all_records().map(|(namespace, key, value)| {
            (namespace, key.to_vec(), value.to_vec())
        }).collect::<Vec<_>>();
        let native_bytes = std::fs::metadata(directory.path().join("controller.journal")).unwrap().len();

        super::require_no_guest_root_publication_v2(
            &mut journal, &snapshot, aos_sandbox_core::NodeId::from_bytes([23; 16]), None,
        ).unwrap();

        assert_eq!(journal.all_records().map(|(namespace, key, value)| {
            (namespace, key.to_vec(), value.to_vec())
        }).collect::<Vec<_>>(), before);
        assert_eq!(std::fs::metadata(directory.path().join("controller.journal")).unwrap().len(), native_bytes);
        snapshot.recheck(&mut journal).unwrap();
    }

    #[test]
    fn real_empty_inventory_cannot_settle_a_retained_reservation() {
        let retained = reservation();
        let (directory, mut journal, snapshot) = inspection_fixture(Some(retained));
        let native_bytes = std::fs::metadata(directory.path().join("controller.journal")).unwrap().len();

        let result = super::require_no_guest_root_publication_v2(
            &mut journal, &snapshot, aos_sandbox_core::NodeId::from_bytes([23; 16]), None,
        );

        assert!(matches!(result, Err(GuestRootPublicationErrorV1::PublicationRequired)));
        assert_eq!(journal.get(crate::RecordNamespace::GuestRootPublication, &retained.workspace_handle),
            Some(retained.encode().as_slice()));
        assert_eq!(std::fs::metadata(directory.path().join("controller.journal")).unwrap().len(), native_bytes);
    }

    #[test]
    fn maintenance_selection_uses_real_absence_and_preserves_pending_debt() {
        let (directory, mut journal, snapshot) = inspection_fixture(None);
        let native_bytes = std::fs::metadata(directory.path().join("controller.journal")).unwrap().len();

        let selection = super::select_maintenance_guest_root_data_v3(
            &mut journal, &snapshot, aos_sandbox_core::NodeId::from_bytes([23; 16]), None,
        ).unwrap();

        assert!(selection.is_none());
        assert_eq!(std::fs::metadata(directory.path().join("controller.journal")).unwrap().len(), native_bytes);
        snapshot.recheck(&mut journal).unwrap();

        let retained = reservation();
        let (_directory, mut journal, snapshot) = inspection_fixture(Some(retained));
        let selection = super::select_maintenance_guest_root_data_v3(
            &mut journal, &snapshot, aos_sandbox_core::NodeId::from_bytes([23; 16]), None,
        );

        assert!(matches!(selection, Err(GuestRootPublicationErrorV1::PublicationRequired)));
        assert_eq!(journal.get(crate::RecordNamespace::GuestRootPublication, &retained.workspace_handle),
            Some(retained.encode().as_slice()));
    }

    #[test]
    fn resumed_reservation_cannot_be_replaced_by_new_operation_assembly() {
        let retained = reservation();
        let selection = super::GuestRootPublicationSelectionDataV3 {
            selected: super::GuestRootSelectionDataV3::Existing(retained),
            used_operations: std::collections::BTreeSet::from([retained.operation.into_bytes()]),
        };

        assert_eq!(selection.existing_reservation_data_v3(), Some(retained));
        assert!(matches!(selection.assemble_new_data_v3(OperationId::from_bytes([31; 16]), [32; 16]),
            Err(GuestRootPublicationErrorV1::Corrupt)));
    }
}
