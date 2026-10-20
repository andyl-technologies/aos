//! Reuses the sole complete physical inventory row folds for Delete planning.
//!
//! All values here are passive model DATA. Genuine callers retain their actual
//! authenticated Session/native originals and admit the complete byte recipe
//! before decoding. No model, generation or empty vector grants a live cut.

use super::*;
mod storage_selection;
pub(crate) use storage_selection::{SelectedDeleteStoragePreparationDataV2,
    SelectedDeleteResourceDataV4, select_first_local_delete_network_data_v4,
    DeleteStorageSelectionErrorV2, select_first_local_delete_storage_preparation_data_v2};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use std::mem::size_of;

/// Retains the existing complete physical model for one of four broker roles.
///
/// These variants are deliberately passive; constructing one does not provide
/// native currentness, a Session, an authorized C17 loan or a six-owner proof.
#[doc(hidden)]
pub enum DeletePlanningBrokerInventoryDataV2 {
    /// Retains the complete canonical Host runtime rows and liveness facts.
    Runtime(LifecycleAuthenticatedRuntimeInventoryV1),
    /// Retains the complete canonical Mount attachment rows.
    Mount(DeletePlanningMountInventoryDataV2),
    /// Retains all five Storage families and every authenticated transition.
    Storage(DeletePlanningStorageInventoryDataV2),
    /// Retains the complete canonical Network namespace rows.
    Network(DeletePlanningNetworkInventoryDataV4),
}

impl DeletePlanningBrokerInventoryDataV2 {
    /// Decodes through the same existing ordinary complete-inventory reducers.
    ///
    /// The role is the canonical lifecycle role1..4, not an endpoint enum. Boot
    /// must come from the actual retained Session context at the genuine caller.
    ///
    /// # Errors
    /// Refuses another role, method/direction, malformed or incomplete canonical
    /// inventory, different kernel boot or an invalid existing inventory model.
    pub fn from_outcome_data_v2(role: u8,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, boot: [u8; 16],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        match role {
            1 => LifecycleAuthenticatedRuntimeInventoryV1::from_authenticated_outcome(outcome, boot)
                .map(Self::Runtime),
            2 => DeletePlanningMountInventoryDataV2::from_outcome_data_v2(outcome, boot).map(Self::Mount),
            3 if boot != [0; 16] => LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome_with_inventory_data_v2(outcome)
                .map(|(lifecycle, workspaces)| Self::Storage(DeletePlanningStorageInventoryDataV2 { lifecycle, workspaces })),
            4 => {
                let (lifecycle, namespaces) = LifecycleAuthenticatedBrokerDomainInventoryV1::from_authenticated_outcome_with_network_data_v4(
                    LifecycleBootBootstrapEndpointV1::Network, outcome, boot)?;
                Ok(Self::Network(DeletePlanningNetworkInventoryDataV4 {
                    lifecycle, namespaces: namespaces.ok_or(LifecyclePhase6ErrorV1::InvalidInput)?,
                }))
            }
            _ => Err(LifecyclePhase6ErrorV1::InvalidInput),
        }
    }

    /// Borrows the entire canonical Mount16 inventory, including namespace rows.
    #[must_use]
    pub fn mount_inventory_data_v2(&self) -> Option<&aos_sandbox_protocol::ValidatedDestinationSlotInventory> {
        match self { Self::Mount(value) => Some(&value.inventory), _ => None }
    }

    /// Borrows the exact workspace inventory decoded with the same signed18 body.
    ///
    /// The complete lifecycle census remains separately retained. These DATA
    /// cannot construct a live Session or a catalog Apply binding.
    #[must_use]
    pub fn storage_inventory_data_v2(&self) -> Option<&aos_sandbox_protocol::ValidatedStorageInventory> {
        match self { Self::Storage(value) => Some(&value.workspaces), _ => None }
    }

    pub(crate) fn storage_lifecycle_data_v2(&self) -> Option<&LifecycleAuthenticatedStorageInventoryV1> {
        match self { Self::Storage(value) => Some(&value.lifecycle), _ => None }
    }

    /// Borrows full canonical namespace rows from the same complete decoder.
    #[must_use]
    pub fn network_inventory_data_v4(&self) -> Option<&aos_sandbox_protocol::ValidatedNetworkInventory> {
        match self { Self::Network(value) => Some(&value.namespaces), _ => None }
    }

    pub(crate) fn network_lifecycle_data_v4(&self) -> Option<&LifecycleAuthenticatedBrokerDomainInventoryV1> {
        match self { Self::Network(value) => Some(&value.lifecycle), _ => None }
    }

    /// Borrows the scoped Host disposal DATA retained by the sole Host fold.
    #[must_use]
    pub fn stopped_namespace_data_v4(&self) -> Option<&aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4> {
        match self { Self::Runtime(value) => value.stopped_namespace.as_ref(), _ => None }
    }

    /// Returns the complete model count/generation/commitment as passive DATA.
    ///
    /// Storage counts every transition as well as all five physical families.
    /// No empty count or model digest establishes native absence by itself.
    #[must_use]
    pub fn complete_model_data_v2(&self) -> Option<(u32, u64, [u8; 32])> {
        let (count, generation, commitment) = match self {
            Self::Runtime(value) => (value.entries.len(), value.generation, value.commitment),
            Self::Mount(value) => (
                value.inventory.slots().len().checked_add(value.inventory.namespace_anchors_v1().len())?,
                value.inventory.journal_sequence(), value.commitment,
            ),
            Self::Network(value) => (value.lifecycle.entries.len(), value.lifecycle.generation, value.lifecycle.commitment),
            Self::Storage(value) => (value.lifecycle.entries.len().checked_add(value.lifecycle.transitions.len())?,
                value.lifecycle.generation, value.lifecycle.commitment),
        };
        Some((u32::try_from(count).ok()?, generation, *commitment.as_bytes()))
    }
}

/// Retains both outputs of the sole complete Network Inventory decoder.
///
/// Full namespace handles remain comparison DATA beside the existing complete
/// lifecycle row plane; neither output can create a live Session or worker.
#[doc(hidden)]
pub struct DeletePlanningNetworkInventoryDataV4 {
    lifecycle: LifecycleAuthenticatedBrokerDomainInventoryV1,
    namespaces: aos_sandbox_protocol::ValidatedNetworkInventory,
}

/// Retains both projections produced by the sole complete Storage18 decoder.
///
/// Workspace roots and lifecycle datasets are distinct schema families. Neither
/// is synthesized from the other, and neither supplies a resolved Apply catalog.
#[doc(hidden)]
pub struct DeletePlanningStorageInventoryDataV2 {
    lifecycle: LifecycleAuthenticatedStorageInventoryV1,
    workspaces: aos_sandbox_protocol::ValidatedStorageInventory,
}

/// Retains the sole full Mount16 model as passive Delete comparison DATA.
///
/// The ordinary Boot Mount6 model is separate and unchanged. No empty slot or
/// namespace is synthesized here, and this value creates no native loan.
#[doc(hidden)]
pub struct DeletePlanningMountInventoryDataV2 {
    inventory: aos_sandbox_protocol::ValidatedDestinationSlotInventory,
    commitment: ObjectDigest,
}

impl DeletePlanningMountInventoryDataV2 {
    fn from_outcome_data_v2(outcome: &AuthenticatedBrokerMethodOutcomeV1, boot: [u8; 16])
        -> Result<Self, LifecyclePhase6ErrorV1>
    {
        if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
            || boot == [0; 16]
        { return Err(LifecyclePhase6ErrorV1::InvalidInput); }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
            else { return Err(LifecyclePhase6ErrorV1::InvalidInput); };
        let inventory = aos_sandbox_protocol::decode_destination_slot_inventory_response(
            exact_body, outcome.request().maximum_response_bytes(),
        ).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        if inventory.kernel_boot_id() != &boot {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let commitment = ObjectDigest::from_bytes(Sha256::new()
            .chain_update(b"aos.sandbox.delete.complete-mount-destination-inventory.v2\0")
            .chain_update(exact_body).finalize().into());
        Ok(Self { inventory, commitment })
    }
}

/// Bounds the exact shared DTO decoders and additional complete row/fact planes.
///
/// The four inputs are in Runtime/Mount/Storage/Network order. This adds the
/// SAME per-method decoder supplier for each actual packet, then prices the
/// concrete ordinary lifecycle row vectors separately. Namespace/cardinality
/// owners are retained elsewhere; parser models receive only MemoryBytes.
///
/// Returns `None` for another method/result or unrepresentable arithmetic.
#[must_use]
pub fn delete_planning_broker_inventory_receiving_demand_v2(
    outcomes: [&AuthenticatedBrokerMethodOutcomeV1; 4],
) -> Option<ResourceVector> {
    let mut bytes = size_of::<[Option<Result<DeletePlanningBrokerInventoryDataV2,
        LifecyclePhase6ErrorV1>>; 4]>().checked_mul(3)?
        .checked_add(size_of::<Sha256>().checked_mul(3)?)?
        .checked_add(size_of::<[aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::
            DeleteSessionInventoryCutDataV2<'_>; 4]>().checked_mul(3)?)?;
    for (index, outcome) in outcomes.into_iter().enumerate() {
        let role = u8::try_from(index).ok()?.checked_add(1)?;
        let reached = delete_planning_broker_inventory_role_receiving_demand_v2(role, outcome)?;
        bytes = bytes.checked_add(usize::try_from(reached.get(D::MemoryBytes)).ok()?)?;
    }
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
}

/// Bounds the same complete decoder and row planes for one reached broker role.
///
/// The canonical lifecycle role is Runtime1, Mount2, Storage3 or Network4.
/// This supplier prices only MemoryBytes; the genuine caller separately pays
/// its retained owner layout and native namespace before constructing models.
/// Returns `None` for another role/method/result or unrepresentable arithmetic.
#[must_use]
pub fn delete_planning_broker_inventory_role_receiving_demand_v2(
    role: u8,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Option<ResourceVector> {
    use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1;
    let method = aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::
        delete_inventory_method_for_role_data_v2(role).ok()?;
    if outcome.method() != method {
        return None;
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return None;
    };
    let shared = AuthenticatedBrokerMethodOutcomeCaptureV1::
            controller_inventory_dynamic_receiving_demand_v1(method, outcome.canonical_packet().len())?;
    // Each protobuf repeated message requires at least tag+length bytes.
    // The ordinary reducers also impose the existing lifecycle row bound.
    let rows = (exact_body.len() / 2).min(super::super::MAXIMUM_LIFECYCLE_EXPECTATIONS);
    let width = match role {
        1 => size_of::<LifecycleBootDomainEntryV1>()
            .checked_add(size_of::<LifecycleAuthenticatedRuntimeFactV1>())?,
        // Mount16 retains its complete typed decoder model directly; the
        // shared method supplier below already owns that full plane.
        2 => 0,
        4 => size_of::<LifecycleBootDomainEntryV1>(),
        3 => size_of::<LifecycleStorageInventoryEntryV1>()
            .checked_add(size_of::<LifecycleStorageTransitionEntryV1>())?,
        _ => return None,
    };
    let bytes = usize::try_from(shared.get(D::MemoryBytes))
        .ok()?
        .checked_add(rows.checked_mul(width)?.checked_mul(3)?)?;
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
}
