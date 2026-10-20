//! Rebuilds final Maintenance assignment and Source tree from actual native cuts.
//!
//! The initial verified current assignment, live lease and fixed policy pair
//! remain borrowed comparison originals. Fresh C and Source replay select the
//! same canonical reservation, active assignment and tree through the existing
//! decoders and parentless compiler before any final acknowledgement.

use super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2;
use super::maintenance_request::RootMaintenanceStorageRequestOriginalV2;
use super::inputs::RootResourceInputsOriginalV2;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootMaintenanceStorageStageReceivingV2};
use crate::policy_compiler::continuation_policy::RootMaintenanceStoragePolicyOriginalV2;
use crate::policy_compiler::provisioning_current::{
    RootProvisioningNativeViewsV1,
    current_cleanup_assignment::CurrentCleanupAssignmentDataV2,
    finality_readonly::RootCreateFinalityReadonlyOriginalV1,
    TreeDataV1, maintenance_tree_model_receiving_demand_v3, maintenance_tree_model_data_v3,
};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

type Cause = Box<dyn std::error::Error>;
type Candidate = (aos_sandbox_policy::PolicyCompilerInputV1,
    aos_sandbox_policy::CompiledPolicyCandidateV1);

pub(super) struct RootMaintenanceFinalModelsOriginalV3 {
    geometry: Option<Result<ResourceVector, Cause>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    selected: Option<CurrentCleanupAssignmentDataV2>,
    specification: Option<crate::sandbox_spec_state::DurableSandboxSpecV1>,
    tree: Option<TreeDataV1>,
    candidate: Option<Candidate>,
    result: Option<Result<(), Cause>>,
    repeated: bool,
}

impl RootMaintenanceFinalModelsOriginalV3 {
    pub(super) fn new() -> Self {
        Self { geometry: None, funding: None, selected: None, specification: None,
            tree: None, candidate: None, result: None, repeated: false }
    }

    pub(super) fn observe_once_v3(&mut self,
        stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        initial: &RootMaintenanceAssignmentOriginalV2,
        initial_views: &RootProvisioningNativeViewsV1,
        request: &RootMaintenanceStorageRequestOriginalV2,
        inputs: &RootResourceInputsOriginalV2,
        policy: &RootMaintenanceStoragePolicyOriginalV2,
        reservation: &[u8], inventory: &aos_sandbox_protocol::ValidatedStorageInventory,
        sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.repeated = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| -> Result<ResourceVector, Cause> {
            let manifest = initial.manifest_v2()?;
            let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
            let current = readonly.maintenance_current_data_v2()?;
            current.require_final_cut_data_v3()?;
            let source = readonly.maintenance_source_data_v2()?;
            let fixed = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CurrentCleanupAssignmentDataV2>()))
                .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Candidate>()))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            Ok(current.compiler_geometry_v2(signed)?
                .checked_add(maintenance_tree_model_receiving_demand_v3(source, manifest.manifest().project())?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))?)
        })());
        let demand = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::JournalTooLarge)?;
        self.funding = Some(stage.admit_maintenance_final_models_once_v2(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.result = Some((|| {
            initial.require_compiled_v2()?;
            initial.require_inventory_cutoff_data_v2(sample, cutoff)?;
            request.require_typed_v2()?;
            let prior = initial.selected_v2()?;
            let current = readonly.maintenance_current_data_v2()?;
            let manifest = initial.manifest_v2()?;
            self.selected = Some(current.assignment_data_v2(manifest.manifest().sandbox())?);
            let selected = self.selected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let lease = inputs.maintenance_lease_v2()?;
            if selected.binding.manifest().canonical_bytes() != manifest.canonical_bytes()
                || selected.binding.lease_digest() != lease.digest()
                || selected.binding.lease_generation() != lease.generation()
                || selected.recovered_lease.canonical_lease() != prior.recovered_lease.canonical_lease()
                || selected.recovered_lease.canonical_signature() != prior.recovered_lease.canonical_signature()
                || selected.recovered_lease.canonical_receipt() != prior.recovered_lease.canonical_receipt()
                || selected.recovered_lease.canonical_receipt_signature() != prior.recovered_lease.canonical_receipt_signature() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let joined = current.reserved_workspace_data_v2(manifest, inventory, reservation,
                aos_sandbox_core::NodeId::from_bytes(stage.enrolled_node_v1()?))?;
            request.require_current_reservation_data_v3(joined.reservation_v2())?;
            self.specification = Some(current.specification_data_v2(manifest.manifest().sandbox_spec())?);
            self.tree = Some(maintenance_tree_model_data_v3(readonly.maintenance_source_data_v2()?,
                manifest.manifest().project())?);
            let tree = self.tree.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let original_tree = initial_views.completed_maintenance_storage_tree_v3()?;
            if tree.head != original_tree.head || tree.lineage != original_tree.lineage
                || tree.generation != original_tree.generation || tree.commitment != original_tree.commitment {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
            self.candidate = Some(crate::policy_compiler::provisioning_current::compile_parentless_current_v1(
                signed, manifest.manifest().project(), manifest.manifest().sandbox(), signed.0.cache_domain())
                .map_err(|cause| cause as Cause)?);
            crate::policy_compiler::provisioning_current::require_manifest_candidate_v1(manifest,
                self.specification.as_ref().ok_or(JournalError::ProtectedBoundary)?.spec(),
                &self.candidate.as_ref().ok_or(JournalError::ProtectedBoundary)?.1)
                .map_err(|cause| cause as Cause)?;
            Ok(())
        })());
        self.require_complete_v3()
    }

    pub(super) fn require_complete_v3(&self) -> Result<(), JournalError> {
        if self.repeated || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.result, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.geometry.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref())
            .or_else(|| self.funding.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.repeated.then_some(&JournalError::ProtectedBoundary as _))
    }
}
