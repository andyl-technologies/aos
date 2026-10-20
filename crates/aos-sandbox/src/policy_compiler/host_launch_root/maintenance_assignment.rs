//! Selects only Root's actual current Maintenance assignment and signed inputs.
//!
//! The same native current C/Source/Cache readers remain held through all late
//! posts. Selection uses the canonical current assignment/gate decoder; pure
//! policy compilation reuses the existing parentless compiler and manifest
//! comparator. Neither a supplied manifest nor an accepted Start enters here.

use std::error::Error;
use aos_sandbox_core::{CanonicalAssignmentManifestV1, NodeId, RawPairedClockSample,
    ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::guest_root_publication::GuestRootPublicationReservationV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootMaintenanceStorageStageReceivingV2};
use crate::policy_compiler::continuation_policy::RootMaintenanceStoragePolicyOriginalV2;
use crate::policy_compiler::provisioning_current::{RootContinuationClockGateV1,
    RootContinuationHorizonDataV1, RootProvisioningNativeViewsV1,
    compile_parentless_current_v1,
    current_cleanup_assignment::CurrentCleanupAssignmentDataV2,
    finality_readonly::RootCreateFinalityReadonlyOriginalV1};

type Cause = Box<dyn Error>;
type Candidate = (aos_sandbox_policy::PolicyCompilerInputV1,
    aos_sandbox_policy::CompiledPolicyCandidateV1);

pub(super) struct RootMaintenanceAssignmentOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    clock: Option<Box<RootContinuationClockGateV1>>,
    observed: Option<RawPairedClockSample>,
    horizon: Option<RootContinuationHorizonDataV1>,
    reservation: Option<GuestRootPublicationReservationV1>,
    selected: Option<CurrentCleanupAssignmentDataV2>,
    specification: Option<crate::sandbox_spec_state::DurableSandboxSpecV1>,
    current: Option<Result<(), Cause>>,
    compiler_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    candidate: Option<Result<Candidate, Cause>>,
    repeated: bool,
}

impl RootMaintenanceAssignmentOriginalV2 {
    pub(super) fn new() -> Self {
        Self { geometry: None, funding: None, clock: None, observed: None, horizon: None,
            reservation: None, selected: None, specification: None, current: None,
            compiler_funding: None, candidate: None, repeated: false }
    }

    pub(super) fn observe_current_once_v2(&mut self,
        stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        views: &RootProvisioningNativeViewsV1,
        policy: &RootMaintenanceStoragePolicyOriginalV2,
        reservation_bytes: &[u8],
        horizon: RootContinuationHorizonDataV1,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.repeated = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some((|| {
            let current = readonly.maintenance_current_data_v2()?;
            current.require_initial_cut_data_v3()?;
            let fixed = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<CurrentCleanupAssignmentDataV2>()))
                .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Candidate>()))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            current.compiler_geometry_v2(policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?)?
                .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let demand = self.geometry.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(JournalError::JournalTooLarge)?;
        self.funding = Some(stage.admit_maintenance_current_assignment_once_v2(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.horizon = Some(horizon);
        self.clock = Some(Box::new(RootContinuationClockGateV1::new(horizon)));
        self.current = Some((|| {
            let sample = self.checked_sample_v2(policy)?;
            self.observed = Some(sample);
            let current = readonly.maintenance_current_data_v2()?;
            self.reservation = Some(current.reservation_data_v2(reservation_bytes)?);
            let sandbox = self.reservation.as_ref().ok_or(JournalError::ProtectedBoundary)?.sandbox();
            self.selected = Some(current.assignment_data_v2(sandbox)?);
            let selected = self.selected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let manifest = selected.binding.manifest().manifest();
            let reservation = self.reservation.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let (incarnation, epoch, generation, digest) = reservation.assignment_fence();
            if manifest.node() != NodeId::from_bytes(stage.enrolled_node_v1()?)
                || manifest.incarnation().as_bytes() != &incarnation
                || manifest.epoch().get() != epoch
                || manifest.desired_generation().get() != generation
                || selected.binding.manifest().digest().as_bytes() != &digest
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.specification = Some(current.specification_data_v2(manifest.sandbox_spec())?);
            let tree = views.prepared_maintenance_storage_tree_v1()?;
            let member = tree.tree_v2().record(manifest.sandbox())
                .ok_or(JournalError::ProtectedBoundary)?;
            if tree.tree_v2().project() != manifest.project()
                || member.project() != manifest.project() || member.parent().is_some()
                || !manifest.ancestry().ancestors().is_empty()
                || member.incarnation() != Some(manifest.incarnation())
                || member.desired_generation() != manifest.desired_generation()
                || views.prepared_maintenance_storage_cache_v1()?.selected_v1().project != manifest.project()
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            views.prepared_maintenance_storage_physical_v1()?;
            views.prepared_maintenance_storage_limits_digest_v1()?;
            Ok(())
        })());
        self.selected_v2().map(|_| ())
    }

    pub(super) fn compile_after_inputs_once_v2(&mut self,
        stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        policy: &RootMaintenanceStoragePolicyOriginalV2,
        inputs: &super::inputs::RootResourceInputsOriginalV2,
    ) -> Result<(), JournalError> {
        self.selected_v2()?;
        if self.compiler_funding.is_some() || self.candidate.is_some() {
            self.repeated = true;
            return Err(JournalError::ProtectedBoundary);
        }
        // CurrentAssignment201 already paid the complete shared decoder and
        // compiler recipe before either could grow. This distinct once-only
        // stage enforces that native Inventory, live lease and request typing
        // precede compilation/plan use without charging that backing twice.
        self.compiler_funding = Some(stage.admit_compiler_once_v1(
            RootContinuationDemandV1::from_demand_v1(ResourceVector::ZERO)));
        if !matches!(self.compiler_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.candidate = Some((|| {
            let lease = inputs.maintenance_lease_v2()?;
            self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .narrow_wall_expiry_data_v1(lease.authority_expires_seconds());
            let sample = self.checked_sample_v2(policy)?;
            self.observed = Some(sample);
            let selected = self.selected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            if selected.binding.lease_digest() != lease.digest()
                || selected.binding.lease_generation() != lease.generation() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
            let manifest = selected.binding.manifest();
            let candidate = compile_parentless_current_v1(signed, manifest.manifest().project(),
                manifest.manifest().sandbox(), signed.0.cache_domain()).map_err(|cause| cause as Cause)?;
            crate::policy_compiler::provisioning_current::require_manifest_candidate_v1(
                manifest, self.specification.as_ref().ok_or(JournalError::ProtectedBoundary)?.spec(), &candidate.1)
                .map_err(|cause| cause as Cause)?;
            Ok(candidate)
        })());
        self.require_compiled_v2()
    }

    fn checked_sample_v2(&mut self, policy: &RootMaintenanceStoragePolicyOriginalV2)
        -> Result<RawPairedClockSample, Cause> {
        let signed = policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
        let clock = self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        clock.narrow_wall_expiry_data_v1(signed.0.head().expires_at());
        clock.narrow_wall_expiry_data_v1(signed.1.expires_at());
        let sample = clock.check_next_once_v1()?;
        policy.verified_at_v1().ok_or(JournalError::ProtectedBoundary)?.validate_later_sample(sample)?;
        Ok(sample)
    }

    pub(super) fn selected_v2(&self) -> Result<&CurrentCleanupAssignmentDataV2, JournalError> {
        if self.repeated || !matches!(self.current, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.selected.as_ref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn require_compiled_v2(&self) -> Result<(), JournalError> {
        self.selected_v2()?;
        if matches!(self.compiler_funding, Some(Ok(()))) && matches!(self.candidate, Some(Ok(_))) {
            Ok(())
        } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn require_inventory_cutoff_data_v2(&self,
        sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        self.selected_v2()?;
        let horizon = self.horizon.ok_or(JournalError::ProtectedBoundary)?;
        horizon.require_sample_v1(sample)?;
        horizon.require_narrowed_cutoff_data_v2(cutoff)
    }

    pub(super) fn manifest_v2(&self) -> Result<&CanonicalAssignmentManifestV1, JournalError> {
        Ok(self.selected_v2()?.binding.manifest())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        cause(&self.geometry).or_else(|| cause(&self.funding))
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| self.current.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| cause(&self.compiler_funding))
            .or_else(|| self.candidate.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.repeated.then_some(&JournalError::ProtectedBoundary as _))
    }
}
