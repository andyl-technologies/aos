//! Shares the one fixed Root Ownership trust acquisition and typed verifier.
//!
//! The closed adapter borrows a genuine Apply or accepted Start Host stage.
//! It cannot supply a path, key, clock, parser implementation or role grant.
//! Each caller retains its actual native credential and verifier destinations
//! through its independently owed post; this helper performs no disposal.

use aos_sandbox_core::{DecodeLimits, ResourceDimension as D, ResourceVector};
use aos_sandbox_ownership_protocol::trusted_policy::{
    OwnershipTrustConfigurationCaptureV1, verifier_from_protected_policy_retaining_v1,
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootApplyStageReceivingV1,
    RootHostLaunchStageReceivingV1, RootMaintenanceStorageStageReceivingV2};
use crate::public_api_session::RootCurrentOwnershipCredentialCustodyV1;
use super::RootContinuationClockGateV1;

type Cause = Box<dyn std::error::Error>;

pub(in crate::policy_compiler) enum RootOwnershipTrustReceivingV2<'held, 'flight, 'startup> {
    Apply(&'held mut RootApplyStageReceivingV1<'flight, 'startup>),
    Host(&'held mut RootHostLaunchStageReceivingV1<'flight, 'startup>),
    MaintenanceStorage(&'held mut RootMaintenanceStorageStageReceivingV2<'flight, 'startup>),
}

impl RootOwnershipTrustReceivingV2<'_, '_, '_> {
    fn admit_typed_once_v2(&mut self, demand: RootContinuationDemandV1)
        -> Result<(), NormalRootStartupErrorV1>
    {
        match self {
            Self::Apply(stage) => stage.admit_apply_trust_typed_once_v1(demand),
            Self::Host(stage) => stage.admit_host_trust_typed_once_v1(demand),
            Self::MaintenanceStorage(stage) => stage.admit_maintenance_trust_typed_once_v2(demand),
        }
    }
}

pub(in crate::policy_compiler) fn receiving_frame_bytes_v2() -> Option<usize> {
    std::mem::size_of::<RootOwnershipTrustReceivingV2<'_, '_, '_>>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(5 * std::mem::size_of::<&mut ()>()))
}

pub(in crate::policy_compiler) fn prepare_once_v2(
    mut stage: RootOwnershipTrustReceivingV2<'_, '_, '_>,
    clock: &mut RootContinuationClockGateV1,
    files: &mut RootCurrentOwnershipCredentialCustodyV1,
    trust: &mut OwnershipTrustConfigurationCaptureV1,
    capture: &mut Option<Result<(), ()>>,
) -> Result<(), Cause> {
        clock.check_next_once_v1()?;
        *capture = Some(files.capture_once());
        if !matches!(*capture, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        let (policy, public) = files.bytes().ok_or(JournalError::ProtectedBoundary)?;
        let memory = OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(policy.len())
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let entries = OwnershipTrustConfigurationCaptureV1::receiving_metadata_cells_v1(policy.len())
            .and_then(|entries| u64::try_from(entries).ok()).ok_or(JournalError::JournalTooLarge)?;
        stage.admit_typed_once_v2(demand(ResourceVector::ZERO
            .with(D::MemoryBytes, memory).with(D::OutputBytes, memory).with(D::MetadataEntries, entries)))?;
        clock.check_next_once_v1()?;
        let public = public.try_into().map_err(|_| JournalError::ProtectedBoundary)?;
        verifier_from_protected_policy_retaining_v1(policy.to_vec(), public, DecodeLimits::default(), trust)?;
        Ok(())
 }

fn demand(value: ResourceVector) -> RootContinuationDemandV1 {
    RootContinuationDemandV1::from_demand_v1(value)
}
