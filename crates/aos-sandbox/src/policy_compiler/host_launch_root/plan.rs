//! Builds unsigned resource DATA only from Root's actual rebuilt Start.

use super::compiler::RootStartResourceCompilerOriginalV2;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::RootHostLaunchStageReceivingV1;
use crate::policy_compiler::create_storage_current::controller_readonly::public_trust::RootBrokerPlanPublicTrustDataV1;
use aos_sandbox_core::{
    BrokerPlanTrustAnchor, RawPairedClockSample, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_protocol::authorization_artifact::{
    BrokerPlanPreparation,
    start_resource_plan::{
        StartResourcePlanPreparationDataV1, prepare_start_mount_plan_v2,
        prepare_start_network_plan_v2, prepare_start_storage_guest_root_plan_v2,
        start_storage_guest_root_unsigned_receiving_demand_v2,
        start_mount_request_receiving_demand_v2,
        start_mount_unsigned_receiving_demand_v2, start_network_content_receiving_demand_v2,
        start_network_unsigned_receiving_demand_v2,
    },
};
use aos_sandbox_protocol::semantics::network::preparation_content::NetworkPreparationContentV2;

type Cause = Box<dyn std::error::Error>;

pub(super) struct RootStartResourceUnsignedPlanOriginalV2 {
    content: Option<Vec<u8>>,
    prepared: Option<StartResourcePlanPreparationDataV1>,
    host: Option<aos_sandbox_protocol::authorization_artifact::HostLaunchPlanPreparationDataV2>,
    host_funding: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    trust: Option<RootBrokerPlanPublicTrustDataV1>,
    result: Option<Result<(), Cause>>,
}

impl RootStartResourceUnsignedPlanOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            content: None,
            prepared: None,
            host: None,
            host_funding: None,
            trust: None,
            result: None,
        }
    }

    pub(super) fn admit_host_pair_once_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        storage_prefix: usize,
        public: RootBrokerPlanPublicTrustDataV1,
        request: &[u8],
        lease: &SignedOwnershipLease,
    ) -> Result<(), JournalError> {
        if self.result.is_some() || self.host_funding.is_some() || self.trust.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.trust = Some(public);
        let trust = self.trust.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let pair = aos_sandbox_protocol::authorization_artifact::start_resource_plan::
            host_launch_pair_unsigned_receiving_demand_v2(request.len(), lease, &trust.authority)
                .ok_or(JournalError::JournalTooLarge)?;
        let storage = super::current_storage::RootCurrentStoragePublicationOriginalV2::
            receiving_demand_v2(storage_prefix, lease, trust)?;
        let fixed = 2_usize.checked_mul(std::mem::size_of::<super::host_catalog::RootHostCatalogInputsOriginalV2>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        self.host_funding = Some(stage.admit_host_plan_once_v1(
            RootContinuationDemandV1::from_demand_v1(pair.checked_add(storage)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed)
                    .with(D::NetworkBytes, aos_sandbox_protocol::domain_ledger::provisioning_root::
                        host_launch::completion::RESOURCE_PROOF_HEADER_BYTES_V2 as u64))?)));
        if matches!(self.host_funding, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_host_pair_once_v2(
        &mut self,
        compiler: &RootStartResourceCompilerOriginalV2,
        catalog: &super::host_catalog::RootHostCatalogInputsOriginalV2,
        request: &[u8],
        lease: &SignedOwnershipLease,
        sample: RawPairedClockSample,
        cutoff: u64,
        policy_expires: i64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() || !matches!(self.host_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some((|| {
            let trust = self.trust.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let compiled = compiler.compiled_v2()?;
            self.host = Some(aos_sandbox_protocol::authorization_artifact::prepare_host_launch_plan_v2(
                request, compiled.manifest_v2(), compiler.specification_v2()?.spec().resource_profile(),
                catalog.catalog_v2()?, compiled.manifest_v2().manifest().policy().digest(),
                lease, sample, cutoff, policy_expires,
                compiled.source_v2().native_origin_data_v2().accepted_v1(),
                trust.authority.clone(), trust.revocation_scope,
            ).map_err(|cause| cause as Cause)?);
            if self.host.as_ref().ok_or(JournalError::ProtectedBoundary)?.request_header.request_id
                != compiled.source_v2().operation_v2().into_bytes() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            // Retains the exact deadline-free subject beside both preparations;
            // the final verifier normalizes the actual signed companion body.
            self.content = Some(request.to_vec());
            Ok(())
        })());
        self.require_complete_v2()
    }

    pub(super) fn admitted_host_public_trust_v2(&self)
        -> Result<&RootBrokerPlanPublicTrustDataV1, JournalError> {
        if !matches!(self.host_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.trust.as_ref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn host_pair_v2(&self)
        -> Result<&aos_sandbox_protocol::authorization_artifact::HostLaunchPlanPreparationDataV2, JournalError> {
        self.require_complete_v2()?;
        self.host.as_ref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn prepare_once_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        compiler: &RootStartResourceCompilerOriginalV2,
        historical: &super::history::RootHostHistoricalCreateOriginalV2,
        kind: super::kind::ResourceKindV2,
        storage_prefix: usize,
        public: RootBrokerPlanPublicTrustDataV1,
        request: &[u8],
        lease: &SignedOwnershipLease,
        sample: RawPairedClockSample,
        cutoff: u64,
        policy_expires: i64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.trust = Some(public);
        self.result = Some(self.prepare_inner_v2(
            stage,
            compiler,
            historical,
            kind,
            storage_prefix,
            request,
            lease,
            sample,
            cutoff,
            policy_expires,
        ));
        self.require_complete_v2()
    }

    // Maintenance lends its actual current assignment and reserved workspace
    // through a distinct closed owner. The canonical Storage argument, request,
    // expiry and unsigned-plan engines are shared DATA recipes; no Start source
    // or accepted-Start receipt is constructed or borrowed here.
    pub(super) fn prepare_maintenance_storage_once_v2(
        &mut self,
        stage: &mut crate::normal_root::RootMaintenanceStorageStageReceivingV2<'_, '_>,
        assignment: &super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2,
        request: &super::maintenance_request::RootMaintenanceStorageRequestOriginalV2,
        public: RootBrokerPlanPublicTrustDataV1,
        inputs: &super::inputs::RootResourceInputsOriginalV2,
        sample: RawPairedClockSample, cutoff: u64, policy_expires: i64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() || self.trust.is_some() || self.host_funding.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.trust = Some(public);
        self.result = Some((|| -> Result<(), Cause> {
            assignment.require_compiled_v2()?;
            assignment.require_inventory_cutoff_data_v2(sample, cutoff)?;
            request.require_typed_v2()?;
            let manifest = assignment.manifest_v2()?;
            let lease = inputs.maintenance_lease_v2()?;
            let public = self.trust.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let normalization = start_storage_guest_root_unsigned_receiving_demand_v2(
                request.request_body_v2()?.len(), lease, &public.authority)
                .ok_or(JournalError::JournalTooLarge)?;
            let fixed = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            stage.admit_maintenance_plan_once_v2(RootContinuationDemandV1::from_demand_v1(
                normalization.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed)
                    .with(D::NetworkBytes, aos_sandbox_protocol::domain_ledger::provisioning_root::
                        host_launch::completion::RESOURCE_PROOF_HEADER_BYTES_V2 as u64))?))?;
            self.prepared = Some(prepare_start_storage_guest_root_plan_v2(
                request.request_body_v2()?, request.arguments_v2()?, manifest,
                manifest.manifest().policy().digest(), lease, sample, cutoff, policy_expires,
                public.authority.clone(), public.revocation_scope,
            ).map_err(|cause| cause as Cause)?);
            if self.prepared.as_ref().ok_or(JournalError::ProtectedBoundary)?
                .request_header.request_id != request.request_id_v2()? {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        self.require_complete_v2()
    }

    fn prepare_inner_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        compiler: &RootStartResourceCompilerOriginalV2,
        historical: &super::history::RootHostHistoricalCreateOriginalV2,
        kind: super::kind::ResourceKindV2,
        storage_prefix: usize,
        request: &[u8],
        lease: &SignedOwnershipLease,
        sample: RawPairedClockSample,
        cutoff: u64,
        policy_expires: i64,
    ) -> Result<(), Cause> {
        let compiled = compiler.compiled_v2()?;
        let specification = compiler.specification_v2()?.spec();
        let specification_bytes = aos_sandbox_core::encode_sandbox_spec(specification);
        // The specification encoding is already prepaid by the full current
        // compiler model. No body-selected manifest or policy enters this path.
        let manifest = compiled.manifest_v2();
        let content_bytes = manifest
            .canonical_bytes()
            .len()
            .checked_add(specification_bytes.len())
            .and_then(|bytes| bytes.checked_add(16))
            .ok_or(JournalError::JournalTooLarge)?;
        let trust = self.trust.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let (content_demand, normalization) = match kind {
            super::kind::ResourceKindV2::Host => return Err(JournalError::ProtectedBoundary.into()),
            super::kind::ResourceKindV2::Network => (
                start_network_content_receiving_demand_v2(
                    manifest.canonical_bytes().len(),
                    specification_bytes.len(),
                    aos_sandbox_protocol::semantics::network::MAXIMUM_NETWORK_ENDPOINTS,
                ),
                start_network_unsigned_receiving_demand_v2(
                    request.len(),
                    content_bytes,
                    specification_bytes.len(),
                    lease,
                    &trust.authority,
                ),
            ),
            super::kind::ResourceKindV2::StorageGuestRoot => (
                aos_sandbox_protocol::semantics::storage_guest_root::
                    CanonicalStorageGuestRootArgumentsV1::deadline_free_request_receiving_bytes_v2()
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .map(|bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes)),
                start_storage_guest_root_unsigned_receiving_demand_v2(
                    request.len(), lease, &trust.authority,
                ),
            ),
            super::kind::ResourceKindV2::Mount => (
                start_mount_request_receiving_demand_v2(specification_bytes.len()),
                start_mount_unsigned_receiving_demand_v2(
                    request.len(),
                    specification_bytes.len(),
                    lease,
                    &trust.authority,
                ),
            ),
        };
        let content_demand = content_demand.ok_or(JournalError::JournalTooLarge)?;
        let normalization = normalization.ok_or(JournalError::JournalTooLarge)?;
        let publication = match kind {
            super::kind::ResourceKindV2::Host => return Err(JournalError::ProtectedBoundary.into()),
            super::kind::ResourceKindV2::Network | super::kind::ResourceKindV2::StorageGuestRoot => ResourceVector::ZERO,
            super::kind::ResourceKindV2::Mount => super::current_storage::RootCurrentStoragePublicationOriginalV2::
                receiving_demand_v2(storage_prefix, lease, trust)?,
        };
        let fixed = u64::try_from(2 * std::mem::size_of::<Self>())
            .map_err(|_| JournalError::JournalTooLarge)?;
        stage.admit_host_plan_once_v1(RootContinuationDemandV1::from_demand_v1(
            content_demand.checked_add(normalization)?.checked_add(publication)?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed).with(D::NetworkBytes, aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::RESOURCE_PROOF_HEADER_BYTES_V2 as u64))?))?;
        self.prepared = Some(match kind {
            super::kind::ResourceKindV2::Host => return Err(JournalError::ProtectedBoundary.into()),
            super::kind::ResourceKindV2::Network => {
                self.content = Some(
                    NetworkPreparationContentV2::new(
                        manifest.canonical_bytes(),
                        &specification_bytes,
                    )?
                    .encode()?,
                );
                prepare_start_network_plan_v2(
                    request,
                    self.content
                        .as_deref()
                        .ok_or(JournalError::ProtectedBoundary)?,
                    manifest,
                    specification,
                    compiled
                        .candidate_v2()
                        .portable()
                        .policy_descriptor()
                        .digest(),
                    lease,
                    sample,
                    cutoff,
                    policy_expires,
                    trust.authority.clone(),
                    trust.revocation_scope,
                )
                .map_err(|cause| cause as Cause)?
            }
            super::kind::ResourceKindV2::StorageGuestRoot => {
                let (handle, creation_operation) = historical.creation_workspace_selectors_v2()?;
                let arguments = aos_sandbox_protocol::semantics::storage_guest_root::
                    CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
                        manifest.broker_assignment()?, compiled.source_v2().operation_v2().into_bytes(),
                        handle, creation_operation,
                    )?;
                prepare_start_storage_guest_root_plan_v2(
                    request, &arguments, manifest, manifest.manifest().policy().digest(),
                    lease, sample, cutoff, policy_expires, trust.authority.clone(),
                    trust.revocation_scope,
                ).map_err(|cause| cause as Cause)?
            }
            super::kind::ResourceKindV2::Mount => prepare_start_mount_plan_v2(
                request,
                manifest,
                manifest.manifest().sandbox_spec(),
                specification,
                lease,
                sample,
                cutoff,
                policy_expires,
                trust.authority.clone(),
                trust.revocation_scope,
            )
            .map_err(|cause| cause as Cause)?,
        });
        Ok(())
    }

    pub(super) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn preparation_v2(&self) -> Result<&BrokerPlanPreparation, JournalError> {
        self.require_complete_v2()?;
        self.host.as_ref().map(|pair| &pair.host).or_else(|| self.prepared
            .as_ref()
            .map(|prepared| &prepared.preparation))
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn request_body_v2(&self) -> Result<&[u8], JournalError> {
        self.require_complete_v2()?;
        self.host.as_ref().and_then(|_| self.content.as_deref()).or_else(|| self.prepared
            .as_ref()
            .map(|prepared| prepared.request_body.as_slice()))
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn public_trust_v2(&self) -> Result<&RootBrokerPlanPublicTrustDataV1, JournalError> {
        self.require_complete_v2()?;
        self.trust.as_ref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn anchor_v2(&self) -> Result<&BrokerPlanTrustAnchor, JournalError> {
        self.require_complete_v2()?;
        self.trust
            .as_ref()
            .map(|trust| &trust.anchor)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.host_funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.result
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause.as_ref()))
    }
}
