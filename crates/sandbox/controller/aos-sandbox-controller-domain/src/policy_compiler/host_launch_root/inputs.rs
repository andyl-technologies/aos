//! Retains genuine fixed Root trust for Start and current Maintenance Storage.
//!
//! The protected predecessor remains manifest1. The independent current Start
//! compiler supplies manifest2; only an Advance naming the exact prior lease
//! and complete successor assignment can authorize that Start resource plan.
//! Maintenance instead revalidates the current protected gate/lease quartet
//! against the same fresh fixed trust and its independently sampled clock.

use super::compiler::RootStartResourceCompilerOriginalV2;
use super::inputs_receiving::{ResourceInputsPurposeV2, ResourceInputsReceivingV2};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{RootHostLaunchStageReceivingV1, RootMaintenanceStorageStageReceivingV2};
use aos_sandbox_policy::root_trust_data::RootBrokerPlanPublicTrustDataV1;
use crate::policy_compiler::provisioning_current::{
    RootContinuationClockGateV1, RootContinuationHorizonDataV1,
    ownership_trust::prepare_once_v2,
};
use aos_sandbox_broker::systemd_credentials::{
    RootCurrentBrokerPlanCredentialCustodyV1, RootCurrentOwnershipCredentialCustodyV1,
    RootCurrentStorageManifestCustodyV1, RootDeleteBrokerManifestsCustodyV2,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1,
    manifest::{BrokerSessionManifestAudienceV1, BrokerSessionManifestV1},
};
use aos_sandbox_model::{LeaseAssignment, ResourceDimension as D, ResourceVector};
use aos_sandbox_policy::bundle_ownership_data::ownership_bundle_typed_demand_v1;
use aos_sandbox_ownership_protocol::{
    OwnershipClaimAction, SignedOwnershipLease,
    response_verification::{OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1},
    trusted_policy::OwnershipTrustConfigurationCaptureV1,
};
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::ready::ReadyBundleDataV1,
    provisioning_root::host_launch::HostLaunchSubjectDataV1,
};

type Cause = Box<dyn std::error::Error>;

pub(super) type RootStartResourceInputsOriginalV2 = RootResourceInputsOriginalV2;

pub(super) struct RootResourceInputsOriginalV2 {
    purpose: Option<ResourceInputsPurposeV2>,
    fixed: Option<Result<(), Cause>>,
    native: Option<Box<Native>>,
}

struct Native {
    trust_files: RootCurrentOwnershipCredentialCustodyV1,
    trust: OwnershipTrustConfigurationCaptureV1,
    storage_files: RootCurrentStorageManifestCustodyV1,
    plan_files: RootCurrentBrokerPlanCredentialCustodyV1,
    broker_files: RootDeleteBrokerManifestsCustodyV2,
    clock: RootContinuationClockGateV1,
    captures: [Option<Result<(), ()>>; 4],
    posts: [Option<Result<(), ()>>; 4],
    trust_result: Option<Result<(), Cause>>,
    public_result: Option<Result<(BrokerSessionManifestV1, BrokerSessionManifestV1), Cause>>,
    host_manifests: Option<Result<[BrokerSessionManifestV1; 2], Cause>>,
    claim: Option<Box<OwnershipClaimDecodeCaptureV1>>,
    response: Option<Box<OwnershipResponseVerifyCaptureV1>>,
    ownership: Option<Result<(), Cause>>,
    public_taken: bool,
    plan_public: Option<Result<Option<RootBrokerPlanPublicTrustDataV1>, Cause>>,
}

impl RootResourceInputsOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            purpose: None,
            fixed: None,
            native: None,
        }
    }

    pub(super) fn prepare_once_v2(
        &mut self, stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        horizon: RootContinuationHorizonDataV1, policy_interval: ResourceVector,
        kind: super::kind::ResourceKindV2,
    ) -> Result<(), JournalError> {
        self.prepare_resource_once_v2(ResourceInputsReceivingV2::Start(stage), horizon, policy_interval, kind)
    }

    pub(super) fn prepare_maintenance_storage_once_v2(
        &mut self, stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        horizon: RootContinuationHorizonDataV1, policy_interval: ResourceVector,
    ) -> Result<(), JournalError> {
        self.prepare_resource_once_v2(ResourceInputsReceivingV2::MaintenanceStorage(stage),
            horizon, policy_interval, super::kind::ResourceKindV2::StorageGuestRoot)
    }

    fn prepare_resource_once_v2(
        &mut self, mut stage: ResourceInputsReceivingV2<'_, '_, '_>,
        horizon: RootContinuationHorizonDataV1, policy_interval: ResourceVector,
        kind: super::kind::ResourceKindV2,
    ) -> Result<(), JournalError> {
        if self.fixed.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.purpose = Some(stage.purpose_v2());
        self.fixed = Some((|| {
            let bytes = std::mem::size_of::<Native>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Self>()))
                .and_then(|bytes| {
                    bytes.checked_add(
                        (if kind == super::kind::ResourceKindV2::Host { 7 } else { 3 })
                            * std::mem::size_of::<BrokerSessionManifestV1>())
                })
                .and_then(|bytes| bytes.checked_add(
                    2 * std::mem::size_of::<ResourceInputsReceivingV2<'_, '_, '_>>()))
                .and_then(|bytes| {
                    crate::policy_compiler::provisioning_current::ownership_trust::
                    receiving_frame_bytes_v2().and_then(|frame| bytes.checked_add(frame))
                })
                .and_then(|bytes| bytes.checked_add(aos_sandbox_policy::bundle_ownership_data::
                    fixed_interface_control_bytes_v1::<JournalError>()?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            let demand = RootCurrentOwnershipCredentialCustodyV1::dominant_demand()
                .ok_or(JournalError::JournalTooLarge)?
                .checked_add(
                    RootCurrentStorageManifestCustodyV1::dominant_demand()
                        .ok_or(JournalError::JournalTooLarge)?,
                )?
                .checked_add(
                    RootCurrentBrokerPlanCredentialCustodyV1::dominant_demand()
                        .ok_or(JournalError::JournalTooLarge)?,
                )?
                .checked_add(
                    RootDeleteBrokerManifestsCustodyV2::dominant_demand()
                        .ok_or(JournalError::JournalTooLarge)?,
                )?
                .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?
                .checked_add(policy_interval)?;
            stage
                .admit_fixed_once_v2(RootContinuationDemandV1::from_demand_v1(demand))?;
            Ok(())
        })());
        if !matches!(self.fixed, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native = Some(Box::new(Native {
            trust_files: RootCurrentOwnershipCredentialCustodyV1::new(),
            trust: OwnershipTrustConfigurationCaptureV1::new(),
            storage_files: RootCurrentStorageManifestCustodyV1::new(),
            plan_files: if kind == super::kind::ResourceKindV2::Mount {
                RootCurrentBrokerPlanCredentialCustodyV1::mount_v2()
            } else {
                RootCurrentBrokerPlanCredentialCustodyV1::new()
            },
            broker_files: RootDeleteBrokerManifestsCustodyV2::new(),
            clock: RootContinuationClockGateV1::new(horizon),
            captures: [None; 4],
            posts: [None; 4],
            trust_result: None,
            public_result: None,
            host_manifests: None,
            claim: None,
            response: None,
            ownership: None,
            public_taken: false,
            plan_public: None,
        }));
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        native.trust_result = Some(prepare_once_v2(
            stage.ownership_trust_v2(),
            &mut native.clock,
            &mut native.trust_files,
            &mut native.trust,
            &mut native.captures[0],
        ));
        if !matches!(native.trust_result, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        native.public_result = Some(native.capture_public_once_v2(&mut stage, kind));
        native
            .public_result
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(|_| ())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn verify_advance_once_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        subject: HostLaunchSubjectDataV1<'_>,
        bundle: ReadyBundleDataV1<'_>,
        compiler: &RootStartResourceCompilerOriginalV2,
    ) -> Result<(), JournalError> {
        if self.purpose != Some(ResourceInputsPurposeV2::Start) {
            return Err(JournalError::ProtectedBoundary);
        }
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native.ownership.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        native.ownership = Some(native.verify_advance_inner_v2(stage, subject, bundle, compiler));
        self.lease_v2().map(|_| ())
    }

    pub(super) fn verify_maintenance_current_ownership_once_v2(
        &mut self,
        stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        assignment: &super::maintenance_assignment::RootMaintenanceAssignmentOriginalV2,
    ) -> Result<(), JournalError> {
        if self.purpose != Some(ResourceInputsPurposeV2::MaintenanceStorage) {
            return Err(JournalError::ProtectedBoundary);
        }
        let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if native.ownership.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        native.ownership = Some((|| {
            let selected = assignment.selected_v2()?;
            let verifier = native.trust.verifier().ok_or(JournalError::ProtectedBoundary)?;
            let recovered = &selected.recovered_lease;
            let quartet_bytes = [recovered.canonical_lease(), recovered.canonical_signature(),
                recovered.canonical_receipt(), recovered.canonical_receipt_signature()]
                .into_iter().try_fold(0_usize, |sum, field| sum.checked_add(field.len()))
                .ok_or(JournalError::JournalTooLarge)?;
            let demand = aos_sandbox_policy::bundle_ownership_data::
                ownership_response_typed_demand_v2(quartet_bytes, verifier)
                    .map_err(|_| JournalError::JournalTooLarge)?;
            stage.admit_maintenance_live_ownership_once_v2(
                RootContinuationDemandV1::from_demand_v1(demand))?;
            native.response = Some(Box::new(OwnershipResponseVerifyCaptureV1::new()));
            let sample = native.clock.check_next_once_v1()?;
            verifier.verify_response_bytes_retaining_v1(selected.gate.claim(),
                recovered.canonical_lease(), recovered.canonical_signature(),
                recovered.canonical_receipt(), recovered.canonical_receipt_signature(),
                &sample, native.response.as_mut().ok_or(JournalError::ProtectedBoundary)?)?;
            let lease = native.response.as_ref().and_then(|capture| capture.value())
                .ok_or(JournalError::ProtectedBoundary)?;
            let manifest = selected.binding.manifest().manifest();
            let assignment = LeaseAssignment::new(manifest.sandbox(), manifest.incarnation(),
                manifest.epoch(), selected.binding.manifest().digest())?;
            if manifest.node().as_bytes() != &stage.enrolled_node_v1()?
                || lease.assignment() != assignment
                || lease.node() != manifest.node()
                || lease.digest() != selected.binding.lease_digest()
                || lease.generation() != selected.binding.lease_generation()
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        self.lease_v2().map(|_| ())
    }

    pub(super) fn maintenance_lease_v2(&self) -> Result<&SignedOwnershipLease, JournalError> {
        if self.purpose != Some(ResourceInputsPurposeV2::MaintenanceStorage) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.lease_v2()
    }

    pub(super) fn lease_v2(&self) -> Result<&SignedOwnershipLease, JournalError> {
        let native = self
            .native
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if !matches!(native.ownership, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        native
            .response
            .as_ref()
            .and_then(|capture| capture.value())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn storage_manifest_v2(&self) -> Result<&BrokerSessionManifestV1, JournalError> {
        self.native
            .as_ref()
            .and_then(|native| native.public_result.as_ref())
            .and_then(|value| value.as_ref().ok())
            .map(|value| &value.0)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn resource_manifest_v2(&self) -> Result<&BrokerSessionManifestV1, JournalError> {
        self.native
            .as_ref()
            .and_then(|native| native.public_result.as_ref())
            .and_then(|value| value.as_ref().ok())
            .map(|value| &value.1)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn host_preparation_manifests_v2(&self)
        -> Result<(&BrokerSessionManifestV1, &BrokerSessionManifestV1), JournalError> {
        let [network, mount] = self.native.as_ref()
            .and_then(|native| native.host_manifests.as_ref())
            .and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        Ok((network, mount))
    }

    pub(super) fn prepare_public_plan_once_v2(
        &mut self, stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
    ) -> Result<(), JournalError> {
        self.prepare_resource_public_plan_once_v2(ResourceInputsReceivingV2::Start(stage))
    }

    pub(super) fn prepare_maintenance_public_plan_once_v2(
        &mut self, stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
    ) -> Result<(), JournalError> {
        self.prepare_resource_public_plan_once_v2(ResourceInputsReceivingV2::MaintenanceStorage(stage))
    }

    pub(super) fn require_maintenance_request_admitted_v2(&self) -> Result<(), JournalError> {
        if self.purpose != Some(ResourceInputsPurposeV2::MaintenanceStorage)
            || !self.native.as_ref().is_some_and(|native|
                matches!(native.plan_public, Some(Ok(Some(_))))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn prepare_resource_public_plan_once_v2(
        &mut self, mut stage: ResourceInputsReceivingV2<'_, '_, '_>,
    ) -> Result<(), JournalError> {
        if self.purpose != Some(stage.purpose_v2()) {
            return Err(JournalError::ProtectedBoundary);
        }
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native.plan_public.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        native.plan_public = Some((|| {
            let public = native
                .plan_files
                .bytes()
                .ok_or(JournalError::ProtectedBoundary)?;
            let carriers =
                aos_sandbox_model::format::TrustPolicyDecodeCaptureV1::receiving_carrier_bytes_v1(
                    public.0.len(),
                )
                .and_then(|bytes| bytes.checked_mul(3))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            stage.admit_request_typed_once_v2(RootContinuationDemandV1::from_demand_v1(
                ResourceVector::ZERO.with(D::MemoryBytes, carriers).checked_add(
                    match stage.purpose_v2() {
                        ResourceInputsPurposeV2::Start => ResourceVector::ZERO,
                        ResourceInputsPurposeV2::MaintenanceStorage =>
                            super::maintenance_request::RootMaintenanceStorageRequestOriginalV2::typed_receiving_demand_v2()?,
                    })?,
            ))?;
            Ok(Some(
                RootBrokerPlanPublicTrustDataV1::from_fixed_public_data_v1(public)?,
            ))
        })());
        if matches!(native.plan_public, Some(Ok(Some(_)))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn take_public_plan_data_v2(
        &mut self,
    ) -> Result<RootBrokerPlanPublicTrustDataV1, JournalError> {
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native.public_taken {
            return Err(JournalError::ProtectedBoundary);
        }
        // Keep the manifest models and their credential owners resident. The
        // plan owner takes only the same pure public policy/anchor DATA.
        native.public_taken = true;
        native
            .plan_public
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .and_then(Option::take)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn finish_posts_once_v2(&mut self) {
        let Some(native) = self.native.as_mut() else {
            return;
        };
        for index in 0..4 {
            if native.captures[index].is_some() && native.posts[index].is_none() {
                native.posts[index] = Some(match index {
                    0 => native.trust_files.recheck_once(),
                    1 => native.storage_files.recheck_once(),
                    2 => native.plan_files.recheck_once(),
                    _ => native.broker_files.recheck_once(),
                });
            }
        }
    }

    pub(super) fn require_complete_v2(&self) -> Result<(), JournalError> {
        self.lease_v2()?;
        let native = self
            .native
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native
            .posts
            .iter()
            .all(|value| matches!(value, Some(Ok(()))))
            && self.failure().is_none()
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause.as_ref())
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
    }
}

impl Native {
    fn capture_public_once_v2(
        &mut self,
        stage: &mut ResourceInputsReceivingV2<'_, '_, '_>,
        kind: super::kind::ResourceKindV2,
    ) -> Result<(BrokerSessionManifestV1, BrokerSessionManifestV1), Cause> {
        self.clock.check_next_once_v1()?;
        self.captures[1] = Some(self.storage_files.capture_once());
        self.captures[2] = Some(self.plan_files.capture_once());
        self.captures[3] = Some(self.broker_files.capture_once());
        if !self.captures[1..]
            .iter()
            .all(|value| matches!(value, Some(Ok(()))))
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let storage = BrokerSessionManifestV1::decode(
            self.storage_files
                .bytes()
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        let network = BrokerSessionManifestV1::decode(
            match kind {
                super::kind::ResourceKindV2::Host => self.broker_files.host_bytes(),
                super::kind::ResourceKindV2::Network => self.broker_files.network_bytes(),
                super::kind::ResourceKindV2::Mount => self.broker_files.mount_bytes(),
                super::kind::ResourceKindV2::StorageGuestRoot => self.storage_files.bytes(),
            }
            .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        let node = stage.enrolled_node_v2()?;
        storage.require_all_active()?;
        network.require_all_active()?;
        if storage.protocol() != BrokerSessionProtocolV1::Storage
            || network.protocol() != kind.protocol_v2()
            || storage.audience() != BrokerSessionManifestAudienceV1::NodeController
            || network.audience() != BrokerSessionManifestAudienceV1::NodeController
            || storage.node_id() != node
            || network.node_id() != node
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        if kind == super::kind::ResourceKindV2::Host {
            self.host_manifests = Some((|| {
                let network = BrokerSessionManifestV1::decode(self.broker_files.network_bytes()
                    .ok_or(JournalError::ProtectedBoundary)?)?;
                let mount = BrokerSessionManifestV1::decode(self.broker_files.mount_bytes()
                    .ok_or(JournalError::ProtectedBoundary)?)?;
                for (manifest, protocol) in [(&network, BrokerSessionProtocolV1::Network),
                    (&mount, BrokerSessionProtocolV1::Mount)] {
                    manifest.require_all_active()?;
                    if manifest.protocol() != protocol
                        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
                        || manifest.node_id() != node {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                }
                Ok([network, mount])
            })());
            if !matches!(self.host_manifests, Some(Ok(_))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        Ok((storage, network))
    }

    fn verify_advance_inner_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        subject: HostLaunchSubjectDataV1<'_>,
        bundle: ReadyBundleDataV1<'_>,
        compiler: &RootStartResourceCompilerOriginalV2,
    ) -> Result<(), Cause> {
        let verifier = self
            .trust
            .verifier()
            .ok_or(JournalError::ProtectedBoundary)?;
        let fresh = ReadyBundleDataV1 {
            ownership_claim: subject.ownership_claim,
            ownership_lease: subject.ownership_lease,
            ownership_signature: subject.ownership_signature,
            ownership_receipt: subject.ownership_receipt,
            ownership_receipt_signature: subject.ownership_receipt_signature,
            ..bundle
        };
        stage.admit_host_fresh_ownership_once_v1(RootContinuationDemandV1::from_demand_v1(
            ownership_bundle_typed_demand_v1(
                fresh,
                compiler
                    .compiled_v2()?
                    .manifest_v2()
                    .canonical_bytes()
                    .len(),
                verifier,
            ).map_err(|_| JournalError::JournalTooLarge)?,
        ))?;
        self.claim = Some(Box::new(OwnershipClaimDecodeCaptureV1::new()));
        self.response = Some(Box::new(OwnershipResponseVerifyCaptureV1::new()));
        self.claim
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .decode_once_v1(subject.ownership_claim)?;
        let claim = self
            .claim
            .as_ref()
            .and_then(|capture| capture.value())
            .ok_or(JournalError::ProtectedBoundary)?;
        let compiled = compiler.compiled_v2()?;
        let manifest = compiled.manifest_v2().manifest();
        let expected = LeaseAssignment::new(
            manifest.sandbox(),
            manifest.incarnation(),
            manifest.epoch(),
            compiled.manifest_v2().digest(),
        )?;
        let prior = compiler.previous_v2()?.publication_v2().lease();
        if claim.action() != OwnershipClaimAction::Advance
            || claim.request_id().as_slice() != subject.start_operation
            || claim.assignment() != expected
            || claim.desired_generation() != manifest.desired_generation()
            || claim.node() != manifest.node()
            || claim.expected_prior().is_none_or(|expected| {
                expected.generation() != prior.lease().lease_generation() || expected.digest() != prior.digest()
            })
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let sample = self.clock.check_next_once_v1()?;
        verifier.verify_response_bytes_retaining_v1(
            claim,
            subject.ownership_lease,
            subject.ownership_signature,
            subject.ownership_receipt,
            subject.ownership_receipt_signature,
            &sample,
            self.response
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.trust_files
            .capture_failure()
            .map(|cause| cause as _)
            .or_else(|| self.clock.failure())
            .or_else(|| self.trust.failure())
            .or_else(|| {
                self.trust_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.storage_files.capture_failure().map(|cause| cause as _))
            .or_else(|| self.plan_files.capture_failure().map(|cause| cause as _))
            .or_else(|| self.broker_files.capture_failure().map(|cause| cause as _))
            .or_else(|| self.host_manifests.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| {
                self.public_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.plan_public
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.claim
                    .as_ref()
                    .and_then(|capture| capture.failure())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.response.as_ref().and_then(|capture| capture.cause()))
            .or_else(|| {
                self.ownership
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.trust_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.storage_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.plan_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.broker_files.post_failure().map(|cause| cause as _))
    }
}
