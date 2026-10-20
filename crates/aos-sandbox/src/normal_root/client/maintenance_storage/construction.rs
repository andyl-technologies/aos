//! Retains Maintenance's real fixed-credential comparison and signing window.
//!
//! The original M lender supplies its actual current C and completed Storage
//! Session. The worker lends its existing ownership verifier and signing
//! authority. The common retained quartet verifier and admitted method31
//! normalizer perform all decoding and cryptography; no Start owner is made.

use super::*;
use crate::policy_compiler::provisioning_current::current_cleanup_assignment::CurrentCleanupAssignmentDataV2;
use aos_sandbox_core::{LeaseAssignment, RevocationScopeId};
use aos_sandbox_ownership_protocol::{
    OwnershipAuthorityVerifier, response_verification::OwnershipResponseVerifyCaptureV1,
};
use aos_sandbox_protocol::authorization_artifact::{
    BrokerPlanPreparation, SignedBrokerPlan, SigningAuthority,
    start_resource_plan::{
        StartResourcePlanPreparationDataV1, prepare_admitted_start_storage_guest_root_plan_v2,
        start_storage_guest_root_normalization_receiving_demand_v2,
    },
};

#[derive(Clone, Copy)]
enum ConstructionFirst {
    BeforeClock,
    BeforeTime,
    BeforePeer,
    Preparation,
    Presign,
    Signed,
    External,
    AfterPeer,
    AfterClock,
    AfterTime,
}

pub(super) struct Construction {
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), HistoryErrorV1>>,
    before_peer: Box<PeerSampleV1>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    selected: Option<CurrentCleanupAssignmentDataV2>,
    lease: OwnershipResponseVerifyCaptureV1,
    preparation: Option<StartResourcePlanPreparationDataV1>,
    primary: Option<Result<(), Cause>>,
    presign_clock: RetainedKernelPairedClockAttemptV1,
    presign_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    presign_time: Option<Result<(), Cause>>,
    signed: Option<SignedBrokerPlan>,
    signed_comparison: Option<Result<(), HistoryErrorV1>>,
    after_peer: Box<PeerSampleV1>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_time: Option<Result<(), Cause>>,
    finished: bool,
    first: Option<ConstructionFirst>,
}

impl Construction {
    pub(super) fn retire_positive_peers_once_v3(&mut self) -> Result<(), Cause> {
        if self.first.is_some() || !self.finished {
            return Err(RootMaintenanceStorageClientClosedV3.into());
        }
        if let Err(cause) = self.before_peer.settle_positive_once() {
            self.first = Some(ConstructionFirst::BeforePeer);
            return Err(cause.into());
        }
        if let Err(cause) = self.after_peer.settle_positive_once() {
            self.first = Some(ConstructionFirst::AfterPeer);
            return Err(cause.into());
        }
        Ok(())
    }

    pub(super) fn completed_after_clock_data_v3(
        &self,
    ) -> Result<RawPairedClockSample, HistoryErrorV1> {
        if self.first.is_some() || !self.finished {
            return Err(HistoryErrorV1::Correlation);
        }
        positive(&self.after_sample).copied()
    }

    fn new() -> Self {
        Self {
            before_clock: Default::default(),
            before_sample: None,
            before_time: None,
            before_peer: Box::new(PeerSampleV1::new()),
            before: None,
            selected: None,
            lease: Default::default(),
            preparation: None,
            primary: None,
            presign_clock: Default::default(),
            presign_sample: None,
            presign_time: None,
            signed: None,
            signed_comparison: None,
            after_peer: Box::new(PeerSampleV1::new()),
            after: None,
            after_clock: Default::default(),
            after_sample: None,
            after_time: None,
            finished: false,
            first: None,
        }
    }

    fn receiving_demand(
        opening: &Opening,
        controller: &Journal,
        verifier: &OwnershipAuthorityVerifier,
    ) -> Result<ResourceVector, Cause> {
        let bad = || ResourceReservationErrorV1::Conflict;
        let native = CreateStorageRootPeerReceivingOriginalsV1::provisioning_turn_native_peak_v1(
            &opening.profile,
        )
        .ok_or_else(bad)?;
        let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or_else(bad)?;
        let memory = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<crate::ControllerMaintenanceStorageRequestOriginalV3>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(clocks))
            .and_then(|bytes| {
                bytes.checked_add(
                    OwnershipResponseVerifyCaptureV1::receiving_construction_bytes_v1()?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(bad)?;
        let files = RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(3)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or_else(bad)?;
        let metadata = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|cells| cells.checked_mul(3))
            .and_then(|cells| u64::try_from(cells).ok())
            .ok_or_else(bad)?;
        // This existing supplier bounds the common current-assignment decoder
        // and full quartet verification from actual protected C extents. It
        // grants no Delete authority and decodes nothing to price itself.
        Ok(native
            .checked_add(
                controller.delete_resource_current_assignment_receiving_demand_v2(verifier)?,
            )?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, files)
                    .with(D::MetadataEntries, metadata),
            )?)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            ConstructionFirst::BeforeClock => self
                .before_clock
                .failure()
                .or_else(|| cause(&self.before_sample)),
            ConstructionFirst::BeforeTime => cause(&self.before_time),
            ConstructionFirst::BeforePeer => {
                self.before_peer.failure().or_else(|| cause(&self.before))
            }
            ConstructionFirst::Preparation => {
                self.lease.cause().or_else(|| boxed_cause(&self.primary))
            }
            ConstructionFirst::Presign => self
                .presign_clock
                .failure()
                .or_else(|| cause(&self.presign_sample))
                .or_else(|| boxed_cause(&self.presign_time)),
            ConstructionFirst::Signed => cause(&self.signed_comparison),
            ConstructionFirst::External => None,
            ConstructionFirst::AfterPeer => {
                self.after_peer.failure().or_else(|| cause(&self.after))
            }
            ConstructionFirst::AfterClock => self
                .after_clock
                .failure()
                .or_else(|| cause(&self.after_sample)),
            ConstructionFirst::AfterTime => boxed_cause(&self.after_time),
        }
    }
}

impl RootMaintenanceStorageClientOriginalV3 {
    pub(crate) fn construction_external_failure_selected_v3(&self) -> bool {
        self.construction
            .as_ref()
            .is_some_and(|local| matches!(local.first, Some(ConstructionFirst::External)))
    }

    pub(crate) fn take_completed_request_once_v3(
        &mut self,
    ) -> Result<
        crate::ControllerMaintenanceStorageRequestOriginalV3,
        RootMaintenanceStorageClientClosedV3,
    > {
        if self.first.is_some() || self.transferred_request.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        let opening = self
            .state
            .as_ref()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        let local = self
            .construction
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        if local.first.is_some()
            || !local.finished
            || !matches!(local.after, Some(Ok(())))
            || !matches!(local.after_time, Some(Ok(())))
            || !matches!(local.signed_comparison, Some(Ok(())))
            || local.lease.value().is_none()
            || local.preparation.is_none()
            || local.signed.is_none()
        {
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        let query = positive(&opening.query)
            .and_then(|query| query.digest_v2())
            .map_err(|_| RootMaintenanceStorageClientClosedV3)?;
        let request =
            crate::ControllerMaintenanceStorageRequestOriginalV3::from_completed_construction_v3(
                local
                    .preparation
                    .take()
                    .ok_or(RootMaintenanceStorageClientClosedV3)?,
                local
                    .signed
                    .take()
                    .ok_or(RootMaintenanceStorageClientClosedV3)?,
                local
                    .lease
                    .take_value_once()
                    .ok_or(RootMaintenanceStorageClientClosedV3)?,
                query,
                opening.origin,
                opening.cutoff,
            );
        self.transferred_request = Some(request.commitment_data_v3());
        Ok(request)
    }

    pub(crate) fn require_transferred_request_v3(
        &self,
        request: &crate::ControllerMaintenanceStorageRequestOriginalV3,
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        let opening = self
            .state
            .as_ref()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        let local = self
            .construction
            .as_ref()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        if self.first.is_some()
            || local.first.is_some()
            || !local.finished
            || self.transferred_request != Some(request.commitment_data_v3())
            || request.query_data_v3()
                != positive(&opening.query)
                    .and_then(|query| query.digest_v2())
                    .map_err(|_| RootMaintenanceStorageClientClosedV3)?
            || request.cutoff_data_v3() != opening.cutoff
        {
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        Ok(())
    }

    pub(super) fn add_receiving_demand_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
        additional: ResourceVector,
        observations: usize,
    ) -> Result<(), Cause> {
        self.complete = self.complete.checked_add(additional)?;
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        funding
            .charge(
                &mut RootClientLoanV1::MaintenanceStorage(loan),
                controller,
                observations,
                0,
                0,
            )
            .map_err(|_| RootMaintenanceStorageClientClosedV3)?;
        Ok(())
    }

    pub(crate) fn begin_construction_once_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
        verifier: &OwnershipAuthorityVerifier,
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        if self.first.is_some() || self.construction_entry.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        self.construction_entry = Some((|| -> Result<(), Cause> {
            loan.require_initial_inventory_v3(controller)?;
            let opening = self
                .state
                .as_ref()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            positive(&opening.temporal)?;
            let demand = Construction::receiving_demand(opening, controller, verifier)?;
            self.add_receiving_demand_v3(loan, controller, demand, 2)?;
            self.construction = Some(Box::new(Construction::new()));
            Ok(())
        })());
        if !matches!(self.construction_entry, Some(Ok(()))) {
            self.first = Some(First::Construction);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        let opening = self
            .state
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        let local = self
            .construction
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        local.before_sample = Some(local.before_clock.observe_once(Some(opening.origin)));
        local.before_time = Some((|| {
            let before = *positive(&local.before_sample)?;
            positive(&opening.after_sample)?
                .validate_later_sample(before)
                .map_err(|_| HistoryErrorV1::Malformed)?;
            require_original_sample(opening.origin, opening.cutoff, before)
        })());
        if !matches!(local.before_sample, Some(Ok(_))) {
            local.first = Some(ConstructionFirst::BeforeClock);
        } else if !matches!(local.before_time, Some(Ok(()))) {
            local.first = Some(ConstructionFirst::BeforeTime);
        }
        if local.first.is_none() {
            local.before = Some((|| {
                local
                    .before_peer
                    .observe_against_sample_with_cutoff_once_v1(
                        &opening.profile,
                        opening
                            .connection
                            .stream()
                            .map_err(|_| NormalRootStartupErrorV1::Service)?,
                        opening
                            .peer_before
                            .as_deref()
                            .ok_or(NormalRootStartupErrorV1::Service)?,
                        None,
                        false,
                        opening.cutoff,
                    )
            })());
            if !matches!(local.before, Some(Ok(()))) {
                local.first = Some(ConstructionFirst::BeforePeer);
            }
        }
        // Return the entered attempt even on a refused native before. Its
        // concrete borrower must still reach the separately prepaid posts.
        Ok(())
    }

    pub(crate) fn prepare_construction_once_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
        verifier: &OwnershipAuthorityVerifier,
        authority: &SigningAuthority,
        scope: RevocationScopeId,
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        let local = self
            .construction
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        if local.first.is_some() || local.primary.is_some() || local.finished {
            local.first.get_or_insert(ConstructionFirst::External);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        // Complete source-bound decoding and retained verification were paid
        // before constructing this phase. The common activated gate owns the
        // original claim, so no claim or acceptance surrogate is reconstructed.
        local.primary = Some((|| -> Result<(), Cause> {
            local.selected = Some(loan.current_assignment_data_v3(controller)?);
            let selected = local
                .selected
                .as_ref()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let recovered = &selected.recovered_lease;
            let before = *positive(&local.before_sample)?;
            verifier.verify_response_bytes_retaining_v1(
                selected.gate.claim(),
                recovered.canonical_lease(),
                recovered.canonical_signature(),
                recovered.canonical_receipt(),
                recovered.canonical_receipt_signature(),
                &before,
                &mut local.lease,
            )?;
            let lease = local
                .lease
                .value()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let manifest = selected.binding.manifest().manifest();
            let assignment = LeaseAssignment::new(
                manifest.sandbox(),
                manifest.incarnation(),
                manifest.epoch(),
                selected.binding.manifest().digest(),
            )?;
            let opening = self
                .state
                .as_ref()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let admission = positive(&opening.reply)?;
            if lease.assignment() != assignment
                || lease.node() != manifest.node()
                || lease.digest() != selected.binding.lease_digest()
                || lease.generation() != selected.binding.lease_generation()
                || lease.authority_expires_seconds() != admission.lease_expires_seconds
            {
                return Err(RootMaintenanceStorageClientClosedV3.into());
            }
            Ok(())
        })());
        if !matches!(local.primary, Some(Ok(()))) {
            local.first = Some(ConstructionFirst::Preparation);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        let model = (|| -> Result<ResourceVector, Cause> {
            let opening = self
                .state
                .as_ref()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let reply = MaintenanceStorageReplyDataV2::decode_v2(opening.received.bytes())?;
            let lease = self
                .construction
                .as_ref()
                .and_then(|local| local.lease.value())
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let demand = start_storage_guest_root_normalization_receiving_demand_v2(
                opening.request_body.len(),
                reply.canonical_plan.len(),
                reply.canonical_statement.len(),
                lease,
                authority,
            )
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let signing = aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::
                receiving_construction_bytes_v1().and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            Ok(demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, signing))?)
        })();
        let paid =
            model.and_then(|demand| self.add_receiving_demand_v3(loan, controller, demand, 0));
        let local = self
            .construction
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        local.primary = Some(paid.and_then(|()| {
            loan.require_current_v3(controller)?;
            let opening = self
                .state
                .as_ref()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let reply = MaintenanceStorageReplyDataV2::decode_v2(opening.received.bytes())?;
            let selected = local
                .selected
                .as_ref()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let manifest = selected.binding.manifest();
            local.preparation = Some(prepare_admitted_start_storage_guest_root_plan_v2(
                &opening.request_body,
                &loan.canonical_arguments_data_v3(controller)?,
                manifest,
                manifest.manifest().policy().digest(),
                local
                    .lease
                    .value()
                    .ok_or(RootMaintenanceStorageClientClosedV3)?,
                *positive(&local.before_sample)?,
                opening.cutoff,
                positive(&opening.reply)?.policy_expires_seconds,
                authority.clone(),
                scope,
                reply.canonical_plan,
                reply.canonical_statement,
            )?);
            Ok(())
        }));
        if !matches!(local.primary, Some(Ok(()))) {
            local.first = Some(ConstructionFirst::Preparation);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        Ok(())
    }

    pub(crate) fn signing_preparation_v3(
        &self,
    ) -> Result<&BrokerPlanPreparation, RootMaintenanceStorageClientClosedV3> {
        if self.first.is_some() {
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        let local = self
            .construction
            .as_ref()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        if local.first.is_some() || local.finished || !matches!(local.primary, Some(Ok(()))) {
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        Ok(&local
            .preparation
            .as_ref()
            .ok_or(RootMaintenanceStorageClientClosedV3)?
            .preparation)
    }

    pub(crate) fn final_signing_clock_once_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
    ) -> Result<RawPairedClockSample, RootMaintenanceStorageClientClosedV3> {
        self.signing_preparation_v3()?;
        let opening = self
            .state
            .as_ref()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        let local = self
            .construction
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        if local.presign_sample.is_some() {
            local.first = Some(ConstructionFirst::Presign);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        local.presign_sample = Some(local.presign_clock.observe_once(Some(opening.origin)));
        local.presign_time = Some((|| -> Result<(), Cause> {
            loan.require_current_v3(controller)?;
            let now = *positive(&local.presign_sample)?;
            positive(&local.before_sample)?.validate_later_sample(now)?;
            require_original_sample(opening.origin, opening.cutoff, now)?;
            let lease = local
                .lease
                .value()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            if now.wall_seconds() >= positive(&opening.reply)?.policy_expires_seconds
                || now.wall_seconds() >= lease.authority_expires_seconds()
            {
                return Err(RootMaintenanceStorageClientClosedV3.into());
            }
            Ok(())
        })());
        if !matches!(local.presign_time, Some(Ok(()))) {
            local.first = Some(ConstructionFirst::Presign);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        positive(&local.presign_sample)
            .copied()
            .map_err(|_| RootMaintenanceStorageClientClosedV3)
    }

    pub(crate) fn retain_signed_once_v3(
        &mut self,
        signed: SignedBrokerPlan,
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        self.signing_preparation_v3()?;
        let local = self
            .construction
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        let already = local.signed.is_some();
        // Retain the actual result before comparing; a refused signed owner
        // cannot disappear through an error return or be replaced by retry.
        if already {
            local.first = Some(ConstructionFirst::Signed);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        local.signed = Some(signed);
        local.signed_comparison = Some((|| {
            positive(&local.presign_time)?;
            let signed = local.signed.as_ref().ok_or(HistoryErrorV1::Malformed)?;
            let prepared = &local
                .preparation
                .as_ref()
                .ok_or(HistoryErrorV1::Malformed)?
                .preparation;
            if signed.canonical_plan() != prepared.canonical_plan()
                || signed.plan() != prepared.plan_data_v1()
            {
                return Err(HistoryErrorV1::Malformed);
            }
            Ok(())
        })());
        if !matches!(local.signed_comparison, Some(Ok(()))) {
            local.first = Some(ConstructionFirst::Signed);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        Ok(())
    }

    pub(crate) fn finish_construction_once_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
        body_succeeded: bool,
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        let opening = self
            .state
            .as_ref()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        let local = self
            .construction
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        if local.finished {
            self.first.get_or_insert(First::Reentry);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        local.finished = true;
        if !body_succeeded || !matches!(local.signed_comparison, Some(Ok(()))) {
            local.first.get_or_insert(ConstructionFirst::External);
        }
        // Each destination runs after every entered body, independently of a
        // failed before, crypto/model/key refusal or earlier post failure.
        local.after = Some((|| {
            local.after_peer.observe_against_sample_with_cutoff_once_v1(
                &opening.profile,
                opening
                    .connection
                    .stream()
                    .map_err(|_| NormalRootStartupErrorV1::Service)?,
                opening
                    .peer_before
                    .as_deref()
                    .ok_or(NormalRootStartupErrorV1::Service)?,
                None,
                true,
                opening.cutoff,
            )
        })());
        if !matches!(local.after, Some(Ok(()))) {
            local.first.get_or_insert(ConstructionFirst::AfterPeer);
        }
        local.after_sample = Some(local.after_clock.observe_once(Some(opening.origin)));
        if !matches!(local.after_sample, Some(Ok(_))) {
            local.first.get_or_insert(ConstructionFirst::AfterClock);
        }
        local.after_time = Some((|| -> Result<(), Cause> {
            loan.require_current_v3(controller)?;
            let after = *positive(&local.after_sample)?;
            positive(&local.before_sample)?.validate_later_sample(after)?;
            if let Some(Ok(presign)) = local.presign_sample {
                presign.validate_later_sample(after)?;
            }
            require_original_sample(opening.origin, opening.cutoff, after)?;
            Ok(())
        })());
        if !matches!(local.after_time, Some(Ok(()))) {
            local.first.get_or_insert(ConstructionFirst::AfterTime);
        }
        if local.first.is_some() {
            self.first.get_or_insert(First::Construction);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        Ok(())
    }
}

fn boxed_cause(value: &Option<Result<(), Cause>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()?
        .as_ref()
        .err()
        .map(|cause| cause.as_ref() as &(dyn Error + 'static))
}
