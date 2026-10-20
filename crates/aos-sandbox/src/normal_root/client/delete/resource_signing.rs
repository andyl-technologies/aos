//! Constructs and returns one concrete cleanup signature on the same live D.
//!
//! The closed Bank borrower owns the real pending fence. Its genuine C17 turn
//! pays before models, key/message backing or native entry. Root's draft is
//! compared to current protected C, the actual fresh Storage packet/native cut
//! and a verified live lease. Independent native posts remain owed on refusal.

use super::*;
use buffa::Message as _;
use super::initial_inventory::RootDeleteClientInitialOriginalV2;
use aos_sandbox_core::{OperationId, RawPairedClockSample, RevocationScopeId};
use aos_sandbox_ownership_protocol::{OwnershipAuthorityVerifier,
    response_verification::OwnershipResponseVerifyCaptureV1};
use aos_sandbox_protocol::authorization_artifact::{BrokerPlanPreparation, SignedBrokerPlan,
    SigningAuthority, delete_resource_plan::{DeleteResourcePlanPreparationDataV2,
        prepare_admitted_delete_resource_plan_v2}};
use aos_sandbox_protocol::domain_ledger::{lifecycle_model::LifecycleResourceV1,
    delete_root::{inventory_cuts::DeleteSessionInventoryCutDataV2,
        resource_exchange::{DeleteRootResourceContextDataV2, DeleteRootResourceDraftDataV2,
            DeleteRootResourceSignedDataV2}}};
use crate::lifecycle::{DeletePlanningBrokerInventoryDataV2,
    select_first_local_delete_storage_preparation_data_v2};
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    bounded_stream_io::{SliceDeadlineStreamIoV1, DeadlineStreamDirectionV1},
    provisioning_current::current_cleanup_assignment::CurrentCleanupAssignmentDataV2};

type Cause = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy)]
enum SigningFirst { Before, Preparation, Current, Presign, ExternalSigner, Send, After }

pub(super) struct DeleteResourceSigningStateV2 {
    purpose: DeleteResourcePurposeV3,
    interval: RootDeleteClientInitialOriginalV2,
    assignment: Option<CurrentCleanupAssignmentDataV2>,
    resources: Vec<LifecycleResourceV1>,
    lease: OwnershipResponseVerifyCaptureV1,
    preparation: Option<DeleteResourcePlanPreparationDataV2>,
    primary: Option<Result<(), Cause>>,
    current: Option<Result<(), aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1>>,
    presign_original: RetainedKernelPairedClockAttemptV1,
    presign: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    presign_current: Option<Result<(), Cause>>,
    signed: Option<SignedBrokerPlan>,
    encoding: Option<Result<(), Cause>>,
    bytes: Vec<u8>,
    io: SliceDeadlineStreamIoV1,
    sent: Option<Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>>,
    after_time: Option<Result<(), Cause>>,
    first: Option<SigningFirst>,
    finished: bool,
}

/// Retains passive signed request data after the real construction disposed.
/// No decoded signature or caller result can create this receipt.
pub(super) struct DeleteResourceSignedReceiptV2 {
    pub(super) preparation: DeleteResourcePlanPreparationDataV2,
    pub(super) signed: SignedBrokerPlan,
    pub(super) lease: aos_sandbox_ownership_protocol::SignedOwnershipLease,
    pub(super) draft_digest: [u8; 32],
    pub(super) presign_clock: RawPairedClockSample,
    pub(super) after_clock: RawPairedClockSample,
}

impl DeleteResourceSigningStateV2 {
    fn new(purpose: DeleteResourcePurposeV3) -> Self {
        Self { purpose, interval: RootDeleteClientInitialOriginalV2::new(), assignment: None,
            resources: Vec::new(), lease: Default::default(), preparation: None,
            primary: None, current: None, presign_original: Default::default(), presign: None,
            presign_current: None, signed: None, encoding: None, bytes: Vec::new(),
            io: Default::default(), sent: None, after_time: None, first: None, finished: false }
    }

    fn receiving_demand_v2(profile: &ProductionControllerNormalRootProfileV1,
        controller: &Journal, verifier: &OwnershipAuthorityVerifier,
        authority: &SigningAuthority, batch_bytes: usize,
        purpose: DeleteResourcePurposeV3, draft_bytes: &[u8],
    ) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let maximum = DeleteRootResourceSignedDataV2::maximum_encoded_bytes_v2()
            .map_err(|_| invalid())?;
        let mut model = DeleteResourcePlanPreparationDataV2::receiving_demand_v2(authority,
            verifier.authority()).ok_or_else(invalid)?;
        if purpose == DeleteResourcePurposeV3::MountReap62 {
            // The fixed draft codec lends slices without allocating. Pay the
            // actual reached protobuf/Spec decoder before it expands fields.
            let draft = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(draft_bytes, purpose)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let decoding = aos_sandbox_protocol::mount_attachment_anchor::
                attachment_anchor_request_decoding_demand_v4(draft.deadline_free_body.len())
                .map_err(|_| invalid())?;
            // The generated body and the independently rebuilt canonical
            // request coexist until the exact-template comparison completes.
            model = model.checked_add(decoding)?.checked_add(decoding)?;
        }
        let memory = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|n| n.checked_add(std::mem::size_of::<DeleteResourceSignedReceiptV2>().checked_mul(3)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<LifecycleResourceV1>()
                .checked_mul(batch_bytes / 17)?.checked_mul(3)?))
            .and_then(|n| n.checked_add(DeleteBatchViewV1::decode_receiving_bytes_v1(batch_bytes)?))
            .and_then(|n| n.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?))
            .and_then(|n| n.checked_add(aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::
                receiving_construction_bytes_v1()?))
            .and_then(|n| n.checked_add(maximum.checked_mul(3)?))
            .and_then(|n| u64::try_from(n).ok()).ok_or_else(invalid)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|n| n.checked_add(DeleteBatchViewV1::nested_decode_metadata_entries_v1(batch_bytes)?))
            .and_then(|n| u64::try_from(n).ok()).ok_or_else(invalid)?;
        let interval = RootDeleteClientInitialOriginalV2::receiving_recipe_v2(profile, 0, maximum)?;
        interval.checked_add(controller.delete_resource_current_assignment_receiving_demand_v2(verifier)?)?
            .checked_add(model)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory)
                .with(D::OpenFiles, RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
                .with(D::MetadataEntries, names))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            SigningFirst::Before | SigningFirst::After => self.interval.failure()
                .or_else(|| self.after_time.as_ref()?.as_ref().err().map(|e| e.as_ref() as &(dyn Error + 'static))),
            SigningFirst::Current => cause(&self.current),
            SigningFirst::Preparation => self.lease.cause()
                .or_else(|| self.primary.as_ref()?.as_ref().err().map(|e| e.as_ref() as &(dyn Error + 'static))),
            SigningFirst::Presign => self.presign_original.failure()
                .or_else(|| cause(&self.presign))
                .or_else(|| self.presign_current.as_ref()?.as_ref().err().map(|e| e.as_ref() as &(dyn Error + 'static))),
            SigningFirst::Send => self.encoding.as_ref().and_then(|r| r.as_ref().err()).map(|e| e.as_ref() as &(dyn Error + 'static))
                .or_else(|| self.io.failure()).or_else(|| cause(&self.sent)),
            SigningFirst::ExternalSigner => None,
        }
    }

    pub(super) fn c_failure_selected(&self) -> bool {
        matches!(self.first, Some(SigningFirst::Current))
            || matches!(self.first, Some(SigningFirst::Before | SigningFirst::After))
                && self.interval.c_failure_selected()
    }

    pub(super) fn property_failure_view(&self) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(SigningFirst::Before | SigningFirst::After)) {
            self.interval.property_failure_view()
        } else { None }
    }
}

impl RootDeleteClientOriginalV1<'_> {
    pub(crate) fn begin_resource_signing_once_v2(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, authority: &SigningAuthority,
        verifier: &OwnershipAuthorityVerifier,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.begin_resource_signing_once_inner_v3(fence, controller, launch, authority, verifier, None)
    }

    /// Enters the same paid signer interval with the actual accepted7 association.
    ///
    /// # Errors
    /// Retains funding, accepted-owner, draft, native and reentry failures.
    pub(crate) fn begin_apply_resource_signing_once_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, authority: &SigningAuthority,
        verifier: &OwnershipAuthorityVerifier,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.begin_resource_signing_once_inner_v3(fence, controller, launch, authority, verifier, Some(accepted))
    }

    fn begin_resource_signing_once_inner_v3(&mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, authority: &SigningAuthority,
        verifier: &OwnershipAuthorityVerifier,
        accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.resource_draft_comparison_data_v2()?;
        if self.resource_signing_admission[resource_slot_v3(self.resource_purpose)].is_some() || self.resource_signing[resource_slot_v3(self.resource_purpose)].is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        self.resource_signing_admission[resource_slot_v3(self.resource_purpose)] = Some((|| {
            // The raw width bounds the canonical decoder and at most one
            // 17-byte resource row per minimum encoded row. No graph decoder
            // runs merely to compute its own prepayment.
            let received = self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            let demand = DeleteResourceSigningStateV2::receiving_demand_v2(self.profile,
                controller, verifier, authority, fence.batch_bytes()?.len(), self.resource_purpose,
                &received.bytes)?;
            fence.reserve_preaccept_additional_v1(controller, launch,
                self.profile.lower_original_v1(), demand)?;
            fence.reserve_preaccept_additional_v1(controller, launch,
                self.profile.lower_original_v1(), Self::peer_traffic_v1(2)?)?;
            self.association = Some(self.require_resource_flight_pending_v3(fence, controller, launch, accepted));
            if !matches!(self.association, Some(Ok(()))) {
                self.first.get_or_insert(First::Association);
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            self.turn = Some(fence.prepare_preaccept_turn_v1(controller, launch,
                self.profile.lower_original_v1(), ResourceVector::ZERO)?);
            Ok(())
        })());
        if !matches!(self.resource_signing_admission[resource_slot_v3(self.resource_purpose)], Some(Ok(()))) {
            self.first.get_or_insert(First::ResourceSigningAdmission);
            return Err(self.closed);
        }
        self.resource_signing[resource_slot_v3(self.resource_purpose)] = Some(Box::new(DeleteResourceSigningStateV2::new(self.resource_purpose)));
        let open = self.open_data()?;
        let challenge = *self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(self.closed)?;
        if let (Some(stable), Some(turn)) = (self.stable.as_ref(), self.turn.as_mut()) {
            local.interval.begin_native_interval_once_v2(&mut self.connection, stable, turn,
                controller, self.profile, open, challenge);
        }
        if local.interval.before_sample_data_v2().is_err() {
            local.first = Some(SigningFirst::Before);
        }
        // Native custody has entered. Return its attempt even after a refusal,
        // so the caller always reaches the independently prepaid afters.
        Ok(())
    }

    pub(crate) fn prepare_resource_signing_once_v2(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, model: &DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>, authority: &SigningAuthority,
        scope: RevocationScopeId, verifier: &OwnershipAuthorityVerifier,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.prepare_resource_signing_once_inner_v3(fence, controller, launch, model, session, authority, scope, verifier, None)
    }

    /// Rebuilds the exact new-catalog Apply7 plan under the original signer gate.
    ///
    /// # Errors
    /// Retains changed ownership, full inventory, predecessor, model or draft failures.
    pub(crate) fn prepare_apply_resource_signing_once_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, model: &DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>, authority: &SigningAuthority,
        scope: RevocationScopeId, verifier: &OwnershipAuthorityVerifier,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.prepare_resource_signing_once_inner_v3(fence, controller, launch, model, session, authority, scope, verifier, Some(accepted))
    }

    fn prepare_resource_signing_once_inner_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1, model: &DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>, authority: &SigningAuthority,
        scope: RevocationScopeId, verifier: &OwnershipAuthorityVerifier,
        accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
    ) -> Result<(), RootDeleteClientClosedV1> {
        let pending = self.require_resource_flight_pending_v3(fence, controller, launch, accepted);
        let received = self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(self.closed)?;
        if local.primary.is_some() || local.first.is_some() || local.finished {
            local.first.get_or_insert(SigningFirst::ExternalSigner);
            local.interval.mark_external_primary_refusal_v2();
            return Err(self.closed);
        }
        local.primary = Some((|| {
            pending?;
            let before = local.interval.before_sample_data_v2()?;
            received.after_clock.validate_later_sample(before)?;
            let draft = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(&received.bytes, self.resource_purpose)?;
            let context = DeleteRootResourceContextDataV2::decode_for_purpose_v3(draft.context, self.resource_purpose)?;
            context.clock.validate_later_sample(before)?;
            if before.wall_seconds() >= context.policy_expires_seconds {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            let batch = DeleteBatchViewV1::decode(fence.batch_bytes()?)?;
            let LifecycleResourceV1::Sandbox(root) = batch.root()?
                else { return Err(JournalError::ProtectedBoundary.into()); };
            let (count, generation, digest) = model.complete_model_data_v2()
                .ok_or(JournalError::ProtectedBoundary)?;
            let role = match self.resource_purpose {
                DeleteResourcePurposeV3::Network9 => 4,
                DeleteResourcePurposeV3::MountReap62 => 2,
                _ => 3,
            };
            if session.role != role || session.count != count || session.inventory != (generation, digest)
                || session.owner_cut_data_v2()? != received.frame.owners[usize::from(role - 1)] {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            local.assignment = Some(controller.current_delete_resource_assignment_data_v2(root)?);
            local.resources.try_reserve_exact(batch.count(4))?;
            for resource in batch.postorder_resources_data_v2() { local.resources.push(resource?); }
            let selected = local.assignment.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let recovered = &selected.recovered_lease;
            verifier.verify_response_bytes_retaining_v1(selected.gate.claim(), recovered.canonical_lease(),
                recovered.canonical_signature(), recovered.canonical_receipt(), recovered.canonical_receipt_signature(),
                &before, &mut local.lease)?;
            let lease = local.lease.value().ok_or(JournalError::ProtectedBoundary)?;
            if selected.binding.lease_digest() != lease.digest()
                || selected.binding.lease_generation() != lease.generation()
                || context.lease != *lease.digest().as_bytes() {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            let challenge = self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
            let policy = selected.binding.manifest().manifest().policy().digest();
            let preparation = if self.resource_purpose == DeleteResourcePurposeV3::MountReap62 {
                let binding = self.mount_activation.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                context.require_cleanup_current_v4(received.frame, binding.current, binding.approved9, context.lease)?;
                binding.before.validate_later_sample(before)?;
                if local.resources.iter().any(|resource| match resource {
                    LifecycleResourceV1::Sandbox(id) => *id != root,
                    LifecycleResourceV1::Snapshot(_) | LifecycleResourceV1::Attachment(_) => true,
                    _ => false,
                }) { return Err(JournalError::ProtectedBoundary.into()); }
                let inventory = model.mount_inventory_data_v2().ok_or(JournalError::ProtectedBoundary)?;
                if !inventory.slots().is_empty() { return Err(JournalError::ProtectedBoundary.into()); }
                let mut rows = inventory.namespace_anchors_v1().iter()
                    .filter(|row| row.fence().sandbox_id() == root.as_bytes());
                let ready = rows.next().ok_or(JournalError::ProtectedBoundary)?;
                if rows.next().is_some() { return Err(JournalError::ProtectedBoundary.into()); }
                let body = aos_proto::aos::sandbox::local::v1::ApplyAttachmentAnchorRequestV1::
                    decode_from_slice(draft.deadline_free_body)?;
                let request = aos_sandbox_protocol::mount_attachment_anchor::prepare_delete_mount_reap_request_data_v4(
                    selected.binding.manifest(), ready, &binding.stopped, &body.sandbox_spec_bytes,
                    OperationId::from_bytes(challenge.source.operation), challenge.source.nonce,
                    binding.current.commitment_v4()?, challenge.source.cutoff)?;
                aos_sandbox_protocol::authorization_artifact::delete_resource_plan::prepare_admitted_delete_mount_reap_plan_v4(
                    &request, OperationId::from_bytes(challenge.source.operation), policy, lease, before,
                    challenge.source.cutoff, context.policy_expires_seconds, authority.clone(), scope,
                    draft.canonical_plan, draft.canonical_statement).map_err(|error| error as Cause)?
            } else {
                let request = match self.resource_purpose {
                DeleteResourcePurposeV3::MountReap62 => return Err(JournalError::ProtectedBoundary.into()),
                DeleteResourcePurposeV3::Network9 => {
                    let binding = self.network_activation.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(JournalError::ProtectedBoundary)?;
                    context.require_network_predecessor_v4(received.frame, binding.predecessor,
                        binding.predecessor.current.draft, context.lease)?;
                    crate::lifecycle::select_first_local_delete_network_data_v4(root, &local.resources,
                        selected.binding.manifest(), model.network_inventory_data_v4().ok_or(JournalError::ProtectedBoundary)?,
                        model.network_lifecycle_data_v4().ok_or(JournalError::ProtectedBoundary)?,
                        OperationId::from_bytes(challenge.source.operation), challenge.source.nonce,
                        binding.predecessor.commitment_v4()?)?
                }
                purpose => {
                    let request = select_first_local_delete_storage_preparation_data_v2(root, &local.resources,
                        selected.binding.manifest(), model.storage_inventory_data_v2().ok_or(JournalError::ProtectedBoundary)?,
                        model.storage_lifecycle_data_v2().ok_or(JournalError::ProtectedBoundary)?,
                        OperationId::from_bytes(challenge.source.operation), challenge.source.nonce, challenge.source.cutoff)?;
                    if purpose == DeleteResourcePurposeV3::Apply7 {
                        let binding = self.apply_activation.as_ref().and_then(|result| result.as_ref().ok())
                            .ok_or(JournalError::ProtectedBoundary)?;
                        context.require_preparation_current_v3(received.frame, binding.current,
                            binding.current.draft, context.lease)?;
                        request.apply_data_v3(binding.catalog, binding.current)?
                    } else { request }
                }
            };
                prepare_admitted_delete_resource_plan_v2(request.request, request.assignment,
                request.operation, request.request_id, policy, lease, before, challenge.source.cutoff,
                context.policy_expires_seconds, authority.clone(), scope, draft.canonical_plan,
                draft.canonical_statement).map_err(|error| error as Cause)?
            };
            if preparation.deadline_free_body_v2() != draft.deadline_free_body {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            local.preparation = Some(preparation);
            Ok(())
        })());
        if !matches!(local.primary, Some(Ok(()))) {
            local.first = Some(SigningFirst::Preparation);
            local.interval.mark_external_primary_refusal_v2();
            return Err(self.closed);
        }
        Ok(())
    }

    pub(crate) fn resource_signing_preparation_v2(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<&BrokerPlanPreparation, RootDeleteClientClosedV1> {
        self.resource_signing_preparation_inner_v3(fence, controller, launch, None)
    }

    /// Borrows the actual prepared7 under its current accepted-owner frontier.
    ///
    /// # Errors
    /// Rejects reentry, changed accepted custody or incomplete preparation.
    pub(crate) fn apply_resource_signing_preparation_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
            accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
) -> Result<&BrokerPlanPreparation, RootDeleteClientClosedV1> {
        self.resource_signing_preparation_inner_v3(fence, controller, launch, Some(accepted))
    }

    fn resource_signing_preparation_inner_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
            accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
) -> Result<&BrokerPlanPreparation, RootDeleteClientClosedV1> {
        self.association = Some(self.require_resource_flight_pending_v3(fence, controller, launch, accepted));
        if !matches!(self.association, Some(Ok(()))) {
            self.first.get_or_insert(First::Association);
            self.refuse_resource_signer_once_v2();
            return Err(self.closed);
        }
        let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(self.closed)?;
        if local.first.is_some() || local.finished || !matches!(local.primary, Some(Ok(()))) {
            return Err(self.closed);
        }
        local.current = Some(self.turn.as_mut().ok_or(self.closed)?
            .require_prepaid_delete_plan_signing_frontier_v2());
        if !matches!(local.current, Some(Ok(()))) {
            local.first = Some(SigningFirst::Current);
            local.interval.mark_external_primary_refusal_v2();
            return Err(self.closed);
        }
        local.preparation.as_ref().map(|p| p.preparation_v2()).ok_or(self.closed)
    }

    pub(crate) fn final_resource_signing_clock_once_v2(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<RawPairedClockSample, RootDeleteClientClosedV1> {
        self.final_resource_signing_clock_once_inner_v3(fence, controller, launch, None)
    }

    /// Samples the final7 signer frontier without extending its horizon.
    ///
    /// # Errors
    /// Retains clock, currentness, deadline and native-frontier failures.
    pub(crate) fn final_apply_resource_signing_clock_once_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
            accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
) -> Result<RawPairedClockSample, RootDeleteClientClosedV1> {
        self.final_resource_signing_clock_once_inner_v3(fence, controller, launch, Some(accepted))
    }

    fn final_resource_signing_clock_once_inner_v3(&mut self,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
            accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
) -> Result<RawPairedClockSample, RootDeleteClientClosedV1> {
        self.resource_signing_preparation_inner_v3(fence, controller, launch, accepted)?;
        let challenge = *self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let open = self.open_data()?;
        let received = self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(self.closed)?;
        if local.presign.is_some() {
            local.first.get_or_insert(SigningFirst::ExternalSigner);
            local.interval.mark_external_primary_refusal_v2();
            return Err(self.closed);
        }
        local.presign = Some(local.presign_original.observe_once(None));
        local.presign_current = Some((|| {
            let sample = *local.presign.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
            local.interval.before_sample_data_v2()?.validate_later_sample(sample)?;
            require_signing_time_v2(local, received, open, challenge, sample)
        })());
        if !matches!(local.presign_current, Some(Ok(()))) {
            local.first = Some(SigningFirst::Presign);
            local.interval.mark_external_primary_refusal_v2();
            return Err(self.closed);
        }
        local.presign.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(self.closed)
    }

    pub(crate) fn send_resource_signature_once_v2(&mut self, controller: &Journal,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, launch: &ControllerBankLaunchOriginalV1,
        signed: SignedBrokerPlan,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.send_resource_signature_once_inner_v3(controller, fence, launch, signed, None)
    }

    /// Retains and returns the genuine signed7 over the same D connection.
    ///
    /// # Errors
    /// Retains artifact, currentness, encoding and stream failures.
    pub(crate) fn send_apply_resource_signature_once_v3(&mut self, controller: &Journal,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, launch: &ControllerBankLaunchOriginalV1,
        signed: SignedBrokerPlan,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(), RootDeleteClientClosedV1> {
        self.send_resource_signature_once_inner_v3(controller, fence, launch, signed, Some(accepted))
    }

    fn send_resource_signature_once_inner_v3(&mut self, controller: &Journal,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>, launch: &ControllerBankLaunchOriginalV1,
        signed: SignedBrokerPlan,
        accepted: Option<&crate::journal::ControllerDeleteAdmissionOriginalV3>,
    ) -> Result<(), RootDeleteClientClosedV1> {
        {
            let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(self.closed)?;
            if local.signed.is_some() || local.finished {
                local.first.get_or_insert(SigningFirst::ExternalSigner);
                local.interval.mark_external_primary_refusal_v2();
                return Err(self.closed);
            }
            // Park the genuine completed artifact before any later gate,
            // allocation, encoding or transport can refuse its continuation.
            local.signed = Some(signed);
        }
        self.resource_signing_preparation_inner_v3(fence, controller, launch, accepted)?;
        let cutoff = self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?.source.cutoff;
        let received = self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(self.closed)?;
        if !matches!(local.presign_current, Some(Ok(()))) {
            local.first.get_or_insert(SigningFirst::ExternalSigner);
            local.interval.mark_external_primary_refusal_v2();
            return Err(self.closed);
        }
        local.encoding = Some((|| {
            let actual = local.signed.as_ref().ok_or(self.closed)?;
            let expected = local.preparation.as_ref().ok_or(self.closed)?.preparation_v2();
            if actual.canonical_plan() != expected.canonical_plan() {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            let digest = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(&received.bytes, self.resource_purpose)?.digest_for_purpose_v3(self.resource_purpose)?;
            let frame = DeleteRootResourceSignedDataV2 { draft: &digest,
                canonical_signature: actual.canonical_signature() };
            let length = frame.encoded_bytes_v2()?;
            local.bytes.try_reserve_exact(length)?;
            local.bytes.resize(length, 0);
            frame.encode_range_for_purpose_v3(0, &mut local.bytes, self.resource_purpose)?;
            Ok(())
        })());
        if matches!(local.encoding, Some(Ok(()))) {
            local.sent = Some(match self.connection.stream_mut() {
                Ok(stream) => local.io.run_once(stream, &mut local.bytes, cutoff, DeadlineStreamDirectionV1::Write),
                Err(error) => Err(error),
            });
        }
        if !matches!(local.encoding, Some(Ok(()))) || !matches!(local.sent, Some(Ok(()))) {
            local.first = Some(SigningFirst::Send);
            local.interval.mark_external_primary_refusal_v2();
            return Err(self.closed);
        }
        Ok(())
    }

    pub(crate) fn resource_signing_original_failure_is_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::ResourceSigningAdmission | First::SourceAdmission | First::Association
            | First::ResourceSigningDisposal))
            || self.resource_signing[resource_slot_v3(self.resource_purpose)].as_ref().is_some_and(|local|
                local.first.is_some_and(|first| !matches!(first, SigningFirst::ExternalSigner)))
    }

    pub(crate) fn refuse_resource_signer_once_v2(&mut self) {
        if let Some(local) = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut() {
            local.first.get_or_insert(SigningFirst::ExternalSigner);
            local.interval.mark_external_primary_refusal_v2();
        }
    }

    pub(crate) fn finish_resource_signing_once_v2(&mut self, controller: &mut Journal)
        -> Result<(), RootDeleteClientClosedV1> {
        if self.resource_signing_complete[resource_slot_v3(self.resource_purpose)].is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(self.closed);
        }
        let open = self.open_data()?;
        let challenge = *self.challenge.as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let received = self.resource_draft_complete[resource_slot_v3(self.resource_purpose)].as_ref().and_then(|r| r.as_ref().ok()).ok_or(self.closed)?;
        let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(self.closed)?;
        if local.finished { return Err(self.closed); }
        local.finished = true;
        if !matches!(local.sent, Some(Ok(()))) {
            local.first.get_or_insert(SigningFirst::ExternalSigner);
            local.interval.mark_external_primary_refusal_v2();
        }
        if let (Some(stable), Some(turn)) = (self.stable.as_ref(), self.turn.as_mut()) {
            local.interval.finish_native_interval_once_v2(&mut self.connection, stable, turn,
                controller, self.profile, open, challenge);
        }
        local.after_time = Some((|| {
            let after = local.interval.after_sample_data_v2()?;
            if let Some(Ok(presign)) = local.presign.as_ref() { presign.validate_later_sample(after)?; }
            require_signing_time_v2(local, received, open, challenge, after)
        })());
        if !local.interval.completed_interval_v2() || !matches!(local.after_time, Some(Ok(()))) {
            local.first.get_or_insert(SigningFirst::After);
        }
        if local.first.is_some() {
            self.first.get_or_insert(First::ResourceSigning);
            return Err(self.closed);
        }
        self.resource_signing_complete[resource_slot_v3(self.resource_purpose)] = Some((|| {
            let token = self.turn.as_mut().ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            let local = self.resource_signing[resource_slot_v3(self.resource_purpose)].as_mut().ok_or(JournalError::ProtectedBoundary)?;
            let preparation = local.preparation.take().ok_or(JournalError::ProtectedBoundary)?;
            let signed = local.signed.take().ok_or(JournalError::ProtectedBoundary)?;
            // Move the actual already-verified lease into continued D custody.
            // Later26 uses the exact signed quartet without reparsing or
            // adopting a current lease from its hash or a caller model.
            let lease = local.lease.take_value_once().ok_or(JournalError::ProtectedBoundary)?;
            let draft_digest = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(&received.bytes, self.resource_purpose)
                .and_then(|draft| draft.digest_for_purpose_v3(self.resource_purpose)).map_err(|_| JournalError::StaleAuthoritySnapshot)?;
            let presign_clock = *local.presign.as_ref().and_then(|r| r.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let after_clock = local.interval.after_sample_data_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            drop(self.resource_signing[resource_slot_v3(self.resource_purpose)].take());
            token.complete_after_upper_disposal_v1();
            Ok(DeleteResourceSignedReceiptV2 { preparation, signed, lease, draft_digest, presign_clock, after_clock })
        })());
        if !matches!(self.resource_signing_complete[resource_slot_v3(self.resource_purpose)], Some(Ok(_))) {
            self.first = Some(First::ResourceSigningDisposal);
            return Err(self.closed);
        }
        drop(self.turn.take());
        Ok(())
    }
}

fn require_signing_time_v2(local: &DeleteResourceSigningStateV2,
    received: &super::initial_inventory::ResourceDraftReceiptV2,
    open: DeleteRootOpenDataV2, challenge: DeleteRootChallengeDataV2, sample: RawPairedClockSample,
) -> Result<(), Cause> {
    let draft = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(&received.bytes, local.purpose)?;
    let context = DeleteRootResourceContextDataV2::decode_for_purpose_v3(draft.context, local.purpose)?;
    context.clock.validate_later_sample(sample)?;
    received.after_clock.validate_later_sample(sample)?;
    super::initial_inventory::require_cutoff(sample, open, challenge.source.cutoff)?;
    let lease = local.lease.value().ok_or(JournalError::ProtectedBoundary)?;
    let plan = local.preparation.as_ref().ok_or(JournalError::ProtectedBoundary)?.preparation_v2().plan_data_v1();
    if sample.wall_seconds() >= context.policy_expires_seconds
        || sample.wall_seconds() >= lease.authority_expires_seconds()
        || sample.wall_seconds() >= plan.expires_seconds() {
        return Err(JournalError::StaleAuthoritySnapshot.into());
    }
    Ok(())
}
