//! Runs one closed Start Source transition and all independently owed posts.

use super::*;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::lifecycle::{LifecycleProtectedJournalOwnerV1,lifecycle_public_mutation_admission_v1,
    lifecycle_operation_from_public_mutation_v1};

impl StartSourceOriginOriginalV1 {
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn admit_once_v1(
        &mut self,state:&mut StartNativeStateV1,plan:&Arc<crate::OperationPlan>,origin:StartNativeOriginDataV1,
        controller:&mut Journal,source:&mut ProtectedSourceDomainJournalOwnerV1,
    )->Result<(),ResourceReservationErrorV1> {
        self.run_once_v2(state, plan, origin, controller, source, None)
    }

    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry) fn run_once_v2(
        &mut self, state: &mut StartNativeStateV1, plan: &Arc<crate::OperationPlan>,
        origin: StartNativeOriginDataV1, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        completion: Option<&super::super::terminal::StartTerminalMaterialV2>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered {self.first.get_or_insert(First::Reentry);return Err(CLOSED);}
        self.entered=true;
        self.next=Some((|| {
            let base=state.history_resident.ok_or(CLOSED)?.checked_add(Self::fixed_demand_v1()?)?;
            self.base=Some(base);
            state.begin_next_start_native_v1(controller,base)
        })());
        // The new C turn starts from a completed Host/previous Source turn.
        // Its distinct after is now owed even if Source acquisition refuses.
        self.controller_entered = state.after.is_none();
        if !matches!(self.next,Some(Ok(()))) {self.first=Some(First::Next);}
        if self.first.is_none() {
            self.native=Some((|| {
                let native=state.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .begin_provisioning_source_native_v1(native.original_mut_v1(),controller,source.journal(),
                        state.profile.as_ref(),self.base.ok_or(CLOSED)?)
            })());
            if self.native.as_ref().and_then(|value|value.as_ref().ok()).is_none_or(|native|native.failure().is_some()) {
                self.first=Some(First::Native);
            }
        }
        if self.first.is_none() {
            self.before=Some(self.before_clock.observe_once(Some(origin.first_native_clock_v1())));
            if !matches!(self.before,Some(Ok(_))) {self.first=Some(First::Clock);}
        }
        if let Some(Ok(sample))=self.before.as_ref() {
            self.time=Some(Self::require_sample_v1(origin,*sample));
            if !matches!(self.time,Some(Ok(()))) {self.first.get_or_insert(First::Time);}
        }
        if self.first.is_none() {
            self.models=Some((|| {
                // Held native metadata IO occurs only after the actual Source
                // before, and complete schema growth follows the C debit.
                let models = crate::lifecycle::start_provisioning_source_receiving_demand_v2(
                    source.journal_ref_v1(), self.purpose)?;
                let scan=crate::lifecycle::protected_journal::LifecycleReplayReceivingV1::
                    additional_selection_receiving_v1(source.journal_ref_v1().all_records()).ok_or(CLOSED)?;
                Ok(self.base.ok_or(CLOSED)?.checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)?
                    .checked_add(models)?.checked_add(scan)?
                    .checked_add(plan.start_source_context_receiving_demand_v1(controller).ok_or(CLOSED)?)?
                    .checked_add(if self.purpose == StartSourcePurposeV2::SemanticCommit {
                        completion.ok_or(CLOSED)?.semantic_receiving_demand_v2(controller)?
                    } else { ResourceVector::ZERO })?)
            })());
            if !matches!(self.models,Some(Ok(_))) {self.first=Some(First::Models);}
        }
        if let Some(Ok(complete))=self.models.as_ref() {
            self.funding=Some((|| {
                let native=state.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_create_provisioning_complete_v1(native.original_mut_v1(),controller,
                        state.profile.as_ref(),*complete)
            })());
            if !matches!(self.funding,Some(Ok(()))) {self.first.get_or_insert(First::Funding);}
        }
        if self.first.is_none() {
            self.replay = Some(if self.purpose == StartSourcePurposeV2::Admission {
                self.read.observe_projection_once_v1(source.journal_ref_v1())
            } else {
                self.read.observe_once_v1(source.journal_ref_v1(), plan.operation_id())
            });
            if !matches!(self.replay,Some(Ok(()))) {self.first=Some(First::Replay);}
        }
        if self.first.is_none() {
            self.writer_models=Some((|| {
                let (_,verifier)=self.read.projection_ready_v1()?;
                let clones=verifier.writer_clone_receiving_demand_v1().ok_or(CLOSED)?;
                Ok(self.models.as_ref().and_then(|value|value.as_ref().ok()).copied().ok_or(CLOSED)?.checked_add(clones)?)
            })());
            if !matches!(self.writer_models,Some(Ok(_))) {self.first=Some(First::WriterModels);}
        }
        if let Some(Ok(complete))=self.writer_models.as_ref() {
            self.writer_funding=Some((|| {
                let native=state.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_create_provisioning_complete_v1(native.original_mut_v1(),controller,state.profile.as_ref(),*complete)
            })());
            if !matches!(self.writer_funding,Some(Ok(()))) {self.first.get_or_insert(First::WriterFunding);}
        }
        if self.first.is_none() {
            self.context=Some(plan.original_start_context_v1());
            if !matches!(self.context,Some(Ok(_))) {self.first=Some(First::Context);}
        }
        if self.first.is_none() {
            self.expected=Some((|| {
                plan.require_accepted_start_data_v1(controller).map_err(|_|SourceAdmissionErrorV1::Closed)?;
                if self.purpose != StartSourcePurposeV2::Admission {
                    self.identity = Some(source.journal_ref_v1().source_provisioning_identity_v1()?);
                    return Ok(self.read.operation_v1()?.0.clone());
                }
                let context=self.context.as_ref().and_then(|value|value.as_ref().ok()).ok_or(SourceAdmissionErrorV1::Closed)?;
                let request=context.validated_request()?;
                if !matches!(request,aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Start(_)) {
                    return Err(SourceAdmissionErrorV1::Closed);
                }
                controller.require_public_mutation_targets_live_v2(context.project(), &request)?;
                self.identity=Some(source.journal_ref_v1().source_provisioning_identity_v1()?);
                let native=state.native.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
                let node=state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .current_start_provisioning_node_v1(native.original_v1(),controller,state.profile.as_ref())?;
                let admission=lifecycle_public_mutation_admission_v1(controller,plan.operation_id(),context.project(),node,&request)?;
                let expected=lifecycle_operation_from_public_mutation_v1(plan.operation_id(),context.caller(),
                    context.project(),context.accepted_wall_seconds(),context.canonical_request(),&request,admission)?;
                Ok(expected)
            })());
            if !matches!(self.expected,Some(Ok(_))) {self.first=Some(First::Expected);}
        }
        if self.first.is_none() {
            // Keep the complete actual model before the in-place origin
            // check, including its refused state if that check fails.
            self.expected_origin=Some(match self.expected.as_mut().and_then(|value|value.as_mut().ok()) {
                Some(expected) if self.purpose == StartSourcePurposeV2::Admission =>
                    expected.select_start_native_origin_retaining_v1(origin),
                Some(expected) if expected.start_native_origin_v1() == Some(origin)
                    && expected.phase() == self.purpose.expected_phase_v2() => Ok(()),
                Some(_) => Err(aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError::InvalidModel),
                None=>Err(aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError::InvalidModel),
            });
            if !matches!(self.expected_origin,Some(Ok(()))) {self.first=Some(First::ExpectedOrigin);}
        }
        if self.first.is_none() && self.purpose == StartSourcePurposeV2::SemanticCommit {
            self.semantic = Some((|| {
                let material = completion.ok_or(SourceAdmissionErrorV1::Closed)?;
                let expected = self.expected.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(SourceAdmissionErrorV1::Closed)?;
                let sample = self.before.as_ref().and_then(|value| value.as_ref().ok()).copied()
                    .ok_or(SourceAdmissionErrorV1::Closed)?;
                material.prepare_semantic_commit_v2(expected, controller, sample)
            })());
            if !matches!(self.semantic, Some(Ok(_))) { self.first = Some(First::Semantic); }
        }
        if self.first.is_none() {
            let authorization=StartSourceAdmissionAuthorizationV1{state:self,native:state,controller,plan,origin,completion};
            self.prepared=Some((|| {
                let owner=LifecycleProtectedJournalOwnerV1::claim_original_start_source_v1(source,&authorization)?;
                authorization.prepare_turn_v2(&owner)
            })());
            if !matches!(self.prepared,Some(Ok(_))) {self.first=Some(First::Prepared);}
        }
        if self.first.is_none() {
            self.binding=Some((|| {
                let transaction=self.prepared.as_ref().and_then(|value|value.as_ref().ok())
                    .and_then(|value|value.transaction_v1());
                let Some(transaction)=transaction else {return Ok(());};
                let source_native=self.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                let native=state.native.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .bind_provisioning_source_native_v1(source_native,native.original_v1(),controller,
                        source.journal(),state.profile.as_ref(),transaction)
            })());
            if !matches!(self.binding,Some(Ok(()))) {self.first=Some(First::Binding);}
        }
        if self.first.is_none() {
            let authorization=StartSourceAdmissionAuthorizationV1{state:self,native:state,controller,plan,origin,completion};
            self.committed=Some((|| {
                let mut owner=LifecycleProtectedJournalOwnerV1::claim_original_start_source_v1(source,&authorization)
                    .map_err(|cause|crate::protected_domain_journal::ResidentDomainCommitFailureV1::Before(cause.into()))?;
                let prepared=self.prepared.as_ref().and_then(|value|value.as_ref().ok())
                    .ok_or_else(||crate::protected_domain_journal::ResidentDomainCommitFailureV1::Before(
                        crate::JournalError::ProtectedBoundary.into()))?;
                owner.commit_original_start_source_admission_v1(prepared,&authorization)
            })());
            // Move the whole actual final-clock owner only after the commit
            // authorization borrow ends. The occupied retained slot prevents
            // any later authorization from rearming the temporary destination.
            self.append_clock_retained = Some(std::mem::take(self.append_clock.get_mut()));
            if !matches!(self.committed,Some(Ok(_))) {self.first=Some(First::Commit);}
        }
        // Every reached Source after is independent of all body Results.
        if let Some(Ok(native))=self.native.as_mut() {
            self.source_after=Some(source.journal_ref_v1().finish_source_provisioning_native_v1(native));
            if !matches!(self.source_after,Some(Ok(()))) {self.first.get_or_insert(First::SourceAfter);}
        }
        if self.controller_entered && state.after.is_none() {
            self.controller_after=Some(state.finish_native_once_v1(controller));
            if !matches!(self.controller_after,Some(Ok(()))) {self.first.get_or_insert(First::NativeAfter);}
        }
        // These distinct paid clock destinations run even when Source/C posts
        // failed. Original accepted coordinates and cutoff never change.
        if self.controller_entered && state.native.as_ref().is_some_and(Result::is_ok) {
            self.after=Some(self.after_clock.observe_once(Some(origin.first_native_clock_v1())));
            if !matches!(self.after,Some(Ok(_))) {self.first.get_or_insert(First::AfterClock);}
            self.after_time=Some(match self.after.as_ref().and_then(|value|value.as_ref().ok()) {
                Some(sample)=>Self::require_sample_v1(origin,*sample).and_then(|()| {
                    let before=*self.before.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
                    before.validate_later_sample(*sample).map_err(|_|CLOSED)?;
                    if let Some(actual) = &self.append_clock_retained {
                        actual.require_after_v2(*sample)?;
                    }
                    Ok(())
                }),None=>Err(CLOSED),
            });
            if !matches!(self.after_time,Some(Ok(()))) {self.first.get_or_insert(First::AfterTime);}
        }
        if self.first.is_none() {
            self.disposal=Some((|| {
                let source_native=self.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                let native=state.native.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
                state.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .dispose_provisioning_source_native_v1(source_native,native.original_v1(),controller,
                        source.journal(),state.profile.as_ref())
            })());
            if !matches!(self.disposal,Some(Ok(()))) {self.first=Some(First::Disposal);}
        }
        if self.first.is_none() {
            self.retirement=Some((|| {
                let committed=self.committed.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
                if self.purpose == StartSourcePurposeV2::Admission {
                    committed.retire_completed_payloads_v1();
                } else {
                    if !matches!(committed, SourceLifecycleAdmissionCommitV1::Applied(_)) { return Err(CLOSED); }
                    let record = self.prepared.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?
                        .original_record_digest_data_v2()?;
                    committed.retire_completed_payloads_v1();
                    self.completed_record = Some(record);
                }
                let bytes=committed.completed_resident_backing_bytes_v1().ok_or(CLOSED)?;
                let retained=ResourceVector::ZERO.with(D::MemoryBytes,u64::try_from(bytes).map_err(|_|CLOSED)?);
                state.history_resident=Some(self.base.ok_or(CLOSED)?
                    .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)?
                    .checked_add(retained)?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                        u64::try_from(aos_sandbox_protocol::domain_ledger::delete_batch::new_use::
                            public_mutation_new_use_receiving_bytes_v2()).map_err(|_| CLOSED)?))?);
                // Positive Source/C/native/clock disposal precedes dropping
                // the completed semantic graph and schema/plan scratch. The
                // Applied snapshot, origin and native/once state stay; later
                // phases replay the same actual durable Source record.
                self.semantic=None;
                self.expected=None;
                self.context=None;
                self.prepared=None;
                self.read=crate::lifecycle::LifecycleHistoricalReadOriginalV1::new();
                *self.admission_decode.get_mut()=crate::lifecycle::LifecycleOperationDecodeOriginalV1::new();
                Ok(())
            })());
            if !matches!(self.retirement,Some(Ok(()))) {self.first=Some(First::Retirement);}
        }
        if self.completed_v1() {Ok(())} else {Err(CLOSED)}
    }
}
