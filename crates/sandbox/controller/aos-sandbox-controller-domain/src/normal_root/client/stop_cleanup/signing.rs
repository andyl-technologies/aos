//! Rebuilds the held Root draft before the ordinary Controller signer is lent.

use super::*;
use aos_sandbox_model::{RevocationScopeId, SandboxId};
use aos_sandbox_ownership_protocol::{
    OwnershipAuthorityVerifier, response_verification::OwnershipResponseVerifyCaptureV1,
};
use aos_sandbox_protocol::authorization_artifact::{
    BrokerPlanPreparation, SignedBrokerPlan, SigningAuthority,
    host_stop_cleanup_plan::{
        StopCleanupPlanPreparationDataV1, host_stop_cleanup_request_body_data_v1,
        prepare_admitted_host_stop_cleanup_plan_v1,
    },
    start_resource_plan::host_stop_cleanup_normalization_receiving_demand_v1,
};

pub(super) struct Signing {
    pub(super) selected: Option<crate::policy_compiler::provisioning_current::current_cleanup_assignment::CurrentCleanupAssignmentDataV2>,
    pub(super) lease: OwnershipResponseVerifyCaptureV1,
    pub(super) preparation: Option<StopCleanupPlanPreparationDataV1>,
    pub(super) deadline_free_body: Option<Vec<u8>>,
    primary: Option<Result<(), Cause>>,
    presign: RetainedKernelPairedClockAttemptV1,
    sample: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    sample_current: Option<Result<(), Cause>>,
    pub(super) signed: Option<SignedBrokerPlan>,
    signed_current: Option<Result<(), Cause>>,
    pub(super) effect: Option<Result<crate::PreparedAuthorityEffectV1, Cause>>,
    pub(super) sent: Option<Result<(), Cause>>,
}

impl Signing {
    fn new() -> Self {
        Self {
            selected: None,
            lease: Default::default(),
            preparation: None,
            deadline_free_body: None,
            primary: None,
            presign: Default::default(),
            sample: None,
            sample_current: None,
            signed: None,
            signed_current: None,
            effect: None,
            sent: None,
        }
    }

    pub(super) fn failure_before_send(&self) -> Option<&(dyn Error + 'static)> {
        self.lease
            .cause()
            .or_else(|| boxed_error(&self.primary))
            .or_else(|| self.presign.failure())
            .or_else(|| error(&self.sample))
            .or_else(|| boxed_error(&self.sample_current))
            .or_else(|| boxed_error(&self.signed_current))
            .or_else(|| {
                self.effect
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref() as _)
            })
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failure_before_send()
            .or_else(|| boxed_error(&self.sent))
    }
}

/// Lends the genuine held Root preparation beside the same paid Source22 owner.
///
/// The ordinary Controller key owner accepts only this closed borrower. Drop
/// drains the already paid Root after even if signing or Source currentness
/// fails. No signer callback or arbitrary preparation constructor is exposed.
#[must_use = "finish the already entered native Root signing interval"]
pub struct RootStopCleanupSigningLoanV1<'root, 'owner, 'source> {
    guard: OwedAfter<'root>,
    source: &'root mut Source<'owner, 'source>,
    controller: &'root Journal,
    finished: bool,
}

impl RootStopCleanupClientOriginalV1 {
    /// Funds and enters the ordinary signature construction for the actual Root draft.
    ///
    /// # Errors
    /// Rejects another phase, payer, branch or capacity before native entry.
    /// After entry a borrower is returned even on refusal so its owed post runs.
    pub fn begin_signing_once_v1<'root, 'owner, 'source>(
        &'root mut self,
        source: &'root mut Source<'owner, 'source>,
        controller: &'root Journal,
        authority: &SigningAuthority,
        verifier: &OwnershipAuthorityVerifier,
        scope: RevocationScopeId,
    ) -> Result<RootStopCleanupSigningLoanV1<'root, 'owner, 'source>, RootStopCleanupClientClosedV1>
    {
        if self.require_phase(1).is_err() {
            return Err(self.refuse_reentry());
        }
        self.validate_source(source, controller)?;
        let native = self.native.as_ref().ok_or(RootStopCleanupClientClosedV1)?;
        if native.observed || native.signing.is_some() {
            return Err(self.refuse_reentry());
        }
        let profile = Arc::clone(&native.profile);
        let demand = controller.delete_resource_current_assignment_receiving_demand_v2(verifier)
            .and_then(|demand| {
                let bytes = size_of::<Signing>().checked_mul(3)
                    .and_then(|n| n.checked_add(size_of::<crate::PreparedAuthorityEffectV1>().checked_mul(3)?))
                    .and_then(|n| n.checked_add(aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::receiving_construction_bytes_v1()?))
                    .and_then(|n| u64::try_from(n).ok()).ok_or(crate::journal::JournalError::JournalTooLarge)?;
                demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                    .map_err(crate::journal::JournalError::ReceivingAccounting)
            }).map_err(|cause| self.retain_validation(Box::new(cause)))?;
        self.add_demand(source, controller, demand)
            .map_err(|cause| self.retain_validation(cause))?;
        self.native
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?
            .signing = Some(Box::new(Signing::new()));
        self.pending = Some(3);
        let guard = OwedAfter {
            owner: self,
            profile,
        };
        let before = guard.owner.observe_bookend(2, &guard.profile, false);
        let result = before
            .map_err(|cause| Box::new(cause) as Cause)
            .and_then(|_| {
                guard
                    .owner
                    .prepare_signing(source, controller, authority, verifier, scope)
            });
        if result.is_err() {
            guard.owner.first.get_or_insert(First::Signing);
        }
        if let Some(local) = guard
            .owner
            .native
            .as_mut()
            .and_then(|native| native.signing.as_mut())
        {
            local.primary = Some(result);
        }
        Ok(RootStopCleanupSigningLoanV1 {
            guard,
            source,
            controller,
            finished: false,
        })
    }

    fn prepare_signing(
        &mut self,
        source: &mut Source<'_, '_>,
        controller: &Journal,
        authority: &SigningAuthority,
        verifier: &OwnershipAuthorityVerifier,
        scope: RevocationScopeId,
    ) -> Result<(), Cause> {
        self.require_source(source, controller)?;
        let generation = source.current_desired_generation_data_v1(controller)?;
        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let before = *positive(&native.bookends[2].sample)?;
        let local = native
            .signing
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let sandbox = SandboxId::from_bytes(
            *native
                .source_subject
                .historical_scope_v1()
                .fence_v4()
                .sandbox_id(),
        );
        local.selected = Some(controller.current_delete_resource_assignment_data_v2(sandbox)?);
        let selected = local
            .selected
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let recovered = &selected.recovered_lease;
        verifier.verify_response_bytes_retaining_v1(
            selected.gate.claim(),
            recovered.canonical_lease(),
            recovered.canonical_signature(),
            recovered.canonical_receipt(),
            recovered.canonical_receipt_signature(),
            &before,
            &mut local.lease,
        )?;
        let lease = local.lease.value().ok_or(RootStopCleanupClientClosedV1)?;
        if selected.binding.lease_digest() != lease.digest()
            || selected.binding.lease_generation() != lease.generation()
        {
            return Err(HistoryErrorV1::Correlation.into());
        }
        let reply = StopCleanupReplyDataV1::decode_v1(native.replies[0].received.bytes())?;
        let StopCleanupDecisionDataV1::Effect(effect) = reply.decision_v1()? else {
            return Err(RootStopCleanupClientClosedV1.into());
        };
        let demand = host_stop_cleanup_normalization_receiving_demand_v1(
            effect.request_body.len(),
            effect.canonical_plan.len(),
            effect.canonical_statement.len(),
            lease,
            authority,
        )
        .ok_or(HistoryErrorV1::Extent)?;
        let retained_body_bytes = effect
            .request_body
            .len()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(HistoryErrorV1::Extent)?;
        let demand =
            demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, retained_body_bytes))?;
        self.add_demand(source, controller, demand)?;

        let native = self.native.as_mut().ok_or(RootStopCleanupClientClosedV1)?;
        let local = native
            .signing
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let selected = local
            .selected
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let lease = local.lease.value().ok_or(RootStopCleanupClientClosedV1)?;
        let reply = StopCleanupReplyDataV1::decode_v1(native.replies[0].received.bytes())?;
        let StopCleanupDecisionDataV1::Effect(effect) = reply.decision_v1()? else {
            return Err(RootStopCleanupClientClosedV1.into());
        };
        let subject = HostStopCleanupSubjectDataV1::decode_v1(effect.subject)?;
        if subject != native.source_subject {
            return Err(HistoryErrorV1::Correlation.into());
        }
        let manifest = selected.binding.manifest();
        // Keep the canonical template bytes even if live normalization later
        // refuses. The prepared request below contains an injected deadline.
        local.deadline_free_body = Some(host_stop_cleanup_request_body_data_v1(
            manifest, generation, subject,
        )?);
        let body = local
            .deadline_free_body
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let preparation = prepare_admitted_host_stop_cleanup_plan_v1(
            body,
            manifest,
            generation,
            subject,
            manifest.manifest().policy().digest(),
            lease,
            before,
            native.cutoff,
            native.expiry,
            native.expiry,
            authority.clone(),
            scope,
            effect.canonical_plan,
            effect.canonical_statement,
        )?;
        if preparation.request_body.as_slice() != effect.request_body {
            return Err(HistoryErrorV1::Correlation.into());
        }
        local.preparation = Some(preparation);
        Ok(())
    }
}

impl RootStopCleanupSigningLoanV1<'_, '_, '_> {
    /// Borrows only the actual independently rebuilt ordinary signing request.
    ///
    /// # Errors
    /// Refuses changed Source/C custody, a prior refusal or a finished interval.
    pub fn signing_preparation_v1(
        &self,
        controller: &Journal,
    ) -> Result<&BrokerPlanPreparation, RootStopCleanupClientClosedV1> {
        if self.finished || self.guard.owner.first.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        self.guard
            .owner
            .require_source(self.source, controller)
            .map_err(|_| RootStopCleanupClientClosedV1)?;
        let native = self
            .guard
            .owner
            .native
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let local = native
            .signing
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?;
        positive(&local.primary)?;
        Ok(&local
            .preparation
            .as_ref()
            .ok_or(RootStopCleanupClientClosedV1)?
            .preparation)
    }

    /// Samples the separately retained last presign clock without renewing D.
    ///
    /// # Errors
    /// Retains clock, current Source/C, expiry and repeated-entry refusals.
    pub fn final_signing_clock_once_v1(
        &mut self,
    ) -> Result<RawPairedClockSample, RootStopCleanupClientClosedV1> {
        self.signing_preparation_v1(self.controller)?;
        let native = self
            .guard
            .owner
            .native
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let local = native
            .signing
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        if local.sample.is_some() {
            return Err(self.guard.owner.refuse_reentry());
        }
        local.sample = Some(local.presign.observe_once(Some(native.origin)));
        local.sample_current = Some((|| -> Result<(), Cause> {
            self.source.require_current_v1(self.controller)?;
            let now = *positive(&local.sample)?;
            positive(&native.bookends[2].sample)?.validate_later_sample(now)?;
            if now.boottime_nanoseconds() >= native.cutoff || now.wall_seconds() >= native.expiry {
                return Err(HistoryErrorV1::Correlation.into());
            }
            Ok(())
        })());
        if !matches!(local.sample_current, Some(Ok(()))) {
            self.guard.owner.first.get_or_insert(First::Signing);
            return Err(RootStopCleanupClientClosedV1);
        }
        positive(&local.sample).copied()
    }

    /// Retains and sends the actual ordinary signature on the held exact Root draft.
    ///
    /// # Errors
    /// Retains changed signature/plan, Source, framing and native send failures.
    pub fn send_signed_once_v1(
        &mut self,
        signed: SignedBrokerPlan,
    ) -> Result<(), RootStopCleanupClientClosedV1> {
        let native = self
            .guard
            .owner
            .native
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let local = native
            .signing
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        if local.signed.is_some() {
            return Err(self.guard.owner.refuse_reentry());
        }
        local.signed = Some(signed);
        let result = self.send_signed_body();
        if result.is_err() {
            self.guard.owner.first.get_or_insert(First::Signing);
        }
        if let Some(local) = self
            .guard
            .owner
            .native
            .as_mut()
            .and_then(|native| native.signing.as_mut())
        {
            local.sent = Some(result);
        }
        if self.guard.owner.first.is_some() {
            Err(RootStopCleanupClientClosedV1)
        } else {
            Ok(())
        }
    }

    fn send_signed_body(&mut self) -> Result<(), Cause> {
        self.signing_preparation_v1(self.controller)?;
        let native = self
            .guard
            .owner
            .native
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let local = native
            .signing
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        local.signed_current = Some((|| -> Result<(), Cause> {
            positive(&local.sample_current)?;
            let signed = local.signed.as_ref().ok_or(RootStopCleanupClientClosedV1)?;
            let preparation = &local
                .preparation
                .as_ref()
                .ok_or(RootStopCleanupClientClosedV1)?
                .preparation;
            if signed.canonical_plan() != preparation.canonical_plan()
                || signed.plan() != preparation.plan_data_v1()
            {
                return Err(HistoryErrorV1::Correlation.into());
            }
            Ok(())
        })());
        positive(&local.signed_current)?;
        let signed = local.signed.as_ref().ok_or(RootStopCleanupClientClosedV1)?;
        let frame = StopCleanupSignatureDataV1 {
            query_digest: &native.query_digest,
            decision_digest: &native.decision_digest,
            canonical_signature: signed.canonical_signature(),
        };
        let bytes = frame.encoded_bytes_v1()?;
        self.guard
            .owner
            .charge(self.source, self.controller, bytes, bytes)?;
        let native = self
            .guard
            .owner
            .native
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let local = native
            .signing
            .as_mut()
            .ok_or(RootStopCleanupClientClosedV1)?;
        let signed = local.signed.as_ref().ok_or(RootStopCleanupClientClosedV1)?;
        let frame = StopCleanupSignatureDataV1 {
            query_digest: &native.query_digest,
            decision_digest: &native.decision_digest,
            canonical_signature: signed.canonical_signature(),
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::StopSignature(frame),
            &mut native.connection,
            &mut native.sender[1],
            &mut native.sent[1],
            &mut native.scratch,
            &mut native.data_failure,
            native.cutoff,
        )
        .map_err(|_| RootStopCleanupClientClosedV1)?;
        self.guard
            .owner
            .receive_child_comparison(self.source, self.controller)?;
        Ok(())
    }

    /// Drains the prepaid Root after even after signing or Source refusal.
    ///
    /// # Errors
    /// Refuses incomplete signing, a primary refusal or the independent after.
    pub fn finish_native_once_v1(&mut self) -> Result<(), RootStopCleanupClientClosedV1> {
        if self.finished {
            return Err(self.guard.owner.refuse_reentry());
        }
        self.finished = true;
        if self
            .guard
            .owner
            .native
            .as_ref()
            .and_then(|native| native.signing.as_ref())
            .is_none_or(|local| !matches!(local.sent, Some(Ok(()))))
        {
            self.guard
                .owner
                .repeated
                .get_or_insert(RootStopCleanupClientClosedV1);
            self.guard.owner.first.get_or_insert(First::External);
        }
        let _ = self.guard.owner.drain_owed(&self.guard.profile);
        if self.guard.owner.first.is_some() {
            return Err(RootStopCleanupClientClosedV1);
        }
        self.guard.owner.body[1] = Some(Ok(()));
        self.guard.owner.phase = 2;
        Ok(())
    }

    /// Borrows the original refusal without fresh native work or allocation.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.guard.owner.failure_v1()
    }
}

impl Drop for RootStopCleanupSigningLoanV1<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish_native_once_v1();
        }
    }
}

fn boxed_error(slot: &Option<Result<(), Cause>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?
        .as_ref()
        .err()
        .map(|cause| cause.as_ref() as _)
}
