//! Shares passive fixed-stage results inside the one genuine Root original.
//!
//! Stage selection is closed and private. Actual callers derive each demand
//! from their own held originals; this reservoir accepts no payer, callback,
//! pathname, FD or public authority constructor.

use aos_sandbox_core::ResourceVector;

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};

use super::{RootReceivingOriginalV1, root_journal::RootJournalDemandErrorV1};

#[derive(Default)]
pub(super) struct RootCurrentProvisionV1 {
    pub(super) permit: Option<Result<ResourceVector, RootJournalDemandErrorV1>>,
    before: Option<Result<(), Error>>,
}

impl RootCurrentProvisionV1 {
    pub(super) fn completed_prefix(&self) -> Option<ResourceVector> {
        if self.failure().is_some() || !matches!(self.before, Some(Ok(()))) {
            return None;
        }
        self.permit.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.permit.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| match cause {
                    Error::ServiceReceiving(original) => original.as_ref() as &(dyn std::error::Error + 'static),
                    _ => cause as &(dyn std::error::Error + 'static),
                }))
    }
}

#[derive(Clone, Copy)]
pub(super) enum RootCurrentStageV1 {
    Open,
    ReadyFixed,
    ReadyBytes,
    Pins,
    PolicyInputs,
    OwnershipTrustFixed,
    OwnershipTrustTyped,
    SourceQuery,
    SourceExchange,
    BundleOwnershipFixed,
    BundleOwnershipTyped,
    CacheCurrent,
    ControllerReadonlyFixed,
    ControllerReadonlyNative,
    ControllerReadonlySemantic,
    UseAuthorized,
    UseAdmitted,
    Closed(crate::policy_compiler::create_storage_current::closed::ClosedFinancialStageV1),
    OutcomeFixed,
    OutcomeBytes,
    OutcomeControllerNative,
    OutcomeControllerSemantic,
    OutcomeSession,
    SignedFixed,
    SignedBytes,
    SignedControllerFixed,
    SignedControllerNative,
    SignedControllerSemantic,
    UseReservedFrame,
    UseSourceQuery,
    UseSourceExchange,
    UseCacheCurrent,
    UseControllerReadonlyFixed,
    UseControllerReadonlyNative,
    UseControllerReadonlySemantic,
}

impl RootReceivingOriginalV1 {
    fn current_provision_mut(
        &mut self,
        stage: RootCurrentStageV1,
    ) -> Result<&mut RootCurrentProvisionV1, Error> {
        match stage {
            RootCurrentStageV1::Open => self.current_open_provision.as_mut(),
            RootCurrentStageV1::ReadyFixed => self.current_ready_provision.as_mut()
                .map(|ready| &mut ready.fixed),
            RootCurrentStageV1::ReadyBytes => self.current_ready_provision.as_mut()
                .map(|ready| &mut ready.variable),
            RootCurrentStageV1::Pins => self.current_pins_provision.as_mut(),
            RootCurrentStageV1::PolicyInputs => self.current_policy_inputs_provision.as_mut(),
            RootCurrentStageV1::OwnershipTrustFixed => self.current_ownership_trust_provision.as_mut()
                .map(|stage| &mut stage.fixed),
            RootCurrentStageV1::OwnershipTrustTyped => self.current_ownership_trust_provision.as_mut()
                .map(|stage| &mut stage.typed),
            RootCurrentStageV1::SourceQuery => self.current_source_query_provision.as_mut(),
            RootCurrentStageV1::SourceExchange => self.current_source_exchange_provision.as_mut(),
            RootCurrentStageV1::BundleOwnershipFixed => self.current_bundle_ownership_provision.as_mut()
                .map(|stage| &mut stage.fixed),
            RootCurrentStageV1::BundleOwnershipTyped => self.current_bundle_ownership_provision.as_mut()
                .map(|stage| &mut stage.typed),
            RootCurrentStageV1::CacheCurrent => self.current_cache_proof_provision.as_mut(),
            RootCurrentStageV1::ControllerReadonlyFixed => self.current_controller_readonly_provision.as_mut()
                .map(|stage| &mut stage.fixed),
            RootCurrentStageV1::ControllerReadonlyNative => self.current_controller_readonly_provision.as_mut()
                .map(|stage| &mut stage.native),
            RootCurrentStageV1::Closed(stage) => self.current_closed_provision.as_mut().map(|owner| &mut owner.stages[stage.index_v1()]),
            RootCurrentStageV1::OutcomeFixed => self.current_outcome_provision.as_mut().map(|stage| &mut stage.fixed),
            RootCurrentStageV1::OutcomeBytes => self.current_outcome_provision.as_mut().map(|stage| &mut stage.variable),
            RootCurrentStageV1::OutcomeControllerNative => self.current_outcome_provision.as_mut().map(|stage| &mut stage.controller_native),
            RootCurrentStageV1::OutcomeControllerSemantic => self.current_outcome_provision.as_mut().map(|stage| &mut stage.controller_semantic),
            RootCurrentStageV1::OutcomeSession => self.current_outcome_provision.as_mut().map(|stage| &mut stage.session),
            RootCurrentStageV1::SignedFixed => self.current_signed_provision.as_mut().map(|stage| &mut stage.fixed),
            RootCurrentStageV1::SignedControllerFixed => self.current_signed_provision.as_mut().map(|stage| &mut stage.read.fixed),
            RootCurrentStageV1::SignedControllerNative => self.current_signed_provision.as_mut().map(|stage| &mut stage.read.native),
            RootCurrentStageV1::SignedControllerSemantic => self.current_signed_provision.as_mut().map(|stage| &mut stage.read.semantic),
            RootCurrentStageV1::SignedBytes => self.current_signed_provision.as_mut().map(|stage| &mut stage.variable),
            RootCurrentStageV1::UseAdmitted => self.current_use_admitted_provision.as_mut(),
            RootCurrentStageV1::UseAuthorized => self.current_use_authorized_provision.as_mut(),
            RootCurrentStageV1::UseSourceQuery => self.current_use_reserved_provision.as_mut().map(|stage| &mut stage.second_query),
            RootCurrentStageV1::UseSourceExchange => self.current_use_reserved_provision.as_mut().map(|stage| &mut stage.second_source),
            RootCurrentStageV1::UseCacheCurrent => self.current_use_reserved_provision.as_mut().map(|stage| &mut stage.second_cache),
            RootCurrentStageV1::UseReservedFrame => self.current_use_reserved_provision.as_mut().map(|stage| &mut stage.frame),
            RootCurrentStageV1::UseControllerReadonlyFixed => self.current_use_reserved_provision.as_mut().map(|stage| &mut stage.read.fixed),
            RootCurrentStageV1::UseControllerReadonlyNative => self.current_use_reserved_provision.as_mut().map(|stage| &mut stage.read.native),
            RootCurrentStageV1::UseControllerReadonlySemantic => self.current_use_reserved_provision.as_mut().map(|stage| &mut stage.read.semantic),
            RootCurrentStageV1::ControllerReadonlySemantic => self.current_controller_readonly_provision.as_mut()
                .map(|stage| &mut stage.semantic),
        }.ok_or(Error::Service)
    }

    pub(super) fn finish_current_provision_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        stage: RootCurrentStageV1,
    ) -> Result<(), Error> {
        // Reborrow the same actual stage after the native service observation;
        // no callback or detached row can choose or mint a receiving owner.
        let original = self.current_provision_mut(stage)?;
        if original.before.is_some() || !matches!(original.permit, Some(Ok(_))) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let before = self.recheck_service(startup);
        let refusal = self.native_refusal_original_v1();
        let original = self.current_provision_mut(stage)?;
        refusal.park_empty_result_v1(&mut original.before, before);
        if original.completed_prefix().is_some() {
            Ok(())
        } else {
            self.activation.latch_root_refusal_v1();
            Err(Error::Service)
        }
    }
}
