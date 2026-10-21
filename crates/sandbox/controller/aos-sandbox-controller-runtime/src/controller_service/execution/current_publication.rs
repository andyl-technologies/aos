//! Execution-only publication under the original Host terminal-currentness loan.
//!
//! The attempt is parked in the existing Host exchange before preparation.
//! Failed preparation, transport, classification, append, or either postcheck
//! keeps the original attempt resident and blocks every subsequent Host flight.
//! It does not make Authorize, Observe, or terminal Cancel publishable.

use aos_sandbox_controller_domain::{CommitResult, EffectFailure, Journal, JournalError};
use aos_sandbox_model::ProjectId;
use aos_linux_descriptors::ImmutableFileError;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerDescriptorRequestPreparationV1, DormantBrokerRequestPreparationV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1,
};

use super::{
    ControllerExecutionActionV1, ControllerExecutionExchangeV1, ControllerExecutionIntentV1,
    ControllerExecutionObservationV1, ExecutionAuthorizationKindV1, ExecutionExchangeContextV1,
    BrokerAuthorizationArtifactsV1, ERRORS, SESSION_UNUSABLE, SealedReadOnlyCredential,
    HostExecutionSpecContentFieldsV1, MAXIMUM_HOST_EXECUTION_SPEC_BYTES, classify_outcome, retryable,
};

#[derive(Clone, Copy)]
enum PublicationContentV2<'content> {
    Control,
    Accepted { content: &'content [u8], version: super::ExecutionDescriptorVersionV2, cutoff: u64 },
    Monitor { content: HostExecutionSpecContentFieldsV1,
        selector: aos_sandbox_protocol::host_execution::monitor::HostExecutionMonitorSelectorV3,
        capture: Option<&'content super::super::execution_output_storage_capture::AuthenticatedControllerStorageCaptureQueryObservationV3<'content>> },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MonitorProjectionPhaseV4 { Read, Completion }

#[derive(Clone, Copy)]
enum PublicationFailureSiteV1 {
    Preparation,
    Transport,
    Currentness,
    Classification,
    ControllerBefore,
    Projection,
    HostAfter,
    ControllerAfter,
    ClientPost,
}

/// Borrows the selected actual cause without replacing it with a diagnostic.
pub(crate) enum ExecutionPublicationCauseV1<'resident> {
    /// An existing execution semantic check refused publication.
    Effect(&'resident EffectFailure),
    /// The original fixed session or preparation check failed.
    Session(&'resident BrokerSessionSecurityError),
    /// The original transport/native readback retains its own typed cause.
    Transport(&'resident (dyn std::error::Error + 'static)),
    /// The actual Controller journal operation failed.
    Journal(&'resident JournalError),
    /// Creation of the original sealed content failed.
    Credential(&'resident ImmutableFileError),
    /// Duplication of that same sealed content failed.
    Descriptor(&'resident rustix::io::Errno),
}

/// Borrows every entered projection/post result, including secondary failures.
pub(crate) struct ExecutionPublicationDebtsV1<'resident> {
    /// The actual original Controller named precheck.
    pub(crate) controller_before: Option<&'resident Result<(), JournalError>>,
    /// The existing exact projection operation's result.
    pub(crate) projection: Option<&'resident Result<(), EffectFailure>>,
    /// The actual native append result, absent on validation refusal or replay.
    pub(crate) native_append: Option<&'resident Result<CommitResult, JournalError>>,
    /// The independent original Host terminal postcheck.
    pub(crate) host_after: Option<&'resident Result<(), BrokerSessionSecurityError>>,
    /// The independent original Controller named postcheck.
    pub(crate) controller_after: Option<&'resident Result<(), JournalError>>,
}

/// Owns every entered return until healthy publication or resident refusal.
pub(super) struct ExecutionPublicationAttemptV1 {
    intent: ControllerExecutionIntentV1,
    kind: ExecutionAuthorizationKindV1,
    request_preparation: Option<Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError>>,
    descriptor_preparation: Option<Result<DormantBrokerDescriptorRequestPreparationV1, BrokerSessionSecurityError>>,
    preparation_failure: Option<EffectFailure>,
    credential: Option<Result<SealedReadOnlyCredential, ImmutableFileError>>,
    descriptor: Option<Result<std::os::fd::OwnedFd, rustix::io::Errno>>,
    transport_failure: Option<EffectFailure>,
    outcome: Option<AuthenticatedBrokerMethodOutcomeV1>,
    currentness: Option<ProtectedBrokerOutcomeCurrentnessOwnerV1>,
    currentness_check: Option<Result<(), BrokerSessionSecurityError>>,
    classification: Option<Result<ControllerExecutionObservationV1, EffectFailure>>,
    monitor: Option<Result<aos_sandbox_protocol::host_execution::ValidatedHostExecutionMonitorOutcomeV3,
        aos_sandbox_protocol::ProtocolValidationError>>,
    controller_before: Option<Result<(), JournalError>>,
    projection: Option<Result<(), EffectFailure>>,
    native_append: Option<Result<CommitResult, JournalError>>,
    projection_transaction: Option<aos_sandbox_controller_domain::JournalTransaction>,
    projection_geometry: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1>>,
    projection_admission: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    host_after: Option<Result<(), BrokerSessionSecurityError>>,
    controller_after: Option<Result<(), JournalError>>,
    first_site: Option<PublicationFailureSiteV1>,
    post_boundary: Option<EffectFailure>,
    terminal_clock: Option<Result<aos_sandbox_model::RawPairedClockSample, aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>>,
    retained_credential: aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1,
    names: [aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1; 4],
    names_phase: usize,
}

impl ExecutionPublicationAttemptV1 {
    fn new(intent: &ControllerExecutionIntentV1, kind: ExecutionAuthorizationKindV1) -> Self {
        Self {
            intent: intent.clone(), kind,
            request_preparation: None, descriptor_preparation: None,
            preparation_failure: None, transport_failure: None,
            credential: None, descriptor: None,
            outcome: None, currentness: None, currentness_check: None,
            classification: None, monitor: None, controller_before: None, projection: None,
            native_append: None, projection_transaction: None, projection_geometry: None,
            projection_admission: None, host_after: None, controller_after: None, first_site: None,
            terminal_clock: None, post_boundary: None,
            retained_credential: aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1::new(),
            names: std::array::from_fn(|_| aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::new()),
            names_phase: 0,
        }
    }

    fn select(&mut self, site: PublicationFailureSiteV1) {
        self.first_site.get_or_insert(site);
    }

    fn failure<'resident>(
        &'resident self,
        transport: Option<&'resident (dyn std::error::Error + 'static)>,
    ) -> Option<ExecutionPublicationCauseV1<'resident>> {
        use ExecutionPublicationCauseV1 as Cause;

        match self.first_site? {
            PublicationFailureSiteV1::Preparation => {
                if let Some(cause) = self.retained_credential.failure() { return Some(Cause::Transport(cause)); }
                if let Some(Err(error)) = &self.credential { return Some(Cause::Credential(error)); }
                if let Some(Err(error)) = &self.descriptor { return Some(Cause::Descriptor(error)); }
                if let Some(Err(error)) = &self.request_preparation { return Some(Cause::Session(error)); }
                if let Some(Err(error)) = &self.descriptor_preparation { return Some(Cause::Session(error)); }
                if let Some(Ok(DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { error, .. }
                    | DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { error, .. })) = &self.request_preparation
                { return Some(Cause::Session(error)); }
                if let Some(Ok(DormantBrokerDescriptorRequestPreparationV1::InitializationRecoveryRequired { error, .. }
                    | DormantBrokerDescriptorRequestPreparationV1::SuccessorRecoveryRequired { error, .. })) = &self.descriptor_preparation
                { return Some(Cause::Session(error)); }
                self.preparation_failure.as_ref().map(Cause::Effect)
            }
            PublicationFailureSiteV1::Transport => transport.map(Cause::Transport)
                .or_else(|| self.transport_failure.as_ref().map(Cause::Effect)),
            PublicationFailureSiteV1::Currentness => self.currentness_check.as_ref()?.as_ref().err().map(Cause::Session),
            PublicationFailureSiteV1::Classification => self.monitor.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| Cause::Transport(cause))
                .or_else(|| self.classification.as_ref()?.as_ref().err().map(Cause::Effect)),
            PublicationFailureSiteV1::ControllerBefore => self.names[self.names_phase].failure().map(Cause::Transport)
                .or_else(|| self.controller_before.as_ref()?.as_ref().err().map(Cause::Journal)),
            PublicationFailureSiteV1::Projection => self.terminal_clock.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| Cause::Transport(cause))
                .or_else(|| self.projection_geometry.as_ref().and_then(|result| result.as_ref().err()).map(|cause| Cause::Transport(cause)))
                .or_else(|| self.projection_admission.as_ref().and_then(|result| result.as_ref().err()).map(|cause| Cause::Transport(cause)))
                .or_else(|| self.native_append.as_ref().and_then(|result| result.as_ref().err()).map(Cause::Journal))
                .or_else(|| self.projection.as_ref()?.as_ref().err().map(Cause::Effect)),
            PublicationFailureSiteV1::HostAfter => self.host_after.as_ref()?.as_ref().err().map(Cause::Session),
            PublicationFailureSiteV1::ClientPost => self.post_boundary.as_ref().map(Cause::Effect),
            PublicationFailureSiteV1::ControllerAfter => self.names[self.names_phase + 1].failure().map(Cause::Transport)
                .or_else(|| self.controller_after.as_ref()?.as_ref().err().map(Cause::Journal)),
        }
    }
}

impl ControllerExecutionExchangeV1 {
    pub(crate) fn completed_accepted_publication_v2(&self) -> bool {
        self.publication.as_ref().is_some_and(|attempt| attempt.first_site.is_none()
            && attempt.currentness.is_some() && attempt.classification.is_none()
            && matches!(attempt.host_after, Some(Ok(())))
            && matches!(attempt.controller_before, Some(Ok(())))
            && matches!(attempt.controller_after, Some(Ok(()))))
            && !self.exchange.requires_reconnect()
    }

    /// Borrows the exact outcome only after this actual publication's posts.
    pub(crate) fn completed_publication_outcome_v2(&self)
        -> Result<&AuthenticatedBrokerMethodOutcomeV1, aos_sandbox_controller_domain::EffectFailure>
    {
        if !self.completed_accepted_publication_v2() {
            return Err(retryable("execution publication has not completed its original posts"));
        }
        self.publication.as_ref().and_then(|attempt| attempt.outcome.as_ref())
            .ok_or_else(|| retryable("completed execution outcome original is absent"))
    }

    /// Reports actual occupied publication custody, never admission readiness.
    pub(crate) const fn has_publication_debt(&self) -> bool {
        self.publication.is_some()
    }

    /// Borrows the sticky original failure of this parked execution attempt.
    pub(crate) fn publication_failure(&self) -> Option<ExecutionPublicationCauseV1<'_>> {
        self.publication.as_ref()?.failure(self.exchange.execution_failure())
    }

    /// Resolves only the selected returned frontier through its actual post.
    pub(crate) fn publication_failure_with_post_v1<'resident>(&'resident self,
        post: &'resident super::super::execution_authorize::AcceptedSessionPostOriginalV1,
    ) -> Option<ExecutionPublicationCauseV1<'resident>> {
        let attempt = self.publication.as_ref()?;
        let native = match attempt.first_site {
            Some(PublicationFailureSiteV1::Currentness) => post.native.terminal_before_failure_v1(),
            Some(PublicationFailureSiteV1::HostAfter) => post.native.terminal_after_failure_v1(),
            Some(PublicationFailureSiteV1::ClientPost) => post.failure(),
            _ => None,
        };
        native.map(ExecutionPublicationCauseV1::Transport)
            .or_else(|| attempt.failure(self.exchange.execution_failure()))
    }

    /// Borrows all entered append and postcheck results without another read.
    pub(crate) fn publication_debts(&self) -> Option<ExecutionPublicationDebtsV1<'_>> {
        let attempt = self.publication.as_ref()?;
        Some(ExecutionPublicationDebtsV1 {
            controller_before: attempt.controller_before.as_ref(),
            projection: attempt.projection.as_ref(),
            native_append: attempt.native_append.as_ref(),
            host_after: attempt.host_after.as_ref(),
            controller_after: attempt.controller_after.as_ref(),
        })
    }

    /// Publishes a control result before releasing its original Host loan.
    ///
    /// # Errors
    ///
    /// Refuses any retained attempt or closed action. Every entered failure
    /// remains in this exchange; neither reconnect nor a replacement is granted.
    pub(crate) fn publish_current_control(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1,
        kind: ExecutionAuthorizationKindV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
        project: ProjectId,
        journal: &mut Journal,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        if !matches!(intent.action,
            ControllerExecutionActionV1::Resize { .. }
                | ControllerExecutionActionV1::Signal { .. } | ControllerExecutionActionV1::Cancel)
            || self.publication.is_some() || self.exchange.has_pending()
        {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        self.publish_engine_v2(session, intent, kind, authorization, project, journal, PublicationContentV2::Control, None, None, None)
    }

    pub(crate) fn publish_accepted_execution_v2(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1, authorization: &BrokerAuthorizationArtifactsV1,
        project: ProjectId, journal: &mut Journal, content: &[u8],
        version: super::ExecutionDescriptorVersionV2, cutoff: u64,
        clock: &mut impl FnMut() -> Result<aos_sandbox_model::RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>,
        post: &mut super::super::execution_authorize::AcceptedSessionPostOriginalV1,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        if self.publication.is_some() || self.exchange.has_pending() {
            return Err(retryable(SESSION_UNUSABLE));
        }
        let result = self.publish_engine_v2(session, intent, ExecutionAuthorizationKindV1::Apply,
            Some(authorization), project, journal, PublicationContentV2::Accepted { content, version, cutoff }, Some(clock), Some(&mut *post), None);
        self.finish_endpoint_post_v4(session, post, result)
    }

    pub(in crate::controller_service) fn publish_monitor_execution_v4(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1, authorization: &BrokerAuthorizationArtifactsV1,
        project: ProjectId, journal: &mut Journal,
        original: &aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1,
        clock: &mut impl FnMut() -> Result<aos_sandbox_model::RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>,
        post: &mut super::super::execution_authorize::AcceptedSessionPostOriginalV1,
        receiving: &mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        if intent.action != ControllerExecutionActionV1::Observe || self.publication.is_some()
            || self.exchange.has_pending()
        { return Err(retryable(SESSION_UNUSABLE)); }
        let result = self.publish_engine_v2(session, intent, ExecutionAuthorizationKindV1::Query,
            Some(authorization), project, journal, PublicationContentV2::Monitor {
                content: original.monitor_content_v4(), selector: original.monitor_selector_v4(), capture: None,
            }, Some(clock), Some(&mut *post), Some((receiving, bank, profile)));
        self.finish_endpoint_post_v4(session, post, result)
    }

    fn finish_endpoint_post_v4(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        post: &mut super::super::execution_authorize::AcceptedSessionPostOriginalV1,
        result: Result<ControllerExecutionObservationV1, EffectFailure>,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        let after = post.finish_once(session);
        if let Err(error) = after {
            if let Some(attempt) = self.publication.as_mut() {
                attempt.post_boundary = Some(error);
                attempt.select(PublicationFailureSiteV1::ClientPost);
            }
            self.exchange.mark_failed();
            return result.and(Err(retryable("execution retains its independently owed endpoint post")));
        }
        result
    }

    /// Rejoins the same authenticated Query27 after the independent Storage61.
    ///
    /// No new Host request or response model is constructed. The second actual
    /// native endpoint interval checks the retained signed outcome, then the
    /// sole canonical projection engine compares the complete physical result.
    ///
    /// # Errors
    /// Retains every entered comparison, append and independent post refusal.
    pub(in crate::controller_service) fn publish_monitor_projection_v4(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        project: ProjectId,
        journal: &mut Journal,
        original: &aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1,
        capture: Option<&super::super::execution_output_storage_capture::AuthenticatedControllerStorageCaptureQueryObservationV3<'_>>,
        clock: &mut impl FnMut() -> Result<aos_sandbox_model::RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>,
        post: &mut super::super::execution_authorize::AcceptedSessionPostOriginalV1,
        receiving: &mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        if !self.completed_accepted_publication_v2()
            || self.publication.as_ref().is_none_or(|attempt|
                attempt.kind != ExecutionAuthorizationKindV1::Query
                    || attempt.names_phase != 0 || !matches!(attempt.monitor, Some(Ok(_))))
        {
            return Err(retryable("monitor read has no completed original to rejoin"));
        }
        let result = self.complete_publication_engine_v4(session, project, journal,
            PublicationContentV2::Monitor { content: original.monitor_content_v4(),
                selector: original.monitor_selector_v4(), capture }, Some(clock), Some(&mut *post),
            Some((receiving, bank, profile)), MonitorProjectionPhaseV4::Completion);
        self.finish_endpoint_post_v4(session, post, result)
    }

    pub(in crate::controller_service) fn retire_monitor_positive_v4(
        &mut self,
        disposal: &aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionPositiveDisposalV1<'_>,
        execution: aos_sandbox_model::ExecutionId,
        post: &super::super::execution_authorize::AcceptedSessionPostOriginalV1,
    ) -> Result<(), EffectFailure> {
        if !self.completed_accepted_publication_v2() || post.failure().is_some()
            || self.publication.as_ref().is_none_or(|attempt|
                attempt.kind != ExecutionAuthorizationKindV1::Query
                    || attempt.names_phase != 2
                    || attempt.intent.operation_id != disposal.operation_v1()
                    || attempt.intent.execution_id != *execution.as_bytes()
                    || !matches!(attempt.monitor, Some(Ok(_))))
        { return Err(retryable("periodic Host query retains incomplete original custody")); }
        drop(self.publication.take());
        Ok(())
    }

    fn publish_engine_v2(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1, kind: ExecutionAuthorizationKindV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>, project: ProjectId,
        journal: &mut Journal, mode: PublicationContentV2<'_>,
        mut clock: Option<&mut dyn FnMut() -> Result<aos_sandbox_model::RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>>,
        mut post: Option<&mut super::super::execution_authorize::AcceptedSessionPostOriginalV1>,
        mut projection_receiving: Option<(&mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'_, '_>,
            &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
            &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1)>,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        self.publication = Some(ExecutionPublicationAttemptV1::new(intent, kind));
        let Some(attempt) = self.publication.as_mut() else {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        };

        // Preparation uses the fixed credential and authenticated Session
        // producers. Ambiguous variants are retained, never recovered.
        let prepared = (|| {
            let authorization = authorization.ok_or_else(|| retryable("current Host execution authorization is unavailable"))?;
            let ordinary_content;
            let content = match mode {
                PublicationContentV2::Control => { ordinary_content = intent.descriptor_content()?; ordinary_content.as_slice() }
                PublicationContentV2::Accepted { content, .. } => content,
                PublicationContentV2::Monitor { .. } => &[],
            };
            let stable_content = match mode {
                PublicationContentV2::Monitor { content, .. } => content,
                _ => HostExecutionSpecContentFieldsV1::for_grant(&content),
            };
            let context = ExecutionExchangeContextV1 { intent: intent.clone(), kind };
            if kind == ExecutionAuthorizationKindV1::Apply {
                let credential = match mode {
                    PublicationContentV2::Control => {
                        attempt.credential = Some(SealedReadOnlyCredential::create(
                            "aos-host-execution-spec", content, MAXIMUM_HOST_EXECUTION_SPEC_BYTES));
                        attempt.credential.as_ref().and_then(|result| result.as_ref().ok())
                    }
                    PublicationContentV2::Accepted { .. } => {
                        let maximum = aos_sandbox_protocol::host_execution::admission_content::MAXIMUM_ADMISSION_CONTENT_BYTES_V5;
                        let _ = attempt.retained_credential.create_once("aos-host-execution-spec", content, maximum);
                        attempt.retained_credential.completed()
                    }
                    PublicationContentV2::Monitor { .. } => return Err(retryable("monitor cannot select an Apply descriptor")),
                }.ok_or_else(|| retryable("execution credential preparation retains original failure"))?;
                attempt.descriptor = Some(rustix::io::dup(credential.as_fd()));
                if !matches!(&attempt.descriptor, Some(Ok(_))) {
                    return Err(retryable("execution descriptor duplication retains original failure"));
                }
                let Some(Ok(descriptor)) = attempt.descriptor.take() else {
                    return Err(retryable("execution descriptor custody is absent"));
                };
                attempt.descriptor_preparation = Some(session.prepare_authenticated_descriptor_request(
                    kind.broker_method(), vec![descriptor], |coordinates| {
                        match mode {
                            PublicationContentV2::Control => intent.envelope(kind, coordinates, authorization, stable_content),
                            PublicationContentV2::Accepted { version, .. } => intent.envelope_content_v2(
                                kind, coordinates, authorization, stable_content, version),
                            PublicationContentV2::Monitor { selector, .. } => intent.monitor_envelope_v4(
                                coordinates, authorization, stable_content, selector),
                        }
                    },
                ));
                if !matches!(&attempt.descriptor_preparation,
                    Some(Ok(DormantBrokerDescriptorRequestPreparationV1::Prepared(_))))
                {
                    return Err(retryable("execution descriptor preparation retains original custody"));
                }
                if let Some(Ok(preparation)) = attempt.descriptor_preparation.take() {
                    self.exchange.start_descriptor(context, preparation);
                }
            } else {
                attempt.request_preparation = Some(session.prepare_authenticated_request(
                    kind.broker_method(), |coordinates| {
                        match mode {
                            PublicationContentV2::Monitor { selector, .. } => intent.monitor_envelope_v4(
                                coordinates, authorization, stable_content, selector),
                            _ => intent.envelope(kind, coordinates, authorization, stable_content),
                        }
                    },
                ));
                if !matches!(&attempt.request_preparation,
                    Some(Ok(DormantBrokerRequestPreparationV1::Prepared(_))))
                {
                    return Err(retryable("execution request preparation retains original custody"));
                }
                if let Some(Ok(preparation)) = attempt.request_preparation.take() {
                    self.exchange.start(context, preparation);
                }
            }
            Ok(())
        })();
        if let Err(error) = prepared {
            attempt.preparation_failure = Some(error);
            attempt.select(PublicationFailureSiteV1::Preparation);
            self.exchange.mark_failed();
            return Err(retryable("execution publication retains failed preparation"));
        }

        match self.exchange.drive_execution_publication(session, &ERRORS) {
            Ok((context, outcome, currentness)) => {
                attempt.intent = context.intent;
                attempt.kind = context.kind;
                attempt.outcome = Some(outcome);
                attempt.currentness = Some(currentness);
            }
            Err(error) => {
                attempt.transport_failure = Some(error);
                attempt.select(PublicationFailureSiteV1::Transport);
                self.exchange.mark_failed();
                return Err(retryable("execution publication retains failed transport"));
            }
        }

        self.complete_publication_engine_v4(session, project, journal, mode, clock, post,
            projection_receiving, MonitorProjectionPhaseV4::Read)
    }

    fn complete_publication_engine_v4(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1, project: ProjectId,
        journal: &mut Journal, mode: PublicationContentV2<'_>,
        mut clock: Option<&mut dyn FnMut() -> Result<aos_sandbox_model::RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError>>,
        mut post: Option<&mut super::super::execution_authorize::AcceptedSessionPostOriginalV1>,
        mut projection_receiving: Option<(&mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1<'_, '_>,
            &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
            &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1)>,
        phase: MonitorProjectionPhaseV4,
    ) -> Result<ControllerExecutionObservationV1, EffectFailure> {
        let attempt = self.publication.as_mut().ok_or_else(|| retryable("actual execution publication is absent"))?;
        attempt.names_phase = match phase { MonitorProjectionPhaseV4::Read => 0, MonitorProjectionPhaseV4::Completion => 2 };
        let Some(owner) = attempt.currentness.take() else {
            self.exchange.mark_failed();
            return Err(retryable("execution publication currentness is absent"));
        };
        let current = match post.as_deref_mut() {
            Some(post) => session.retain_execution_outcome_current_with_post_v1(owner, &mut post.native),
            None => session.retain_execution_outcome_current(owner),
        };
        let mut current = match current {
            Ok(current) => {
                attempt.currentness_check = Some(Ok(()));
                current
            }
            Err((owner, error)) => {
                attempt.currentness = Some(owner);
                attempt.currentness_check = Some(Err(error));
                attempt.select(PublicationFailureSiteV1::Currentness);
                // Admission refused the Host loan, but the independent
                // Controller named post remains available under this owner.
                attempt.controller_after = Some(match mode {
                    PublicationContentV2::Control => journal.validate_held_protected_names(),
                    PublicationContentV2::Accepted { .. } | PublicationContentV2::Monitor { .. } => journal.observe_held_names_post_retaining_v1(&mut attempt.names[attempt.names_phase + 1]),
                });
                if attempt.controller_after.as_ref().is_some_and(Result::is_err) {
                    attempt.select(PublicationFailureSiteV1::ControllerAfter);
                }
                self.exchange.mark_failed();
                return Err(retryable("execution publication retains failed currentness"));
            }
        };
        attempt.classification = attempt.outcome.as_ref().map(|outcome| {
            match mode {
                PublicationContentV2::Monitor { content, selector, capture } => {
                    super::monitor::require_monitor_request_v4(&attempt.intent, outcome, content, selector)?;
                    let query = outcome.request().host_execution_query_data_v3()
                        .ok_or_else(|| retryable("actual signed Query3 context is absent"))?;
                    let super::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
                        return Err(retryable("Host monitor query was rejected"));
                    };
                    if phase == MonitorProjectionPhaseV4::Read {
                        attempt.monitor = Some(aos_sandbox_protocol::host_execution::decode_host_execution_monitor_outcome_v3(exact_body, query));
                    }
                    let monitor = attempt.monitor.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or_else(|| retryable("Host monitor response retains its actual decoder refusal"))?;
                    super::monitor::classify_monitor_v4(&attempt.intent, monitor, capture)
                }
                _ => classify_outcome(&attempt.intent, attempt.kind, outcome, match mode {
                    PublicationContentV2::Control => None,
                    PublicationContentV2::Accepted { content, version, .. } =>
                        Some((HostExecutionSpecContentFieldsV1::for_grant(content), version)),
                    PublicationContentV2::Monitor { .. } => None,
                }),
            }
        });
        if attempt.kind == ExecutionAuthorizationKindV1::Apply
            && matches!(&attempt.classification, Some(Ok(ControllerExecutionObservationV1::Absent)))
        {
            attempt.classification = Some(Err(retryable("Host execution effect has not completed")));
        }
        if attempt.classification.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::Classification);
        }
        attempt.controller_before = Some(match mode {
            PublicationContentV2::Control => journal.validate_held_protected_names(),
            PublicationContentV2::Accepted { .. } | PublicationContentV2::Monitor { .. } => journal.validate_held_protected_names_retaining(&mut attempt.names[attempt.names_phase]),
        });
        if attempt.controller_before.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::ControllerBefore);
        }
        if attempt.first_site.is_none() && !(matches!(mode, PublicationContentV2::Accepted { .. })
            && attempt.intent.action == ControllerExecutionActionV1::Authorize)
            && (!matches!(mode, PublicationContentV2::Monitor { .. })
                || (phase == MonitorProjectionPhaseV4::Completion
                    && matches!(&attempt.classification,
                        Some(Ok(ControllerExecutionObservationV1::Applied(completion))) if completion.is_terminal()))) {
            if let Some(Ok(ControllerExecutionObservationV1::Applied(completion))) = &attempt.classification {
                attempt.projection = Some(match mode {
                    PublicationContentV2::Control => attempt.intent.commit_control_projection_retained(
                        project, journal, completion, &mut attempt.native_append),
                    PublicationContentV2::Accepted { cutoff, .. } => {
                        // The same outer retained paired-clock original is used;
                        // no ordinary proc capture replaces selected custody.
                        attempt.terminal_clock = clock.as_mut().map(|sample| sample());
                        match attempt.terminal_clock.as_ref().and_then(|value| value.as_ref().ok()) {
                            Some(sample) if sample.boottime_nanoseconds() < cutoff =>
                                attempt.intent.commit_control_projection_with_clock_retained(
                                    project, journal, completion, &mut attempt.native_append, Some(*sample)),
                            _ => Err(retryable("original execution cutoff expired before publication")),
                        }
                    }
                    PublicationContentV2::Monitor { capture, .. } => {
                        attempt.terminal_clock = clock.as_mut().map(|sample| sample());
                        match attempt.terminal_clock.as_ref().and_then(|value| value.as_ref().ok()) {
                            Some(sample) if attempt.outcome.as_ref().is_some_and(|outcome|
                                sample.boottime_nanoseconds() < outcome.request().deadline_boottime_nanoseconds()) => {
                                match projection_receiving.as_mut() {
                                    Some((receiving, bank, profile)) => {
                                        let mut paid = super::monitor::MonitorProjectionReceivingV4 {
                                            receiving, bank, profile, transaction: &mut attempt.projection_transaction,
                                            geometry: &mut attempt.projection_geometry, admission: &mut attempt.projection_admission,
                                        };
                                        attempt.intent.commit_projection_output_engine_v4(project, journal, completion,
                                            &mut attempt.native_append, Some(*sample), capture, Some(&mut paid))
                                    }
                                    None => Err(retryable("actual monitor projection receiver is absent")),
                                }
                            }
                            _ => Err(retryable("fresh monitor query expired before projection")),
                        }
                    }
                });
                if attempt.projection.as_ref().is_some_and(Result::is_err) {
                    attempt.select(PublicationFailureSiteV1::Projection);
                }
            }
        }

        // Both independent posts run even when projection failed. The actual
        // Current owner and SAME outer session mutex remain live throughout.
        attempt.host_after = Some(match post.as_deref_mut() {
            Some(post) => current.revalidate_execution_with_post_v1(&mut post.native),
            None => current.revalidate(),
        });
        if attempt.host_after.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::HostAfter);
        }
        attempt.controller_after = Some(match mode {
                    PublicationContentV2::Control => journal.validate_held_protected_names(),
                    PublicationContentV2::Accepted { .. } | PublicationContentV2::Monitor { .. } => journal.observe_held_names_post_retaining_v1(&mut attempt.names[attempt.names_phase + 1]),
                });
        if attempt.controller_after.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::ControllerAfter);
        }
        attempt.currentness = Some(current.into_currentness_owner());
        if attempt.first_site.is_some() {
            self.exchange.mark_failed();
            return Err(retryable("execution publication retains original failure and postcheck debt"));
        }

        let result = attempt.classification.take().ok_or_else(|| retryable("execution classification is absent"))?;
        if matches!(mode, PublicationContentV2::Control) { self.publication = None; }
        result
    }
}

#[cfg(test)]
mod tests {
    //! Inert cause-selection and borrowed-debt checks; all execution is UNRUN.

    use super::*;
    use aos_sandbox_model::{ObjectDigest, OperationId};

    fn attempt() -> ExecutionPublicationAttemptV1 {
        let intent = ControllerExecutionIntentV1 {
            operation_id: OperationId::from_bytes([1; 16]),
            projection_operation_id: OperationId::from_bytes([1; 16]),
            execution_id: [2; 16],
            action: ControllerExecutionActionV1::Signal { signal_code: 15 },
            specification: None,
            specification_digest: ObjectDigest::from_bytes([3; 32]),
            source_operation_commitment: [4; 32],
        };
        ExecutionPublicationAttemptV1::new(&intent, ExecutionAuthorizationKindV1::Apply)
    }

    #[test]
    fn first_classification_cause_survives_independent_post_failures() {
        let mut attempt = attempt();
        attempt.classification = Some(Err(retryable("original classification")));
        attempt.select(PublicationFailureSiteV1::Classification);

        attempt.host_after = Some(Err(BrokerSessionSecurityError::Currentness));
        attempt.select(PublicationFailureSiteV1::HostAfter);
        attempt.controller_after = Some(Err(JournalError::Poisoned));
        attempt.select(PublicationFailureSiteV1::ControllerAfter);

        let exchange = ControllerExecutionExchangeV1 {
            exchange: Default::default(), publication: Some(attempt),
        };
        assert!(matches!(exchange.publication_failure(),
            Some(ExecutionPublicationCauseV1::Effect(EffectFailure::Retryable(message)))
                if message == "original classification"));
        let debts = exchange.publication_debts().unwrap();
        assert!(matches!(debts.host_after, Some(Err(BrokerSessionSecurityError::Currentness))));
        assert!(matches!(debts.controller_after, Some(Err(JournalError::Poisoned))));
        assert!(exchange.has_pending());
        assert!(!exchange.needs_fresh_authorization());
    }

    #[test]
    fn native_append_error_is_borrowed_ahead_of_its_projection_diagnostic() {
        let mut attempt = attempt();
        attempt.native_append = Some(Err(JournalError::Poisoned));
        attempt.projection = Some(Err(retryable("mapped append diagnostic")));
        attempt.select(PublicationFailureSiteV1::Projection);
        attempt.host_after = Some(Err(BrokerSessionSecurityError::Currentness));
        attempt.select(PublicationFailureSiteV1::HostAfter);

        assert!(matches!(attempt.failure(None),
            Some(ExecutionPublicationCauseV1::Journal(JournalError::Poisoned))));
        assert!(matches!(&attempt.projection, Some(Err(EffectFailure::Retryable(message)))
            if message == "mapped append diagnostic"));
    }
}
