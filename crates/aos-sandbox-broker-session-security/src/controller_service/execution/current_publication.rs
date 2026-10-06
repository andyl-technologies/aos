//! Execution-only publication under the original Host terminal-currentness loan.
//!
//! The attempt is parked in the existing Host exchange before preparation.
//! Failed preparation, transport, classification, append, or either postcheck
//! keeps the original attempt resident and blocks every subsequent Host flight.
//! It does not make Authorize, Observe, or terminal Cancel publishable.

use aos_sandbox::{CommitResult, EffectFailure, Journal, JournalError};
use aos_sandbox_core::ProjectId;
use aos_sandbox_linux::immutable_file::ImmutableFileError;
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
enum PublicationFailureSiteV1 {
    Preparation,
    Transport,
    Currentness,
    Classification,
    ControllerBefore,
    Projection,
    HostAfter,
    ControllerAfter,
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
    controller_before: Option<Result<(), JournalError>>,
    projection: Option<Result<(), EffectFailure>>,
    native_append: Option<Result<CommitResult, JournalError>>,
    host_after: Option<Result<(), BrokerSessionSecurityError>>,
    controller_after: Option<Result<(), JournalError>>,
    first_site: Option<PublicationFailureSiteV1>,
}

impl ExecutionPublicationAttemptV1 {
    fn new(intent: &ControllerExecutionIntentV1, kind: ExecutionAuthorizationKindV1) -> Self {
        Self {
            intent: intent.clone(), kind,
            request_preparation: None, descriptor_preparation: None,
            preparation_failure: None, transport_failure: None,
            credential: None, descriptor: None,
            outcome: None, currentness: None, currentness_check: None,
            classification: None, controller_before: None, projection: None,
            native_append: None, host_after: None, controller_after: None, first_site: None,
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
            PublicationFailureSiteV1::Classification => self.classification.as_ref()?.as_ref().err().map(Cause::Effect),
            PublicationFailureSiteV1::ControllerBefore => self.controller_before.as_ref()?.as_ref().err().map(Cause::Journal),
            PublicationFailureSiteV1::Projection => self.native_append.as_ref().and_then(|result| result.as_ref().err()).map(Cause::Journal)
                .or_else(|| self.projection.as_ref()?.as_ref().err().map(Cause::Effect)),
            PublicationFailureSiteV1::HostAfter => self.host_after.as_ref()?.as_ref().err().map(Cause::Session),
            PublicationFailureSiteV1::ControllerAfter => self.controller_after.as_ref()?.as_ref().err().map(Cause::Journal),
        }
    }
}

impl ControllerExecutionExchangeV1 {
    /// Reports actual occupied publication custody, never admission readiness.
    pub(crate) const fn has_publication_debt(&self) -> bool {
        self.publication.is_some()
    }

    /// Borrows the sticky original failure of this parked execution attempt.
    pub(crate) fn publication_failure(&self) -> Option<ExecutionPublicationCauseV1<'_>> {
        self.publication.as_ref()?.failure(self.exchange.execution_failure())
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
        self.publication = Some(ExecutionPublicationAttemptV1::new(intent, kind));
        let Some(attempt) = self.publication.as_mut() else {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        };

        // This preparation is the same fixed producer used by the legacy
        // execution exchange. Ambiguous variants are retained, never recovered.
        let prepared = (|| {
            let authorization = authorization.ok_or_else(|| retryable("current Host execution authorization is unavailable"))?;
            let content = intent.descriptor_content()?;
            let stable_content = HostExecutionSpecContentFieldsV1::for_grant(&content);
            let context = ExecutionExchangeContextV1 { intent: intent.clone(), kind };
            if kind == ExecutionAuthorizationKindV1::Apply {
                attempt.credential = Some(SealedReadOnlyCredential::create(
                    "aos-host-execution-spec", &content, MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
                ));
                let Some(Ok(credential)) = &attempt.credential else {
                    return Err(retryable("execution credential preparation retains original failure"));
                };
                attempt.descriptor = Some(rustix::io::dup(credential.as_fd()));
                if !matches!(&attempt.descriptor, Some(Ok(_))) {
                    return Err(retryable("execution descriptor duplication retains original failure"));
                }
                let Some(Ok(descriptor)) = attempt.descriptor.take() else {
                    return Err(retryable("execution descriptor custody is absent"));
                };
                attempt.descriptor_preparation = Some(session.prepare_authenticated_descriptor_request(
                    kind.broker_method(), vec![descriptor], |coordinates| {
                        intent.envelope(kind, coordinates, authorization, stable_content)
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
                        intent.envelope(kind, coordinates, authorization, stable_content)
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

        let Some(owner) = attempt.currentness.take() else {
            self.exchange.mark_failed();
            return Err(retryable("execution publication currentness is absent"));
        };
        let mut current = match session.retain_execution_outcome_current(owner) {
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
                attempt.controller_after = Some(journal.validate_held_protected_names());
                if attempt.controller_after.as_ref().is_some_and(Result::is_err) {
                    attempt.select(PublicationFailureSiteV1::ControllerAfter);
                }
                self.exchange.mark_failed();
                return Err(retryable("execution publication retains failed currentness"));
            }
        };
        attempt.classification = attempt.outcome.as_ref().map(|outcome| {
            classify_outcome(&attempt.intent, attempt.kind, outcome)
        });
        if attempt.kind == ExecutionAuthorizationKindV1::Apply
            && matches!(&attempt.classification, Some(Ok(ControllerExecutionObservationV1::Absent)))
        {
            attempt.classification = Some(Err(retryable("Host execution effect has not completed")));
        }
        if attempt.classification.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::Classification);
        }
        attempt.controller_before = Some(journal.validate_held_protected_names());
        if attempt.controller_before.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::ControllerBefore);
        }
        if attempt.first_site.is_none() {
            if let Some(Ok(ControllerExecutionObservationV1::Applied(completion))) = &attempt.classification {
                attempt.projection = Some(attempt.intent.commit_control_projection_retained(
                    project, journal, completion, &mut attempt.native_append,
                ));
                if attempt.projection.as_ref().is_some_and(Result::is_err) {
                    attempt.select(PublicationFailureSiteV1::Projection);
                }
            }
        }

        // Both independent posts run even when projection failed. The actual
        // Current owner and SAME outer session mutex remain live throughout.
        attempt.host_after = Some(current.revalidate());
        if attempt.host_after.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::HostAfter);
        }
        attempt.controller_after = Some(journal.validate_held_protected_names());
        if attempt.controller_after.as_ref().is_some_and(Result::is_err) {
            attempt.select(PublicationFailureSiteV1::ControllerAfter);
        }
        attempt.currentness = Some(current.into_currentness_owner());
        if attempt.first_site.is_some() {
            self.exchange.mark_failed();
            return Err(retryable("execution publication retains original failure and postcheck debt"));
        }

        let result = attempt.classification.take().ok_or_else(|| retryable("execution classification is absent"))?;
        self.publication = None;
        result
    }
}

#[cfg(test)]
mod tests {
    //! Inert cause-selection and borrowed-debt checks; all execution is UNRUN.

    use super::*;
    use aos_sandbox_core::{ObjectDigest, OperationId};

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
