//! Retains the controller's protected Host catalog publication exchange.
//!
//! Request admission precedes descriptor transport. Backpressure retains the
//! exact signed packet and sealed memfd; ambiguous durable writes retain their
//! move-only readback tokens. This owner never clears previous-process history.

use aos_proto::aos::sandbox::local::v1::{
    BrokerDescriptorEntry, BrokerMethod, BrokerRequestEnvelope, PublishHostCatalogRequest,
    RequestHeader, RuntimeAction,
};
use aos_sandbox::host_catalog_publication::{
    HostCatalogPublicationDraftV1, HostCatalogPublicationError,
};
use aos_sandbox::lifecycle::{
    CurrentLifecycleEffectV1, LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
    LifecycleBootInventoryBootstrapChallengeV1, LifecycleEffectObservationV1,
    LifecyclePhase6ErrorV1, LiveRuntimeFenceV1,
};
use aos_sandbox::{
    AuthorityEffectObservationV1, EffectFailure, PreparedAuthorityEffectV1,
    ValidatedAuthorityEffectReceiptV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::host_catalog::HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES;
use buffa::Message as _;

use crate::controller_authority_effect::ControllerAuthorityEffectExchangeV1;
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerDescriptorRequestPreparationV1, DormantBrokerDescriptorRequestSendProgressV1,
    DormantBrokerRequestCoordinatesV1, DormantBrokerResponseProgressV1,
    DormantBrokerSessionHandshakeErrorV1, DormantOutstandingBrokerRequestV1,
    ProtectedBrokerOutcomeCommitResultV1,
};

/// Owns one Host channel and any exact publication awaiting completion.
pub(crate) struct ControllerHostPublication {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    pending: Option<PendingPublication>,
    authority_effects: ControllerAuthorityEffectExchangeV1,
    poisoned: bool,
}

struct PendingPublication {
    draft: HostCatalogPublicationDraftV1,
    stage: PublicationStage,
}

enum PublicationStage {
    Prepare(DormantBrokerDescriptorRequestPreparationV1),
    Send(DormantBrokerDescriptorRequestSendProgressV1),
    Receive(DormantOutstandingBrokerRequestV1),
    Commit(ProtectedBrokerOutcomeCommitResultV1),
}

/// Reports a retained retry or a fail-closed publication failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControllerHostPublicationError {
    #[error("Host publication differs from the retained request or its session is unusable")]
    Conflict,
    #[error("Host publication has retained protected recovery work")]
    RecoveryPending,
    #[error(transparent)]
    Catalog(#[from] HostCatalogPublicationError),
    #[error(transparent)]
    Protected(#[from] BrokerSessionSecurityError),
    #[error(transparent)]
    Session(#[from] DormantBrokerSessionHandshakeErrorV1),
}

impl ControllerHostPublication {
    pub(crate) fn new(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self {
            session: Some(session),
            pending: None,
            authority_effects: ControllerAuthorityEffectExchangeV1::default(),
            poisoned: false,
        }
    }

    /// Applies or resumes one exact Host authority effect on this same session.
    pub(crate) fn apply_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        if self.pending.is_some() || self.poisoned {
            return Err(EffectFailure::Retryable(
                "Host session has retained catalog publication work".to_owned(),
            ));
        }
        let session = self.session.as_mut().ok_or_else(|| {
            EffectFailure::Retryable("Host session is temporarily unavailable".to_owned())
        })?;
        self.authority_effects.apply(session, effect)
    }

    /// Resumes matching retained Host effect custody without issuing a new Apply.
    pub(crate) fn resume_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Option<Result<ValidatedAuthorityEffectReceiptV1, EffectFailure>> {
        let session = self.session.as_mut()?;
        self.authority_effects.resume(session, effect)
    }

    /// Recovers this exact Apply from prior-process terminal history.
    pub(crate) fn recover_terminal_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
        if self.pending.is_some() || self.authority_effects.has_pending() || self.poisoned {
            return Err(EffectFailure::Retryable(
                "Host session has retained recovery work".to_owned(),
            ));
        }
        self.session
            .as_mut()
            .ok_or_else(|| {
                EffectFailure::Retryable("Host session is temporarily unavailable".to_owned())
            })?
            .recover_terminal_authority_effect(effect)
    }

    /// Queries Host for one exact prior-process authority effect.
    pub(crate) fn query_authority_effect(
        &mut self,
        effect: &PreparedAuthorityEffectV1,
    ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
        if self.pending.is_some() || self.poisoned {
            return Err(EffectFailure::Retryable(
                "Host session has retained catalog publication work".to_owned(),
            ));
        }
        let session = self.session.as_mut().ok_or_else(|| {
            EffectFailure::Retryable("Host session is temporarily unavailable".to_owned())
        })?;
        self.authority_effects.query_host(session, effect)
    }

    /// Applies one exact lifecycle runtime effect with adjacent Host inventory.
    pub(crate) fn apply_lifecycle_runtime<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        fence: LiveRuntimeFenceV1,
        action: RuntimeAction,
        authority: &PreparedAuthorityEffectV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        if self.pending.is_some()
            || self.authority_effects.has_pending()
            || self.poisoned
            || self.session.is_none()
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let session = self
            .session
            .take()
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let mut owner = crate::DormantLifecycleDomainEffectOwnerV1::from_protected_session(session);
        let result = owner
            .observe_runtime(challenge, effect, fence, action, authority)
            .and_then(|progress| owner.complete_blocking(progress));
        self.session = Some(owner.into_protected_session());
        if result.is_err() {
            // Reopen durable history on a fresh transport before any new Host
            // work; the exact request remains protected even if this process's
            // recovery token could not settle.
            self.poisoned = true;
        }
        result
    }

    /// Reports whether no other Host exchange owns this protected session.
    pub(crate) const fn lifecycle_runtime_ready(&self) -> bool {
        self.pending.is_none()
            && !self.authority_effects.has_pending()
            && !self.poisoned
            && self.session.is_some()
    }

    /// Captures an adjacent challenge-authenticated Host inventory pair.
    pub(crate) fn bootstrap_runtime_inventory(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
    ) -> Result<LifecycleAuthenticatedRuntimeInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
        if !self.lifecycle_runtime_ready() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let session = self
            .session
            .take()
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let mut owner = crate::DormantHostRuntimeInventoryOwnerV1::from_protected_session(session);
        let result = owner.bootstrap_inventory_pair(challenge);
        self.session = Some(owner.into_protected_session());
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Reports that the current authenticated session must be replaced.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.poisoned || self.authority_effects.requires_reconnect()
    }

    /// Completes a publication without replacing any retained request identity.
    pub(crate) fn publish(
        &mut self,
        draft: &HostCatalogPublicationDraftV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerHostPublicationError> {
        if self.authority_effects.has_pending()
            || self.poisoned
            || self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.draft != *draft)
        {
            return Err(ControllerHostPublicationError::Conflict);
        }
        if self.pending.is_none() {
            let descriptor = draft.sealed_transfer_descriptor()?;
            // A failed preparation may follow a protected write. Never issue a
            // different request on this owner after a fatal admission error.
            self.poisoned = true;
            let preparation = self
                .session
                .as_mut()
                .ok_or(ControllerHostPublicationError::Conflict)?
                .prepare_authenticated_descriptor_request(
                    BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG,
                    vec![descriptor],
                    |coordinates| publication_envelope(draft, coordinates),
                )?;
            self.pending = Some(PendingPublication {
                draft: draft.clone(),
                stage: PublicationStage::Prepare(preparation),
            });
            self.poisoned = false;
        }

        let mut attempted_recovery = false;
        loop {
            let pending = self
                .pending
                .take()
                .ok_or(ControllerHostPublicationError::Conflict)?;
            // Consuming lower-level failures invalidate this process-local
            // owner. The protected journal and controller pending record stay.
            self.poisoned = true;
            let stage = match pending.stage {
                PublicationStage::Prepare(
                    DormantBrokerDescriptorRequestPreparationV1::Prepared(request),
                ) => PublicationStage::Send(
                    self.session
                        .as_mut()
                        .ok_or(ControllerHostPublicationError::Conflict)?
                        .send_authenticated_descriptor_request(request),
                ),
                PublicationStage::Prepare(preparation) => {
                    if attempted_recovery {
                        return self.retain_recovery(
                            pending.draft,
                            PublicationStage::Prepare(preparation),
                        );
                    }
                    attempted_recovery = true;
                    let preparation = self.recover_preparation(preparation)?;
                    PublicationStage::Prepare(preparation)
                }
                PublicationStage::Send(DormantBrokerDescriptorRequestSendProgressV1::Sent(
                    request,
                )) => PublicationStage::Receive(request),
                PublicationStage::Send(DormantBrokerDescriptorRequestSendProgressV1::Pending(
                    request,
                )) => {
                    let deadline = request.deadline_boottime_nanoseconds();
                    if let Err(error) = self.wait(true, deadline) {
                        self.retain(
                            pending.draft,
                            PublicationStage::Send(
                                DormantBrokerDescriptorRequestSendProgressV1::Pending(request),
                            ),
                        );
                        return Err(error);
                    }
                    PublicationStage::Send(
                        self.session
                            .as_mut()
                            .ok_or(ControllerHostPublicationError::Conflict)?
                            .send_authenticated_descriptor_request(request),
                    )
                }
                PublicationStage::Send(
                    DormantBrokerDescriptorRequestSendProgressV1::RecoveryRequired(recovery),
                ) => {
                    if attempted_recovery {
                        return self.retain_recovery(
                            pending.draft,
                            PublicationStage::Send(
                                DormantBrokerDescriptorRequestSendProgressV1::RecoveryRequired(
                                    recovery,
                                ),
                            ),
                        );
                    }
                    attempted_recovery = true;
                    PublicationStage::Send(
                        self.session
                            .as_mut()
                            .ok_or(ControllerHostPublicationError::Conflict)?
                            .retry_authenticated_descriptor_request(recovery),
                    )
                }
                PublicationStage::Receive(request) => {
                    let deadline = request.deadline_boottime_nanoseconds();
                    match self
                        .session
                        .as_mut()
                        .ok_or(ControllerHostPublicationError::Conflict)?
                        .receive_authenticated_response(request)?
                    {
                        DormantBrokerResponseProgressV1::Pending(request) => {
                            if let Err(error) = self.wait(false, deadline) {
                                self.retain(pending.draft, PublicationStage::Receive(request));
                                return Err(error);
                            }
                            PublicationStage::Receive(request)
                        }
                        DormantBrokerResponseProgressV1::Committed(committed) => {
                            PublicationStage::Commit(committed)
                        }
                    }
                }
                PublicationStage::Commit(ProtectedBrokerOutcomeCommitResultV1::Committed(
                    committed,
                )) => {
                    let (outcome, currentness) = committed.into_outcome_and_currentness();
                    let mut current = self
                        .session
                        .as_mut()
                        .ok_or(ControllerHostPublicationError::Conflict)?
                        .revalidate_broker_outcome(currentness)?;
                    current.revalidate()?;
                    crate::dormant_handshake::check_production_deadline(
                        outcome.request().deadline_boottime_nanoseconds(),
                    )?;
                    self.poisoned = false;
                    return Ok(outcome);
                }
                PublicationStage::Commit(
                    commit @ ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. },
                ) => {
                    if attempted_recovery {
                        return self
                            .retain_recovery(pending.draft, PublicationStage::Commit(commit));
                    }
                    attempted_recovery = true;
                    let ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } =
                        commit
                    else {
                        return Err(ControllerHostPublicationError::Conflict);
                    };
                    PublicationStage::Commit(
                        self.session
                            .as_mut()
                            .ok_or(ControllerHostPublicationError::Conflict)?
                            .recover_broker_outcome_commit(recovery),
                    )
                }
            };
            self.retain(pending.draft, stage);
        }
    }

    fn retain(&mut self, draft: HostCatalogPublicationDraftV1, stage: PublicationStage) {
        self.pending = Some(PendingPublication { draft, stage });
        self.poisoned = false;
    }

    fn recover_preparation(
        &mut self,
        preparation: DormantBrokerDescriptorRequestPreparationV1,
    ) -> Result<DormantBrokerDescriptorRequestPreparationV1, ControllerHostPublicationError> {
        let session = self
            .session
            .as_mut()
            .ok_or(ControllerHostPublicationError::Conflict)?;
        match preparation {
            DormantBrokerDescriptorRequestPreparationV1::InitializationRecoveryRequired {
                recovery,
                request,
                ..
            } => Ok(session.recover_prepared_descriptor_initialization(recovery, request)),
            DormantBrokerDescriptorRequestPreparationV1::SuccessorRecoveryRequired {
                recovery,
                request,
                ..
            } => Ok(session.recover_prepared_descriptor_successor(recovery, request)),
            prepared @ DormantBrokerDescriptorRequestPreparationV1::Prepared(_) => Ok(prepared),
        }
    }

    fn retain_recovery(
        &mut self,
        draft: HostCatalogPublicationDraftV1,
        stage: PublicationStage,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, ControllerHostPublicationError> {
        self.retain(draft, stage);
        Err(ControllerHostPublicationError::RecoveryPending)
    }

    fn wait(&self, wants_write: bool, deadline: u64) -> Result<(), ControllerHostPublicationError> {
        crate::dormant_handshake::wait_for_handshake_readiness(
            self.session
                .as_ref()
                .ok_or(ControllerHostPublicationError::Conflict)?
                .as_fd()?,
            wants_write,
            deadline,
        )?;
        crate::dormant_handshake::check_production_deadline(deadline)?;
        Ok(())
    }
}

fn publication_envelope(
    draft: &HostCatalogPublicationDraftV1,
    coordinates: DormantBrokerRequestCoordinatesV1,
) -> BrokerRequestEnvelope {
    publication_message(
        draft,
        RequestHeader {
            protocol_major: u32::from(coordinates.protocol_version().major()),
            protocol_minor: u32::from(coordinates.protocol_version().minor()),
            request_id: coordinates.request_id().to_vec(),
            audience: coordinates.audience().into(),
            deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
            maximum_response_bytes: coordinates.maximum_response_bytes(),
            ..Default::default()
        },
    )
}

fn publication_message(
    draft: &HostCatalogPublicationDraftV1,
    header: RequestHeader,
) -> BrokerRequestEnvelope {
    let request = PublishHostCatalogRequest {
        header: Some(header).into(),
        catalog_generation: draft.expected_generation(),
        catalog_bytes: draft.canonical_catalog().len() as u64,
        catalog_sha256: draft.expected_digest().as_bytes().to_vec(),
        ..Default::default()
    };
    BrokerRequestEnvelope {
        method: BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG.into(),
        body: request.encode_to_vec(),
        descriptors: vec![BrokerDescriptorEntry {
            index: 0,
            role: HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES[0].into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn publication_message_preserves_header_and_exact_descriptor_binding() {
        let draft = HostCatalogPublicationDraftV1::new(vec![1, 2, 3], 7).unwrap();
        let header = RequestHeader {
            request_id: vec![4; 16],
            deadline_boottime_nanoseconds: 123,
            maximum_response_bytes: 4096,
            ..Default::default()
        };

        let envelope = publication_message(&draft, header.clone());
        let request = PublishHostCatalogRequest::decode_from_slice(&envelope.body).unwrap();

        assert_eq!(
            envelope.method.as_known(),
            Some(BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG)
        );
        assert_eq!(envelope.descriptors.len(), 1);
        assert_eq!(envelope.descriptors[0].index, 0);
        assert_eq!(
            envelope.descriptors[0].role.as_known(),
            Some(HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES[0])
        );
        assert_eq!(request.header.as_option(), Some(&header));
        assert_eq!(request.catalog_generation, 7);
        assert_eq!(request.catalog_bytes, 3);
        assert_eq!(request.catalog_sha256, draft.expected_digest().as_bytes());
    }

    #[test]
    fn transfer_descriptor_contains_exact_bytes_and_cannot_change() {
        let draft = HostCatalogPublicationDraftV1::new(vec![1, 2, 3], 7).unwrap();
        let descriptor = draft.sealed_transfer_descriptor().unwrap();
        let mut contents = [0; 3];

        assert_eq!(
            rustix::io::pread(descriptor.as_fd(), &mut contents, 0).unwrap(),
            3
        );
        assert_eq!(contents, [1, 2, 3]);
        assert!(rustix::io::pwrite(descriptor.as_fd(), &[4], 0).is_err());
        assert!(rustix::fs::ftruncate(descriptor.as_fd(), 4).is_err());
        let seals = rustix::fs::fcntl_get_seals(descriptor.as_fd()).unwrap();
        assert!(seals.contains(
            rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SEAL
        ));
    }
}
