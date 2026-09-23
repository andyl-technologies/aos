//! Durable controller dispatch identity for public execution-control effects.
//!
//! The accepted controller effect retains the authenticated caller, project,
//! and canonical public request. This protected admission context, not the
//! mutable execution projection, is the source for Host requests after a
//! restart. Later controls can supersede the projection while an earlier
//! operation is still pending.

use aos_proto::aos::sandbox::local::v1::{
    ApplyHostExecutionRequestV1, BrokerAuthorizationArtifactsV1, BrokerMethod,
    BrokerRequestEnvelope, HostExecutionActionV1, HostExecutionCompletionStatusV1,
    HostExecutionPhaseV1, QueryHostExecutionRequestV1, RequestHeader,
};
use aos_sandbox::cli_model::DormantSandboxRequestKindV1;
use aos_sandbox::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};
use aos_sandbox::production_operation_compiler::{
    PublicExecutionControlDispatchV1, lower_public_execution_control_v1,
};
use aos_sandbox::{
    AuthorityPublicationStore, EffectFailure, EffectObservation, EffectReceipt, Journal,
    PublicMutationEffectV1,
};
use aos_sandbox_core::runtime_backend::EffectOperationV1;
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, ExecutionId, NodeId, ObjectDigest,
    OperationId, ProjectId, ProtocolId, ProtocolVersion, SandboxId,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::host_execution::decode_host_execution_outcome_v1;
use aos_sandbox_protocol::semantics::{
    host_execution_apply_grant_v1, host_execution_query_grant_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestCoordinatesV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestSendProgressV1,
    DormantBrokerResponseProgressV1, DormantOutstandingBrokerRequestV1,
    DormantPreparedBrokerRequestV1, DormantUnconfirmedBrokerRequestV1,
    ProtectedBrokerOutcomeCommitRecoveryV1, ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerRequestCommitRecoveryV1, ProtectedBrokerSessionInitializationRecoveryV1,
};

use super::REQUEST_SCOPE;

const PUBLIC_REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.controller-public-request.v1\0";
const EXECUTION_RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-receipt.v1\0";
const RETAINED_RECOVERY: &str = "execution effect retains protected Host session recovery custody";
const SESSION_UNUSABLE: &str = "execution effect Host session is unusable";

/// Carries one exact source-domain execution-control operation into the Host carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerExecutionIntentV1 {
    operation_id: OperationId,
    execution_id: [u8; 16],
    action: ControllerExecutionActionV1,
    source_operation_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerExecutionActionV1 {
    Resize { rows: u16, columns: u16 },
    Signal { signal_code: u8 },
}

#[derive(Clone, Copy)]
pub(crate) enum ExecutionAuthorizationKindV1 {
    Apply,
    Query,
}

impl ControllerExecutionIntentV1 {
    pub(crate) fn from_control(
        operation_id: OperationId,
        context: &PublicMutationEffectV1,
    ) -> Result<Self, EffectFailure> {
        let DormantSandboxRequestKindV1::ExecutionControl(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Err(EffectFailure::Permanent(
                "execution effect has the wrong public method".to_owned(),
            ));
        };
        let execution_id: [u8; 16] = request.execution_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("execution effect identity is invalid".to_owned())
        })?;
        let PublicExecutionControlDispatchV1::Effect(effect) =
            lower_public_execution_control_v1(&request)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Err(EffectFailure::Permanent(
                "execution attachment requires a separate route".to_owned(),
            ));
        };
        let action = match effect {
            EffectOperationV1::ResizeTerminal { rows, columns } => {
                ControllerExecutionActionV1::Resize { rows, columns }
            }
            EffectOperationV1::Signal { signal_code } => {
                ControllerExecutionActionV1::Signal { signal_code }
            }
            _ => {
                return Err(EffectFailure::Permanent(
                    "execution control action is unsupported".to_owned(),
                ));
            }
        };

        let source_operation_commitment: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_REQUEST_DIGEST_DOMAIN)
            .chain_update(REQUEST_SCOPE)
            .chain_update(context.caller().as_bytes())
            .chain_update(context.project().as_bytes())
            .chain_update((context.canonical_request().len() as u64).to_be_bytes())
            .chain_update(context.canonical_request())
            .finalize()
            .into();

        Ok(Self {
            operation_id,
            execution_id,
            action,
            source_operation_commitment,
        })
    }

    pub(crate) fn prepare_authorization(
        &self,
        kind: ExecutionAuthorizationKindV1,
        project: ProjectId,
        node: NodeId,
        journal: &mut Journal,
        signer: Option<&ControllerBrokerPlanSignerV1>,
    ) -> Result<BrokerAuthorizationArtifactsV1, EffectFailure> {
        let signer = signer.ok_or_else(|| {
            EffectFailure::Retryable("Host execution plan signer is unavailable".to_owned())
        })?;
        let projection = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Execution, self.execution_id)
            .map_err(retryable)?
            .ok_or_else(|| {
                EffectFailure::Retryable("protected execution projection is absent".to_owned())
            })?;
        if projection.project() != project {
            return Err(EffectFailure::Permanent(
                "execution projection crossed its admitted project".to_owned(),
            ));
        }
        let PublicProjectionResourceV1::Execution(execution) = projection.resource() else {
            return Err(EffectFailure::Permanent(
                "execution projection has another resource kind".to_owned(),
            ));
        };
        let sandbox_id: [u8; 16] = execution.sandbox_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("execution sandbox identity is invalid".to_owned())
        })?;
        let sandbox = SandboxId::from_bytes(sandbox_id);
        let current = AuthorityPublicationStore::new(journal)
            .current(sandbox)
            .map_err(retryable)?
            .ok_or_else(|| {
                EffectFailure::Retryable("current execution authority is absent".to_owned())
            })?;
        let manifest = current.manifest();
        let assignment = manifest.broker_assignment().map_err(retryable)?;
        let lease_assignment = current.lease().lease().assignment();
        if manifest.manifest().project() != project
            || manifest.manifest().node() != node
            || execution.sandbox_incarnation_id.as_slice()
                != manifest.manifest().incarnation().as_bytes()
            || execution.assignment_epoch != manifest.manifest().epoch().get()
            || lease_assignment.sandbox() != assignment.sandbox()
            || lease_assignment.incarnation() != assignment.incarnation()
            || lease_assignment.epoch() != assignment.epoch()
            || lease_assignment.digest() != assignment.digest()
            || current.lease().lease().node() != node
        {
            return Err(EffectFailure::Retryable(
                "execution assignment is not current".to_owned(),
            ));
        }

        let semantics = match kind {
            ExecutionAuthorizationKindV1::Apply => {
                let action = match self.action {
                    ControllerExecutionActionV1::Resize { rows, columns } => {
                        EffectOperationV1::ResizeTerminal { rows, columns }
                    }
                    ControllerExecutionActionV1::Signal { signal_code } => {
                        EffectOperationV1::Signal { signal_code }
                    }
                };
                host_execution_apply_grant_v1(
                    assignment,
                    *self.operation_id.as_bytes(),
                    ExecutionId::from_bytes(self.execution_id),
                    ObjectDigest::from_bytes(self.source_operation_commitment),
                    action,
                    None,
                )
            }
            ExecutionAuthorizationKindV1::Query => host_execution_query_grant_v1(
                assignment,
                *self.operation_id.as_bytes(),
                ExecutionId::from_bytes(self.execution_id),
                ObjectDigest::from_bytes(self.source_operation_commitment),
            ),
        }
        .map_err(retryable)?;
        let template = current
            .templates()
            .iter()
            .find(|candidate| candidate.audience() == BrokerAudience::Host)
            .ok_or_else(|| {
                EffectFailure::Retryable("current Host authority template is absent".to_owned())
            })?;
        let parent = template.plan();
        if parent.assignment() != assignment || parent.node() != node {
            return Err(EffectFailure::Retryable(
                "current Host template differs from execution assignment".to_owned(),
            ));
        }
        let now = crate::controller_ownership::sample_ownership_clock()
            .map_err(retryable)?
            .wall_seconds();
        let expires = now
            .checked_add(30)
            .map(|limit| {
                limit
                    .min(parent.expires_seconds())
                    .min(current.lease().lease().authority_expires_seconds())
            })
            .ok_or_else(|| EffectFailure::Retryable("execution clock overflowed".to_owned()))?;
        if now < parent.issued_seconds() || expires <= now {
            return Err(EffectFailure::Retryable(
                "current Host authority is outside its validity interval".to_owned(),
            ));
        }
        let grant = BrokerGrant::new(
            semantics.verb(),
            semantics.target(),
            semantics.commitment(),
            64 * 1024,
            0,
        )
        .map_err(retryable)?;
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Host,
            ProtocolId::HostBroker,
            ProtocolVersion::new(1, 0),
            assignment,
            node,
            parent.ownership_authority().clone(),
            vec![grant],
            parent.policy_commitment(),
            parent.revocation_scope(),
            now,
            expires,
            Vec::new(),
        )
        .map_err(retryable)?;
        let signed = signer.sign_plan(plan, now).map_err(retryable)?;
        Ok(BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        })
    }

    fn envelope(
        &self,
        kind: ExecutionExchangeKindV1,
        coordinates: DormantBrokerRequestCoordinatesV1,
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> BrokerRequestEnvelope {
        let header = RequestHeader {
            protocol_major: u32::from(coordinates.protocol_version().major()),
            protocol_minor: u32::from(coordinates.protocol_version().minor()),
            request_id: coordinates.request_id().to_vec(),
            audience: coordinates.audience().into(),
            deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
            maximum_response_bytes: coordinates.maximum_response_bytes(),
            ..Default::default()
        };
        let (method, body) = match kind {
            ExecutionExchangeKindV1::Apply => {
                let (action, terminal_rows, terminal_columns, signal_number) = match self.action {
                    ControllerExecutionActionV1::Resize { rows, columns } => (
                        HostExecutionActionV1::HOST_EXECUTION_ACTION_RESIZE,
                        u32::from(rows),
                        u32::from(columns),
                        0,
                    ),
                    ControllerExecutionActionV1::Signal { signal_code } => (
                        HostExecutionActionV1::HOST_EXECUTION_ACTION_SIGNAL,
                        0,
                        0,
                        u32::from(signal_code),
                    ),
                };
                let request = ApplyHostExecutionRequestV1 {
                    header: Some(header).into(),
                    operation_id: self.operation_id.as_bytes().to_vec(),
                    execution_id: self.execution_id.to_vec(),
                    action: action.into(),
                    source_operation_commitment: self.source_operation_commitment.to_vec(),
                    terminal_rows,
                    terminal_columns,
                    signal_number,
                    ..Default::default()
                };
                (
                    BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION,
                    request.encode_to_vec(),
                )
            }
            ExecutionExchangeKindV1::Query => {
                let request = QueryHostExecutionRequestV1 {
                    header: Some(header).into(),
                    operation_id: self.operation_id.as_bytes().to_vec(),
                    execution_id: self.execution_id.to_vec(),
                    source_operation_commitment: self.source_operation_commitment.to_vec(),
                    ..Default::default()
                };
                (
                    BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION,
                    request.encode_to_vec(),
                )
            }
        };
        BrokerRequestEnvelope {
            method: method.into(),
            body,
            authorization: Some(authorization.clone()).into(),
            ..Default::default()
        }
    }
}

fn retryable(error: impl ToString) -> EffectFailure {
    EffectFailure::Retryable(error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionExchangeKindV1 {
    Apply,
    Query,
}

struct PendingExecutionExchangeV1 {
    intent: ControllerExecutionIntentV1,
    kind: ExecutionExchangeKindV1,
    stage: ExecutionExchangeStageV1,
}

enum ExecutionExchangeStageV1 {
    Initialization {
        recovery: ProtectedBrokerSessionInitializationRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Successor {
        recovery: ProtectedBrokerRequestCommitRecoveryV1,
        request: DormantUnconfirmedBrokerRequestV1,
    },
    Send(DormantPreparedBrokerRequestV1),
    Receive(DormantOutstandingBrokerRequestV1),
    Commit(ProtectedBrokerOutcomeCommitRecoveryV1),
}

/// Retains the exact signed Host request across transport and commit ambiguity.
#[derive(Default)]
pub(crate) struct ControllerExecutionExchangeV1 {
    pending: Option<PendingExecutionExchangeV1>,
    failed: bool,
}

impl ControllerExecutionExchangeV1 {
    pub(crate) const fn has_pending(&self) -> bool {
        self.pending.is_some() || self.failed
    }

    pub(crate) const fn needs_fresh_authorization(&self) -> bool {
        self.pending.is_none() && !self.failed
    }

    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.failed
    }

    pub(crate) fn query(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<EffectObservation, EffectFailure> {
        let outcome = self.exchange(
            session,
            intent,
            ExecutionExchangeKindV1::Query,
            authorization,
        )?;
        let result = classify_outcome(intent, ExecutionExchangeKindV1::Query, &outcome);
        if matches!(&result, Err(EffectFailure::Permanent(_))) {
            self.failed = true;
        }
        result
    }

    pub(crate) fn apply(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<EffectReceipt, EffectFailure> {
        let outcome = self.exchange(
            session,
            intent,
            ExecutionExchangeKindV1::Apply,
            authorization,
        )?;
        let result = classify_outcome(intent, ExecutionExchangeKindV1::Apply, &outcome);
        if matches!(&result, Err(EffectFailure::Permanent(_))) {
            self.failed = true;
        }
        match result? {
            EffectObservation::Applied(receipt) => Ok(receipt),
            EffectObservation::Absent => Err(EffectFailure::Retryable(
                "Host execution effect has not completed".to_owned(),
            )),
        }
    }

    fn exchange(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: &ControllerExecutionIntentV1,
        kind: ExecutionExchangeKindV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        if self.failed {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.intent != *intent || pending.kind != kind)
        {
            return Err(EffectFailure::Retryable(
                "another exact execution exchange retains Host session custody".to_owned(),
            ));
        }
        if self.pending.is_none() {
            let authorization = authorization.ok_or_else(|| {
                EffectFailure::Retryable(
                    "current Host execution authorization is unavailable".to_owned(),
                )
            })?;
            let method = match kind {
                ExecutionExchangeKindV1::Apply => BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION,
                ExecutionExchangeKindV1::Query => BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION,
            };
            let preparation = session
                .prepare_authenticated_request(method, |coordinates| {
                    intent.envelope(kind, coordinates, authorization)
                })
                .map_err(|_| {
                    self.failed = true;
                    EffectFailure::Retryable(
                        "execution request could not enter protected Host session custody"
                            .to_owned(),
                    )
                })?;
            self.pending = Some(PendingExecutionExchangeV1 {
                intent: intent.clone(),
                kind,
                stage: preparation_stage(preparation),
            });
        }
        self.drive(session)
    }

    fn drive(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        let mut attempted_recovery = false;
        loop {
            let pending = self.pending.take().ok_or_else(|| {
                EffectFailure::Retryable("execution exchange custody is absent".to_owned())
            })?;
            let intent = pending.intent;
            let kind = pending.kind;
            let stage = match pending.stage {
                ExecutionExchangeStageV1::Initialization { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            intent,
                            kind,
                            ExecutionExchangeStageV1::Initialization { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_initialization(recovery, request))
                }
                ExecutionExchangeStageV1::Successor { recovery, request } => {
                    if attempted_recovery {
                        return self.retain(
                            intent,
                            kind,
                            ExecutionExchangeStageV1::Successor { recovery, request },
                        );
                    }
                    attempted_recovery = true;
                    preparation_stage(session.recover_prepared_successor(recovery, request))
                }
                ExecutionExchangeStageV1::Send(prepared) => {
                    let deadline = prepared.deadline_boottime_nanoseconds();
                    match session.send_authenticated_request(prepared) {
                        Ok(DormantBrokerRequestSendProgressV1::Sent(outstanding)) => {
                            ExecutionExchangeStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerRequestSendProgressV1::Pending(prepared)) => {
                            if wait(session, true, deadline).is_err() {
                                return self.retain(
                                    intent,
                                    kind,
                                    ExecutionExchangeStageV1::Send(prepared),
                                );
                            }
                            ExecutionExchangeStageV1::Send(prepared)
                        }
                        Err(_) => return self.fail(),
                    }
                }
                ExecutionExchangeStageV1::Receive(outstanding) => {
                    let deadline = outstanding.deadline_boottime_nanoseconds();
                    match session.receive_authenticated_response(outstanding) {
                        Ok(DormantBrokerResponseProgressV1::Pending(outstanding)) => {
                            if wait(session, false, deadline).is_err() {
                                return self.retain(
                                    intent,
                                    kind,
                                    ExecutionExchangeStageV1::Receive(outstanding),
                                );
                            }
                            ExecutionExchangeStageV1::Receive(outstanding)
                        }
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::Committed(committed),
                        )) => return self.complete(session, committed),
                        Ok(DormantBrokerResponseProgressV1::Committed(
                            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                                recovery, ..
                            },
                        )) => ExecutionExchangeStageV1::Commit(recovery),
                        Err(_) => return self.fail(),
                    }
                }
                ExecutionExchangeStageV1::Commit(recovery) => {
                    if attempted_recovery {
                        return self.retain(
                            intent,
                            kind,
                            ExecutionExchangeStageV1::Commit(recovery),
                        );
                    }
                    attempted_recovery = true;
                    match session.recover_broker_outcome_commit(recovery) {
                        ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => {
                            return self.complete(session, committed);
                        }
                        ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired {
                            recovery, ..
                        } => ExecutionExchangeStageV1::Commit(recovery),
                    }
                }
            };
            self.pending = Some(PendingExecutionExchangeV1 {
                intent,
                kind,
                stage,
            });
        }
    }

    fn retain<T>(
        &mut self,
        intent: ControllerExecutionIntentV1,
        kind: ExecutionExchangeKindV1,
        stage: ExecutionExchangeStageV1,
    ) -> Result<T, EffectFailure> {
        self.pending = Some(PendingExecutionExchangeV1 {
            intent,
            kind,
            stage,
        });
        Err(EffectFailure::Retryable(RETAINED_RECOVERY.to_owned()))
    }

    fn fail<T>(&mut self) -> Result<T, EffectFailure> {
        self.failed = true;
        Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()))
    }

    fn complete(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        let (outcome, currentness) = committed.into_outcome_and_currentness();
        let Ok(mut current) = session.revalidate_broker_outcome(currentness) else {
            return self.fail();
        };
        if current.revalidate().is_err() {
            return self.fail();
        }
        Ok(outcome)
    }
}

fn preparation_stage(preparation: DormantBrokerRequestPreparationV1) -> ExecutionExchangeStageV1 {
    match preparation {
        DormantBrokerRequestPreparationV1::Prepared(prepared) => {
            ExecutionExchangeStageV1::Send(prepared)
        }
        DormantBrokerRequestPreparationV1::InitializationRecoveryRequired {
            recovery,
            request,
            ..
        } => ExecutionExchangeStageV1::Initialization { recovery, request },
        DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired {
            recovery, request, ..
        } => ExecutionExchangeStageV1::Successor { recovery, request },
    }
}

fn wait(
    session: &DormantAuthenticatedBrokerSessionV1,
    wants_write: bool,
    deadline_boottime_nanoseconds: u64,
) -> Result<(), ()> {
    let descriptor = session.as_fd().map_err(|_| ())?;
    crate::dormant_handshake::wait_for_handshake_readiness(
        descriptor,
        wants_write,
        deadline_boottime_nanoseconds,
    )
    .map_err(|_| ())
}

fn classify_outcome(
    intent: &ControllerExecutionIntentV1,
    kind: ExecutionExchangeKindV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<EffectObservation, EffectFailure> {
    let expected_method = match kind {
        ExecutionExchangeKindV1::Apply => BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION,
        ExecutionExchangeKindV1::Query => BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION,
    };
    if outcome.method() != expected_method || !request_matches_intent(intent, kind, outcome) {
        return Err(EffectFailure::Permanent(
            "Host execution outcome has the wrong signed request".to_owned(),
        ));
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(EffectFailure::Retryable(
            "Host execution method is unavailable or rejected".to_owned(),
        ));
    };
    let body = decode_host_execution_outcome_v1(
        exact_body,
        *intent.operation_id.as_bytes(),
        ExecutionId::from_bytes(intent.execution_id),
        ObjectDigest::from_bytes(intent.source_operation_commitment),
    )
    .map_err(|_| {
        EffectFailure::Permanent("signed Host execution outcome is malformed".to_owned())
    })?;
    match body.phase.as_known() {
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE) => {
            let effect_commitment: [u8; 32] =
                body.effect_commitment.as_slice().try_into().map_err(|_| {
                    EffectFailure::Permanent(
                        "Host execution effect commitment is invalid".to_owned(),
                    )
                })?;
            let completion_digest: [u8; 32] =
                body.completion_digest.as_slice().try_into().map_err(|_| {
                    EffectFailure::Permanent(
                        "Host execution completion digest is invalid".to_owned(),
                    )
                })?;
            if effect_commitment == [0; 32]
                || completion_digest == [0; 32]
                || body.completion_bytes.is_empty()
            {
                return Err(EffectFailure::Permanent(
                    "Host execution completion is incomplete".to_owned(),
                ));
            }
            if body.observation_sequence == 0 {
                return Err(EffectFailure::Permanent(
                    "Host execution completion has no observation sequence".to_owned(),
                ));
            }
            match body.completion_status.as_known() {
                Some(HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED) => {}
                Some(
                    HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_REJECTED_BEFORE_EFFECT
                    | HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_FAILED_PERMANENT,
                ) => {
                    return Err(EffectFailure::Permanent(
                        "Host execution effect completed without success".to_owned(),
                    ));
                }
                _ => {
                    return Err(EffectFailure::Permanent(
                        "Host execution completion status is invalid".to_owned(),
                    ));
                }
            }
            let digest: [u8; 32] = Sha256::new()
                .chain_update(EXECUTION_RECEIPT_DOMAIN)
                .chain_update(intent.operation_id.as_bytes())
                .chain_update(intent.execution_id)
                .chain_update(intent.source_operation_commitment)
                .chain_update(effect_commitment)
                .chain_update(completion_digest)
                .chain_update(body.observation_sequence.to_be_bytes())
                .chain_update(&body.completion_bytes)
                .finalize()
                .into();
            let receipt = EffectReceipt::new([b"AOSEXE01".as_slice(), digest.as_slice()].concat())
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            Ok(EffectObservation::Applied(receipt))
        }
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT)
            if kind == ExecutionExchangeKindV1::Query =>
        {
            Ok(EffectObservation::Absent)
        }
        Some(
            HostExecutionPhaseV1::HOST_EXECUTION_PHASE_PENDING
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ISSUED
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_INDETERMINATE,
        ) => Err(EffectFailure::Retryable(
            "Host execution effect is pending exact recovery".to_owned(),
        )),
        _ => Err(EffectFailure::Permanent(
            "signed Host execution outcome has an invalid phase".to_owned(),
        )),
    }
}

fn request_matches_intent(
    intent: &ControllerExecutionIntentV1,
    kind: ExecutionExchangeKindV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> bool {
    let exact_body = outcome.request().exact_body();
    match kind {
        ExecutionExchangeKindV1::Apply => {
            let Ok(request) = ApplyHostExecutionRequestV1::decode_from_slice(exact_body) else {
                return false;
            };
            let action_matches = match intent.action {
                ControllerExecutionActionV1::Resize { rows, columns } => {
                    request.action.as_known()
                        == Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_RESIZE)
                        && request.terminal_rows == u32::from(rows)
                        && request.terminal_columns == u32::from(columns)
                        && request.signal_number == 0
                }
                ControllerExecutionActionV1::Signal { signal_code } => {
                    request.action.as_known()
                        == Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_SIGNAL)
                        && request.terminal_rows == 0
                        && request.terminal_columns == 0
                        && request.signal_number == u32::from(signal_code)
                }
            };
            request.encode_to_vec() == exact_body
                && request.operation_id == intent.operation_id.as_bytes()
                && request.execution_id == intent.execution_id
                && request.source_operation_commitment == intent.source_operation_commitment
                && request.canonical_execution_spec.is_empty()
                && action_matches
        }
        ExecutionExchangeKindV1::Query => {
            let Ok(request) = QueryHostExecutionRequestV1::decode_from_slice(exact_body) else {
                return false;
            };
            request.encode_to_vec() == exact_body
                && request.operation_id == intent.operation_id.as_bytes()
                && request.execution_id == intent.execution_id
                && request.source_operation_commitment == intent.source_operation_commitment
        }
    }
}
