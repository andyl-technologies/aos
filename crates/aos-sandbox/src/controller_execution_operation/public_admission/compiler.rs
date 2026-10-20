//! Retains the canonical public Execution authorization and compiler prefix.
//!
//! The owning C18 scope stays installed while this mechanical child calls the
//! same protected holder, authorization and production lowering engines. No
//! caller-provided decoder, signer, readiness flag or admission callback exists.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_core::CapabilityId;

use crate::production_operation_compiler::ProductionOperationCompilerV1;
use crate::public_api_session::{PublicApiPeer, PublicApiPeerRecheckV1};
use crate::public_mutation_compiler::{
    AuthorizedPublicMutationRequestV1, PublicMutationAuthorizationErrorV1,
    PublicMutationAuthorizationNativeV1,
};
use crate::{ControllerServiceError, Journal, OperationCompilationError, OperationPlan};

#[derive(Clone, Copy)]
enum First {
    Current,
    Handle,
    Authorization,
    Compilation,
    PeerPost,
    Reentry,
}

pub(crate) struct ExecutionPublicCompilerOriginalV2 {
    native: PublicMutationAuthorizationNativeV1,
    input: Vec<u8>,
    current: Option<Result<(), crate::JournalError>>,
    handle: Option<Result<CapabilityId, ControllerServiceError>>,
    authorization: Option<Result<AuthorizedPublicMutationRequestV1, PublicMutationAuthorizationErrorV1>>,
    plan: Option<Result<Arc<OperationPlan>, OperationCompilationError>>,
    peer_post: PublicApiPeerRecheckV1,
    peer_post_returned: Option<Result<(), crate::public_api_session::PublicApiSessionError>>,
    original_peer_cutoff: Option<u64>,
    entered: bool,
    first: Option<First>,
}

impl ExecutionPublicCompilerOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            native: PublicMutationAuthorizationNativeV1::new(),
            input: Vec::new(),
            current: None,
            handle: None,
            authorization: None,
            plan: None,
            peer_post: PublicApiPeerRecheckV1::new(),
            peer_post_returned: None,
            original_peer_cutoff: None,
            entered: false,
            first: None,
        }
    }

    pub(crate) fn prepare_once_v2(
        &mut self,
        controller: &mut Journal,
        compiler: &mut ProductionOperationCompilerV1,
        peer: &PublicApiPeer,
        capability: CapabilityId,
        handle: &[u8],
        encoded: &[u8],
        digest: [u8; 32],
    ) -> Result<Arc<OperationPlan>, OperationCompilationError> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(OperationCompilationError::Rejected);
        }
        self.entered = true;
        self.original_peer_cutoff = Some(peer.accepted_original_deadline_data_v1());
        self.current = Some(controller.require_execution_admission_current_v2());
        if !matches!(self.current, Some(Ok(()))) {
            self.first = Some(First::Current);
            return Err(OperationCompilationError::Rejected);
        }

        // The scope paid the real request/model peak before native C18 entry.
        self.input.extend_from_slice(encoded);
        self.handle = Some(crate::controller::resolve_delete_capability_handle_retaining_v1(
            controller, peer, capability, handle, &mut self.native.handle_peers,
        ));
        if !matches!(self.handle, Some(Ok(_))) {
            self.first = Some(First::Handle);
            return Err(OperationCompilationError::Rejected);
        }

        self.authorization = Some(compiler.authorize_original_execution_v2(
            controller, peer, capability, &self.input, &mut self.native,
        ));
        if !matches!(self.authorization, Some(Ok(_))) {
            self.first = Some(First::Authorization);
            return Err(OperationCompilationError::Rejected);
        }
        let Some(authorized) = self.authorization.as_ref().and_then(|result| result.as_ref().ok()) else {
            return Err(OperationCompilationError::Rejected);
        };

        self.plan = Some(compiler.compile_original_execution_v2(
            controller, authorized, &self.input, digest,
        ).map(Arc::new));
        if !matches!(self.plan, Some(Ok(_))) {
            self.first = Some(First::Compilation);
            return Err(OperationCompilationError::Rejected);
        }
        self.peer_post_returned = Some(peer.recheck_retaining_v1(&mut self.peer_post));
        if !matches!(self.peer_post_returned, Some(Ok(()))) {
            self.first = Some(First::PeerPost);
            return Err(OperationCompilationError::Rejected);
        }

        self.plan.as_ref().and_then(|result| result.as_ref().ok())
            .map(Arc::clone).ok_or(OperationCompilationError::Rejected)
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Current => self.current.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Handle => self.native.failure()
                .or_else(|| self.handle.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Authorization => self.native.failure()
                .or_else(|| self.authorization.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Compilation => self.plan.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::PeerPost => self.peer_post.failure()
                .or_else(|| self.peer_post_returned.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Reentry => Some(&super::ResourceReservationErrorV1::Conflict),
        }
    }

    pub(super) fn retains_plan_v2(&self, expected: &Arc<OperationPlan>) -> bool {
        self.first.is_none() && self.plan.as_ref().is_some_and(|result| {
            matches!(result, Ok(actual) if Arc::ptr_eq(actual, expected))
        })
    }

    pub(super) fn preaccept_target_v2(&self) -> Result<(
        aos_sandbox_core::SandboxId, [u8; 16], aos_sandbox_core::ProjectId,
    ), crate::JournalError> {
        let bad = || crate::JournalError::ProtectedBoundary;
        if self.first.is_some() {
            return Err(bad());
        }
        let authorized = self.authorization.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(bad)?;
        let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Exec(request) =
            authorized.request().request()
        else { return Err(bad()); };
        let mutation = request.mutation.as_option().ok_or_else(bad)?;
        Ok((aos_sandbox_core::SandboxId::from_bytes(request.sandbox_id.as_slice().try_into().map_err(|_| bad())?),
            mutation.expected_incarnation_id.as_slice().try_into().map_err(|_| bad())?,
            authorized.project()))
    }

    pub(super) fn matches_accepted_context_v2(
        &self,
        accepted: &aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1,
    ) -> bool {
        self.first.is_none() && accepted.canonical_request() == self.input
            && self.authorization.as_ref().and_then(|value| value.as_ref().ok())
                .is_some_and(|authorized| accepted.project() == authorized.project()
                    && accepted.caller() == authorized.caller())
    }

    pub(super) fn preaccept_horizon_checked_v2(&self)
        -> Result<(aos_sandbox_core::RawPairedClockSample, i64, u64, u64), crate::JournalError>
    {
        let bad = || crate::JournalError::ProtectedBoundary;
        if self.first.is_some() {
            return Err(bad());
        }
        let decision = self.native.decision.as_ref().ok_or_else(bad)?;
        let authorized = self.authorization.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(bad)?;
        let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Exec(request) =
            authorized.request().request()
        else { return Err(bad()); };
        let timeout = request.mutation.as_option().and_then(|mutation| mutation.operation_timeout.as_option())
            .ok_or_else(bad)?.nanoseconds;
        let clock = decision.clock();
        let expires = decision.capability().claims().expires_at.min(decision.policy().expires_at());
        let cutoff = self.original_peer_cutoff.ok_or_else(bad)?;
        if timeout == 0 || cutoff <= clock.boottime_nanoseconds() || expires <= clock.wall_seconds() {
            return Err(bad());
        }
        Ok((clock, expires, cutoff, timeout))
    }
}
