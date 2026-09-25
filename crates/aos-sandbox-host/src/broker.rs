//! Durable ordering and replay for fixed host runtime effects.

mod agent_launch;
mod consumer_cgroup;
mod existing_output;
mod guardian_transaction;
mod mount_scope;
mod payload_scope;
mod runtime_pins;

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Instant;

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, BrokerMethod, InventoryRuntimeResponse, QueryRuntimeEffectResponse,
    RuntimeAction, RuntimeEffectStatus, RuntimeObservation, RuntimeState,
};
use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox::controller_execution_preissue::ControllerExecutionReserveSourceV1;
use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, VerifiedHostOutputReserveSourceV1,
    verify_host_output_reserve_source_v1,
};
use aos_sandbox_broker::{
    BrokerAuthorizationFenceV1, BrokerEffectIntentV1, BrokerEffectStatusV1,
    ProtectedBrokerPublicCredentialRole,
};
use aos_sandbox_core::{
    BrokerAdmissionIntersection, BrokerAssignment, ObjectDigest, ProtocolVersion,
    RawClockProvenance, RawPairedClockSample, VerifiedOwnershipLease,
};
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredential;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_protocol::host_execution_argument::receipt::{
    HostExecutionArgumentFreshReceiptV1, HostExecutionArgumentHistoricalReceiptV1,
    MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1,
};
use aos_sandbox_protocol::host_execution_argument::{
    ValidatedHostExecutionArgumentRequestV1, decode_host_execution_argument_observe_request_v1,
    decode_host_execution_argument_query_request_v1,
};
use aos_sandbox_protocol::host_output::{
    ValidatedHostOutputQueryRequestV1, ValidatedHostOutputReserveRequestV1,
    decode_host_output_query_request_v1, decode_host_output_reserve_request_v1,
};
use aos_sandbox_protocol::semantics::{
    CanonicalHostAttachGateSemanticsV1, CanonicalHostExecutionArgumentSemanticsV1,
    CanonicalHostExecutionSemanticsV1, CanonicalHostOutputSemanticsV1,
    canonical_host_attach_gate_semantics_v1, canonical_host_attach_readiness_semantics_v1,
    canonical_host_attach_route_query_semantics_v1, canonical_host_execution_apply_semantics_v1,
    canonical_host_execution_query_semantics_v1, host_execution_argument_observe_grant_v1,
    host_execution_argument_query_grant_v1, host_output_query_grant_v1,
    host_output_reserve_grant_v1,
};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    HistoricalRuntimeRequestCandidateV1, PeerCredentials, PeerPolicy, ValidatedAssignmentFence,
    ValidatedHostAttachGateRequestV1, ValidatedHostAttachReadinessRequestV1,
    ValidatedHostAttachRouteQueryV1, ValidatedHostExecutionApplyV1, ValidatedHostExecutionQueryV1,
    ValidatedQueryRuntimeEffectRequestV1, ValidatedRuntimeRequest,
    classify_historical_runtime_request_v1, decode_grandfathered_runtime_request_replay_v1,
    decode_host_attach_gate_request_v1, decode_host_attach_readiness_request_v1,
    decode_host_attach_route_query_v1, decode_host_execution_apply_v1,
    decode_host_execution_query_v1, decode_runtime_request,
};
use aos_systemd::{
    GuardianCredentialDescriptors, GuardianCredentialRole, GuardianUnitSpec,
    SandboxUnitDiscoverySnapshot,
};
use buffa::Message as _;
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use crate::attach_route::HostOpenSshAttachRouteOwnerV1;
use crate::authorization::HostAuthorityV1;
use crate::authorization::semantics_v1::runtime_handle_v1;
use crate::live_agent::argument_attempt::{
    HostArgumentAttemptErrorV1, HostArgumentAttemptJournalV1, HostArgumentHistoricalVerifierV1,
    OriginalHostArgumentIntentV1,
};
use crate::live_agent::{HostAgentLiveErrorV1, HostAgentLiveSessionV1, HostAgentPendingSessionV1};
use crate::plan::{
    GuardianConfig, HostCatalog, NspawnConfig, PreparedLaunch, ResolvedLaunchResources,
};
use crate::recovery::{HostRuntimeRecoveryReport, reconcile};
use crate::state::transition::{
    AuthorityFreshness, DurableExecution, ExecutionContext, HostExecutionHandoffRecord,
    PresentUnitState, UnitObservation, protected_input_snapshots,
};
use crate::state::{
    Admission, CompletedGuardianLineage, GuardianLineage, HostAction, HostState, HostStateStore,
    RuntimeEffectQuery,
};
use crate::worker::{
    CompletedRuntimeProof, GuardianObservation, GuardianObservedState, HostRuntimeIdentity,
    HostWorker, ObservedRuntimeState, PinnedLeader, PinnedPayloadLeader, WorkerObservation,
    WorkerOperation,
};
use crate::{HostError, Result};

const MAXIMUM_INVENTORY_RUNTIMES: usize = 1_024;
const MAXIMUM_SCOPE_HANDLE_ATTEMPTS: usize = 16;
#[cfg(test)]
pub(crate) struct RuntimeEffectQueryContext<'a> {
    pub(crate) original_request_bytes: &'a [u8],
    pub(crate) request_id: [u8; 16],
    pub(crate) peer: PeerCredentials,
    pub(crate) policy: PeerPolicy,
    pub(crate) current_clock: RawPairedClockSample,
    pub(crate) maximum_response_bytes: u32,
}

/// Applies validated runtime requests through durable fixed-function effects.
pub struct HostBroker<C, S, W> {
    catalog: C,
    store: S,
    worker: W,
    authority: HostAuthorityV1,
    nspawn: Option<NspawnConfig>,
    guardian: Option<GuardianConfig>,
    protected_agent_launch: bool,
    live_agent: Option<HostAgentLiveSessionV1>,
    state: HostState,
    state_healthy: bool,
    observed_leaders: BTreeMap<HostRuntimeIdentity, PinnedLeader>,
    pub(crate) runtime_pins: BTreeMap<HostRuntimeIdentity, RetainedRuntimePins>,
    #[cfg(test)]
    fail_runtime_retention: bool,
}

/// Proves a Host execution grant was durably reserved in the shared lease fence.
///
/// This token is minted only after signed-plan, lease, current assignment, and
/// exact request semantics have passed the existing Host authority admission.
pub struct HostExecutionGrantReservationV1 {
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    assignment: BrokerAssignment,
    runtime_handle: ObjectDigest,
    request: HostExecutionGrantRequestV1,
    effect: BrokerEffectIntentV1,
    verified_lease: VerifiedOwnershipLease,
    intersection: BrokerAdmissionIntersection,
    verified_output_source: Option<VerifiedHostOutputReserveSourceV1>,
}

/// Retains only authenticated read-only ATTACH query authority and selectors.
pub struct HostAttachReadOnlyProofV1 {
    request: HostAttachReadOnlyRequestV1,
    verified_lease: VerifiedOwnershipLease,
    assignment: BrokerAssignment,
    runtime_handle: ObjectDigest,
}

/// Names the two distinct read-only attach operations.
pub enum HostAttachReadOnlyRequestV1 {
    /// Advisory signed-session and lease readiness.
    Readiness(ValidatedHostAttachReadinessRequestV1),
    /// Fresh readback of one accepted route.
    Route(ValidatedHostAttachRouteQueryV1),
}

impl HostAttachReadOnlyProofV1 {
    /// Returns the exact validated request and selectors.
    #[must_use]
    pub const fn request(&self) -> &HostAttachReadOnlyRequestV1 {
        &self.request
    }

    /// Returns the signature-verified current ownership lease.
    #[must_use]
    pub const fn verified_lease(&self) -> &VerifiedOwnershipLease {
        &self.verified_lease
    }

    /// Checks the protected runtime assignment at the observation boundary.
    #[must_use]
    pub fn matches_claim(&self, claim: &DormantRuntimeExecutionClaimV1<'_>) -> bool {
        execution_assignment(claim).is_ok_and(|assignment| assignment == self.assignment)
            && claim.currentness().runtime().handle() == self.runtime_handle
            && claim.revalidate().is_ok()
    }
}

#[derive(Clone, Copy)]
enum HostExactGrantSemanticsV1 {
    Execution(CanonicalHostExecutionSemanticsV1),
    AttachGate(CanonicalHostAttachGateSemanticsV1),
    Output(CanonicalHostOutputSemanticsV1),
    Argument(CanonicalHostExecutionArgumentSemanticsV1),
}

impl HostExactGrantSemanticsV1 {
    fn commitment(&self) -> aos_sandbox_core::BrokerArgumentCommitment {
        match self {
            Self::Execution(semantics) => semantics.commitment(),
            Self::AttachGate(semantics) => semantics.commitment(),
            Self::Output(semantics) => semantics.commitment(),
            Self::Argument(semantics) => semantics.commitment(),
        }
    }
}

/// Retains the exact decoded request associated with a verified Host grant.
pub enum HostExecutionGrantRequestV1 {
    /// Applies one closed guest execution action.
    Apply(ValidatedHostExecutionApplyV1),
    /// Reads one exact protected execution outcome.
    Query(ValidatedHostExecutionQueryV1),
    /// Installs one exact signed pending OpenSSH gate and reads it back.
    AttachGate(ValidatedHostAttachGateRequestV1),
    /// Reserves one exact Controller-signed provisional output claim.
    ReserveOutput(ValidatedHostOutputReserveRequestV1),
    /// Reads one prior original provisional output attempt without reserving.
    QueryOutput(ValidatedHostOutputQueryRequestV1),
    /// Issues one original retained Guest runtime argument observation.
    ObserveArgument(ValidatedHostExecutionArgumentRequestV1),
    /// Reads historical custody for an original argument observation.
    QueryArgument(ValidatedHostExecutionArgumentRequestV1),
}

impl HostExecutionGrantReservationV1 {
    /// Checks the exact method, request, and protected runtime claimed at use.
    #[must_use]
    pub fn matches(
        &self,
        method: BrokerMethod,
        request_id: [u8; 16],
        body: &[u8],
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> bool {
        matches!(
            (&self.request, method),
            (
                HostExecutionGrantRequestV1::Apply(_),
                BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION
            ) | (
                HostExecutionGrantRequestV1::Query(_),
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            ) | (
                HostExecutionGrantRequestV1::AttachGate(_),
                BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE
            ) | (
                HostExecutionGrantRequestV1::ReserveOutput(_),
                BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT
            ) | (
                HostExecutionGrantRequestV1::QueryOutput(_),
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT
            ) | (
                HostExecutionGrantRequestV1::ObserveArgument(_),
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
            ) | (
                HostExecutionGrantRequestV1::QueryArgument(_),
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT
            )
        ) && self.request_id == request_id
            && self.request_body_digest.as_bytes() == Sha256::digest(body).as_slice()
            && execution_assignment(claim).is_ok_and(|assignment| assignment == self.assignment)
            && self.runtime_handle == claim.currentness().runtime().handle()
            && self.effect.request_id() == &request_id
    }

    /// Borrows the exact validated request bound by the signed grant.
    #[must_use]
    pub const fn request(&self) -> &HostExecutionGrantRequestV1 {
        &self.request
    }

    /// Returns the freshly verified ownership lease retained by admission.
    #[must_use]
    pub const fn verified_lease(&self) -> &VerifiedOwnershipLease {
        &self.verified_lease
    }

    /// Borrows the matched Controller source only after durable Host admission.
    #[must_use]
    pub const fn verified_output_source(&self) -> Option<&VerifiedHostOutputReserveSourceV1> {
        self.verified_output_source.as_ref()
    }

    /// Sends the original argument challenge under this matched, durable grant.
    ///
    /// The reservation retains the pinned plan and semantic digests; neither
    /// can be supplied as a scalar by the broker-session caller. A replayed
    /// method-37 request is rejected before this method can be reached.
    ///
    /// # Errors
    ///
    /// Rejects a non-observe grant, stale Host claim/lease clock, missing
    /// output correlation, repeated one-shot attempt, or invalid Guest proof.
    pub fn observe_argument_once(
        &self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        agent: &mut HostAgentLiveSessionV1,
        deadline: Instant,
    ) -> std::result::Result<HostExecutionArgumentFreshReceiptV1, HostArgumentAttemptErrorV1> {
        let HostExecutionGrantRequestV1::ObserveArgument(request) = &self.request else {
            return Err(HostArgumentAttemptErrorV1::Binding);
        };
        if self.intersection.verb() != aos_sandbox_core::BrokerVerb::HostObserveExecutionArgument
            || self.intersection.request_id() != &self.request_id
            || self.effect.request_id() != &self.request_id
            || self.intersection.host_boot_id() != &claim.host_verifier().boot_id()
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(request.canonical_attempt())
                .map_err(|_| HostArgumentAttemptErrorV1::Binding)?;
        if source.request_id() != self.request_id
            || source.assignment_digest() != self.assignment.digest()
            || source.host_boot_id() != *self.intersection.host_boot_id()
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;
        agent.observe_execution_argument_once(
            claim,
            &source,
            self.intersection.plan_digest(),
            self.intersection.request_digest(),
            || {
                let sample = crate::service::trusted_paired_clock_sample()
                    .map_err(|_| HostArgumentAttemptErrorV1::Binding)?;
                if sample.host_boot_id() != *self.intersection.host_boot_id()
                    || sample.boottime_nanoseconds()
                        >= self.intersection.fail_stop_boottime_nanoseconds()
                    || sample.wall_seconds() >= self.intersection.plan_expires_seconds()
                    || sample.wall_seconds() >= self.intersection.authority_expires_seconds()
                {
                    return Err(HostArgumentAttemptErrorV1::Binding);
                }
                Ok(sample)
            },
            deadline,
        )
    }

    /// Reads the original argument attempt as historical, digest-only custody.
    ///
    /// # Errors
    ///
    /// Rejects a non-query grant, stale Host claim/output, foreign original
    /// source, or unavailable protected attempt journal.
    pub(crate) fn query_argument_historical(
        &self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        original_intent: &OriginalHostArgumentIntentV1,
    ) -> std::result::Result<HostExecutionArgumentHistoricalReceiptV1, HostArgumentAttemptErrorV1>
    {
        let HostExecutionGrantRequestV1::QueryArgument(request) = &self.request else {
            return Err(HostArgumentAttemptErrorV1::Binding);
        };
        if self.intersection.verb() != aos_sandbox_core::BrokerVerb::HostQueryExecutionArgument
            || self.intersection.request_id() != &self.request_id
            || self.effect.request_id() != &self.request_id
            || self.intersection.host_boot_id() != &claim.host_verifier().boot_id()
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        let source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(request.canonical_attempt())
                .map_err(|_| HostArgumentAttemptErrorV1::Binding)?;
        if source.assignment_digest() != self.assignment.digest()
            || source.host_boot_id() != *self.intersection.host_boot_id()
        {
            return Err(HostArgumentAttemptErrorV1::Binding);
        }
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;
        claim
            .host_output_for_argument_v1(&source)
            .map_err(HostAgentLiveErrorV1::from)?;
        let verifier = HostArgumentHistoricalVerifierV1::from_claim(claim)?;
        let historical = HostArgumentAttemptJournalV1::open_for_historical_query()?
            .query_historical(&source, &verifier, original_intent)?;
        claim.revalidate().map_err(HostAgentLiveErrorV1::from)?;
        Ok(historical)
    }
}

pub(crate) struct RetainedRuntimePins {
    pub(crate) invocation_id: [u8; 16],
    pub(crate) supervisor: PinnedLeader,
    pub(crate) payload: PinnedPayloadLeader,
    pub(crate) scope_handle: [u8; 32],
}

/// Carries response metadata validated before a Host Apply effect can run.
pub(crate) struct ValidatedRuntimeApplyResponse {
    request_id: [u8; 16],
    maximum_response_bytes: u32,
    body: Vec<u8>,
}

impl ValidatedRuntimeApplyResponse {
    /// Returns the request ID from the fully validated Apply header.
    pub(crate) const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Returns the fully validated Apply response ceiling.
    pub(crate) const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Consumes the response and returns its encoded observation or receipt.
    pub(crate) fn into_body(self) -> Vec<u8> {
        self.body
    }
}

impl RetainedRuntimePins {
    pub(crate) fn recheck_kernel(&self) -> Result<()> {
        self.payload.recheck_kernel(&self.supervisor)
    }
}

impl<C, S, W> HostBroker<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker,
{
    /// Loads durable state and constructs a broker with no inherited handles.
    ///
    /// # Errors
    ///
    /// Returns an error when the state snapshot is unavailable or invalid.
    pub fn open(
        catalog: C,
        store: S,
        worker: W,
        nspawn: Option<NspawnConfig>,
        authority: HostAuthorityV1,
    ) -> Result<Self> {
        let state = store.load()?;
        state.validate_authenticated(&authority)?;
        Ok(Self {
            catalog,
            store,
            worker,
            authority,
            nspawn,
            guardian: None,
            protected_agent_launch: false,
            live_agent: None,
            state,
            state_healthy: true,
            observed_leaders: BTreeMap::new(),
            runtime_pins: BTreeMap::new(),
            #[cfg(test)]
            fail_runtime_retention: false,
        })
    }

    /// Installs the fixed production Guardian executable profile.
    #[must_use]
    pub fn with_guardian(mut self, guardian: GuardianConfig) -> Self {
        self.guardian = Some(guardian);
        self
    }

    /// Requires protected guest-agent custody before any new nspawn start.
    ///
    /// This does not supply backend readiness or enable Launch by itself. A
    /// missing protected runtime claim, signing seed, or attach trust rejects
    /// the request before the durable launch intent is committed.
    #[must_use]
    pub fn with_protected_agent_launch(mut self) -> Self {
        self.protected_agent_launch = true;
        self
    }

    pub(crate) fn take_authenticated_agent_launch(&mut self) -> Option<HostAgentLiveSessionV1> {
        self.live_agent.take()
    }

    /// Reports whether the closed Guardian-first launch backend is available.
    #[must_use]
    pub fn launch_available(&self) -> bool {
        closed_launch_backend_available(self.nspawn.is_some(), self.guardian.is_some())
            && self
                .nspawn
                .as_ref()
                .is_some_and(|nspawn| nspawn.revalidate().is_ok())
            && matches!(
                self.authority.revalidated_guardian_credentials(),
                Ok(Some(_))
            )
            && self
                .guardian
                .as_ref()
                .is_some_and(|guardian| guardian.revalidate().is_ok())
    }

    /// Verifies one read-only attach query without advancing the Host fence.
    ///
    /// The returned lease proof is useful only while the protected runtime,
    /// guest session, and broker request remain current. No route is installed
    /// and no guest packet is sent here.
    ///
    /// # Errors
    ///
    /// Rejects malformed selectors, wrong verb, stale Host runtime/boot,
    /// invalid signed plan or lease, or a missing protected base fence.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_host_attach_query<F>(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
        mut trusted_clock: F,
    ) -> Result<HostAttachReadOnlyProofV1>
    where
        F: FnMut() -> Result<RawPairedClockSample>,
    {
        self.ensure_healthy()?;
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime claim is stale"))?;
        let admission_clock = trusted_clock()?;
        if admission_clock.host_boot_id() != protected_boot_id
            || claim.host_verifier().boot_id() != protected_boot_id
        {
            return Err(HostError::Fence("Host attach query boot changed"));
        }
        let assignment = execution_assignment(claim)?;
        let (header, semantics, request) = match method {
            BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS => {
                let request = decode_host_attach_readiness_request_v1(
                    request_body,
                    peer,
                    policy,
                    admission_clock.boottime_nanoseconds(),
                )?;
                (
                    *request.header(),
                    canonical_host_attach_readiness_semantics_v1(assignment),
                    HostAttachReadOnlyRequestV1::Readiness(request),
                )
            }
            BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE => {
                let request = decode_host_attach_route_query_v1(
                    request_body,
                    peer,
                    policy,
                    admission_clock.boottime_nanoseconds(),
                )?;
                let semantics = canonical_host_attach_route_query_semantics_v1(
                    assignment,
                    request.operation_id(),
                    request.execution_id(),
                )
                .map_err(|_| HostError::Fence("Host attach route query is invalid"))?;
                (
                    *request.header(),
                    semantics,
                    HostAttachReadOnlyRequestV1::Route(request),
                )
            }
            _ => return Err(HostError::Fence("Host attach query method is invalid")),
        };
        if header.request_id() != &request_id {
            return Err(HostError::Fence(
                "Host attach query request identity differs",
            ));
        }
        let prior_fence = self
            .state
            .prior_authorization(assignment.sandbox().as_bytes())
            .ok_or(HostError::Fence("Host attach query base fence is absent"))?;
        let admitted = self.authority.admit_attach_query(
            artifacts,
            assignment,
            request_id,
            request_body,
            semantics,
            header.deadline_boottime_nanoseconds(),
            &admission_clock,
            prior_fence,
        )?;
        self.authority
            .check_before_effect(&admitted.effect, &mut || {
                trusted_clock().map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
            })?;
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime changed after query admission"))?;
        Ok(HostAttachReadOnlyProofV1 {
            request,
            verified_lease: admitted.verified_lease,
            assignment,
            runtime_handle: claim.currentness().runtime().handle(),
        })
    }

    /// Reserves one signed Host execution grant in the shared Host lease fence.
    ///
    /// # Errors
    ///
    /// Rejects a stale protected runtime, malformed request, invalid signer or
    /// lease, conflicting idempotency, or ambiguous durable Host state.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_host_execution<F>(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        method: BrokerMethod,
        request_body: &[u8],
        execution_spec_content: Option<&[u8]>,
        request_id: [u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
        mut trusted_clock: F,
    ) -> Result<HostExecutionGrantReservationV1>
    where
        F: FnMut() -> Result<RawPairedClockSample>,
    {
        if !self.state_healthy {
            let recovered = self.store.load()?;
            recovered.validate_authenticated(&self.authority)?;
            self.state = recovered;
            self.state_healthy = true;
        }
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime claim is stale"))?;
        let admission_clock = trusted_clock()?;
        if admission_clock.host_boot_id() != protected_boot_id
            || claim.host_verifier().boot_id() != protected_boot_id
        {
            return Err(HostError::Fence("Host execution boot changed"));
        }
        let assignment = execution_assignment(claim)?;
        let (header, operation_id, execution_id, source_commitment, semantics, action, request) =
            match method {
                BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => {
                    let mut request = decode_host_execution_apply_v1(
                        request_body,
                        peer,
                        policy,
                        admission_clock.boottime_nanoseconds(),
                    )?;
                    let content = execution_spec_content
                        .ok_or(HostError::Fence("Host execution content is absent"))?;
                    request.verify_content(content)?;
                    let semantics = canonical_host_execution_apply_semantics_v1(
                        &request, assignment,
                    )
                    .map_err(|_| HostError::Fence("Host execution semantics are invalid"))?;
                    (
                        *request.header(),
                        request.operation_id(),
                        request.execution_id(),
                        request.source_commitment(),
                        HostExactGrantSemanticsV1::Execution(semantics),
                        HostAction::ApplyExecution,
                        HostExecutionGrantRequestV1::Apply(request),
                    )
                }
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION => {
                    if execution_spec_content.is_some() {
                        return Err(HostError::Fence("Host execution query content is invalid"));
                    }
                    let request = decode_host_execution_query_v1(
                        request_body,
                        peer,
                        policy,
                        admission_clock.boottime_nanoseconds(),
                    )?;
                    let semantics = canonical_host_execution_query_semantics_v1(
                        &request, assignment,
                    )
                    .map_err(|_| HostError::Fence("Host execution semantics are invalid"))?;
                    (
                        *request.header(),
                        request.operation_id(),
                        request.execution_id(),
                        request.source_commitment(),
                        HostExactGrantSemanticsV1::Execution(semantics),
                        HostAction::QueryExecution,
                        HostExecutionGrantRequestV1::Query(request),
                    )
                }
                BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE => {
                    let request = decode_host_attach_gate_request_v1(
                        request_body,
                        peer,
                        policy,
                        admission_clock.boottime_nanoseconds(),
                    )?;
                    let grant = HostOpenSshAttachRouteOwnerV1::verify_pending_grant(
                        request.pending_grant(),
                    )
                    .map_err(|_| HostError::Fence("Host attach pending grant is invalid"))?;
                    let semantics = canonical_host_attach_gate_semantics_v1(
                        assignment,
                        request.pending_grant(),
                    )
                    .map_err(|_| HostError::Fence("Host attach semantics are invalid"))?;
                    (
                        *request.header(),
                        grant.operation_id,
                        aos_sandbox_core::ExecutionId::from_bytes(grant.execution_id),
                        ObjectDigest::from_bytes(grant.pending_digest),
                        HostExactGrantSemanticsV1::AttachGate(semantics),
                        HostAction::InstallAttachGate,
                        HostExecutionGrantRequestV1::AttachGate(request),
                    )
                }
                BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => {
                    if execution_spec_content.is_some() {
                        return Err(HostError::Fence(
                            "Host output content descriptor is invalid",
                        ));
                    }
                    let request = decode_host_output_reserve_request_v1(
                        request_body,
                        peer,
                        policy,
                        admission_clock.boottime_nanoseconds(),
                    )?;
                    let source =
                        ControllerExecutionReserveSourceV1::decode_structural(request.source())
                            .map_err(|_| HostError::Fence("Host output source is invalid"))?;
                    let semantics =
                        host_output_reserve_grant_v1(assignment, request_id, request.source())
                            .map_err(|_| HostError::Fence("Host output semantics are invalid"))?;
                    (
                        *request.header(),
                        *source.preissue().create_operation().as_bytes(),
                        source.preissue().execution(),
                        source.carrier_digest(),
                        HostExactGrantSemanticsV1::Output(semantics),
                        HostAction::ReserveExecutionOutput,
                        HostExecutionGrantRequestV1::ReserveOutput(request),
                    )
                }
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT => {
                    if execution_spec_content.is_some() {
                        return Err(HostError::Fence("Host output query content is invalid"));
                    }
                    let request = decode_host_output_query_request_v1(
                        request_body,
                        peer,
                        policy,
                        admission_clock.boottime_nanoseconds(),
                    )?;
                    let locator = request.locator();
                    if locator.assignment_digest() != assignment.digest()
                        || locator.host_boot_id() != protected_boot_id
                    {
                        return Err(HostError::Fence("Host output query locator is stale"));
                    }
                    let semantics =
                        host_output_query_grant_v1(assignment, request_id, request_body)
                            .map_err(|_| HostError::Fence("Host output semantics are invalid"))?;
                    (
                        *request.header(),
                        *locator.create_operation().as_bytes(),
                        locator.execution(),
                        locator.carrier_digest(),
                        HostExactGrantSemanticsV1::Output(semantics),
                        HostAction::QueryExecutionOutput,
                        HostExecutionGrantRequestV1::QueryOutput(request),
                    )
                }
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
                    if execution_spec_content.is_some() {
                        return Err(HostError::Fence("Host argument descriptor is invalid"));
                    }
                    let request = decode_host_execution_argument_observe_request_v1(
                        request_body,
                        peer,
                        policy,
                        admission_clock.boottime_nanoseconds(),
                    )?;
                    // Reserve enough response budget for every canonical
                    // signed Guest packet before the one-shot send can occur.
                    if request.header().maximum_response_bytes()
                        < (MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1 + 4) as u32
                    {
                        return Err(HostError::Fence(
                            "Host argument response budget is too small",
                        ));
                    }
                    let source = ControllerExecutionArgumentAttemptV1::decode_canonical(
                        request.canonical_attempt(),
                    )
                    .map_err(|_| HostError::Fence("Host argument source is invalid"))?;
                    claim.host_output_for_argument_v1(&source).map_err(|_| {
                        HostError::Fence("Host argument output correlation is not current")
                    })?;
                    if source.host_boot_id() != protected_boot_id
                        || admission_clock.boottime_nanoseconds()
                            >= source.deadline_boottime_nanoseconds()
                    {
                        return Err(HostError::Fence("Host argument source is stale"));
                    }
                    let semantics = host_execution_argument_observe_grant_v1(
                        assignment,
                        request_id,
                        request.canonical_attempt(),
                    )
                    .map_err(|_| HostError::Fence("Host argument semantics are invalid"))?;
                    (
                        *request.header(),
                        *source.create_operation().as_bytes(),
                        source.execution(),
                        source.record_digest(),
                        HostExactGrantSemanticsV1::Argument(semantics),
                        HostAction::ObserveExecutionArgument,
                        HostExecutionGrantRequestV1::ObserveArgument(request),
                    )
                }
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT => {
                    if execution_spec_content.is_some() {
                        return Err(HostError::Fence(
                            "Host argument query descriptor is invalid",
                        ));
                    }
                    let request = decode_host_execution_argument_query_request_v1(
                        request_body,
                        peer,
                        policy,
                        admission_clock.boottime_nanoseconds(),
                    )?;
                    let source = ControllerExecutionArgumentAttemptV1::decode_canonical(
                        request.canonical_attempt(),
                    )
                    .map_err(|_| HostError::Fence("Host argument source is invalid"))?;
                    claim.host_output_for_argument_v1(&source).map_err(|_| {
                        HostError::Fence("Host argument output correlation is not current")
                    })?;
                    if source.host_boot_id() != protected_boot_id {
                        return Err(HostError::Fence("Host argument source boot is stale"));
                    }
                    let semantics = host_execution_argument_query_grant_v1(
                        assignment,
                        request_id,
                        request.canonical_attempt(),
                    )
                    .map_err(|_| HostError::Fence("Host argument query semantics are invalid"))?;
                    (
                        *request.header(),
                        *source.create_operation().as_bytes(),
                        source.execution(),
                        source.record_digest(),
                        HostExactGrantSemanticsV1::Argument(semantics),
                        HostAction::QueryExecutionArgument,
                        HostExecutionGrantRequestV1::QueryArgument(request),
                    )
                }
                _ => return Err(HostError::Fence("Host execution method is invalid")),
            };
        if header.request_id() != &request_id {
            return Err(HostError::Fence("Host execution request identity differs"));
        }
        let runtime_witness_request_id = self
            .state
            .runtime_witness_request_id(assignment.sandbox().as_bytes())
            .ok_or(HostError::Fence("Host runtime witness is absent"))?;
        if action == HostAction::ObserveExecutionArgument
            && self.state.effect(&request_id).is_some()
        {
            return Err(HostError::Fence(
                "Host argument original request must use historical query after replay",
            ));
        }
        if self.state.effect(&request_id).is_some()
            && !self
                .state
                .execution_handoff_is_current(assignment.sandbox().as_bytes(), &request_id)
        {
            return Err(HostError::Fence("Host execution replay was superseded"));
        }
        let prior_fence = self
            .state
            .effect(&request_id)
            .map_or_else(
                || {
                    self.state
                        .prior_authorization(assignment.sandbox().as_bytes())
                },
                |_| self.state.request_base_authorization(&request_id),
            )
            .ok_or(HostError::Fence("Host execution base fence is absent"))?;
        let admitted = match semantics {
            HostExactGrantSemanticsV1::Execution(semantics) => self.authority.admit_execution(
                artifacts,
                assignment,
                request_id,
                request_body,
                semantics,
                header.deadline_boottime_nanoseconds(),
                &admission_clock,
                prior_fence,
            )?,
            HostExactGrantSemanticsV1::AttachGate(semantics) => self.authority.admit_attach_gate(
                artifacts,
                assignment,
                request_id,
                request_body,
                semantics,
                header.deadline_boottime_nanoseconds(),
                &admission_clock,
                prior_fence,
            )?,
            HostExactGrantSemanticsV1::Output(semantics) => self.authority.admit_output(
                artifacts,
                assignment,
                request_id,
                request_body,
                semantics,
                header.deadline_boottime_nanoseconds(),
                &admission_clock,
                prior_fence,
            )?,
            HostExactGrantSemanticsV1::Argument(semantics) => self.authority.admit_argument(
                artifacts,
                assignment,
                request_id,
                request_body,
                semantics,
                header.deadline_boottime_nanoseconds(),
                &admission_clock,
                prior_fence,
            )?,
        };
        let verified_output_source = match &request {
            HostExecutionGrantRequestV1::ReserveOutput(reserve) => {
                let source =
                    ControllerExecutionReserveSourceV1::decode_structural(reserve.source())
                        .map_err(|_| HostError::Fence("Host output source changed"))?;
                Some(
                    verify_host_output_reserve_source_v1(
                        source,
                        assignment,
                        claim.currentness().runtime().currentness().node(),
                        &admitted.intersection,
                        admission_clock,
                    )
                    .map_err(|_| HostError::Fence("Host output source authority is invalid"))?,
                )
            }
            _ => None,
        };
        let sealed_base_fence = self.authority.advance_base_execution_fence(
            assignment.sandbox().as_bytes(),
            prior_fence,
            &admitted,
        )?;
        let sealed_fence = self
            .authority
            .seal_fence(assignment.sandbox().as_bytes(), &admitted.fence)?;
        let sealed_effect = self.authority.seal_effect(&request_id, &admitted.effect)?;
        let request_body_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
        let handoff = HostExecutionHandoffRecord {
            runtime_witness_request_id,
            runtime_handle: *claim.currentness().runtime().handle().as_bytes(),
            operation_id,
            execution_id: *execution_id.as_bytes(),
            source_commitment: *source_commitment.as_bytes(),
            semantic_commitment: *semantics.commitment().digest().as_bytes(),
        };
        let mut proposed = self.state.clone();
        let admission = proposed.admit_execution_handoff(
            assignment,
            request_id,
            *request_body_digest.as_bytes(),
            action,
            handoff,
            sealed_fence,
            sealed_base_fence,
            &admitted,
            sealed_effect,
            &self.authority,
        )?;
        if action == HostAction::InstallAttachGate
            && matches!(admission, crate::state::Admission::Complete(_))
        {
            return Err(HostError::Fence(
                "Host attach gate request is already terminal",
            ));
        }
        if proposed != self.state {
            self.commit_state(&proposed)?;
        }
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime changed after grant commit"))?;
        self.authority
            .check_before_effect(&admitted.effect, &mut || {
                trusted_clock().map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
            })?;
        let verified_output_source = if verified_output_source.is_some() {
            let effect_clock = trusted_clock()?;
            let HostExecutionGrantRequestV1::ReserveOutput(reserve) = &request else {
                return Err(HostError::Fence("Host output source request changed"));
            };
            let source = ControllerExecutionReserveSourceV1::decode_structural(reserve.source())
                .map_err(|_| HostError::Fence("Host output source changed"))?;
            Some(
                verify_host_output_reserve_source_v1(
                    source,
                    assignment,
                    claim.currentness().runtime().currentness().node(),
                    &admitted.intersection,
                    effect_clock,
                )
                .map_err(|_| HostError::Fence("Host output source expired before effect"))?,
            )
        } else {
            None
        };

        Ok(HostExecutionGrantReservationV1 {
            request_id,
            request_body_digest,
            assignment,
            runtime_handle: claim.currentness().runtime().handle(),
            request,
            effect: admitted.effect,
            verified_lease: admitted.verified_lease,
            intersection: admitted.intersection,
            verified_output_source,
        })
    }

    /// Reads Query38 only after rejoining its source to the sealed method-37 intent.
    ///
    /// # Errors
    ///
    /// Rejects missing or replaced Host state, a foreign original source, and
    /// lost or conflicting one-shot Guest custody. None proves a fresh send.
    pub(crate) fn query_host_execution_argument_historical(
        &self,
        reservation: &HostExecutionGrantReservationV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> std::result::Result<HostExecutionArgumentHistoricalReceiptV1, HostArgumentAttemptErrorV1>
    {
        let HostExecutionGrantRequestV1::QueryArgument(request) = &reservation.request else {
            return Err(HostArgumentAttemptErrorV1::Binding);
        };
        let source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(request.canonical_attempt())
                .map_err(|_| HostArgumentAttemptErrorV1::Binding)?;

        self.ensure_healthy()
            .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?;
        let durable = self
            .store
            .load()
            .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?;
        durable
            .validate_authenticated(&self.authority)
            .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?;
        if durable != self.state {
            return Err(HostArgumentAttemptErrorV1::OutcomeUnknown);
        }

        let original = durable
            .effect(&source.request_id())
            .ok_or(HostArgumentAttemptErrorV1::OutcomeUnknown)?;
        let original = self
            .authority
            .open_effect(&source.request_id(), original)
            .map_err(|_| HostArgumentAttemptErrorV1::OutcomeUnknown)?;
        let original_intent =
            OriginalHostArgumentIntentV1::from_effect(&source, reservation.assignment, &original)?;
        reservation.query_argument_historical(claim, &original_intent)
    }

    /// Closes the shared Host reservation after exact runtime-journal readback.
    ///
    /// # Errors
    ///
    /// Rejects a stale claim, substituted outcome, replaced fence, or an
    /// ambiguous durable Host state commit.
    pub fn complete_host_execution_reservation(
        &mut self,
        reservation: &HostExecutionGrantReservationV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        outcome: &[u8],
    ) -> Result<()> {
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime claim is stale"))?;
        if outcome.is_empty()
            || !self.state.execution_handoff_is_current(
                reservation.assignment.sandbox().as_bytes(),
                &reservation.request_id,
            )
            || !execution_assignment(claim)
                .is_ok_and(|assignment| assignment == reservation.assignment)
            || claim.currentness().runtime().handle() != reservation.runtime_handle
        {
            return Err(HostError::Fence("Host execution reservation is stale"));
        }
        let existing = self
            .state
            .effect(&reservation.request_id)
            .ok_or(HostError::Fence("Host execution reservation is absent"))?;
        let existing = self
            .authority
            .open_effect(&reservation.request_id, existing)?;
        if existing.transport_request_digest() != reservation.request_body_digest
            || existing.request_digest() != reservation.effect.request_digest()
            || existing.request_digest() != reservation.intersection.request_digest()
            || existing.plan_digest() != reservation.intersection.plan_digest()
            || existing.verb() != reservation.effect.verb()
            || existing.target() != reservation.effect.target()
        {
            return Err(HostError::Fence("Host execution reservation changed"));
        }
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.host.execution-reservation-receipt.v1\0");
        digest.update(reservation.request_id);
        digest.update((outcome.len() as u64).to_be_bytes());
        digest.update(outcome);
        let receipt = digest.finalize().to_vec();
        let completed = match existing.status() {
            BrokerEffectStatusV1::Pending => existing
                .complete(receipt.clone())
                .map_err(|_| HostError::Fence("Host execution receipt is invalid"))?,
            BrokerEffectStatusV1::Complete if existing.receipt() == receipt.as_slice() => {
                return Ok(());
            }
            BrokerEffectStatusV1::Complete => {
                return Err(HostError::Fence(
                    "Host execution outcome conflicts with replay",
                ));
            }
        };
        let sealed = self
            .authority
            .seal_effect(&reservation.request_id, &completed)?;
        let mut proposed = self.state.clone();
        proposed.complete(
            reservation.request_id,
            *reservation.request_body_digest.as_bytes(),
            sealed,
            receipt,
        )?;
        self.commit_state(&proposed)?;
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime changed after Host commit"))
    }

    /// Joins authenticated host authority with one bounded systemd snapshot.
    ///
    /// The returned report is observation only. A same-name unit is not
    /// adopted, and this method neither calls the worker nor authorizes a
    /// lifecycle effect. Any later mutation must reacquire fresh systemd and
    /// kernel identity evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if the public snapshot is structurally malformed,
    /// internally inconsistent, or over its fixed bounds, or if authenticated
    /// host state no longer has a complete current witness. This method cannot
    /// establish snapshot provenance.
    pub fn compare_runtime_discovery(
        &self,
        snapshot: SandboxUnitDiscoverySnapshot,
    ) -> Result<HostRuntimeRecoveryReport> {
        self.ensure_healthy()?;
        reconcile(self.state.runtime_recovery_inventory()?, snapshot)
    }

    /// Validates, fences, applies, and durably completes one runtime request.
    ///
    /// The caller must supply credentials read from the accepted Unix socket,
    /// never serialized peer claims. Returned bytes are a bounded
    /// `RuntimeObservation` protobuf suitable for one `SOCK_SEQPACKET` reply.
    ///
    /// # Errors
    ///
    /// Returns an error before effects for hostile input, peer mismatch,
    /// stale/equivocating fences, request-ID conflicts, or catalog failures.
    /// Worker and durable-state failures leave a persisted pending intent that
    /// the exact request can safely reconcile.
    pub async fn apply_runtime(
        &mut self,
        request_bytes: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        trusted_clock: impl FnMut() -> Result<RawPairedClockSample> + Send,
    ) -> Result<Vec<u8>>
    where
        W: Sync,
    {
        if !is_exact_host_protocol(protocol_version) {
            return Err(HostError::Authority(
                aos_sandbox_broker::BrokerAdmissionError::RequestMismatch,
            ));
        }
        let candidate = classify_historical_runtime_request_v1(request_bytes, peer, policy)?;
        self.apply_runtime_candidate(
            candidate,
            artifacts,
            protocol_version,
            peer,
            policy,
            u32::MAX,
            trusted_clock,
        )
        .await
        .map(ValidatedRuntimeApplyResponse::into_body)
    }

    /// Applies a preclassified canonical or grandfathered Host request.
    ///
    /// A grandfathered candidate remains nonauthorizing until its exact request
    /// ID and transport digest locate an existing protected effect. It can only
    /// replay or resume that effect and can never select a new one.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn apply_runtime_candidate(
        &mut self,
        candidate: HistoricalRuntimeRequestCandidateV1,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        negotiated_maximum_response_bytes: u32,
        mut trusted_clock: impl FnMut() -> Result<RawPairedClockSample> + Send,
    ) -> Result<ValidatedRuntimeApplyResponse>
    where
        W: Sync,
    {
        self.ensure_healthy()?;
        if !is_exact_host_protocol(protocol_version) {
            return Err(HostError::Authority(
                aos_sandbox_broker::BrokerAdmissionError::RequestMismatch,
            ));
        }
        let request_bytes = candidate.exact_bytes();
        let request_id = *candidate.request_id();
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let durable_status = self.state.query_effect(&request_id, request_digest)?;
        let existing_effect = self
            .state
            .effect(&request_id)
            .map(|bytes| self.authority.open_effect(&request_id, bytes))
            .transpose()?;

        let canonical_request = candidate.canonical_request().cloned();
        let replay_request = match canonical_request {
            Some(request) => request,
            None => {
                if matches!(durable_status, RuntimeEffectQuery::Absent) {
                    return Err(request_mismatch());
                }
                let existing = existing_effect.as_ref().ok_or_else(|| {
                    HostError::State(
                        "grandfathered request lost its protected durable effect".to_owned(),
                    )
                })?;
                validate_effect_request(existing, request_digest)?;

                decode_grandfathered_runtime_request_replay_v1(
                    candidate
                        .grandfathered_candidate()
                        .ok_or_else(request_mismatch)?,
                    peer,
                    policy,
                )?
            }
        };
        if replay_request.header().protocol_version() != protocol_version {
            return Err(HostError::Authority(
                aos_sandbox_broker::BrokerAdmissionError::RequestMismatch,
            ));
        }
        if replay_request.header().maximum_response_bytes() > negotiated_maximum_response_bytes {
            return Err(HostError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::InvalidResponseBound,
            ));
        }
        let guardian_launch = replay_request.action() == RuntimeAction::RUNTIME_ACTION_LAUNCH;
        let composite_stop = replay_request.action() == RuntimeAction::RUNTIME_ACTION_STOP;

        if let Some(effect) = &existing_effect {
            validate_effect_request(effect, request_digest)?;
            if effect.status() == BrokerEffectStatusV1::Complete {
                return Ok(ValidatedRuntimeApplyResponse {
                    request_id,
                    maximum_response_bytes: replay_request.header().maximum_response_bytes(),
                    body: effect.receipt().to_vec(),
                });
            }
        }
        if guardian_launch
            && agent_launch::agent_replay_is_quarantined(self.state.guardian_attempt(&request_id))
        {
            // An agent-required launch may have crossed the payload-start
            // boundary before the private socket disappeared. Its durable
            // phase can be inspected for containment, but this request must
            // never mint a replacement socket or issue a second start.
            return Err(HostError::AgentLaunchQuarantined);
        }

        let guardian_backend = guardian_launch && self.guardian.is_some() && self.nspawn.is_some();
        let composite_stop_backend = composite_stop && self.guardian.is_some();
        if (guardian_launch && !guardian_backend) || (composite_stop && !composite_stop_backend) {
            return Err(request_mismatch());
        }

        let admission_clock = trusted_clock()?;
        let verification_clock = match &existing_effect {
            Some(effect) => historical_clock(effect)?,
            None => admission_clock.clone(),
        };
        let request = if candidate.canonical_request().is_some() {
            decode_runtime_request(
                request_bytes,
                peer,
                policy,
                verification_clock.boottime_nanoseconds(),
            )?
        } else {
            replay_request
        };
        let action = action_code(request.action());

        let operation = if guardian_launch || composite_stop {
            None
        } else {
            Some(self.compile_operation(&request)?)
        };
        let prior_fence_bytes = if existing_effect.is_some() {
            self.state.request_authorization(&request_id)
        } else {
            self.state.prior_authorization(request.fence().sandbox_id())
        };
        let pending_fence = if existing_effect.is_some() {
            Some(self.authority.open_fence(
                request.fence().sandbox_id(),
                prior_fence_bytes.ok_or_else(|| {
                    HostError::State(
                        "pending request lost its authenticated assignment fence".to_owned(),
                    )
                })?,
            )?)
        } else {
            None
        };
        let admitted = self.authority.admit(
            artifacts,
            &request,
            request_bytes,
            protocol_version,
            &verification_clock,
            prior_fence_bytes,
        )?;
        if let Some(existing) = &existing_effect {
            validate_effect_refresh(existing, &admitted.effect)?;
            validate_pending_fence_refresh(
                pending_fence.as_ref().ok_or_else(|| {
                    HostError::State("pending request has no authenticated fence".to_owned())
                })?,
                &admitted.fence,
            )?;
        }
        let sealed_fence = self
            .authority
            .seal_fence(request.fence().sandbox_id(), &admitted.fence)?;
        let sealed_effect = self.authority.seal_effect(&request_id, &admitted.effect)?;

        let (guardian_payload, pending_agent): (_, Option<HostAgentPendingSessionV1>) =
            if guardian_launch {
                let payload = self.compile_launch(&request)?;
                if self.protected_agent_launch {
                    let (payload, pending) =
                        self.prepare_protected_agent_payload(request.fence(), payload)?;
                    (Some(payload), Some(pending))
                } else {
                    (Some(payload), None)
                }
            } else {
                (None, None)
            };
        let mut proposed = self.state.clone();
        let guardian_start = if guardian_launch {
            let payload = guardian_payload.ok_or_else(|| {
                HostError::State("Guardian launch lost its compiled payload".to_owned())
            })?;
            let (execution, spec) = self.prepare_guardian_execution(
                &request,
                artifacts,
                &admitted,
                request_digest,
                payload.snapshot(),
            )?;
            let binding = execution.guardian_binding().ok_or_else(|| {
                HostError::State("Guardian launch lost its immutable binding".to_owned())
            })?;
            let payload = payload.bind(binding)?;
            match proposed.admit_guardian(
                request.fence(),
                request_id,
                request_digest,
                execution,
                sealed_fence,
                &admitted,
                sealed_effect,
                &self.authority,
            )? {
                Admission::New | Admission::Pending => {}
                Admission::Complete(_) => {
                    return Err(HostError::Fence(
                        "completed replay status contradicts authenticated effect",
                    ));
                }
            }
            Some((spec, payload))
        } else if composite_stop {
            let execution = self
                .prepare_composite_stop_execution(&request, request_digest)
                .await?;
            match proposed.admit_composite_stop(
                request.fence(),
                request_id,
                request_digest,
                execution,
                sealed_fence,
                &admitted,
                sealed_effect,
                &self.authority,
            )? {
                Admission::New | Admission::Pending => {}
                Admission::Complete(_) => {
                    return Err(HostError::Fence(
                        "completed replay status contradicts authenticated effect",
                    ));
                }
            }
            None
        } else {
            match proposed.admit(
                request.fence(),
                request_id,
                request_digest,
                action,
                sealed_fence,
                &admitted,
                sealed_effect,
                &self.authority,
            )? {
                Admission::New | Admission::Pending => {}
                Admission::Complete(_) => {
                    return Err(HostError::Fence(
                        "completed replay status contradicts authenticated effect",
                    ));
                }
            }
            None
        };
        self.commit_state(&proposed)?;

        let effect = admitted.effect;
        if let Some((spec, payload)) = guardian_start {
            let body = self
                .advance_guardian_start(
                    request.fence(),
                    request_id,
                    request_digest,
                    &effect,
                    spec,
                    payload,
                    pending_agent,
                    request.header().maximum_response_bytes(),
                    &mut trusted_clock,
                )
                .await?;
            return Ok(ValidatedRuntimeApplyResponse {
                request_id,
                maximum_response_bytes: request.header().maximum_response_bytes(),
                body,
            });
        }
        if composite_stop {
            let body = self
                .advance_composite_stop(
                    request.fence(),
                    request_id,
                    request_digest,
                    &effect,
                    request.header().maximum_response_bytes(),
                    &mut trusted_clock,
                )
                .await?;
            return Ok(ValidatedRuntimeApplyResponse {
                request_id,
                maximum_response_bytes: request.header().maximum_response_bytes(),
                body,
            });
        }
        let operation = operation.ok_or_else(|| {
            HostError::State("direct lifecycle request lost its compiled operation".to_owned())
        })?;
        let observation = {
            let authority = &self.authority;
            let mut before_effect = || {
                authority
                    .check_before_effect(&effect, &mut || {
                        trusted_clock()
                            .map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
                    })
                    .map_err(HostError::from)
            };
            self.worker
                .execute(request.fence(), operation, &mut before_effect)
                .await?
        };
        let sequence = proposed.next_observation_sequence(*request.fence().incarnation_id())?;
        let identity = HostRuntimeIdentity::from(request.fence());
        let response = encode_observation(&identity, sequence, &observation)?;
        let response_limit = usize::try_from(request.header().maximum_response_bytes())
            .map_err(|_| HostError::State("response limit does not fit usize".to_owned()))?;
        if response.len() > response_limit {
            return Err(HostError::State(
                "runtime observation exceeds the admitted response bound".to_owned(),
            ));
        }
        self.retain_runtime_observation(identity, observation)?;
        let completed = effect
            .complete(response.clone())
            .map_err(|_| HostError::Fence("completed host effect is invalid"))?;
        let sealed_completed = self.authority.seal_effect(&request_id, &completed)?;
        proposed.complete(
            request_id,
            request_digest,
            sealed_completed,
            response.clone(),
        )?;
        self.commit_state(&proposed)?;
        Ok(ValidatedRuntimeApplyResponse {
            request_id,
            maximum_response_bytes: request.header().maximum_response_bytes(),
            body: response,
        })
    }

    /// Authenticates and reports one exact original Apply transaction.
    ///
    /// This method is strictly read-only: it does not compile a backend
    /// operation, call a worker, admit a fence, or commit state. Existing
    /// records are reverified at their authenticated admission clock because
    /// this query reports history and grants no effect authority. An absent
    /// canonical request must still be live under the current protected clock;
    /// an absent noncanonical request is rejected without semantic decoding.
    pub(crate) fn query_validated_runtime_effect(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        query: &ValidatedQueryRuntimeEffectRequestV1,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: RawPairedClockSample,
    ) -> Result<Vec<u8>> {
        self.query_runtime_effect_semantics(
            artifacts,
            query.original_apply_candidate(),
            *query.header().request_id(),
            peer,
            policy,
            current_clock,
            query.header().maximum_response_bytes(),
        )
    }

    #[cfg(test)]
    pub(crate) fn query_runtime_effect(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        context: RuntimeEffectQueryContext<'_>,
    ) -> Result<Vec<u8>> {
        let RuntimeEffectQueryContext {
            original_request_bytes,
            request_id,
            peer,
            policy,
            current_clock,
            maximum_response_bytes,
        } = context;
        let candidate =
            classify_historical_runtime_request_v1(original_request_bytes, peer, policy)?;
        self.query_runtime_effect_semantics(
            artifacts,
            &candidate,
            request_id,
            peer,
            policy,
            current_clock,
            maximum_response_bytes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn query_runtime_effect_semantics(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        candidate: &HistoricalRuntimeRequestCandidateV1,
        query_request_id: [u8; 16],
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: RawPairedClockSample,
        maximum_response_bytes: u32,
    ) -> Result<Vec<u8>> {
        self.ensure_healthy()?;
        if candidate.request_id() != &query_request_id {
            return Err(request_mismatch());
        }
        let original_request_bytes = candidate.exact_bytes();
        let request_digest: [u8; 32] = Sha256::digest(original_request_bytes).into();
        let status = self.state.query_effect(&query_request_id, request_digest)?;
        let existing_effect = self
            .state
            .effect(&query_request_id)
            .map(|bytes| self.authority.open_effect(&query_request_id, bytes))
            .transpose()?;
        let request = match candidate.canonical_request() {
            Some(request) => request.clone(),
            None => {
                if matches!(status, RuntimeEffectQuery::Absent) {
                    return Err(request_mismatch());
                }
                let existing = existing_effect.as_ref().ok_or_else(|| {
                    HostError::State(
                        "grandfathered query lost its protected durable effect".to_owned(),
                    )
                })?;
                validate_effect_request(existing, request_digest)?;

                decode_grandfathered_runtime_request_replay_v1(
                    candidate
                        .grandfathered_candidate()
                        .ok_or_else(request_mismatch)?,
                    peer,
                    policy,
                )?
            }
        };
        if !is_exact_host_protocol(request.header().protocol_version())
            || request.header().request_id() != &query_request_id
        {
            return Err(request_mismatch());
        }
        if let Some(effect) = &existing_effect {
            validate_effect_request(effect, request_digest)?;
        }
        let verification_clock = match &existing_effect {
            Some(effect) => historical_clock(effect)?,
            None => current_clock,
        };
        let prior_fence = existing_effect.as_ref().map_or_else(
            || self.state.prior_authorization(request.fence().sandbox_id()),
            |_| self.state.request_authorization(&query_request_id),
        );
        let admitted = self.authority.admit(
            artifacts,
            &request,
            original_request_bytes,
            request.header().protocol_version(),
            &verification_clock,
            prior_fence,
        )?;

        if let Some(existing) = existing_effect {
            let request_fence = self
                .state
                .request_authorization(&query_request_id)
                .ok_or_else(|| HostError::State("host query lost its request fence".to_owned()))?;
            let durable_fence = self
                .authority
                .open_fence(request.fence().sandbox_id(), request_fence)?;
            let expected = match &status {
                RuntimeEffectQuery::Pending => admitted.effect,
                RuntimeEffectQuery::Complete(receipt) => admitted
                    .effect
                    .complete(receipt.clone())
                    .map_err(|_| HostError::Fence("completed query effect is invalid"))?,
                RuntimeEffectQuery::Absent => {
                    return Err(HostError::State(
                        "host query effect index is inconsistent".to_owned(),
                    ));
                }
            };
            if existing != expected || durable_fence != admitted.fence {
                return Err(HostError::Fence(
                    "query authorization differs from durable host effect",
                ));
            }
        }

        let (status, receipt) = match status {
            RuntimeEffectQuery::Absent => (
                RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_ABSENT,
                Vec::new(),
            ),
            RuntimeEffectQuery::Pending => (
                RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_PENDING,
                Vec::new(),
            ),
            RuntimeEffectQuery::Complete(receipt) => {
                (RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE, receipt)
            }
        };
        let bytes = QueryRuntimeEffectResponse {
            status: status.into(),
            receipt,
            ..Default::default()
        }
        .encode_to_vec();
        ensure_response_bound(&bytes, maximum_response_bytes)?;
        Ok(bytes)
    }

    /// Resolves a live leader handle retained by this broker process.
    ///
    /// Handles intentionally expire across broker restart and are never
    /// serialized as descriptor integers.
    #[must_use]
    pub fn leader(&self, handle: &[u8; 32]) -> Option<&PidFd> {
        if !self.state_healthy {
            return None;
        }
        self.observed_leaders
            .values()
            .find(|leader| leader.handle() == handle)
            .map(PinnedLeader::pidfd)
    }

    pub(crate) async fn observe_runtime(
        &mut self,
        identity: HostRuntimeIdentity,
        supplied_handle: [u8; 32],
        maximum_response_bytes: u32,
    ) -> Result<Vec<u8>> {
        self.ensure_healthy()?;
        if runtime_handle(&identity) != supplied_handle || !self.state.contains_runtime(&identity) {
            return Err(HostError::UnknownHandle);
        }
        let observation = self.worker.observe(&identity).await?;
        let mut proposed = self.state.clone();
        let sequence = proposed.next_observation_sequence(*identity.incarnation_id())?;
        let response = project_observation(&identity, sequence, &observation);
        let bytes = response.encode_to_vec();
        ensure_response_bound(&bytes, maximum_response_bytes)?;

        self.commit_state(&proposed)?;
        self.retain_runtime_observation(identity, observation)?;
        Ok(bytes)
    }

    pub(crate) async fn inventory_runtime(
        &mut self,
        maximum_response_bytes: u32,
    ) -> Result<Vec<u8>> {
        self.ensure_healthy()?;
        let identities = self.state.runtime_inventory();
        if identities.len() > MAXIMUM_INVENTORY_RUNTIMES {
            return Err(HostError::ResourceExhausted);
        }
        let mut identities = identities
            .into_iter()
            .map(|identity| (runtime_handle(&identity), identity))
            .collect::<Vec<_>>();
        identities.sort_unstable();

        let mut proposed = self.state.clone();
        let mut runtimes = Vec::with_capacity(identities.len());
        let mut observations = Vec::new();
        for (_, identity) in identities {
            let observation = self.worker.observe(&identity).await?;
            let sequence = proposed.next_observation_sequence(*identity.incarnation_id())?;
            let runtime = project_observation(&identity, sequence, &observation);
            runtimes.push(runtime);
            observations.push((identity, observation));
        }
        let bytes = InventoryRuntimeResponse {
            runtimes,
            ..Default::default()
        }
        .encode_to_vec();
        ensure_response_bound(&bytes, maximum_response_bytes)?;

        self.commit_state(&proposed)?;
        for (identity, observation) in observations {
            self.retain_runtime_observation(identity, observation)?;
        }
        Ok(bytes)
    }

    fn prepare_guardian_execution(
        &self,
        request: &ValidatedRuntimeRequest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        admitted: &aos_sandbox_broker::VerifiedBrokerAdmission,
        transport_request_digest: [u8; 32],
        payload_snapshot: &crate::state::transition::PayloadLaunchSnapshot,
    ) -> Result<(DurableExecution, GuardianUnitSpec)> {
        const MAXIMUM_PLAN_BYTES: usize = 256 * 1024;
        const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
        const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;

        let config = self.guardian.as_ref().ok_or_else(|| {
            HostError::InvalidPlan("Guardian backend readiness is unavailable".to_owned())
        })?;
        let protected = self
            .authority
            .revalidated_guardian_credentials()
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?
            .ok_or_else(|| {
                HostError::InvalidPlan(
                    "Guardian requires protected public-credential custody".to_owned(),
                )
            })?;
        let protected_snapshots = protected_input_snapshots(&protected).ok_or_else(|| {
            HostError::State("Guardian protected credential order is invalid".to_owned())
        })?;

        let execution =
            if let Some(execution) = self.state.guardian_execution(request.header().request_id()) {
                execution
            } else {
                let companion = request.guardian_arm().ok_or_else(request_mismatch)?;
                let lease = admitted.effect.local_lease_record();
                let context = ExecutionContext {
                    action: HostAction::Launch,
                    request_id: *request.header().request_id(),
                    request_digest: transport_request_digest,
                    sandbox_id: *request.fence().sandbox_id(),
                    incarnation_id: *request.fence().incarnation_id(),
                    assignment_epoch: request.fence().assignment_epoch(),
                    desired_generation: request.fence().desired_generation(),
                    assignment_digest: *request.fence().assignment_digest(),
                    receipt_present: false,
                };
                DurableExecution::guardian_launch(
                    context,
                    *admitted.effect.request_digest().as_bytes(),
                    *admitted.fence.node().as_bytes(),
                    *admitted.effect.host_boot_id(),
                    lease.lease_generation(),
                    *admitted.effect.lease_digest().as_bytes(),
                    companion.broker_plan(),
                    companion.broker_plan_signature(),
                    artifacts.ownership_lease(),
                    artifacts.ownership_lease_signature(),
                    protected_snapshots.clone(),
                    config.executable_snapshot(),
                    payload_snapshot.clone(),
                )
                .ok_or_else(|| {
                    HostError::State("Guardian durable execution evidence is invalid".to_owned())
                })?
            };

        let attempt = execution.guardian_attempt().ok_or_else(|| {
            HostError::State("Guardian request lost its durable execution evidence".to_owned())
        })?;
        if !execution.guardian_runtime_inputs_match(
            &protected_snapshots,
            config.executable_snapshot(),
            payload_snapshot,
        ) {
            return Err(HostError::InvalidPlan(
                "current Guardian executable or protected credentials differ from the durable attempt"
                    .to_owned(),
            ));
        }
        let dynamic_credentials = [
            (
                GuardianCredentialRole::BrokerPlan,
                SealedReadOnlyCredential::create(
                    GuardianCredentialRole::BrokerPlan.as_str(),
                    attempt.broker_plan,
                    MAXIMUM_PLAN_BYTES,
                ),
            ),
            (
                GuardianCredentialRole::BrokerPlanSignature,
                SealedReadOnlyCredential::create(
                    GuardianCredentialRole::BrokerPlanSignature.as_str(),
                    attempt.broker_plan_signature,
                    MAXIMUM_SIGNATURE_BYTES,
                ),
            ),
            (
                GuardianCredentialRole::OwnershipLease,
                SealedReadOnlyCredential::create(
                    GuardianCredentialRole::OwnershipLease.as_str(),
                    attempt.ownership_lease,
                    MAXIMUM_LEASE_BYTES,
                ),
            ),
            (
                GuardianCredentialRole::OwnershipLeaseSignature,
                SealedReadOnlyCredential::create(
                    GuardianCredentialRole::OwnershipLeaseSignature.as_str(),
                    attempt.ownership_lease_signature,
                    MAXIMUM_SIGNATURE_BYTES,
                ),
            ),
        ];
        let dynamic_credentials = dynamic_credentials
            .into_iter()
            .map(|(role, credential)| {
                credential
                    .map(|credential| (role, credential))
                    .map_err(|error| HostError::InvalidPlan(error.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut descriptors = Vec::with_capacity(10);
        descriptors.extend(
            protected
                .iter()
                .map(|(role, descriptor, _)| (guardian_credential_role(*role), *descriptor)),
        );
        descriptors.extend(
            dynamic_credentials
                .iter()
                .map(|(role, credential)| (*role, credential.as_fd())),
        );
        let credentials = GuardianCredentialDescriptors::from_descriptors(descriptors)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let spec = config.prepare(
            *request.fence().incarnation_id(),
            credentials,
            attempt.binding,
        )?;
        Ok((execution, spec))
    }

    fn compile_operation(&self, request: &ValidatedRuntimeRequest) -> Result<WorkerOperation> {
        Ok(match request.action() {
            RuntimeAction::RUNTIME_ACTION_LAUNCH => {
                let prepared = self.compile_launch(request)?;
                let (spec, pins) = prepared.into_parts();
                WorkerOperation::Launch {
                    spec: Box::new(spec),
                    pins,
                }
            }
            RuntimeAction::RUNTIME_ACTION_STOP => WorkerOperation::Stop,
            RuntimeAction::RUNTIME_ACTION_FREEZE => WorkerOperation::Freeze,
            RuntimeAction::RUNTIME_ACTION_THAW => WorkerOperation::Thaw,
            RuntimeAction::RUNTIME_ACTION_KILL => WorkerOperation::Kill,
            RuntimeAction::RUNTIME_ACTION_UNSPECIFIED => {
                return Err(HostError::InvalidPlan(
                    "validated request contains unspecified action".to_owned(),
                ));
            }
        })
    }

    fn compile_launch(&self, request: &ValidatedRuntimeRequest) -> Result<PreparedLaunch> {
        let nspawn = self.nspawn.as_ref().ok_or_else(|| {
            HostError::InvalidPlan("nspawn backend readiness is unavailable".to_owned())
        })?;
        let plan = request.launch_plan().ok_or(HostError::InvalidPlan(
            "validated launch request lost its launch plan".to_owned(),
        ))?;
        let resolved: ResolvedLaunchResources = self.catalog.resolve(request.fence(), plan)?;
        let root_mount = self.catalog.export_root_mount(&resolved.workspace)?;
        nspawn.compile_resolved(request.fence(), plan, resolved, root_mount)
    }

    fn retain_runtime_observation(
        &mut self,
        identity: HostRuntimeIdentity,
        mut observation: WorkerObservation,
    ) -> Result<()> {
        #[cfg(test)]
        if self.fail_runtime_retention {
            self.fail_runtime_retention = false;
            return Err(HostError::Worker(
                "injected runtime retention failure".to_owned(),
            ));
        }
        if matches!(
            observation.state,
            ObservedRuntimeState::Absent
                | ObservedRuntimeState::Stopping
                | ObservedRuntimeState::Exited
                | ObservedRuntimeState::Failed
        ) {
            self.runtime_pins
                .retain(|retained, _| retained.sandbox_id() != identity.sandbox_id());
            self.observed_leaders.remove(&identity);
            return Ok(());
        }
        let supervisor = observation.leader.take();
        let observed_leader = supervisor
            .as_ref()
            .map(PinnedLeader::try_clone)
            .transpose()?;
        let retained = if let (Some(invocation_id), Some(supervisor), Some(payload)) = (
            observation.invocation_id,
            supervisor,
            observation.payload.take(),
        ) {
            payload.recheck_kernel(&supervisor)?;
            let mut prior_scope = None;
            for (prior_identity, retained) in &self.runtime_pins {
                if let Some(handle) = retained.scope_for_observation(
                    prior_identity,
                    &identity,
                    invocation_id,
                    &supervisor,
                    &payload,
                )? {
                    let duplicate = prior_scope.replace(handle).is_some();
                    if duplicate {
                        return Err(HostError::State(
                            "ambiguous retained payload scope".to_owned(),
                        ));
                    }
                }
            }
            let scope_handle = prior_scope.map_or_else(|| self.mint_scope_handle(), Ok)?;
            // The opaque scope identifies physical pins, not assignment
            // authority. Reindex only after a complete current proof; old
            // assignment handles remain rejected by the durable fence checks.
            Some(RetainedRuntimePins {
                invocation_id,
                supervisor,
                payload,
                scope_handle,
            })
        } else {
            None
        };

        // All descriptor duplication, kernel rechecks, and handle minting have
        // succeeded. Only now replace the volatile indexes as one infallible
        // update, so a caller can safely prepare retention before committing a
        // durable completion.
        self.observed_leaders.retain(|retained, _| {
            retained.sandbox_id() != identity.sandbox_id() || retained == &identity
        });
        match observed_leader {
            Some(leader) => {
                self.observed_leaders.insert(identity, leader);
            }
            None => {
                self.observed_leaders.remove(&identity);
            }
        }
        if let Some(retained) = retained {
            self.runtime_pins
                .retain(|retained, _| retained.sandbox_id() != identity.sandbox_id());
            self.runtime_pins.insert(identity, retained);
            return Ok(());
        }

        // A supervisor-only observation cannot transfer a payload proof to a
        // different assignment. Such a transfer requires launch verification.
        self.runtime_pins.retain(|retained, _| {
            retained.sandbox_id() != identity.sandbox_id() || retained == &identity
        });
        let remains_exact = self.runtime_pins.get(&identity).is_some_and(|retained| {
            observation.invocation_id == Some(retained.invocation_id)
                && self
                    .observed_leaders
                    .get(&identity)
                    .is_some_and(|leader| leader.handle() == retained.supervisor.handle())
        });
        if !remains_exact {
            self.runtime_pins.remove(&identity);
        }
        Ok(())
    }

    fn mint_scope_handle(&self) -> Result<[u8; 32]> {
        for _ in 0..MAXIMUM_SCOPE_HANDLE_ATTEMPTS {
            let mut handle = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut handle)
                .map_err(|_| HostError::State("payload scope entropy unavailable".to_owned()))?;
            if handle != [0; 32]
                && self
                    .runtime_pins
                    .values()
                    .all(|retained| retained.scope_handle != handle)
            {
                return Ok(handle);
            }
        }
        Err(HostError::ResourceExhausted)
    }

    pub(crate) async fn refresh_payload_scope(
        &mut self,
        identity: HostRuntimeIdentity,
    ) -> Result<()>
    where
        W: Sync,
    {
        self.ensure_healthy()?;
        if !self.state.contains_runtime(&identity) {
            return Err(HostError::UnknownHandle);
        }
        let guardian_lineage = match self.state.completed_guardian_lineage(
            identity.sandbox_id(),
            identity.incarnation_id(),
            &self.authority,
        )? {
            GuardianLineage::Absent => None,
            GuardianLineage::Shadowed => return Err(HostError::UnknownHandle),
            GuardianLineage::Complete(lineage) => Some(lineage),
        };
        let retained = self
            .runtime_pins
            .get(&identity)
            .ok_or(HostError::UnknownHandle)?;
        let observation =
            guard_payload_scope_refresh(&self.worker, &identity, guardian_lineage, || {
                self.worker.refresh_payload_scope(
                    &identity,
                    retained.invocation_id,
                    &retained.supervisor,
                    &retained.payload,
                )
            })
            .await?;
        let invocation_id = observation.invocation_id.ok_or_else(|| {
            HostError::Worker("refreshed payload proof omitted its invocation".to_owned())
        })?;
        let supervisor = observation.leader.ok_or_else(|| {
            HostError::Worker("refreshed payload proof omitted its supervisor".to_owned())
        })?;
        let payload = observation.payload.ok_or_else(|| {
            HostError::Worker("refreshed payload proof omitted its payload".to_owned())
        })?;
        if !matches!(
            observation.state,
            ObservedRuntimeState::Ready | ObservedRuntimeState::Frozen
        ) || invocation_id != retained.invocation_id
            || supervisor.handle() != retained.supervisor.handle()
            || !payload.has_same_cgroup(&retained.payload)
            || payload.relative_cgroup_hint() != retained.payload.relative_cgroup_hint()
            || payload
                .pidfd()
                .info()
                .ok()
                .zip(retained.payload.pidfd().info().ok())
                .is_none_or(|(current, prior)| current != prior)
        {
            return Err(HostError::Worker(
                "refreshed payload proof changed its retained identity".to_owned(),
            ));
        }
        let observed_leader = supervisor.try_clone()?;
        let scope_handle = retained.scope_handle;
        self.observed_leaders.insert(identity, observed_leader);
        self.runtime_pins.insert(
            identity,
            RetainedRuntimePins {
                invocation_id,
                supervisor,
                payload,
                scope_handle,
            },
        );
        Ok(())
    }

    pub(crate) async fn recover_completed_runtime_scope(
        &mut self,
        identity: HostRuntimeIdentity,
    ) -> Result<()>
    where
        W: Sync,
    {
        if !self.state.contains_runtime(&identity) {
            return Err(HostError::UnknownHandle);
        }
        let (lineage, retained_pins_are_current) = select_completed_guardian_scope(
            self.state.completed_guardian_lineage(
                identity.sandbox_id(),
                identity.incarnation_id(),
                &self.authority,
            )?,
            self.runtime_pins.contains_key(&identity),
        )?;
        // A pending or terminal successor shadows even still-retained pins.
        // Authenticate lineage before the fast path so a scope query cannot
        // race a newly admitted lifecycle transition.
        if retained_pins_are_current {
            return Ok(());
        }
        let recovered = self
            .worker
            .recover_completed_payload(
                &identity,
                lineage.binding,
                lineage.guardian_invocation,
                lineage.payload_invocation,
                CompletedRuntimeProof::from_snapshot(lineage.worker_proof),
            )
            .await?;
        if recovered.verification.binding != Some(lineage.binding)
            || recovered.verification.invocation_id != lineage.payload_invocation
            || recovered.verification.proof != lineage.worker_proof
        {
            return Err(HostError::Worker(
                "completed runtime recovery contradicted durable exact evidence".to_owned(),
            ));
        }
        self.retain_runtime_observation(identity, recovered.verification.observation)
            .and_then(|()| {
                self.runtime_pins
                    .contains_key(&identity)
                    .then_some(())
                    .ok_or_else(|| {
                        HostError::Worker(
                            "completed runtime recovery omitted retained payload pins".to_owned(),
                        )
                    })
            })
    }

    pub(crate) fn payload_pin(
        &self,
        identity: &HostRuntimeIdentity,
    ) -> Option<&RetainedRuntimePins> {
        self.state_healthy
            .then(|| {
                self.state
                    .contains_runtime(identity)
                    .then(|| self.runtime_pins.get(identity))
                    .flatten()
            })
            .flatten()
    }

    pub(crate) fn ensure_healthy(&self) -> Result<()> {
        if self.state_healthy {
            Ok(())
        } else {
            Err(HostError::State(
                "host state is indeterminate after a failed commit".to_owned(),
            ))
        }
    }

    // Terminal replay constructs its exact assignment between this check and
    // opening the saved authorization; keep those operations separate.
    fn checked_scope_runtime(
        &self,
        fence: &ValidatedAssignmentFence,
    ) -> Result<HostRuntimeIdentity> {
        self.ensure_healthy()?;
        self.state.validate_authenticated(&self.authority)?;

        let identity = HostRuntimeIdentity::new(
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
        );
        if !self.state.contains_runtime(&identity) {
            return Err(HostError::UnknownHandle);
        }
        Ok(identity)
    }

    fn open_scope_fence(
        &self,
        fence: &ValidatedAssignmentFence,
    ) -> Result<(Vec<u8>, BrokerAuthorizationFenceV1)> {
        let prior = self
            .state
            .prior_authorization(fence.sandbox_id())
            .ok_or(HostError::UnknownHandle)?
            .to_vec();
        let current = self.authority.open_fence(fence.sandbox_id(), &prior)?;
        Ok((prior, current))
    }

    pub(crate) fn retain_scope_replay_authority(
        &mut self,
        binding: crate::state::HostScopeReplayBindingV1,
    ) -> Result<[u8; 32]> {
        self.ensure_healthy()?;
        let mut proposed = self.state.clone();
        let locator = proposed.retain_scope_replay(binding, &self.authority)?;
        self.commit_state(&proposed)?;
        Ok(locator)
    }

    pub(crate) fn terminal_verifier_commitment(&self) -> Result<[u8; 32]> {
        self.authority
            .terminal_verifier_commitment()
            .map_err(|error| HostError::State(error.to_string()))
    }

    pub(crate) fn revalidate_scope_replay_authority(
        &self,
        retained_locator: Option<[u8; 32]>,
        binding: &crate::state::HostScopeReplayBindingV1,
    ) -> Result<[u8; 32]> {
        self.ensure_healthy()?;
        self.state
            .revalidate_scope_replay(retained_locator, binding, &self.authority)
    }

    pub(crate) fn finalize_scope_replay_authority(
        &mut self,
        receipt: &aos_sandbox_protocol::BrokerTerminalCommitReceiptV1,
    ) -> Result<[u8; 32]> {
        if !self.state_healthy {
            let recovered = self.store.load()?;
            recovered.validate_authenticated(&self.authority)?;
            self.state = recovered;
            self.state_healthy = true;
        }
        let mut proposed = self.state.clone();
        let locator = proposed.finalize_scope_replay(receipt, &self.authority)?;
        if proposed == self.state {
            return Ok(locator);
        }
        self.commit_state(&proposed)?;
        Ok(locator)
    }

    fn commit_state(&mut self, proposed: &HostState) -> Result<()> {
        self.state_healthy = false;
        self.store.commit(proposed)?;
        self.state = proposed.clone();
        self.state_healthy = true;
        Ok(())
    }
}

fn execution_assignment(claim: &DormantRuntimeExecutionClaimV1<'_>) -> Result<BrokerAssignment> {
    let current = claim.currentness().runtime().currentness();
    BrokerAssignment::new(
        current.sandbox(),
        current.incarnation(),
        current.assignment_epoch(),
        current.desired_generation(),
        current.assignment_digest(),
    )
    .map_err(|_| HostError::Fence("protected runtime assignment is invalid"))
}

fn historical_clock(effect: &BrokerEffectIntentV1) -> Result<RawPairedClockSample> {
    let provenance = RawClockProvenance::new_untrusted(*effect.clock_provenance())
        .map_err(|_| HostError::State("durable effect clock provenance is invalid".to_owned()))?;
    RawPairedClockSample::new_untrusted(
        provenance,
        *effect.host_boot_id(),
        effect.admitted_wall_seconds(),
        effect.admitted_boottime_nanoseconds(),
    )
    .map_err(|_| HostError::State("durable effect admission clock is invalid".to_owned()))
}

fn is_exact_host_protocol(version: ProtocolVersion) -> bool {
    version == ProtocolVersion::new(1, 0)
}

fn guardian_credential_role(role: ProtectedBrokerPublicCredentialRole) -> GuardianCredentialRole {
    match role {
        ProtectedBrokerPublicCredentialRole::BrokerPlanPolicy => {
            GuardianCredentialRole::BrokerPlanPolicy
        }
        ProtectedBrokerPublicCredentialRole::BrokerPlanPublicKey => {
            GuardianCredentialRole::BrokerPlanPublicKey
        }
        ProtectedBrokerPublicCredentialRole::BrokerPlanRevocationScope => {
            GuardianCredentialRole::BrokerPlanRevocationScope
        }
        ProtectedBrokerPublicCredentialRole::OwnershipLeasePolicy => {
            GuardianCredentialRole::OwnershipLeasePolicy
        }
        ProtectedBrokerPublicCredentialRole::OwnershipLeasePublicKey => {
            GuardianCredentialRole::OwnershipLeasePublicKey
        }
        ProtectedBrokerPublicCredentialRole::NodeId => GuardianCredentialRole::NodeId,
    }
}

fn guardian_authority_freshness(
    authority: &HostAuthorityV1,
    effect: &BrokerEffectIntentV1,
    trusted_clock: &mut (impl FnMut() -> Result<RawPairedClockSample> + Send),
) -> AuthorityFreshness {
    if authority
        .check_before_effect(effect, &mut || {
            trusted_clock().map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
        })
        .is_ok()
    {
        AuthorityFreshness::Fresh
    } else {
        AuthorityFreshness::Expired
    }
}

fn guardian_unit_observation(observation: GuardianObservation) -> UnitObservation {
    let GuardianObservation {
        binding,
        invocation_id,
        state,
    } = observation;
    if state == GuardianObservedState::Absent {
        return UnitObservation::Absent;
    }
    let Some(invocation) = invocation_id.filter(|invocation| *invocation != [0; 16]) else {
        return UnitObservation::Indeterminate;
    };
    UnitObservation::Present {
        binding,
        invocation,
        state: match state {
            GuardianObservedState::ActiveRunning => PresentUnitState::ActiveRunning,
            GuardianObservedState::Activating => PresentUnitState::Activating,
            GuardianObservedState::TerminalInactive => PresentUnitState::TerminalInactive,
            GuardianObservedState::TerminalFailed => PresentUnitState::TerminalFailed,
            GuardianObservedState::Other => PresentUnitState::Other,
            GuardianObservedState::Absent => return UnitObservation::Indeterminate,
        },
    }
}

async fn guard_payload_scope_refresh<W, T, F, Fut>(
    worker: &W,
    identity: &HostRuntimeIdentity,
    lineage: Option<CompletedGuardianLineage>,
    refresh: F,
) -> Result<T>
where
    W: HostWorker + Sync,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let before = if let Some(lineage) = lineage {
        Some(require_exact_live_guardian(
            worker.observe_guardian(identity).await?,
            lineage,
        )?)
    } else {
        None
    };

    let refreshed = refresh().await?;

    if let Some(lineage) = lineage {
        let after = require_exact_live_guardian(worker.observe_guardian(identity).await?, lineage)?;
        if before != Some(after) {
            return Err(HostError::Worker(
                "Guardian identity changed during payload scope refresh".to_owned(),
            ));
        }
    }
    Ok(refreshed)
}

fn require_exact_live_guardian(
    observation: GuardianObservation,
    lineage: CompletedGuardianLineage,
) -> Result<GuardianObservation> {
    if observation.binding != Some(lineage.binding)
        || observation.invocation_id != Some(lineage.guardian_invocation)
        || observation.state != GuardianObservedState::ActiveRunning
    {
        return Err(HostError::Worker(
            "payload scope Guardian does not match durable live lineage".to_owned(),
        ));
    }
    Ok(observation)
}

fn select_completed_guardian_scope(
    lineage: GuardianLineage,
    retained_pins_are_current: bool,
) -> Result<(CompletedGuardianLineage, bool)> {
    let GuardianLineage::Complete(lineage) = lineage else {
        return Err(HostError::UnknownHandle);
    };
    Ok((lineage, retained_pins_are_current))
}

fn guardian_pending() -> HostError {
    HostError::Worker("Guardian launch remains durably pending".to_owned())
}

fn guardian_rejected() -> HostError {
    HostError::Worker("Guardian launch is not authorized by current durable evidence".to_owned())
}

fn guardian_quarantined() -> HostError {
    HostError::Worker("Guardian launch observation requires quarantine".to_owned())
}

fn composite_stop_pending() -> HostError {
    HostError::Worker("composite Stop remains durably pending".to_owned())
}

fn request_mismatch() -> HostError {
    HostError::Authority(aos_sandbox_broker::BrokerAdmissionError::RequestMismatch)
}

const fn closed_launch_backend_available(nspawn_available: bool, guardian_available: bool) -> bool {
    nspawn_available && guardian_available
}

fn encode_observation(
    identity: &HostRuntimeIdentity,
    sequence: u64,
    observation: &WorkerObservation,
) -> Result<Vec<u8>> {
    let bytes = project_observation(identity, sequence, observation).encode_to_vec();
    if bytes.is_empty() {
        return Err(HostError::State(
            "runtime observation encoded to an empty receipt".to_owned(),
        ));
    }
    Ok(bytes)
}

fn project_observation(
    identity: &HostRuntimeIdentity,
    sequence: u64,
    observation: &WorkerObservation,
) -> RuntimeObservation {
    let mut response = RuntimeObservation {
        runtime_handle: runtime_handle(identity).to_vec(),
        fence: Some(AssignmentFence {
            sandbox_id: identity.sandbox_id().to_vec(),
            incarnation_id: identity.incarnation_id().to_vec(),
            assignment_epoch: identity.assignment_epoch(),
            desired_generation: identity.desired_generation(),
            assignment_digest: identity.assignment_digest().to_vec(),
            ..Default::default()
        })
        .into(),
        state: protocol_state(observation.state).into(),
        observation_sequence: sequence,
        ..Default::default()
    };
    if let Some(leader) = &observation.leader {
        response.leader_handle = leader.handle().to_vec();
    }
    response
}

fn ensure_response_bound(bytes: &[u8], maximum_response_bytes: u32) -> Result<()> {
    let maximum = usize::try_from(maximum_response_bytes)
        .map_err(|_| HostError::State("response limit does not fit usize".to_owned()))?;
    if bytes.len() > maximum {
        return Err(HostError::ResourceExhausted);
    }
    Ok(())
}

fn validate_effect_request(effect: &BrokerEffectIntentV1, request_digest: [u8; 32]) -> Result<()> {
    if effect.transport_request_digest().as_bytes() != &request_digest {
        return Err(HostError::Fence(
            "request ID was reused with different transport bytes",
        ));
    }
    Ok(())
}

fn validate_effect_refresh(
    existing: &BrokerEffectIntentV1,
    refreshed: &BrokerEffectIntentV1,
) -> Result<()> {
    if existing.status() != BrokerEffectStatusV1::Pending
        || existing.transport_request_digest() != refreshed.transport_request_digest()
        || existing.request_digest() != refreshed.request_digest()
        || existing.verb() != refreshed.verb()
        || existing.target() != refreshed.target()
    {
        return Err(HostError::Fence(
            "pending replay changed its authenticated effect semantics",
        ));
    }
    Ok(())
}

fn validate_pending_fence_refresh(
    existing: &BrokerAuthorizationFenceV1,
    refreshed: &BrokerAuthorizationFenceV1,
) -> Result<()> {
    if existing.assignment() != refreshed.assignment()
        || existing.node() != refreshed.node()
        || existing.plan_digest() != refreshed.plan_digest()
        || existing.ownership_authority() != refreshed.ownership_authority()
    {
        return Err(HostError::Fence(
            "pending replay changed its authenticated authority lineage",
        ));
    }
    Ok(())
}

fn action_code(action: RuntimeAction) -> u8 {
    match action {
        RuntimeAction::RUNTIME_ACTION_LAUNCH => 1,
        RuntimeAction::RUNTIME_ACTION_STOP => 2,
        RuntimeAction::RUNTIME_ACTION_FREEZE => 3,
        RuntimeAction::RUNTIME_ACTION_THAW => 4,
        RuntimeAction::RUNTIME_ACTION_KILL => 5,
        RuntimeAction::RUNTIME_ACTION_UNSPECIFIED => 0,
    }
}

fn protocol_state(state: ObservedRuntimeState) -> RuntimeState {
    match state {
        ObservedRuntimeState::Absent => RuntimeState::RUNTIME_STATE_ABSENT,
        ObservedRuntimeState::Starting => RuntimeState::RUNTIME_STATE_STARTING,
        ObservedRuntimeState::Ready => RuntimeState::RUNTIME_STATE_READY,
        ObservedRuntimeState::Frozen => RuntimeState::RUNTIME_STATE_FROZEN,
        ObservedRuntimeState::Stopping => RuntimeState::RUNTIME_STATE_STOPPING,
        ObservedRuntimeState::Exited => RuntimeState::RUNTIME_STATE_EXITED,
        ObservedRuntimeState::Failed => RuntimeState::RUNTIME_STATE_FAILED,
    }
}

fn runtime_handle(identity: &HostRuntimeIdentity) -> [u8; 32] {
    runtime_handle_v1(
        identity.incarnation_id(),
        identity.assignment_epoch(),
        identity.assignment_digest(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    mod guardian;

    #[cfg(feature = "kernel-tests")]
    mod guardian_systemd;

    #[cfg(feature = "kernel-tests")]
    mod service_peer;

    #[path = "../../authorization/payload_scope_tests.rs"]
    mod payload_scope_tests;

    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerMethod,
        BrokerRequestEnvelope, Feature, ResourceLimit,
    };
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
        BrokerGrantTarget, BrokerVerb, DecodeLimits, DesiredGeneration, GuardianPlanBinding,
        IncarnationId, LeaseAssignment, MediaType, NodeId, ObjectDigest, OwnershipLease,
        OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId, RawClockProvenance,
        RevocationScopeId, SandboxId, TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_protocol::session::decode_request_envelope;
    use aos_sandbox_protocol::{
        MAXIMUM_REQUEST_BYTES, ValidatedAssignmentFence, encode_host_guardian_companion_v1,
    };
    use aos_systemd::ExactUnitRole;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::plan::{
        ResolvedAttachmentAnchor, ResolvedIdentityAllocation, ResolvedLaunchResources,
        ResolvedNetwork, ResolvedWorkspace,
    };
    use crate::state::transition::{
        GuardianLaunchPhase, NamespaceProofSnapshot, ProcessProofSnapshot, RuntimeProofSnapshot,
    };
    use crate::worker::ExactWorkerStopOutcome;

    #[derive(Clone, Default)]
    struct MemoryStore(Arc<Mutex<HostState>>);

    impl HostStateStore for MemoryStore {
        fn load(&self) -> Result<HostState> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn commit(&self, state: &HostState) -> Result<()> {
            *self.0.lock().unwrap() = state.clone();
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct GuardianRecordingStore {
        state: Arc<Mutex<HostState>>,
        phases: Arc<Mutex<Vec<GuardianLaunchPhase>>>,
        fail_payload_verified_commit: Arc<AtomicBool>,
        fail_complete_commit: Arc<AtomicBool>,
    }

    impl HostStateStore for GuardianRecordingStore {
        fn load(&self) -> Result<HostState> {
            Ok(self.state.lock().unwrap().clone())
        }

        fn commit(&self, state: &HostState) -> Result<()> {
            if let Some(attempt) = state.guardian_attempt(&[61; 16]) {
                if matches!(attempt.phase, GuardianLaunchPhase::PayloadVerified { .. })
                    && self
                        .fail_payload_verified_commit
                        .swap(false, Ordering::SeqCst)
                {
                    return Err(HostError::State(
                        "injected crash before payload proof commit".to_owned(),
                    ));
                }
                if matches!(attempt.phase, GuardianLaunchPhase::Complete { .. })
                    && self.fail_complete_commit.swap(false, Ordering::SeqCst)
                {
                    return Err(HostError::State(
                        "injected crash before launch receipt commit".to_owned(),
                    ));
                }
                self.phases.lock().unwrap().push(attempt.phase.clone());
            }
            *self.state.lock().unwrap() = state.clone();
            Ok(())
        }
    }

    struct FailingStore;

    impl HostStateStore for FailingStore {
        fn load(&self) -> Result<HostState> {
            Ok(HostState::default())
        }

        fn commit(&self, _state: &HostState) -> Result<()> {
            Err(HostError::State("injected ambiguous commit".to_owned()))
        }
    }

    struct FixedCatalog;

    impl HostCatalog for FixedCatalog {
        fn resolve(
            &self,
            fence: &ValidatedAssignmentFence,
            plan: &aos_sandbox_protocol::ValidatedRuntimePlan,
        ) -> Result<ResolvedLaunchResources> {
            if plan.workspace_handle() != &[6; 32] {
                return Err(HostError::Catalog("unknown workspace".to_owned()));
            }
            if plan.network_handle() != &[7; 32] {
                return Err(HostError::Catalog("unknown network".to_owned()));
            }
            let workspace_pin = rustix::fs::open(
                "/",
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let workspace_identity = rustix::fs::fstat(&workspace_pin).unwrap();
            let network_fd = rustix::fs::open(
                "/proc/self/ns/net",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let network_pin = aos_sandbox_linux::pidfd::NamespaceFd::from_owned(
                network_fd,
                aos_sandbox_linux::pidfd::NamespaceKind::Network,
            )
            .unwrap();
            let network_identity = network_pin.identity();
            if plan.attachment_anchor_handle() != &[12; 32] {
                return Err(HostError::Catalog("unknown attachment anchor".to_owned()));
            }
            let anchor_pin = rustix::fs::open(
                "/",
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let anchor_identity = rustix::fs::fstat(&anchor_pin).unwrap();
            let anchor_mount_id = aos_sandbox_linux::inventory::MountId::from_fd(
                std::os::fd::AsFd::as_fd(&anchor_pin),
            )
            .unwrap()
            .get();
            let attachment_anchor = ResolvedAttachmentAnchor::from_pinned(
                format!(
                    "/run/aos/sandbox-mount-catalog/slots/{}/{}/0000000000000007",
                    crate::catalog::encode_hex(fence.sandbox_id()),
                    crate::catalog::encode_hex(fence.incarnation_id()),
                ),
                anchor_identity.st_dev,
                anchor_identity.st_ino,
                anchor_mount_id,
                anchor_pin,
            )?;
            Ok(ResolvedLaunchResources {
                workspace: ResolvedWorkspace::from_pinned(
                    "/run/aos/sandbox-pins/workspaces/test-root".to_owned(),
                    workspace_identity.st_dev,
                    workspace_identity.st_ino,
                    workspace_pin,
                )?,
                network: ResolvedNetwork::from_pinned(
                    "/run/aos/sandbox-pins/netns/test-net".to_owned(),
                    network_identity.device,
                    network_identity.inode,
                    network_pin,
                )?,
                identity: ResolvedIdentityAllocation {
                    range_start: 65_536,
                    range_size: 65_536,
                    catalog_generation: 1,
                },
                attachment_anchor,
            })
        }

        fn export_root_mount(
            &self,
            workspace: &ResolvedWorkspace,
        ) -> Result<aos_sandbox_linux::mount::DetachedMount> {
            // Unit tests exercise durable ordering without invoking nspawn.
            // Production FileHostCatalog uses Storage's authenticated export.
            let descriptor = workspace
                .pin()
                .try_clone_to_owned()
                .map_err(|error| HostError::Catalog(error.to_string()))?;
            aos_sandbox_linux::mount::DetachedMount::from_inherited(descriptor)
                .map_err(|error| HostError::Catalog(error.to_string()))
        }
    }

    #[derive(Clone, Default)]
    struct FakeWorker {
        calls: Arc<AtomicUsize>,
        fail_next: Arc<AtomicBool>,
        observe_calls: Arc<Mutex<Vec<[u8; 16]>>>,
        fail_observe_at: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl HostWorker for FakeWorker {
        async fn execute(
            &self,
            fence: &ValidatedAssignmentFence,
            operation: WorkerOperation,
            before_effect: &mut (dyn FnMut() -> Result<()> + Send),
        ) -> Result<WorkerObservation> {
            let state = match operation {
                WorkerOperation::Launch { spec, pins } => {
                    let descriptor_prefix =
                        format!("/proc/{}/fd/", rustix::process::getpid().as_raw_nonzero());
                    assert!(spec.executable().starts_with(&descriptor_prefix));
                    let expected_machine = format!(
                        "--machine=aos-{}",
                        fence
                            .incarnation_id()
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    );
                    let expected_arguments = vec![
                        "--boot",
                        "--quiet",
                        "--keep-unit",
                        "--register=no",
                        "--settings=no",
                        expected_machine.as_str(),
                        "--aos-root-mount-fd=aos-sandbox-root-mount-v1",
                        "--private-users=65536:65536",
                        "--private-users-ownership=map",
                        "--notify-ready=yes",
                        "--selinux-context=system_u:system_r:aos_sandbox_payload_t:s0",
                        "--no-new-privileges=yes",
                        "--drop-capability=CAP_AUDIT_CONTROL,CAP_AUDIT_READ,CAP_AUDIT_WRITE,CAP_BLOCK_SUSPEND,CAP_BPF,CAP_CHECKPOINT_RESTORE,CAP_DAC_READ_SEARCH,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_LEASE,CAP_LINUX_IMMUTABLE,CAP_MAC_ADMIN,CAP_MAC_OVERRIDE,CAP_MKNOD,CAP_NET_ADMIN,CAP_NET_BROADCAST,CAP_NET_RAW,CAP_PERFMON,CAP_SYSLOG,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_CHROOT,CAP_SYS_MODULE,CAP_SYS_NICE,CAP_SYS_PACCT,CAP_SYS_PTRACE,CAP_SYS_RAWIO,CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_WAKE_ALARM",
                        "--system-call-filter=~@mount @module @raw-io @reboot bpf perf_event_open ptrace setns unshare",
                        "--aos-payload-seccomp-profile=aos-sandbox-payload-v1",
                        "--aos-lifecycle-profile=aos-sandbox-lifecycle-v1",
                        "--aos-attachment-anchor-fd=aos-sandbox-attachment-anchor-v1",
                    ];
                    let _attachment_anchor = pins.attachment_anchor();
                    assert_eq!(spec.arguments(), expected_arguments);
                    assert!(spec.root_directory().starts_with(&descriptor_prefix));
                    assert!(
                        spec.network_namespace_path()
                            .starts_with(&descriptor_prefix)
                    );
                    ObservedRuntimeState::Ready
                }
                WorkerOperation::Stop | WorkerOperation::Kill => ObservedRuntimeState::Exited,
                WorkerOperation::Freeze => ObservedRuntimeState::Frozen,
                WorkerOperation::Thaw => ObservedRuntimeState::Ready,
            };
            before_effect()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(HostError::Worker("injected crash boundary".to_owned()));
            }
            Ok(WorkerObservation {
                state,
                invocation_id: Some([9; 16]),
                leader: None,
                payload: None,
            })
        }

        async fn observe(&self, identity: &HostRuntimeIdentity) -> Result<WorkerObservation> {
            let call = {
                let mut calls = self.observe_calls.lock().unwrap();
                calls.push(*identity.sandbox_id());
                calls.len()
            };
            if self.fail_observe_at.load(Ordering::SeqCst) == call {
                return Err(HostError::Worker("injected observation failure".to_owned()));
            }
            Ok(WorkerObservation {
                state: ObservedRuntimeState::Ready,
                invocation_id: Some([9; 16]),
                leader: None,
                payload: None,
            })
        }

        async fn refresh_payload_scope(
            &self,
            _identity: &HostRuntimeIdentity,
            _invocation_id: [u8; 16],
            _supervisor: &PinnedLeader,
            _payload: &PinnedPayloadLeader,
        ) -> Result<WorkerObservation> {
            Err(HostError::Worker(
                "fake worker has no retained payload proof".to_owned(),
            ))
        }
    }

    #[derive(Clone)]
    struct GuardianWorker {
        store: GuardianRecordingStore,
        starts: Arc<AtomicUsize>,
        payload_effects: Arc<AtomicUsize>,
        binding: Arc<Mutex<Option<[u8; 32]>>>,
        guardian_alive: Arc<AtomicBool>,
        guardian_terminal: Arc<AtomicBool>,
        guardian_start_mode: Arc<AtomicUsize>,
        payload_started: Arc<AtomicBool>,
        payload_frozen: Arc<AtomicBool>,
        fail_payload_start: Arc<AtomicBool>,
        disappear_after_payload_start: Arc<AtomicBool>,
        kill_guardian_after_payload_start: Arc<AtomicBool>,
        disappear_during_payload_proof: Arc<AtomicBool>,
        ordering_events: Arc<Mutex<Vec<&'static str>>>,
        stop_roles: Arc<Mutex<Vec<ExactUnitRole>>>,
        fail_stop_once: Arc<AtomicBool>,
        residual_stop_once: Arc<AtomicBool>,
    }

    impl GuardianWorker {
        fn new(store: GuardianRecordingStore) -> Self {
            Self {
                store,
                starts: Arc::new(AtomicUsize::new(0)),
                payload_effects: Arc::new(AtomicUsize::new(0)),
                binding: Arc::new(Mutex::new(None)),
                guardian_alive: Arc::new(AtomicBool::new(false)),
                guardian_terminal: Arc::new(AtomicBool::new(false)),
                guardian_start_mode: Arc::new(AtomicUsize::new(0)),
                payload_started: Arc::new(AtomicBool::new(false)),
                payload_frozen: Arc::new(AtomicBool::new(false)),
                fail_payload_start: Arc::new(AtomicBool::new(false)),
                disappear_after_payload_start: Arc::new(AtomicBool::new(false)),
                kill_guardian_after_payload_start: Arc::new(AtomicBool::new(false)),
                disappear_during_payload_proof: Arc::new(AtomicBool::new(false)),
                ordering_events: Arc::new(Mutex::new(Vec::new())),
                stop_roles: Arc::new(Mutex::new(Vec::new())),
                fail_stop_once: Arc::new(AtomicBool::new(false)),
                residual_stop_once: Arc::new(AtomicBool::new(false)),
            }
        }

        fn payload_verification(
            &self,
            binding: [u8; 32],
        ) -> crate::worker::BoundPayloadVerification {
            crate::worker::BoundPayloadVerification {
                binding: Some(binding),
                invocation_id: [63; 16],
                observation: WorkerObservation {
                    state: ObservedRuntimeState::Ready,
                    invocation_id: Some([63; 16]),
                    leader: None,
                    payload: None,
                },
                proof: Self::runtime_proof(),
                shifted_payload_inspection: None,
            }
        }

        fn runtime_proof() -> RuntimeProofSnapshot {
            RuntimeProofSnapshot {
                host_boot_id: [64; 16],
                supervisor: ProcessProofSnapshot {
                    pid: 65,
                    thread_group_id: 65,
                    parent_pid: 1,
                    cgroup_id: 66,
                    start_time_ticks: 67,
                },
                payload: ProcessProofSnapshot {
                    pid: 68,
                    thread_group_id: 68,
                    parent_pid: 65,
                    cgroup_id: 69,
                    start_time_ticks: 70,
                },
                supervisor_cgroup_id: 66,
                payload_cgroup_id: 69,
                workspace_mount_id: 71,
                payload_root_mount_id: 72,
                network_namespace: NamespaceProofSnapshot {
                    device: 73,
                    inode: 74,
                },
                mount_namespace: NamespaceProofSnapshot {
                    device: 75,
                    inode: 76,
                },
                user_namespace: NamespaceProofSnapshot {
                    device: 77,
                    inode: 78,
                },
            }
        }
    }

    #[async_trait]
    impl HostWorker for GuardianWorker {
        async fn execute(
            &self,
            _fence: &ValidatedAssignmentFence,
            operation: WorkerOperation,
            before_effect: &mut (dyn FnMut() -> Result<()> + Send),
        ) -> Result<WorkerObservation> {
            let state = match operation {
                WorkerOperation::Freeze => {
                    before_effect()?;
                    assert!(self.payload_started.load(Ordering::SeqCst));
                    self.payload_frozen.store(true, Ordering::SeqCst);
                    ObservedRuntimeState::Frozen
                }
                WorkerOperation::Thaw => {
                    before_effect()?;
                    assert!(self.payload_started.load(Ordering::SeqCst));
                    self.payload_frozen.store(false, Ordering::SeqCst);
                    ObservedRuntimeState::Ready
                }
                WorkerOperation::Stop | WorkerOperation::Kill => {
                    before_effect()?;
                    self.payload_started.store(false, Ordering::SeqCst);
                    self.payload_frozen.store(false, Ordering::SeqCst);
                    ObservedRuntimeState::Exited
                }
                WorkerOperation::Launch { .. } => {
                    return Err(HostError::Worker(
                        "Guardian integration test reached direct payload launch".to_owned(),
                    ));
                }
            };
            Ok(WorkerObservation {
                state,
                invocation_id: Some([63; 16]),
                leader: None,
                payload: None,
            })
        }

        async fn observe(&self, _identity: &HostRuntimeIdentity) -> Result<WorkerObservation> {
            Ok(WorkerObservation {
                state: ObservedRuntimeState::Absent,
                invocation_id: None,
                leader: None,
                payload: None,
            })
        }

        async fn refresh_payload_scope(
            &self,
            _identity: &HostRuntimeIdentity,
            _invocation_id: [u8; 16],
            _supervisor: &PinnedLeader,
            _payload: &PinnedPayloadLeader,
        ) -> Result<WorkerObservation> {
            Err(HostError::Worker(
                "Guardian integration test has no payload proof".to_owned(),
            ))
        }

        async fn observe_guardian(
            &self,
            _identity: &HostRuntimeIdentity,
        ) -> Result<GuardianObservation> {
            self.ordering_events
                .lock()
                .unwrap()
                .push("observe_guardian");
            let binding = *self.binding.lock().unwrap();
            Ok(
                match (
                    binding,
                    self.guardian_alive.load(Ordering::SeqCst),
                    self.guardian_terminal.load(Ordering::SeqCst),
                ) {
                    (Some(binding), true, false) => GuardianObservation {
                        binding: Some(binding),
                        invocation_id: Some([62; 16]),
                        state: GuardianObservedState::ActiveRunning,
                    },
                    (Some(binding), true, true) => GuardianObservation {
                        binding: Some(binding),
                        invocation_id: Some([62; 16]),
                        state: GuardianObservedState::TerminalFailed,
                    },
                    (None, _, _) | (Some(_), false, _) => GuardianObservation {
                        binding: None,
                        invocation_id: None,
                        state: GuardianObservedState::Absent,
                    },
                },
            )
        }

        async fn start_guardian(
            &self,
            spec: &GuardianUnitSpec,
            _identity: &HostRuntimeIdentity,
            before_effect: &mut (dyn FnMut() -> Result<()> + Send),
        ) -> Result<crate::worker::GuardianStartObservation> {
            before_effect()?;
            assert_eq!(
                self.store.phases.lock().unwrap().as_slice(),
                [
                    GuardianLaunchPhase::Authorized,
                    GuardianLaunchPhase::GuardianStartIssued,
                ]
            );
            self.starts.fetch_add(1, Ordering::SeqCst);
            match self.guardian_start_mode.load(Ordering::SeqCst) {
                1 => Ok(crate::worker::GuardianStartObservation {
                    job_done: false,
                    observation: GuardianObservation {
                        binding: None,
                        invocation_id: None,
                        state: GuardianObservedState::Absent,
                    },
                }),
                2 => {
                    *self.binding.lock().unwrap() = Some(spec.binding());
                    self.guardian_alive.store(true, Ordering::SeqCst);
                    self.guardian_terminal.store(true, Ordering::SeqCst);
                    Ok(crate::worker::GuardianStartObservation {
                        job_done: false,
                        observation: GuardianObservation {
                            binding: Some(spec.binding()),
                            invocation_id: Some([62; 16]),
                            state: GuardianObservedState::TerminalFailed,
                        },
                    })
                }
                3 => Err(HostError::Worker(
                    "injected ambiguous Guardian start failure".to_owned(),
                )),
                _ => {
                    *self.binding.lock().unwrap() = Some(spec.binding());
                    self.guardian_alive.store(true, Ordering::SeqCst);
                    Ok(crate::worker::GuardianStartObservation {
                        job_done: true,
                        observation: GuardianObservation {
                            binding: Some(spec.binding()),
                            invocation_id: Some([62; 16]),
                            state: GuardianObservedState::ActiveRunning,
                        },
                    })
                }
            }
        }

        async fn observe_bound_payload(
            &self,
            _identity: &HostRuntimeIdentity,
        ) -> Result<GuardianObservation> {
            let binding = *self.binding.lock().unwrap();
            Ok(if self.payload_started.load(Ordering::SeqCst) {
                GuardianObservation {
                    binding,
                    invocation_id: Some([63; 16]),
                    state: GuardianObservedState::ActiveRunning,
                }
            } else {
                GuardianObservation {
                    binding: None,
                    invocation_id: None,
                    state: GuardianObservedState::Absent,
                }
            })
        }

        async fn start_bound_payload(
            &self,
            spec: &aos_systemd::SandboxUnitSpec,
            _pins: &crate::plan::LaunchPins,
            _identity: &HostRuntimeIdentity,
            guardian_invocation_id: [u8; 16],
            before_effect: &mut (dyn FnMut() -> Result<()> + Send),
        ) -> Result<crate::worker::CurrentJobDone> {
            before_effect()?;
            let binding = spec.launch_binding().unwrap();
            assert_eq!(*self.binding.lock().unwrap(), Some(binding));
            assert_eq!(guardian_invocation_id, [62; 16]);
            self.payload_effects.fetch_add(1, Ordering::SeqCst);
            self.payload_started.store(true, Ordering::SeqCst);
            if self.disappear_after_payload_start.load(Ordering::SeqCst) {
                self.payload_started.store(false, Ordering::SeqCst);
            }
            if self
                .kill_guardian_after_payload_start
                .load(Ordering::SeqCst)
            {
                self.guardian_alive.store(false, Ordering::SeqCst);
            }
            if self.fail_payload_start.load(Ordering::SeqCst) {
                return Err(HostError::Worker(
                    "injected ambiguous payload start failure".to_owned(),
                ));
            }
            let result = crate::worker::CurrentJobDone {
                verification: self.payload_verification(binding),
            };
            Ok(result)
        }

        async fn prove_bound_payload(
            &self,
            spec: &aos_systemd::SandboxUnitSpec,
            _pins: &crate::plan::LaunchPins,
            identity: &HostRuntimeIdentity,
        ) -> Result<crate::worker::RecoveredExactProof> {
            self.ordering_events.lock().unwrap().push("prove_payload");
            let first = self.observe_bound_payload(identity).await?;
            if self.disappear_during_payload_proof.load(Ordering::SeqCst) {
                self.payload_started.store(false, Ordering::SeqCst);
            }
            let second = self.observe_bound_payload(identity).await?;
            let binding = spec.launch_binding().unwrap();
            if first.binding != Some(binding)
                || first.state != GuardianObservedState::ActiveRunning
                || second != first
            {
                return Err(HostError::Worker(
                    "recovered payload changed during observation-only proof".to_owned(),
                ));
            }

            Ok(crate::worker::RecoveredExactProof {
                verification: self.payload_verification(binding),
            })
        }

        async fn recover_completed_payload(
            &self,
            identity: &HostRuntimeIdentity,
            binding: [u8; 32],
            guardian_invocation_id: [u8; 16],
            payload_invocation_id: [u8; 16],
            expected_proof: crate::worker::CompletedRuntimeProof,
        ) -> Result<crate::worker::RecoveredExactProof> {
            self.ordering_events.lock().unwrap().push("recover_payload");
            let guardian = self.observe_guardian(identity).await?;
            let payload = self.observe_bound_payload(identity).await?;
            if guardian.binding != Some(binding)
                || guardian.invocation_id != Some(guardian_invocation_id)
                || guardian.state != GuardianObservedState::ActiveRunning
                || payload.binding != Some(binding)
                || payload.invocation_id != Some(payload_invocation_id)
                || payload.state != GuardianObservedState::ActiveRunning
            {
                return Err(HostError::Worker(
                    "fake completed payload is not exact and active".to_owned(),
                ));
            }
            let verification = self.payload_verification(binding);
            if verification.proof != expected_proof.snapshot() {
                return Err(HostError::Worker(
                    "fake completed payload proof changed".to_owned(),
                ));
            }
            Ok(crate::worker::RecoveredExactProof { verification })
        }

        async fn stop_exact_unit(
            &self,
            _identity: &HostRuntimeIdentity,
            role: ExactUnitRole,
            binding: [u8; 32],
            invocation_id: [u8; 16],
        ) -> Result<ExactWorkerStopOutcome> {
            assert_eq!(*self.binding.lock().unwrap(), Some(binding));
            let expected_invocation = match role {
                ExactUnitRole::Payload => [63; 16],
                ExactUnitRole::Guardian => [62; 16],
            };
            assert_eq!(invocation_id, expected_invocation);
            if self.fail_stop_once.swap(false, Ordering::SeqCst) {
                return Err(HostError::Worker(
                    "injected crash before exact stop".to_owned(),
                ));
            }
            self.stop_roles.lock().unwrap().push(role);
            match role {
                ExactUnitRole::Payload => {
                    self.payload_started.store(false, Ordering::SeqCst);
                }
                ExactUnitRole::Guardian => {
                    self.guardian_alive.store(false, Ordering::SeqCst);
                    self.guardian_terminal.store(false, Ordering::SeqCst);
                }
            }
            if self.residual_stop_once.swap(false, Ordering::SeqCst) {
                return Ok(ExactWorkerStopOutcome::Residual(GuardianObservation {
                    binding: Some(binding),
                    invocation_id: Some(invocation_id),
                    state: GuardianObservedState::TerminalInactive,
                }));
            }
            Ok(ExactWorkerStopOutcome::AwaitingAbsence(
                GuardianObservation {
                    binding: Some(binding),
                    invocation_id: Some(invocation_id),
                    state: GuardianObservedState::TerminalInactive,
                },
            ))
        }

        async fn observe_post_unref(
            &self,
            identity: &HostRuntimeIdentity,
            role: ExactUnitRole,
        ) -> Result<GuardianObservation> {
            match role {
                ExactUnitRole::Payload => self.observe_bound_payload(identity).await,
                ExactUnitRole::Guardian => self.observe_guardian(identity).await,
            }
        }
    }

    fn nspawn() -> NspawnConfig {
        NspawnConfig::for_tests("/nix/store/aos-systemd/bin/systemd-nspawn").unwrap()
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    const TEST_NODE: NodeId = NodeId::from_bytes([31; 16]);
    const TEST_WALL_SECONDS: i64 = 150;
    const TEST_BOOTTIME_NANOSECONDS: u64 = 100;

    struct AuthorityFixture {
        plan_key: SigningKey,
        lease_key: SigningKey,
        alternate_lease_key: SigningKey,
        plan_signer: KeyReference,
        lease_signer: KeyReference,
        alternate_lease_signer: KeyReference,
        plan_policy: Vec<u8>,
        plan_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        plan_scope: TrustScopeId,
        lease_policy: Vec<u8>,
        lease_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        lease_scope: TrustScopeId,
        revocation_scope: RevocationScopeId,
    }

    impl AuthorityFixture {
        fn new() -> Self {
            let plan_key = SigningKey::from_bytes(&[41; 32]);
            let lease_key = SigningKey::from_bytes(&[42; 32]);
            let alternate_lease_key = SigningKey::from_bytes(&[52; 32]);
            let plan_signer = key_reference(
                "host-plan-controller",
                3,
                KeyUsage::BrokerAuthorization,
                &plan_key,
            );
            let lease_signer = key_reference(
                "host-ownership-authority",
                7,
                KeyUsage::OwnershipLease,
                &lease_key,
            );
            let alternate_lease_signer = key_reference(
                "host-ownership-alternate",
                8,
                KeyUsage::OwnershipLease,
                &alternate_lease_key,
            );
            let plan_scope = TrustScopeId::from_bytes([43; 16]);
            let lease_scope = TrustScopeId::from_bytes([44; 16]);
            let (plan_policy, plan_policy_descriptor) = trust_policy(
                plan_scope,
                SignaturePurpose::BrokerAuthorization,
                plan_signer.clone(),
            );
            let (lease_policy, lease_policy_descriptor) = trust_policy_many(
                lease_scope,
                SignaturePurpose::OwnershipLease,
                vec![lease_signer.clone(), alternate_lease_signer.clone()],
            );
            Self {
                plan_key,
                lease_key,
                alternate_lease_key,
                plan_signer,
                lease_signer,
                alternate_lease_signer,
                plan_policy,
                plan_policy_descriptor,
                plan_scope,
                lease_policy,
                lease_policy_descriptor,
                lease_scope,
                revocation_scope: RevocationScopeId::from_bytes([45; 16]),
            }
        }

        fn authority(&self) -> HostAuthorityV1 {
            let plan_anchor = aos_sandbox_core::BrokerPlanTrustAnchor::from_trusted_configuration(
                self.plan_policy.clone(),
                self.plan_policy_descriptor.clone(),
                self.plan_scope,
                self.plan_signer.clone(),
                self.plan_key.verifying_key().to_bytes(),
                self.revocation_scope,
                DecodeLimits::default(),
            )
            .unwrap();
            let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
                self.lease_policy.clone(),
                self.lease_policy_descriptor.clone(),
                self.lease_scope,
                self.lease_signer.clone(),
                self.lease_key.verifying_key().to_bytes(),
                DecodeLimits::default(),
            )
            .unwrap();
            HostAuthorityV1::new(plan_anchor, lease_anchor, TEST_NODE, [46; 16], [47; 32]).unwrap()
        }

        fn protected_authority(&self, directory: &Path) -> HostAuthorityV1 {
            let plan_public_key = self.plan_key.verifying_key().to_bytes();
            let lease_public_key = self.lease_key.verifying_key().to_bytes();
            let mut journal_key = Vec::with_capacity(48);
            journal_key.extend_from_slice(&[46; 16]);
            journal_key.extend_from_slice(&[47; 32]);
            for (name, bytes) in [
                ("broker-plan-policy.cbor", self.plan_policy.as_slice()),
                ("broker-plan-public-key", plan_public_key.as_slice()),
                ("broker-revocation-scope", self.revocation_scope.as_bytes()),
                ("ownership-lease-policy.cbor", self.lease_policy.as_slice()),
                ("ownership-lease-public-key", lease_public_key.as_slice()),
                ("node-id", TEST_NODE.as_bytes()),
                ("journal-mac-key", journal_key.as_slice()),
            ] {
                let path = directory.join(name);
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
            }
            std::fs::set_permissions(directory, Permissions::from_mode(0o700)).unwrap();
            HostAuthorityV1::from_protected_directory(directory).unwrap()
        }

        fn artifacts(
            &self,
            request_bytes: &[u8],
            lease_generation: u64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_with_lease_authority(request_bytes, lease_generation, false)
        }

        fn artifacts_with_lease_authority(
            &self,
            request_bytes: &[u8],
            lease_generation: u64,
            alternate: bool,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let validated =
                decode_runtime_request(request_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
                    .unwrap();
            let semantics =
                crate::authorization::semantics_v1::canonical_host_semantics_v1(&validated)
                    .unwrap();
            let assignment = BrokerAssignment::new(
                SandboxId::from_bytes(*validated.fence().sandbox_id()),
                IncarnationId::from_bytes(*validated.fence().incarnation_id()),
                AssignmentEpoch::new(validated.fence().assignment_epoch()),
                DesiredGeneration::new(validated.fence().desired_generation()),
                ObjectDigest::from_bytes(*validated.fence().assignment_digest()),
            )
            .unwrap();
            let grant = BrokerGrant::new(
                semantics.verb(),
                semantics.target(),
                semantics.commitment(),
                u32::try_from(request_bytes.len()).unwrap(),
                0,
            )
            .unwrap();
            let (lease_signer, lease_key) = if alternate {
                (&self.alternate_lease_signer, &self.alternate_lease_key)
            } else {
                (&self.lease_signer, &self.lease_key)
            };
            let plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Host,
                ProtocolId::HostBroker,
                ProtocolVersion::new(1, 0),
                assignment,
                TEST_NODE,
                lease_signer.clone(),
                vec![grant],
                ObjectDigest::from_bytes([48; 32]),
                self.revocation_scope,
                100,
                300,
                Vec::new(),
            )
            .unwrap();
            let broker_plan = encode_broker_authorization_plan(&plan);
            let broker_plan_signature = signed_object(
                &broker_plan,
                PortableMediaType::BrokerAuthorizationPlan,
                self.plan_scope,
                self.plan_signer.clone(),
                SignaturePurpose::BrokerAuthorization,
                &self.plan_policy_descriptor,
                &self.plan_key,
            );
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                TEST_NODE,
                lease_generation,
                100,
                300,
                10,
                [u8::try_from(lease_generation).unwrap_or(255); 16],
            )
            .unwrap();
            let ownership_lease = encode_ownership_lease(&lease);
            let ownership_lease_signature = signed_object(
                &ownership_lease,
                PortableMediaType::OwnershipLease,
                self.lease_scope,
                lease_signer.clone(),
                SignaturePurpose::OwnershipLease,
                &self.lease_policy_descriptor,
                lease_key,
            );
            validated_artifacts(BrokerAuthorizationArtifactsV1 {
                broker_plan,
                broker_plan_signature,
                ownership_lease,
                ownership_lease_signature,
                ..Default::default()
            })
        }

        fn guardian_request_and_artifacts(
            &self,
            request_id: u8,
        ) -> (Vec<u8>, ValidatedUntrustedAuthorizationArtifacts) {
            let assignment = BrokerAssignment::new(
                SandboxId::from_bytes([2; 16]),
                IncarnationId::from_bytes([3; 16]),
                AssignmentEpoch::new(1),
                DesiredGeneration::new(1),
                ObjectDigest::from_bytes([4; 32]),
            )
            .unwrap();
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                TEST_NODE,
                1,
                100,
                300,
                10,
                [1; 16],
            )
            .unwrap();
            let ownership_lease = encode_ownership_lease(&lease);
            let ownership_lease_signature = signed_object(
                &ownership_lease,
                PortableMediaType::OwnershipLease,
                self.lease_scope,
                self.lease_signer.clone(),
                SignaturePurpose::OwnershipLease,
                &self.lease_policy_descriptor,
                &self.lease_key,
            );
            let lease_digest = descriptor_for_bytes(
                MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
                &ownership_lease,
            )
            .digest();
            let guardian_binding = GuardianPlanBinding::new(
                assignment,
                TEST_NODE,
                clock().host_boot_id(),
                1,
                lease_digest,
            )
            .unwrap();
            let guardian_plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Guardian,
                ProtocolId::Guardian,
                ProtocolVersion::new(1, 0),
                assignment,
                TEST_NODE,
                self.lease_signer.clone(),
                vec![
                    BrokerGrant::new(
                        BrokerVerb::GuardianArm,
                        BrokerGrantTarget::Assignment,
                        guardian_binding.commitment(),
                        guardian_binding.encoded_len(),
                        4,
                    )
                    .unwrap(),
                ],
                ObjectDigest::from_bytes([58; 32]),
                self.revocation_scope,
                100,
                300,
                Vec::new(),
            )
            .unwrap();
            let guardian_plan = encode_broker_authorization_plan(&guardian_plan);
            let guardian_plan_signature = signed_object(
                &guardian_plan,
                PortableMediaType::BrokerAuthorizationPlan,
                self.plan_scope,
                self.plan_signer.clone(),
                SignaturePurpose::BrokerAuthorization,
                &self.plan_policy_descriptor,
                &self.plan_key,
            );

            let base_request = request_at_protocol(request_id, 2, ProtocolVersion::new(1, 0));
            let request = encode_host_guardian_companion_v1(
                &base_request,
                &guardian_plan,
                &guardian_plan_signature,
            )
            .unwrap();
            let validated =
                decode_runtime_request(&request, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
                    .unwrap();
            let semantics =
                crate::authorization::semantics_v1::canonical_host_semantics_v1(&validated)
                    .unwrap();
            let host_plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Host,
                ProtocolId::HostBroker,
                ProtocolVersion::new(1, 0),
                assignment,
                TEST_NODE,
                self.lease_signer.clone(),
                vec![
                    BrokerGrant::new(
                        semantics.verb(),
                        semantics.target(),
                        semantics.commitment(),
                        u32::try_from(MAXIMUM_REQUEST_BYTES).unwrap(),
                        0,
                    )
                    .unwrap(),
                ],
                ObjectDigest::from_bytes([59; 32]),
                self.revocation_scope,
                100,
                300,
                Vec::new(),
            )
            .unwrap();
            let broker_plan = encode_broker_authorization_plan(&host_plan);
            let broker_plan_signature = signed_object(
                &broker_plan,
                PortableMediaType::BrokerAuthorizationPlan,
                self.plan_scope,
                self.plan_signer.clone(),
                SignaturePurpose::BrokerAuthorization,
                &self.plan_policy_descriptor,
                &self.plan_key,
            );
            let artifacts = validated_artifacts(BrokerAuthorizationArtifactsV1 {
                broker_plan,
                broker_plan_signature,
                ownership_lease,
                ownership_lease_signature,
                ..Default::default()
            });
            (request, artifacts)
        }
    }

    fn key_reference(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(id.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn trust_policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        signer: KeyReference,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        trust_policy_many(scope, purpose, vec![signer])
    }

    fn trust_policy_many(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        mut signers: Vec<KeyReference>,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        signers.sort_by(|left, right| {
            (left.stable_key_id(), left.generation())
                .cmp(&(right.stable_key_id(), right.generation()))
        });
        let bytes =
            encode_trust_policy(&TrustPolicy::new(scope, purpose, signers, Vec::new()).unwrap());
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_object(
        bytes: &[u8],
        media_type: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy: &aos_sandbox_core::ObjectDescriptor,
        key: &SigningKey,
    ) -> Vec<u8> {
        let subject = descriptor_for_bytes(
            MediaType::new(media_type.as_str().to_owned()).unwrap(),
            bytes,
        );
        let statement = SignatureStatement::new(
            subject,
            scope,
            signer,
            purpose,
            100,
            Some(300),
            policy.clone(),
        )
        .unwrap();
        encode_signature(&sign_statement(statement, key).unwrap())
    }

    fn validated_artifacts(
        artifacts: BrokerAuthorizationArtifactsV1,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::HostBroker, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }

    fn clock() -> RawPairedClockSample {
        clock_at(TEST_WALL_SECONDS, TEST_BOOTTIME_NANOSECONDS)
    }

    fn clock_at(wall_seconds: i64, boottime_nanoseconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([49; 16]).unwrap(),
            [50; 16],
            wall_seconds,
            boottime_nanoseconds,
        )
        .unwrap()
    }

    async fn apply<C: HostCatalog, S: HostStateStore, W: HostWorker + Sync>(
        broker: &mut HostBroker<C, S, W>,
        fixture: &AuthorityFixture,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        apply_generation(broker, fixture, request_bytes, 1).await
    }

    async fn apply_generation<C: HostCatalog, S: HostStateStore, W: HostWorker + Sync>(
        broker: &mut HostBroker<C, S, W>,
        fixture: &AuthorityFixture,
        request_bytes: &[u8],
        lease_generation: u64,
    ) -> Result<Vec<u8>> {
        let artifacts = fixture.artifacts(request_bytes, lease_generation);
        broker
            .apply_runtime(
                request_bytes,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
    }

    async fn apply_protocol<C: HostCatalog, S: HostStateStore, W: HostWorker + Sync>(
        broker: &mut HostBroker<C, S, W>,
        fixture: &AuthorityFixture,
        request_bytes: &[u8],
        protocol_version: ProtocolVersion,
    ) -> Result<Vec<u8>> {
        let artifacts = fixture.artifacts(request_bytes, 1);
        broker
            .apply_runtime(
                request_bytes,
                &artifacts,
                protocol_version,
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
    }

    fn runtime_identity(request_bytes: &[u8]) -> HostRuntimeIdentity {
        let request =
            decode_runtime_request(request_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
                .unwrap();
        HostRuntimeIdentity::from(request.fence())
    }

    fn request(request_id: u8, generation: u64, digest: u8) -> Vec<u8> {
        request_with_sandbox(request_id, generation, digest, 2, 65_536, 65_536)
    }

    fn request_at_protocol(
        request_id: u8,
        sandbox_id: u8,
        protocol_version: ProtocolVersion,
    ) -> Vec<u8> {
        let bytes = launch_request_with_sandbox(request_id, 1, 4, sandbox_id, 65_536, 65_536);
        let mut request = ApplyRuntimeRequest::decode_from_slice(&bytes).unwrap();
        let header = request.header.get_or_insert_default();
        header.protocol_major = u32::from(protocol_version.major());
        header.protocol_minor = u32::from(protocol_version.minor());
        request
            .launch_plan
            .get_or_insert_default()
            .attachment_anchor_handle = vec![12; 32];
        request.encode_to_vec()
    }

    fn request_with_sandbox(
        request_id: u8,
        generation: u64,
        digest: u8,
        sandbox_id: u8,
        uid_range_start: u32,
        uid_range_size: u32,
    ) -> Vec<u8> {
        let bytes = launch_request_with_sandbox(
            request_id,
            generation,
            digest,
            sandbox_id,
            uid_range_start,
            uid_range_size,
        );
        let mut request = ApplyRuntimeRequest::decode_from_slice(&bytes).unwrap();
        request.action = RuntimeAction::RUNTIME_ACTION_FREEZE.into();
        request.launch_plan = Default::default();
        request.encode_to_vec()
    }

    fn launch_request_with_sandbox(
        request_id: u8,
        generation: u64,
        digest: u8,
        sandbox_id: u8,
        uid_range_start: u32,
        uid_range_size: u32,
    ) -> Vec<u8> {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![request_id; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 1000;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![sandbox_id; 16];
        fence.incarnation_id = vec![sandbox_id.wrapping_add(1); 16];
        fence.assignment_epoch = 1;
        fence.desired_generation = generation;
        fence.assignment_digest = vec![digest; 32];
        request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
        let plan = request.launch_plan.get_or_insert_default();
        let root = plan.root_image.get_or_insert_default();
        root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
        root.sha256 = vec![5; 32];
        root.encoded_size = 10;
        plan.workspace_handle = vec![6; 32];
        plan.network_handle = vec![7; 32];
        plan.uid_range_start = uid_range_start;
        plan.uid_range_size = uid_range_size;
        plan.limits = vec![
            ResourceLimit {
                dimension: 2,
                value: 128,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 3,
                value: 1 << 30,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 4,
                value: 100,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 9,
                value: 1024,
                ..Default::default()
            },
        ];
        plan.required_features.push(Feature {
            namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        });
        request.encode_to_vec()
    }

    fn request_with_sandbox_and_incarnation(
        request_id: u8,
        sandbox_id: u8,
        incarnation_id: u8,
        assignment_epoch: u64,
    ) -> Vec<u8> {
        let bytes = request_with_sandbox(request_id, 1, 4, sandbox_id, 65_536, 65_536);
        let mut request = ApplyRuntimeRequest::decode_from_slice(&bytes).unwrap();
        let fence = request.fence.get_or_insert_default();
        fence.incarnation_id = vec![incarnation_id; 16];
        fence.assignment_epoch = assignment_epoch;
        request.encode_to_vec()
    }

    fn request_with_action(
        request_id: u8,
        generation: u64,
        digest: u8,
        action: RuntimeAction,
    ) -> Vec<u8> {
        let mut request =
            ApplyRuntimeRequest::decode_from_slice(&request(request_id, generation, digest))
                .unwrap();
        request.action = action.into();
        request.launch_plan = Default::default();
        request.encode_to_vec()
    }

    fn discovered_runtime(incarnation: [u8; 16]) -> aos_systemd::DiscoveredSandboxUnit {
        let unit = aos_systemd::SandboxUnitName::from_incarnation(incarnation);
        aos_systemd::DiscoveredSandboxUnit {
            unit: unit.clone(),
            incarnation,
            object_path: format!("/org/freedesktop/systemd1/unit/{}", incarnation[0]),
            load_state: "loaded".to_owned(),
            active_state: "inactive".to_owned(),
            sub_state: "dead".to_owned(),
            freezer_state: aos_systemd::FreezerState::Running,
            cgroup: Some(unit.cgroup_path()),
            supervisor_pid: None,
            invocation_id: None,
        }
    }

    fn discovery(
        mut units: Vec<aos_systemd::DiscoveredSandboxUnit>,
    ) -> SandboxUnitDiscoverySnapshot {
        units.sort_by(|left, right| left.unit.cmp(&right.unit));
        SandboxUnitDiscoverySnapshot {
            units,
            conflicts: Vec::new(),
        }
    }

    #[test]
    fn failed_commit_latches_all_state_authority_unhealthy() {
        let fixture = AuthorityFixture::new();
        let mut broker = HostBroker::open(
            FixedCatalog,
            FailingStore,
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();

        assert!(broker.commit_state(&HostState::default()).is_err());
        assert!(broker.ensure_healthy().is_err());
        assert!(
            broker
                .payload_pin(&HostRuntimeIdentity::new([1; 16], [2; 16], 1, 1, [3; 32]))
                .is_none()
        );
        assert!(broker.leader(&[4; 32]).is_none());
    }

    #[tokio::test]
    async fn completed_request_replays_without_a_second_effect() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let bytes = request(1, 1, 4);
        let first = apply(&mut broker, &fixture, &bytes).await.unwrap();
        let replay = apply(&mut broker, &fixture, &bytes).await.unwrap();
        assert_eq!(first, replay);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let reopened_worker = FakeWorker::default();
        let reopened_calls = reopened_worker.calls.clone();
        let mut reopened = HostBroker::open(
            FixedCatalog,
            store.clone(),
            reopened_worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert_eq!(apply(&mut reopened, &fixture, &bytes).await.unwrap(), first);
        assert_eq!(reopened_calls.load(Ordering::SeqCst), 0);

        let unavailable_worker = FakeWorker::default();
        let unavailable_calls = unavailable_worker.calls.clone();
        let mut unavailable = HostBroker::open(
            FixedCatalog,
            store,
            unavailable_worker,
            None,
            fixture.authority(),
        )
        .unwrap();
        let unavailable_artifacts = fixture.artifacts(&bytes, 1);
        let unavailable_clock_calls = AtomicUsize::new(0);
        assert_eq!(
            unavailable
                .apply_runtime(
                    &bytes,
                    &unavailable_artifacts,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || {
                        unavailable_clock_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(clock())
                    },
                )
                .await
                .unwrap(),
            first
        );
        assert_eq!(unavailable_clock_calls.load(Ordering::SeqCst), 0);
        assert_eq!(unavailable_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn direct_lifecycle_does_not_require_the_launch_backend() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            None,
            fixture.authority(),
        )
        .unwrap();

        assert!(
            apply(&mut broker, &fixture, &request(1, 1, 4))
                .await
                .is_ok()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(store.load().unwrap().effect(&[1; 16]).is_some());

        let pending_store = MemoryStore::default();
        let failing_worker = FakeWorker::default();
        failing_worker.fail_next.store(true, Ordering::SeqCst);
        let mut admitting = HostBroker::open(
            FixedCatalog,
            pending_store.clone(),
            failing_worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let pending_request = request(2, 1, 5);
        assert!(
            apply(&mut admitting, &fixture, &pending_request)
                .await
                .is_err()
        );

        let denied_worker = FakeWorker::default();
        let denied_calls = denied_worker.calls.clone();
        let mut denied = HostBroker::open(
            FixedCatalog,
            pending_store,
            denied_worker,
            None,
            fixture.authority(),
        )
        .unwrap();
        let pending_artifacts = fixture.artifacts(&pending_request, 1);
        let pending_clock_calls = AtomicUsize::new(0);
        assert!(
            denied
                .apply_runtime(
                    &pending_request,
                    &pending_artifacts,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || {
                        pending_clock_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(clock())
                    },
                )
                .await
                .is_ok()
        );
        assert!(pending_clock_calls.load(Ordering::SeqCst) > 0);
        assert_eq!(denied_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn distinct_sandboxes_cannot_retain_the_same_runtime_incarnation() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let first = request_with_sandbox_and_incarnation(1, 2, 3, 1);
        let collision = request_with_sandbox_and_incarnation(2, 8, 3, 1);

        let receipt = apply(&mut broker, &fixture, &first).await.unwrap();
        let error = apply(&mut broker, &fixture, &collision).await.unwrap_err();
        assert!(matches!(
            error,
            HostError::Fence("runtime incarnation is already retained by another sandbox")
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(apply(&mut broker, &fixture, &first).await.unwrap(), receipt);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn historical_runtime_incarnation_remains_reserved_after_successor() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let original = request_with_sandbox_and_incarnation(1, 2, 3, 1);
        let successor = request_with_sandbox_and_incarnation(2, 2, 4, 2);
        let historical_collision = request_with_sandbox_and_incarnation(3, 8, 3, 1);

        apply(&mut broker, &fixture, &original).await.unwrap();
        apply(&mut broker, &fixture, &successor).await.unwrap();
        let report = broker
            .compare_runtime_discovery(discovery(vec![discovered_runtime([3; 16])]))
            .unwrap();
        assert!(report.current.is_empty());
        assert_eq!(report.missing.len(), 1);
        assert_eq!(
            report.missing[0].expected.identity.incarnation_id(),
            &[4; 16]
        );
        assert_eq!(report.historical_residuals.len(), 1);
        assert_eq!(report.historical_residuals[0].incarnation, [3; 16]);
        assert_eq!(report.historical_residuals[0].retained.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(broker.worker.observe_calls.lock().unwrap().is_empty());
        HostBroker::open(
            FixedCatalog,
            store,
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let error = apply(&mut broker, &fixture, &historical_collision)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            HostError::Fence("runtime incarnation is already retained by another sandbox")
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn kill_observation_remains_known_without_worker_calls() {
        for (action, expected_intent) in [(
            RuntimeAction::RUNTIME_ACTION_KILL,
            crate::recovery::RetainedRuntimeIntent::Kill,
        )] {
            let fixture = AuthorityFixture::new();
            let worker = FakeWorker::default();
            let calls = worker.calls.clone();
            let observations = worker.observe_calls.clone();
            let mut broker = HostBroker::open(
                FixedCatalog,
                MemoryStore::default(),
                worker,
                Some(nspawn()),
                fixture.authority(),
            )
            .unwrap();
            apply(&mut broker, &fixture, &request(1, 1, 4))
                .await
                .unwrap();
            apply(&mut broker, &fixture, &request_with_action(2, 2, 5, action))
                .await
                .unwrap();

            let report = broker
                .compare_runtime_discovery(discovery(vec![discovered_runtime([3; 16])]))
                .unwrap();
            assert_eq!(report.current.len(), 1);
            assert_eq!(report.current[0].expected.intent, expected_intent);
            assert_eq!(
                report.current[0].expected.durability,
                crate::recovery::RetainedEffectDurability::Complete
            );
            assert!(report.quarantine.is_empty());
            assert!(report.historical_residuals.is_empty());
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert!(observations.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn pending_current_effect_is_reported_without_retrying_it() {
        let fixture = AuthorityFixture::new();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let calls = worker.calls.clone();
        let observations = worker.observe_calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply(&mut broker, &fixture, &request(1, 1, 4))
                .await
                .is_err()
        );

        let report = broker
            .compare_runtime_discovery(discovery(Vec::new()))
            .unwrap();
        assert_eq!(report.missing.len(), 1);
        assert_eq!(
            report.missing[0].expected.durability,
            crate::recovery::RetainedEffectDurability::Pending
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(observations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn startup_rejects_authenticated_cross_sandbox_historical_collision() {
        let fixture = AuthorityFixture::new();
        let retained = MemoryStore::default();
        let mut first = HostBroker::open(
            FixedCatalog,
            retained.clone(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        apply(
            &mut first,
            &fixture,
            &request_with_sandbox_and_incarnation(1, 2, 3, 1),
        )
        .await
        .unwrap();
        apply(
            &mut first,
            &fixture,
            &request_with_sandbox_and_incarnation(2, 2, 4, 2),
        )
        .await
        .unwrap();

        let conflicting = MemoryStore::default();
        let mut second = HostBroker::open(
            FixedCatalog,
            conflicting.clone(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        apply(
            &mut second,
            &fixture,
            &request_with_sandbox_and_incarnation(3, 8, 3, 1),
        )
        .await
        .unwrap();

        retained
            .0
            .lock()
            .unwrap()
            .merge_retained_authority_for_test(&conflicting.0.lock().unwrap());
        let reopened = HostBroker::open(
            FixedCatalog,
            retained,
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        );
        assert!(matches!(
            reopened,
            Err(HostError::State(message))
                if message.contains("same current or historical runtime incarnation")
        ));
    }

    #[tokio::test]
    async fn observation_requires_the_exact_durable_runtime_handle() {
        let fixture = AuthorityFixture::new();
        let worker = FakeWorker::default();
        let observations = worker.observe_calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let bytes = request(1, 1, 4);
        apply(&mut broker, &fixture, &bytes).await.unwrap();
        let identity = runtime_identity(&bytes);
        let handle = runtime_handle(&identity);

        assert!(matches!(
            broker.observe_runtime(identity, [99; 32], 4_096).await,
            Err(HostError::UnknownHandle)
        ));
        assert!(observations.lock().unwrap().is_empty());
        let encoded = broker
            .observe_runtime(identity, handle, 4_096)
            .await
            .unwrap();
        let observation = RuntimeObservation::decode_from_slice(&encoded).unwrap();
        assert_eq!(observation.runtime_handle, handle);
        assert_eq!(observation.observation_sequence, 2);
        assert_eq!(observations.lock().unwrap().as_slice(), &[[2; 16]]);
    }

    #[tokio::test]
    async fn inventory_is_complete_ordered_bounded_and_atomic_on_failure() {
        let fixture = AuthorityFixture::new();
        let worker = FakeWorker::default();
        let store = MemoryStore::default();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store,
            worker.clone(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let first = request(1, 1, 4);
        let second = request_with_sandbox(2, 1, 4, 8, 65_536, 65_536);
        apply(&mut broker, &fixture, &first).await.unwrap();
        apply(&mut broker, &fixture, &second).await.unwrap();

        worker.fail_observe_at.store(2, Ordering::SeqCst);
        assert!(matches!(
            broker.inventory_runtime(4_096).await,
            Err(HostError::Worker(_))
        ));
        worker.fail_observe_at.store(0, Ordering::SeqCst);
        worker.observe_calls.lock().unwrap().clear();

        let encoded = broker.inventory_runtime(4_096).await.unwrap();
        let inventory = InventoryRuntimeResponse::decode_from_slice(&encoded).unwrap();
        assert_eq!(inventory.runtimes.len(), 2);
        assert!(
            inventory
                .runtimes
                .windows(2)
                .all(|pair| pair[0].runtime_handle < pair[1].runtime_handle)
        );
        assert!(
            inventory
                .runtimes
                .iter()
                .all(|runtime| runtime.observation_sequence == 2)
        );
        assert!(matches!(
            broker.inventory_runtime(1).await,
            Err(HostError::ResourceExhausted)
        ));
    }

    #[tokio::test]
    async fn empty_inventory_is_a_complete_empty_protobuf() {
        let fixture = AuthorityFixture::new();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            None,
            fixture.authority(),
        )
        .unwrap();
        let bytes = broker.inventory_runtime(4_096).await.unwrap();
        assert!(bytes.is_empty());
        assert!(
            InventoryRuntimeResponse::decode_from_slice(&bytes)
                .unwrap()
                .runtimes
                .is_empty()
        );
    }

    #[tokio::test]
    async fn authenticated_complete_receipt_replays_after_effect_deadline() {
        let fixture = AuthorityFixture::new();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let first = broker
            .apply_runtime(
                &bytes,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .await
            .unwrap();
        let replay = broker
            .apply_runtime(
                &bytes,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || {
                    Err(HostError::State(
                        "complete replay unexpectedly sampled the effect clock".to_owned(),
                    ))
                },
            )
            .await
            .unwrap();

        assert_eq!(replay, first);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_new_request_cannot_use_the_complete_replay_path() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();

        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock_at(TEST_WALL_SECONDS, 1_000)),
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.load().unwrap(), HostState::default());
    }

    #[tokio::test]
    async fn pending_request_reconciles_after_worker_failure() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let bytes = request(1, 1, 4);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(apply(&mut broker, &fixture, &bytes).await.is_err());

        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut reopened = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(apply(&mut reopened, &fixture, &bytes).await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn later_host_versions_are_rejected_before_clock_state_or_worker() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let initial_state = store.load().unwrap();
        let clock_calls = AtomicUsize::new(0);

        for (request_id, minor) in (1_u8..=4).zip(1_u16..=4) {
            let protocol_version = ProtocolVersion::new(1, minor);
            let authorized_request = request(request_id, 1, 4);
            let artifacts = fixture.artifacts(&authorized_request, 1);
            let request =
                request_at_protocol(request_id, request_id.wrapping_add(1), protocol_version);

            assert!(matches!(
                broker
                    .apply_runtime(
                        &request,
                        &artifacts,
                        protocol_version,
                        peer(),
                        policy(),
                        || {
                            clock_calls.fetch_add(1, Ordering::SeqCst);
                            Ok(clock())
                        },
                    )
                    .await,
                Err(HostError::Authority(
                    aos_sandbox_broker::BrokerAdmissionError::RequestMismatch
                ))
            ));
        }

        assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.load().unwrap(), initial_state);
    }

    #[tokio::test]
    async fn runtime_effect_query_is_read_only_for_absent_pending_and_complete_requests() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker.clone(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let request = request(1, 1, 4);
        let artifacts = fixture.artifacts(&request, 1);

        let before = store.load().unwrap();
        let response = broker
            .query_runtime_effect(
                &artifacts,
                RuntimeEffectQueryContext {
                    original_request_bytes: &request,
                    request_id: [1; 16],
                    peer: peer(),
                    policy: policy(),
                    current_clock: clock(),
                    maximum_response_bytes: 4096,
                },
            )
            .unwrap();
        let response = QueryRuntimeEffectResponse::decode_from_slice(&response).unwrap();
        assert_eq!(
            response.status,
            RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_ABSENT
        );
        assert!(response.receipt.is_empty());
        assert_eq!(store.load().unwrap(), before);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        worker.fail_next.store(true, Ordering::SeqCst);
        assert!(apply(&mut broker, &fixture, &request).await.is_err());
        let pending = store.load().unwrap();
        let response = broker
            .query_runtime_effect(
                &artifacts,
                RuntimeEffectQueryContext {
                    original_request_bytes: &request,
                    request_id: [1; 16],
                    peer: peer(),
                    policy: policy(),
                    current_clock: clock_at(1_000, 10_000),
                    maximum_response_bytes: 4096,
                },
            )
            .unwrap();
        let response = QueryRuntimeEffectResponse::decode_from_slice(&response).unwrap();
        assert_eq!(
            response.status,
            RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_PENDING
        );
        assert!(response.receipt.is_empty());
        assert_eq!(store.load().unwrap(), pending);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let completed = apply(&mut broker, &fixture, &request).await.unwrap();
        let complete_state = store.load().unwrap();
        let response = broker
            .query_runtime_effect(
                &artifacts,
                RuntimeEffectQueryContext {
                    original_request_bytes: &request,
                    request_id: [1; 16],
                    peer: peer(),
                    policy: policy(),
                    current_clock: clock_at(1_000, 10_000),
                    maximum_response_bytes: 4096,
                },
            )
            .unwrap();
        let response = QueryRuntimeEffectResponse::decode_from_slice(&response).unwrap();
        assert_eq!(
            response.status,
            RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE
        );
        assert_eq!(response.receipt, completed);
        assert_eq!(store.load().unwrap(), complete_state);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn runtime_effect_query_rejects_changed_original_identity_without_side_effects() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let original = request(1, 1, 4);
        assert!(apply(&mut broker, &fixture, &original).await.is_ok());
        let state = store.load().unwrap();
        let changed = request(1, 2, 5);
        let changed_artifacts = fixture.artifacts(&changed, 2);

        assert!(
            broker
                .query_runtime_effect(
                    &changed_artifacts,
                    RuntimeEffectQueryContext {
                        original_request_bytes: &changed,
                        request_id: [1; 16],
                        peer: peer(),
                        policy: policy(),
                        current_clock: clock(),
                        maximum_response_bytes: 4096,
                    },
                )
                .is_err()
        );
        let artifacts = fixture.artifacts(&original, 1);
        let altered_artifacts = fixture.artifacts_with_lease_authority(&original, 1, true);
        assert!(
            broker
                .query_runtime_effect(
                    &altered_artifacts,
                    RuntimeEffectQueryContext {
                        original_request_bytes: &original,
                        request_id: [1; 16],
                        peer: peer(),
                        policy: policy(),
                        current_clock: clock(),
                        maximum_response_bytes: 4096,
                    },
                )
                .is_err()
        );
        assert!(
            broker
                .query_runtime_effect(
                    &artifacts,
                    RuntimeEffectQueryContext {
                        original_request_bytes: &original,
                        request_id: [9; 16],
                        peer: peer(),
                        policy: policy(),
                        current_clock: clock(),
                        maximum_response_bytes: 4096,
                    },
                )
                .is_err()
        );
        assert_eq!(store.load().unwrap(), state);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_sandbox_cannot_admit_two_pending_transitions() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply(&mut broker, &fixture, &request(1, 1, 4))
                .await
                .is_err()
        );
        assert!(
            apply(&mut broker, &fixture, &request(2, 2, 5))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_generation_and_request_id_equivocation_fail_before_effect() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        apply(&mut broker, &fixture, &request(1, 2, 4))
            .await
            .unwrap();
        assert!(
            apply(&mut broker, &fixture, &request(2, 1, 4))
                .await
                .is_err()
        );
        assert!(
            apply(&mut broker, &fixture, &request(1, 3, 5))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn launch_is_available_only_when_nspawn_and_guardian_are_configured() {
        let fixture = AuthorityFixture::new();
        assert!(!closed_launch_backend_available(false, false));
        assert!(!closed_launch_backend_available(true, false));
        assert!(!closed_launch_backend_available(false, true));
        assert!(closed_launch_backend_available(true, true));

        let unavailable = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            None,
            fixture.authority(),
        )
        .unwrap();
        assert!(!unavailable.launch_available());

        let nspawn_only = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(!nspawn_only.launch_available());

        let unprotected = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap()
        .with_guardian(GuardianConfig::for_tests().unwrap());
        assert!(!unprotected.launch_available());
    }

    #[test]
    fn launch_availability_revalidates_the_protected_guardian_executable() {
        if !rustix::process::geteuid().is_root() {
            return;
        }

        use std::fs::{File, Permissions};
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = AuthorityFixture::new();
        let credentials = tempfile::tempdir().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("guardian");
        std::fs::write(&path, b"guardian-a").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o500)).unwrap();
        let descriptor = File::open(&path).unwrap();
        let guardian = GuardianConfig::for_test_descriptor(descriptor.as_fd()).unwrap();
        let broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.protected_authority(credentials.path()),
        )
        .unwrap()
        .with_guardian(guardian);
        assert!(broker.launch_available());

        std::fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&path, b"guardian-b").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o500)).unwrap();

        assert!(!broker.launch_available());
    }

    #[test]
    fn launch_availability_revalidates_protected_guardian_credentials() {
        if !rustix::process::geteuid().is_root() {
            return;
        }

        let fixture = AuthorityFixture::new();
        let credentials = tempfile::tempdir().unwrap();
        let authority = fixture.protected_authority(credentials.path());
        let broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            Some(nspawn()),
            authority,
        )
        .unwrap()
        .with_guardian(GuardianConfig::for_tests().unwrap());
        assert!(broker.launch_available());

        let path = credentials.path().join("broker-plan-public-key");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();

        assert!(!broker.launch_available());
    }

    #[tokio::test]
    async fn unready_launch_fails_before_durable_intent_or_effect() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            None,
            fixture.authority(),
        )
        .unwrap();
        let (launch, _) = fixture.guardian_request_and_artifacts(1);
        assert!(
            apply_protocol(&mut broker, &fixture, &launch, ProtocolVersion::new(1, 0),)
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.load().unwrap(), HostState::default());
    }

    #[test]
    fn requested_identity_must_equal_catalog_allocation() {
        let fixture = AuthorityFixture::new();
        let broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let (request, _) = fixture.guardian_request_and_artifacts(1);
        let mut request = ApplyRuntimeRequest::decode_from_slice(&request).unwrap();
        request.launch_plan.get_or_insert_default().uid_range_start = 131_072;
        let request = decode_runtime_request(
            &request.encode_to_vec(),
            peer(),
            policy(),
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap();

        assert!(broker.compile_operation(&request).is_err());
    }

    #[tokio::test]
    async fn signed_authority_rejects_wrong_signature_body_and_protocol() {
        let fixture = AuthorityFixture::new();
        let bytes = request(1, 1, 4);
        let valid = fixture.artifacts(&bytes, 1);
        let mut signature = valid.broker_plan_signature().to_vec();
        let last = signature.len() - 1;
        signature[last] ^= 1;
        let wrong_signature = validated_artifacts(BrokerAuthorizationArtifactsV1 {
            broker_plan: valid.broker_plan().to_vec(),
            broker_plan_signature: signature,
            ownership_lease: valid.ownership_lease().to_vec(),
            ownership_lease_signature: valid.ownership_lease_signature().to_vec(),
            ..Default::default()
        });
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &wrong_signature,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &valid,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        assert!(
            broker
                .apply_runtime(
                    &request(2, 1, 5),
                    &valid,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authority_expiry_after_intent_prevents_the_systemd_effect() {
        let fixture = AuthorityFixture::new();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let mut samples = 0;
        let result = broker
            .apply_runtime(
                &bytes,
                &artifacts,
                ProtocolVersion::new(1, 0),
                peer(),
                policy(),
                || {
                    samples += 1;
                    Ok(if samples == 1 {
                        clock()
                    } else {
                        clock_at(300, 200)
                    })
                },
            )
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.load().unwrap().effect(&[1; 16]).is_some());

        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut expired_at_admission = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            expired_at_admission
                .apply_runtime(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock_at(300, TEST_BOOTTIME_NANOSECONDS)),
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn effect_time_clock_identity_substitution_fails_closed() {
        let fixture = AuthorityFixture::new();
        let bytes = request(1, 1, 4);
        let artifacts = fixture.artifacts(&bytes, 1);
        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut broker = HostBroker::open(
            FixedCatalog,
            MemoryStore::default(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let mut samples = 0;
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || {
                        samples += 1;
                        if samples == 1 {
                            return Ok(clock());
                        }
                        RawPairedClockSample::new_untrusted(
                            RawClockProvenance::new_untrusted([59; 16]).unwrap(),
                            [60; 16],
                            TEST_WALL_SECONDS,
                            TEST_BOOTTIME_NANOSECONDS,
                        )
                        .map_err(|error| HostError::State(error.to_string()))
                    },
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pending_replay_refreshes_lease_but_rejects_rollback_and_authority_substitution() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let bytes = request(1, 1, 4);
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply_generation(&mut broker, &fixture, &bytes, 2)
                .await
                .is_err()
        );

        let rollback = fixture.artifacts(&bytes, 1);
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &rollback,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );
        let substituted = fixture.artifacts_with_lease_authority(&bytes, 3, true);
        assert!(
            broker
                .apply_runtime(
                    &bytes,
                    &substituted,
                    ProtocolVersion::new(1, 0),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .await
                .is_err()
        );

        let worker = FakeWorker::default();
        let calls = worker.calls.clone();
        let mut reopened = HostBroker::open(
            FixedCatalog,
            store,
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply_generation(&mut reopened, &fixture, &bytes, 3)
                .await
                .is_ok()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn authenticated_effect_tamper_and_relocation_fail_closed() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker.clone(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let first = request(1, 1, 4);
        assert!(apply(&mut broker, &fixture, &first).await.is_err());
        worker.fail_next.store(true, Ordering::SeqCst);
        let second = request_with_sandbox(2, 1, 4, 8, 65_536, 65_536);
        assert!(apply(&mut broker, &fixture, &second).await.is_err());
        store.0.lock().unwrap().swap_effects(&[1; 16], &[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                store.clone(),
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );

        store.0.lock().unwrap().swap_effects(&[1; 16], &[2; 16]);
        store.0.lock().unwrap().corrupt_effect(&[1; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                store,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn unauthenticated_guardian_execution_fails_closed_on_restart() {
        let fixture = AuthorityFixture::new();

        let guardian_store = MemoryStore::default();
        let guardian_worker = FakeWorker::default();
        guardian_worker.fail_next.store(true, Ordering::SeqCst);
        let mut guardian_broker = HostBroker::open(
            FixedCatalog,
            guardian_store.clone(),
            guardian_worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        assert!(
            apply(&mut guardian_broker, &fixture, &request(1, 1, 4))
                .await
                .is_err()
        );
        guardian_store
            .0
            .lock()
            .unwrap()
            .tamper_execution_to_guardian(&[1; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                guardian_store,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn restart_rejects_deleted_current_requests_and_corrupt_or_swapped_receipts() {
        let fixture = AuthorityFixture::new();

        let pending_store = MemoryStore::default();
        let pending_worker = FakeWorker::default();
        pending_worker.fail_next.store(true, Ordering::SeqCst);
        let mut pending_broker = HostBroker::open(
            FixedCatalog,
            pending_store.clone(),
            pending_worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let pending_request = request(1, 1, 4);
        assert!(
            apply(&mut pending_broker, &fixture, &pending_request)
                .await
                .is_err()
        );
        pending_store.0.lock().unwrap().remove_request(&[1; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                pending_store,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );

        let complete_store = MemoryStore::default();
        let mut complete_broker = HostBroker::open(
            FixedCatalog,
            complete_store.clone(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let first = request(1, 1, 4);
        let second = request_with_sandbox(2, 1, 4, 8, 65_536, 65_536);
        assert!(apply(&mut complete_broker, &fixture, &first).await.is_ok());
        assert!(apply(&mut complete_broker, &fixture, &second).await.is_ok());
        let valid = complete_store.load().unwrap();

        let deleted = MemoryStore(Arc::new(Mutex::new(valid.clone())));
        deleted.0.lock().unwrap().remove_request(&[1; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                deleted,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
        let corrupt = MemoryStore(Arc::new(Mutex::new(valid.clone())));
        corrupt.0.lock().unwrap().corrupt_receipt(&[1; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                corrupt,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
        let swapped = MemoryStore(Arc::new(Mutex::new(valid)));
        swapped.0.lock().unwrap().swap_receipts(&[1; 16], &[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                swapped,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn restart_rejects_deleted_latest_request_even_when_an_older_fence_is_identical() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            FakeWorker::default(),
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let first = request(1, 1, 4);
        let second = request(2, 1, 4);
        assert!(apply(&mut broker, &fixture, &first).await.is_ok());
        assert!(apply(&mut broker, &fixture, &second).await.is_ok());

        store.0.lock().unwrap().remove_request(&[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                store,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn startup_rejects_corrupt_or_deleted_authorization_fences() {
        let fixture = AuthorityFixture::new();
        let store = MemoryStore::default();
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            store.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let request = request(1, 1, 4);
        assert!(apply(&mut broker, &fixture, &request).await.is_err());
        let valid_state = store.load().unwrap();

        let corrupt = MemoryStore(Arc::new(Mutex::new(valid_state.clone())));
        corrupt.0.lock().unwrap().corrupt_fence(&[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                corrupt,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );

        let relocated = MemoryStore(Arc::new(Mutex::new(valid_state.clone())));
        let worker = FakeWorker::default();
        worker.fail_next.store(true, Ordering::SeqCst);
        let mut broker = HostBroker::open(
            FixedCatalog,
            relocated.clone(),
            worker,
            Some(nspawn()),
            fixture.authority(),
        )
        .unwrap();
        let second = request_with_sandbox(2, 1, 4, 8, 65_536, 65_536);
        assert!(apply(&mut broker, &fixture, &second).await.is_err());
        relocated.0.lock().unwrap().swap_fences(&[2; 16], &[8; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                relocated,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );

        let deleted = MemoryStore(Arc::new(Mutex::new(valid_state)));
        deleted.0.lock().unwrap().remove_fence(&[2; 16]);
        assert!(
            HostBroker::open(
                FixedCatalog,
                deleted,
                FakeWorker::default(),
                Some(nspawn()),
                fixture.authority(),
            )
            .is_err()
        );
    }
}
