//! Dormant authenticated-session callsite for Host ApplyRuntime.
//!
//! This adapter is deliberately not referenced by the production service. It
//! enters the existing durable Host broker only through an explicit protected
//! broker-session handoff and rechecks every supplied clock sample against the
//! session's pinned kernel boot.

use std::future::Future;
use std::os::fd::OwnedFd;
use std::pin::Pin;

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, ProtectedHostNoApplySettlementHistoryV1,
};
use aos_sandbox_core::{ObjectDigest, ProtocolVersion};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::host_consumer_cgroup::decode_consumer_cgroup_request_v1;
use aos_sandbox_protocol::host_execution_argument::receipt::HostExecutionArgumentHistoricalReceiptV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, decode_mount_scope_request,
    decode_mount_scope_request_for_protected_replay, decode_payload_scope_request,
    decode_payload_scope_request_for_protected_replay, decode_query_runtime_effect_request_v1,
};
use sha2::{Digest as _, Sha256};

use crate::HostError;
use crate::broker::{HostAttachReadOnlyProofV1, HostBroker, HostExecutionGrantReservationV1};
use crate::live_agent::HostAgentLiveSessionV1;
use crate::live_agent::argument_attempt::HostArgumentAttemptErrorV1;
use crate::plan::HostCatalog;
use crate::state::HostStateStore;
use crate::worker::HostWorker;

mod sealed {
    pub trait Sealed {}
}

/// Reports rejection at the dormant broker-session-to-Host boundary.
#[derive(Debug, thiserror::Error)]
pub enum DormantHostBrokerCallErrorV1 {
    /// The request or live kernel boot no longer matches the protected handoff.
    #[error("authenticated Host handoff has stale kernel evidence")]
    StaleKernel,
    /// The exact observation request did not satisfy its closed wire profile.
    #[error("authenticated Host observation request is invalid: {0}")]
    Protocol(#[from] ProtocolValidationError),
    /// The existing durable Host operation rejected the request.
    #[error("authenticated Host ApplyRuntime failed: {0}")]
    Broker(#[from] HostError),
}

/// Seals one response emitted by the real Host broker operation.
pub struct DormantHostBrokerObservationV1 {
    request_id: [u8; 16],
    response: Vec<u8>,
    commitment: ObjectDigest,
    descriptors: Vec<OwnedFd>,
    scope_replay_ticket: Option<DormantHostScopeReplayTicketV1>,
}

/// Retains Host-minted authority to repeat one exact live-admitted scope readback.
///
/// Fields and construction stay private. Possession proves the Host previously
/// admitted the exact request and authorization artifacts while its deadline
/// was live; every reopen still revalidates current Host state and kernel scope.
#[must_use = "retain only with the protected terminal replay that owns this request"]
pub struct DormantHostScopeReplayTicketV1 {
    locator: [u8; 32],
    method: BrokerMethod,
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    signed_request_digest: [u8; 32],
    session_binding: [u8; 32],
    response_body_digest: [u8; 32],
    terminal_verifier_commitment: [u8; 32],
    signed_outcome_digest: [u8; 32],
    protected_generation: u64,
    protected_head: [u8; 32],
    artifact_commitment: ObjectDigest,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol_version: ProtocolVersion,
    protected_boot_id: [u8; 16],
}

/// Carries one exact Host-authenticated reservation found during cold replay.
#[must_use = "consume the reservation only with protected terminal replay custody"]
pub struct DormantHostScopeReplayReservationV1([u8; 32]);

impl DormantHostScopeReplayReservationV1 {
    #[doc(hidden)]
    pub const fn locator(&self) -> [u8; 32] {
        self.0
    }
}

impl DormantHostScopeReplayTicketV1 {
    /// Returns the nonauthorizing locator included in a protected commit receipt.
    #[doc(hidden)]
    pub const fn reservation_locator(&self) -> [u8; 32] {
        self.locator
    }

    /// Reports whether this opaque Host ticket belongs to one protected replay.
    ///
    /// This is a nonauthorizing selector. The effectful reopen independently
    /// authenticates the retained Host record and all physical scope state.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_protected_replay(
        &self,
        method: BrokerMethod,
        request_id: [u8; 16],
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        response_body_digest: [u8; 32],
        signed_outcome_digest: [u8; 32],
        protected_generation: u64,
        protected_head: [u8; 32],
    ) -> bool {
        self.method == method
            && self.request_id == request_id
            && self.signed_request_digest == signed_request_digest
            && self.session_binding == session_binding
            && self.response_body_digest == response_body_digest
            && self.signed_outcome_digest == signed_outcome_digest
            && self.protected_generation == protected_generation
            && self.protected_head == protected_head
    }
}

impl DormantHostBrokerObservationV1 {
    /// Returns the exact request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the bounded Host response body.
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// Returns the domain-separated observation commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }

    /// Consumes the observation into its exact body and descriptor custody.
    #[must_use]
    pub fn into_response_descriptors_and_replay_ticket(
        self,
    ) -> (
        Vec<u8>,
        Vec<OwnedFd>,
        Option<DormantHostScopeReplayTicketV1>,
    ) {
        (self.response, self.descriptors, self.scope_replay_ticket)
    }
}

/// Defines the closed asynchronous Host call surface accepted by security.
#[doc(hidden)]
pub trait DormantHostBrokerCallsiteV1: sealed::Sealed {
    /// Transfers an authenticated launch-owned guest channel after Host commit.
    ///
    /// A failed response transport does not erase this one-shot in-memory
    /// custody. The service must revalidate it against protected currentness.
    fn take_authenticated_agent_launch(&mut self) -> Option<HostAgentLiveSessionV1>;

    /// Returns the verifier commitment pinned by protected Host configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed credential is absent or no longer current.
    fn fixed_terminal_verifier_commitment(&self) -> Result<[u8; 32], DormantHostBrokerCallErrorV1>;

    /// Reserves a signed execution grant in the shared durable Host fence.
    /// Apply carries sealed content for verification; Query carries none.
    ///
    /// # Errors
    ///
    /// Rejects stale claim/boot, signer, lease, current assignment, or an
    /// unresolved Host state commit.
    #[allow(clippy::too_many_arguments)]
    fn reserve_authenticated_execution(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        execution_spec_content: Option<&[u8]>,
        protected_boot_id: [u8; 16],
    ) -> Result<HostExecutionGrantReservationV1, DormantHostBrokerCallErrorV1>;

    /// Appends or exactly replays one signed preliminary Host settlement.
    ///
    /// # Errors
    ///
    /// Rejects stale boot, signature-bound request, Host custody, or uncertain
    /// protected append. Floor and ACK phases remain unavailable.
    fn commit_no_apply_preliminary_v2(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
    ) -> Result<Option<Vec<u8>>, DormantHostBrokerCallErrorV1>;

    /// Reads an exact protected Host settlement history for a signed query.
    ///
    /// # Errors
    ///
    /// Rejects stale boot, foreign source, or unmatched HostState and journal
    /// custody. The returned history grants no Controller settlement authority.
    fn query_no_apply_settlement_v2(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
    ) -> Result<Option<ProtectedHostNoApplySettlementHistoryV1>, DormantHostBrokerCallErrorV1>;

    /// Verifies a distinct read-only ATTACH plan and fresh ownership lease.
    ///
    /// # Errors
    ///
    /// Rejects malformed selectors, stale protected runtime, signer, lease,
    /// base fence, or request deadline.
    #[allow(clippy::too_many_arguments)]
    fn verify_authenticated_attach_query(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
    ) -> Result<HostAttachReadOnlyProofV1, DormantHostBrokerCallErrorV1>;

    /// Completes an exact Host authorization reservation after protected readback.
    ///
    /// # Errors
    ///
    /// Rejects stale currentness, conflicting outcome, or ambiguous Host state.
    fn complete_authenticated_execution(
        &mut self,
        reservation: &HostExecutionGrantReservationV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        outcome: &[u8],
    ) -> Result<(), DormantHostBrokerCallErrorV1>;

    /// Rejoins historical Guest custody to the sealed original Host admission.
    ///
    /// # Errors
    ///
    /// Rejects absent or replaced original intent and indeterminate custody.
    fn query_authenticated_argument_historical(
        &self,
        reservation: &HostExecutionGrantReservationV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<HostExecutionArgumentHistoricalReceiptV1, HostArgumentAttemptErrorV1>;

    /// Executes one exact authenticated Host ApplyRuntime operation.
    ///
    /// The returned future resolves with an error when request or kernel
    /// evidence is stale, or when the durable Host broker rejects the call.
    fn consume_authenticated_apply<'call>(
        &'call mut self,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    >;

    /// Executes one exact authenticated Host observation or inventory method.
    ///
    /// # Errors
    ///
    /// Returns an error when the method is not a closed Host read method, the
    /// request or kernel evidence is stale, or the real Host broker rejects it.
    fn consume_authenticated_observation<'call>(
        &'call mut self,
        method: BrokerMethod,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: Option<&'call ValidatedUntrustedAuthorizationArtifacts>,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    >;

    /// Produces one Host payload or mount scope with exact descriptor custody.
    ///
    /// # Errors
    ///
    /// Returns an error for another method, stale request/kernel evidence, or
    /// a rejected protected Host scope observation.
    fn consume_authenticated_scope<'call>(
        &'call mut self,
        method: BrokerMethod,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    >;

    /// Observes Storage's exact read-only consumer cgroup without a grant.
    ///
    /// The same call is safe for a protected terminal replay because it has
    /// no effect; it still requires the original live deadline and a fresh
    /// physical readback. Its sealed observation is not permission to send an FD.
    ///
    /// # Errors
    ///
    /// Rejects changed signed-session boot, body digest, request identity,
    /// current assignment, scope handle, deadline, or physical membership.
    #[allow(clippy::too_many_arguments)]
    fn consume_authenticated_consumer_cgroup<'call>(
        &'call mut self,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    >;

    /// Reopens one exact protected Host scope replay with descriptor custody.
    ///
    /// The caller must already own protected byte-exact terminal replay
    /// authority. This path does not renew the historical request deadline;
    /// it retains live kernel boot, fence, and physical scope validation.
    ///
    /// # Errors
    ///
    /// Returns an error for another method, a request differing from protected
    /// replay state, stale kernel evidence, or rejected physical readback.
    fn consume_authenticated_scope_replay<'call>(
        &'call mut self,
        replay: Option<&'call DormantHostScopeReplayTicketV1>,
        method: BrokerMethod,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        expected_response_body_digest: [u8; 32],
        signed_outcome_digest: [u8; 32],
        protected_generation: u64,
        protected_head: [u8; 32],
        terminal_verifier_commitment: [u8; 32],
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    >;

    /// Finalizes a live Host reservation from one protected post-CAS receipt.
    #[doc(hidden)]
    fn bind_authenticated_scope_terminal(
        &mut self,
        ticket: Option<&mut DormantHostScopeReplayTicketV1>,
        receipt: &aos_sandbox_protocol::BrokerTerminalCommitReceiptV1,
    ) -> Result<[u8; 32], DormantHostBrokerCallErrorV1>;

    /// Reads back the exact nonauthorizing reservation locator after restart.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    fn locate_authenticated_scope_reservation(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        response_body_digest: [u8; 32],
        terminal_verifier_commitment: [u8; 32],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantHostScopeReplayReservationV1, DormantHostBrokerCallErrorV1>;
}

/// Retains the concrete Host broker and kernel clock.
pub struct DormantHostBrokerCompositionV1<'a, Catalog, Store, Worker>
where
    Catalog: HostCatalog,
    Store: HostStateStore,
    Worker: HostWorker,
{
    broker: &'a mut HostBroker<Catalog, Store, Worker>,
    last_boottime_nanoseconds: Option<u64>,
}

impl<'a, Catalog, Store, Worker> DormantHostBrokerCompositionV1<'a, Catalog, Store, Worker>
where
    Catalog: HostCatalog,
    Store: HostStateStore,
    Worker: HostWorker,
{
    /// Constructs an explicit dormant callsite with a fixed kernel clock owner.
    #[must_use]
    pub const fn new(broker: &'a mut HostBroker<Catalog, Store, Worker>) -> Self {
        Self {
            broker,
            last_boottime_nanoseconds: None,
        }
    }
}

impl<Catalog, Store, Worker> sealed::Sealed
    for DormantHostBrokerCompositionV1<'_, Catalog, Store, Worker>
where
    Catalog: HostCatalog,
    Store: HostStateStore,
    Worker: HostWorker,
{
}

impl<Catalog, Store, Worker> DormantHostBrokerCallsiteV1
    for DormantHostBrokerCompositionV1<'_, Catalog, Store, Worker>
where
    Catalog: HostCatalog,
    Store: HostStateStore,
    Worker: HostWorker + Sync,
{
    fn take_authenticated_agent_launch(&mut self) -> Option<HostAgentLiveSessionV1> {
        self.broker.take_authenticated_agent_launch()
    }

    fn fixed_terminal_verifier_commitment(&self) -> Result<[u8; 32], DormantHostBrokerCallErrorV1> {
        self.broker
            .terminal_verifier_commitment()
            .map_err(DormantHostBrokerCallErrorV1::from)
    }

    fn reserve_authenticated_execution(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        execution_spec_content: Option<&[u8]>,
        protected_boot_id: [u8; 16],
    ) -> Result<HostExecutionGrantReservationV1, DormantHostBrokerCallErrorV1> {
        let last_boottime = &mut self.last_boottime_nanoseconds;
        self.broker
            .reserve_host_execution(
                claim,
                request,
                execution_spec_content,
                protected_boot_id,
                || {
                    let sample = crate::service::trusted_paired_clock_sample()?;
                    if sample.host_boot_id() != protected_boot_id
                        || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                    {
                        return Err(HostError::Fence("Host execution clock is stale"));
                    }
                    *last_boottime = Some(sample.boottime_nanoseconds());
                    Ok(sample)
                },
            )
            .map_err(Into::into)
    }

    fn commit_no_apply_preliminary_v2(
        &mut self,
        claim: &mut DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
    ) -> Result<Option<Vec<u8>>, DormantHostBrokerCallErrorV1> {
        let sample = crate::service::trusted_paired_clock_sample()?;
        if sample.host_boot_id() != protected_boot_id
            || self
                .last_boottime_nanoseconds
                .is_some_and(|floor| sample.boottime_nanoseconds() < floor)
        {
            return Err(DormantHostBrokerCallErrorV1::StaleKernel);
        }
        self.last_boottime_nanoseconds = Some(sample.boottime_nanoseconds());
        self.broker
            .commit_no_apply_preliminary_v2(claim, request, sample.boottime_nanoseconds())
            .map_err(Into::into)
    }

    fn query_no_apply_settlement_v2(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
    ) -> Result<Option<ProtectedHostNoApplySettlementHistoryV1>, DormantHostBrokerCallErrorV1> {
        let sample = crate::service::trusted_paired_clock_sample()?;
        if sample.host_boot_id() != protected_boot_id
            || self
                .last_boottime_nanoseconds
                .is_some_and(|floor| sample.boottime_nanoseconds() < floor)
        {
            return Err(DormantHostBrokerCallErrorV1::StaleKernel);
        }
        self.last_boottime_nanoseconds = Some(sample.boottime_nanoseconds());
        self.broker
            .query_no_apply_settlement_v2(claim, request, sample.boottime_nanoseconds())
            .map_err(Into::into)
    }

    fn verify_authenticated_attach_query(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protected_boot_id: [u8; 16],
    ) -> Result<HostAttachReadOnlyProofV1, DormantHostBrokerCallErrorV1> {
        let last_boottime = &mut self.last_boottime_nanoseconds;
        self.broker
            .verify_host_attach_query(
                claim,
                method,
                request_body,
                request_id,
                artifacts,
                peer,
                policy,
                protected_boot_id,
                || {
                    let sample = crate::service::trusted_paired_clock_sample()?;
                    if sample.host_boot_id() != protected_boot_id
                        || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                    {
                        return Err(HostError::Fence("Host attach query clock is stale"));
                    }
                    *last_boottime = Some(sample.boottime_nanoseconds());
                    Ok(sample)
                },
            )
            .map_err(Into::into)
    }

    fn complete_authenticated_execution(
        &mut self,
        reservation: &HostExecutionGrantReservationV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        outcome: &[u8],
    ) -> Result<(), DormantHostBrokerCallErrorV1> {
        self.broker
            .complete_host_execution_reservation(reservation, claim, outcome)
            .map_err(Into::into)
    }

    fn query_authenticated_argument_historical(
        &self,
        reservation: &HostExecutionGrantReservationV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
    ) -> Result<HostExecutionArgumentHistoricalReceiptV1, HostArgumentAttemptErrorV1> {
        self.broker
            .query_host_execution_argument_historical(reservation, claim)
    }

    fn consume_authenticated_apply<'call>(
        &'call mut self,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    > {
        Box::pin(async move {
            let current_boot_id = KernelBootId::current()
                .map_err(|_| DormantHostBrokerCallErrorV1::StaleKernel)?
                .into_bytes();
            if current_boot_id != protected_boot_id
                || ObjectDigest::from_bytes(Sha256::digest(request_body).into())
                    != request_body_digest
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }

            let last_boottime = &mut self.last_boottime_nanoseconds;
            let checked_clock = || {
                let sample = crate::service::trusted_paired_clock_sample()?;
                if sample.host_boot_id() != protected_boot_id
                    || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                {
                    return Err(HostError::Fence(
                        "broker-session kernel boot changed before Host effect",
                    ));
                }
                *last_boottime = Some(sample.boottime_nanoseconds());
                Ok(sample)
            };
            let response = self
                .broker
                .apply_runtime(
                    request_body,
                    artifacts,
                    protocol_version,
                    peer,
                    policy,
                    checked_clock,
                )
                .await?;
            let mut digest = Sha256::new();
            digest.update(b"aos-sandbox-host-broker-observation-v1\0");
            digest.update(request_id);
            digest.update(request_body_digest.as_bytes());
            digest.update(Sha256::digest(&response));
            Ok(DormantHostBrokerObservationV1 {
                request_id,
                response,
                commitment: ObjectDigest::from_bytes(digest.finalize().into()),
                descriptors: Vec::new(),
                scope_replay_ticket: None,
            })
        })
    }

    fn consume_authenticated_observation<'call>(
        &'call mut self,
        method: BrokerMethod,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: Option<&'call ValidatedUntrustedAuthorizationArtifacts>,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    > {
        Box::pin(async move {
            let current_boot_id = KernelBootId::current()
                .map_err(|_| DormantHostBrokerCallErrorV1::StaleKernel)?
                .into_bytes();
            if current_boot_id != protected_boot_id
                || ObjectDigest::from_bytes(Sha256::digest(request_body).into())
                    != request_body_digest
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }

            let current_clock = crate::service::trusted_paired_clock_sample()?;
            if current_clock.host_boot_id() != protected_boot_id
                || self
                    .last_boottime_nanoseconds
                    .is_some_and(|floor| current_clock.boottime_nanoseconds() < floor)
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }
            self.last_boottime_nanoseconds = Some(current_clock.boottime_nanoseconds());

            let response = match method {
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME if artifacts.is_none() => {
                    let request = crate::observation::decode_observe_runtime_request(
                        request_body,
                        peer,
                        policy,
                        current_clock.boottime_nanoseconds(),
                    )?;
                    if request.header.request_id() != &request_id
                        || request.header.protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .observe_runtime(
                            request.identity,
                            request.runtime_handle,
                            request.header.maximum_response_bytes(),
                        )
                        .await?
                }
                BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME if artifacts.is_none() => {
                    let header = crate::observation::decode_inventory_runtime_request(
                        request_body,
                        peer,
                        policy,
                        current_clock.boottime_nanoseconds(),
                    )?;
                    if header.request_id() != &request_id
                        || header.protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .inventory_runtime(header.maximum_response_bytes())
                        .await?
                }
                BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => {
                    let artifacts = artifacts.ok_or(DormantHostBrokerCallErrorV1::StaleKernel)?;
                    let request = decode_query_runtime_effect_request_v1(
                        request_body,
                        peer,
                        policy,
                        current_clock.boottime_nanoseconds(),
                    )?;
                    if request.header().request_id() != &request_id
                        || request.header().protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker.query_validated_runtime_effect(
                        artifacts,
                        &request,
                        peer,
                        policy,
                        current_clock,
                    )?
                }
                _ => return Err(DormantHostBrokerCallErrorV1::StaleKernel),
            };

            let mut digest = Sha256::new();
            digest.update(b"aos-sandbox-host-broker-observation-v1\0");
            digest.update((method as i32).to_be_bytes());
            digest.update(request_id);
            digest.update(request_body_digest.as_bytes());
            digest.update(Sha256::digest(&response));
            Ok(DormantHostBrokerObservationV1 {
                request_id,
                response,
                commitment: ObjectDigest::from_bytes(digest.finalize().into()),
                descriptors: Vec::new(),
                scope_replay_ticket: None,
            })
        })
    }

    fn consume_authenticated_scope<'call>(
        &'call mut self,
        method: BrokerMethod,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    > {
        Box::pin(async move {
            if KernelBootId::current()
                .map_err(|_| DormantHostBrokerCallErrorV1::StaleKernel)?
                .into_bytes()
                != protected_boot_id
                || ObjectDigest::from_bytes(Sha256::digest(request_body).into())
                    != request_body_digest
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }
            let last_boottime = &mut self.last_boottime_nanoseconds;
            let mut clock = || {
                let sample = crate::service::trusted_paired_clock_sample()?;
                if sample.host_boot_id() != protected_boot_id
                    || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                {
                    return Err(HostError::Fence(
                        "broker-session kernel boot changed before Host scope observation",
                    ));
                }
                *last_boottime = Some(sample.boottime_nanoseconds());
                Ok(sample)
            };
            let now = clock()?.boottime_nanoseconds();
            let (response, descriptors) = match method {
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
                    let request = decode_payload_scope_request(request_body, peer, policy, now)?;
                    if request.header().request_id() != &request_id
                        || request.header().protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .prepare_payload_scope(artifacts, &request, request_body, &mut clock)
                        .await?
                        .into_parts()
                }
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
                    let request = decode_mount_scope_request(request_body, peer, policy, now)?;
                    if request.header().request_id() != &request_id
                        || request.header().protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .prepare_mount_scope(artifacts, &request, request_body, &mut clock)
                        .await?
                        .into_parts()
                }
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
                    let request = decode_mount_scope_request(request_body, peer, policy, now)?;
                    if request.header().request_id() != &request_id
                        || request.header().protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .prepare_mount_scope_identity(artifacts, &request, request_body, &mut clock)
                        .await?
                        .into_parts()
                }
                _ => return Err(DormantHostBrokerCallErrorV1::StaleKernel),
            };
            let response_body_digest: [u8; 32] = Sha256::digest(&response).into();
            let terminal_verifier_commitment = self.broker.terminal_verifier_commitment()?;
            let binding = scope_replay_binding(
                method,
                request_id,
                request_body_digest,
                signed_request_digest,
                session_binding,
                response_body_digest,
                terminal_verifier_commitment,
                artifacts,
                peer,
                policy,
                protocol_version,
                protected_boot_id,
            );
            let locator = self.broker.retain_scope_replay_authority(binding)?;
            let mut digest = Sha256::new();
            digest.update(b"aos-sandbox-host-broker-observation-v1\0");
            digest.update((method as i32).to_be_bytes());
            digest.update(request_id);
            digest.update(request_body_digest.as_bytes());
            digest.update(Sha256::digest(&response));
            Ok(DormantHostBrokerObservationV1 {
                request_id,
                response,
                commitment: ObjectDigest::from_bytes(digest.finalize().into()),
                descriptors,
                scope_replay_ticket: Some(DormantHostScopeReplayTicketV1 {
                    locator,
                    method,
                    request_id,
                    request_body_digest,
                    signed_request_digest,
                    session_binding,
                    response_body_digest,
                    terminal_verifier_commitment,
                    signed_outcome_digest: [0; 32],
                    protected_generation: 0,
                    protected_head: [0; 32],
                    artifact_commitment: authorization_artifact_commitment(artifacts),
                    peer,
                    policy,
                    protocol_version,
                    protected_boot_id,
                }),
            })
        })
    }

    fn consume_authenticated_consumer_cgroup<'call>(
        &'call mut self,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    > {
        Box::pin(async move {
            if KernelBootId::current()
                .map_err(|_| DormantHostBrokerCallErrorV1::StaleKernel)?
                .into_bytes()
                != protected_boot_id
                || ObjectDigest::from_bytes(Sha256::digest(request_body).into())
                    != request_body_digest
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }

            let last_boottime = &mut self.last_boottime_nanoseconds;
            let mut clock = || {
                let sample = crate::service::trusted_paired_clock_sample()?;
                if sample.host_boot_id() != protected_boot_id
                    || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                {
                    return Err(HostError::Fence(
                        "broker-session kernel boot changed before consumer cgroup readback",
                    ));
                }
                *last_boottime = Some(sample.boottime_nanoseconds());
                Ok(sample)
            };
            let now = clock()?.boottime_nanoseconds();
            let request = decode_consumer_cgroup_request_v1(request_body, peer, policy, now)?;
            if request.header().request_id() != &request_id
                || request.header().protocol_version() != protocol_version
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }
            let (response, descriptors) = self
                .broker
                .prepare_consumer_cgroup(&request, &mut clock)
                .await?
                .into_checked_parts(&mut clock)?;

            let mut digest = Sha256::new();
            digest.update(b"aos-sandbox-host-broker-observation-v1\0");
            digest.update(
                (BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP as i32).to_be_bytes(),
            );
            digest.update(request_id);
            digest.update(request_body_digest.as_bytes());
            digest.update(Sha256::digest(&response));
            Ok(DormantHostBrokerObservationV1 {
                request_id,
                response,
                commitment: ObjectDigest::from_bytes(digest.finalize().into()),
                descriptors,
                scope_replay_ticket: None,
            })
        })
    }

    fn consume_authenticated_scope_replay<'call>(
        &'call mut self,
        replay: Option<&'call DormantHostScopeReplayTicketV1>,
        method: BrokerMethod,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        expected_response_body_digest: [u8; 32],
        signed_outcome_digest: [u8; 32],
        protected_generation: u64,
        protected_head: [u8; 32],
        terminal_verifier_commitment: [u8; 32],
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1>,
                > + 'call,
        >,
    > {
        Box::pin(async move {
            let body_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
            if signed_outcome_digest == [0; 32]
                || protected_generation == 0
                || protected_head == [0; 32]
                || replay.is_some_and(|replay| {
                    replay.method != method
                        || replay.request_id != request_id
                        || replay.request_body_digest != body_digest
                        || replay.signed_request_digest != signed_request_digest
                        || replay.session_binding != session_binding
                        || replay.response_body_digest != expected_response_body_digest
                        || replay.signed_outcome_digest != signed_outcome_digest
                        || replay.protected_generation != protected_generation
                        || replay.protected_head != protected_head
                        || replay.artifact_commitment
                            != authorization_artifact_commitment(artifacts)
                        || replay.peer != peer
                        || replay.policy != policy
                        || replay.protocol_version != protocol_version
                        || replay.protected_boot_id != protected_boot_id
                })
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }
            if KernelBootId::current()
                .map_err(|_| DormantHostBrokerCallErrorV1::StaleKernel)?
                .into_bytes()
                != protected_boot_id
                || body_digest != request_body_digest
            {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }
            let mut binding = scope_replay_binding(
                method,
                request_id,
                request_body_digest,
                signed_request_digest,
                session_binding,
                expected_response_body_digest,
                terminal_verifier_commitment,
                artifacts,
                peer,
                policy,
                protocol_version,
                protected_boot_id,
            );
            binding.terminal_reservation_locator =
                crate::state::scope_replay_reservation_locator(&binding);
            binding.signed_outcome_digest = signed_outcome_digest;
            binding.protected_generation = protected_generation;
            binding.protected_head = protected_head;
            let retained_locator = replay.map(|replay| replay.locator);
            self.broker
                .revalidate_scope_replay_authority(retained_locator, &binding)?;
            let last_boottime = &mut self.last_boottime_nanoseconds;
            let mut clock = || {
                let sample = crate::service::trusted_paired_clock_sample()?;
                if sample.host_boot_id() != protected_boot_id
                    || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                {
                    return Err(HostError::Fence(
                        "broker-session kernel boot changed before Host scope replay",
                    ));
                }
                *last_boottime = Some(sample.boottime_nanoseconds());
                Ok(sample)
            };
            // Replay still samples the protected monotone clock and the Host
            // physical readback samples it again. Only fresh deadline admission
            // is deliberately omitted for the already-terminal exact request.
            let _current_clock = clock()?;
            let (response, descriptors) = match method {
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
                    let request = decode_payload_scope_request_for_protected_replay(
                        request_body,
                        peer,
                        policy,
                    )?;
                    if request.header().request_id() != &request_id
                        || request.header().protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .reopen_payload_scope_for_terminal_replay(&request, &mut clock)
                        .await?
                }
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
                    let request = decode_mount_scope_request_for_protected_replay(
                        request_body,
                        peer,
                        policy,
                    )?;
                    if request.header().request_id() != &request_id
                        || request.header().protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .reopen_mount_scope_for_terminal_replay(&request, &mut clock)
                        .await?
                }
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
                    let request = decode_mount_scope_request_for_protected_replay(
                        request_body,
                        peer,
                        policy,
                    )?;
                    if request.header().request_id() != &request_id
                        || request.header().protocol_version() != protocol_version
                    {
                        return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                    }
                    self.broker
                        .reopen_mount_scope_identity_for_terminal_replay(&request, &mut clock)
                        .await?
                }
                _ => return Err(DormantHostBrokerCallErrorV1::StaleKernel),
            };
            let response_body_digest: [u8; 32] = Sha256::digest(&response).into();
            if expected_response_body_digest != response_body_digest {
                return Err(DormantHostBrokerCallErrorV1::StaleKernel);
            }
            let mut digest = Sha256::new();
            digest.update(b"aos-sandbox-host-broker-observation-v1\0");
            digest.update((method as i32).to_be_bytes());
            digest.update(request_id);
            digest.update(request_body_digest.as_bytes());
            digest.update(Sha256::digest(&response));
            Ok(DormantHostBrokerObservationV1 {
                request_id,
                response,
                commitment: ObjectDigest::from_bytes(digest.finalize().into()),
                descriptors,
                scope_replay_ticket: None,
            })
        })
    }

    fn bind_authenticated_scope_terminal(
        &mut self,
        ticket: Option<&mut DormantHostScopeReplayTicketV1>,
        receipt: &aos_sandbox_protocol::BrokerTerminalCommitReceiptV1,
    ) -> Result<[u8; 32], DormantHostBrokerCallErrorV1> {
        let locator = self.broker.finalize_scope_replay_authority(receipt)?;
        if let Some(ticket) = ticket {
            ticket.locator = locator;
            ticket.signed_outcome_digest = receipt.binding().signed_outcome_digest();
            ticket.protected_generation = receipt.binding().protected_generation();
            ticket.protected_head = receipt.binding().protected_head();
        }
        Ok(locator)
    }

    fn locate_authenticated_scope_reservation(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        signed_request_digest: [u8; 32],
        session_binding: [u8; 32],
        response_body_digest: [u8; 32],
        terminal_verifier_commitment: [u8; 32],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantHostScopeReplayReservationV1, DormantHostBrokerCallErrorV1> {
        let request_body_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
        if KernelBootId::current()
            .map_err(|_| DormantHostBrokerCallErrorV1::StaleKernel)?
            .into_bytes()
            != protected_boot_id
        {
            return Err(DormantHostBrokerCallErrorV1::StaleKernel);
        }
        let binding = scope_replay_binding(
            method,
            request_id,
            request_body_digest,
            signed_request_digest,
            session_binding,
            response_body_digest,
            terminal_verifier_commitment,
            artifacts,
            peer,
            policy,
            protocol_version,
            protected_boot_id,
        );
        self.broker
            .revalidate_scope_replay_authority(None, &binding)
            .map(DormantHostScopeReplayReservationV1)
            .map_err(Into::into)
    }
}

fn authorization_artifact_commitment(
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-broker-effect-authorization-v1\0");
    for field in [
        artifacts.broker_plan(),
        artifacts.broker_plan_signature(),
        artifacts.ownership_lease(),
        artifacts.ownership_lease_signature(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the durable binding covers every authenticated scope dimension"
)]
fn scope_replay_binding(
    method: BrokerMethod,
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    signed_request_digest: [u8; 32],
    session_binding: [u8; 32],
    response_body_digest: [u8; 32],
    terminal_verifier_commitment: [u8; 32],
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol_version: ProtocolVersion,
    protected_boot_id: [u8; 16],
) -> crate::state::HostScopeReplayBindingV1 {
    crate::state::HostScopeReplayBindingV1 {
        method: method as i32,
        request_id,
        request_body_digest: *request_body_digest.as_bytes(),
        signed_request_digest,
        session_binding,
        response_body_digest,
        terminal_verifier_commitment,
        terminal_reservation_locator: [0; 32],
        signed_outcome_digest: [0; 32],
        protected_generation: 0,
        protected_head: [0; 32],
        artifact_commitment: *authorization_artifact_commitment(artifacts).as_bytes(),
        peer_uid: peer.uid,
        peer_gid: peer.gid,
        peer_pid: peer.pid.unwrap_or_default(),
        policy_uid: policy.uid,
        policy_gid: policy.gid.unwrap_or(u32::MAX),
        policy_audience: policy.audience as i32,
        protocol_major: protocol_version.major(),
        protocol_minor: protocol_version.minor(),
        protected_boot_id,
    }
}
