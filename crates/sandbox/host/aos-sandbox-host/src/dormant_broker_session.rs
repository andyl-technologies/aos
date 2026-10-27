//! Dormant authenticated-session callsite for Host ApplyRuntime.
//!
//! This adapter is deliberately not referenced by the production service. It
//! enters the existing durable Host broker only through an explicit protected
//! broker-session handoff and rechecks every supplied clock sample against the
//! session's pinned kernel boot.

use std::future::Future;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::pin::Pin;

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_controller_domain::runtime_execution::{
    DormantRuntimeExecutionClaimV1, ProtectedHostNoApplySettlementHistoryV1,
};
use aos_sandbox_model::{ObjectDigest, ProtocolVersion};
use aos_linux_descriptors::boot::KernelBootId;
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

/// Retains comparison-only reply copies from the actual original worker launch.
///
/// This is not a terminal outcome, live Mount lease or read grant. Security
/// retains the original pending session writer while lending this reply; the
/// owning Host broker separately retains the actual process and private PID1
/// connection. Borrowed descriptors can be duplicated, so their presence
/// does not establish completion of the outgoing copy-close barrier.
#[doc(hidden)]
pub struct DormantOriginalHostFuseWorkerPreparationV1 {
    body: Vec<u8>,
    descriptors: [OwnedFd; 2],
}

impl DormantOriginalHostFuseWorkerPreparationV1 {
    /// Borrows the bounded original response solely for exact comparisons.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Borrows Host's reply copies without converting them into worker authority.
    #[must_use]
    pub fn descriptors(&self) -> [BorrowedFd<'_>; 2] {
        self.descriptors.each_ref().map(|fd| fd.as_fd())
    }
}

/// Selects one operation on the original worker's held comparison transport.
///
/// This private-production callback contract carries no copy-absence, worker
/// lease, terminal outcome or read authority. The security owner performs each
/// operation on its original authenticated socket and still-held journal.
#[doc(hidden)]
pub enum OriginalHostFuseWorkerTransportActionV1<'record> {
    /// Rechecks the actual original pending head, deadline and fixed Mount peer.
    CheckCurrentness,
    /// Sends the exact comparison body and two original Host-produced copies.
    SendComparison {
        /// Borrows the original bounded response, never an alternate body.
        body: &'record [u8],
        /// Borrows the worker pidfd and cgroup comparison copies in that order.
        descriptors: [BorrowedFd<'record>; 2],
    },
    /// Sends a distinct zero-rights challenge after actual PID1 copy cleanup.
    SendRendezvousReady {
        /// Carries comparison bytes generated inside this same Host call.
        challenge:
            &'record aos_sandbox_protocol::fuse_worker_preparation::WorkerRendezvousChallengeV2,
    },
    /// Receives Mount's exact same-flight, nonauthorizing record-join ACK.
    ReceiveRendezvousJoined {
        /// Names the original fresh challenge, not another preparation.
        challenge:
            &'record aos_sandbox_protocol::fuse_worker_preparation::WorkerRendezvousChallengeV2,
    },
    /// Confirms only after Host repeats its physical/live-worker observations.
    SendRendezvousConfirmed {
        /// Names that same original fresh challenge.
        challenge:
            &'record aos_sandbox_protocol::fuse_worker_preparation::WorkerRendezvousChallengeV2,
    },
    /// Schedules kernel-only INIT while the same physical/live Host cut is held.
    SendKernelInitStart {
        /// Binds the original fresh flight, not another worker or initialized FD.
        challenge:
            &'record aos_sandbox_protocol::fuse_worker_preparation::WorkerRendezvousChallengeV2,
    },
    /// Receives Mount's original idmap-effect and same-session preparation ACK.
    ReceiveKernelIdmapApplied {
        /// Names the same original fresh flight; this is no read grant.
        challenge:
            &'record aos_sandbox_protocol::fuse_worker_preparation::WorkerRendezvousChallengeV2,
    },
    /// Confirms preparation after another complete physical/live Host recheck.
    SendKernelPreparationConfirmed {
        /// Names the same flight with metadata/backing still closed.
        challenge:
            &'record aos_sandbox_protocol::fuse_worker_preparation::WorkerRendezvousChallengeV2,
    },
}

/// Reports one original transport operation without claiming copy closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum OriginalHostFuseWorkerTransportProgressV1 {
    /// The original owner completed its currentness check.
    Checked,
    /// The kernel accepted the complete original comparison/control record.
    Sent,
    /// The operation did not complete; the same flight waited for readiness.
    Backpressure,
    /// The same fixed Mount peer sent its exact preparation ACK, not a grant.
    RendezvousJoined,
    /// The fixed Mount peer completed its distinct kernel-only preparation ACK.
    KernelIdmapApplied,
}

/// Borrows the fixed original comparison transport throughout Host dispatch.
/// The sealed callsite polls this callback inline on its local future while
/// the same pending Journal remains borrowed; it never transfers the callback.
#[doc(hidden)]
pub type OriginalHostFuseWorkerTransportCallbackV1<'owner> = dyn for<'record> FnMut(
        OriginalHostFuseWorkerTransportActionV1<'record>,
    ) -> Result<OriginalHostFuseWorkerTransportProgressV1, HostError>
    + 'owner;

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
    /// Borrows the actual startup Control for financial-only cold cleanup entry.
    ///
    /// # Errors
    /// Refuses a missing original; the concrete lender separately checks its
    /// currentness and pays all native/body work before entering the cold engine.
    fn borrow_control_cold_session_owner_v1(&mut self)
        -> Result<crate::HostControlColdSessionOwnerV1, DormantHostBrokerCallErrorV1>;

    /// Lends the actual installed catalog publication destination.
    ///
    /// # Errors
    /// Refuses absent component Control or occupied/failed native custody.
    fn borrow_catalog_publication_v2(&mut self)
        -> Result<crate::catalog::HostCatalogPublicationCallsiteV2<'_>, DormantHostBrokerCallErrorV1>;

    /// Borrows the selected native catalog cause without replacing its owner.
    fn catalog_publication_failure_view_v2(&self)
        -> crate::catalog::HostCatalogPublicationFailureViewV2<'_>;

    /// Admits purpose 56 and retains permanent escrow before fixed PID1 launch.
    ///
    /// The caller must hold the actual original pending session cut, consume
    /// its received packet and move the exact four role owners here. The
    /// currentness callback supplements, never replaces, Host's independent
    /// signed-plan, installed-assignment and complete local-lease admission.
    /// No terminal outcome or backing permission is produced.
    ///
    /// # Errors
    ///
    /// Rejects a foreign request, role substitution, changed pending/current
    /// custody, occupied escrow, stale image or failed launch/readback. Any
    /// failure after escrow is durable requires reconciliation, not reissue.
    fn prepare_original_fuse_worker<'call>(
        &'call mut self,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        roles: [OwnedFd; 4],
        pending_guard: &'call mut dyn FnMut() -> Result<(), HostError>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        DormantOriginalHostFuseWorkerPreparationV1,
                        DormantHostBrokerCallErrorV1,
                    >,
                > + 'call,
        >,
    >;

    /// Sends the original nonterminal comparison under Host's live launch cut.
    ///
    /// The transport owner must retain the same pending writer and socket.
    /// Successful send does not settle the request or prove descriptor-copy
    /// absence. Every error after launch preserves the permanent escrow.
    ///
    /// # Errors
    ///
    /// Rejects the original admission/launch failures and any changed physical
    /// Host state, worker invocation, pending peer or comparison send custody.
    fn send_original_fuse_worker_comparison<'call>(
        &'call mut self,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        roles: [OwnedFd; 4],
        transport: &'call mut OriginalHostFuseWorkerTransportCallbackV1<'call>,
    ) -> Pin<Box<dyn Future<Output = Result<(), DormantHostBrokerCallErrorV1>> + 'call>>;

    /// Transfers an authenticated launch-owned guest channel after Host commit.
    ///
    /// A failed response transport does not erase this one-shot in-memory
    /// custody. The service must revalidate it against protected currentness.
    fn take_authenticated_agent_launch(&mut self) -> Option<HostAgentLiveSessionV1>;

    /// Borrows the actual launch channel before any fallible upper adoption.
    ///
    /// The broker keeps ownership if validation fails. This read-only borrow
    /// permits no exchange, descriptor extraction or replacement channel.
    fn authenticated_agent_launch(&self) -> Option<&HostAgentLiveSessionV1>;

    /// Borrows entered native custody solely to defer optional stale retirement.
    ///
    /// Partial and failed originals remain relevant; this is never a positive
    /// readiness, currentness, request or effect proof.
    fn retained_runtime_native_custody_v2(&self)
        -> Option<crate::broker::HostRuntimeNativeCustodyViewV2<'_>>;

    /// Borrows the first retained launch cause for installed diagnostics.
    ///
    /// # Errors
    /// Rejects unavailable or poisoned intrinsic/capsule locks without IO.
    fn launch_failure_view_v2(&self)
        -> Result<Option<crate::broker::HostLaunchFailureViewV2<'_>>, DormantHostBrokerCallErrorV1>;

    /// Returns the verifier commitment pinned by protected Host configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed credential is absent or no longer current.
    fn fixed_terminal_verifier_commitment(&self) -> Result<[u8; 32], DormantHostBrokerCallErrorV1>;

    /// Executes the two fixed argument methods under the same original Host phase.
    ///
    /// The concrete Host owner pays before native/codec/State growth, retains
    /// every reached native prefix and runs the independently owed original
    /// post. The authenticated Session and same live Agent remain borrowed;
    /// this returns no execution Apply permission or replacement original.
    ///
    /// # Errors
    /// Refuses absent/spent financial originals, stale currentness, wrong
    /// Session/Agent/preparation, native failure or unresolved commit ambiguity.
    fn execute_prepared_argument<'call>(
        &'call mut self,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
        agent: &'call mut HostAgentLiveSessionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>>;

    /// Executes preaccept or accepted binding on the same paid native receiver.
    ///
    /// # Errors
    /// Retains financial/native/currentness causes and owed posts on refusal.
    /// Canonical response DATA cannot reconstruct or replace this receiver.
    fn execute_execution_availability<'call>(
        &'call mut self, request: &'call AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16], deadline_boottime_nanoseconds: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>>;

    /// Reports resident availability solely to select its sealed native route.
    ///
    /// This passive selector grants no request, role or currentness permission.
    fn has_execution_availability(&self) -> bool;

    /// Joins an actual Sent closure or settlement outcome to the same native owner.
    ///
    /// This is invoked only while the real committed Sent owner is retained.
    /// It creates no native owner, current lease or financial disposal token.
    ///
    /// # Errors
    /// Refuses a changed authenticated outcome, native phase or durable marker.
    fn retain_sent_execution_availability_response(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), DormantHostBrokerCallErrorV1>;

    /// Reports resident accepted custody solely for selecting its sealed route.
    ///
    /// This performs no IO and does not authorize a request or continuation.
    fn has_accepted_execution(&self, request: &AuthenticatedBrokerMethodRequestV1) -> bool;

    /// Closes an exact authenticated pending continuation on outer refusal.
    ///
    /// # Errors
    /// Rejects unrelated/unauthenticated identities or retains the actual
    /// predecessor's terminal/Ack failure. No primary operation is entered.
    fn abort_pending_accepted_execution(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1) -> Result<(), DormantHostBrokerCallErrorV1>;

    /// Attempts an independently owed Abort on the same actual fixed hold.
    ///
    /// # Errors
    /// Rejects a foreign/unentered association or retains actual terminal/Ack
    /// errors. This port cannot complete, refund or authorize an operation.
    fn abort_accepted_execution(&mut self, request: [u8; 16], session: [u8; 32],
        signed: [u8; 32]) -> Result<(), DormantHostBrokerCallErrorV1>;

    /// Executes sealed admission or first Observe on the actual held59 owner.
    ///
    /// # Errors
    /// Refuses absent live custody, changed Session, unpaid bounds, stale native
    /// proof, Storage hold failure, Guest failure or any independently owed post.
    fn execute_accepted_execution<'call>(
        &'call mut self, request: &'call AuthenticatedBrokerMethodRequestV1,
        descriptor: &'call OwnedFd, protected_boot_id: [u8; 16],
        agent: &'call mut HostAgentLiveSessionV1, deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>>;

    /// Reads QueryExecution27 through the same actual resident journal owner.
    ///
    /// # Errors
    /// Refuses foreign/unpaid read scope, stale currentness, incompatible
    /// original selectors or any held native/post/State ambiguity.
    fn query_resident_execution<'call>(
        &'call mut self, request: &'call AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16], deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>>;

    /// Disposes a positive argument interval after authenticated response completion.
    ///
    /// This sealed resource-disposal port requires the exact original request
    /// and actual resident native-positive stage. It creates no effect grant.
    ///
    /// # Errors
    /// Refuses a different, absent, failed, aliased or already disposed interval.
    fn retire_authenticated_argument(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), DormantHostBrokerCallErrorV1>;

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
    /// A successful response requires its immediate protected admission
    /// witness; a stage-only crash or expired replay stays quarantined.
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

    /// Verifies method 48 and reads the exact protected original Host pair.
    ///
    /// The response body is not an authenticated terminal until the caller
    /// commits and signs it on the same Storage-owned broker session.
    ///
    /// # Errors
    ///
    /// Rejects an inexact signed Host plan, stale lease or boot, or changed
    /// protected output custody.
    fn observe_authenticated_storage_output(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantHostBrokerCallErrorV1>;

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

    /// Executes Runtime Apply with its actual authenticated Session original.
    ///
    /// # Errors
    /// Rejects mismatched transport, stale boot/clock, failed signed admission,
    /// insufficient same-original capacity or any ambiguous native outcome.
    fn consume_authenticated_runtime_v2<'call>(
        &'call mut self,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        retained_agent: Option<&'call HostAgentLiveSessionV1>,
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = Result<DormantHostBrokerObservationV1,
        DormantHostBrokerCallErrorV1>> + 'call>>;

    /// Borrows a scheduling scalar from the same admitted execution resident.
    ///
    /// This performs no IO and grants no effect or new interval. The actual
    /// monitor separately pays and rechecks its whole original permission.
    fn resident_execution_monitor_due_data_v5(&self) -> Option<u64>;

    /// Drives one finite same-original monitor interval without a new request.
    ///
    /// # Errors
    /// Retains and reports original funding, currentness, native, clock, Agent
    /// and durability failures. An absent Agent keeps the resident unknown.
    fn monitor_resident_execution_once_v5<'call>(
        &'call mut self, agent: Option<&'call mut HostAgentLiveSessionV1>,
    ) -> Pin<Box<dyn Future<Output = Result<(), DormantHostBrokerCallErrorV1>> + 'call>>;

    /// Moves only the same fully completed paid launch Agent.
    ///
    /// # Errors
    /// Refuses incomplete/negative launch custody or a changed exact Agent;
    /// ordinary profiles return `None` and keep their existing validation path.
    fn take_paid_authenticated_agent_launch_v2(&mut self)
        -> Result<Option<HostAgentLiveSessionV1>, DormantHostBrokerCallErrorV1>;

    /// Disposes only the actual Agent of a fully authenticated terminal Stop.
    ///
    /// # Errors
    /// Retains the moved Agent on its same paid parent if native association,
    /// owed posts or the existing financial completion cannot be proven. The
    /// sealed default preserves ordinary callers without moving any owner.
    fn retire_authenticated_stopped_agent_v4(
        &mut self,
        _incoming: &mut Option<HostAgentLiveSessionV1>,
    ) -> Result<bool, DormantHostBrokerCallErrorV1> {
        Ok(false)
    }

    /// Closes a genuinely positive old Stop before a fresh Controller Session.
    ///
    /// Current Control pays both Source bookends and protected-history checks.
    /// This neither renews the old request nor supplies a new absence answer.
    ///
    /// # Errors
    /// Retains uncertain native custody, actual history/currentness failure and
    /// every independently owed post. Ordinary profiles move no owner.
    fn retire_completed_unsent_stopped_agent_v1<'call>(
        &'call mut self,
        _incoming: &'call mut Option<HostAgentLiveSessionV1>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async { Ok(false) })
    }

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

impl<Store, Worker> DormantHostBrokerCallsiteV1
    for DormantHostBrokerCompositionV1<'_, crate::catalog::FileHostCatalog, Store, Worker>
where
    Store: HostStateStore + Sync,
    Worker: HostWorker + Sync,
{
    fn borrow_control_cold_session_owner_v1(&mut self)
        -> Result<crate::HostControlColdSessionOwnerV1, DormantHostBrokerCallErrorV1>
    {
        self.broker.borrow_control_cold_session_owner_v1().map_err(Into::into)
    }

    fn borrow_catalog_publication_v2(&mut self)
        -> Result<crate::catalog::HostCatalogPublicationCallsiteV2<'_>, DormantHostBrokerCallErrorV1>
    {
        self.broker.borrow_catalog_publication_v2().map_err(Into::into)
    }

    fn catalog_publication_failure_view_v2(&self)
        -> crate::catalog::HostCatalogPublicationFailureViewV2<'_>
    {
        self.broker.catalog_publication_failure_view_v2()
    }

    fn send_original_fuse_worker_comparison<'call>(
        &'call mut self,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        roles: [OwnedFd; 4],
        transport: &'call mut OriginalHostFuseWorkerTransportCallbackV1<'call>,
    ) -> Pin<Box<dyn Future<Output = Result<(), DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async move {
            self.broker
                .send_original_fuse_worker_comparison(request, roles, transport)
                .await?;
            Ok(())
        })
    }

    fn prepare_original_fuse_worker<'call>(
        &'call mut self,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        roles: [OwnedFd; 4],
        pending_guard: &'call mut dyn FnMut() -> Result<(), HostError>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        DormantOriginalHostFuseWorkerPreparationV1,
                        DormantHostBrokerCallErrorV1,
                    >,
                > + 'call,
        >,
    > {
        Box::pin(async move {
            let reply = self
                .broker
                .prepare_original_fuse_worker(request, roles, pending_guard)
                .await?;
            Ok(DormantOriginalHostFuseWorkerPreparationV1 {
                body: reply.body,
                descriptors: reply.descriptors,
            })
        })
    }

    fn take_authenticated_agent_launch(&mut self) -> Option<HostAgentLiveSessionV1> {
        self.broker.take_authenticated_agent_launch()
    }

    fn authenticated_agent_launch(&self) -> Option<&HostAgentLiveSessionV1> {
        self.broker.authenticated_agent_launch()
    }

    fn retained_runtime_native_custody_v2(&self)
        -> Option<crate::broker::HostRuntimeNativeCustodyViewV2<'_>>
    {
        self.broker.retained_runtime_native_custody_v2()
    }

    fn resident_execution_monitor_due_data_v5(&self) -> Option<u64> {
        self.broker.resident_execution_monitor_due_data_v5()
    }

    fn monitor_resident_execution_once_v5<'call>(
        &'call mut self, agent: Option<&'call mut HostAgentLiveSessionV1>,
    ) -> Pin<Box<dyn Future<Output = Result<(), DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async move {
            match agent {
                Some(agent) => self.broker.monitor_resident_execution_once_v5(agent).await.map_err(Into::into),
                None => {
                    self.broker.retain_resident_monitor_unavailable_v5();
                    Err(DormantHostBrokerCallErrorV1::Broker(HostError::Fence(
                        "same execution resident has no live Agent")))
                }
            }
        })
    }

    fn take_paid_authenticated_agent_launch_v2(&mut self)
        -> Result<Option<HostAgentLiveSessionV1>, DormantHostBrokerCallErrorV1> {
        self.broker.take_paid_authenticated_agent_launch_v2().map_err(Into::into)
    }

    fn retire_authenticated_stopped_agent_v4(
        &mut self,
        incoming: &mut Option<HostAgentLiveSessionV1>,
    ) -> Result<bool, DormantHostBrokerCallErrorV1> {
        self.broker.retire_authenticated_stopped_agent_v4(incoming).map_err(Into::into)
    }

    fn retire_completed_unsent_stopped_agent_v1<'call>(
        &'call mut self,
        incoming: &'call mut Option<HostAgentLiveSessionV1>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async move {
            self.broker.retire_completed_unsent_stopped_agent_v1(incoming).await.map_err(Into::into)
        })
    }

    fn launch_failure_view_v2(&self)
        -> Result<Option<crate::broker::HostLaunchFailureViewV2<'_>>, DormantHostBrokerCallErrorV1>
    {
        self.broker.launch_failure_view_v2().map_err(Into::into)
    }

    fn fixed_terminal_verifier_commitment(&self) -> Result<[u8; 32], DormantHostBrokerCallErrorV1> {
        self.broker
            .terminal_verifier_commitment()
            .map_err(DormantHostBrokerCallErrorV1::from)
    }

    fn execute_prepared_argument<'call>(
        &'call mut self,
        request: &'call AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
        agent: &'call mut HostAgentLiveSessionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async move {
            self.broker.execute_argument_flight_v2(request, protected_boot_id, agent,
                deadline_boottime_nanoseconds).await.map_err(Into::into)
        })
    }

    fn has_accepted_execution(&self, request: &AuthenticatedBrokerMethodRequestV1) -> bool {
        self.broker.has_accepted_execution_v2(request)
    }

    fn has_execution_availability(&self) -> bool {
        self.broker.has_execution_availability_v2()
    }

    fn retain_sent_execution_availability_response(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), DormantHostBrokerCallErrorV1> {
        if request.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return self.broker.retain_sent_stop_cleanup_response_v1(request,outcome).map_err(Into::into);
        }
        self.broker
            .retain_sent_execution_availability_response_v2(request, outcome)
            .map_err(Into::into)
    }

    fn execute_execution_availability<'call>(
        &'call mut self, request: &'call AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16], deadline_boottime_nanoseconds: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async move {
            self.broker.execute_execution_availability_v2(request, protected_boot_id,
                deadline_boottime_nanoseconds).await.map_err(Into::into)
        })
    }

    fn abort_pending_accepted_execution(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1) -> Result<(), DormantHostBrokerCallErrorV1> {
        self.broker.abort_pending_accepted_execution_v2(request).map_err(Into::into)
    }

    fn abort_accepted_execution(&mut self, request: [u8; 16], session: [u8; 32],
        signed: [u8; 32]) -> Result<(), DormantHostBrokerCallErrorV1> {
        self.broker.abort_accepted_execution_v2(request, session, signed).map_err(Into::into)
    }

    fn execute_accepted_execution<'call>(
        &'call mut self, request: &'call AuthenticatedBrokerMethodRequestV1,
        descriptor: &'call OwnedFd, protected_boot_id: [u8; 16],
        agent: &'call mut HostAgentLiveSessionV1, deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async move {
            self.broker.execute_accepted_execution_v2(request, descriptor,
                protected_boot_id, agent, deadline).await.map_err(Into::into)
        })
    }

    fn query_resident_execution<'call>(
        &'call mut self, request: &'call AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16], deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DormantHostBrokerCallErrorV1>> + 'call>> {
        Box::pin(async move {
            self.broker.query_resident_execution_v3(request, protected_boot_id, deadline).await.map_err(Into::into)
        })
    }

    fn retire_authenticated_argument(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), DormantHostBrokerCallErrorV1> {
        self.broker.retire_authenticated_argument_v2(request).map_err(Into::into)
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

    fn observe_authenticated_storage_output(
        &mut self,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantHostBrokerCallErrorV1> {
        let last_boottime = &mut self.last_boottime_nanoseconds;
        self.broker
            .observe_storage_output(claim, request, protected_boot_id, || {
                let sample = crate::service::trusted_paired_clock_sample()?;
                if sample.host_boot_id() != protected_boot_id
                    || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
                {
                    return Err(HostError::Fence(
                        "Host Storage output readback clock is stale",
                    ));
                }
                *last_boottime = Some(sample.boottime_nanoseconds());
                Ok(sample)
            })
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
        self.consume_apply_engine_v2(request_body, request_id, request_body_digest,
            artifacts, peer, policy, protocol_version, protected_boot_id, None, None)
    }

    fn consume_authenticated_runtime_v2<'call>(
        &'call mut self, request: &'call AuthenticatedBrokerMethodRequestV1,
        retained_agent: Option<&'call HostAgentLiveSessionV1>,
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion, protected_boot_id: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = Result<DormantHostBrokerObservationV1,
        DormantHostBrokerCallErrorV1>> + 'call>> {
        self.consume_apply_engine_v2(request.exact_body(), request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            artifacts, request.peer(), request.peer_policy(), protocol_version,
            protected_boot_id, Some(request), retained_agent)
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
            if method == BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                && artifacts.is_none() && self.broker.requires_native_inventory_entry_v5()
            {
                if ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest {
                    return Err(DormantHostBrokerCallErrorV1::StaleKernel);
                }
                let response = self.broker.inventory_runtime_received_native_v5(request_body,
                    request_id, peer, policy, protocol_version, protected_boot_id,
                    &mut self.last_boottime_nanoseconds).await?;
                return Ok(seal_readonly_observation_v5(method, request_id,
                    request_body_digest, response));
            }

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
                        .inventory_runtime_authenticated_v4(&header)
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

            Ok(seal_readonly_observation_v5(method, request_id,
                request_body_digest, response))
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

impl<Store, Worker> DormantHostBrokerCompositionV1<'_, crate::catalog::FileHostCatalog, Store, Worker>
where Store: HostStateStore + Sync, Worker: HostWorker + Sync,
{
    fn consume_apply_engine_v2<'call>(
        &'call mut self,
        request_body: &'call [u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &'call ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
        authenticated: Option<&'call AuthenticatedBrokerMethodRequestV1>,
        retained_agent: Option<&'call HostAgentLiveSessionV1>,
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
            let response = match authenticated {
                Some(request) => self.broker.apply_runtime_authenticated_v2(
                    request, retained_agent, artifacts, protocol_version, checked_clock).await?,
                None => self.broker.apply_runtime(request_body, artifacts, protocol_version,
                    peer, policy, checked_clock).await?,
            };
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
}

// Both readonly dispositions seal the same actual returned body. This pure
// construction neither establishes discovery provenance nor grants a caller.
fn seal_readonly_observation_v5(method: BrokerMethod, request_id: [u8; 16],
    request_body_digest: ObjectDigest, response: Vec<u8>) -> DormantHostBrokerObservationV1 {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-host-broker-observation-v1\0");
    digest.update((method as i32).to_be_bytes());
    digest.update(request_id);
    digest.update(request_body_digest.as_bytes());
    digest.update(Sha256::digest(&response));
    DormantHostBrokerObservationV1 {
        request_id,
        response,
        commitment: ObjectDigest::from_bytes(digest.finalize().into()),
        descriptors: Vec::new(),
        scope_replay_ticket: None,
    }
}
