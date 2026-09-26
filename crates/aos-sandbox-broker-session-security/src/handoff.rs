//! Dormant broker-specific effect handoff after protected terminal currentness.
//!
//! The fixed protected owner mints one move-only permit only after revalidating
//! its exact terminal history, live pidfd peer, role profile, and kernel boot.
//! Four concrete adapters enter the existing Host, Storage, Mount, and Network
//! operations. A domain result is sealed only after a second protected-head,
//! endpoint, transcript, peer, and boot revalidation. Ambiguous post-effect
//! readback retains both the permit and privately constructed observation for
//! bounded identical reopen/readback retry without repeating the effect.
//! The mint path retains the reconstructed typed terminal outcome and rejects
//! signed `Error` results before broker-family authority can be selected.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, authenticated_broker_method_profile_v1, decode_canonical_request_v1,
};
use aos_sandbox_core::{ObjectDigest, ProtocolVersion};
use aos_sandbox_host::{
    DormantHostBrokerCallErrorV1, DormantHostBrokerCallsiteV1, DormantHostBrokerObservationV1,
};
use aos_sandbox_mount::{
    DormantMountBrokerCallErrorV1, DormantMountBrokerCallsiteV1, DormantMountBrokerObservationV1,
};
use aos_sandbox_network::{
    DormantNetworkBrokerCallErrorV1, DormantNetworkBrokerCallsiteV1,
    DormantNetworkBrokerObservationV1,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use aos_sandbox_storage::{
    DormantStorageBrokerCallErrorV1, DormantStorageBrokerCallsiteV1,
    DormantStorageBrokerObservationV1,
};
use sha2::{Digest as _, Sha256};

use crate::{BrokerSessionSecurityError, ProtectedBrokerOutcomeCurrentV1};

const MAXIMUM_OBSERVATION_EXACT_READBACK_ATTEMPTS: u8 = 3;

pub(crate) fn request_artifacts_match(
    request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
) -> bool {
    request
        .authorization()
        .is_some_and(|expected| artifact_commitment(expected) == artifact_commitment(artifacts))
}

/// Binds every role, kernel, request, session, and protected-owner fact used by an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedBrokerEffectEvidenceV1 {
    method: BrokerMethod,
    protocol: BrokerSessionProtocolV1,
    protocol_version: ProtocolVersion,
    audience: Audience,
    direction: AuthenticatedBrokerRequestDirectionV1,
    request_id: [u8; 16],
    client_sequence: u64,
    request_body_digest: ObjectDigest,
    authorization_digest: ObjectDigest,
    broker_sequence: u64,
    success_body_digest: ObjectDigest,
    success_semantic_commitment: [u8; 32],
    peer: PeerCredentials,
    peer_policy: PeerPolicy,
    policy_digest: ObjectDigest,
    node_id: [u8; 16],
    kernel_boot_id: [u8; 16],
    client_process_execution_id: [u8; 16],
    broker_process_execution_id: [u8; 16],
    profile_digest: ObjectDigest,
    session_binding: [u8; 32],
    peer_binding: [u8; 32],
    protected_generation: u64,
    protected_head: [u8; 32],
}

impl ProtectedBrokerEffectEvidenceV1 {
    /// Returns the exact authenticated broker method.
    #[must_use]
    pub const fn method(self) -> BrokerMethod {
        self.method
    }

    /// Returns the independently versioned broker family.
    #[must_use]
    pub const fn protocol(self) -> BrokerSessionProtocolV1 {
        self.protocol
    }

    /// Returns the exact negotiated domain protocol version.
    #[must_use]
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the exact negotiated local role audience.
    #[must_use]
    pub const fn audience(self) -> Audience {
        self.audience
    }

    /// Returns the endpoint-local authenticated request direction.
    #[must_use]
    pub const fn direction(self) -> AuthenticatedBrokerRequestDirectionV1 {
        self.direction
    }

    /// Returns the exact request identity.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the authenticated client-to-broker sequence.
    #[must_use]
    pub const fn client_sequence(self) -> u64 {
        self.client_sequence
    }

    /// Returns the digest of the exact validated method body.
    #[must_use]
    pub const fn request_body_digest(self) -> ObjectDigest {
        self.request_body_digest
    }

    /// Returns the commitment to all four exact signed authority artifacts.
    #[must_use]
    pub const fn authorization_digest(self) -> ObjectDigest {
        self.authorization_digest
    }

    /// Returns the authenticated broker-to-client terminal sequence.
    #[must_use]
    pub const fn broker_sequence(self) -> u64 {
        self.broker_sequence
    }

    /// Returns the digest of the exact method-validated Success body.
    #[must_use]
    pub const fn success_body_digest(self) -> ObjectDigest {
        self.success_body_digest
    }

    /// Returns the method-separated semantic commitment to the Success body.
    #[must_use]
    pub const fn success_semantic_commitment(self) -> [u8; 32] {
        self.success_semantic_commitment
    }

    /// Returns the exact kernel credentials admitted with the request.
    #[must_use]
    pub const fn peer(self) -> PeerCredentials {
        self.peer
    }

    /// Returns the exact protected endpoint policy used for admission.
    #[must_use]
    pub const fn peer_policy(self) -> PeerPolicy {
        self.peer_policy
    }

    /// Returns the commitment to the complete peer policy.
    #[must_use]
    pub const fn policy_digest(self) -> ObjectDigest {
        self.policy_digest
    }

    /// Returns the protected node identity.
    #[must_use]
    pub const fn node_id(self) -> [u8; 16] {
        self.node_id
    }

    /// Returns the kernel boot pinned by protected session custody.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the protected client process-execution identity.
    #[must_use]
    pub const fn client_process_execution_id(self) -> [u8; 16] {
        self.client_process_execution_id
    }

    /// Returns the protected broker process-execution identity.
    #[must_use]
    pub const fn broker_process_execution_id(self) -> [u8; 16] {
        self.broker_process_execution_id
    }

    /// Returns the exact closed method-profile commitment.
    #[must_use]
    pub const fn profile_digest(self) -> ObjectDigest {
        self.profile_digest
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn session_binding(self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the pidfd-backed peer binding.
    #[must_use]
    pub const fn peer_binding(self) -> [u8; 32] {
        self.peer_binding
    }

    /// Returns the exact protected owner generation.
    #[must_use]
    pub const fn protected_generation(self) -> u64 {
        self.protected_generation
    }

    /// Returns the exact protected terminal history head.
    #[must_use]
    pub const fn protected_head(self) -> [u8; 32] {
        self.protected_head
    }
}

/// Retains one exact protected terminal outcome through a dormant effect handoff.
#[must_use = "select and consume the exact broker family while currentness is borrowed"]
pub struct ProtectedBrokerEffectHandoffV1<'owner> {
    current: ProtectedBrokerOutcomeCurrentV1<'owner>,
    evidence: ProtectedBrokerEffectEvidenceV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    request_packet: Vec<u8>,
    request_body: Vec<u8>,
    signed_request_digest: [u8; 32],
    request_semantic_commitment: [u8; 32],
}

impl<'owner> ProtectedBrokerEffectHandoffV1<'owner> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        current: ProtectedBrokerOutcomeCurrentV1<'owner>,
        evidence: ProtectedBrokerEffectEvidenceV1,
        request_packet: Vec<u8>,
        request_body: Vec<u8>,
        signed_request_digest: [u8; 32],
        request_semantic_commitment: [u8; 32],
    ) -> Result<Self, BrokerSessionSecurityError> {
        let Some(profile) = authenticated_broker_method_profile_v1(evidence.method) else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let outcome = &current.owner.outcome;
        let (success_body, success_semantic_commitment) = require_success(outcome)?;
        if evidence.direction != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ServerSend
            || outcome.method() != evidence.method
            || outcome.request().canonical_packet() != request_packet
            || outcome.request().exact_body() != request_body
            || outcome.request().semantic_commitment() != request_semantic_commitment
            || outcome.broker_sequence() != evidence.broker_sequence
            || outcome.filesystem_worker_qualification_commitment()
                != current.owner.qualification_record_commitment
            || ObjectDigest::from_bytes(Sha256::digest(success_body).into())
                != evidence.success_body_digest
            || success_semantic_commitment != evidence.success_semantic_commitment
            || success_semantic_commitment
                != exact_success_semantic_commitment(evidence.method, success_body)?
            || profile.protocol() != evidence.protocol
            || profile.version()
                != (
                    evidence.protocol_version.major(),
                    evidence.protocol_version.minor(),
                )
            || profile.audience() != evidence.audience
            || evidence.peer.uid != evidence.peer_policy.uid
            || evidence
                .peer_policy
                .gid
                .is_some_and(|gid| gid != evidence.peer.gid)
            || evidence.peer_policy.audience != evidence.audience
            || profile_commitment(profile) != evidence.profile_digest
            || policy_commitment(evidence.peer_policy) != evidence.policy_digest
            || ObjectDigest::from_bytes(Sha256::digest(&request_body).into())
                != evidence.request_body_digest
            || evidence.request_id == [0; 16]
            || evidence.client_sequence == 0
            || evidence.broker_sequence == 0
            || evidence.kernel_boot_id == [0; 16]
            || evidence.client_process_execution_id == [0; 16]
            || evidence.broker_process_execution_id == [0; 16]
            || evidence.protected_generation == 0
            || evidence.protected_head == [0; 32]
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let outcome = outcome.clone();
        Ok(Self {
            current,
            evidence,
            outcome,
            request_packet,
            request_body,
            signed_request_digest,
            request_semantic_commitment,
        })
    }

    /// Returns the complete exact evidence retained through the owner borrow.
    #[must_use]
    pub const fn evidence(&self) -> ProtectedBrokerEffectEvidenceV1 {
        self.evidence
    }

    /// Returns the byte-exact canonical authenticated request packet.
    #[must_use]
    pub fn request_packet(&self) -> &[u8] {
        &self.request_packet
    }

    /// Returns the exact semantically validated method body.
    #[must_use]
    pub fn request_body(&self) -> &[u8] {
        &self.request_body
    }

    /// Returns the byte-exact canonical authenticated outcome packet.
    #[must_use]
    pub fn outcome_packet(&self) -> &[u8] {
        self.outcome.canonical_packet()
    }

    /// Returns the digest of the complete signed request artifact.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }

    /// Returns the closed request semantic commitment.
    #[must_use]
    pub const fn request_semantic_commitment(&self) -> [u8; 32] {
        self.request_semantic_commitment
    }

    /// Returns the closed outcome semantic commitment.
    #[must_use]
    pub const fn outcome_semantic_commitment(&self) -> [u8; 32] {
        self.evidence.success_semantic_commitment
    }

    /// Selects Host authority without weakening the protected-owner borrow.
    ///
    /// # Errors
    ///
    /// Returns the intact handoff when it belongs to another broker family.
    pub fn into_host(self) -> Result<ProtectedHostEffectHandoffV1<'owner>, Self> {
        self.select(BrokerSessionProtocolV1::Host)
            .map(ProtectedHostEffectHandoffV1)
    }

    /// Selects Storage authority without weakening the protected-owner borrow.
    ///
    /// # Errors
    ///
    /// Returns the intact handoff when it belongs to another broker family.
    pub fn into_storage(self) -> Result<ProtectedStorageEffectHandoffV1<'owner>, Self> {
        self.select(BrokerSessionProtocolV1::Storage)
            .map(ProtectedStorageEffectHandoffV1)
    }

    /// Selects Mount authority without weakening the protected-owner borrow.
    ///
    /// # Errors
    ///
    /// Returns the intact handoff when it belongs to another broker family.
    pub fn into_mount(self) -> Result<ProtectedMountEffectHandoffV1<'owner>, Self> {
        self.select(BrokerSessionProtocolV1::Mount)
            .map(ProtectedMountEffectHandoffV1)
    }

    /// Selects Network authority without weakening the protected-owner borrow.
    ///
    /// # Errors
    ///
    /// Returns the intact handoff when it belongs to another broker family.
    pub fn into_network(self) -> Result<ProtectedNetworkEffectHandoffV1<'owner>, Self> {
        self.select(BrokerSessionProtocolV1::Network)
            .map(ProtectedNetworkEffectHandoffV1)
    }

    fn select(self, expected: BrokerSessionProtocolV1) -> Result<Self, Self> {
        if self.evidence.protocol == expected {
            Ok(self)
        } else {
            Err(self)
        }
    }

    fn seal<Observation>(
        mut self,
        observation: Observation,
        domain_commitment: ObjectDigest,
    ) -> ProtectedBrokerEffectObservationOutcomeV1<'owner, Observation> {
        if let Err(last_error) = self.current.revalidate() {
            return ProtectedBrokerEffectObservationOutcomeV1::ExactReadbackRequired(
                ProtectedBrokerEffectObservationRetryV1 {
                    handoff: self,
                    observation,
                    domain_commitment,
                    attempts: 1,
                    last_error,
                },
            );
        }

        ProtectedBrokerEffectObservationOutcomeV1::Sealed(
            self.finish_seal(observation, domain_commitment),
        )
    }

    fn finish_seal<Observation>(
        self,
        observation: Observation,
        domain_commitment: ObjectDigest,
    ) -> ProtectedBrokerEffectObservationV1<Observation> {
        let mut digest = Sha256::new();
        digest.update(b"aos-sandbox-broker-effect-observation-v1\0");
        digest.update([self.evidence.protocol as u8]);
        digest.update((self.evidence.method as i32).to_be_bytes());
        digest.update((self.evidence.audience as i32).to_be_bytes());
        digest.update([match self.evidence.direction {
            AuthenticatedBrokerRequestDirectionV1::ClientSend => 1,
            AuthenticatedBrokerRequestDirectionV1::ServerReceive => 2,
        }]);
        digest.update(self.evidence.request_id);
        digest.update(self.evidence.client_sequence.to_be_bytes());
        digest.update(self.evidence.request_body_digest.as_bytes());
        digest.update(self.evidence.authorization_digest.as_bytes());
        digest.update(self.evidence.policy_digest.as_bytes());
        digest.update(self.evidence.profile_digest.as_bytes());
        digest.update(self.evidence.node_id);
        digest.update(self.evidence.kernel_boot_id);
        digest.update(self.evidence.peer.uid.to_be_bytes());
        digest.update(self.evidence.peer.gid.to_be_bytes());
        match self.evidence.peer.pid {
            Some(pid) => {
                digest.update([1]);
                digest.update(pid.to_be_bytes());
            }
            None => digest.update([0]),
        }
        digest.update(self.evidence.client_process_execution_id);
        digest.update(self.evidence.broker_process_execution_id);
        digest.update(self.evidence.session_binding);
        digest.update(self.evidence.peer_binding);
        digest.update(self.evidence.protected_generation.to_be_bytes());
        digest.update(self.evidence.protected_head);
        digest.update(self.signed_request_digest);
        digest.update(self.request_semantic_commitment);
        digest.update(self.evidence.broker_sequence.to_be_bytes());
        digest.update(self.evidence.success_body_digest.as_bytes());
        digest.update(self.evidence.success_semantic_commitment);
        digest.update(Sha256::digest(self.outcome.canonical_packet()));
        digest.update(domain_commitment.as_bytes());
        ProtectedBrokerEffectObservationV1 {
            evidence: self.evidence,
            observation,
            seal: ObjectDigest::from_bytes(digest.finalize().into()),
        }
    }
}

/// Preserves a completed domain observation when protected exact readback is ambiguous.
#[must_use = "seal the observation or retain its exact-readback retry authority"]
pub enum ProtectedBrokerEffectObservationOutcomeV1<'owner, Observation> {
    /// Protected currentness was revalidated and the domain observation was sealed.
    Sealed(ProtectedBrokerEffectObservationV1<Observation>),
    /// Exact protected reopen/readback must be retried without repeating the domain effect.
    ExactReadbackRequired(ProtectedBrokerEffectObservationRetryV1<'owner, Observation>),
}

/// Retains one effect permit and its exact observation across ambiguous readback.
#[must_use = "retry bounded exact readback or retain this move-only recovery authority"]
pub struct ProtectedBrokerEffectObservationRetryV1<'owner, Observation> {
    handoff: ProtectedBrokerEffectHandoffV1<'owner>,
    observation: Observation,
    domain_commitment: ObjectDigest,
    attempts: u8,
    last_error: BrokerSessionSecurityError,
}

impl<'owner, Observation> ProtectedBrokerEffectObservationRetryV1<'owner, Observation> {
    /// Returns the number of exact-readback attempts already made.
    #[must_use]
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Returns the redacted error from the most recent protected readback.
    #[must_use]
    pub const fn last_error(&self) -> &BrokerSessionSecurityError {
        &self.last_error
    }

    /// Reopens and revalidates the exact protected head without repeating the effect.
    ///
    /// # Errors
    ///
    /// Returns this intact retry authority when protected exact readback remains
    /// unavailable or the fixed three-attempt bound has already been reached.
    pub fn retry_exact_readback(
        mut self,
    ) -> Result<ProtectedBrokerEffectObservationV1<Observation>, Self> {
        if self.attempts >= MAXIMUM_OBSERVATION_EXACT_READBACK_ATTEMPTS {
            return Err(self);
        }

        self.attempts += 1;
        match self.handoff.current.revalidate() {
            Ok(()) => Ok(self
                .handoff
                .finish_seal(self.observation, self.domain_commitment)),
            Err(last_error) => {
                self.last_error = last_error;
                Err(self)
            }
        }
    }
}

/// Carries a domain observation sealed after post-effect protected revalidation.
pub struct ProtectedBrokerEffectObservationV1<Observation> {
    evidence: ProtectedBrokerEffectEvidenceV1,
    observation: Observation,
    seal: ObjectDigest,
}

impl<Observation> ProtectedBrokerEffectObservationV1<Observation> {
    /// Returns the exact protected evidence bound to the observation.
    #[must_use]
    pub const fn evidence(&self) -> ProtectedBrokerEffectEvidenceV1 {
        self.evidence
    }

    /// Returns the domain observation that passed owner revalidation.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }

    /// Returns the complete broker-session/domain observation seal.
    #[must_use]
    pub const fn seal(&self) -> ObjectDigest {
        self.seal
    }

    /// Consumes the seal and returns the privately constructed domain result.
    #[must_use]
    pub fn into_observation(self) -> Observation {
        self.observation
    }
}

/// Preserves whether the domain call or protected post-read rejected handoff.
#[derive(Debug, thiserror::Error)]
pub enum DormantBrokerEffectHandoffErrorV1<Domain> {
    /// The real domain operation rejected the request or effect.
    #[error("broker domain operation rejected the authenticated handoff")]
    Domain(Domain),
    /// The protected head or live kernel evidence changed around the call.
    #[error("protected broker-session currentness changed during handoff: {0}")]
    Currentness(#[from] BrokerSessionSecurityError),
}

macro_rules! family_handoff {
    ($authority:ident, $summary:literal) => {
        #[doc = $summary]
        #[must_use = "consume the authority while its protected-owner borrow is live"]
        pub struct $authority<'owner>(ProtectedBrokerEffectHandoffV1<'owner>);

        impl $authority<'_> {
            /// Borrows the complete protected broker-session evidence.
            #[must_use]
            pub const fn evidence(&self) -> ProtectedBrokerEffectEvidenceV1 {
                self.0.evidence
            }
        }
    };
}

family_handoff!(
    ProtectedHostEffectHandoffV1,
    "Protected Host broker effect authority."
);
family_handoff!(
    ProtectedStorageEffectHandoffV1,
    "Protected Storage broker effect authority."
);
family_handoff!(
    ProtectedMountEffectHandoffV1,
    "Protected Mount broker effect authority."
);
family_handoff!(
    ProtectedNetworkEffectHandoffV1,
    "Protected Network broker effect authority."
);

/// Adapts only the sealed Host callsite implemented by `aos-sandbox-host`.
pub struct DormantHostBrokerEffectAdapterV1<'adapter> {
    callsite: &'adapter mut dyn DormantHostBrokerCallsiteV1,
    artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
}

/// Adapts the sealed Host observe, inventory, and effect-query callsites.
pub struct DormantHostBrokerObservationAdapterV1<'adapter> {
    callsite: &'adapter mut dyn DormantHostBrokerCallsiteV1,
    artifacts: Option<&'adapter ValidatedUntrustedAuthorizationArtifacts>,
}

impl<'adapter> DormantHostBrokerObservationAdapterV1<'adapter> {
    /// Constructs an adapter for a Host observation method without artifacts.
    #[must_use]
    pub fn new(callsite: &'adapter mut dyn DormantHostBrokerCallsiteV1) -> Self {
        Self {
            callsite,
            artifacts: None,
        }
    }

    /// Constructs an adapter for Host QueryRuntimeEffect's exact artifacts.
    #[must_use]
    pub fn new_authorized(
        callsite: &'adapter mut dyn DormantHostBrokerCallsiteV1,
        artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
    ) -> Self {
        Self {
            callsite,
            artifacts: Some(artifacts),
        }
    }

    pub(crate) fn matches_request(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        match (request.authorization(), self.artifacts) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                artifact_commitment(expected) == artifact_commitment(actual)
            }
            (None, Some(_)) | (Some(_), None) => false,
        }
    }

    pub(crate) async fn execute_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1> {
        self.callsite
            .consume_authenticated_observation(
                request.method(),
                request.exact_body(),
                request.request_id(),
                ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
                self.artifacts,
                request.peer(),
                request.peer_policy(),
                protocol_version,
                protected_boot_id,
            )
            .await
    }
}

impl<'adapter> DormantHostBrokerEffectAdapterV1<'adapter> {
    pub(crate) fn matches_request(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        request_artifacts_match(request, self.artifacts)
    }

    /// Constructs an explicit source-only Host adapter.
    #[must_use]
    pub fn new(
        callsite: &'adapter mut dyn DormantHostBrokerCallsiteV1,
        artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
    ) -> Self {
        Self {
            callsite,
            artifacts,
        }
    }

    pub(crate) fn fixed_terminal_verifier_commitment(
        &self,
    ) -> Result<[u8; 32], DormantHostBrokerCallErrorV1> {
        self.callsite.fixed_terminal_verifier_commitment()
    }

    pub(crate) async fn execute_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1> {
        self.callsite
            .consume_authenticated_apply(
                request.exact_body(),
                request.request_id(),
                ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
                self.artifacts,
                request.peer(),
                request.peer_policy(),
                protocol_version,
                protected_boot_id,
            )
            .await
    }

    pub(crate) async fn execute_scope_before_outcome(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1> {
        self.callsite
            .consume_authenticated_scope(
                request.method(),
                request.exact_body(),
                request.request_id(),
                ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
                request.signed_request_digest(),
                request.session_binding(),
                self.artifacts,
                request.peer(),
                request.peer_policy(),
                protocol_version,
                protected_boot_id,
            )
            .await
    }

    pub(crate) async fn execute_scope_replay_before_outcome(
        &mut self,
        replay: Option<&aos_sandbox_host::DormantHostScopeReplayTicketV1>,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        expected_response_body_digest: [u8; 32],
        signed_outcome_digest: [u8; 32],
        protected_generation: u64,
        protected_head: [u8; 32],
        terminal_verifier_commitment: [u8; 32],
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantHostBrokerObservationV1, DormantHostBrokerCallErrorV1> {
        self.callsite
            .consume_authenticated_scope_replay(
                replay,
                request.method(),
                request.exact_body(),
                request.request_id(),
                ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
                request.signed_request_digest(),
                request.session_binding(),
                expected_response_body_digest,
                signed_outcome_digest,
                protected_generation,
                protected_head,
                terminal_verifier_commitment,
                self.artifacts,
                request.peer(),
                request.peer_policy(),
                protocol_version,
                protected_boot_id,
            )
            .await
    }

    pub(crate) fn bind_scope_terminal(
        &mut self,
        ticket: Option<&mut aos_sandbox_host::DormantHostScopeReplayTicketV1>,
        receipt: &aos_sandbox_protocol::BrokerTerminalCommitReceiptV1,
    ) -> Result<[u8; 32], DormantHostBrokerCallErrorV1> {
        self.callsite
            .bind_authenticated_scope_terminal(ticket, receipt)
    }

    pub(crate) fn locate_scope_reservation(
        &mut self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        response_body_digest: [u8; 32],
        terminal_verifier_commitment: [u8; 32],
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<aos_sandbox_host::DormantHostScopeReplayReservationV1, DormantHostBrokerCallErrorV1>
    {
        self.callsite.locate_authenticated_scope_reservation(
            request.method(),
            request.exact_body(),
            request.request_id(),
            request.signed_request_digest(),
            request.session_binding(),
            response_body_digest,
            terminal_verifier_commitment,
            self.artifacts,
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }
}

impl<'owner> ProtectedHostEffectHandoffV1<'owner> {
    /// Immediately consumes Host ApplyRuntime and seals its post-read observation.
    ///
    /// # Errors
    ///
    /// Returns an error before or during the domain call when the exact family,
    /// artifacts, currentness, or Host operation rejects the handoff. Ambiguous
    /// post-effect readback is retained in the successful outcome for bounded retry.
    pub async fn handoff_to(
        self,
        adapter: DormantHostBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerEffectObservationOutcomeV1<'owner, DormantHostBrokerObservationV1>,
        DormantBrokerEffectHandoffErrorV1<DormantHostBrokerCallErrorV1>,
    > {
        let mut handoff = self.0;
        handoff.current.revalidate()?;
        let evidence = handoff.evidence;
        if evidence.method != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        if artifact_commitment(adapter.artifacts) != evidence.authorization_digest {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        let observation = adapter
            .callsite
            .consume_authenticated_apply(
                &handoff.request_body,
                evidence.request_id,
                evidence.request_body_digest,
                adapter.artifacts,
                evidence.peer,
                evidence.peer_policy,
                evidence.protocol_version,
                evidence.kernel_boot_id,
            )
            .await
            .map_err(DormantBrokerEffectHandoffErrorV1::Domain)?;
        let commitment = observation.commitment();
        Ok(handoff.seal(observation, commitment))
    }
}

/// Adapts only the sealed Storage callsite implemented by `aos-sandbox-storage`.
pub struct DormantStorageBrokerEffectAdapterV1<'adapter> {
    callsite: &'adapter mut dyn DormantStorageBrokerCallsiteV1,
    artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
}

impl<'adapter> DormantStorageBrokerEffectAdapterV1<'adapter> {
    pub(crate) fn matches_request(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        request_artifacts_match(request, self.artifacts)
    }

    /// Constructs an explicit source-only Storage adapter.
    #[must_use]
    pub fn new(
        callsite: &'adapter mut dyn DormantStorageBrokerCallsiteV1,
        artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
    ) -> Self {
        Self {
            callsite,
            artifacts,
        }
    }

    pub(crate) fn execute_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantStorageBrokerObservationV1, DormantStorageBrokerCallErrorV1> {
        self.callsite.consume_authenticated_apply(
            request.exact_body(),
            request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            self.artifacts,
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }

    pub(crate) fn execute_operation_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<Vec<u8>, DormantStorageBrokerCallErrorV1> {
        self.callsite.consume_authenticated_operation(
            request.method(),
            request.exact_body(),
            request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            self.artifacts,
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }
}

impl<'owner> ProtectedStorageEffectHandoffV1<'owner> {
    /// Immediately consumes Storage Apply and seals its post-read observation.
    ///
    /// # Errors
    ///
    /// Returns an error before or during the domain call when the exact family,
    /// artifacts, currentness, or Storage operation rejects the handoff. Ambiguous
    /// post-effect readback is retained in the successful outcome for bounded retry.
    pub fn handoff_to(
        self,
        adapter: DormantStorageBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerEffectObservationOutcomeV1<'owner, DormantStorageBrokerObservationV1>,
        DormantBrokerEffectHandoffErrorV1<DormantStorageBrokerCallErrorV1>,
    > {
        let mut handoff = self.0;
        handoff.current.revalidate()?;
        let evidence = handoff.evidence;
        if evidence.method != BrokerMethod::BROKER_METHOD_STORAGE_APPLY {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        if artifact_commitment(adapter.artifacts) != evidence.authorization_digest {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        let observation = adapter
            .callsite
            .consume_authenticated_apply(
                &handoff.request_body,
                evidence.request_id,
                evidence.request_body_digest,
                adapter.artifacts,
                evidence.peer,
                evidence.peer_policy,
                evidence.protocol_version,
                evidence.kernel_boot_id,
            )
            .map_err(DormantBrokerEffectHandoffErrorV1::Domain)?;
        let commitment = observation.commitment();
        Ok(handoff.seal(observation, commitment))
    }
}

/// Adapts only the sealed Mount callsite implemented by `aos-sandbox-mount`.
pub struct DormantMountBrokerEffectAdapterV1<'adapter> {
    callsite: &'adapter mut dyn DormantMountBrokerCallsiteV1,
    artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
}

/// Adapts only the sealed authoritative Mount inventory callsite.
pub struct DormantMountBrokerInventoryAdapterV1<'adapter> {
    callsite: &'adapter mut dyn DormantMountBrokerCallsiteV1,
}

impl<'adapter> DormantMountBrokerInventoryAdapterV1<'adapter> {
    /// Constructs an explicit source-only Mount inventory adapter.
    #[must_use]
    pub fn new(callsite: &'adapter mut dyn DormantMountBrokerCallsiteV1) -> Self {
        Self { callsite }
    }

    pub(crate) fn matches_request(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        request.authorization().is_none()
    }

    pub(crate) fn execute_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        self.callsite.consume_authenticated_inventory(
            request.method(),
            request.exact_body(),
            request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }
}

/// Couples a sealed Mount callsite to a Host-authenticated mount scope.
pub struct DormantMountCatalogPreparationAdapterV1<'adapter> {
    callsite: &'adapter mut dyn DormantMountBrokerCallsiteV1,
    scope: aos_sandbox_mount::host_scope::ObservedMountScope,
}

impl<'adapter> DormantMountCatalogPreparationAdapterV1<'adapter> {
    /// Constructs the adapter from the non-forgeable Host scope observation.
    #[must_use]
    pub fn new(
        callsite: &'adapter mut dyn DormantMountBrokerCallsiteV1,
        scope: aos_sandbox_mount::host_scope::ObservedMountScope,
    ) -> Self {
        Self { callsite, scope }
    }

    pub(crate) fn execute_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        self.callsite.consume_authenticated_catalog_preparation(
            request.exact_body(),
            request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            self.scope,
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }
}

impl<'adapter> DormantMountBrokerEffectAdapterV1<'adapter> {
    pub(crate) fn matches_request(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        request_artifacts_match(request, self.artifacts)
    }

    /// Constructs an explicit source-only Mount adapter.
    #[must_use]
    pub fn new(
        callsite: &'adapter mut dyn DormantMountBrokerCallsiteV1,
        artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
    ) -> Self {
        Self {
            callsite,
            artifacts,
        }
    }

    pub(crate) fn execute_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        self.callsite.consume_authenticated_apply(
            request.exact_body(),
            request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            self.artifacts,
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }

    pub(crate) fn execute_destination_slot_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        self.callsite.consume_authenticated_destination_slot(
            request.method(),
            request.exact_body(),
            request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            self.artifacts,
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }
}

impl<'owner> ProtectedMountEffectHandoffV1<'owner> {
    /// Immediately consumes Mount Apply and seals its post-read observation.
    ///
    /// # Errors
    ///
    /// Returns an error before or during the domain call when the exact family,
    /// artifacts, currentness, or Mount operation rejects the handoff. Ambiguous
    /// post-effect readback is retained in the successful outcome for bounded retry.
    pub fn handoff_to(
        self,
        adapter: DormantMountBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerEffectObservationOutcomeV1<'owner, DormantMountBrokerObservationV1>,
        DormantBrokerEffectHandoffErrorV1<DormantMountBrokerCallErrorV1>,
    > {
        let mut handoff = self.0;
        handoff.current.revalidate()?;
        let evidence = handoff.evidence;
        if evidence.method != BrokerMethod::BROKER_METHOD_MOUNT_APPLY {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        if artifact_commitment(adapter.artifacts) != evidence.authorization_digest {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        let observation = adapter
            .callsite
            .consume_authenticated_apply(
                &handoff.request_body,
                evidence.request_id,
                evidence.request_body_digest,
                adapter.artifacts,
                evidence.peer,
                evidence.peer_policy,
                evidence.protocol_version,
                evidence.kernel_boot_id,
            )
            .map_err(DormantBrokerEffectHandoffErrorV1::Domain)?;
        let commitment = observation.commitment();
        Ok(handoff.seal(observation, commitment))
    }
}

/// Adapts only the sealed Network callsite implemented by `aos-sandbox-network`.
pub struct DormantNetworkBrokerEffectAdapterV1<'adapter> {
    callsite: &'adapter mut dyn DormantNetworkBrokerCallsiteV1,
    artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
}

impl<'adapter> DormantNetworkBrokerEffectAdapterV1<'adapter> {
    pub(crate) fn matches_request(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        request_artifacts_match(request, self.artifacts)
    }

    /// Constructs an explicit source-only Network adapter.
    #[must_use]
    pub fn new(
        callsite: &'adapter mut dyn DormantNetworkBrokerCallsiteV1,
        artifacts: &'adapter ValidatedUntrustedAuthorizationArtifacts,
    ) -> Self {
        Self {
            callsite,
            artifacts,
        }
    }

    pub(crate) fn execute_before_outcome(
        self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
        self.callsite.consume_authenticated_apply(
            request.exact_body(),
            request.request_id(),
            ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            self.artifacts,
            request.peer(),
            request.peer_policy(),
            protocol_version,
            protected_boot_id,
        )
    }
}

impl<'owner> ProtectedNetworkEffectHandoffV1<'owner> {
    /// Immediately consumes Network Apply and seals its post-read observation.
    ///
    /// # Errors
    ///
    /// Returns an error before or during the domain call when the exact family,
    /// artifacts, currentness, or Network operation rejects the handoff. Ambiguous
    /// post-effect readback is retained in the successful outcome for bounded retry.
    pub fn handoff_to(
        self,
        adapter: DormantNetworkBrokerEffectAdapterV1<'_>,
    ) -> Result<
        ProtectedBrokerEffectObservationOutcomeV1<'owner, DormantNetworkBrokerObservationV1>,
        DormantBrokerEffectHandoffErrorV1<DormantNetworkBrokerCallErrorV1>,
    > {
        let mut handoff = self.0;
        handoff.current.revalidate()?;
        let evidence = handoff.evidence;
        if evidence.method != BrokerMethod::BROKER_METHOD_NETWORK_APPLY {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        if artifact_commitment(adapter.artifacts) != evidence.authorization_digest {
            return Err(DormantBrokerEffectHandoffErrorV1::Currentness(
                BrokerSessionSecurityError::Currentness,
            ));
        }
        let observation = adapter
            .callsite
            .consume_authenticated_apply(
                &handoff.request_body,
                evidence.request_id,
                evidence.request_body_digest,
                adapter.artifacts,
                evidence.peer,
                evidence.peer_policy,
                evidence.protocol_version,
                evidence.kernel_boot_id,
            )
            .map_err(DormantBrokerEffectHandoffErrorV1::Domain)?;
        let commitment = observation.commitment();
        Ok(handoff.seal(observation, commitment))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn effect_evidence(
    method: BrokerMethod,
    direction: AuthenticatedBrokerRequestDirectionV1,
    request_id: [u8; 16],
    client_sequence: u64,
    request_body: &[u8],
    request_packet: &[u8],
    peer: PeerCredentials,
    peer_policy: PeerPolicy,
    node_id: [u8; 16],
    kernel_boot_id: [u8; 16],
    protocol: BrokerSessionProtocolV1,
    protocol_version: ProtocolVersion,
    audience: Audience,
    client_process_execution_id: [u8; 16],
    broker_process_execution_id: [u8; 16],
    session_binding: [u8; 32],
    peer_binding: [u8; 32],
    protected_generation: u64,
    protected_head: [u8; 32],
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<ProtectedBrokerEffectEvidenceV1, BrokerSessionSecurityError> {
    let profile = authenticated_broker_method_profile_v1(method)
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let canonical = decode_canonical_request_v1(request_packet)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    let authorization = canonical
        .message()
        .authorization
        .as_option()
        .ok_or(BrokerSessionSecurityError::Currentness)?;
    let (success_body, success_semantic_commitment) = require_success(outcome)?;
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ServerSend
        || outcome.method() != method
        || outcome.request().canonical_packet() != request_packet
        || outcome.request().exact_body() != request_body
        || outcome.request().direction() != direction
        || outcome.request().request_id() != request_id
        || outcome.request().client_sequence() != client_sequence
        || outcome.request().session_binding() != session_binding
        || outcome.request().peer() != peer
        || outcome.request().peer_policy() != peer_policy
        || success_semantic_commitment != exact_success_semantic_commitment(method, success_body)?
    {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(ProtectedBrokerEffectEvidenceV1 {
        method,
        protocol,
        protocol_version,
        audience,
        direction,
        request_id,
        client_sequence,
        request_body_digest: ObjectDigest::from_bytes(Sha256::digest(request_body).into()),
        authorization_digest: artifact_bytes_commitment(
            &authorization.broker_plan,
            &authorization.broker_plan_signature,
            &authorization.ownership_lease,
            &authorization.ownership_lease_signature,
        ),
        broker_sequence: outcome.broker_sequence(),
        success_body_digest: ObjectDigest::from_bytes(Sha256::digest(success_body).into()),
        success_semantic_commitment,
        peer,
        peer_policy,
        policy_digest: policy_commitment(peer_policy),
        node_id,
        kernel_boot_id,
        client_process_execution_id,
        broker_process_execution_id,
        profile_digest: profile_commitment(profile),
        session_binding,
        peer_binding,
        protected_generation,
        protected_head,
    })
}

fn require_success(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(&[u8], [u8; 32]), BrokerSessionSecurityError> {
    match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success {
            exact_body,
            semantic_commitment,
            ..
        } => Ok((exact_body, *semantic_commitment)),
        AuthenticatedBrokerMethodResultV1::Error(_) => Err(BrokerSessionSecurityError::Currentness),
    }
}

fn exact_success_semantic_commitment(
    method: BrokerMethod,
    body: &[u8],
) -> Result<[u8; 32], BrokerSessionSecurityError> {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-authenticated-method-outcome-v1\0");
    digest.update((method as i32).to_be_bytes());
    digest.update(
        u64::try_from(body.len())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .to_be_bytes(),
    );
    digest.update(body);
    Ok(digest.finalize().into())
}

fn artifact_commitment(artifacts: &ValidatedUntrustedAuthorizationArtifacts) -> ObjectDigest {
    artifact_bytes_commitment(
        artifacts.broker_plan(),
        artifacts.broker_plan_signature(),
        artifacts.ownership_lease(),
        artifacts.ownership_lease_signature(),
    )
}

fn artifact_bytes_commitment(
    broker_plan: &[u8],
    broker_plan_signature: &[u8],
    ownership_lease: &[u8],
    ownership_lease_signature: &[u8],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-broker-effect-authorization-v1\0");
    for field in [
        broker_plan,
        broker_plan_signature,
        ownership_lease,
        ownership_lease_signature,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn policy_commitment(policy: PeerPolicy) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-broker-effect-peer-policy-v1\0");
    digest.update(policy.uid.to_be_bytes());
    match policy.gid {
        Some(gid) => {
            digest.update([1]);
            digest.update(gid.to_be_bytes());
        }
        None => digest.update([0]),
    }
    digest.update((policy.audience as i32).to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn profile_commitment(
    profile: aos_sandbox_broker_session_protocol::BrokerSessionMethodProfileV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-broker-effect-profile-v1\0");
    digest.update((profile.method() as i32).to_be_bytes());
    digest.update([profile.protocol() as u8]);
    digest.update(profile.version().0.to_be_bytes());
    digest.update(profile.version().1.to_be_bytes());
    digest.update((profile.audience() as i32).to_be_bytes());
    digest.update((profile.request_descriptor_roles().len() as u64).to_be_bytes());
    for role in profile.request_descriptor_roles() {
        digest.update((*role as i32).to_be_bytes());
    }
    digest.update((profile.success_response_descriptor_roles().len() as u64).to_be_bytes());
    for role in profile.success_response_descriptor_roles() {
        digest.update((*role as i32).to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}
