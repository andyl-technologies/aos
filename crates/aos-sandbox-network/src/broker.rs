//! Crash-recoverable network preparation coordinator.
//!
//! The coordinator validates portable PREPARE semantics, requires an opaque
//! protected-catalog token, verifies signed Network authority, and atomically
//! journals linked operation records. An admitted operation must cross the
//! durable Ambiguous boundary before a future helper attempts an effect, and a
//! complete typed observation commits the resulting physical namespace. The
//! fixed kernel helper does not exist yet, so Apply remains unadvertised and
//! existing-resource actions are categorically rejected. Authoritative
//! inventory is independently available through the read-only service.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::RecordNamespace;
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_protocol::semantics::network::{CanonicalNetworkSemanticsV1, NetworkOperation};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use sha2::{Digest as _, Sha256};

use crate::authorization::{NetworkAuthorityV1, decode_assignment};
use crate::catalog::{AuthenticatedNetworkPreparationV1, ResolvedNetworkPreparationV1};
use crate::namespace_catalog::{NetworkNamespaceCatalogError, NetworkNamespacePublicationV1};
use crate::preparation_catalog::{NetworkPreparationCatalogError, NetworkPreparationCatalogV1};
use crate::state::{
    CommittedNetworkResultV1, DurableNetworkPhase, NetworkBeginOutcome, NetworkRecoveryEntry,
    NetworkStateError, NetworkStateStore, PreparedNetworkRecordInput, VerifiedNetworkResultV1,
    prepared_record,
};

/// Reports fail-closed network admission failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkBrokerError {
    /// Hostile request bytes or local catalog association failed.
    #[error("network request or catalog resolution was rejected")]
    Request,
    /// Protected signed plan, lease, or fence validation failed.
    #[error("network authority was rejected")]
    Authority,
    /// Durable admission state was corrupt, conflicting, or unavailable.
    #[error("network durable admission failed: {0}")]
    State(#[from] NetworkStateError),
    /// Protected preparation history no longer reproduces committed state.
    #[error("network preparation catalog rejected committed state: {0}")]
    PreparationCatalog(#[from] NetworkPreparationCatalogError),
    /// A committed observation cannot form a current namespace publication.
    #[error("network namespace publication was rejected: {0}")]
    NamespaceCatalog(#[from] NetworkNamespaceCatalogError),
}

/// Classifies durable admission without implying an executable effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAdmissionOutcome {
    /// Exact signed authority and intent were durably prepared.
    Prepared {
        /// Deterministic identity of the one-shot preparation effect.
        effect_digest: ObjectDigest,
    },
    /// The same effect is unfinished and must only be observed.
    ObserveOnly {
        /// Current durable crash phase.
        phase: DurableNetworkPhase,
        /// Deterministic identity of the one-shot preparation effect.
        effect_digest: ObjectDigest,
    },
    /// The exact request already committed and returns its prior result.
    Replay(CommittedNetworkResultV1),
}

/// Serializes protected network authority and durable preparation state.
pub struct NetworkAdmissionCoordinator {
    authority: NetworkAuthorityV1,
    state: NetworkStateStore,
}

impl NetworkAdmissionCoordinator {
    /// Constructs a coordinator from complete protected authority and state.
    #[must_use]
    pub const fn new(authority: NetworkAuthorityV1, state: NetworkStateStore) -> Self {
        Self { authority, state }
    }

    /// Verifies and journals an unadvertised Apply intent without executing it.
    ///
    /// Preparation accepts only an opaque token from the protected preparation
    /// catalog. Existing-resource actions are categorically rejected, and this
    /// coordinator does not invoke a privileged kernel helper.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] for hostile bytes, resolution-shape or
    /// boot mismatch, signed authority failure, or durable-state conflict.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &AuthenticatedNetworkPreparationV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<NetworkAdmissionOutcome, NetworkBrokerError> {
        let semantics = CanonicalNetworkSemanticsV1::decode(
            request_body,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| NetworkBrokerError::Request)?;
        let assignment =
            decode_assignment(request_body).map_err(|_| NetworkBrokerError::Request)?;
        let catalog = self
            .authority
            .validate_catalog(catalog, assignment)
            .map_err(|_| NetworkBrokerError::Authority)?;
        validate_catalog(&semantics, catalog)?;
        let sandbox_id = *assignment.sandbox().as_bytes();
        let request_id = *semantics.header().request_id();
        let prior_fence = self
            .state
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)
            .map(<[u8]>::to_vec);
        let admission = self
            .authority
            .admit(
                artifacts,
                &semantics,
                request_body,
                protocol_version,
                current_clock,
                prior_fence.as_deref(),
            )
            .map_err(|_| NetworkBrokerError::Authority)?;
        let fence = self
            .authority
            .seal_fence(&sandbox_id, &admission)
            .map_err(|_| NetworkBrokerError::Authority)?;
        let effect = self
            .authority
            .seal_effect(&request_id, &admission)
            .map_err(|_| NetworkBrokerError::Authority)?;
        let operation_fence = self
            .authority
            .seal_operation_fence(&request_id, &admission)
            .map_err(|_| NetworkBrokerError::Authority)?;
        let record = prepared_record(PreparedNetworkRecordInput {
            request_id,
            sandbox_id,
            transport_digest: ObjectDigest::from_bytes(Sha256::digest(request_body).into()),
            semantic_digest: semantics.argument_commitment().digest(),
            verb: semantics.broker_verb(),
            catalog: catalog.clone(),
            current_fence: fence,
            operation_fence,
            effect,
        });
        Ok(
            match self.state.begin_authorized(&self.authority, record)? {
                NetworkBeginOutcome::Prepared { effect_digest } => {
                    NetworkAdmissionOutcome::Prepared { effect_digest }
                }
                NetworkBeginOutcome::ObserveOnly {
                    phase,
                    effect_digest,
                } => NetworkAdmissionOutcome::ObserveOnly {
                    phase,
                    effect_digest,
                },
                NetworkBeginOutcome::Replay(result) => NetworkAdmissionOutcome::Replay(result),
            },
        )
    }

    /// Durably crosses the point after which a preparation may have run.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless the exact prepared request
    /// and effect digest are current.
    pub fn mark_effect_ambiguous(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
    ) -> Result<(), NetworkBrokerError> {
        self.state
            .mark_effect_ambiguous(&self.authority, request_id, effect_digest)?;
        Ok(())
    }

    /// Commits one verified current-boot namespace observation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] unless the assertion exactly
    /// matches the ambiguous durable effect and a unique physical namespace.
    pub fn commit_verified(
        &mut self,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        verified: VerifiedNetworkResultV1,
    ) -> Result<CommittedNetworkResultV1, NetworkBrokerError> {
        self.state
            .commit_verified(&self.authority, request_id, effect_digest, verified)
            .map_err(Into::into)
    }

    /// Reconstructs one default-drop namespace publication from committed state.
    ///
    /// The operation store must reproduce the exact result and protected
    /// resolution, and the preparation catalog must independently retain that
    /// resolution with its portable assignment. Pin and current-boot checks are
    /// performed later by [`crate::NetworkNamespaceCatalogV1::publish`].
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError`] when committed state is not current, the
    /// preparation reservation is absent or disagrees, or the resulting
    /// publication is incomplete.
    pub fn namespace_publication(
        &self,
        result: CommittedNetworkResultV1,
        preparations: &NetworkPreparationCatalogV1,
    ) -> Result<NetworkNamespacePublicationV1, NetworkBrokerError> {
        let entry = self.state.committed_recovery_entry(result)?;
        let resolution = self.state.recover_preparation(&entry)?;
        let assignment =
            preparations.assignment_for_resolution(result.network_handle(), &resolution)?;

        NetworkNamespacePublicationV1::from_committed(result, &resolution, assignment)
            .map_err(Into::into)
    }

    /// Reconstructs the exact protected preparation for a recovery entry.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerError::State`] when the entry no longer names
    /// the exact current record.
    pub fn recover_preparation(
        &self,
        entry: &NetworkRecoveryEntry,
    ) -> Result<ResolvedNetworkPreparationV1, NetworkBrokerError> {
        self.state.recover_preparation(entry).map_err(Into::into)
    }

    /// Returns bounded authenticated durable history for recovery.
    ///
    /// This is not current kernel inventory or readiness evidence.
    #[must_use]
    pub fn recovery_snapshot(&self) -> crate::state::NetworkRecoverySnapshotV1 {
        self.state.recovery_snapshot()
    }
}

fn validate_catalog(
    semantics: &CanonicalNetworkSemanticsV1,
    catalog: &ResolvedNetworkPreparationV1,
) -> Result<(), NetworkBrokerError> {
    match semantics.operation() {
        NetworkOperation::Prepare { endpoint_ids }
            if endpoint_ids
                .iter()
                .eq(catalog.endpoints().iter().map(|item| item.id())) => {}
        // Existing-resource admission stays closed until a typed current
        // per-handle lifecycle index can prove Prepare -> observed creation ->
        // arm/disarm/destroy CAS without permitting resurrection.
        NetworkOperation::ArmLease { .. }
        | NetworkOperation::RenewLease { .. }
        | NetworkOperation::Disarm { .. }
        | NetworkOperation::Destroy { .. } => return Err(NetworkBrokerError::Request),
        _ => return Err(NetworkBrokerError::Request),
    }
    Ok(())
}

/// Returns the closed method set safe for the current network service.
///
/// Apply remains absent until tc-BPF/netlink helpers and P0-06 readiness exist.
/// Inventory is read-only and is advertised only because service startup opens
/// and validates the complete protected namespace catalog and fixed pin root.
#[must_use]
pub fn advertised_network_methods() -> Vec<BrokerMethod> {
    vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::Path;

    use aos_proto::aos::sandbox::local::v1::{
        ApplyNetworkRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerRequestEnvelope,
        NetworkAction,
    };
    use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
    use aos_sandbox_broker::BrokerLocalRecordDomain;
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerPlanTrustAnchor, BrokerVerb,
        DecodeLimits, LeaseAssignment, MediaType, NodeId, OwnershipLease,
        OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId, RawClockProvenance,
        RevocationScopeId, TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_protocol::decode_request_envelope;
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use super::*;
    use crate::{ResolvedEndpointV1, ResolvedNetworkPreparationV1};

    const NODE: NodeId = NodeId::from_bytes([31; 16]);

    struct Fixture {
        plan_key: SigningKey,
        lease_key: SigningKey,
        plan_signer: KeyReference,
        lease_signer: KeyReference,
        plan_policy: Vec<u8>,
        plan_descriptor: aos_sandbox_core::ObjectDescriptor,
        lease_policy: Vec<u8>,
        lease_descriptor: aos_sandbox_core::ObjectDescriptor,
        plan_scope: TrustScopeId,
        lease_scope: TrustScopeId,
        revocation: RevocationScopeId,
    }

    impl Fixture {
        fn new() -> Self {
            let plan_key = SigningKey::from_bytes(&[41; 32]);
            let lease_key = SigningKey::from_bytes(&[42; 32]);
            let plan_signer = key_ref("network-plan", 3, KeyUsage::BrokerAuthorization, &plan_key);
            let lease_signer = key_ref("network-lease", 7, KeyUsage::OwnershipLease, &lease_key);
            let plan_scope = TrustScopeId::from_bytes([43; 16]);
            let lease_scope = TrustScopeId::from_bytes([44; 16]);
            let (plan_policy, plan_descriptor) = policy(
                plan_scope,
                SignaturePurpose::BrokerAuthorization,
                plan_signer.clone(),
            );
            let (lease_policy, lease_descriptor) = policy(
                lease_scope,
                SignaturePurpose::OwnershipLease,
                lease_signer.clone(),
            );
            Self {
                plan_key,
                lease_key,
                plan_signer,
                lease_signer,
                plan_policy,
                plan_descriptor,
                lease_policy,
                lease_descriptor,
                plan_scope,
                lease_scope,
                revocation: RevocationScopeId::from_bytes([45; 16]),
            }
        }

        fn authority(&self) -> NetworkAuthorityV1 {
            let plan = BrokerPlanTrustAnchor::from_trusted_configuration(
                self.plan_policy.clone(),
                self.plan_descriptor.clone(),
                self.plan_scope,
                self.plan_signer.clone(),
                self.plan_key.verifying_key().to_bytes(),
                self.revocation,
                DecodeLimits::default(),
            )
            .unwrap();
            let lease = OwnershipLeaseTrustAnchor::from_trusted_configuration(
                self.lease_policy.clone(),
                self.lease_descriptor.clone(),
                self.lease_scope,
                self.lease_signer.clone(),
                self.lease_key.verifying_key().to_bytes(),
                DecodeLimits::default(),
            )
            .unwrap();
            NetworkAuthorityV1::new(plan, lease, NODE, [46; 16], [47; 32]).unwrap()
        }

        fn artifacts(&self, request: &[u8]) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing(request, &[request])
        }

        fn artifacts_authorizing(
            &self,
            request: &[u8],
            authorized: &[&[u8]],
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let assignment = decode_assignment(request).unwrap();
            let mut grants = authorized
                .iter()
                .map(|bytes| {
                    let candidate =
                        CanonicalNetworkSemanticsV1::decode(bytes, peer(), peer_policy(), 100)
                            .unwrap();
                    BrokerGrant::new(
                        candidate.broker_verb(),
                        candidate.grant_target(),
                        candidate.argument_commitment(),
                        bytes.len() as u32,
                        0,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            grants.sort_by_key(|grant| (grant.verb(), grant.target(), grant.argument_commitment()));
            let plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Network,
                ProtocolId::NetworkBroker,
                ProtocolVersion::new(1, 1),
                assignment,
                NODE,
                self.lease_signer.clone(),
                grants,
                ObjectDigest::from_bytes([48; 32]),
                self.revocation,
                100,
                300,
                Vec::new(),
            )
            .unwrap();
            let plan_bytes = encode_broker_authorization_plan(&plan);
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                NODE,
                1,
                100,
                300,
                10,
                [49; 16],
            )
            .unwrap();
            let lease_bytes = encode_ownership_lease(&lease);
            validated(BrokerAuthorizationArtifactsV1 {
                broker_plan_signature: signed(
                    &plan_bytes,
                    PortableMediaType::BrokerAuthorizationPlan,
                    self.plan_scope,
                    self.plan_signer.clone(),
                    SignaturePurpose::BrokerAuthorization,
                    &self.plan_descriptor,
                    &self.plan_key,
                ),
                broker_plan: plan_bytes,
                ownership_lease_signature: signed(
                    &lease_bytes,
                    PortableMediaType::OwnershipLease,
                    self.lease_scope,
                    self.lease_signer.clone(),
                    SignaturePurpose::OwnershipLease,
                    &self.lease_descriptor,
                    &self.lease_key,
                ),
                ownership_lease: lease_bytes,
                ..Default::default()
            })
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn peer_policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [50; 16],
            150,
            100,
        )
        .unwrap()
    }

    fn request() -> Vec<u8> {
        request_for(7, 2, &[7, 8])
    }

    fn request_for(request_id: u8, sandbox_id: u8, endpoints: &[u8]) -> Vec<u8> {
        request_for_assignment(request_id, sandbox_id, 5, 6, endpoints)
    }

    fn request_for_assignment(
        request_id: u8,
        sandbox_id: u8,
        desired_generation: u64,
        assignment_digest: u8,
        endpoints: &[u8],
    ) -> Vec<u8> {
        let mut request = ApplyNetworkRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 1;
        header.request_id = vec![request_id; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 180;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![sandbox_id; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = desired_generation;
        fence.assignment_digest = vec![assignment_digest; 32];
        request.action = NetworkAction::NETWORK_ACTION_PREPARE.into();
        request.endpoint_ids = endpoints.iter().map(|value| vec![*value; 16]).collect();
        request.encode_to_vec()
    }

    fn catalog() -> ResolvedNetworkPreparationV1 {
        catalog_for(9, 10, 11, &[(7, 12), (8, 13)])
    }

    fn catalog_for(
        generation: u64,
        handle: u8,
        profile: u8,
        endpoints: &[(u8, u8)],
    ) -> ResolvedNetworkPreparationV1 {
        ResolvedNetworkPreparationV1::new(
            generation,
            [handle; 32],
            ObjectDigest::from_bytes([profile; 32]),
            endpoints
                .iter()
                .map(|(id, policy)| {
                    ResolvedEndpointV1::new([*id; 16], ObjectDigest::from_bytes([*policy; 32]))
                        .unwrap()
                })
                .collect(),
        )
        .unwrap()
    }

    fn authenticated_catalog(
        authority: &NetworkAuthorityV1,
        resolution: ResolvedNetworkPreparationV1,
        request: &[u8],
    ) -> AuthenticatedNetworkPreparationV1 {
        authority
            .authenticate_protected_catalog_for_assignment(
                resolution,
                decode_assignment(request).unwrap(),
            )
            .unwrap()
    }

    fn key_ref(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(id.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        signer: KeyReference,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        let bytes = encode_trust_policy(
            &TrustPolicy::new(scope, purpose, vec![signer], Vec::new()).unwrap(),
        );
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed(
        bytes: &[u8],
        media: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy: &aos_sandbox_core::ObjectDescriptor,
        key: &SigningKey,
    ) -> Vec<u8> {
        let subject =
            descriptor_for_bytes(MediaType::new(media.as_str().to_owned()).unwrap(), bytes);
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

    fn validated(
        artifacts: BrokerAuthorizationArtifactsV1,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_NETWORK_APPLY.into(),
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::NetworkBroker, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }

    #[test]
    fn only_authoritative_inventory_is_advertised() {
        assert_eq!(
            advertised_network_methods(),
            [BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES]
        );
    }

    #[test]
    fn real_signed_authority_cross_links_and_replays_prepared_intent() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let semantics =
            CanonicalNetworkSemanticsV1::decode(&request, peer(), peer_policy(), 100).unwrap();
        let admission = authority
            .admit(
                &artifacts,
                &semantics,
                &request,
                ProtocolVersion::new(1, 1),
                &clock(),
                None,
            )
            .unwrap();
        assert!(authority.seal_fence(&[99; 16], &admission).is_err());
        assert!(authority.seal_effect(&[98; 16], &admission).is_err());
        let catalog = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("first admission did not prepare the effect");
        };
        assert_ne!(effect_digest.as_bytes(), &[0; 32]);
        assert_eq!(coordinator.recovery_snapshot().entries().len(), 1);
        assert_eq!(
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .unwrap(),
            NetworkAdmissionOutcome::ObserveOnly {
                phase: DurableNetworkPhase::Prepared,
                effect_digest,
            }
        );
    }

    #[test]
    fn preparation_crosses_exact_crash_phases_and_replays_committed_result() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);

        let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        else {
            panic!("first admission did not prepare the effect");
        };
        let premature = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&request).into()),
            &catalog(),
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        assert!(
            coordinator
                .commit_verified([7; 16], effect_digest, premature)
                .is_err()
        );
        assert!(
            coordinator
                .mark_effect_ambiguous([7; 16], ObjectDigest::from_bytes([1; 32]))
                .is_err()
        );
        coordinator
            .mark_effect_ambiguous([7; 16], effect_digest)
            .unwrap();
        assert!(
            coordinator
                .mark_effect_ambiguous([7; 16], effect_digest)
                .is_err()
        );

        let verified = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&request).into()),
            &catalog(),
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        let result = coordinator
            .commit_verified([7; 16], effect_digest, verified)
            .unwrap();
        assert_eq!(result.request_id(), [7; 16]);
        assert_eq!(result.network_handle(), [10; 32]);
        assert_eq!(result.kernel_boot_id(), [51; 16]);
        assert_eq!(result.namespace_device(), 52);
        assert_eq!(result.namespace_inode(), 53);
        assert_ne!(result.result_digest().as_bytes(), &[54; 32]);

        assert_eq!(
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            NetworkAdmissionOutcome::Replay(result)
        );
        let snapshot = coordinator.recovery_snapshot();
        let entry = &snapshot.entries()[0];
        assert_eq!(entry.phase(), DurableNetworkPhase::Committed);
        assert_eq!(entry.effect_digest(), effect_digest);
        assert_eq!(entry.result(), Some(result));
        assert_eq!(coordinator.recover_preparation(entry).unwrap(), catalog());

        drop(coordinator);
        let authority = fixture.authority();
        let recovered = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        assert_eq!(
            recovered.phase([7; 16]),
            Some(DurableNetworkPhase::Committed)
        );
        assert_eq!(
            recovered.committed_recovery_entry(result).unwrap().result(),
            Some(result)
        );
    }

    #[test]
    fn ambiguous_restart_is_observation_only() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let effect_digest;
        {
            let authority = fixture.authority();
            let token = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            effect_digest = match coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap()
            {
                NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
                _ => panic!("first admission did not prepare the effect"),
            };
            coordinator
                .mark_effect_ambiguous([7; 16], effect_digest)
                .unwrap();
        }

        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert_eq!(
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap(),
            NetworkAdmissionOutcome::ObserveOnly {
                phase: DurableNetworkPhase::Ambiguous,
                effect_digest,
            }
        );
    }

    #[test]
    fn legacy_prepared_record_remains_recoverable_but_cannot_cross_the_effect_boundary() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let effect_digest;
        {
            let authority = fixture.authority();
            let token = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            effect_digest = match coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap()
            {
                NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
                _ => panic!("first admission did not prepare the effect"),
            };
            coordinator
                .state
                .rewrite_as_legacy_for_test(&coordinator.authority, [7; 16])
                .unwrap();
        }

        let authority = fixture.authority();
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        assert_eq!(store.phase([7; 16]), Some(DurableNetworkPhase::Prepared));
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(
            coordinator
                .mark_effect_ambiguous([7; 16], effect_digest)
                .is_err()
        );
    }

    #[test]
    fn mismatched_results_and_duplicate_physical_namespaces_fail_closed() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first_request = request_for(7, 2, &[7]);
        let second_request = request_for(8, 3, &[8]);
        let first_artifacts = fixture.artifacts(&first_request);
        let second_artifacts = fixture.artifacts(&second_request);
        let first_catalog = catalog_for(9, 10, 11, &[(7, 12)]);
        let second_catalog = catalog_for(10, 20, 21, &[(8, 22)]);
        let authority = fixture.authority();
        let first_token = authenticated_catalog(&authority, first_catalog.clone(), &first_request);
        let second_token =
            authenticated_catalog(&authority, second_catalog.clone(), &second_request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);

        let first_effect = match coordinator
            .admit_apply_intent(
                &first_request,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        {
            NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
            _ => panic!("first admission did not prepare the effect"),
        };
        coordinator
            .mark_effect_ambiguous([7; 16], first_effect)
            .unwrap();
        let mismatched = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&first_request).into()),
            &second_catalog,
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        assert!(
            coordinator
                .commit_verified([7; 16], first_effect, mismatched)
                .is_err()
        );
        let first_verified = VerifiedNetworkResultV1::verify_preparation(
            [7; 16],
            ObjectDigest::from_bytes(Sha256::digest(&first_request).into()),
            &first_catalog,
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([54; 32]),
        )
        .unwrap();
        coordinator
            .commit_verified([7; 16], first_effect, first_verified)
            .unwrap();

        let second_effect = match coordinator
            .admit_apply_intent(
                &second_request,
                &second_artifacts,
                &second_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap()
        {
            NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
            _ => panic!("second admission did not prepare the effect"),
        };
        coordinator
            .mark_effect_ambiguous([8; 16], second_effect)
            .unwrap();
        let collision = VerifiedNetworkResultV1::verify_preparation(
            [8; 16],
            ObjectDigest::from_bytes(Sha256::digest(&second_request).into()),
            &second_catalog,
            [51; 16],
            52,
            53,
            ObjectDigest::from_bytes([55; 32]),
        )
        .unwrap();
        assert!(
            coordinator
                .commit_verified([8; 16], second_effect, collision)
                .is_err()
        );
    }

    #[test]
    fn later_current_fence_does_not_orphan_committed_operation_authority() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first_request = request_for(7, 2, &[7]);
        let second_request = request_for_assignment(8, 2, 6, 60, &[8]);
        let first_artifacts = fixture.artifacts(&first_request);
        let second_artifacts = fixture.artifacts(&second_request);
        let first_fence;
        {
            let authority = fixture.authority();
            let first_catalog = catalog_for(9, 10, 11, &[(7, 12)]);
            let second_catalog = catalog_for(10, 20, 21, &[(8, 22)]);
            let first_token =
                authenticated_catalog(&authority, first_catalog.clone(), &first_request);
            let second_token = authenticated_catalog(&authority, second_catalog, &second_request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            let first_effect = match coordinator
                .admit_apply_intent(
                    &first_request,
                    &first_artifacts,
                    &first_token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap()
            {
                NetworkAdmissionOutcome::Prepared { effect_digest } => effect_digest,
                _ => panic!("first admission did not prepare the effect"),
            };
            coordinator
                .mark_effect_ambiguous([7; 16], first_effect)
                .unwrap();
            let verified = VerifiedNetworkResultV1::verify_preparation(
                [7; 16],
                ObjectDigest::from_bytes(Sha256::digest(&first_request).into()),
                &first_catalog,
                [51; 16],
                52,
                53,
                ObjectDigest::from_bytes([54; 32]),
            )
            .unwrap();
            coordinator
                .commit_verified([7; 16], first_effect, verified)
                .unwrap();
            first_fence = coordinator
                .state
                .authority_record(RecordNamespace::DesiredState, &[2; 16])
                .unwrap()
                .to_vec();
            assert!(matches!(
                coordinator
                    .admit_apply_intent(
                        &second_request,
                        &second_artifacts,
                        &second_token,
                        ProtocolVersion::new(1, 1),
                        peer(),
                        peer_policy(),
                        &clock(),
                    )
                    .unwrap(),
                NetworkAdmissionOutcome::Prepared { .. }
            ));
        }

        let authority = fixture.authority();
        let recovered = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        assert_eq!(recovered.recovery_snapshot().entries().len(), 2);
        assert_eq!(
            recovered.phase([7; 16]),
            Some(DurableNetworkPhase::Committed)
        );
        assert_eq!(
            recovered.phase([8; 16]),
            Some(DurableNetworkPhase::Prepared)
        );
        drop(recovered);

        let (mut journal, _) = Journal::open(
            directory.path().join("network-state.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [89; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        vec![2; 16],
                        first_fence,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn relocated_authenticated_operation_fails_recovery() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        {
            let authority = fixture.authority();
            let catalog = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        {
            let (mut journal, _) = Journal::open(
                directory.path().join("network-state.journal"),
                JournalLimits::default(),
            )
            .unwrap();
            let moved = journal
                .get(RecordNamespace::Operation, &[7; 16])
                .unwrap()
                .to_vec();
            journal
                .commit(
                    &JournalTransaction::new(
                        [90; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::Operation,
                            vec![9; 16],
                            moved,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        assert!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn relocated_operation_fence_fails_recovery() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        {
            let authority = fixture.authority();
            let catalog = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        let (mut journal, _) = Journal::open(
            directory.path().join("network-state.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        let moved = journal
            .get(RecordNamespace::AuthorityPublication, &[7; 16])
            .unwrap()
            .to_vec();
        journal
            .commit(
                &JournalTransaction::new(
                    [91; 16],
                    vec![
                        JournalRecord::delete(RecordNamespace::AuthorityPublication, vec![7; 16]),
                        JournalRecord::put(
                            RecordNamespace::AuthorityPublication,
                            vec![9; 16],
                            moved,
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn catalog_token_rejects_tamper_and_resolution_substitution() {
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        for substitute_resolution in [false, true] {
            let directory = TempDir::new().unwrap();
            let authority = fixture.authority();
            let mut token = authenticated_catalog(&authority, catalog(), &request);
            if substitute_resolution {
                token.resolution = catalog_for(10, 10, 11, &[(7, 12), (8, 13)]);
            } else {
                token.sealed[0] ^= 1;
            }
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            assert!(matches!(
                coordinator.admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                ),
                Err(NetworkBrokerError::Authority)
            ));
        }

        let directory = TempDir::new().unwrap();
        let relocated_request = request_for(7, 9, &[7, 8]);
        let relocated_artifacts = fixture.artifacts(&relocated_request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &relocated_request,
                &relocated_artifacts,
                &token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Authority)
        ));

        let directory = TempDir::new().unwrap();
        let authority = fixture.authority();
        let resolution = catalog();
        let sealed = authority
            .0
            .seal_local_record(
                RecordNamespace::DesiredState,
                resolution.binding().digest().as_bytes(),
                BrokerLocalRecordDomain::new(*b"AOSNETCATALOG002").unwrap(),
                &crate::catalog::encode_resolution(&resolution),
            )
            .unwrap();
        let token = crate::AuthenticatedNetworkPreparationV1 {
            resolution,
            assignment: decode_assignment(&request).unwrap(),
            sealed,
        };
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Authority)
        ));
    }

    #[test]
    fn missing_or_tampered_atomic_authority_links_fail_recovery() {
        for (namespace, key, tamper) in [
            (RecordNamespace::DesiredState, vec![2; 16], false),
            (RecordNamespace::Effect, vec![7; 16], false),
            (RecordNamespace::AuthorityPublication, vec![7; 16], false),
            (RecordNamespace::Operation, vec![7; 16], false),
            (RecordNamespace::DesiredState, vec![2; 16], true),
            (RecordNamespace::Effect, vec![7; 16], true),
            (RecordNamespace::AuthorityPublication, vec![7; 16], true),
            (RecordNamespace::Operation, vec![7; 16], true),
        ] {
            let directory = TempDir::new().unwrap();
            let fixture = Fixture::new();
            let request = request();
            let artifacts = fixture.artifacts(&request);
            {
                let authority = fixture.authority();
                let token = authenticated_catalog(&authority, catalog(), &request);
                let store =
                    NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
                let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
                coordinator
                    .admit_apply_intent(
                        &request,
                        &artifacts,
                        &token,
                        ProtocolVersion::new(1, 1),
                        peer(),
                        peer_policy(),
                        &clock(),
                    )
                    .unwrap();
            }
            {
                let recovered =
                    NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0)
                        .unwrap();
                assert_eq!(recovered.recovery_snapshot().entries().len(), 1);
            }
            let (mut journal, _) = Journal::open(
                directory.path().join("network-state.journal"),
                JournalLimits::default(),
            )
            .unwrap();
            let record = if tamper {
                let mut bytes = journal.get(namespace, &key).unwrap().to_vec();
                let middle = bytes.len() / 2;
                bytes[middle] ^= 1;
                JournalRecord::put(namespace, key, bytes)
            } else {
                JournalRecord::delete(namespace, key)
            };
            journal
                .commit(
                    &JournalTransaction::new(
                        [namespace as u8 + 70 + u8::from(tamper) * 10; 16],
                        vec![record],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(journal);
            assert!(
                NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 0)
                    .is_err()
            );
        }
    }

    #[test]
    fn exact_replay_accepts_only_exact_catalog_and_request_semantics() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        let changed = authenticated_catalog(
            &coordinator.authority,
            catalog_for(10, 10, 11, &[(7, 12), (8, 13)]),
            &request,
        );
        assert!(matches!(
            coordinator.admit_apply_intent(
                &request,
                &artifacts,
                &changed,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
    }

    #[test]
    fn request_semantic_and_sandbox_equivocation_fail_closed() {
        let fixture = Fixture::new();
        let first = request_for(7, 2, &[7]);
        let changed_semantics = request_for(7, 2, &[8]);
        let authorized = [&first[..], &changed_semantics[..]];
        let first_artifacts = fixture.artifacts_authorizing(&first, &authorized);
        let changed_artifacts = fixture.artifacts_authorizing(&changed_semantics, &authorized);
        let directory = TempDir::new().unwrap();
        let authority = fixture.authority();
        let first_token =
            authenticated_catalog(&authority, catalog_for(9, 10, 11, &[(7, 12)]), &first);
        let changed_token = authenticated_catalog(
            &authority,
            catalog_for(10, 20, 21, &[(8, 22)]),
            &changed_semantics,
        );
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &changed_semantics,
                &changed_artifacts,
                &changed_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));

        let directory = TempDir::new().unwrap();
        let changed_sandbox = request_for(7, 3, &[7]);
        let first_artifacts = fixture.artifacts(&first);
        let changed_artifacts = fixture.artifacts(&changed_sandbox);
        let authority = fixture.authority();
        let first_token =
            authenticated_catalog(&authority, catalog_for(9, 10, 11, &[(7, 12)]), &first);
        let changed_token = authenticated_catalog(
            &authority,
            catalog_for(10, 20, 21, &[(7, 22)]),
            &changed_sandbox,
        );
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &changed_sandbox,
                &changed_artifacts,
                &changed_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
    }

    #[test]
    fn one_pending_operation_per_sandbox_is_enforced() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first = request_for(7, 2, &[7, 8]);
        let second = request_for(8, 2, &[9, 10]);
        let authorized = [&first[..], &second[..]];
        let first_artifacts = fixture.artifacts_authorizing(&first, &authorized);
        let second_artifacts = fixture.artifacts_authorizing(&second, &authorized);
        let authority = fixture.authority();
        let first_token = authenticated_catalog(&authority, catalog(), &first);
        let second_catalog = catalog_for(10, 20, 21, &[(9, 22), (10, 23)]);
        let second_token = authenticated_catalog(&authority, second_catalog, &second);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &second,
                &second_artifacts,
                &second_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(
                NetworkStateError::PendingConflict
            ))
        ));
    }

    #[test]
    fn generation_rollback_is_rejected_on_open_and_each_begin() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        {
            let authority = fixture.authority();
            let token = authenticated_catalog(&authority, catalog(), &request);
            let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
            let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        assert!(matches!(
            NetworkStateStore::open_for_test(directory.path(), &fixture.authority(), 10),
            Err(NetworkStateError::Rollback)
        ));
        let lower_than_current = request_for(8, 3, &[9]);
        let lower_than_current_artifacts = fixture.artifacts(&lower_than_current);
        let authority = fixture.authority();
        let lower_than_current_token = authenticated_catalog(
            &authority,
            catalog_for(8, 20, 21, &[(9, 22)]),
            &lower_than_current,
        );
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &lower_than_current,
                &lower_than_current_artifacts,
                &lower_than_current_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Rollback))
        ));

        let empty = TempDir::new().unwrap();
        assert!(matches!(
            NetworkStateStore::open_for_test(empty.path(), &fixture.authority(), 10),
            Err(NetworkStateError::Rollback)
        ));
    }

    #[test]
    fn duplicate_reserved_handle_across_sandboxes_is_rejected() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let first = request_for(7, 2, &[7]);
        let second = request_for(8, 3, &[8]);
        let first_artifacts = fixture.artifacts(&first);
        let second_artifacts = fixture.artifacts(&second);
        let authority = fixture.authority();
        let first_token =
            authenticated_catalog(&authority, catalog_for(9, 10, 11, &[(7, 12)]), &first);
        let second_token =
            authenticated_catalog(&authority, catalog_for(10, 10, 13, &[(8, 14)]), &second);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &first,
                &first_artifacts,
                &first_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(matches!(
            coordinator.admit_apply_intent(
                &second,
                &second_artifacts,
                &second_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(NetworkStateError::Equivocation))
        ));
    }

    #[test]
    fn recovery_snapshot_is_lossless_and_bytewise_ordered() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let authority = fixture.authority();
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        let expected_catalog = catalog_for(10, 10, 11, &[(7, 12)]);
        for (request_id, sandbox_id, catalog) in [
            (9, 3, catalog_for(10, 20, 21, &[(8, 22)])),
            (7, 2, expected_catalog.clone()),
        ] {
            let request = request_for(
                request_id,
                sandbox_id,
                &[if request_id == 7 { 7 } else { 8 }],
            );
            let artifacts = fixture.artifacts(&request);
            let token = authenticated_catalog(&coordinator.authority, catalog, &request);
            coordinator
                .admit_apply_intent(
                    &request,
                    &artifacts,
                    &token,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap();
        }
        let snapshot = coordinator.recovery_snapshot();
        assert_eq!(snapshot.entries().len(), 2);
        assert_eq!(snapshot.entries()[0].request_id(), [7; 16]);
        assert_eq!(snapshot.entries()[1].request_id(), [9; 16]);
        assert_eq!(snapshot.entries()[0].verb(), BrokerVerb::NetworkPrepare);
        assert_eq!(
            snapshot.entries()[0].catalog_resolution(),
            &expected_catalog
        );
    }

    #[test]
    fn bounded_epoch_exhaustion_is_typed() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        let authority = fixture.authority();
        let token = authenticated_catalog(&authority, catalog(), &request);
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        coordinator
            .admit_apply_intent(
                &request,
                &artifacts,
                &token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        coordinator.state.fill_epoch_for_test();
        let next = request_for(8, 3, &[9]);
        let next_artifacts = fixture.artifacts(&next);
        let next_token = authenticated_catalog(
            &coordinator.authority,
            catalog_for(10, 20, 21, &[(9, 22)]),
            &next,
        );
        assert!(matches!(
            coordinator.admit_apply_intent(
                &next,
                &next_artifacts,
                &next_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::State(
                NetworkStateError::ResourceExhausted
            ))
        ));
    }

    #[test]
    fn production_open_rejects_relative_and_unsafe_directories() {
        let fixture = Fixture::new();
        assert!(
            NetworkStateStore::open_root_owned(
                Path::new("relative-network-state"),
                &fixture.authority(),
                0,
            )
            .is_err()
        );
        assert!(
            NetworkStateStore::open_root_owned(Path::new("/tmp"), &fixture.authority(), 0).is_err()
        );
    }

    #[test]
    fn action_and_catalog_kinds_cannot_be_substituted() {
        let prepared = request();
        let prepared_semantics =
            CanonicalNetworkSemanticsV1::decode(&prepared, peer(), peer_policy(), 100).unwrap();
        assert!(validate_catalog(&prepared_semantics, &catalog()).is_ok());

        let mut destroy = ApplyNetworkRequest::decode_from_slice(&prepared).unwrap();
        destroy.action = NetworkAction::NETWORK_ACTION_DESTROY.into();
        destroy.endpoint_ids.clear();
        destroy.network_handle = vec![10; 32];
        let destroy_semantics = CanonicalNetworkSemanticsV1::decode(
            &destroy.encode_to_vec(),
            peer(),
            peer_policy(),
            100,
        )
        .unwrap();
        assert!(validate_catalog(&destroy_semantics, &catalog()).is_err());

        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let destroy_bytes = destroy.encode_to_vec();
        // Deliberately supply authority for a different action. Receiving a
        // request error proves the closed existing-action gate runs before
        // signed admission could inspect or accept these artifacts.
        let artifacts = fixture.artifacts(&request());
        let authority = fixture.authority();
        let preparation_token = authenticated_catalog(&authority, catalog(), &request());
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
        assert!(matches!(
            coordinator.admit_apply_intent(
                &destroy_bytes,
                &artifacts,
                &preparation_token,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            ),
            Err(NetworkBrokerError::Request)
        ));
    }
}
