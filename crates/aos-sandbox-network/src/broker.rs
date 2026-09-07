//! Non-executing network admission coordinator.
//!
//! The coordinator validates portable PREPARE semantics, requires an opaque
//! protected-catalog token, verifies signed Network authority, and atomically
//! journals linked Prepared records. Existing-resource actions are
//! categorically rejected. No production catalog-token publisher exists in
//! this increment, so admission is mechanically unreachable outside internal
//! tests and no helper or transition can attempt a kernel effect.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::RecordNamespace;
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_protocol::semantics::network::{CanonicalNetworkSemanticsV1, NetworkOperation};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use sha2::{Digest as _, Sha256};

use crate::authorization::{NetworkAuthorityV1, decode_assignment};
use crate::catalog::{AuthenticatedNetworkPreparationV1, ResolvedNetworkPreparationV1};
use crate::state::{
    NetworkBeginOutcome, NetworkStateError, NetworkStateStore, PreparedNetworkRecordInput,
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
}

/// Classifies durable admission without implying an executable effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAdmissionOutcome {
    /// Exact signed authority and intent were durably prepared.
    Prepared,
    /// The exact Prepared intent already exists and must not be reissued.
    AlreadyPrepared,
}

/// Serializes protected network authority and non-executing journal admission.
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
    /// Preparation accepts only an opaque token from the future protected
    /// catalog publisher. Existing-resource actions are categorically rejected.
    /// No production token constructor exists in this increment, so this path
    /// remains mechanically unavailable even though its admission theorem is
    /// tested internally.
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
        let catalog = self
            .authority
            .validate_catalog(catalog)
            .map_err(|_| NetworkBrokerError::Authority)?;
        validate_catalog(&semantics, catalog)?;
        let assignment =
            decode_assignment(request_body).map_err(|_| NetworkBrokerError::Request)?;
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
        let record = prepared_record(PreparedNetworkRecordInput {
            request_id,
            sandbox_id,
            transport_digest: ObjectDigest::from_bytes(Sha256::digest(request_body).into()),
            semantic_digest: semantics.argument_commitment().digest(),
            verb: semantics.broker_verb(),
            catalog: catalog.clone(),
            fence,
            effect,
        });
        Ok(
            match self.state.begin_authorized(&self.authority, record)? {
                NetworkBeginOutcome::Prepared => NetworkAdmissionOutcome::Prepared,
                NetworkBeginOutcome::AlreadyPrepared => NetworkAdmissionOutcome::AlreadyPrepared,
            },
        )
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

/// Returns the closed method set safe for the incomplete network service.
///
/// Apply remains absent until tc-BPF/netlink helpers and P0-06 readiness exist.
/// Inventory also remains absent because durable operation history is not
/// authoritative current kernel state.
#[must_use]
pub fn advertised_network_methods() -> Vec<BrokerMethod> {
    Vec::new()
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
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
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
    fn apply_is_never_advertised() {
        assert!(advertised_network_methods().is_empty());
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
        let catalog = authority.authenticate_protected_catalog(catalog()).unwrap();
        let store = NetworkStateStore::open_for_test(directory.path(), &authority, 0).unwrap();
        let mut coordinator = NetworkAdmissionCoordinator::new(authority, store);
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
            NetworkAdmissionOutcome::Prepared
        );
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
            NetworkAdmissionOutcome::AlreadyPrepared
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
            let catalog = authority.authenticate_protected_catalog(catalog()).unwrap();
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
    fn catalog_token_rejects_tamper_and_resolution_substitution() {
        let fixture = Fixture::new();
        let request = request();
        let artifacts = fixture.artifacts(&request);
        for substitute_resolution in [false, true] {
            let directory = TempDir::new().unwrap();
            let authority = fixture.authority();
            let mut token = authority.authenticate_protected_catalog(catalog()).unwrap();
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
        let token = crate::AuthenticatedNetworkPreparationV1 { resolution, sealed };
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
            (RecordNamespace::Operation, vec![7; 16], false),
            (RecordNamespace::DesiredState, vec![2; 16], true),
            (RecordNamespace::Effect, vec![7; 16], true),
            (RecordNamespace::Operation, vec![7; 16], true),
        ] {
            let directory = TempDir::new().unwrap();
            let fixture = Fixture::new();
            let request = request();
            let artifacts = fixture.artifacts(&request);
            {
                let authority = fixture.authority();
                let token = authority.authenticate_protected_catalog(catalog()).unwrap();
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
        let token = authority.authenticate_protected_catalog(catalog()).unwrap();
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
        let changed = coordinator
            .authority
            .authenticate_protected_catalog(catalog_for(10, 10, 11, &[(7, 12), (8, 13)]))
            .unwrap();
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
        let first_token = authority
            .authenticate_protected_catalog(catalog_for(9, 10, 11, &[(7, 12)]))
            .unwrap();
        let changed_token = authority
            .authenticate_protected_catalog(catalog_for(10, 20, 21, &[(8, 22)]))
            .unwrap();
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
        let first_token = authority
            .authenticate_protected_catalog(catalog_for(9, 10, 11, &[(7, 12)]))
            .unwrap();
        let changed_token = authority
            .authenticate_protected_catalog(catalog_for(10, 20, 21, &[(7, 22)]))
            .unwrap();
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
        let first_token = authority.authenticate_protected_catalog(catalog()).unwrap();
        let second_catalog = catalog_for(10, 20, 21, &[(9, 22), (10, 23)]);
        let second_token = authority
            .authenticate_protected_catalog(second_catalog)
            .unwrap();
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
            let token = authority.authenticate_protected_catalog(catalog()).unwrap();
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
        let lower_than_current_token = authority
            .authenticate_protected_catalog(catalog_for(8, 20, 21, &[(9, 22)]))
            .unwrap();
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
        let first_token = authority
            .authenticate_protected_catalog(catalog_for(9, 10, 11, &[(7, 12)]))
            .unwrap();
        let second_token = authority
            .authenticate_protected_catalog(catalog_for(10, 10, 13, &[(8, 14)]))
            .unwrap();
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
            let token = coordinator
                .authority
                .authenticate_protected_catalog(catalog)
                .unwrap();
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
        let token = authority.authenticate_protected_catalog(catalog()).unwrap();
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
        let next_token = coordinator
            .authority
            .authenticate_protected_catalog(catalog_for(10, 20, 21, &[(9, 22)]))
            .unwrap();
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
        let preparation_token = authority.authenticate_protected_catalog(catalog()).unwrap();
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
