//! Non-executing storage admission coordinator.
//!
//! The coordinator is the sole owner of the storage journal lock. It verifies
//! portable signed authority against an exact node-local catalog resolution,
//! then commits the authenticated assignment fence, non-authorizing admission
//! intent, and storage transaction intent in one journal transaction. It does
//! not cross the ambiguous-mutation boundary and exposes no ZFS invocation.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::journal::RecordNamespace;
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use sha2::{Digest as _, Sha256};

use crate::authorization::{StorageAuthorityV1, decode_assignment};
use crate::{
    BeginStorageTransaction, DurableStoragePhase, ResolvedCatalogCommitmentV1,
    StorageTransactionStore, decode_resolved,
};

/// Reports fail-closed storage admission failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageBrokerError {
    /// Hostile request bytes or local catalog association failed.
    #[error("storage request or catalog resolution was rejected")]
    Request,
    /// Protected signed plan, lease, or fence validation failed.
    #[error("storage authority was rejected")]
    Authority,
    /// Durable admission state was corrupt, conflicting, or unavailable.
    #[error("storage durable admission failed: {0}")]
    State(#[from] crate::StorageStateError),
}

/// Classifies a durable admission without implying that mutation is runnable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageAdmissionOutcome {
    /// Exact authority and intent were durably prepared for future observation.
    Prepared {
        /// Deterministic identity of the non-executing mutation intent.
        mutation_digest: ObjectDigest,
    },
    /// Recovery must only re-observe; it must never blindly reapply mutation.
    ObservationRequired {
        /// Durable crash phase requiring reconciliation.
        phase: DurableStoragePhase,
        /// Deterministic identity of the pending mutation.
        mutation_digest: ObjectDigest,
    },
    /// A future observer previously committed an exact result.
    Replay(crate::CommittedStorageResultV1),
}

/// Serializes protected storage authority and durable transaction admission.
pub struct StorageAdmissionCoordinator {
    authority: StorageAuthorityV1,
    transactions: StorageTransactionStore,
}

impl StorageAdmissionCoordinator {
    /// Constructs a coordinator from complete protected authority and state.
    #[must_use]
    pub const fn new(authority: StorageAuthorityV1, transactions: StorageTransactionStore) -> Self {
        Self {
            authority,
            transactions,
        }
    }

    /// Verifies and durably records an unadvertised Apply admission intent.
    ///
    /// This method deliberately does not make StorageApply service-ready. A
    /// future privileged observer/helper must reconcile the typed transaction
    /// under this same lock before any service may advertise Apply.
    ///
    /// # Errors
    ///
    /// Returns [`StorageBrokerError`] for hostile bytes, catalog substitution,
    /// signed-authority failure, fencing conflict, or durable-state failure.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_apply_intent(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        catalog: &ResolvedCatalogCommitmentV1,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        current_clock: &RawPairedClockSample,
    ) -> Result<StorageAdmissionOutcome, StorageBrokerError> {
        let semantics = decode_resolved(
            request_body,
            catalog,
            peer,
            policy,
            current_clock.boottime_nanoseconds(),
        )
        .map_err(|_| StorageBrokerError::Request)?;
        let assignment =
            decode_assignment(request_body).map_err(|_| StorageBrokerError::Request)?;
        let sandbox_id = *assignment.sandbox().as_bytes();
        let request_id = *semantics.header().request_id();
        let existing = self.transactions.phase(*semantics.operation_id()).is_some();
        let prior_fence = self
            .transactions
            .authority_record(RecordNamespace::DesiredState, &sandbox_id)
            .map(<[u8]>::to_vec);
        let prior_admission_intent = self
            .transactions
            .authority_record(RecordNamespace::Effect, &request_id)
            .map(<[u8]>::to_vec);
        if existing && (prior_fence.is_none() || prior_admission_intent.is_none()) {
            return Err(StorageBrokerError::State(
                crate::StorageStateError::MissingAuthorityLink,
            ));
        }
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
            .map_err(|_| StorageBrokerError::Authority)?;
        if existing {
            let persisted_fence = self
                .authority
                .open_fence(
                    &sandbox_id,
                    prior_fence
                        .as_deref()
                        .ok_or(crate::StorageStateError::MissingAuthorityLink)?,
                )
                .map_err(|_| StorageBrokerError::Authority)?;
            let persisted_intent = self
                .authority
                .open_admission_intent(
                    &request_id,
                    prior_admission_intent
                        .as_deref()
                        .ok_or(crate::StorageStateError::MissingAuthorityLink)?,
                )
                .map_err(|_| StorageBrokerError::Authority)?;
            let transport_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
            if persisted_fence.assignment() != assignment
                || persisted_intent.transport_request_digest() != transport_digest
                || persisted_intent.request_digest() != semantics.argument_commitment().digest()
                || persisted_intent.verb() != semantics.broker_verb()
                || persisted_intent.target() != semantics.grant_target()
                || persisted_intent.plan_digest() != admission.effect.plan_digest()
                || persisted_intent.lease_digest() != admission.effect.lease_digest()
            {
                return Err(StorageBrokerError::State(
                    crate::StorageStateError::AuthorityLinkMismatch,
                ));
            }
        }
        let (sealed_fence, sealed_admission_intent) = self
            .authority
            .seal(&sandbox_id, &request_id, &admission)
            .map_err(|_| StorageBrokerError::Authority)?;
        let request_digest = ObjectDigest::from_bytes(Sha256::digest(request_body).into());
        let outcome = self.transactions.begin_authorized(
            *semantics.operation_id(),
            request_digest,
            catalog,
            sandbox_id,
            request_id,
            sealed_fence,
            sealed_admission_intent,
        )?;
        Ok(match outcome {
            BeginStorageTransaction::Prepared { mutation_digest } => {
                StorageAdmissionOutcome::Prepared { mutation_digest }
            }
            BeginStorageTransaction::ObserveOnly {
                phase,
                mutation_digest,
            } => StorageAdmissionOutcome::ObservationRequired {
                phase,
                mutation_digest,
            },
            BeginStorageTransaction::Replay(result) => StorageAdmissionOutcome::Replay(result),
        })
    }
}

/// Returns the closed method set safe for the incomplete storage service.
///
/// Apply is intentionally absent until catalog publication, key provisioning,
/// privileged observation, and helper readiness form one complete startup
/// proof. Inventory is included only when a caller has a complete bounded
/// catalog inventory implementation.
#[must_use]
pub fn advertised_storage_methods(inventory_ready: bool) -> Vec<BrokerMethod> {
    if inventory_ready {
        vec![BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyStorageRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerRequestEnvelope,
        StorageAction,
    };
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget, BrokerVerb,
        DecodeLimits, LeaseAssignment, MediaType, NodeId, OwnershipLease,
        OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId, RawClockProvenance,
        RevocationScopeId, TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_protocol::decode_request_envelope;
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, ProjectAncestorPolicyV1, ReservationPolicy,
        ResolvedDataset, StorageDomainsV1, StorageStateKey, WorkspaceSpacePolicyV1,
    };

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
            let plan_signer = key_ref("storage-plan", 3, KeyUsage::BrokerAuthorization, &plan_key);
            let lease_signer = key_ref("storage-lease", 7, KeyUsage::OwnershipLease, &lease_key);
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

        fn authority(&self) -> StorageAuthorityV1 {
            let plan = aos_sandbox_core::BrokerPlanTrustAnchor::from_trusted_configuration(
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
            StorageAuthorityV1::new(plan, lease, NODE, [46; 16], [47; 32]).unwrap()
        }

        fn artifacts(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            expires: i64,
            audience: BrokerAudience,
            protocol: ProtocolId,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_authorizing(request, catalog, &[request], expires, audience, protocol)
        }

        fn artifacts_authorizing(
            &self,
            request: &[u8],
            catalog: &ResolvedCatalogCommitmentV1,
            authorized: &[&[u8]],
            expires: i64,
            audience: BrokerAudience,
            protocol: ProtocolId,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let semantics = decode_resolved(request, catalog, peer(), peer_policy(), 100).unwrap();
            let assignment = decode_assignment(request).unwrap();
            let mut grants = if audience == BrokerAudience::Storage {
                authorized
                    .iter()
                    .map(|bytes| {
                        let candidate =
                            decode_resolved(bytes, catalog, peer(), peer_policy(), 100).unwrap();
                        BrokerGrant::new(
                            candidate.broker_verb(),
                            candidate.grant_target(),
                            candidate.argument_commitment(),
                            bytes.len() as u32,
                            0,
                        )
                        .unwrap()
                    })
                    .collect()
            } else {
                vec![
                    BrokerGrant::new(
                        BrokerVerb::MountInventorySummary,
                        BrokerGrantTarget::Assignment,
                        semantics.argument_commitment(),
                        request.len() as u32,
                        0,
                    )
                    .unwrap(),
                ]
            };
            grants.sort_by_key(|grant| (grant.verb(), grant.target(), grant.argument_commitment()));
            let plan = BrokerAuthorizationPlan::new(
                audience,
                protocol,
                ProtocolVersion::new(1, 1),
                assignment,
                NODE,
                self.lease_signer.clone(),
                grants,
                ObjectDigest::from_bytes([48; 32]),
                self.revocation,
                100,
                expires,
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
            validated(
                BrokerAuthorizationArtifactsV1 {
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
                },
                protocol,
            )
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
    fn request(operation: u8, handle: u8) -> Vec<u8> {
        let mut value = ApplyStorageRequest::default();
        let header = value.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 1;
        header.request_id = vec![operation; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;
        let fence = value.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
        value.action = StorageAction::STORAGE_ACTION_SET_QUOTA.into();
        value.operation_id = vec![operation; 16];
        value.storage_handle = vec![handle; 32];
        value.quota_bytes = 4096;
        value.encode_to_vec()
    }
    fn catalog(handle: u8, generation: u64) -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [9; 32], domains)
                .unwrap();
        let dataset =
            ResolvedDataset::from_catalog(root, "tank/aos/project/work", 11, [handle; 32], domains)
                .unwrap();
        ResolvedCatalogCommitmentV1::new(
            generation,
            domains,
            CatalogPlanV1::SetQuota {
                dataset,
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1)).unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(ancestor, 65_536, 8, 16).unwrap(),
            },
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
        protocol: ProtocolId,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: if protocol == ProtocolId::StorageBroker {
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY.into()
            } else {
                BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into()
            },
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), protocol, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }
    fn coordinator(directory: &TempDir, fixture: &Fixture) -> StorageAdmissionCoordinator {
        let store = StorageTransactionStore::open_for_test(
            directory.path(),
            StorageStateKey::new([51; 16], [52; 32]).unwrap(),
            0,
        )
        .unwrap();
        StorageAdmissionCoordinator::new(fixture.authority(), store)
    }

    #[test]
    fn real_authority_prepares_and_exact_replay_is_observation_only() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let original_request = request(7, 8);
        let original_catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &original_request,
            &original_catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = coordinator(&directory, &fixture);
        assert!(matches!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &artifacts,
                    &original_catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .unwrap(),
            StorageAdmissionOutcome::Prepared { .. }
        ));
        assert!(matches!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &artifacts,
                    &original_catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .unwrap(),
            StorageAdmissionOutcome::ObservationRequired {
                phase: DurableStoragePhase::Prepared,
                ..
            }
        ));
    }

    #[test]
    fn substitutions_and_invalid_authority_fail_closed() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let original_request = request(7, 8);
        let original_catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &original_request,
            &original_catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = coordinator(&directory, &fixture);
        broker
            .admit_apply_intent(
                &original_request,
                &artifacts,
                &original_catalog,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();
        assert!(
            broker
                .admit_apply_intent(
                    &request(9, 8),
                    &artifacts,
                    &original_catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );
        assert!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &artifacts,
                    &catalog(9, 10),
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );

        let expired = fixture.artifacts(
            &original_request,
            &original_catalog,
            140,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        assert!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &expired,
                    &original_catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );
        let wrong = fixture.artifacts(
            &original_request,
            &original_catalog,
            300,
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
        );
        assert!(
            broker
                .admit_apply_intent(
                    &original_request,
                    &wrong,
                    &original_catalog,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    peer_policy(),
                    &clock()
                )
                .is_err()
        );
    }

    #[test]
    fn missing_link_after_recovery_is_rejected() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let request = request(7, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts(
            &request,
            &catalog,
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = coordinator(&directory, &fixture);
        broker
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
        broker
            .transactions
            .remove_authority_record_for_test(RecordNamespace::Effect, &[7; 16]);
        drop(broker);
        let mut recovered = coordinator(&directory, &fixture);
        assert!(matches!(
            recovered.admit_apply_intent(
                &request,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock()
            ),
            Err(StorageBrokerError::State(
                crate::StorageStateError::MissingAuthorityLink
            ))
        ));
    }

    #[test]
    fn cross_linked_intent_cannot_be_sealed_for_another_request() {
        let directory = TempDir::new().unwrap();
        let fixture = Fixture::new();
        let original = request(7, 8);
        let substituted = request(9, 8);
        let catalog = catalog(8, 9);
        let artifacts = fixture.artifacts_authorizing(
            &original,
            &catalog,
            &[&original, &substituted],
            300,
            BrokerAudience::Storage,
            ProtocolId::StorageBroker,
        );
        let mut broker = coordinator(&directory, &fixture);
        broker
            .admit_apply_intent(
                &original,
                &artifacts,
                &catalog,
                ProtocolVersion::new(1, 1),
                peer(),
                peer_policy(),
                &clock(),
            )
            .unwrap();

        let semantics =
            decode_resolved(&substituted, &catalog, peer(), peer_policy(), 100).unwrap();
        let admission = broker
            .authority
            .admit(
                &artifacts,
                &semantics,
                &substituted,
                ProtocolVersion::new(1, 1),
                &clock(),
                broker
                    .transactions
                    .authority_record(RecordNamespace::DesiredState, &[2; 16]),
            )
            .unwrap();
        assert!(
            broker
                .authority
                .seal(&[2; 16], &[7; 16], &admission)
                .is_err()
        );
    }

    #[test]
    fn apply_is_never_advertised_without_complete_effect_readiness() {
        assert!(advertised_storage_methods(false).is_empty());
        assert_eq!(
            advertised_storage_methods(true),
            [BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY]
        );
        assert!(
            !advertised_storage_methods(true).contains(&BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
        );
    }
}
