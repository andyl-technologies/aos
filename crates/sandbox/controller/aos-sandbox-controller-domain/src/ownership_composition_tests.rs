//! Exercises actual Controller/Ownership composition across the Cargo boundary.

#![allow(clippy::unwrap_used)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;

use aos_sandbox_model::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
use aos_sandbox_model::model::{
    KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
};
use aos_sandbox_model::{
    AssignmentEpoch, DecodeLimits, DesiredGeneration, IncarnationId, LeaseAssignment,
    MediaType, NodeId, OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType,
    ProtocolVersion, RawClockProvenance, RawPairedClockSample, TrustScopeId, descriptor_for_bytes, sign_statement,
};
use aos_sandbox_ownership_protocol::protocol::session_client::OwnershipAuthoritySessionClient;
use aos_sandbox_ownership_protocol::protocol::{
    MAXIMUM_OWNERSHIP_RESPONSE_BYTES, NegotiatedOwnershipSessionV1, OwnershipClientHelloV1,
    OwnershipMethodV1, OwnershipProtocolValidationError, OwnershipRequestBodyV1,
    OwnershipResponseOutcomeV1, OwnershipTransactionReferenceV1, OwnershipTransactionStatusV1,
};
use ed25519_dalek::SigningKey;

use crate::*;
use aos_sandbox_ownership::{DurableOwnershipAuthority, DurableOwnershipQueryOutcome};
use aos_sandbox_ownership_protocol::*;
use crate::journal::IdempotencyKey;
use crate::publication::tests::{activation_claim, descriptor_free_activation_fixture};
use crate::{
    ActivatedOperationCompiler, EffectFailure, EffectObservation, NodeController,
    NodeControllerLimits, OperationCompilationError, OperationPlan, OwnershipResumeOutcomeV1,
    Reconciler, SingleNodeEffectExecutor,
};
use aos_sandbox_protocol::domain_ledger::effect_history::{EffectPlan, EffectReceipt};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "aos-sandbox-ownership-{label}-{}-{}",
            std::process::id(),
            aos_sandbox_model::OperationId::new()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("authority.journal")
    }

    fn controller_journal(&self) -> PathBuf {
        self.0.join("controller.journal")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestAuthority {
    signing_key: SigningKey,
    authority: KeyReference,
    scope: TrustScopeId,
    policy_descriptor: aos_sandbox_model::ObjectDescriptor,
    requests: BTreeMap<[u8; 16], (ObjectDigest, UnverifiedOwnershipLeaseResponse)>,
    current: Option<(
        LeaseAssignment,
        NodeId,
        u64,
        ObjectDigest,
        DesiredGeneration,
    )>,
    now_seconds: i64,
    duration_seconds: i64,
    generation_increment: u64,
    override_assignment: Option<LeaseAssignment>,
    override_node: Option<NodeId>,
    calls: Rc<Cell<usize>>,
}

impl TestAuthority {
    fn issue(
        &mut self,
        claim: &OwnershipClaimV1,
        generation: u64,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        if let Some((digest, response)) = self.requests.get(claim.request_id()) {
            return if *digest == claim.digest() {
                Ok(response.clone())
            } else {
                Err(OwnershipAuthorityError::IdempotencyConflict)
            };
        }
        let assignment = self.override_assignment.unwrap_or(claim.assignment());
        let node = self.override_node.unwrap_or(claim.node());
        let nonce_byte = claim.request_id()[0].wrapping_add(generation as u8).max(1);
        let lease = OwnershipLease::new(
            assignment,
            node,
            generation,
            self.now_seconds - 10,
            self.now_seconds - 10 + self.duration_seconds,
            5,
            [nonce_byte; 16],
        )
        .map_err(|_| OwnershipAuthorityError::Internal)?;
        let lease_bytes = encode_ownership_lease(&lease);
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                .map_err(|_| OwnershipAuthorityError::Internal)?,
            &lease_bytes,
        );
        let statement = SignatureStatement::new(
            descriptor.clone(),
            self.scope,
            self.authority.clone(),
            SignaturePurpose::OwnershipLease,
            lease.authority_issued_seconds(),
            Some(lease.authority_expires_seconds()),
            self.policy_descriptor.clone(),
        )
        .map_err(|_| OwnershipAuthorityError::Internal)?;
        let signature = sign_statement(statement, &self.signing_key)
            .map_err(|_| OwnershipAuthorityError::Internal)?;
        let receipt =
            OwnershipTransactionReceiptV1::new(self.authority.clone(), claim, &lease_bytes)
                .map_err(|_| OwnershipAuthorityError::Internal)?;
        let receipt_descriptor = descriptor_for_bytes(
            MediaType::new(
                PortableMediaType::OwnershipTransactionReceipt
                    .as_str()
                    .to_owned(),
            )
            .map_err(|_| OwnershipAuthorityError::Internal)?,
            receipt.canonical_bytes(),
        );
        let receipt_statement = SignatureStatement::new(
            receipt_descriptor,
            self.scope,
            self.authority.clone(),
            SignaturePurpose::OwnershipLease,
            lease.authority_issued_seconds(),
            Some(lease.authority_expires_seconds()),
            self.policy_descriptor.clone(),
        )
        .map_err(|_| OwnershipAuthorityError::Internal)?;
        let receipt_signature = sign_statement(receipt_statement, &self.signing_key)
            .map_err(|_| OwnershipAuthorityError::Internal)?;
        let response = UnverifiedOwnershipLeaseResponse::from_transport(
            lease_bytes,
            encode_signature(&signature),
            receipt.canonical_bytes().to_vec(),
            encode_signature(&receipt_signature),
        )
        .map_err(|_| OwnershipAuthorityError::Internal)?;
        self.requests
            .insert(*claim.request_id(), (claim.digest(), response.clone()));
        self.current = Some((
            assignment,
            node,
            generation,
            descriptor.digest(),
            claim.desired_generation(),
        ));
        Ok(response)
    }
}

impl OwnershipAuthority for TestAuthority {
    fn acquire(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        self.calls.set(self.calls.get() + 1);
        if claim.action() != OwnershipClaimAction::Acquire {
            return Err(OwnershipAuthorityError::Internal);
        }
        if let Some((digest, response)) = self.requests.get(claim.request_id()) {
            return if *digest == claim.digest() {
                Ok(response.clone())
            } else {
                Err(OwnershipAuthorityError::IdempotencyConflict)
            };
        }
        if self.current.is_some() {
            return Err(OwnershipAuthorityError::AlreadyOwned);
        }
        self.issue(claim, 7)
    }

    fn renew(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        self.calls.set(self.calls.get() + 1);
        if claim.action() != OwnershipClaimAction::Renew {
            return Err(OwnershipAuthorityError::Internal);
        }
        if let Some((digest, response)) = self.requests.get(claim.request_id()) {
            return if *digest == claim.digest() {
                Ok(response.clone())
            } else {
                Err(OwnershipAuthorityError::IdempotencyConflict)
            };
        }
        let Some((assignment, node, generation, digest, desired_generation)) = self.current
        else {
            return Err(OwnershipAuthorityError::StaleExpectedPrior);
        };
        if assignment != claim.assignment()
            || node != claim.node()
            || desired_generation != claim.desired_generation()
            || claim.expected_prior()
                != Some(
                    ExpectedOwnershipLease::new(generation, digest)
                        .map_err(|_| OwnershipAuthorityError::Internal)?,
                )
        {
            return Err(OwnershipAuthorityError::StaleExpectedPrior);
        }
        let next = generation
            .checked_add(self.generation_increment)
            .ok_or(OwnershipAuthorityError::Internal)?;
        self.issue(claim, next)
    }

    fn advance(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        self.calls.set(self.calls.get() + 1);
        if claim.action() != OwnershipClaimAction::Advance {
            return Err(OwnershipAuthorityError::Internal);
        }
        if let Some((digest, response)) = self.requests.get(claim.request_id()) {
            return if *digest == claim.digest() {
                Ok(response.clone())
            } else {
                Err(OwnershipAuthorityError::IdempotencyConflict)
            };
        }
        let Some((assignment, node, generation, digest, desired)) = self.current else {
            return Err(OwnershipAuthorityError::StaleExpectedPrior);
        };
        let proposed = claim.assignment();
        if assignment.sandbox() != proposed.sandbox()
            || assignment.incarnation() != proposed.incarnation()
            || assignment.epoch() != proposed.epoch()
            || assignment.digest() == proposed.digest()
            || node != claim.node()
            || desired >= claim.desired_generation()
            || claim.expected_prior()
                != Some(
                    ExpectedOwnershipLease::new(generation, digest)
                        .map_err(|_| OwnershipAuthorityError::Internal)?,
                )
        {
            return Err(OwnershipAuthorityError::StaleExpectedPrior);
        }
        self.issue(
            claim,
            generation
                .checked_add(self.generation_increment)
                .ok_or(OwnershipAuthorityError::Internal)?,
        )
    }
}

fn test_clock(wall_seconds: i64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"test-owner-clock")
            .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
        [42; 16],
        wall_seconds,
        10_000_000_000,
    )
    .unwrap_or_else(|error| panic!("test clock failed: {error}"))
}

#[test]
fn node_controller_composes_with_in_process_service_across_both_journals() {
    #[derive(Default)]
    struct CompositionExecutor;

    impl SingleNodeEffectExecutor for CompositionExecutor {
        fn observe(
            &mut self,
            _operation_id: aos_sandbox_model::OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            Ok(EffectObservation::Absent)
        }

        fn apply(
            &mut self,
            _operation_id: aos_sandbox_model::OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            Ok(EffectReceipt::new(vec![1]).unwrap())
        }
    }

    struct CompositionCompiler;

    impl ActivatedOperationCompiler for CompositionCompiler {
        fn compile(
            &mut self,
            _journal: &mut crate::Journal,
            _canonical_request: &[u8],
            _request_digest: [u8; 32],
        ) -> Result<OperationPlan, OperationCompilationError> {
            Err(OperationCompilationError::Rejected)
        }
    }

    let directory = TestDirectory::new("controller-service-composition");
    let (draft, _) = descriptor_free_activation_fixture(1);
    let claim = activation_claim(&draft, 1);
    let transaction = OwnershipTransactionReferenceV1::from_claim(&claim);
    let signing_key = SigningKey::from_bytes(&[41; 32]);
    let authority_reference = draft.ownership_authority().clone();
    assert_eq!(
        authority_reference.public_key_sha256(),
        ObjectDigest::from_bytes(Sha256::digest(signing_key.verifying_key().as_bytes()).into())
    );
    let make_verifier = || {
        let scope = TrustScopeId::from_bytes([61; 16]);
        let policy = TrustPolicy::new(
            scope,
            SignaturePurpose::OwnershipLease,
            vec![authority_reference.clone()],
            Vec::new(),
        )
        .unwrap();
        let policy_bytes = encode_trust_policy(&policy);
        let policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &policy_bytes,
        );
        let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            policy_bytes,
            policy_descriptor.clone(),
            scope,
            authority_reference.clone(),
            signing_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap();
        (
            OwnershipAuthorityVerifier::new(anchor, authority_reference.clone()),
            scope,
            policy_descriptor,
        )
    };
    let (authority_verifier, authority_scope, authority_policy) = make_verifier();
    let (controller_verifier, _, _) = make_verifier();
    let (reopen_verifier, _, _) = make_verifier();
    let issuer_calls = Rc::new(Cell::new(0));
    let mut issuer = TestAuthority {
        signing_key,
        authority: authority_reference.clone(),
        scope: authority_scope,
        policy_descriptor: authority_policy,
        requests: BTreeMap::new(),
        current: None,
        now_seconds: 150,
        duration_seconds: 40,
        generation_increment: 1,
        override_assignment: None,
        override_node: None,
        calls: issuer_calls.clone(),
    };

    let operation_id = aos_sandbox_model::OperationId::from_bytes([0x81; 16]);
    let effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
        &draft,
        draft.templates()[0].digest(),
    )
    .map_err(crate::publication::AuthorityPublicationError::from)
    .unwrap();
    let plan = OperationPlan::ownership_gated(
        operation_id,
        IdempotencyKey::new(b"controller-service-composition".to_vec()).unwrap(),
        [0x82; 32],
        b"sandbox".to_vec(),
        b"ownership-pending".to_vec(),
        vec![effect],
        claim,
        draft,
    )
    .unwrap();
    let (controller_journal, _) =
        Journal::open(directory.controller_journal(), JournalLimits::default()).unwrap();
    let mut reconciler = Reconciler::new(controller_journal, CompositionExecutor);
    reconciler.accept(&plan).unwrap();
    let mut controller = NodeController::new(
        crate::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x83; 32])).unwrap(),
        NodeControllerLimits::default(),
        CompositionCompiler,
        reconciler,
    );
    let (mut authority_store, _) =
        DurableOwnershipAuthority::open_fixture(directory.journal(), authority_verifier).unwrap();
    let hello = OwnershipClientHelloV1::new(
        [0x84; 32],
        ProtocolVersion::new(1, 0),
        authority_reference.clone(),
        vec![
            OwnershipMethodV1::Begin,
            OwnershipMethodV1::CompleteOrResume,
            OwnershipMethodV1::Query,
        ],
        aos_sandbox_ownership_protocol::protocol::MINIMUM_OWNERSHIP_RESPONSE_BYTES,
    )
    .unwrap();
    let session = NegotiatedOwnershipSessionV1::negotiate(
        &hello,
        [0x85; 32],
        authority_reference,
        vec![
            OwnershipMethodV1::Begin,
            OwnershipMethodV1::CompleteOrResume,
            OwnershipMethodV1::Query,
        ],
    )
    .unwrap();
    let protected_clock_calls = Rc::new(Cell::new(0));
    let counted_clock_calls = protected_clock_calls.clone();
    let mut protected_clock = move || {
        counted_clock_calls.set(counted_clock_calls.get() + 1);
        Ok(test_clock(150))
    };
    {
        let mut client = aos_sandbox_ownership::InProcessOwnershipSessionClient::new(
            session.clone(),
            &mut authority_store,
            &mut issuer,
            &mut protected_clock,
        )
        .unwrap();
        assert_eq!(
            controller
                .resume_ownership(operation_id, &mut client, &controller_verifier, &mut || Ok(
                    test_clock(150)
                ),)
                .unwrap(),
            OwnershipResumeOutcomeV1::Activated
        );
    }
    assert_eq!(issuer_calls.get(), 1);
    assert_eq!(protected_clock_calls.get(), 1);

    // Advance the signed namespace target through the actual controller
    // resume and publication path. This is still an inert Stop template,
    // not live namespace replay or permission to use historical pins.
    let advanced_draft =
        crate::publication::tests::descriptor_free_stop_draft_with_generations(8, 9);
    let proposed = activation_claim(&advanced_draft, 2);
    let previous = authority_store
        .current(proposed.assignment().sandbox())
        .unwrap();
    let advance_claim = OwnershipClaimV1::advance(
        [2; 16],
        proposed.assignment(),
        proposed.desired_generation(),
        proposed.node(),
        previous.expected_renewal_fence(),
        100,
    )
    .unwrap();
    let advance_transaction = OwnershipTransactionReferenceV1::from_claim(&advance_claim);
    let advance_operation = aos_sandbox_model::OperationId::from_bytes([0x91; 16]);
    let advance_effect = aos_sandbox_protocol::publication::bind_authority_publication_effect(
        &advanced_draft,
        advanced_draft.templates()[0].digest(),
    )
    .map_err(crate::publication::AuthorityPublicationError::from)
    .unwrap();
    let advance_plan = OperationPlan::ownership_gated(
        advance_operation,
        IdempotencyKey::new(b"controller-service-advance".to_vec()).unwrap(),
        [0x92; 32],
        b"sandbox".to_vec(),
        b"advanced-ownership-pending".to_vec(),
        vec![advance_effect],
        advance_claim,
        advanced_draft,
    )
    .unwrap();
    drop(controller);
    let (controller_journal, _) =
        Journal::open(directory.controller_journal(), JournalLimits::default()).unwrap();
    let mut reconciler = Reconciler::new(controller_journal, CompositionExecutor);
    reconciler.accept(&advance_plan).unwrap();
    let mut controller = NodeController::new(
        crate::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x83; 32])).unwrap(),
        NodeControllerLimits::default(),
        CompositionCompiler,
        reconciler,
    );
    let advanced_session = session.clone();
    {
        let mut client = aos_sandbox_ownership::InProcessOwnershipSessionClient::new(
            advanced_session.clone(),
            &mut authority_store,
            &mut issuer,
            &mut protected_clock,
        )
        .unwrap();
        assert_eq!(
            controller
                .resume_ownership(
                    advance_operation,
                    &mut client,
                    &controller_verifier,
                    &mut || Ok(test_clock(150)),
                )
                .unwrap(),
            OwnershipResumeOutcomeV1::Activated
        );
    }
    assert_eq!(issuer_calls.get(), 2);
    assert_eq!(protected_clock_calls.get(), 2);

    drop(authority_store);
    drop(controller);
    let (mut authority_store, _) =
        DurableOwnershipAuthority::open_fixture(directory.journal(), reopen_verifier).unwrap();
    assert!(matches!(
        authority_store.query(transaction).unwrap(),
        DurableOwnershipQueryOutcome::Completed(_)
    ));
    assert!(matches!(
        authority_store.query(advance_transaction).unwrap(),
        DurableOwnershipQueryOutcome::Completed(_)
    ));
    let (mut controller_journal, _) =
        Journal::open(directory.controller_journal(), JournalLimits::default()).unwrap();
    let current = crate::AuthorityPublicationStore::new(&mut controller_journal)
        .current(proposed.assignment().sandbox())
        .unwrap()
        .unwrap();
    assert_eq!(current.manifest().manifest().desired_generation().get(), 8);
    assert_eq!(
        current.manifest().manifest().namespace_generation().get(),
        9
    );
    assert_eq!(current.manifest().digest(), proposed.assignment().digest());
    assert_eq!(
        OwnershipTransactionReceiptV1::from_canonical_bytes(
            current.lease().canonical_receipt(),
        )
        .unwrap()
        .action(),
        OwnershipClaimAction::Advance
    );
    let mut controller = NodeController::new(
        crate::ControllerRequestScopeV1::new(ObjectDigest::from_bytes([0x83; 32])).unwrap(),
        NodeControllerLimits::default(),
        CompositionCompiler,
        Reconciler::new(controller_journal, CompositionExecutor),
    );
    let mut replay_client = aos_sandbox_ownership::InProcessOwnershipSessionClient::new(
        advanced_session,
        &mut authority_store,
        &mut issuer,
        &mut protected_clock,
    )
    .unwrap();
    assert_eq!(
        controller
            .resume_ownership(
                operation_id,
                &mut replay_client,
                &controller_verifier,
                &mut || panic!("activated replay sampled the controller clock"),
            )
            .unwrap(),
        OwnershipResumeOutcomeV1::Replay
    );
    assert_eq!(
        controller
            .resume_ownership(
                advance_operation,
                &mut replay_client,
                &controller_verifier,
                &mut || panic!("advanced replay sampled time"),
            )
            .unwrap(),
        OwnershipResumeOutcomeV1::Replay
    );
    assert_eq!(issuer_calls.get(), 2);
    assert_eq!(protected_clock_calls.get(), 2);
}
