//! Pure historical state, canonical-record attack, and prepared-scope regressions.
//!
//! These fixtures materialize inert records in memory. They deliberately make
//! no native storage or protected-clock claim; those integration tests remain
//! with the protected journal adapter in Domain.

#![allow(clippy::unwrap_used)]

mod advance;

use std::cell::Cell;
use std::rc::Rc;

use aos_sandbox_core::format::{encode_ownership_lease, encode_signature, encode_trust_policy};
use aos_sandbox_core::model::{
    KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, DecodeLimits, DesiredGeneration, IncarnationId, LeaseAssignment, MediaType,
    NodeId, OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType, RawClockProvenance,
    TrustScopeId, descriptor_for_bytes, sign_statement,
};
use aos_sandbox_ownership_protocol::{
    ExpectedOwnershipLease, OwnershipAuthority, OwnershipAuthorityError,
    OwnershipTransactionReceiptV1, SignedOwnershipLease,
};
use ed25519_dalek::SigningKey;

use super::*;

struct TestAuthority {
    signing_key: SigningKey,
    authority: KeyReference,
    scope: TrustScopeId,
    policy_descriptor: aos_sandbox_core::ObjectDescriptor,
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
        let Some((assignment, node, generation, digest, desired_generation)) = self.current else {
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

struct Fixture {
    authority: TestAuthority,
    verifier: OwnershipAuthorityVerifier,
    clock: RawPairedClockSample,
}

fn fixture(key_byte: u8) -> Fixture {
    let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let authority = KeyReference::new(
        StableKeyId::new(format!("ownership-authority-{key_byte}"))
            .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
        3,
        ObjectDigest::from_bytes(Sha256::digest(public_key).into()),
        KeyUsage::OwnershipLease,
    );
    let scope = TrustScopeId::from_bytes([41; 16]);
    let policy = TrustPolicy::new(
        scope,
        SignaturePurpose::OwnershipLease,
        vec![authority.clone()],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test policy failed: {error}"));
    let policy_bytes = encode_trust_policy(&policy);
    let policy_descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test media type failed: {error}")),
        &policy_bytes,
    );
    let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
        policy_bytes,
        policy_descriptor.clone(),
        scope,
        authority.clone(),
        public_key,
        DecodeLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test anchor failed: {error}"));
    let clock = test_clock(150);
    Fixture {
        authority: TestAuthority {
            signing_key,
            authority: authority.clone(),
            scope,
            policy_descriptor,
            requests: BTreeMap::new(),
            current: None,
            now_seconds: 150,
            duration_seconds: 40,
            generation_increment: 2,
            override_assignment: None,
            override_node: None,
            calls: Rc::new(Cell::new(0)),
        },
        verifier: OwnershipAuthorityVerifier::new(anchor, authority),
        clock,
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

fn assignment(byte: u8) -> LeaseAssignment {
    LeaseAssignment::new(
        SandboxId::from_bytes([byte; 16]),
        IncarnationId::from_bytes([byte + 1; 16]),
        AssignmentEpoch::new(5),
        ObjectDigest::from_bytes([byte + 2; 32]),
    )
    .unwrap_or_else(|error| panic!("test assignment failed: {error}"))
}

fn acquire_claim(request: u8) -> OwnershipClaimV1 {
    OwnershipClaimV1::acquire(
        [request; 16],
        assignment(1),
        DesiredGeneration::new(6),
        NodeId::from_bytes([4; 16]),
        60,
    )
    .unwrap_or_else(|error| panic!("test claim failed: {error}"))
}

trait LeasePrior {
    fn assignment(&self) -> LeaseAssignment;
    fn node(&self) -> NodeId;
    fn fence(&self) -> ExpectedOwnershipLease;
}

impl LeasePrior for SignedOwnershipLease {
    fn assignment(&self) -> LeaseAssignment {
        self.assignment()
    }

    fn node(&self) -> NodeId {
        self.node()
    }

    fn fence(&self) -> ExpectedOwnershipLease {
        self.expected_renewal_fence()
    }
}

impl LeasePrior for RecoveredOwnershipLease {
    fn assignment(&self) -> LeaseAssignment {
        self.assignment()
    }

    fn node(&self) -> NodeId {
        self.node()
    }

    fn fence(&self) -> ExpectedOwnershipLease {
        self.expected_renewal_fence()
    }
}

fn renewal_claim(request: u8, prior: &impl LeasePrior) -> OwnershipClaimV1 {
    OwnershipClaimV1::renew(
        [request; 16],
        prior.assignment(),
        DesiredGeneration::new(6),
        prior.node(),
        prior.fence(),
        60,
    )
    .unwrap_or_else(|error| panic!("test renewal claim failed: {error}"))
}

fn completed_entry(
    claim: OwnershipClaimV1,
    lease: SignedOwnershipLease,
    accepted_wall_seconds: i64,
) -> DurableOwnershipEntry {
    DurableOwnershipEntry {
        claim,
        state: DurableEntryState::Completed {
            accepted_wall_seconds,
            lease: Box::new(lease.into_recovered()),
        },
    }
}

fn flip_embedded_artifact(bytes: &mut [u8], artifact: &[u8]) {
    let offset = bytes
        .windows(artifact.len())
        .position(|candidate| candidate == artifact)
        .unwrap_or_else(|| panic!("test artifact was not embedded"));
    bytes[offset + artifact.len() / 2] ^= 1;
}

#[derive(Default)]
struct Records {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
    currents: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Records {
    fn materialize(&mut self, transaction: &OwnershipHistoryTransaction) {
        for record in transaction.records() {
            let map = match record.kind() {
                OwnershipHistoryRecordKind::Entry => &mut self.entries,
                OwnershipHistoryRecordKind::Current => &mut self.currents,
            };

            map.insert(record.key().to_vec(), record.value().to_vec());
        }
    }

    fn recover(&self, key_byte: u8) -> Result<OwnershipHistory, OwnershipHistoryError> {
        OwnershipHistory::from_records(
            fixture(key_byte).verifier,
            self.entries
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice())),
            self.currents
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice())),
            std::iter::empty(),
            std::iter::empty(),
        )
    }

    fn insert_completed(&mut self, entry: &DurableOwnershipEntry, authority: &KeyReference) {
        self.entries.insert(
            durable_entry_key(entry.claim.request_id()),
            encode_durable_entry(entry, authority),
        );
    }
}

fn empty_history(key_byte: u8) -> OwnershipHistory {
    Records::default().recover(key_byte).unwrap()
}

fn publish_intent(history: &mut OwnershipHistory, records: &mut Records, claim: &OwnershipClaimV1) {
    let OwnershipHistoryBegin::Prepared(prepared, transaction) =
        history.prepare_begin(claim).unwrap()
    else {
        panic!("test intent was not prepared");
    };

    records.materialize(&transaction);
    prepared.publish();
}

fn publish_completion(
    history: &mut OwnershipHistory,
    records: &mut Records,
    issuer: &mut TestAuthority,
    claim: &OwnershipClaimV1,
) -> UnverifiedOwnershipLeaseResponse {
    let OwnershipHistoryCompletion::Pending(pending) =
        history.prepare_completion(*claim.request_id()).unwrap()
    else {
        panic!("test completion was not pending");
    };
    let response = match claim.action() {
        OwnershipClaimAction::Acquire => issuer.acquire(claim),
        OwnershipClaimAction::Renew => issuer.renew(claim),
        OwnershipClaimAction::Advance => issuer.advance(claim),
    }
    .unwrap();
    let (prepared, transaction) = pending.authenticate(response, &test_clock(150)).unwrap();

    records.materialize(&transaction);
    prepared.publish()
}

fn acquired_history(
    key_byte: u8,
) -> (
    OwnershipHistory,
    Records,
    TestAuthority,
    RecoveredOwnershipLease,
) {
    let mut records = Records::default();
    let mut history = empty_history(key_byte);
    let mut issuer = fixture(key_byte).authority;
    let claim = acquire_claim(5);
    publish_intent(&mut history, &mut records, &claim);
    publish_completion(&mut history, &mut records, &mut issuer, &claim);
    let prior = history
        .current(claim.assignment().sandbox())
        .unwrap()
        .clone();

    (history, records, issuer, prior)
}

#[test]
fn cross_sandbox_current_pointer_substitution_fails_recovery_closed() {
    for attack in 0..3_u8 {
        let key_byte = 46 + attack;
        let mut history = empty_history(key_byte);
        let mut records = Records::default();
        let mut issuer_a = fixture(key_byte).authority;
        let mut issuer_b = fixture(key_byte).authority;
        let claim_a = OwnershipClaimV1::acquire(
            [10; 16],
            assignment(10),
            DesiredGeneration::new(6),
            NodeId::from_bytes([50; 16]),
            60,
        )
        .unwrap();
        let claim_b = OwnershipClaimV1::acquire(
            [20; 16],
            assignment(20),
            DesiredGeneration::new(6),
            NodeId::from_bytes([51; 16]),
            60,
        )
        .unwrap();

        publish_intent(&mut history, &mut records, &claim_a);
        publish_completion(&mut history, &mut records, &mut issuer_a, &claim_a);
        let lease_a = history
            .current(claim_a.assignment().sandbox())
            .unwrap()
            .clone();
        publish_intent(&mut history, &mut records, &claim_b);
        publish_completion(&mut history, &mut records, &mut issuer_b, &claim_b);
        let lease_b = history
            .current(claim_b.assignment().sandbox())
            .unwrap()
            .clone();
        drop(history);

        let key_a = durable_current_key(claim_a.assignment().sandbox());
        let key_b = durable_current_key(claim_b.assignment().sandbox());
        match attack {
            0 => {
                records.currents.remove(&key_a);
            }
            1 => {
                records.currents.insert(
                    key_a,
                    encode_current_pointer(*claim_b.request_id(), &lease_b),
                );
            }
            _ => {
                records.currents.insert(
                    key_a,
                    encode_current_pointer(*claim_b.request_id(), &lease_b),
                );
                records.currents.insert(
                    key_b,
                    encode_current_pointer(*claim_a.request_id(), &lease_a),
                );
            }
        }

        assert!(matches!(
            records.recover(key_byte),
            Err(OwnershipHistoryError::CorruptState)
        ));
    }
}

#[test]
fn durable_recovery_rejects_duplicate_roots_and_forks() {
    let (_, mut records, _, _) = acquired_history(33);
    let mut second = fixture(33);
    let second_claim = acquire_claim(6);
    let second_lease = second
        .verifier
        .acquire(&mut second.authority, &second_claim, &second.clock)
        .unwrap();
    let entry = completed_entry(second_claim, second_lease, 150);

    records.insert_completed(&entry, second.verifier.authority());
    assert!(matches!(
        records.recover(33),
        Err(OwnershipHistoryError::CorruptState)
    ));

    let (_, mut records, _, root) = acquired_history(34);
    for request in [7, 8] {
        let mut branch = fixture(34);
        branch.authority.current = Some((
            root.assignment(),
            root.node(),
            root.generation(),
            root.digest(),
            root.desired_generation(),
        ));
        let claim = renewal_claim(request, &root);
        let lease = branch
            .verifier
            .renew(&mut branch.authority, &claim, &branch.clock)
            .unwrap();
        let entry = completed_entry(claim, lease, 150);
        records.insert_completed(&entry, branch.verifier.authority());
    }

    assert!(matches!(
        records.recover(34),
        Err(OwnershipHistoryError::CorruptState)
    ));
}

#[test]
fn durable_recovery_rejects_broken_predecessor_rollback_and_tamper() {
    for attack in 0..4 {
        let key_byte = 35 + attack;
        let (_, mut records, _, root) = acquired_history(key_byte);
        let mut branch = fixture(key_byte);
        let claim = renewal_claim(7, &root);
        let raw = branch
            .authority
            .issue(&claim, root.generation() + 2)
            .unwrap();
        let signed = branch
            .verifier
            .verify_response(&claim, raw.clone(), &branch.clock)
            .unwrap();
        let entry = completed_entry(claim.clone(), signed, 150);
        let mut encoded = encode_durable_entry(&entry, &branch.authority.authority);

        match attack {
            0 => flip_embedded_artifact(&mut encoded, claim.canonical_bytes()),
            1 => flip_embedded_artifact(&mut encoded, raw.lease()),
            2 => flip_embedded_artifact(&mut encoded, raw.receipt()),
            _ => flip_embedded_artifact(&mut encoded, raw.receipt_signature()),
        }
        records
            .entries
            .insert(durable_entry_key(claim.request_id()), encoded);

        assert!(matches!(
            records.recover(key_byte),
            Err(OwnershipHistoryError::CorruptState)
        ));
    }
}

#[test]
fn durable_recovery_rejects_oversized_record_before_decode() {
    let mut records = Records::default();
    records.entries.insert(
        durable_entry_key(&[5; 16]),
        vec![0; MAXIMUM_DURABLE_ENTRY_BYTES + 1],
    );

    assert!(matches!(
        records.recover(39),
        Err(OwnershipHistoryError::CorruptState)
    ));
}

#[test]
fn dropping_prepared_scopes_preserves_intent_and_head_frontiers() {
    let mut history = empty_history(50);
    let claim = acquire_claim(5);
    let reference = OwnershipTransactionReferenceV1::from_claim(&claim);
    let OwnershipHistoryBegin::Prepared(intent, _transaction) =
        history.prepare_begin(&claim).unwrap()
    else {
        panic!("test intent was not prepared");
    };
    drop(intent);
    assert_eq!(
        history.query(reference).unwrap(),
        OwnershipHistoryQuery::Absent
    );

    let mut records = Records::default();
    publish_intent(&mut history, &mut records, &claim);
    let OwnershipHistoryCompletion::Pending(pending) =
        history.prepare_completion(*claim.request_id()).unwrap()
    else {
        panic!("test completion was not pending");
    };
    drop(pending);
    assert!(history.is_pending(claim.request_id()));
    assert!(history.current(claim.assignment().sandbox()).is_none());

    let OwnershipHistoryCompletion::Pending(pending) =
        history.prepare_completion(*claim.request_id()).unwrap()
    else {
        panic!("test completion was not pending");
    };
    let mut issuer = fixture(50).authority;
    let response = issuer.acquire(&claim).unwrap();
    let (prepared, transaction) = pending.authenticate(response, &test_clock(150)).unwrap();
    assert_eq!(transaction.records().len(), 2);
    drop(prepared);

    assert!(history.is_pending(claim.request_id()));
    assert!(history.current(claim.assignment().sandbox()).is_none());
    assert!(records.recover(50).unwrap().is_pending(claim.request_id()));
}
