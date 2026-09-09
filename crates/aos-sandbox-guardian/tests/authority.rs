//! Adversarial coverage for Guardian plan/lease intersection and durability.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox_core::format::{
    encode_broker_authorization_plan, encode_ownership_lease, encode_signature, encode_trust_policy,
};
use aos_sandbox_core::model::{
    KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    BrokerGrantTarget, BrokerPlanTrustAnchor, BrokerVerb, DecodeLimits, DesiredGeneration,
    IncarnationId, LeaseAssignment, MediaType, NodeId, ObjectDescriptor, ObjectDigest,
    OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId, ProtocolVersion,
    RawClockProvenance, RawPairedClockSample, RevocationScopeId, SandboxId, TrustScopeId,
    descriptor_for_bytes, sign_statement,
};
use aos_sandbox_guardian::{
    GuardianArtifacts, GuardianAuthority, GuardianPlanBinding, GuardianState, GuardianStateStore,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

const INCARNATION: [u8; 16] = [2; 16];
const NODE: [u8; 16] = [6; 16];
const PROVENANCE: [u8; 16] = [20; 16];

struct Fixture {
    authority: GuardianAuthority,
    plan: Vec<u8>,
    plan_signature: Vec<u8>,
    lease: Vec<u8>,
    lease_signature: Vec<u8>,
    boot: [u8; 16],
}

impl Fixture {
    fn artifacts(&self) -> GuardianArtifacts<'_> {
        GuardianArtifacts {
            broker_plan: &self.plan,
            broker_plan_signature: &self.plan_signature,
            ownership_lease: &self.lease,
            ownership_lease_signature: &self.lease_signature,
        }
    }

    fn clock(&self, wall_seconds: i64, boottime_nanoseconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(PROVENANCE)
                .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
            self.boot,
            wall_seconds,
            boottime_nanoseconds,
        )
        .unwrap_or_else(|error| panic!("test clock failed: {error}"))
    }
}

#[test]
fn exact_signed_plan_and_lease_arm_only_after_durable_round_trip() {
    let fixture = fixture([8; 16], 7, None, None, 4);
    let clock = fixture.clock(150, 1_000);
    let pending = fixture
        .authority
        .admit(fixture.artifacts(), INCARNATION, &clock, None)
        .unwrap_or_else(|error| panic!("valid guardian authority failed: {error}"));

    let directory = protected_tempdir();
    let mut store = GuardianStateStore::open(directory.path())
        .unwrap_or_else(|error| panic!("test store failed: {error}"));
    let durable = store
        .commit(pending)
        .unwrap_or_else(|error| panic!("durable commit failed: {error}"));
    let later = fixture.clock(151, 1_000_001_000);
    let ready = fixture
        .authority
        .confirm_current(fixture.artifacts(), INCARNATION, &later, durable)
        .unwrap_or_else(|error| panic!("durable confirmation failed: {error}"));

    assert_eq!(ready.state().desired_generation().get(), 4);
    assert_eq!(ready.state().lease_generation(), 7);
    assert_eq!(ready.state().host_boot_id(), &[8; 16]);
    assert_eq!(ready.deadline_boottime_nanoseconds(), 35_000_001_000);
    assert_eq!(
        store
            .load()
            .unwrap_or_else(|error| panic!("durable load failed: {error}")),
        Some(ready.state().clone())
    );
}

#[test]
fn independently_valid_lease_substitution_misses_the_signed_plan_binding() {
    let fixture = fixture([8; 16], 7, Some(8), None, 4);
    let clock = fixture.clock(150, 1_000);

    assert!(
        fixture
            .authority
            .admit(fixture.artifacts(), INCARNATION, &clock, None)
            .is_err()
    );
}

#[test]
fn floored_wall_sample_never_admits_before_signed_not_before() {
    let fixture = fixture([8; 16], 7, None, None, 4);
    let before_issuance = fixture.clock(99, 1_000);

    assert!(
        fixture
            .authority
            .admit(fixture.artifacts(), INCARNATION, &before_issuance, None)
            .is_err()
    );
}

#[test]
fn old_boot_plan_fails_but_fresh_current_authority_replaces_old_timer_state() {
    let old = fixture([8; 16], 7, None, None, 4);
    let old_clock = old.clock(150, 1_000);
    let old_pending = old
        .authority
        .admit(old.artifacts(), INCARNATION, &old_clock, None)
        .unwrap_or_else(|error| panic!("old admission failed: {error}"));
    let directory = protected_tempdir();
    let mut store = GuardianStateStore::open(directory.path())
        .unwrap_or_else(|error| panic!("old store failed: {error}"));
    store
        .commit(old_pending)
        .unwrap_or_else(|error| panic!("old durable commit failed: {error}"));
    let prior = store
        .load()
        .unwrap_or_else(|error| panic!("old durable load failed: {error}"))
        .unwrap_or_else(|| panic!("old durable state is absent"));

    let lower_desired = fixture([9; 16], 8, None, None, 3);
    assert!(
        lower_desired
            .authority
            .admit(
                lower_desired.artifacts(),
                INCARNATION,
                &lower_desired.clock(150, 1_000),
                Some(&prior),
            )
            .is_err()
    );
    let lower_lease = fixture([9; 16], 6, None, None, 5);
    assert!(
        lower_lease
            .authority
            .admit(
                lower_lease.artifacts(),
                INCARNATION,
                &lower_lease.clock(150, 1_000),
                Some(&prior),
            )
            .is_err()
    );
    let equivocal_lease = fixture_with_nonce([9; 16], 7, None, None, 4, 99);
    assert!(
        equivocal_lease
            .authority
            .admit(
                equivocal_lease.artifacts(),
                INCARNATION,
                &equivocal_lease.clock(150, 1_000),
                Some(&prior),
            )
            .is_err()
    );

    // The lease itself is byte-identical across these fixtures. Only the
    // controller plan is freshly signed for the current boot binding.
    let current = fixture([9; 16], 7, None, None, 4);
    let current_clock = current.clock(150, 1_000);
    let replacement = current
        .authority
        .admit(
            current.artifacts(),
            INCARNATION,
            &current_clock,
            Some(&prior),
        )
        .unwrap_or_else(|error| panic!("fresh current-boot arm failed: {error}"));
    let durable = store
        .commit(replacement)
        .unwrap_or_else(|error| panic!("current-boot replacement failed: {error}"));
    assert_eq!(durable.state().host_boot_id(), &[9; 16]);
    assert_eq!(durable.state().lease_generation(), 7);

    let forged_clock = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(PROVENANCE)
            .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
        [9; 16],
        150,
        1_000,
    )
    .unwrap_or_else(|error| panic!("test clock failed: {error}"));
    assert!(
        old.authority
            .admit(old.artifacts(), INCARNATION, &forged_clock, None)
            .is_err()
    );
}

#[test]
fn persistence_that_consumes_the_deadline_cannot_confirm_readiness() {
    let fixture = fixture([8; 16], 7, None, None, 4);
    let pending = fixture
        .authority
        .admit(
            fixture.artifacts(),
            INCARNATION,
            &fixture.clock(150, 1_000),
            None,
        )
        .unwrap_or_else(|error| panic!("valid admission failed: {error}"));
    let directory = protected_tempdir();
    let mut store = GuardianStateStore::open(directory.path())
        .unwrap_or_else(|error| panic!("test store failed: {error}"));
    let durable = store
        .commit(pending)
        .unwrap_or_else(|error| panic!("durable commit failed: {error}"));

    assert!(
        fixture
            .authority
            .confirm_current(
                fixture.artifacts(),
                INCARNATION,
                &fixture.clock(185, 35_000_001_000),
                durable,
            )
            .is_err()
    );
}

#[test]
fn wall_rollback_reverification_cannot_extend_the_persisted_deadline() {
    let fixture = fixture([8; 16], 7, None, None, 4);
    let pending = fixture
        .authority
        .admit(
            fixture.artifacts(),
            INCARNATION,
            &fixture.clock(150, 1_000),
            None,
        )
        .unwrap_or_else(|error| panic!("valid admission failed: {error}"));
    let original_deadline = pending.state().deadline_boottime_nanoseconds();
    let directory = protected_tempdir();
    let mut store = GuardianStateStore::open(directory.path())
        .unwrap_or_else(|error| panic!("test store failed: {error}"));
    let durable = store
        .commit(pending)
        .unwrap_or_else(|error| panic!("durable commit failed: {error}"));
    let confirmed = fixture
        .authority
        .confirm_current(
            fixture.artifacts(),
            INCARNATION,
            &fixture.clock(149, 2_000),
            durable,
        )
        .unwrap_or_else(|error| panic!("rollback-safe confirmation failed: {error}"));

    assert_eq!(confirmed.deadline_boottime_nanoseconds(), original_deadline);
}

#[test]
fn store_lock_and_predecessor_binding_reject_concurrent_or_stale_writers() {
    let fixture = fixture([8; 16], 7, None, None, 4);
    let clock = fixture.clock(150, 1_000);
    let first = fixture
        .authority
        .admit(fixture.artifacts(), INCARNATION, &clock, None)
        .unwrap_or_else(|error| panic!("first admission failed: {error}"));
    let stale = fixture
        .authority
        .admit(fixture.artifacts(), INCARNATION, &clock, None)
        .unwrap_or_else(|error| panic!("stale admission failed: {error}"));
    let directory = protected_tempdir();
    let mut store = GuardianStateStore::open(directory.path())
        .unwrap_or_else(|error| panic!("test store failed: {error}"));
    assert!(GuardianStateStore::open(directory.path()).is_err());

    store
        .commit(first)
        .unwrap_or_else(|error| panic!("first commit failed: {error}"));
    assert!(store.commit(stale).is_err());
}

#[test]
fn restart_rejects_rollback_and_equal_generation_plan_equivocation() {
    let current = fixture([8; 16], 8, None, None, 5);
    let clock = current.clock(150, 1_000);
    let prior = current
        .authority
        .admit(current.artifacts(), INCARNATION, &clock, None)
        .unwrap_or_else(|error| panic!("current admission failed: {error}"))
        .into_state();

    let stale = fixture([8; 16], 7, None, None, 4);
    assert!(
        stale
            .authority
            .admit(stale.artifacts(), INCARNATION, &clock, Some(&prior))
            .is_err()
    );

    let changed_plan = fixture([8; 16], 8, None, None, 6);
    assert!(
        changed_plan
            .authority
            .admit(changed_plan.artifacts(), INCARNATION, &clock, Some(&prior))
            .is_err()
    );
}

#[test]
fn durable_state_rejects_corruption_and_trailing_bytes() {
    let fixture = fixture([8; 16], 7, None, None, 4);
    let pending = fixture
        .authority
        .admit(
            fixture.artifacts(),
            INCARNATION,
            &fixture.clock(150, 1_000),
            None,
        )
        .unwrap_or_else(|error| panic!("valid guardian authority failed: {error}"));
    let encoded = pending.state().encode();

    let mut corrupt = encoded.clone();
    corrupt[20] ^= 1;
    assert!(GuardianState::decode(&corrupt).is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(GuardianState::decode(&trailing).is_err());
}

fn fixture(
    boot: [u8; 16],
    lease_generation: u64,
    plan_binding_generation: Option<u64>,
    plan_binding_digest: Option<ObjectDigest>,
    desired_generation: u64,
) -> Fixture {
    fixture_with_nonce(
        boot,
        lease_generation,
        plan_binding_generation,
        plan_binding_digest,
        desired_generation,
        lease_generation as u8,
    )
}

fn fixture_with_nonce(
    boot: [u8; 16],
    lease_generation: u64,
    plan_binding_generation: Option<u64>,
    plan_binding_digest: Option<ObjectDigest>,
    desired_generation: u64,
    nonce_byte: u8,
) -> Fixture {
    let plan_key = SigningKey::from_bytes(&[9; 32]);
    let lease_key = SigningKey::from_bytes(&[31; 32]);
    let plan_signer = key_reference(
        "guardian-controller",
        7,
        KeyUsage::BrokerAuthorization,
        &plan_key,
    );
    let lease_signer = key_reference(
        "ownership-authority",
        4,
        KeyUsage::OwnershipLease,
        &lease_key,
    );
    let plan_scope = TrustScopeId::from_bytes([10; 16]);
    let lease_scope = TrustScopeId::from_bytes([11; 16]);
    let plan_policy = trust_policy(
        plan_scope,
        SignaturePurpose::BrokerAuthorization,
        plan_signer.clone(),
    );
    let lease_policy = trust_policy(
        lease_scope,
        SignaturePurpose::OwnershipLease,
        lease_signer.clone(),
    );
    let plan_policy_descriptor = policy_descriptor(&plan_policy);
    let lease_policy_descriptor = policy_descriptor(&lease_policy);
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes([1; 16]),
        IncarnationId::from_bytes(INCARNATION),
        AssignmentEpoch::new(3),
        DesiredGeneration::new(desired_generation),
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
    let node = NodeId::from_bytes(NODE);
    let lease = OwnershipLease::new(
        LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test lease assignment failed: {error}")),
        node,
        lease_generation,
        100,
        200,
        10,
        [nonce_byte; 16],
    )
    .unwrap_or_else(|error| panic!("test lease failed: {error}"));
    let lease_bytes = encode_ownership_lease(&lease);
    let lease_descriptor = object_descriptor(PortableMediaType::OwnershipLease, &lease_bytes);
    let lease_signature = signed(
        lease_descriptor.clone(),
        lease_scope,
        lease_signer.clone(),
        SignaturePurpose::OwnershipLease,
        100,
        200,
        lease_policy_descriptor.clone(),
        &lease_key,
    );

    let binding = GuardianPlanBinding::new(
        assignment,
        node,
        boot,
        plan_binding_generation.unwrap_or(lease_generation),
        plan_binding_digest.unwrap_or(lease_descriptor.digest()),
    )
    .unwrap_or_else(|error| panic!("test binding failed: {error}"));
    let grant = BrokerGrant::new(
        BrokerVerb::GuardianArm,
        BrokerGrantTarget::Assignment,
        binding.commitment(),
        binding.encoded_len(),
        0,
    )
    .unwrap_or_else(|error| panic!("test grant failed: {error}"));
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Guardian,
        ProtocolId::Guardian,
        ProtocolVersion::new(1, 0),
        assignment,
        node,
        lease_signer.clone(),
        vec![grant],
        ObjectDigest::from_bytes([7; 32]),
        RevocationScopeId::from_bytes([8; 16]),
        100,
        190,
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test plan failed: {error}"));
    let plan_bytes = encode_broker_authorization_plan(&plan);
    let plan_signature = signed(
        object_descriptor(PortableMediaType::BrokerAuthorizationPlan, &plan_bytes),
        plan_scope,
        plan_signer.clone(),
        SignaturePurpose::BrokerAuthorization,
        100,
        190,
        plan_policy_descriptor.clone(),
        &plan_key,
    );

    let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
        plan_policy,
        plan_policy_descriptor,
        plan_scope,
        plan_signer,
        plan_key.verifying_key().to_bytes(),
        RevocationScopeId::from_bytes([8; 16]),
        DecodeLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test plan anchor failed: {error}"));
    let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
        lease_policy,
        lease_policy_descriptor,
        lease_scope,
        lease_signer,
        lease_key.verifying_key().to_bytes(),
        DecodeLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test lease anchor failed: {error}"));
    let authority = GuardianAuthority::new(
        plan_anchor,
        lease_anchor,
        node,
        RawClockProvenance::new_untrusted(PROVENANCE)
            .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
    )
    .unwrap_or_else(|error| panic!("test authority failed: {error}"));

    Fixture {
        authority,
        plan: plan_bytes,
        plan_signature: encode_signature(&plan_signature),
        lease: lease_bytes,
        lease_signature: encode_signature(&lease_signature),
        boot,
    }
}

fn key_reference(name: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
    KeyReference::new(
        StableKeyId::new(name.to_owned())
            .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
        generation,
        ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
        usage,
    )
}

fn trust_policy(scope: TrustScopeId, purpose: SignaturePurpose, signer: KeyReference) -> Vec<u8> {
    let policy = TrustPolicy::new(scope, purpose, vec![signer], Vec::new())
        .unwrap_or_else(|error| panic!("test policy failed: {error}"));
    encode_trust_policy(&policy)
}

fn policy_descriptor(bytes: &[u8]) -> ObjectDescriptor {
    object_descriptor(PortableMediaType::TrustPolicy, bytes)
}

fn object_descriptor(kind: PortableMediaType, bytes: &[u8]) -> ObjectDescriptor {
    descriptor_for_bytes(
        MediaType::new(kind.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test media type failed: {error}")),
        bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed(
    subject: ObjectDescriptor,
    scope: TrustScopeId,
    signer: KeyReference,
    purpose: SignaturePurpose,
    issued_seconds: i64,
    expires_seconds: i64,
    policy: ObjectDescriptor,
    key: &SigningKey,
) -> aos_sandbox_core::model::Signature {
    let statement = SignatureStatement::new(
        subject,
        scope,
        signer,
        purpose,
        issued_seconds,
        Some(expires_seconds),
        policy,
    )
    .unwrap_or_else(|error| panic!("test statement failed: {error}"));
    sign_statement(statement, key).unwrap_or_else(|error| panic!("test signature failed: {error}"))
}

fn protected_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("test temporary directory failed: {error}"));
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("test permissions failed: {error}"));
    directory
}
