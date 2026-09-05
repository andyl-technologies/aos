//! Protected selection and cryptographic preflight tests, without live Host proofs.
//!
//! Raw fixture clocks exercise the effect-free preparation helper only. No test
//! here constructs `CurrentRuntimeScope` or substitutes for kernel/VM coverage.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::format::{descriptor_for_bytes, encode_trust_policy};
use aos_sandbox_core::model::{KeyReference, KeyUsage, SignaturePurpose, StableKeyId, TrustPolicy};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, OperationId, OwnershipLeaseTrustAnchor,
    PortableMediaType, RawClockProvenance, RevocationScopeId, TrustScopeId,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::publication::tests::{
    activation_claim, descriptor_free_activation_fixture, runtime_scope_activation_fixture,
};
use crate::runtime_authority::RuntimeAuthorityIntentV1;
use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey, JournalLimits,
    OperationPlan, Reconciler, SingleNodeEffectExecutor,
};

use super::*;

struct NoEffects;
impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("scope preparation must not dispatch runtime effects");
    }
    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("scope preparation must not dispatch runtime effects");
    }
}

fn open(directory: &std::path::Path) -> Journal {
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    Journal::open_protected_at_uid(
        directory,
        "controller.journal",
        JournalLimits::default(),
        std::fs::metadata(directory).unwrap().uid(),
    )
    .unwrap()
    .0
}

fn activate(
    reconciler: &mut Reconciler<NoEffects>,
    generation: u8,
    intent: RuntimeAuthorityIntentV1,
    with_scope: bool,
) -> RuntimeScopeHolder {
    let (draft, prepared) = if with_scope {
        runtime_scope_activation_fixture(u64::from(generation))
    } else {
        descriptor_free_activation_fixture(u64::from(generation))
    };
    let selection = RuntimeScopeHolder {
        sandbox: draft.manifest().manifest().sandbox(),
        holder: PrincipalId::from_bytes([0x91; 16]),
    };
    let operation = OperationId::from_bytes([generation; 16]);
    let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
    let plan = OperationPlan::ownership_gated(
        operation,
        IdempotencyKey::new(vec![generation]).unwrap(),
        [generation; 32],
        vec![generation],
        vec![generation],
        vec![effect],
        activation_claim(&draft, u64::from(generation)),
        draft.clone(),
    )
    .unwrap()
    .with_runtime_authority(intent)
    .unwrap();
    reconciler.accept(&plan).unwrap();
    let activation = AuthorityPublicationStore::new(reconciler.journal_mut())
        .prepare_gate_activation(&draft, &prepared)
        .unwrap();
    reconciler
        .activate_ownership_gate(operation, activation)
        .unwrap();
    selection
}

fn bind(revision: Option<u64>) -> RuntimeAuthorityIntentV1 {
    RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x91; 16]), revision).unwrap()
}

fn trust(
    key: &SigningKey,
    id: &str,
    usage: KeyUsage,
    purpose: SignaturePurpose,
    scope_byte: u8,
) -> (Vec<u8>, ObjectDescriptor, TrustScopeId, KeyReference) {
    let reference = KeyReference::new(
        StableKeyId::new(id.to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
        usage,
    );
    let scope = TrustScopeId::from_bytes([scope_byte; 16]);
    let bytes = encode_trust_policy(
        &TrustPolicy::new(scope, purpose, vec![reference.clone()], Vec::new()).unwrap(),
    );
    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
        &bytes,
    );
    (bytes, descriptor, scope, reference)
}

fn policy_keys(broker_key: u8, lease_key: u8) -> CurrentRuntimeScopePolicy {
    let broker = SigningKey::from_bytes(&[broker_key; 32]);
    let (bytes, descriptor, scope, reference) = trust(
        &broker,
        "controller",
        KeyUsage::BrokerAuthorization,
        SignaturePurpose::BrokerAuthorization,
        20,
    );
    let broker_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
        bytes,
        descriptor,
        scope,
        reference,
        broker.verifying_key().to_bytes(),
        RevocationScopeId::from_bytes([51; 16]),
        DecodeLimits::default(),
    )
    .unwrap();
    let lease = SigningKey::from_bytes(&[lease_key; 32]);
    let (bytes, descriptor, scope, reference) = trust(
        &lease,
        "lease",
        KeyUsage::OwnershipLease,
        SignaturePurpose::OwnershipLease,
        61,
    );
    let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
        bytes,
        descriptor,
        scope,
        reference.clone(),
        lease.verifying_key().to_bytes(),
        DecodeLimits::default(),
    )
    .unwrap();
    CurrentRuntimeScopePolicy {
        node: NodeId::from_bytes([5; 16]),
        clock_provenance: [91; 16],
        maximum_validity_seconds: 30,
        runtime_limits: RuntimeAuthorityLimits::default(),
        ownership_verifier: OwnershipAuthorityVerifier::new(lease_anchor, reference),
        broker_anchor,
    }
}

fn policy() -> CurrentRuntimeScopePolicy {
    policy_keys(40, 41)
}

fn clock(wall: i64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([91; 16]).unwrap(),
        [92; 16],
        wall,
        1_000,
    )
    .unwrap()
}

#[test]
fn missing_holder_and_unprotected_journal_are_not_authority() {
    let directory = tempfile::tempdir().unwrap();
    let selection = RuntimeScopeHolder {
        sandbox: SandboxId::from_bytes([1; 16]),
        holder: PrincipalId::from_bytes([0x91; 16]),
    };
    assert!(matches!(
        prepare(
            &mut open(directory.path()),
            selection,
            &policy(),
            clock(150)
        ),
        Err(CurrentRuntimeScopeError::CurrentMismatch)
    ));
    let (mut ordinary, _) = Journal::open(
        directory.path().join("ordinary.journal"),
        JournalLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        prepare(&mut ordinary, selection, &policy(), clock(150)),
        Err(CurrentRuntimeScopeError::RuntimeAuthority(_))
    ));
}

#[test]
fn protected_reopen_derives_exact_current_request_and_verified_lease() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), true);
    let prepared = prepare(reconciler.journal_mut(), selection, &policy(), clock(150)).unwrap();
    let decoded = decode_local_body(&prepared.body, 1_000).unwrap();
    assert_eq!(
        decoded.fence().assignment_digest(),
        prepared.binding.assignment_digest().as_bytes()
    );
    assert_eq!(decoded.fence().sandbox_id(), selection.sandbox.as_bytes());
    assert_eq!(
        decoded.header().deadline_boottime_nanoseconds(),
        30_000_001_000
    );
    assert_eq!(prepared.lease.generation(), 1);
    assert_eq!(prepared.binding.holder(), Some(selection.holder));
    assert_eq!(
        prepared.template.plan().protocol_version(),
        AUTHORITY_VERSION
    );
    let original_binding = prepared.binding;
    drop(reconciler);

    let recovered = prepare(
        &mut open(directory.path()),
        selection,
        &policy(),
        clock(150),
    )
    .unwrap();
    assert_eq!(recovered.binding, original_binding);
    assert_eq!(recovered.lease.generation(), 1);
    assert_eq!(recovered.validity.deadline(), 30_000_001_000);
}

#[test]
fn mismatched_holder_node_and_revoked_head_fail_before_host_io() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), true);
    let mut wrong = selection;
    wrong.holder = PrincipalId::from_bytes([0x92; 16]);
    assert!(matches!(
        prepare(reconciler.journal_mut(), wrong, &policy(), clock(150)),
        Err(CurrentRuntimeScopeError::CurrentMismatch)
    ));
    let mut wrong_node = policy();
    wrong_node.node = NodeId::from_bytes([6; 16]);
    assert!(matches!(
        prepare(reconciler.journal_mut(), selection, &wrong_node, clock(150)),
        Err(CurrentRuntimeScopeError::CurrentMismatch)
    ));
    activate(
        &mut reconciler,
        2,
        RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap(),
        true,
    );
    assert!(matches!(
        prepare(reconciler.journal_mut(), selection, &policy(), clock(150)),
        Err(CurrentRuntimeScopeError::CurrentMismatch)
    ));
}

#[test]
fn renewal_and_same_holder_rebind_select_new_revision_and_exact_lease() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), true);
    let original = prepare(reconciler.journal_mut(), selection, &policy(), clock(150)).unwrap();
    activate(&mut reconciler, 2, bind(Some(1)), true);
    let renewed = prepare(reconciler.journal_mut(), selection, &policy(), clock(150)).unwrap();
    assert_eq!(renewed.binding.manifest(), original.binding.manifest());
    assert_ne!(renewed.binding, original.binding);
    assert!(matches!(
        select_exact_current(
            reconciler.journal_mut(),
            selection,
            &policy(),
            &original.binding
        ),
        Err(CurrentRuntimeScopeError::CurrentMismatch)
    ));
    select_exact_current(
        reconciler.journal_mut(),
        selection,
        &policy(),
        &renewed.binding,
    )
    .unwrap();
    assert_eq!(renewed.lease.generation(), 2);
    assert_ne!(
        renewed.lease.canonical_lease(),
        original.lease.canonical_lease()
    );
    activate(
        &mut reconciler,
        3,
        RuntimeAuthorityIntentV1::revoke(Some(2)).unwrap(),
        true,
    );
    activate(&mut reconciler, 4, bind(Some(3)), true);
    let rebound = prepare(reconciler.journal_mut(), selection, &policy(), clock(150)).unwrap();
    assert_eq!(rebound.binding.holder(), original.binding.holder());
    assert_eq!(rebound.binding.revision(), 4);
    assert_ne!(rebound.binding, original.binding);
    assert!(matches!(
        select_exact_current(
            reconciler.journal_mut(),
            selection,
            &policy(),
            &original.binding
        ),
        Err(CurrentRuntimeScopeError::CurrentMismatch)
    ));
}

#[test]
fn old_plans_missing_observation_grants_and_wrong_trust_keys_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), false);
    assert!(matches!(
        prepare(reconciler.journal_mut(), selection, &policy(), clock(150)),
        Err(CurrentRuntimeScopeError::MissingGrant)
    ));
    let second_directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(second_directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), true);
    assert!(matches!(
        prepare(
            reconciler.journal_mut(),
            selection,
            &policy_keys(40, 42),
            clock(150)
        ),
        Err(CurrentRuntimeScopeError::Ownership(_))
    ));
    assert!(matches!(
        prepare(
            reconciler.journal_mut(),
            selection,
            &policy_keys(42, 41),
            clock(150)
        ),
        Err(CurrentRuntimeScopeError::Plan(_))
    ));
    assert!(prepare(reconciler.journal_mut(), selection, &policy(), clock(190)).is_err());
    assert!(prepare(reconciler.journal_mut(), selection, &policy(), clock(180)).is_err());
    let short = prepare(reconciler.journal_mut(), selection, &policy(), clock(179)).unwrap();
    assert_eq!(short.validity.deadline(), 1_000_001_000);
}
