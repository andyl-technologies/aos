//! Protected selection and cryptographic preflight tests, without live Host proofs.
//!
//! Raw fixture clocks exercise the effect-free preparation helper only. No test
//! here constructs `CurrentRuntimeScope` or substitutes for kernel/VM coverage.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

#[cfg(feature = "kernel-tests")]
use std::fs::File;
#[cfg(feature = "kernel-tests")]
use std::num::NonZeroU32;
#[cfg(feature = "kernel-tests")]
use std::path::Path;

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
use crate::runtime_authority::{
    ControllerRuntimeCurrentnessReceiptV1, RuntimeAuthorityError, RuntimeAuthorityIntentV1,
};
use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey, JournalLimits,
    OperationPlan, Reconciler, SingleNodeEffectExecutor,
};

#[cfg(feature = "kernel-tests")]
use aos_proto::aos::sandbox::local::v1::BrokerMethod;
#[cfg(feature = "kernel-tests")]
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
#[cfg(feature = "kernel-tests")]
use aos_sandbox_linux::pidfd::PidFd;
#[cfg(feature = "kernel-tests")]
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
#[cfg(feature = "kernel-tests")]
use aos_sandbox_protocol::payload_scope::{
    decode_payload_scope_response, encode_payload_scope_response,
};
#[cfg(feature = "kernel-tests")]
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, decode_request_envelope, encode_authorized_request_envelope,
};
#[cfg(feature = "kernel-tests")]
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

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
        bytes.clone(),
        descriptor.clone(),
        scope,
        reference.clone(),
        broker.verifying_key().to_bytes(),
        RevocationScopeId::from_bytes([51; 16]),
        DecodeLimits::default(),
    )
    .unwrap();
    let mount_broker_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
        bytes,
        descriptor,
        scope,
        reference,
        broker.verifying_key().to_bytes(),
        RevocationScopeId::from_bytes([52; 16]),
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
        mount_broker_anchor,
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

#[cfg(feature = "kernel-tests")]
pub(crate) struct CurrentNamespaceFixture {
    reconciler: Reconciler<NoEffects>,
    selection: RuntimeScopeHolder,
}

#[cfg(feature = "kernel-tests")]
impl CurrentNamespaceFixture {
    pub(crate) fn new(directory: &Path) -> Self {
        let mut reconciler = Reconciler::new(open(directory), NoEffects);
        let selection = activate(&mut reconciler, 1, bind(None), true);
        Self {
            reconciler,
            selection,
        }
    }

    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        self.reconciler.journal_mut()
    }

    pub(crate) fn current_target(&mut self) -> CurrentNamespaceTarget {
        let boottime = crate::runtime_scope::transport::boottime().unwrap();
        let mut clock = || Ok(clock_at_boottime(150, boottime));
        let prepared = prepare(
            self.reconciler.journal_mut(),
            self.selection,
            &policy(),
            clock_at_boottime(150, boottime),
        )
        .unwrap();
        let request = decode_local_body(&prepared.body, boottime).unwrap();
        let authorization_packet = encode_authorized_request_envelope(
            ProtocolId::HostBroker,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE,
            &prepared.body,
            &[],
            AuthorizationArtifactBytes {
                broker_plan: prepared.template.canonical_plan(),
                broker_plan_signature: prepared.template.canonical_plan_signature(),
                ownership_lease: prepared.lease.canonical_lease(),
                ownership_lease_signature: prepared.lease.canonical_signature(),
            },
        )
        .unwrap();
        let authorization =
            decode_request_envelope(&authorization_packet, ProtocolId::HostBroker, 0)
                .unwrap()
                .authorization()
                .unwrap()
                .clone();

        let (host_anchor, payload_anchor) = current_cgroup_anchors();
        let (receiver, sender) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut receiver = DescriptorSubjectSocket::from_owned(receiver).unwrap();
        let mut sender = DescriptorSubjectSocket::from_owned(sender).unwrap();
        sender.send(b"current namespace fixture").unwrap();
        let (_, subject, _) = receiver.receive(64, 0).unwrap().into_parts();
        let host = HostExecution::new(
            HostServiceIdentity {
                uid: rustix::process::geteuid().as_raw(),
                gid: rustix::process::getegid().as_raw(),
                cgroup: host_anchor,
            },
            subject,
        )
        .unwrap();
        let payload = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let response = encode_payload_scope_response(
            request.fence(),
            request.runtime_handle(),
            &[72; 32],
            b"",
        )
        .unwrap();
        let metadata =
            decode_payload_scope_response(&response, request.fence(), request.runtime_handle())
                .unwrap();
        let payload_info = observe_payload(&payload, &payload_anchor, b"").unwrap();
        let observed = ObservedPayloadScope {
            host,
            payload,
            anchor: payload_anchor,
            metadata,
            payload_info,
            authorization,
            request_deadline_boottime_nanoseconds: prepared.validity.deadline(),
        };
        let scope = CurrentRuntimeScope {
            selection: self.selection,
            policy: policy(),
            binding: prepared.binding,
            observed,
            validity: prepared.validity,
        };
        let generation =
            CurrentRuntimeGeneration::track(scope, self.reconciler.journal_mut(), &mut clock)
                .unwrap();
        match CurrentNamespaceTarget::bind(generation, self.reconciler.journal_mut(), &mut clock)
            .unwrap()
        {
            NamespaceTargetOutcome::Current(target) => *target,
            NamespaceTargetOutcome::AdvanceRequired(_) => {
                panic!("fixture assignment must name its first namespace target")
            }
        }
    }
}

#[cfg(feature = "kernel-tests")]
fn clock_at_boottime(wall: i64, boottime: u64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([91; 16]).unwrap(),
        KernelBootId::current().unwrap().into_bytes(),
        wall,
        boottime,
    )
    .unwrap()
}

#[cfg(feature = "kernel-tests")]
fn current_cgroup_anchors() -> (RetainedCgroupAnchor, RetainedCgroupAnchor) {
    let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .unwrap();
    let relative = Path::new(if relative.is_empty() { "." } else { relative });
    let first = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").unwrap().into())
        .unwrap()
        .resolve(relative)
        .unwrap();
    let second = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").unwrap().into())
        .unwrap()
        .resolve(relative)
        .unwrap();
    (first, second)
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
fn controller_node_validation_checks_every_current_runtime_binding() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), false);
    let store =
        RuntimeAuthorityStore::load(reconciler.journal_mut(), RuntimeAuthorityLimits::default())
            .unwrap();
    let binding = store.current(selection.sandbox).unwrap().unwrap();
    let expected_node = binding.manifest().manifest().node();

    store.validate_current_node(expected_node).unwrap();
    assert!(matches!(
        store.validate_current_node(NodeId::from_bytes([0xfe; 16])),
        Err(RuntimeAuthorityError::NodeMismatch)
    ));
}

#[test]
fn controller_currentness_receipt_requires_exact_cold_replayed_head() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), false);
    let signer = SigningKey::from_bytes(&[0x35; 32]);
    let receipt = ControllerRuntimeCurrentnessReceiptV1::issue_at_uid_for_test(
        reconciler.journal_mut(),
        directory.path(),
        selection.sandbox,
        7,
        &signer,
    )
    .unwrap();
    drop(reconciler);

    let mut cold = open(directory.path());
    let recovered = ControllerRuntimeCurrentnessReceiptV1::decode(receipt.as_bytes()).unwrap();
    recovered
        .verify_replayed_at_uid_for_test(&mut cold, directory.path(), 7, &signer.verifying_key())
        .unwrap();
    assert!(
        recovered
            .verify_replayed_at_uid_for_test(
                &mut cold,
                directory.path(),
                8,
                &signer.verifying_key(),
            )
            .is_err()
    );
    assert!(
        recovered
            .verify_replayed_at_uid_for_test(
                &mut cold,
                directory.path(),
                7,
                &SigningKey::from_bytes(&[0x36; 32]).verifying_key(),
            )
            .is_err()
    );

    let mut changed = receipt.as_bytes().to_vec();
    changed[128] ^= 1;
    let changed = ControllerRuntimeCurrentnessReceiptV1::decode(&changed).unwrap();
    assert!(
        changed
            .verify_replayed_at_uid_for_test(
                &mut cold,
                directory.path(),
                7,
                &signer.verifying_key(),
            )
            .is_err()
    );
    drop(cold);

    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    activate(&mut reconciler, 2, bind(Some(1)), false);
    assert!(
        recovered
            .verify_replayed_at_uid_for_test(
                reconciler.journal_mut(),
                directory.path(),
                7,
                &signer.verifying_key(),
            )
            .is_err()
    );
}

#[test]
fn controller_currentness_receipt_rejects_noncanonical_or_revoked_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), false);
    let signer = SigningKey::from_bytes(&[0x37; 32]);
    assert!(
        ControllerRuntimeCurrentnessReceiptV1::issue_at_uid_for_test(
            reconciler.journal_mut(),
            directory.path(),
            selection.sandbox,
            0,
            &signer,
        )
        .is_err()
    );

    let receipt = ControllerRuntimeCurrentnessReceiptV1::issue_at_uid_for_test(
        reconciler.journal_mut(),
        directory.path(),
        selection.sandbox,
        1,
        &signer,
    )
    .unwrap();
    let mut changed = receipt.as_bytes().to_vec();
    changed[10] = 1;
    assert!(ControllerRuntimeCurrentnessReceiptV1::decode(&changed).is_err());
    assert!(ControllerRuntimeCurrentnessReceiptV1::decode(&changed[..changed.len() - 1]).is_err());

    activate(
        &mut reconciler,
        2,
        RuntimeAuthorityIntentV1::revoke(Some(1)).unwrap(),
        false,
    );
    assert!(
        ControllerRuntimeCurrentnessReceiptV1::issue_at_uid_for_test(
            reconciler.journal_mut(),
            directory.path(),
            selection.sandbox,
            1,
            &signer,
        )
        .is_err()
    );
    assert!(
        receipt
            .verify_replayed_at_uid_for_test(
                reconciler.journal_mut(),
                directory.path(),
                1,
                &signer.verifying_key(),
            )
            .is_err()
    );
}

#[test]
fn controller_currentness_receipt_rejects_orphaned_writer_after_root_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), false);
    let signer = SigningKey::from_bytes(&[0x38; 32]);
    let receipt = ControllerRuntimeCurrentnessReceiptV1::issue_at_uid_for_test(
        reconciler.journal_mut(),
        directory.path(),
        selection.sandbox,
        1,
        &signer,
    )
    .unwrap();

    let orphaned = directory.path().with_extension("orphaned");
    std::fs::rename(directory.path(), &orphaned).unwrap();
    std::fs::create_dir(directory.path()).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(
        ControllerRuntimeCurrentnessReceiptV1::issue_at_uid_for_test(
            reconciler.journal_mut(),
            directory.path(),
            selection.sandbox,
            1,
            &signer,
        )
        .is_err()
    );
    assert!(
        receipt
            .verify_replayed_at_uid_for_test(
                reconciler.journal_mut(),
                directory.path(),
                1,
                &signer.verifying_key(),
            )
            .is_err()
    );

    std::fs::remove_dir(directory.path()).unwrap();
    std::fs::rename(orphaned, directory.path()).unwrap();
    receipt
        .verify_replayed_at_uid_for_test(
            reconciler.journal_mut(),
            directory.path(),
            1,
            &signer.verifying_key(),
        )
        .unwrap();
}

#[test]
fn prelaunch_assignment_target_requires_no_host_observation() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), false);
    let target =
        prepare_assignment(reconciler.journal_mut(), selection, policy(), clock(150)).unwrap();

    target
        .recheck_at(reconciler.journal_mut(), clock(150))
        .unwrap();
    assert_eq!(target.sandbox(), selection.sandbox);
    assert_eq!(
        target.incarnation(),
        target.binding().manifest().manifest().incarnation()
    );
    assert_eq!(
        target.namespace_generation(),
        target
            .binding()
            .manifest()
            .manifest()
            .namespace_generation()
            .get()
    );
    assert_eq!(
        target.sandbox_spec(),
        target.binding().manifest().manifest().sandbox_spec()
    );
    assert_eq!(target.deadline_boottime_nanoseconds(), 30_000_001_000);
}

#[test]
fn prelaunch_target_allows_only_uninterrupted_same_holder_renewal() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let selection = activate(&mut reconciler, 1, bind(None), false);
    let origin =
        prepare_assignment(reconciler.journal_mut(), selection, policy(), clock(150)).unwrap();
    let reference = origin.durable_reference();

    activate(&mut reconciler, 2, bind(Some(1)), false);
    origin
        .recheck_at(reconciler.journal_mut(), clock(150))
        .unwrap();
    let renewed =
        prepare_assignment(reconciler.journal_mut(), selection, policy(), clock(150)).unwrap();
    renewed
        .validate_durable_reference(reconciler.journal_mut(), reference)
        .unwrap();

    activate(
        &mut reconciler,
        3,
        RuntimeAuthorityIntentV1::revoke(Some(2)).unwrap(),
        false,
    );
    assert!(
        origin
            .recheck_at(reconciler.journal_mut(), clock(150))
            .is_err()
    );
    activate(&mut reconciler, 4, bind(Some(3)), false);
    let rebound =
        prepare_assignment(reconciler.journal_mut(), selection, policy(), clock(150)).unwrap();
    assert!(
        rebound
            .validate_durable_reference(reconciler.journal_mut(), reference)
            .is_err()
    );
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
