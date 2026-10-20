//! Seeded-history regressions for the protected terminal append engine.
//!
//! The seed uses canonical DATA and the real framing/sync implementation; it
//! does not exercise PID1 enrollment, Root authentication or installed Q04.
//! Private test-local original construction never becomes a production factory.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox_core::{
    ObjectDigest, PrincipalId, ProjectId, ResourceDimension, ResourceVector, SandboxId,
};
use aos_sandbox_policy::*;
use aos_sandbox_protocol::policy_data::RetainedPublisherCompilerOriginV3;
use aos_sandbox_protocol::domain_ledger::create_q04_history::{Q04CutIdentityV1, Q04PhaseRecordV1};
use aos_sandbox_protocol::domain_ledger::effect_history::{
    EffectLedgerRecord, EffectState, encode_q04_effect,
};
use aos_sandbox_protocol::domain_ledger::operation::effect_key;
use aos_sandbox_protocol::domain_ledger::resource_bank::{
    self as bank, ClaimCut, CoissuanceMutation, InputAssociation,
};
use aos_sandbox_protocol::domain_ledger::transaction::encode_transaction;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::super::{AccountTransition, Q04TerminalOriginalsV1, ReturnedAppend};
use super::*;
use crate::journal::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};
use crate::policy_compiler::create_q04::{
    controller_phase_recipe_v1, q04_controller_capacity_events_v1,
};

const HOLD_KEY: &[u8] = b"\0aos-controller-policy-hold-v1\0";

// These verifiers describe fixture DATA only. They are never used by the
// production Root current-input verifier or any installed owner constructor.
struct FixtureData;

impl SandboxProjectRelationVerifierV1 for FixtureData {
    fn verify(
        &self,
        _: SandboxId,
        _: ProjectId,
        _: &aos_sandbox_core::ObjectDescriptor,
        _: &[u8],
    ) -> bool {
        true
    }
}

impl CacheDomainVerifierV1 for FixtureData {
    fn verify(&self, _: &aos_sandbox_core::ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl EndpointCatalogVerifierV1 for FixtureData {
    fn verify(&self, _: &aos_sandbox_core::ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl NamespaceCatalogVerifierV1 for FixtureData {
    fn verify(&self, _: &aos_sandbox_core::ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

fn compiler_origin() -> RetainedPublisherCompilerOriginV3 {
    use aos_sandbox_core::model::{CacheDomain, CacheDomainKind, RevocationMode, RevocationPolicy};

    let mechanisms = vec![
        HardEnforcementV1::CgroupV2,
        HardEnforcementV1::BrokerLedger,
        HardEnforcementV1::ZfsQuota,
        HardEnforcementV1::NodeBoundedSharedResidency,
        HardEnforcementV1::HardIsolatedResidency,
        HardEnforcementV1::CombinedFileDescriptor,
        HardEnforcementV1::CombinedMemoryAccounting,
    ];
    let resources = |bounded: bool| {
        let entry = |key| {
            let value = if bounded {
                HardLimitValueV1::Bounded(4096)
            } else {
                HardLimitValueV1::Inherit
            };
            let enforcement =
                bounded.then(|| *mechanisms.iter().find(|value| value.supports(key)).unwrap());
            HardLimitRequestV1::new(key, value, enforcement).unwrap()
        };
        HardResourceProfileV1::new(
            PORTABLE_LIMIT_DIMENSIONS
                .into_iter()
                .map(|dimension| entry(HardResourceKeyV1::Portable(dimension)))
                .collect(),
            ResourceDimension::ALL
                .into_iter()
                .map(|dimension| entry(HardResourceKeyV1::Accounting(dimension)))
                .collect(),
        )
        .unwrap()
    };
    let project = ProjectId::from_bytes([1; 16]);
    let sandbox = SandboxId::from_bytes([2; 16]);
    let domain = AuthenticatedCacheDomainV1::authenticate(
        CacheDomain::new(
            CacheDomainKind::Project,
            aos_sandbox_core::CacheDomainId::from_bytes([1; 16]),
        ),
        CacheDomainBindingV1::Project(project),
        &FixtureData,
    )
    .unwrap();
    let ceiling = PolicyLayerV1::new(
        Vec::new(),
        resources(true),
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Exact(domain),
        RevocationInputV1::Exact(RevocationPolicy::new(RevocationMode::DenyNew, 0)),
    )
    .unwrap();
    let inherited = PolicyLayerV1::new(
        Vec::new(),
        resources(false),
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Inherit,
        RevocationInputV1::Inherit,
    )
    .unwrap();
    let input = PolicyCompilerInputV1::new(
        AuthenticatedSandboxProjectRelationV1::authenticate(sandbox, project, &FixtureData)
            .unwrap(),
        NodePolicyInputV1::new(ceiling).unwrap(),
        SitePolicyInputV1::new(inherited.clone()).unwrap(),
        ProjectPolicyInputV1::new(project, inherited.clone()).unwrap(),
        Vec::new(),
        RequestPolicyInputV1::new(inherited).unwrap(),
        AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &FixtureData).unwrap(),
        AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &FixtureData).unwrap(),
        BackendCapabilitiesV1::new(
            BackendEnforcementSetV1::new(mechanisms).unwrap(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
        PolicyCompilerLimitsV1::DEFAULT,
    )
    .unwrap();
    let candidate = PolicyCompilerV1::compile_retained(&input).unwrap();
    retain_publisher_compiler_derivation_v3(&input, &candidate).unwrap()
}

#[derive(Clone, Copy)]
enum FixtureImage {
    Q04,
    CreateIntake,
}

fn canonical_image_and_delivery(
    clock: aos_sandbox_core::RawPairedClockSample,
    selected: FixtureImage,
) -> (bank::ImageBootstrapPolicy, bank::EnrollmentIdentity) {
    let mut image = Vec::from(match selected {
        FixtureImage::Q04 => *b"AOSRSB05",
        FixtureImage::CreateIntake => *b"AOSRSB07",
    });
    image.extend_from_slice(&[10; 16]);
    image.extend_from_slice(&[11; 16]);
    let amounts = [
        1_u64 << 60,
        0,
        1 << 55,
        1 << 50,
        1 << 45,
        1 << 45,
        1 << 40,
        1 << 40,
        1 << 40,
    ];
    for amount in amounts {
        for _ in ResourceDimension::ALL {
            image.extend_from_slice(&amount.to_be_bytes());
        }
    }
    if matches!(selected, FixtureImage::CreateIntake) {
        let root = ResourceVector::new([1 << 40; ResourceDimension::COUNT])
            .with(ResourceDimension::CpuMicrosPerPeriod, 1_000_000);
        let intake = ResourceVector::new([1 << 40; ResourceDimension::COUNT]);
        let storage = ResourceVector::new([1 << 40; ResourceDimension::COUNT])
            .with(ResourceDimension::CpuMicrosPerPeriod, 1_000_000);
        for vector in [root, intake, storage] {
            for dimension in ResourceDimension::ALL {
                image.extend_from_slice(&vector.get(dimension).to_be_bytes());
            }
        }
    }
    image.extend_from_slice(&Sha256::digest(&image));
    let policy = bank::decode_image_policy(&image, bank::NativeLayoutDemand::new(1, 1)).unwrap();

    let mut delivery = Vec::from(*b"AOSRSE01");
    delivery.extend_from_slice(&[10; 16]);
    delivery.extend_from_slice(&[11; 16]);
    delivery.extend_from_slice(&clock.host_boot_id());
    delivery.extend_from_slice(&[12; 16]);
    delivery.extend_from_slice(&Sha256::digest(&image));
    delivery.extend_from_slice(&[13; 16]);
    delivery.extend_from_slice(&Sha256::digest(&delivery));
    let (identity, _) = bank::decode_pid1_delivery(&delivery).unwrap();
    (policy, identity)
}

fn reopen(directory: &TempDir) -> Journal {
    // The existing fixture opener checks the private leaf and native names.
    // A temporary directory cannot satisfy production root-ancestry policy.
    Journal::open_protected_at_uid(
        directory.path(),
        "controller.journal",
        crate::journal::controller::production_journal_limits(),
        rustix::process::geteuid().as_raw(),
    )
    .unwrap()
    .0
}

// This bypasses semantic admission only to seed history in a private test
// directory. The append under test below never uses this helper.
fn seed(
    directory: &TempDir,
    journal: Journal,
    transaction: &JournalTransaction,
) -> (Journal, Result<CommitResult, JournalError>) {
    let next = journal.snapshot_sequence();
    drop(journal);
    let frames = encode_transaction(transaction, next).unwrap();
    let mut file = OpenOptions::new()
        .append(true)
        .open(directory.path().join("controller.journal"))
        .unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).unwrap();
    let result = aos_sandbox_journal::framing::append_and_sync(&mut file, &frames)
        .map(|durable_bytes| CommitResult {
            commit_sequence: next + u64::try_from(frames.len()).unwrap() - 1,
            durable_bytes,
        })
        .map_err(JournalError::from);
    drop(file);
    (reopen(directory), result)
}

fn hold_bytes(identity: &Q04CutIdentityV1, held: bool) -> Vec<u8> {
    let mut bytes = Vec::from(*b"AOSCTH01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(if held { 1 } else { 2 });
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(identity.operation().as_bytes());
    bytes.extend_from_slice(identity.sandbox().as_bytes());
    bytes.extend_from_slice(&[19; 32]);
    bytes.extend_from_slice(identity.binding().as_bytes());
    bytes.extend_from_slice(&identity.epoch().to_be_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller-policy-hold.v1\0")
        .chain_update(&bytes)
        .finalize();
    bytes.extend_from_slice(&digest);
    bytes
}

fn cut_identity(
    clock: aos_sandbox_core::RawPairedClockSample,
    origin: &RetainedPublisherCompilerOriginV3,
    operation: aos_sandbox_core::OperationId,
) -> Q04CutIdentityV1 {
    let mut body = [0; crate::policy_compiler::create_q04::IDENTITY_BYTES];
    body[16..32].fill(3);
    body[32..48].copy_from_slice(origin.project().as_bytes());
    body[48..64].copy_from_slice(operation.as_bytes());
    body[64..80].copy_from_slice(origin.original_target().as_bytes());
    body[80..84].copy_from_slice(&rustix::process::geteuid().as_raw().to_be_bytes());
    body[84..88].copy_from_slice(&1001_u32.to_be_bytes());
    body[88..96].copy_from_slice(&1_u64.to_be_bytes());
    body[96..104].copy_from_slice(&1_u64.to_be_bytes());
    body[112..128].copy_from_slice(&clock.host_boot_id());
    let times = [
        (128, clock.boottime_nanoseconds()),
        (136, clock.boottime_nanoseconds() + 60_000_000_000),
        (144, clock.boottime_nanoseconds()),
        (152, clock.boottime_nanoseconds() + 65_000_000_000),
        (160, 1),
    ];
    for (offset, value) in times {
        body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    body[168..184].fill(4);
    body[184..200].fill(5);
    for (index, offset) in (200..648).step_by(32).enumerate() {
        body[offset..offset + 32].fill(6 + index as u8);
    }
    body[456..488].copy_from_slice(origin.normalized_input().as_bytes());
    body[488..520].copy_from_slice(origin.candidate().as_bytes());
    Q04CutIdentityV1::from_body(body).unwrap()
}

fn applying_effect() -> EffectLedgerRecord {
    use aos_proto::aos::sandbox::v1::{CreateSandboxRequest, Duration, ObjectDescriptor};
    use buffa::Message as _;

    let descriptor = ObjectDescriptor {
        media_type: "application/vnd.aos.sandbox.spec.v1+cbor".to_owned(),
        sha256: vec![20; 32],
        encoded_size: 1,
        ..Default::default()
    };
    let requested = ObjectDescriptor {
        media_type: "application/vnd.aos.sandbox.policy.v1+cbor".to_owned(),
        ..descriptor.clone()
    };
    let request = CreateSandboxRequest {
        project_id: vec![1; 16],
        expected_project_resource_version: vec![21; 32],
        specification: Some(descriptor).into(),
        requested_policy: Some(requested).into(),
        idempotency_key: b"terminal-native-fixture".to_vec(),
        operation_timeout: Some(Duration {
            nanoseconds: 1,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let envelope = crate::cli_model::PublicMutationRequestV1::new(
        crate::cli_model::PublicApiAuditMethodV1::CreateSandbox,
        &request.encode_to_vec(),
    )
    .unwrap()
    .encode();
    let plan = crate::reconciler::PublicMutationEffectV1::new(
        PrincipalId::from_bytes([22; 16]),
        ProjectId::from_bytes([1; 16]),
        100,
        envelope,
    )
    .unwrap()
    .into_plan(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
    .unwrap();
    EffectLedgerRecord::from_parts((
        plan,
        EffectState::Applying {
            attempt: 1,
            diagnostic: String::new(),
        },
        None,
        None,
    ))
}

struct Fixture {
    directory: TempDir,
    journal: Journal,
    original: Q04ResourceTransferV1,
    native: [Option<Result<CommitResult, CreateQ04ErrorV1>>; 8],
    posts: [Option<Result<(), CreateQ04ErrorV1>>; 7],
    terminal: AccountTransition,
}

fn fixture() -> Fixture {
    fixture_for_image(FixtureImage::Q04)
}

fn fixture_for_image(selected: FixtureImage) -> Fixture {
    fixture_with_create_operation(selected, None)
}

fn fixture_with_create_operation(
    selected: FixtureImage,
    accepted: Option<aos_sandbox_core::OperationId>,
) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = reopen(&directory);
    let publication = crate::sandbox_spec_state::slot_spec_publication_for_test(Vec::new(), 30);
    let (specification, _) = crate::sandbox_spec_state::commit(&mut journal, publication).unwrap();
    let clock = crate::policy_compiler::observe_root_first_source_successor_clock_v2(None).unwrap();
    let origin = compiler_origin();
    let identity = cut_identity(clock, &origin, accepted.unwrap_or(specification.operation_id()));
    let (policy, enrollment) = canonical_image_and_delivery(clock, selected);

    let (heads, host, prefix, nix, intake, root, create, storage) = bank::prepare_enrollment_subdivisions(
        enrollment,
        policy,
        bank::NativeLayoutDemand::new(1, 1),
    )
    .unwrap();
    let claims = bank::initial_enrollment_claims(enrollment, policy, &heads);
    let enrollment_transaction = bank::EnrollmentMutation::new((
        &[31; 16], &heads, &claims, &host, &prefix, &nix, &intake, &root, &create, &storage,
    ))
    .transaction()
    .unwrap();
    journal = seed(&directory, journal, &enrollment_transaction).0;
    let q = intake.unwrap();
    let q_settle = AccountTransition::settle(heads[1], q, true).unwrap();
    journal = seed(&directory, journal, &q_settle.transaction().unwrap()).0;

    let project = bank::project_child(
        enrollment,
        heads[0],
        identity.project().into_bytes(),
        [32; 32],
        ResourceVector::new([1 << 40; ResourceDimension::COUNT]),
    )
    .unwrap();
    let cut = ClaimCut::Operation {
        original_wall_seconds: clock.wall_seconds(),
        original_boottime_nanoseconds: clock.boottime_nanoseconds(),
        deadline_boottime_nanoseconds: clock.boottime_nanoseconds() + 60_000_000_000,
    };
    let grant_claim = bank::project_grant_claim(
        enrollment,
        [33; 16],
        heads[0].native_fields().id,
        project.native_fields().id,
        [34; 32],
        identity.project().into_bytes(),
        [32; 32],
        cut,
        [35; 32],
        project.finite_ceilings().unwrap(),
    );
    let grant = AccountTransition::grant(heads[0], project, grant_claim, clock).unwrap();
    journal = seed(&directory, journal, &grant.transaction().unwrap()).0;

    let names = journal.protected_writer_physical_names_v1().unwrap();
    let preparation_claim = bank::project_preparation_claim(
        enrollment,
        identity.operation().into_bytes(),
        project.native_fields().id,
        [34; 32],
        identity.project().into_bytes(),
        [32; 32],
        cut,
        [35; 32],
        ResourceVector::new([1 << 32; ResourceDimension::COUNT]),
    );
    let preparation = bank::PreparationBinding::from_parts((
        preparation_claim,
        identity.nonce(),
        names,
        names,
        1,
        *identity.gen1_floor().as_bytes(),
        [36; 32],
        [37; 32],
    ));
    let mut reservation = AccountTransition::reserve(project, preparation_claim).unwrap();
    reservation.preparation = Some(preparation);
    journal = seed(&directory, journal, &reservation.transaction().unwrap()).0;

    let before = reservation.after;
    let after = before.with_generation(before.native_fields().generation + 1);
    let amount = ResourceVector::new([4096; ResourceDimension::COUNT]);
    let retained_use = ResourceVector::new([2048; ResourceDimension::COUNT]);
    let residual = preparation_claim.with_amount(
        preparation_claim
            .native_fields()
            .amount
            .checked_sub(amount)
            .unwrap(),
    );
    let child = bank::sandbox_child(
        before,
        identity.sandbox().into_bytes(),
        amount,
        retained_use,
    )
    .unwrap();
    let inclusive = bank::inclusive_claim_for_cut(
        preparation_claim,
        &identity,
        identity.sandbox().into_bytes(),
        amount,
    );
    let use_claim = bank::retained_use_claim_for_cut(
        inclusive,
        &identity,
        identity.sandbox().into_bytes(),
        retained_use,
    );
    let input_origin = origin.to_record_bytes().unwrap();
    let association = InputAssociation::from_parts((
        *origin.normalized_input().as_bytes(),
        Sha256::digest(&input_origin).into(),
        input_origin.len() as u64,
        ResourceVector::new([1 << 20; ResourceDimension::COUNT]),
        q.native_fields().id,
        27,
    ));
    let binding = bank::CoissuanceBinding::from_parts((
        preparation,
        inclusive,
        use_claim,
        *specification.descriptor().digest().as_bytes(),
        specification.descriptor().encoded_size(),
        *specification.record_digest().as_bytes(),
        specification.operation_id().into_bytes(),
        *specification.request_digest().as_bytes(),
        *origin.candidate().as_bytes(),
        *identity.binding().as_bytes(),
        Some(association),
    ));
    let bank_members = CoissuanceMutation::new((&before, &after, &residual, &child, &binding))
        .records()
        .unwrap();

    let held = hold_bytes(&identity, true);
    let released = hold_bytes(&identity, false);
    let mut pairs = std::array::from_fn(|index| ObjectDigest::from_bytes([40 + index as u8; 32]));
    pairs[0] = ObjectDigest::from_bytes(Sha256::digest(&held).into());
    pairs[1] = ObjectDigest::from_bytes(Sha256::digest(&released).into());
    let (decision, events) = q04_controller_capacity_events_v1(&identity, pairs, 1, 1).unwrap();
    let consumed =
        crate::policy_compiler::create_q04::root_consumed_gate_v1(&identity, &decision).unwrap();
    let released_gate = consumed.next_status_recipe(events.release_ack).unwrap();
    let settled_gate = released_gate
        .next_status_recipe(events.settlement_ack)
        .unwrap();
    let cleared_gate = settled_gate
        .next_status_recipe(events.clearance_ack)
        .unwrap();
    let gates = [consumed, released_gate, settled_gate, cleared_gate];
    let effect = applying_effect();

    let mut phases: Vec<Q04PhaseRecordV1> = Vec::new();
    let mut native = std::array::from_fn(|_| None);
    let mut posts = std::array::from_fn(|_| None);
    let mut transactions = Vec::new();
    for index in 0..8 {
        let number = index as u8 + 1;
        let phase = controller_phase_recipe_v1(&identity, number, phases.last(), &events).unwrap();
        let mut key = crate::policy_compiler::create_q04::CONTROLLER_PHASE_PREFIX.to_vec();
        key.push(number);
        let mut records = if index == 0 {
            vec![
                JournalRecord::put(
                    RecordNamespace::ControllerPolicyHold,
                    HOLD_KEY.to_vec(),
                    held.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::ControllerPolicyHold,
                    crate::policy_compiler::create_q04::CONTROLLER_IDENTITY_KEY.to_vec(),
                    identity.bytes().to_vec(),
                ),
            ]
        } else {
            Vec::new()
        };
        if number == 5 {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                HOLD_KEY.to_vec(),
                released.clone(),
            ));
        }
        records.push(JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            key,
            phase.bytes().to_vec(),
        ));
        let gate_index = match number {
            2 => Some(0),
            5 => Some(1),
            7 => Some(2),
            8 => Some(3),
            _ => None,
        };
        if let Some(gate_index) = gate_index {
            records.push(JournalRecord::put(
                RecordNamespace::Effect,
                effect_key(identity.operation(), 0).to_vec(),
                encode_q04_effect(&effect, &gates[gate_index]).unwrap(),
            ));
        }
        if index == 0 {
            records.extend(bank_members.clone());
            records.push(JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                bank::CONTROLLER_INPUT_ORIGIN_KEY.to_vec(),
                input_origin.clone(),
            ));
        }
        let transaction = JournalTransaction::new(phase.native_transaction_id(), records).unwrap();
        let (next, result) = seed(&directory, journal, &transaction);
        journal = next;
        native[index] = Some(result.map_err(Into::into));
        if index < 7 {
            posts[index] = Some(journal.validate_held_protected_names().map_err(Into::into));
        }
        phases.push(phase);
        transactions.push(transaction);
    }

    // This private literal represents fixture DATA, not genuine installed
    // Root/PID1 custody. No production constructor or visibility is widened.
    let original = Q04ResourceTransferV1 {
        before,
        after,
        residual,
        child,
        binding,
        original_clock: clock,
        crossing: OnceCell::new(),
        last_clock: OnceCell::new(),
        transaction: OnceCell::new(),
        specification,
        input_origin,
    };
    original.crossing.set(Ok(clock)).unwrap();
    original.last_clock.set(Ok(clock)).unwrap();
    original.retain_transaction(&transactions[0]).unwrap();
    original.require_readback(&journal).unwrap();

    let before = bank::find_head(
        journal.controller_resource_state_v1().unwrap(),
        use_claim.native_fields().account,
    )
    .unwrap();
    let mut terminal = AccountTransition::settle(before, use_claim, true).unwrap();
    terminal.original_clock = Some(clock);
    let origins = std::array::from_fn(|index| {
        let result = native[index].as_ref().unwrap().as_ref().unwrap();
        (
            *transactions[index].id(),
            bank::transaction_digest(&transactions[index]).unwrap(),
            result.commit_sequence,
            result.durable_bytes,
        )
    });
    let prior_end = native[7].as_ref().unwrap().as_ref().unwrap().durable_bytes;
    terminal.terminal = Some(bank::TerminalBinding::from_parts((
        true,
        preparation_claim.native_fields().id,
        binding.commitment().unwrap(),
        terminal.transaction_id,
        journal.protected_writer_physical_names_v1().unwrap(),
        journal.snapshot_sequence(),
        prior_end,
        [80; 32],
        origins,
    )));
    Fixture {
        directory,
        journal,
        original,
        native,
        posts,
        terminal,
    }
}

#[test]
fn seeded_terminal_crosses_both_guards_and_replays_exact_native_origins() {
    let Fixture {
        directory,
        mut journal,
        original,
        native,
        posts,
        terminal,
    } = fixture();
    let state = journal.controller_resource_state_v1().unwrap();
    let project_before = bank::find_head(state, original.after.native_fields().id).unwrap();
    let child_before = bank::find_head(state, original.child.native_fields().id).unwrap();
    let use_before = original.binding.native_fields().use_claim;
    let before = journal.snapshot_sequence();
    let mut returned = ReturnedAppend::new();
    returned.append_q04_terminal_into(
        &mut journal,
        Ok(terminal),
        Q04TerminalOriginalsV1 {
            original: &original,
            native: &native,
            posts: &posts,
        },
    );

    assert!(returned.failure().is_none(), "{:?}", returned.failure());
    assert!(returned.native.as_ref().is_some_and(Result::is_ok));
    returned.require_committed().unwrap();
    assert_eq!(journal.snapshot_sequence(), before + 5);
    journal.require_controller_resource_history_v1().unwrap();
    drop(journal);
    let journal = reopen(&directory);
    journal.require_controller_resource_history_v1().unwrap();
    let state = journal.controller_resource_state_v1().unwrap();
    let child_after = bank::find_head(state, original.child.native_fields().id).unwrap();
    let use_after =
        bank::Claim::decode(bank::claim_bytes(state, use_before.native_fields().id).unwrap())
            .unwrap();

    assert_eq!(
        bank::find_head(state, project_before.native_fields().id).unwrap(),
        project_before
    );
    assert_eq!(
        child_after.finite_ceilings().unwrap(),
        child_before.finite_ceilings().unwrap()
    );
    assert_eq!(
        child_after.native_fields().generation,
        child_before.native_fields().generation + 1
    );
    assert_eq!(use_before.native_fields().state, bank::ClaimState::Reserved);
    assert_eq!(use_after.native_fields().state, bank::ClaimState::Committed);
    assert_eq!(
        use_after.native_fields().amount,
        use_before.native_fields().amount
    );

    let original_claim = original
        .binding
        .native_fields()
        .original_claim
        .native_fields()
        .id;
    assert!(
        bank::terminal_bytes(
            journal.controller_resource_state_v1().unwrap(),
            original_claim
        )
        .is_some()
    );
}

#[test]
fn terminal_data_without_retained_original_cannot_select_the_exception() {
    let Fixture {
        directory,
        mut journal,
        terminal,
        ..
    } = fixture();
    let before = journal.snapshot_sequence();
    let before_bytes = fs::read(directory.path().join("controller.journal")).unwrap();
    let mut returned = ReturnedAppend::new();
    returned.append_into(&mut journal, Ok(terminal));

    assert!(returned.native.as_ref().is_some_and(Result::is_err));
    assert_eq!(journal.snapshot_sequence(), before);
    assert_eq!(
        fs::read(directory.path().join("controller.journal")).unwrap(),
        before_bytes
    );
}

#[test]
fn a_failed_retained_post_preserves_the_failure_and_prevents_terminal_growth() {
    let Fixture {
        directory,
        mut journal,
        original,
        native,
        mut posts,
        terminal,
    } = fixture();
    posts[3] = Some(Err(CreateQ04ErrorV1::Io(
        std::io::Error::from_raw_os_error(13),
    )));
    let before = journal.snapshot_sequence();
    let before_bytes = fs::read(directory.path().join("controller.journal")).unwrap();
    let mut returned = ReturnedAppend::new();
    returned.append_q04_terminal_into(
        &mut journal,
        Ok(terminal),
        Q04TerminalOriginalsV1 {
            original: &original,
            native: &native,
            posts: &posts,
        },
    );

    assert!(returned.native.as_ref().is_some_and(Result::is_err));
    assert!(
        matches!(posts[3], Some(Err(CreateQ04ErrorV1::Io(ref error)))
        if error.raw_os_error() == Some(13))
    );
    assert_eq!(journal.snapshot_sequence(), before);
    assert_eq!(
        fs::read(directory.path().join("controller.journal")).unwrap(),
        before_bytes
    );
}

#[test]
fn changed_returned_native_position_refuses_the_typed_terminal() {
    let Fixture {
        directory,
        mut journal,
        original,
        mut native,
        posts,
        terminal,
    } = fixture();
    let position = native[2].as_ref().unwrap().as_ref().unwrap();
    native[2] = Some(Ok(CommitResult {
        commit_sequence: position.commit_sequence,
        durable_bytes: position.durable_bytes + 1,
    }));
    let before = journal.snapshot_sequence();
    let before_bytes = fs::read(directory.path().join("controller.journal")).unwrap();
    let mut returned = ReturnedAppend::new();
    returned.append_q04_terminal_into(
        &mut journal,
        Ok(terminal),
        Q04TerminalOriginalsV1 {
            original: &original,
            native: &native,
            posts: &posts,
        },
    );

    assert!(returned.native.as_ref().is_some_and(Result::is_err));
    assert_eq!(journal.snapshot_sequence(), before);
    assert_eq!(
        fs::read(directory.path().join("controller.journal")).unwrap(),
        before_bytes
    );
}

#[test]
fn extra_terminal_member_is_rejected_before_crossing_or_native_growth() {
    let Fixture {
        directory,
        mut journal,
        original,
        native,
        posts,
        terminal,
    } = fixture();
    let expected = terminal.transaction().unwrap();
    let mut records = expected.records().to_vec();
    records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        b"extra".to_vec(),
        vec![1],
    ));
    let transaction = JournalTransaction::new(*expected.id(), records).unwrap();
    let crossing = OnceCell::new();
    let loan = super::super::Q04TerminalBankAppendV1::new(
        &terminal,
        Q04TerminalOriginalsV1 {
            original: &original,
            native: &native,
            posts: &posts,
        },
    );
    let transition = Transition {
        original: TransitionOriginal::Q04Terminal(loan),
        crossing: Some(NativeCrossing {
            original: original.original_clock,
            deadline: original.original_clock.boottime_nanoseconds() + 60_000_000_000,
            result: &crossing,
        }),
    };
    let before = journal.snapshot_sequence();
    let before_bytes = fs::read(directory.path().join("controller.journal")).unwrap();

    assert!(
        transition
            .require_current(
                journal.controller_resource_state_v1().unwrap(),
                &transaction,
            )
            .is_err()
    );
    assert!(
        journal
            .commit_controller_resource_transition_v1(&transaction, &transition)
            .is_err()
    );
    assert!(crossing.get().is_none());
    assert_eq!(journal.snapshot_sequence(), before);
    assert_eq!(
        fs::read(directory.path().join("controller.journal")).unwrap(),
        before_bytes
    );
}

#[test]
fn changed_terminal_bank_member_is_rejected_before_crossing_or_native_growth() {
    let Fixture {
        directory,
        mut journal,
        original,
        native,
        posts,
        terminal,
    } = fixture();
    let expected = terminal.transaction().unwrap();
    let mut records = expected.records().to_vec();
    let member = &records[0];
    let mut value = member.value().unwrap().to_vec();
    let last = value.len() - 1;
    value[last] ^= 1;
    records[0] = JournalRecord::put(member.namespace(), member.key().to_vec(), value);
    let transaction = JournalTransaction::new(*expected.id(), records).unwrap();
    let crossing = OnceCell::new();
    let loan = super::super::Q04TerminalBankAppendV1::new(
        &terminal,
        Q04TerminalOriginalsV1 {
            original: &original,
            native: &native,
            posts: &posts,
        },
    );
    let transition = Transition {
        original: TransitionOriginal::Q04Terminal(loan),
        crossing: Some(NativeCrossing {
            original: original.original_clock,
            deadline: original.original_clock.boottime_nanoseconds() + 60_000_000_000,
            result: &crossing,
        }),
    };
    let before = journal.snapshot_sequence();
    let before_bytes = fs::read(directory.path().join("controller.journal")).unwrap();

    assert!(
        transition
            .require_current(
                journal.controller_resource_state_v1().unwrap(),
                &transaction,
            )
            .is_err()
    );
    assert!(
        journal
            .commit_controller_resource_transition_v1(&transaction, &transition)
            .is_err()
    );
    assert!(crossing.get().is_none());
    assert_eq!(journal.snapshot_sequence(), before);
    assert_eq!(
        fs::read(directory.path().join("controller.journal")).unwrap(),
        before_bytes
    );
}


#[test]
fn canonical_j_data_cannot_select_an_ordinary_native_transition() {
    let Fixture {
        directory, mut journal, original, native, posts, terminal,
    } = fixture_for_image(FixtureImage::CreateIntake);
    let mut returned = ReturnedAppend::new();
    returned.append_q04_terminal_into(&mut journal, Ok(terminal), Q04TerminalOriginalsV1 {
        original: &original, native: &native, posts: &posts,
    });
    returned.require_committed().unwrap();
    let identity = original.binding.native_fields().original_claim.native_fields().enrollment;
    let id = identity.account_id(b"controller-create-continuation-intake-v1");
    let state = journal.controller_resource_state_v1().unwrap();
    let claim = bank::Claim::decode(bank::claim_bytes(state, id).unwrap()).unwrap();
    let before = bank::find_head(state, claim.native_fields().account).unwrap();
    let mut account = AccountTransition::settle(before, claim, true).unwrap();
    account.original_clock = Some(original.original_clock);
    let transaction = account.transaction().unwrap();
    let crossing = OnceCell::new();
    let transition = Transition {
        original: TransitionOriginal::Account(&account),
        crossing: Some(NativeCrossing {
            original: original.original_clock,
            deadline: original.original_clock.boottime_nanoseconds(),
            result: &crossing,
        }),
    };
    let next = journal.snapshot_sequence();
    let bytes = fs::read(directory.path().join("controller.journal")).unwrap();

    assert_eq!(transaction.records().len(), 2);
    account.require_current(journal.controller_resource_state_v1().unwrap(), &transaction).unwrap();
    assert!(transition.require_current(journal.controller_resource_state_v1().unwrap(), &transaction).is_err());
    assert!(journal.commit_controller_resource_transition_v1(&transaction, &transition).is_err());
    assert!(crossing.get().is_none());
    assert_eq!(journal.snapshot_sequence(), next);
    assert_eq!(fs::read(directory.path().join("controller.journal")).unwrap(), bytes);
}

#[test]
fn create_preappend_position_requires_the_actual_terminal_to_remain_last() {
    let Fixture {
        directory, mut journal, original, native, posts, terminal,
    } = fixture_for_image(FixtureImage::CreateIntake);
    let mut returned = ReturnedAppend::new();
    returned.append_q04_terminal_into(&mut journal, Ok(terminal), Q04TerminalOriginalsV1 {
        original: &original, native: &native, posts: &posts,
    });
    returned.require_committed().unwrap();
    let names = journal.protected_writer_physical_names_v1().unwrap();
    let terminal = returned.transaction.as_ref().unwrap().as_ref().unwrap();
    let native = returned.native.as_ref().unwrap().as_ref().unwrap();

    journal.require_create_intake_preappend_position_v1(names, terminal, native).unwrap();
    assert!(journal.require_create_intake_preappend_position_v1(names, terminal, &CommitResult {
        commit_sequence: native.commit_sequence,
        durable_bytes: native.durable_bytes + 1,
    }).is_err());
    assert!(journal.require_create_intake_preappend_position_v1(names, terminal, &CommitResult {
        commit_sequence: native.commit_sequence + 1,
        durable_bytes: native.durable_bytes,
    }).is_err());

    let intervening = JournalTransaction::new([99; 16], vec![JournalRecord::put(
        RecordNamespace::DesiredState, b"unrelated-native-fixture".to_vec(), vec![1],
    )]).unwrap();
    let (journal, result) = seed(&directory, journal, &intervening);
    result.unwrap();

    assert!(journal.require_create_intake_preappend_position_v1(names, terminal, native).is_err());
}

#[test]
fn create_lane_keeps_accepted_operation_distinct_from_spec_publication() {
    let accepted = aos_sandbox_core::OperationId::from_bytes([251; 16]);
    let Fixture {
        directory: _directory, mut journal, original, native, posts, terminal,
    } = fixture_with_create_operation(FixtureImage::CreateIntake, Some(accepted));
    let publication = original.specification.operation_id();
    assert_ne!(accepted, publication);
    assert_eq!(original.binding.native_fields().original_claim.operation(),
        accepted.into_bytes());
    original.require_readback(&journal).unwrap();
    let lane = original.create_continuation_lane(accepted.into_bytes()).unwrap();

    assert_ne!(lane, [0; 16]);
    assert_eq!(original.create_continuation_lane(accepted.into_bytes()).unwrap(), lane);
    assert!(original.create_continuation_lane(publication.into_bytes()).is_err());

    let mut returned = ReturnedAppend::new();
    returned.append_q04_terminal_into(&mut journal, Ok(terminal), Q04TerminalOriginalsV1 {
        original: &original, native: &native, posts: &posts,
    });
    returned.require_committed().unwrap();
    journal.require_controller_resource_history_v1().unwrap();
    original.require_readback(&journal).unwrap();

    assert_eq!(original.specification.operation_id(), publication);
    assert_eq!(original.create_continuation_lane(accepted.into_bytes()).unwrap(), lane);
    assert!(original.create_continuation_lane(publication.into_bytes()).is_err());
}

#[test]
fn cleared_q04_history_never_allows_ordinary_controller_or_source_history_writes() {
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
    };

    let Fixture { directory, mut journal, original, native, posts, terminal } =
        fixture_for_image(FixtureImage::CreateIntake);
    let mut returned = ReturnedAppend::new();
    returned.append_q04_terminal_into(&mut journal, Ok(terminal), Q04TerminalOriginalsV1 {
        original: &original, native: &native, posts: &posts,
    });
    returned.require_committed().unwrap();
    let next = journal.snapshot_sequence();
    let bytes = fs::read(directory.path().join("controller.journal")).unwrap();

    // These are canonical envelope DATA, not genuine post-J role loans. Both
    // selectors must remain blocked at the ordinary Native boundary even on
    // the real cleared eight-phase framing seeded by the existing fixture.
    for owner in [OwnerV1::Controller, OwnerV1::Source] {
        let key = KeyV1::new([91; 16], owner, 1).unwrap();
        let latest = KeyV1::new([91; 16], owner, 0).unwrap();
        let phase = PhaseV1::new(owner, 1).unwrap();
        let mut record = vec![0; 140 + 1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor: [0; 32], correlation: [92; 32],
        }, &[1], &mut record).unwrap();
        let transaction = JournalTransaction::new([93; 16], vec![
            JournalRecord::put(RecordNamespace::CreateStorageHistory, key.encode().to_vec(), record),
            JournalRecord::put(RecordNamespace::CreateStorageHistory, latest.encode().to_vec(),
                LatestHeadV1::new(1, checksum).unwrap().encode().to_vec()),
        ]).unwrap();

        assert!(matches!(journal.preflight_transactions(std::slice::from_ref(&transaction)),
            Err(JournalError::ProtectedBoundary)));
        assert!(matches!(journal.commit(&transaction), Err(JournalError::ProtectedBoundary)));
        assert_eq!(journal.snapshot_sequence(), next);
        assert_eq!(fs::read(directory.path().join("controller.journal")).unwrap(), bytes);
    }
}
