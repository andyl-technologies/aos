//! Synthetic held-owner exercise of the Root project admission terminal CAS.
//!
//! This fixture signs internally consistent Controller and Source claims, but
//! deliberately does not create production Source genesis or an antirollback
//! floor. Only the Root terminal transition and its exact cold replay are
//! qualified here; public Create remains closed.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, RevocationScopeId};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::lifecycle::protected_journal_join::source_domain_journal_limits;
use crate::policy_compiler::controller_project_admission_readback::sign_synthetic_controller_project_admission_v1;
use crate::policy_compiler::source_project_admission_readback::sign_source_project_admission_fields_v1;
use crate::policy_compiler::{
    encode_controller_hold_signer_credential_v1, encode_source_hold_readback_signer_credential_v1,
};
use crate::publisher_policy::project_revocation_digest;

const PROJECT: ProjectId = ProjectId::from_bytes([1; 16]);
const OPERATION: OperationId = OperationId::from_bytes([3; 16]);
const SOURCE_COMMITMENT: ObjectDigest = ObjectDigest::from_bytes([4; 32]);
const PUBLISHER_DIGEST: ObjectDigest = ObjectDigest::from_bytes([5; 32]);
const CACHE_DOMAIN_HEAD: ObjectDigest = ObjectDigest::from_bytes([6; 32]);
const ANCESTRY: ObjectDigest = ObjectDigest::from_bytes([7; 32]);
const REVOCATION_SCOPE: RevocationScopeId = RevocationScopeId::from_bytes([8; 16]);
const DEPLOYMENT_GENERATION: u64 = 2;
const PROJECT_GENERATION: u64 = 3;
const CONTROLLER_GENERATION: u64 = 4;
const SOURCE_GENERATION: u64 = 5;
const NOW: i64 = 20;

pub(crate) struct SignedHeads {
    pub(crate) deployment: Vec<u8>,
    pub(crate) deployment_inputs: [Vec<u8>; 4],
    pub(crate) project: Vec<u8>,
    pub(crate) project_input: Vec<u8>,
}

impl SignedHeads {
    pub(crate) fn deployment_inputs(&self) -> PolicyDeploymentInputsV1<'_> {
        PolicyDeploymentInputsV1 {
            node: &self.deployment_inputs[0],
            site: &self.deployment_inputs[1],
            backend: &self.deployment_inputs[2],
            catalogs: &self.deployment_inputs[3],
        }
    }
}

fn signed_heads(deployment_key: &SigningKey, project_key: &SigningKey) -> SignedHeads {
    signed_heads_for_project(deployment_key, project_key, PROJECT)
}

pub(crate) fn signed_heads_for_project(
    deployment_key: &SigningKey,
    project_key: &SigningKey,
    project: ProjectId,
) -> SignedHeads {
    let deployment_inputs = ["AOSPNI01", "AOSPSI01", "AOSPBI01", "AOSPCI01"].map(|magic| {
        serde_json::to_vec(&serde_json::json!({
            "generation": 1,
            "input": {},
            "magic": magic,
        }))
        .expect("canonical deployment fixture")
    });
    let mut deployment = b"AOSPDH01".to_vec();
    deployment.extend_from_slice(&1_u64.to_be_bytes());
    deployment.extend_from_slice(&10_i64.to_be_bytes());
    deployment.extend_from_slice(&30_i64.to_be_bytes());
    for input in &deployment_inputs {
        deployment.extend_from_slice(&Sha256::digest(input));
    }
    let mut preimage = b"aos.sandbox.policy-deployment-head.v1\0".to_vec();
    preimage.extend_from_slice(&deployment);
    deployment.extend_from_slice(&deployment_key.sign(&preimage).to_bytes());

    let project_input = serde_json::to_vec(&serde_json::json!({
        "generation": 1,
        "input": {
            "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
            "advisory_actions": [],
            "cache_domain": "project",
            "grants": [],
            "namespace_rules": [],
            "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
            "revocation": {"grace_nanos": 0, "mode": "deny-new"},
        },
        "magic": "AOSPPL02",
        "project_id": project.to_string(),
    }))
    .expect("canonical project fixture");
    let revocation = project_revocation_digest(project, REVOCATION_SCOPE, 1);
    let mut packet = b"AOSPPH02".to_vec();
    packet.extend_from_slice(project.as_bytes());
    packet.extend_from_slice(&1_u64.to_be_bytes());
    packet.extend_from_slice(&10_i64.to_be_bytes());
    packet.extend_from_slice(&30_i64.to_be_bytes());
    packet.extend_from_slice(&1_u64.to_be_bytes());
    packet.extend_from_slice(PUBLISHER_DIGEST.as_bytes());
    packet.extend_from_slice(&Sha256::digest(&project_input));
    packet.extend_from_slice(ANCESTRY.as_bytes());
    packet.extend_from_slice(&Sha256::digest(&deployment));
    packet.extend_from_slice(CACHE_DOMAIN_HEAD.as_bytes());
    packet.extend_from_slice(revocation.as_bytes());
    packet.extend_from_slice(&DEPLOYMENT_GENERATION.to_be_bytes());
    packet.extend_from_slice(&PROJECT_GENERATION.to_be_bytes());
    let mut preimage = b"aos.sandbox.policy-project-head.v2\0".to_vec();
    preimage.extend_from_slice(&packet);
    packet.extend_from_slice(&project_key.sign(&preimage).to_bytes());

    SignedHeads {
        deployment,
        deployment_inputs,
        project: packet,
        project_input,
    }
}

fn seed_root(
    root: &mut Journal,
    heads: &SignedHeads,
    deployment_key: &SigningKey,
    project_key: &SigningKey,
    controller_pin: &[u8],
    source_pin: &[u8],
) {
    let pins = encode_policy_signer_pins_v1(
        DEPLOYMENT_GENERATION,
        &deployment_key.verifying_key(),
        PROJECT_GENERATION,
        &project_key.verifying_key(),
    )
    .expect("exact role pins");
    root.commit(
        &JournalTransaction::new(
            [9; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    SIGNER_PINS_KEY.to_vec(),
                    pins.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    HEAD_KEY.to_vec(),
                    heads.deployment.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    CONTROLLER_HOLD_PIN_KEY.to_vec(),
                    controller_pin.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    SOURCE_HOLD_PIN_KEY.to_vec(),
                    source_pin.to_vec(),
                ),
            ],
        )
        .expect("Root credential transaction"),
    )
    .expect("Root credentials under protected writer");
}

#[allow(clippy::too_many_arguments)]
fn commit_from_signed_owner_rows(
    root: &mut Journal,
    stage: RootProjectAdmissionStageV1,
    controller_packet: &[u8],
    source_row: SourceProjectAdmissionChallengeV1,
    source_packet: &[u8],
    controller_pin: &[u8],
    source_pin: &[u8],
    heads: &SignedHeads,
    deployment_key: &SigningKey,
    project_key: &SigningKey,
) -> Result<RootProjectAdmissionOutcomeV1, PolicyDeploymentHeadErrorV1> {
    admit_root_project_source_from_owner_proofs_with_journal(
        ProjectAdmissionJournalSource::held(root),
        stage.record_digest(),
        controller_packet,
        &source_row.record_bytes(),
        source_packet,
        controller_pin,
        source_pin,
        811,
        &heads.project,
        &heads.project_input,
        &project_key.verifying_key(),
        PROJECT_GENERATION,
        &heads.deployment,
        &heads.deployment_inputs(),
        &deployment_key.verifying_key(),
        DEPLOYMENT_GENERATION,
        NOW,
    )
}

#[test]
fn held_synthetic_owners_commit_root_once_and_cold_replay_lost_reply() {
    exercise_held_synthetic_commit(false);
}

#[test]
fn held_synthetic_owners_preserve_history_suffix_after_commit_and_cold_replay() {
    exercise_held_synthetic_commit(true);
}

fn exercise_held_synthetic_commit(history_retirement: bool) {
    let source_dir = tempfile::tempdir().expect("Source directory");
    let root_dir = tempfile::tempdir().expect("Root directory");
    for directory in [source_dir.path(), root_dir.path()] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("protected owner directory");
    }
    let uid = fs::metadata(root_dir.path()).expect("Root owner").uid();
    let (mut source, _) = Journal::open_protected_at_uid(
        source_dir.path(),
        "source-domains-v1.journal",
        source_domain_journal_limits(),
        uid,
    )
    .expect("held Source writer");
    let (mut root, _) = Journal::open_protected_at_uid(
        root_dir.path(),
        "policy-authority-v1.journal",
        policy_authority_journal_limits(),
        uid,
    )
    .expect("held Root writer");

    let deployment_key = SigningKey::from_bytes(&[10; 32]);
    let project_key = SigningKey::from_bytes(&[11; 32]);
    let controller_key = SigningKey::from_bytes(&[12; 32]);
    let source_key = SigningKey::from_bytes(&[13; 32]);
    let heads = signed_heads(&deployment_key, &project_key);
    let controller_pin = encode_controller_hold_signer_credential_v1(
        CONTROLLER_GENERATION,
        &controller_key.verifying_key(),
    )
    .expect("Controller pin");
    let source_pin = encode_source_hold_readback_signer_credential_v1(
        SOURCE_GENERATION,
        &source_key.verifying_key(),
    )
    .expect("Source pin");
    seed_root(
        &mut root,
        &heads,
        &deployment_key,
        &project_key,
        &controller_pin,
        &source_pin,
    );
    let deployment = verify_policy_deployment_head_v1(
        &heads.deployment,
        &heads.deployment_inputs(),
        &deployment_key.verifying_key(),
        NOW,
    )
    .expect("signed deployment");
    let project = verify_signed_project_policy_source_v2(
        &heads.project,
        &heads.project_input,
        &project_key.verifying_key(),
        NOW,
    )
    .expect("signed synthetic project source");

    let client_nonce = project_admission_client_nonce_v1(OPERATION, SOURCE_COMMITMENT);
    let names = source
        .protected_writer_physical_names_v1()
        .expect("Source names");
    source
        .preflight_source_project_admission_capacity_v1(client_nonce, PROJECT, ANCESTRY, names)
        .expect("Source reserve/challenge/settlement headroom");
    let preview = source
        .preview_source_project_admission_reservation_v1(client_nonce, PROJECT, names)
        .expect("canonical prospective Source row");
    let prepare = if history_retirement {
        intent::prepare_test_exact_history_intent_with_journal
    } else {
        intent::prepare_test_exact_intent_with_journal
    };
    let intent = prepare(
        &mut root,
        preview,
        &heads.project,
        &heads.project_input,
        &heads.deployment,
    )
    .expect("Root capacity intent precedes Source reservation");
    let reservation = source
        .record_source_project_admission_reservation_v1(client_nonce, PROJECT, names)
        .expect("Source durable reservation");
    assert_eq!(reservation, preview);

    // The typed Root stage is synthetic, but its row and transaction use the
    // production codecs. No structural Tree is promoted to current ancestry.
    let mut stage = RootProjectAdmissionStageV1 {
        client_nonce,
        root_nonce: [14; 16],
        cut: zero_digest(),
        project: PROJECT,
        packet_digest: project.head().packet_digest(),
        input_digest: project.head().input_digest(),
        deployment_digest: deployment.packet_digest(),
        prior_packet_digest: zero_digest(),
        prior_input_digest: zero_digest(),
        source_reservation_digest: reservation.record_digest(),
        issued_at: 10,
        expires_at: 30,
    };
    stage.cut = stage.expected_cut();
    root.claim_protected_authority(RecordNamespace::DesiredState)
        .expect("Root stage custody")
        .commit(&stage_transaction(stage).expect("canonical stage transaction"))
        .expect("durable Root stage");
    let row = source
        .record_source_project_admission_challenge_v1(
            PROJECT,
            ANCESTRY,
            stage.root_nonce,
            stage.cut,
            stage.record_digest(),
            names,
        )
        .expect("synthetic ancestry-bound Source challenge");
    let source_packet =
        sign_source_project_admission_fields_v1(row, reservation, SOURCE_GENERATION, &source_key)
            .expect("signed Source challenge");
    let challenge = ControllerProjectAdmissionChallengeV1::new(stage.root_nonce, stage.cut)
        .expect("Root challenge");
    let controller_packet = sign_synthetic_controller_project_admission_v1(
        challenge,
        PROJECT,
        OPERATION,
        SOURCE_COMMITMENT,
        PUBLISHER_DIGEST,
        CACHE_DOMAIN_HEAD,
        REVOCATION_SCOPE,
        project_revocation_digest(PROJECT, REVOCATION_SCOPE, 1),
        CONTROLLER_GENERATION,
        &controller_key,
    )
    .expect("synthetic signed Controller acceptance");

    let changed_publisher = sign_synthetic_controller_project_admission_v1(
        challenge,
        PROJECT,
        OPERATION,
        SOURCE_COMMITMENT,
        ObjectDigest::from_bytes([19; 32]),
        CACHE_DOMAIN_HEAD,
        REVOCATION_SCOPE,
        project_revocation_digest(PROJECT, REVOCATION_SCOPE, 1),
        CONTROLLER_GENERATION,
        &controller_key,
    )
    .expect("validly signed changed Controller claim");
    assert!(
        commit_from_signed_owner_rows(
            &mut root,
            stage,
            &changed_publisher,
            row,
            &source_packet,
            &controller_pin,
            &source_pin,
            &heads,
            &deployment_key,
            &project_key,
        )
        .is_err(),
        "a signed but changed publisher claim cannot enter the Root CAS"
    );
    assert!(intent::require_intent_capacity(&mut root, intent).is_ok());
    assert_eq!(
        root.claim_protected_authority(RecordNamespace::DesiredState)
            .expect("Root rejection readback")
            .get(HEAD_KEY_V2)
            .expect("unchanged V2 head"),
        None
    );

    let committed = commit_from_signed_owner_rows(
        &mut root,
        stage,
        &controller_packet,
        row,
        &source_packet,
        &controller_pin,
        &source_pin,
        &heads,
        &deployment_key,
        &project_key,
    )
    .expect("Root terminal CAS from exact signed owner rows");
    assert_eq!(
        committed.kind(),
        RootProjectAdmissionOutcomeKindV1::Committed
    );
    assert!(intent::require_intent_capacity(&mut root, intent).is_err());
    let decided = intent::current_intent(&mut root).unwrap().unwrap();
    let suffix = root
        .lookup_global_capacity_reservation_v1(decided.capacity_id())
        .unwrap();
    assert_eq!(suffix.is_some(), history_retirement);
    if history_retirement {
        assert_eq!(suffix.unwrap().request().future_transactions, 1);
        assert_eq!(decided.decision(), committed.record_digest());
    }
    assert_eq!(
        root.claim_protected_authority(RecordNamespace::DesiredState)
            .expect("Root readback custody")
            .get(HEAD_KEY_V2)
            .expect("V2 project head"),
        Some(heads.project.as_slice())
    );
    assert_eq!(
        source
            .source_project_admission_status_v1()
            .expect("held Source challenge"),
        Some((row, false)),
        "Root commit does not retire Source without exact peer-checked outcome"
    );
    drop(root);

    let (mut cold, _) = Journal::open_protected_at_uid(
        root_dir.path(),
        "policy-authority-v1.journal",
        policy_authority_journal_limits(),
        uid,
    )
    .expect("cold Root replay after lost terminal reply");
    let before = cold
        .claim_protected_authority(RecordNamespace::DesiredState)
        .expect("cold Root custody")
        .snapshot()
        .expect("Root sequence")
        .sequence();
    assert_eq!(
        commit_from_signed_owner_rows(
            &mut cold,
            stage,
            &controller_packet,
            row,
            &source_packet,
            &controller_pin,
            &source_pin,
            &heads,
            &deployment_key,
            &project_key,
        )
        .expect("idempotent exact replay of lost Root reply"),
        committed
    );
    let authority = cold
        .claim_protected_authority(RecordNamespace::DesiredState)
        .expect("cold Root custody");
    assert_eq!(
        authority.snapshot().expect("Root sequence").sequence(),
        before,
        "Root lost-reply replay must not append"
    );
    assert_eq!(
        authority
            .get(&outcome_key(stage.record_digest()))
            .expect("typed outcome"),
        Some(committed.record_bytes().as_slice())
    );
    assert_eq!(
        authority.get(HEAD_KEY_V2).expect("project head"),
        Some(heads.project.as_slice())
    );
    assert_eq!(
        authority.get(INPUT_KEY_V2).expect("project input"),
        Some(heads.project_input.as_slice())
    );
    drop(authority);

    if history_retirement {
        source
            .settle_source_project_admission_challenge_v1(
                row,
                super::super::RootProjectAdmissionOutcomeProofV1::from_test_outcome(committed),
            )
            .expect("actual Source terminal after synthetic Controller acceptance");
        let source_terminal = super::super::source_project_admission_readback::sign_test_source_project_completed_terminal_readback_v1(
            &source, SOURCE_GENERATION, &source_key,
        ).unwrap();
        let claims = crate::reconciler::project_admission::AcceptedControllerProjectTerminalV1 {
            operation: OPERATION,
            sandbox: aos_sandbox_core::SandboxId::from_bytes(committed.sandbox()),
            project: PROJECT,
            source_commitment: SOURCE_COMMITMENT,
            admission_revision: ObjectDigest::from_bytes([90; 32]),
            admission_generation: 1,
            accepted_metadata: ObjectDigest::from_bytes([91; 32]),
            reservation,
            challenge: Some(row),
            root_terminal: committed.record_digest(),
            kind: history::RootProjectHistoryTerminalKindV1::Committed,
        };
        let controller_terminal = super::super::controller_project_terminal_readback::sign_synthetic_controller_project_terminal_v1(
            &claims, 811, 99, CONTROLLER_GENERATION, &controller_key,
        ).unwrap();
        let floor = history::retire_root_project_history_with_journal(
            &mut cold,
            &controller_terminal,
            &source_terminal,
            811,
        )
        .expect("exact protected committed history retirement");
        assert_eq!(
            floor.kind(),
            history::RootProjectHistoryTerminalKindV1::Committed
        );
        assert!(cold.get(RecordNamespace::DesiredState, STAGE_KEY).is_none());
        assert!(
            cold.get(
                RecordNamespace::DesiredState,
                &outcome_key(stage.record_digest())
            )
            .is_none()
        );
        assert!(
            cold.records(RecordNamespace::GlobalCapacityReservation)
                .next()
                .is_none()
        );
        assert_eq!(
            cold.get(RecordNamespace::DesiredState, HEAD_KEY_V2),
            Some(heads.project.as_slice())
        );
        let cut = cold.snapshot_sequence();
        assert_eq!(
            history::retire_root_project_history_with_journal(
                &mut cold,
                &controller_terminal,
                &source_terminal,
                811,
            )
            .unwrap(),
            floor
        );
        assert_eq!(cold.snapshot_sequence(), cut);
    }
}
