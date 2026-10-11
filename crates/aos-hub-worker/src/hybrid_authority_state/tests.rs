//! Authority protocol and durable control ordering regressions.

#[path = "tests/denial.rs"]
mod denial;

use super::*;
use aos_hub_core::storage_authority::control::{sign_authority_message, verify_authority_message};
use aos_hub_core::storage_authority::*;
use aos_hub_core::storage_work::StorageWorkKey;

const NAMESPACE: &str = "account/actual-object-namespace";
const EXECUTOR: &str = "approved-worker-executor";
const DEPLOYMENT: &str = "paired-native-deployment";

#[derive(Default)]
struct MemoryJournal {
    values: BTreeMap<String, Value>,
    fail_commit: bool,
    commits: usize,
}

impl AuthorityJournal for MemoryJournal {
    async fn get(&mut self, key: &str) -> Result<Option<Value>> {
        Ok(self.values.get(key).cloned())
    }

    async fn put_atomic(&mut self, values: BTreeMap<String, Value>) -> Result<()> {
        ensure!(!self.fail_commit, "injected atomic persistence failure");
        self.values.extend(values);
        self.commits += 1;
        Ok(())
    }
}

fn publication() -> StorageAuthorityPublication {
    let authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let authority = CreatePhysicalStorageAuthority {
        authority_id: authority_id.clone(),
        guard_namespace_id: NAMESPACE.into(),
        physical_resource_evidence_digest: "a".repeat(64),
        qualification_digest: "b".repeat(64),
        qualified_managed_prefix: "managed".into(),
    };
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("storage.example.test".into()),
            port: 443,
            bucket: "bucket-one".into(),
        },
        equivalence_evidence_digest: "c".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: 1,
        binding_stable_id: "binding-one".into(),
        binding_resource_version: 1,
        binding_write_revision: 1,
        binding_prefix: "managed".into(),
    };
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "attestation-one".into(),
        authority_id: authority_id.clone(),
        managed_prefix: "managed".into(),
        qualification_digest: authority.qualification_digest.clone(),
        provider_policy_evidence_digest: "d".repeat(64),
        executor_identity: EXECUTOR.into(),
        credentials: vec![StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: "write".into(),
            generation: 1,
            secret_version_ref: "provider-secret/version-one".into(),
            credential_fingerprint: "e".repeat(64),
        }],
        valid_until: 1000,
    };
    let admission = SetStorageAuthorityAdmission {
        authority_id,
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: NAMESPACE.into(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id.clone()),
        association_ids: vec![association.association_id.clone()],
    };
    let digest = digest(&admission).unwrap();
    StorageAuthorityPublication {
        authority,
        aliases: vec![alias],
        associations: vec![association],
        attestation: Some(attestation),
        admission,
        generation: 1,
        digest,
    }
}

#[tokio::test]
async fn exact_attestation_can_admit_only_a_subset_of_its_associations() {
    let mut publication = publication();
    let mut auxiliary = publication.associations[0].clone();
    auxiliary.association_id = "association-two".into();
    auxiliary.binding_id = 2;
    auxiliary.binding_stable_id = "binding-two".into();
    publication.associations.push(auxiliary.clone());

    let mut reader = publication.attestation.as_ref().unwrap().credentials[0].clone();
    reader.association_id = auxiliary.association_id.clone();
    reader.purpose = "read".into();
    publication
        .attestation
        .as_mut()
        .unwrap()
        .credentials
        .push(reader);
    let frozen_attestation = publication.attestation.clone();

    publication.validate(NAMESPACE, EXECUTOR).unwrap();
    let mut journal = MemoryJournal::default();
    let reply = publish(&mut journal, publication.clone(), 100).await;
    assert_eq!(reply.watermark.unwrap().generation, 1);
    assert_eq!(publication.attestation, frozen_attestation);
    assert!(publication
        .object_scope("association-one", "", "object", 100)
        .is_ok());
    assert!(publication
        .object_scope("association-two", "", "object", 100)
        .is_err());

    let mut unproven_writer = publication.clone();
    unproven_writer
        .admission
        .association_ids
        .push(auxiliary.association_id);
    unproven_writer.digest = digest(&unproven_writer.admission).unwrap();
    assert!(unproven_writer.validate(NAMESPACE, EXECUTOR).is_err());
}

#[tokio::test]
async fn creation_ceiling_survives_narrow_first_publication_and_later_reopening() {
    let mut first = publication();
    first.associations[0].binding_prefix = "managed/narrow".into();
    first.attestation.as_mut().unwrap().managed_prefix = "managed/narrow".into();
    let mut journal = MemoryJournal::default();
    journal.values.insert(
        "object/unknown-effect".into(),
        serde_json::json!({"pending":true}),
    );
    publish(&mut journal, first.clone(), 100).await;
    assert_eq!(
        journal.values[&authority_key(&first.authority.authority_id, "managed-prefix")],
        Value::String("managed".into())
    );

    let mut reopened = next_state(&first, StorageAuthorityAdmissionState::Admitted);
    reopened.attestation.as_mut().unwrap().attestation_id = "attestation-reopened".into();
    reopened.attestation.as_mut().unwrap().managed_prefix = "managed".into();
    reopened.admission.attestation_id = Some("attestation-reopened".into());
    reopened.digest = digest(&reopened.admission).unwrap();
    publish(&mut journal, reopened.clone(), 101).await;
    assert_eq!(
        journal.values["object/unknown-effect"],
        serde_json::json!({"pending":true})
    );

    let replay = handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(first.clone()), 102, '4'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        102,
    )
    .await
    .unwrap();
    assert_eq!(replay.control_receipt.unwrap().generation, 1);
    assert_eq!(replay.watermark.unwrap().generation, 2);

    let mut expanded = next_state(&reopened, StorageAuthorityAdmissionState::Admitted);
    expanded.attestation.as_mut().unwrap().attestation_id = "attestation-expanded".into();
    expanded
        .attestation
        .as_mut()
        .unwrap()
        .managed_prefix
        .clear();
    expanded.admission.attestation_id = Some("attestation-expanded".into());
    expanded.digest = digest(&expanded.admission).unwrap();
    assert!(handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(expanded), 103, '5'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        103
    )
    .await
    .is_err());

    let mut changed_ceiling = next_state(&reopened, StorageAuthorityAdmissionState::Blocked);
    changed_ceiling.authority.qualified_managed_prefix.clear();
    assert!(handle(
        &mut journal,
        &request(
            StorageAuthorityOperation::Publish(changed_ceiling),
            103,
            '6'
        ),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        103
    )
    .await
    .is_err());
}

#[test]
fn creation_ceiling_is_required_even_when_legacy_publication_would_match_attestation() {
    let mut encoded = serde_json::to_value(publication()).unwrap();
    encoded["authority"]
        .as_object_mut()
        .unwrap()
        .remove("qualified_managed_prefix");
    assert!(serde_json::from_value::<StorageAuthorityPublication>(encoded).is_err());
}

#[tokio::test]
async fn blocked_first_publication_also_reserves_the_creation_ceiling() {
    let admitted = publication();
    let mut first = next_state(&admitted, StorageAuthorityAdmissionState::Blocked);
    first.generation = 1;
    first.admission.expected_generation = 0;
    first.admission.expected_digest = None;
    first.digest = digest(&first.admission).unwrap();
    let mut journal = MemoryJournal::default();
    publish(&mut journal, first.clone(), 100).await;
    assert_eq!(
        journal.values[&authority_key(&first.authority.authority_id, "managed-prefix")],
        Value::String("managed".into())
    );

    let mut reopened = admitted;
    reopened.generation = 2;
    reopened.admission.expected_generation = 1;
    reopened.admission.expected_digest = Some(first.digest);
    reopened.digest = digest(&reopened.admission).unwrap();
    publish(&mut journal, reopened, 101).await;
}

#[test]
fn qualification_prefixes_use_canonical_component_boundaries() {
    let mut scoped = publication();
    scoped.authority.qualified_managed_prefix = "foo/root".into();
    scoped.associations[0].binding_prefix = "foo/root/objects".into();

    for prefix in ["foo/root", "foo/root/objects"] {
        scoped.attestation.as_mut().unwrap().managed_prefix = prefix.into();
        scoped.validate(NAMESPACE, EXECUTOR).unwrap();
    }

    for prefix in ["foo", "foo/root-other", "foobar/root", "foo/root/", ""] {
        scoped.attestation.as_mut().unwrap().managed_prefix = prefix.into();
        assert!(scoped.validate(NAMESPACE, EXECUTOR).is_err(), "{prefix}");
    }

    scoped.authority.qualified_managed_prefix.clear();
    scoped.attestation.as_mut().unwrap().managed_prefix.clear();
    scoped.validate(NAMESPACE, EXECUTOR).unwrap();
    scoped.authority.qualified_managed_prefix = "foo/".into();
    assert!(scoped.validate(NAMESPACE, EXECUTOR).is_err());
}

fn request(
    operation: StorageAuthorityOperation,
    now: i64,
    nonce_byte: char,
) -> StorageAuthorityRequest {
    StorageAuthorityRequest {
        version: 1,
        deployment_id: DEPLOYMENT.into(),
        guard_namespace_id: NAMESPACE.into(),
        nonce: nonce_byte.to_string().repeat(64),
        issued_at: now,
        expires_at: now + 30,
        operation,
    }
}

async fn publish(
    journal: &mut MemoryJournal,
    publication: StorageAuthorityPublication,
    now: i64,
) -> StorageAuthorityResponse {
    handle(
        journal,
        &request(StorageAuthorityOperation::Publish(publication), now, '1'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        now,
    )
    .await
    .unwrap()
}

fn next_state(
    previous: &StorageAuthorityPublication,
    state: StorageAuthorityAdmissionState,
) -> StorageAuthorityPublication {
    let mut next = previous.clone();
    next.admission.expected_generation = previous.generation;
    next.admission.expected_digest = Some(previous.digest.clone());
    next.admission.state = state;
    if state != StorageAuthorityAdmissionState::Admitted {
        next.admission.attestation_id = None;
        next.admission.association_ids.clear();
        next.associations.clear();
        next.attestation = None;
    }
    next.generation += 1;
    next.digest = digest(&next.admission).unwrap();
    next
}

#[tokio::test]
async fn restored_sql_cannot_receive_a_fresh_stale_watermark_from_old_control() {
    let mut journal = MemoryJournal::default();
    let original = publication();
    publish(&mut journal, original.clone(), 100).await;
    let blocked = next_state(&original, StorageAuthorityAdmissionState::Blocked);
    publish(&mut journal, blocked.clone(), 101).await;
    let commits = journal.commits;

    let replay_request = request(
        StorageAuthorityOperation::Publish(original.clone()),
        110,
        '2',
    );
    let replay = handle(
        &mut journal,
        &replay_request,
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        110,
    )
    .await
    .unwrap();
    replay.validate_for(&replay_request, 110).unwrap();

    assert_eq!(replay.control_receipt.unwrap().generation, 1);
    let watermark = replay.watermark.unwrap();
    assert_eq!(watermark.generation, 2);
    assert_eq!(watermark.digest, blocked.digest);
    assert_ne!(watermark.digest, original.digest);
    assert_eq!(journal.commits, commits);
}

#[tokio::test]
async fn new_control_requires_exact_remote_predecessor_even_after_restore() {
    let mut journal = MemoryJournal::default();
    let original = publication();
    publish(&mut journal, original.clone(), 100).await;
    let blocked = next_state(&original, StorageAuthorityAdmissionState::Blocked);
    publish(&mut journal, blocked.clone(), 101).await;
    let mut stale = next_state(&original, StorageAuthorityAdmissionState::Admitted);
    stale.admission.expected_digest = Some("f".repeat(64));
    stale.digest = digest(&stale.admission).unwrap();

    assert!(handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(stale), 102, '3'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        102
    )
    .await
    .is_err());
    assert_eq!(journal.commits, 2);
}

#[tokio::test]
async fn exact_replay_never_replaces_immutable_alias_evidence() {
    let mut journal = MemoryJournal::default();
    let original = publication();
    publish(&mut journal, original.clone(), 100).await;
    let mut changed = original;
    changed.aliases[0].equivalence_evidence_digest = "f".repeat(64);

    assert!(handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(changed), 101, '2'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        101
    )
    .await
    .is_err());
    assert_eq!(journal.commits, 1);
}

#[tokio::test]
async fn immutable_reservations_survive_retirement_and_cannot_transfer() {
    let mut journal = MemoryJournal::default();
    let original = publication();
    publish(&mut journal, original.clone(), 100).await;
    let retired = next_state(&original, StorageAuthorityAdmissionState::Retired);
    publish(&mut journal, retired.clone(), 101).await;
    let resurrected = next_state(&retired, StorageAuthorityAdmissionState::Blocked);
    assert!(handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(resurrected), 102, '3'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        102
    )
    .await
    .is_err());

    let mut conflicting = publication();
    let second = PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000002").unwrap();
    conflicting.authority.authority_id = second.clone();
    conflicting.authority.physical_resource_evidence_digest = "f".repeat(64);
    conflicting.admission.authority_id = second.clone();
    conflicting.aliases[0].authority_id = second.clone();
    conflicting.aliases[0].alias_id = "alias-two".into();
    conflicting.associations[0].authority_id = second.clone();
    conflicting.associations[0].alias_id = "alias-two".into();
    conflicting.associations[0].association_id = "association-two".into();
    conflicting.associations[0].binding_stable_id = "binding-two".into();
    conflicting.admission.association_ids = vec!["association-two".into()];
    let attestation = conflicting.attestation.as_mut().unwrap();
    attestation.authority_id = second;
    attestation.attestation_id = "attestation-two".into();
    attestation.credentials[0].association_id = "association-two".into();
    conflicting.admission.attestation_id = Some("attestation-two".into());
    conflicting.digest = digest(&conflicting.admission).unwrap();
    assert!(handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(conflicting), 102, '4'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        102
    )
    .await
    .is_err());
    assert_eq!(journal.commits, 2);
}

#[tokio::test]
async fn one_actual_namespace_supports_multiple_distinct_physical_authorities() {
    let mut journal = MemoryJournal::default();
    let original = publication();
    publish(&mut journal, original.clone(), 100).await;
    let mut second = original;
    let id = PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000002").unwrap();
    second.authority.authority_id = id.clone();
    second.authority.physical_resource_evidence_digest = "f".repeat(64);
    second.aliases[0].authority_id = id.clone();
    second.aliases[0].alias_id = "alias-two".into();
    second.aliases[0].spec.bucket = "bucket-two".into();
    second.associations[0].authority_id = id.clone();
    second.associations[0].association_id = "association-two".into();
    second.associations[0].alias_id = "alias-two".into();
    second.associations[0].binding_stable_id = "binding-two".into();
    second.admission.authority_id = id.clone();
    second.admission.association_ids = vec!["association-two".into()];
    second.admission.attestation_id = Some("attestation-two".into());
    let attestation = second.attestation.as_mut().unwrap();
    attestation.authority_id = id.clone();
    attestation.attestation_id = "attestation-two".into();
    attestation.credentials[0].association_id = "association-two".into();
    second.digest = digest(&second.admission).unwrap();

    let reply = publish(&mut journal, second, 101).await;
    assert_eq!(reply.watermark.unwrap().authority_id, id);
    assert_eq!(journal.commits, 2);
}

#[tokio::test]
async fn failed_atomic_commit_cannot_leave_partial_alias_claim_or_receipt() {
    let mut journal = MemoryJournal {
        fail_commit: true,
        ..Default::default()
    };
    let request = request(StorageAuthorityOperation::Publish(publication()), 100, '1');
    assert!(
        handle(&mut journal, &request, DEPLOYMENT, NAMESPACE, EXECUTOR, 100)
            .await
            .is_err()
    );
    assert!(journal.values.is_empty());

    journal.fail_commit = false;
    let reply = handle(&mut journal, &request, DEPLOYMENT, NAMESPACE, EXECUTOR, 100)
        .await
        .unwrap();
    assert_eq!(reply.watermark.unwrap().generation, 1);
    assert_eq!(journal.commits, 1);
}

#[tokio::test]
async fn expiry_and_control_changes_do_not_clear_unknown_object_effects() {
    let mut journal = MemoryJournal::default();
    journal.values.insert(
        "object/unknown-effect".into(),
        serde_json::json!({"pending":true,"operation":"original"}),
    );
    let original = publication();
    publish(&mut journal, original.clone(), 100).await;
    let request = request(
        StorageAuthorityOperation::Watermark(original.authority.authority_id.clone()),
        1001,
        '2',
    );
    let reply = handle(
        &mut journal,
        &request,
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        1001,
    )
    .await
    .unwrap();
    assert_eq!(reply.watermark.unwrap().generation, 1);
    assert!(original
        .object_scope("association-one", "", "object", 1001)
        .is_err());

    let blocked = next_state(&original, StorageAuthorityAdmissionState::Blocked);
    publish(&mut journal, blocked, 1001).await;
    assert_eq!(
        journal.values["object/unknown-effect"],
        serde_json::json!({"pending":true,"operation":"original"})
    );
}

#[tokio::test]
async fn namespace_executor_and_initial_scope_cannot_change() {
    let mut journal = MemoryJournal::default();
    let original = publication();
    publish(&mut journal, original.clone(), 100).await;
    let lookup = request(
        StorageAuthorityOperation::Watermark(original.authority.authority_id.clone()),
        101,
        '2',
    );
    assert!(handle(
        &mut journal,
        &lookup,
        DEPLOYMENT,
        NAMESPACE,
        "another-executor",
        101
    )
    .await
    .is_err());
    let mut other_namespace = lookup.clone();
    other_namespace.guard_namespace_id = "another-namespace".into();
    assert!(handle(
        &mut journal,
        &other_namespace,
        DEPLOYMENT,
        "another-namespace",
        EXECUTOR,
        101
    )
    .await
    .is_err());

    let mut expanded = next_state(&original, StorageAuthorityAdmissionState::Admitted);
    expanded.attestation.as_mut().unwrap().attestation_id = "attestation-two".into();
    expanded
        .attestation
        .as_mut()
        .unwrap()
        .managed_prefix
        .clear();
    expanded.admission.attestation_id = Some("attestation-two".into());
    expanded.digest = digest(&expanded.admission).unwrap();
    assert!(handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(expanded), 101, '3'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        101
    )
    .await
    .is_err());
}

#[test]
fn signed_fresh_response_rejects_nonce_substitution_domain_replay_and_tampering() {
    let key = StorageWorkKey::new("a".repeat(32)).unwrap();
    let request = request(
        StorageAuthorityOperation::Watermark(publication().authority.authority_id),
        100,
        '1',
    );
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let request_signature = sign_authority_message(&key, false, &request_bytes).unwrap();
    verify_authority_message(&key, false, &request_signature, &request_bytes).unwrap();
    assert!(verify_authority_message(&key, true, &request_signature, &request_bytes).is_err());
    assert!(key.verify_body(&request_signature, &request_bytes).is_err());

    let reply = StorageAuthorityResponse {
        version: 1,
        request_digest: digest(&request).unwrap(),
        nonce: request.nonce.clone(),
        deployment_id: DEPLOYMENT.into(),
        guard_namespace_id: NAMESPACE.into(),
        issued_at: 100,
        expires_at: 130,
        watermark: None,
        control_receipt: None,
    };
    let bytes = serde_json::to_vec(&reply).unwrap();
    let signature = sign_authority_message(&key, true, &bytes).unwrap();
    verify_authority_message(&key, true, &signature, &bytes).unwrap();
    reply.validate_for(&request, 100).unwrap();
    let mut newer = request.clone();
    newer.nonce = "2".repeat(64);
    assert!(reply.validate_for(&newer, 100).is_err());
    assert!(reply.validate_for(&request, 130).is_err());
    let tampered = serde_json::to_vec(&serde_json::json!({"version":2})).unwrap();
    assert!(verify_authority_message(&key, true, &signature, &tampered).is_err());
}

#[test]
fn alias_prefix_partitions_and_credential_rotation_share_full_key_guard_identity() {
    let original = publication();
    let first = original
        .object_scope("association-one", "part", "object", 100)
        .unwrap();
    let mut rotated = original.clone();
    rotated.associations[0].binding_id = 2;
    rotated.associations[0].binding_stable_id = "binding-two".into();
    rotated.associations[0].binding_resource_version = 9;
    rotated.associations[0].binding_write_revision = 20;
    rotated.associations[0].binding_prefix = "managed/part".into();
    rotated.aliases[0].spec.host = StorageAuthorityHost::Dns("alias.example.test".into());
    rotated.attestation.as_mut().unwrap().credentials[0].generation = 30;
    let second = rotated
        .object_scope("association-one", "", "object", 100)
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.guard_name().unwrap(), second.guard_name().unwrap());

    let stamp = StorageGuardStamp {
        physical_authority_id: original.authority.authority_id,
        incarnation: GuardIncarnation::parse("1").unwrap(),
    };
    first.validate_stamp(&stamp).unwrap();
    let mut wrong = stamp;
    wrong.physical_authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000002").unwrap();
    assert!(first.validate_stamp(&wrong).is_err());
}

#[test]
fn closed_messages_reject_unknown_fields_and_unbounded_or_future_requests() {
    let request = request(
        StorageAuthorityOperation::Watermark(publication().authority.authority_id),
        100,
        '1',
    );
    let mut encoded = serde_json::to_value(&request).unwrap();
    encoded["delete"] = Value::Bool(true);
    assert!(serde_json::from_value::<StorageAuthorityRequest>(encoded).is_err());
    assert!(request.validate(DEPLOYMENT, NAMESPACE, 99).is_err());
    assert!(request.validate("wrong", NAMESPACE, 100).is_err());
    let mut unbounded = request;
    unbounded.expires_at = 131;
    assert!(unbounded.validate(DEPLOYMENT, NAMESPACE, 100).is_err());
}

struct SqliteJournal {
    backend: aos_hub_core::backend::SqlxBackend,
    fail_after_first_batch: bool,
    largest_commit: usize,
}

impl AuthorityJournal for SqliteJournal {
    async fn get(&mut self, key: &str) -> Result<Option<Value>> {
        use aos_hub_core::backend::Backend as _;
        self.backend
            .query_opt(
                "SELECT value FROM authority_journal WHERE key = ?1",
                &[aos_hub_core::value::Value::Text(key.into())],
            )
            .await?
            .map(|row| Ok(serde_json::from_str(&row.get::<String>(0)?)?))
            .transpose()
    }

    async fn put_atomic(&mut self, values: BTreeMap<String, Value>) -> Result<()> {
        use aos_hub_core::backend::{Backend as _, Statement};
        self.largest_commit = self.largest_commit.max(values.len());
        let mut statements = Vec::new();
        for (index, batch) in write_batches(values).into_iter().enumerate() {
            assert!(batch.len() <= 128);
            if index == 1 && self.fail_after_first_batch {
                statements.push(Statement::new(
                    "INSERT INTO deliberately_absent_table VALUES (1)",
                    vec![],
                ));
            }
            for (key, value) in batch {
                statements.push(Statement::new("INSERT INTO authority_journal(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", vec![aos_hub_core::value::Value::Text(key), aos_hub_core::value::Value::Text(serde_json::to_string(&value)?)]));
            }
        }
        self.backend.batch(&statements).await
    }
}

#[tokio::test]
async fn actual_sqlite_256_associations_publish_atomically_across_api_batches() {
    use aos_hub_core::backend::{Backend as _, SqlxBackend};
    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    backend
        .execute_batch("CREATE TABLE authority_journal(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        .await
        .unwrap();
    let mut journal = SqliteJournal {
        backend,
        fail_after_first_batch: true,
        largest_commit: 0,
    };
    let mut publication = publication();
    let template = publication.associations.remove(0);
    let credential = publication
        .attestation
        .as_mut()
        .unwrap()
        .credentials
        .remove(0);
    for number in 0..256 {
        let mut association = template.clone();
        association.association_id = format!("association-{number:03}");
        association.binding_id = number + 1;
        association.binding_stable_id = format!("binding-{number:03}");
        publication
            .admission
            .association_ids
            .push(association.association_id.clone());
        let mut member = credential.clone();
        member.association_id = association.association_id.clone();
        publication.associations.push(association);
        publication
            .attestation
            .as_mut()
            .unwrap()
            .credentials
            .push(member);
    }
    publication.admission.association_ids.remove(0);
    publication.digest = digest(&publication.admission).unwrap();
    publication.validate(NAMESPACE, EXECUTOR).unwrap();
    let control_request = request(
        StorageAuthorityOperation::Publish(publication.clone()),
        100,
        '1',
    );
    assert!(
        serde_json::to_vec(&control_request).unwrap().len()
            < aos_hub_core::storage_authority::control::MAX_AUTHORITY_CONTROL_BYTES
    );

    assert!(handle(
        &mut journal,
        &control_request,
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        100
    )
    .await
    .is_err());
    let count = journal
        .backend
        .query_opt("SELECT COUNT(*) FROM authority_journal", &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count.get::<i64>(0).unwrap(), 0);
    assert!(journal.largest_commit > 128);

    journal.fail_after_first_batch = false;
    let reply = handle(
        &mut journal,
        &control_request,
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        100,
    )
    .await
    .unwrap();
    assert_eq!(reply.watermark.unwrap().generation, 1);
    let count = journal
        .backend
        .query_opt("SELECT COUNT(*) FROM authority_journal", &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        count.get::<i64>(0).unwrap(),
        i64::try_from(journal.largest_commit).unwrap()
    );
    let stored_receipt = journal
        .get(&authority_key(
            &publication.authority.authority_id,
            "receipt/1",
        ))
        .await
        .unwrap();
    assert!(stored_receipt.is_some());
    let lookup = request(
        StorageAuthorityOperation::Watermark(publication.authority.authority_id),
        101,
        '2',
    );
    let reply = handle(&mut journal, &lookup, DEPLOYMENT, NAMESPACE, EXECUTOR, 101)
        .await
        .unwrap();
    assert_eq!(reply.watermark.unwrap().generation, 1);
}

fn large_publication() -> StorageAuthorityPublication {
    let mut publication = publication();
    publication.authority.qualified_managed_prefix = "\"".repeat(512);
    publication.attestation.as_mut().unwrap().managed_prefix =
        publication.authority.qualified_managed_prefix.clone();
    publication.aliases.clear();
    publication.associations.clear();
    publication
        .attestation
        .as_mut()
        .unwrap()
        .credentials
        .clear();
    publication.admission.association_ids.clear();

    for index in 0..256 {
        let suffix = format!("{index:03}");
        let alias_id = format!("{}{suffix}", "\"".repeat(61));
        let association_id = format!("{}{suffix}", "\"".repeat(61));
        publication.aliases.push(ApproveStorageAuthorityAlias {
            alias_id: alias_id.clone(),
            authority_id: publication.authority.authority_id.clone(),
            spec: StorageAuthorityAliasSpec {
                host: StorageAuthorityHost::Dns(format!(
                    "{}.{}.{}.{}{suffix}",
                    "a".repeat(63),
                    "a".repeat(63),
                    "a".repeat(63),
                    "a".repeat(57)
                )),
                port: 65535,
                bucket: "\"".repeat(255),
            },
            equivalence_evidence_digest: "c".repeat(64),
        });
        publication
            .associations
            .push(AssociateStorageAuthorityBinding {
                association_id: association_id.clone(),
                authority_id: publication.authority.authority_id.clone(),
                alias_id,
                binding_id: index + 1,
                binding_stable_id: format!("{}{suffix}", "\"".repeat(61)),
                binding_resource_version: 1,
                binding_write_revision: 1,
                binding_prefix: publication.authority.qualified_managed_prefix.clone(),
            });
        publication.attestation.as_mut().unwrap().credentials.push(
            StorageAuthorityCredentialMember {
                association_id: association_id.clone(),
                purpose: "write".into(),
                generation: 1,
                secret_version_ref: format!("worker://ns/{}/v1", "s".repeat(113)),
                credential_fingerprint: "e".repeat(64),
            },
        );
        publication.admission.association_ids.push(association_id);
    }
    publication.digest = digest(&publication.admission).unwrap();
    publication
}

fn publication_at_encoded_size(target: usize) -> StorageAuthorityPublication {
    publication_at_encoded_size_in_namespace(target, NAMESPACE)
}

fn publication_at_encoded_size_in_namespace(
    target: usize,
    namespace: &str,
) -> StorageAuthorityPublication {
    let mut publication = large_publication();
    publication.authority.guard_namespace_id = namespace.into();
    publication.admission.guard_namespace_id = namespace.into();
    publication.attestation.as_mut().unwrap().valid_until = i64::MAX;
    publication.digest = digest(&publication.admission).unwrap();
    let size = serde_json::to_vec(&publication).unwrap().len();
    assert!(size >= target, "fixture must exceed requested encoded size");
    let mut excess = size - target;

    for alias in &mut publication.aliases {
        let removed_quotes = (excess / 2).min(alias.spec.bucket.len() - 1);
        alias
            .spec
            .bucket
            .truncate(alias.spec.bucket.len() - removed_quotes);
        excess -= removed_quotes * 2;
        if excess == 1 && alias.spec.bucket.starts_with('"') {
            alias.spec.bucket.replace_range(..1, "x");
            excess = 0;
        }
        if excess == 0 {
            break;
        }
    }
    assert_eq!(excess, 0);
    assert_eq!(serde_json::to_vec(&publication).unwrap().len(), target);
    publication
}

#[tokio::test]
async fn publication_budget_accepts_boundary_and_rejects_next_byte_without_writes() {
    use aos_hub_core::storage_authority::control::MAX_AUTHORITY_PUBLICATION_BYTES;

    let boundary = publication_at_encoded_size(MAX_AUTHORITY_PUBLICATION_BYTES);
    boundary.validate(NAMESPACE, EXECUTOR).unwrap();
    let oversized = publication_at_encoded_size(MAX_AUTHORITY_PUBLICATION_BYTES + 1);
    let mut journal = MemoryJournal::default();
    let error = handle(
        &mut journal,
        &request(StorageAuthorityOperation::Publish(oversized), 100, '1'),
        DEPLOYMENT,
        NAMESPACE,
        EXECUTOR,
        100,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("encoded admission budget"));
    assert_eq!(journal.commits, 0);
    assert!(journal.values.is_empty());
}

#[test]
fn exact_request_wire_boundary_and_bounded_domain_fields_are_checked() {
    use aos_hub_core::storage_authority::control::{
        MAX_AUTHORITY_CONTROL_BYTES, MAX_AUTHORITY_DEPLOYMENT_ID_BYTES,
    };

    let mut control = request(StorageAuthorityOperation::Publish(publication()), 100, '1');
    let overhead = serde_json::to_vec(&control).unwrap().len()
        - serde_json::to_vec(&publication()).unwrap().len();
    control.operation = StorageAuthorityOperation::Publish(publication_at_encoded_size(
        MAX_AUTHORITY_CONTROL_BYTES - overhead,
    ));
    assert_eq!(
        serde_json::to_vec(&control).unwrap().len(),
        MAX_AUTHORITY_CONTROL_BYTES
    );
    control.validate(DEPLOYMENT, NAMESPACE, 100).unwrap();

    if let StorageAuthorityOperation::Publish(publication) = &mut control.operation {
        publication.aliases[0].spec.bucket.push('x');
    }
    assert!(control
        .validate(DEPLOYMENT, NAMESPACE, 100)
        .unwrap_err()
        .to_string()
        .contains("encoded wire bound"));

    let mut control = request(StorageAuthorityOperation::Publish(publication()), 100, '1');
    control.deployment_id = "x".repeat(MAX_AUTHORITY_DEPLOYMENT_ID_BYTES + 1);
    assert!(control
        .validate(&control.deployment_id, NAMESPACE, 100)
        .is_err());
}

#[test]
fn ordinary_256_members_still_fit_publication_and_envelope_budgets() {
    use aos_hub_core::storage_authority::control::MAX_AUTHORITY_PUBLICATION_BYTES;

    let mut publication = large_publication();
    publication.authority.qualified_managed_prefix = "managed".into();
    publication.attestation.as_mut().unwrap().managed_prefix = "managed".into();
    for association in &mut publication.associations {
        association.binding_prefix = "managed".into();
    }
    publication.validate(NAMESPACE, EXECUTOR).unwrap();
    let bytes = serde_json::to_vec(&publication).unwrap().len();
    assert!(bytes < MAX_AUTHORITY_PUBLICATION_BYTES);
    println!("ordinary-prefix 256-member fixture: {bytes} publication bytes");
}

#[tokio::test]
async fn maximum_escaped_envelope_fits_and_returns_a_bounded_receipt() {
    use aos_hub_core::storage_authority::control::{
        MAX_AUTHORITY_CONTROL_BYTES, MAX_AUTHORITY_DEPLOYMENT_ID_BYTES,
        MAX_AUTHORITY_NAMESPACE_ID_BYTES, MAX_AUTHORITY_PUBLICATION_BYTES,
    };

    let deployment = "\\".repeat(MAX_AUTHORITY_DEPLOYMENT_ID_BYTES);
    let namespace = "\"".repeat(MAX_AUTHORITY_NAMESPACE_ID_BYTES);
    let publication =
        publication_at_encoded_size_in_namespace(MAX_AUTHORITY_PUBLICATION_BYTES, &namespace);
    publication.validate(&namespace, EXECUTOR).unwrap();
    let now = i64::MAX - 30;
    let mut control = request(StorageAuthorityOperation::Publish(publication), now, 'f');
    control.deployment_id = deployment.clone();
    control.guard_namespace_id = namespace.clone();
    control.expires_at = i64::MAX;
    assert_eq!(
        serde_json::to_vec(&control).unwrap().len(),
        MAX_AUTHORITY_CONTROL_BYTES
    );
    control.validate(&deployment, &namespace, now).unwrap();

    let mut journal = MemoryJournal::default();
    let reply = handle(
        &mut journal,
        &control,
        &deployment,
        &namespace,
        EXECUTOR,
        now,
    )
    .await
    .unwrap();
    assert_eq!(journal.commits, 1);
    reply.validate_for(&control, now).unwrap();
    let response_bytes = serde_json::to_vec(&reply).unwrap();
    assert!(response_bytes.len() < 2 * 1024);
    println!(
        "maximum escaped envelope receipt: {} bytes",
        response_bytes.len()
    );

    let mut widest_generation_reply = reply.clone();
    widest_generation_reply
        .watermark
        .as_mut()
        .unwrap()
        .generation = aos_hub_core::storage_authority::control::MAX_AUTHORITY_GENERATION;
    widest_generation_reply
        .control_receipt
        .as_mut()
        .unwrap()
        .generation = aos_hub_core::storage_authority::control::MAX_AUTHORITY_GENERATION;
    let widest_response_bytes = serde_json::to_vec(&widest_generation_reply).unwrap();
    assert!(widest_response_bytes.len() < 2 * 1024);
    println!(
        "maximum escaped envelope and generation widths: {} bytes",
        widest_response_bytes.len()
    );

    let before = journal.values.clone();
    if let StorageAuthorityOperation::Publish(publication) = &mut control.operation {
        publication.aliases[0].spec.bucket.push('x');
    }
    assert!(handle(
        &mut journal,
        &control,
        &deployment,
        &namespace,
        EXECUTOR,
        now
    )
    .await
    .is_err());
    assert_eq!(journal.commits, 1);
    assert_eq!(journal.values, before);
}

#[test]
fn versioned_string_entries_preserve_full_sql_integer_range() {
    let mut publication = publication();
    publication.attestation.as_mut().unwrap().valid_until = i64::MAX;
    publication.associations[0].binding_id = i64::MAX;
    publication.associations[0].binding_resource_version = i64::MAX;
    publication.associations[0].binding_write_revision = i64::MAX;
    publication.validate(NAMESPACE, EXECUTOR).unwrap();

    let value = serde_json::to_value(&publication).unwrap();
    let encoded = encode_journal_value(&value).unwrap();
    assert!(encoded.contains("9223372036854775807"));
    let decoded = decode_journal_value(&encoded).unwrap();
    assert_eq!(decoded, value);
    let restored: StorageAuthorityPublication = serde_json::from_value(decoded).unwrap();
    assert_eq!(restored, publication);
}

#[test]
fn legacy_or_unsupported_journal_strings_never_decode_as_absence() {
    assert!(decode_journal_value("null").is_err());
    assert!(decode_journal_value("{}").is_err());
    assert!(decode_journal_value(r#"{"generation":1}"#).is_err());
    assert!(decode_journal_value(r#"{"version":2,"value":null}"#).is_err());
    assert!(decode_journal_value(r#"{"version":1,"value":null,"extra":true}"#).is_err());
    assert_eq!(
        decode_journal_value(r#"{"version":1,"value":null}"#).unwrap(),
        Value::Null
    );
}
