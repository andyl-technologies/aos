//! Actual signed lease fixtures for compact-turn ordering and replay semantics.

use std::cell::RefCell;

use aos_hub_core::storage_authority::{
    control::StorageAuthorityPublication, lease::*, ApproveStorageAuthorityAlias,
    AssociateStorageAuthorityBinding, AttestStorageAuthorityExclusivity,
    CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId, SetStorageAuthorityAdmission,
    StorageAuthorityAdmissionState, StorageAuthorityAliasSpec, StorageAuthorityCredentialMember,
    StorageAuthorityHost,
};
use aos_hub_core::storage_work::{
    StorageCredentialSelector, StorageWorkKey, StorageWorkOperation, StorageWorkPlan,
};
use ed25519_dalek::SigningKey;

use super::{
    config::Config,
    protocol::{self, Effect, GuardOperation, GuardReply, GuardRequest, Intent, Outcome, Receipt},
    state::Head,
};

const EXECUTOR: &str = "qualified-executor";
const KEY_ID: &str = "external-issuer-one";

fn integer(value: i64) -> LeaseInteger {
    LeaseInteger::new(value).unwrap()
}

pub(super) fn clock(value: i64) -> LeaseClock {
    LeaseClock {
        observed_at: value,
        uncertainty: 2,
    }
}

fn profile() -> LeaseTimingProfile {
    // Fixture-only example; these values are not a qualified deployment default.
    LeaseTimingProfile {
        profile_id: "fixture-reviewed-clock".into(),
        review_digest: "9".repeat(64),
        maximum_lifetime: integer(30),
        maximum_clock_uncertainty: integer(2),
    }
}

fn publication() -> StorageAuthorityPublication {
    let authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let authority = CreatePhysicalStorageAuthority {
        authority_id: authority_id.clone(),
        guard_namespace_id: "permanent-guard-namespace".into(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
        qualified_managed_prefix: "managed".into(),
    };
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("objects.example.invalid".into()),
            port: 443,
            bucket: "qualified-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: 9_007_199_254_740_993,
        binding_stable_id: "binding-one".into(),
        binding_resource_version: 9_007_199_254_740_995,
        binding_write_revision: 9_007_199_254_740_997,
        binding_prefix: "managed/binding".into(),
    };
    let credentials = ["delete", "list", "read", "write"]
        .into_iter()
        .map(|purpose| StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: purpose.into(),
            generation: 9_007_199_254_741_001,
            secret_version_ref: format!("secret://fixture/{purpose}/immutable-v1"),
            credential_fingerprint: "4".repeat(64),
        })
        .collect();
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "attestation-one".into(),
        authority_id: authority_id.clone(),
        managed_prefix: "managed".into(),
        qualification_digest: authority.qualification_digest.clone(),
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: EXECUTOR.into(),
        credentials,
        valid_until: 1000,
    };
    let admission = SetStorageAuthorityAdmission {
        authority_id,
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority.guard_namespace_id.clone(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id.clone()),
        association_ids: vec![association.association_id.clone()],
    };
    let digest = protocol::digest(&admission).unwrap();
    let publication = StorageAuthorityPublication {
        authority,
        aliases: vec![alias],
        associations: vec![association],
        attestation: Some(attestation),
        admission,
        generation: 1,
        digest,
    };
    publication
        .validate(&publication.authority.guard_namespace_id, EXECUTOR)
        .unwrap();
    publication
}

pub(super) fn config() -> Config {
    let publication = publication();
    let write = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Write,
        "managed/binding/objects",
        vec![LeaseEffect::Put],
    )
    .unwrap();
    let read = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Read,
        "managed/binding/objects",
        vec![LeaseEffect::Head],
    )
    .unwrap();
    let value = Config {
        version: 1,
        guard_namespace_id: publication.authority.guard_namespace_id.clone(),
        executor_identity: EXECUTOR.into(),
        issuer_key_id: KEY_ID.into(),
        issuer_public_key: hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()),
        timing_profile: profile(),
        clock_uncertainty: 2,
        aliases: publication.aliases.clone(),
        cohorts: vec![write, read],
        publications: vec![publication],
    };
    value.validate().unwrap();
    value
}

pub(super) fn intent(config: &Config, index: usize, op: &str) -> Intent {
    let cohort = &config.cohorts[index];
    Intent {
        scope: config
            .scope(cohort, "managed/binding/objects/blob".into())
            .unwrap(),
        operation_id: op.into(),
        context: "8".repeat(64),
        cohort_digest: protocol::digest(cohort).unwrap(),
        effect: if index == 0 {
            Effect::Put {
                sha256: "a".repeat(64),
                bytes: 3,
            }
        } else {
            Effect::Head
        },
    }
}

pub(super) async fn token(config: &Config, index: usize, previous_sequence: i64) -> Vec<u8> {
    let publication = &config.publications[0];
    let mut journal = EpochLeaseIssuerJournal::initialize_fresh_namespace(
        publication,
        EXECUTOR,
        BoundedLeaseRevocationPolicy {
            timing_profile: profile(),
        },
        clock(100),
    )
    .unwrap();
    // Fixture models the exact retained issuer state before a new actual CAS.
    journal.last_sequence = integer(previous_sequence);
    if previous_sequence > 0 {
        journal.largest_issued_expiry = integer(130);
    }
    let live = RefCell::new(journal);
    let prepared = live
        .borrow()
        .prepare_issue(
            publication,
            config.cohorts[index].clone(),
            KEY_ID,
            130,
            clock(100),
        )
        .unwrap();
    let key = EpochLeaseSigningKey::from_bytes(KEY_ID.into(), &[7; 32]).unwrap();
    prepared
        .commit_and_sign(
            &key,
            |transition| {
                let live = &live;
                async move {
                    anyhow::ensure!(
                        *live.borrow() == transition.expected,
                        "fixture issuer CAS changed"
                    );
                    *live.borrow_mut() = transition.next;
                    Ok(())
                }
            },
            || Ok(clock(100)),
        )
        .await
        .unwrap()
}

pub(super) async fn pending(config: &Config, index: usize) -> (Head, Intent) {
    let intent = intent(config, index, "retained-op-one");
    let initial = Head::initialize(config, &intent, clock(100)).unwrap();
    let (head, reply) = initial
        .begin(
            config,
            intent.clone(),
            &token(config, index, 0).await,
            "b".repeat(64),
            clock(101),
        )
        .unwrap();
    assert!(matches!(reply, GuardReply::Dispatch { .. }));
    (head, intent)
}

pub(super) fn receipt(head: &Head) -> Receipt {
    let turn = head.pending.clone().unwrap();
    let outcome = match turn.intent.effect {
        Effect::Put { .. } => Outcome::PutAcknowledged,
        Effect::Head => Outcome::HistoricalHead { object: None },
        Effect::Delete { ref expected } => Outcome::DeleteAcknowledged {
            provider_version: expected.provider_version.clone(),
            etag: expected.etag.clone(),
        },
        Effect::ProbeHash { .. } => panic!("hash probes need actual bounded evidence"),
    };
    Receipt { turn, outcome }
}

#[tokio::test]
async fn durable_begin_binds_exact_floor_and_pending() {
    let config = config();
    let (head, intent) = pending(&config, 0).await;
    assert!(head.pending.as_ref().unwrap().intent == intent);
    assert_eq!(head.floor.generation.get(), 1);
    assert_eq!(head.floor.lease_sequence.get(), 1);
    assert_eq!(head.floor.clock_floor.get(), 101);
}

#[tokio::test]
async fn repeated_unknown_begin_never_regenerates_permit() {
    let config = config();
    let (head, intent) = pending(&config, 0).await;
    assert!(head
        .begin(
            &config,
            intent,
            &token(&config, 0, 1).await,
            "c".repeat(64),
            clock(102)
        )
        .is_err());
}

#[tokio::test]
async fn unknown_write_blocks_head_and_new_write_after_lossless_restart() {
    let config = config();
    let (head, _) = pending(&config, 0).await;
    let raw = serde_json::to_string(&head).unwrap();
    assert!(raw.contains("\"lease_sequence\":\"1\""));
    let config_raw = serde_json::to_string(&config).unwrap();
    assert!(config_raw.contains("\"9007199254740993\""));
    let restored_config = Config::parse(&config_raw).unwrap();
    assert_eq!(
        restored_config.cohorts[0].association.binding_id.get(),
        9_007_199_254_740_993
    );
    let restored: Head = serde_json::from_str(&raw).unwrap();
    assert!(restored == head);
    for index in [0, 1] {
        assert!(restored
            .begin(
                &config,
                intent(&config, index, "new-op"),
                &token(&config, index, 1).await,
                "c".repeat(64),
                clock(102)
            )
            .is_err());
    }
}

#[tokio::test]
async fn unknown_observation_blocks_put_until_terminal() {
    let config = config();
    let (head, _) = pending(&config, 1).await;
    assert!(head
        .begin(
            &config,
            intent(&config, 0, "new-op"),
            &token(&config, 0, 1).await,
            "c".repeat(64),
            clock(102)
        )
        .is_err());
    let complete = head.terminal(&receipt(&head)).unwrap();
    assert!(complete
        .begin(
            &config,
            intent(&config, 0, "new-op"),
            &token(&config, 0, 1).await,
            "c".repeat(64),
            clock(102)
        )
        .is_ok());
}

#[tokio::test]
async fn terminal_replay_needs_no_current_lease_and_only_clears_matching_turn() {
    let config = config();
    let (head, intent) = pending(&config, 0).await;
    let receipt = receipt(&head);
    let complete = head.terminal(&receipt).unwrap();
    let (replayed, reply) = head.replay(&intent, &receipt).unwrap();
    assert!(replayed.pending.is_none());
    assert!(matches!(reply, GuardReply::Terminal { .. }));
    assert!(complete.replay(&intent, &receipt).is_ok());
}

#[tokio::test]
async fn old_receipt_replay_never_clears_unrelated_pending() {
    let config = config();
    let (head, old_intent) = pending(&config, 0).await;
    let old = receipt(&head);
    let complete = head.terminal(&old).unwrap();
    let (next, _) = complete
        .begin(
            &config,
            intent(&config, 0, "op-two"),
            &token(&config, 0, 1).await,
            "c".repeat(64),
            clock(102),
        )
        .unwrap();
    assert!(next.replay(&old_intent, &old).unwrap().0.pending == next.pending);
}

#[tokio::test]
async fn changed_body_and_context_cannot_replay_exact_operation() {
    let config = config();
    let (head, old_intent) = pending(&config, 0).await;
    let old = receipt(&head);
    let mut changed = old_intent.clone();
    changed.effect = Effect::Put {
        sha256: "d".repeat(64),
        bytes: 3,
    };
    assert!(head.replay(&changed, &old).is_err());
    changed = old_intent;
    changed.context = "d".repeat(64);
    assert!(head.replay(&changed, &old).is_err());
}

#[tokio::test]
async fn changed_nonce_and_outcome_cannot_settle_unknown_turn() {
    let config = config();
    let (head, _) = pending(&config, 0).await;
    let mut terminal = receipt(&head);
    terminal.turn.dispatch_nonce = "c".repeat(64);
    assert!(head.terminal(&terminal).is_err());
    terminal = receipt(&head);
    terminal.outcome = Outcome::HistoricalHead { object: None };
    assert!(head.terminal(&terminal).is_err());
}

#[tokio::test]
async fn unknown_turn_is_unchanged_by_elapsed_time_and_sql_labels() {
    let config = config();
    let (head, intent) = pending(&config, 0).await;
    let copy = head.clone();
    assert!(head
        .begin(&config, intent, &[], "c".repeat(64), clock(1000))
        .is_err());
    assert!(head == copy);
}

#[tokio::test]
async fn final_validation_after_begin_rejects_expiry_and_clock_rollback() {
    let config = config();
    let token = token(&config, 0, 0).await;
    let (head, intent) = pending(&config, 0).await;
    for at in [100, 128, 130] {
        assert!(config
            .verifier()
            .unwrap()
            .validate_lease(
                &token,
                &config.cohorts[0],
                &config.timing_profile,
                &head.floor,
                &intent.scope.full_key,
                LeaseEffect::Put,
                clock(at)
            )
            .is_err());
    }
    assert!(head.pending.is_some());
}

#[tokio::test]
async fn signed_lease_cannot_change_permanent_domain_or_config() {
    let config = config();
    let intent = intent(&config, 0, "one");
    let head = Head::initialize(&config, &intent, clock(100)).unwrap();
    let mut other = config.clone();
    other.guard_namespace_id = "other-namespace".into();
    assert!(head.validate(&other, &intent.scope).is_err());
    other = config.clone();
    other.issuer_public_key = "9".repeat(64);
    assert!(head
        .begin(
            &other,
            intent,
            &token(&config, 0, 0).await,
            "b".repeat(64),
            clock(101)
        )
        .is_err());
}

#[tokio::test]
async fn local_denied_and_retired_floors_reject_without_clearing_pending() {
    let config = config();
    let intent = intent(&config, 0, "one");
    let (head, _) = pending(&config, 0).await;
    let complete = head.terminal(&receipt(&head)).unwrap();
    for retired in [false, true] {
        let mut floor = complete.clone();
        floor.floor.denied = true;
        floor.floor.retired = retired;
        assert!(floor
            .begin(
                &config,
                intent.clone(),
                &token(&config, 0, 1).await,
                "c".repeat(64),
                clock(102)
            )
            .is_err());
    }
}

#[tokio::test]
async fn receipt_capacity_blocks_new_begin_but_keeps_exact_replay() {
    let config = config();
    let (head, intent) = pending(&config, 0).await;
    let receipt = receipt(&head);
    let mut complete = head.terminal(&receipt).unwrap();
    complete.receipts = integer(super::state::MAX_RECEIPTS);
    assert!(complete
        .begin(
            &config,
            intent.clone(),
            &token(&config, 0, 1).await,
            "c".repeat(64),
            clock(102)
        )
        .is_err());
    assert!(complete.replay(&intent, &receipt).is_ok());
}

#[test]
fn closed_guard_auth_uses_distinct_key_and_domain() {
    let config = config();
    let intent = intent(&config, 0, "one");
    let request = GuardRequest {
        domain: protocol::DOMAIN.into(),
        scope: intent.scope.clone(),
        operation: GuardOperation::Begin {
            intent,
            lease: String::new(),
        },
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    let guard = StorageWorkKey::new([1; 32]).unwrap();
    let public = StorageWorkKey::new([2; 32]).unwrap();
    assert!(protocol::authenticated(&guard, &guard.sign_body(&bytes).unwrap(), &bytes).is_ok());
    assert!(protocol::authenticated(&guard, &public.sign_body(&bytes).unwrap(), &bytes).is_err());
    let mut changed = request;
    changed.domain = "aos.external-object-application.v1".into();
    let changed = serde_json::to_vec(&changed).unwrap();
    assert!(
        protocol::authenticated(&guard, &guard.sign_body(&changed).unwrap(), &changed).is_err()
    );
}

#[test]
fn configured_cohort_cannot_be_forked_or_token_derived() {
    let mut config = config();
    config.cohorts[0].publication_digest = "0".repeat(64);
    assert!(config.validate().is_err());
    config = super::tests::config();
    config.publications.clear();
    assert!(config.validate().is_err());
}

#[test]
fn full_key_and_body_metadata_are_bounded_without_truncation() {
    let config = config();
    assert!(config.scope(&config.cohorts[0], "x".repeat(1025)).is_err());
    let mut intent = intent(&config, 0, "one");
    intent.effect = Effect::Put {
        sha256: "a".repeat(64),
        bytes: 131073,
    };
    assert!(intent.validate().is_err());
}

#[tokio::test]
async fn historical_head_receipt_replay_is_explicit_and_not_new_observation() {
    let config = config();
    let (head, intent) = pending(&config, 1).await;
    let receipt = receipt(&head);
    let (_, reply) = head.replay(&intent, &receipt).unwrap();
    assert!(matches!(
        reply,
        GuardReply::Terminal {
            receipt: Receipt {
                outcome: Outcome::HistoricalHead { .. },
                ..
            }
        }
    ));
}

pub(super) fn application(
) -> aos_hub_core::storage_authority::external_object::ExternalObjectRequest {
    aos_hub_core::storage_authority::external_object::ExternalObjectRequest {
        version: 1,
        domain:
            aos_hub_core::storage_authority::external_object::EXTERNAL_OBJECT_APPLICATION_DOMAIN
                .into(),
        operation_id: "retained-business-effect".into(),
        binding_write_revision: integer(1),
        plan: StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "fixture-deployment".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 1,
            placement_resource_version: 1,
            binding_id: 1,
            binding_resource_version: 1,
            binding_kind: "s3".into(),
            binding_snapshot_revision: Some("b".repeat(64)),
            credential_references: vec![StorageCredentialSelector {
                purpose: "read".into(),
                generation: 1,
            }],
            placement_prefix: "objects".into(),
            operation: StorageWorkOperation::Head {
                path: "blob".into(),
            },
        },
        lease: String::new(),
    }
}

#[test]
fn application_envelope_roundtrip_and_unknown_fields_are_closed() {
    use aos_hub_core::storage_authority::external_object::ExternalObjectRequest;
    let key = StorageWorkKey::new([2; 32]).unwrap();
    let (body, signature) = application().sign(&key, "fixture-deployment", 101).unwrap();
    assert!(ExternalObjectRequest::authenticate(
        &key,
        &signature,
        &body,
        "fixture-deployment",
        101
    )
    .is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    value["unapproved"] = serde_json::json!(true);
    let body = serde_json::to_vec(&value).unwrap();
    assert!(ExternalObjectRequest::authenticate(
        &key,
        &key.sign_body(&body).unwrap(),
        &body,
        "fixture-deployment",
        101
    )
    .is_err());
}

#[test]
fn application_grant_expiry_and_unsupported_operations_reject() {
    let mut request = application();
    assert!(request.validate("fixture-deployment", 131).is_err());
    request.plan.operation = StorageWorkOperation::DeleteProbe {
        path: ".aos-internal/conditional-delete-probes/one".into(),
    };
    assert!(request.validate("fixture-deployment", 101).is_err());
}

#[tokio::test]
async fn reusable_lower_sequence_same_cohort_preserves_largest_witness() {
    let config = config();
    let intent = intent(&config, 0, "newer-token-turn");
    let head = Head::initialize(&config, &intent, clock(100)).unwrap();
    let (head, _) = head
        .begin(
            &config,
            intent,
            &token(&config, 0, 1).await,
            "b".repeat(64),
            clock(101),
        )
        .unwrap();
    let complete = head.terminal(&receipt(&head)).unwrap();
    let (next, _) = complete
        .begin(
            &config,
            super::tests::intent(&config, 0, "old-reusable-token-turn"),
            &token(&config, 0, 0).await,
            "c".repeat(64),
            clock(102),
        )
        .unwrap();
    assert_eq!(next.floor.lease_sequence.get(), 2);
    assert!(next.floor.payload_digest == complete.floor.payload_digest);
}

#[tokio::test]
async fn reusable_lower_sequence_different_cohort_keeps_same_epoch_witness() {
    let config = config();
    let read_intent = intent(&config, 1, "newer-read-token-turn");
    let head = Head::initialize(&config, &read_intent, clock(100)).unwrap();
    let (head, _) = head
        .begin(
            &config,
            read_intent,
            &token(&config, 1, 1).await,
            "b".repeat(64),
            clock(101),
        )
        .unwrap();
    let complete = head.terminal(&receipt(&head)).unwrap();
    let (next, _) = complete
        .begin(
            &config,
            intent(&config, 0, "older-write-token-turn"),
            &token(&config, 0, 0).await,
            "c".repeat(64),
            clock(102),
        )
        .unwrap();
    assert_eq!(next.floor.lease_sequence.get(), 2);
    assert!(next.floor.payload_digest == complete.floor.payload_digest);
}

#[tokio::test]
async fn corrupt_retained_floor_denies_terminal_and_historical_replay() {
    let config = config();
    let (head, _) = pending(&config, 0).await;
    let mut corrupted = head.clone();
    corrupted.floor.publication_digest = None;
    assert!(corrupted.validate(&config, &head.scope).is_err());
    corrupted = head.clone();
    corrupted.floor.payload_digest = Some("not-a-canonical-digest".into());
    assert!(corrupted.validate(&config, &head.scope).is_err());
}

#[test]
fn application_writer_revision_is_required_and_lossless() {
    use aos_hub_core::storage_authority::external_object::ExternalObjectRequest;
    let key = StorageWorkKey::new([2; 32]).unwrap();
    let mut request = application();
    request.binding_write_revision = integer(9_007_199_254_740_997);
    let (body, signature) = request.sign(&key, "fixture-deployment", 101).unwrap();
    let decoded =
        ExternalObjectRequest::authenticate(&key, &signature, &body, "fixture-deployment", 101)
            .unwrap();
    assert_eq!(decoded.binding_write_revision.get(), 9_007_199_254_740_997);
    let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("binding_write_revision");
    let body = serde_json::to_vec(&value).unwrap();
    assert!(ExternalObjectRequest::authenticate(
        &key,
        &key.sign_body(&body).unwrap(),
        &body,
        "fixture-deployment",
        101
    )
    .is_err());
}

pub(super) fn snapshot(config: &Config) -> aos_hub_core::storage_work::StorageBindingSnapshot {
    let cohort = &config.cohorts[0];
    aos_hub_core::storage_work::StorageBindingSnapshot {
        version: 1,
        deployment_id: "fixture-deployment".into(),
        binding_id: cohort.association.binding_id.get(),
        binding_resource_version: cohort.association.binding_resource_version.get(),
        binding_stable_id: cohort.association.binding_stable_id.clone(),
        binding_kind: "s3".into(),
        object_bucket: cohort.alias.spec.bucket.clone(),
        object_prefix: cohort.association.binding_prefix.clone(),
        endpoint_scheme: "https".into(),
        endpoint_host_kind: "dns".into(),
        endpoint_host_bytes: b"objects.example.invalid".to_vec(),
        endpoint_port: Some(443),
        signing_region: "auto".into(),
        access_mode: "private".into(),
        credentials: config.publications[0]
            .attestation
            .as_ref()
            .unwrap()
            .credentials
            .iter()
            .map(
                |reference| aos_hub_core::storage_work::StorageCredentialReference {
                    purpose: reference.purpose.clone(),
                    generation: reference.generation,
                    secret_version_ref: reference.secret_version_ref.clone(),
                    fingerprint: reference.credential_fingerprint.clone(),
                },
            )
            .collect(),
        issued_at: 100,
        expires_at: 130,
    }
}

#[tokio::test]
async fn signature_validation_success_cannot_bypass_expiry_at_final_observation() {
    let config = config();
    let (head, intent) = pending(&config, 0).await;
    let signed = token(&config, 0, 0).await;
    let validated = config
        .verifier()
        .unwrap()
        .validate_lease(
            &signed,
            &config.cohorts[0],
            &config.timing_profile,
            &head.floor,
            &intent.scope.full_key,
            LeaseEffect::Put,
            clock(101),
        )
        .unwrap();
    let request = application();
    let binding = snapshot(&config);
    assert!(request
        .check_dispatch_time(&binding, &validated, &head.floor, clock(127))
        .is_ok());
    // The cryptographic check accepted at101. CPU/await time crosses the safe
    // lease bound before the actual invocation: the last scalar check rejects.
    assert!(request
        .check_dispatch_time(&binding, &validated, &head.floor, clock(128))
        .is_err());
    assert!(head.pending.is_some());
}

#[tokio::test]
async fn final_observation_rechecks_application_snapshot_and_clock() {
    let config = config();
    let (head, intent) = pending(&config, 0).await;
    let signed = token(&config, 0, 0).await;
    let validated = config
        .verifier()
        .unwrap()
        .validate_lease(
            &signed,
            &config.cohorts[0],
            &config.timing_profile,
            &head.floor,
            &intent.scope.full_key,
            LeaseEffect::Put,
            clock(101),
        )
        .unwrap();
    let mut request = application();
    let mut binding = snapshot(&config);
    assert!(request
        .check_dispatch_time(&binding, &validated, &head.floor, clock(100))
        .is_err());
    request.plan.expires_at = 101;
    assert!(request
        .check_dispatch_time(&binding, &validated, &head.floor, clock(102))
        .is_err());
    request.plan.expires_at = 130;
    binding.expires_at = 101;
    assert!(request
        .check_dispatch_time(&binding, &validated, &head.floor, clock(102))
        .is_err());
    binding.expires_at = 130;
    assert!(request
        .check_dispatch_time(
            &binding,
            &validated,
            &head.floor,
            LeaseClock {
                observed_at: 102,
                uncertainty: 3
            }
        )
        .is_err());
    assert!(request
        .check_dispatch_time(&binding, &validated, &head.floor, clock(i64::MAX))
        .is_err());
}
