//! Actual reviewed SQL publication and independent Native issuer fixture.

use std::path::Path;
use std::sync::Arc;

use aos_hub_core::{
    db::{Database, TokenAuth},
    domain::{Permission, Principal, Scope},
    service::RpcService,
    storage_authority::{
        lease::{
            BoundedLeaseRevocationPolicy, LeaseCohort, LeaseEffect, LeaseInteger, LeasePurpose,
            LeaseTimingProfile,
        },
        PhysicalStorageAuthorityId,
    },
};
use aos_proto_types::hub_v1 as pb;
use serde_json::{json, Value};

use crate::{
    auth::jwt::JwtKeys, authority_journal::IssuerInstallation,
    authority_server::AuthorityConfiguration,
};

const AUTHORITY: &str = "00000000-0000-4000-8000-000000000075";
const NAMESPACE: &str = "connected-copy-guard";
const EXECUTOR: &str = "connected-copy-worker";
pub(super) const RENEWAL: &str = "fixture-copy-renewal-independent-role-key";
pub(super) const APPLICATION: &str = "connected-copy-application-key-independent";
pub(super) const GUARD: &str = "fixture-copy-permanent-guard-independent-key";

async fn decision(
    rpc: &RpcService,
    auth: &str,
    input: pb::storage_authority_decision::Input,
    version: &str,
    id: &str,
) {
    let reviewed = rpc
        .plan_storage_authority_decision(
            Some(auth),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(pb::StorageAuthorityDecision { input: Some(input) }),
                expected_resource_version: version.into(),
                idempotency_key: format!("copy-{id}-plan"),
            },
        )
        .await
        .unwrap();
    let plan = reviewed.plan.unwrap();
    rpc.apply_storage_authority_decision(
        Some(auth),
        pb::ApplyStorageAuthorityDecisionRequest {
            plan_id: plan.plan_id,
            confirmation_hash: plan.confirmation_hash,
            idempotency_key: format!("copy-{id}-apply"),
        },
    )
    .await
    .unwrap();
}

pub(super) async fn configure(
    db: Arc<Database>,
    binding_id: i64,
    root: &Path,
) -> (
    AuthorityConfiguration,
    Value,
    Value,
    Arc<RpcService>,
    String,
) {
    configure_bindings(db, &[binding_id], root).await
}

pub(super) async fn configure_bindings(
    db: Arc<Database>,
    binding_ids: &[i64],
    root: &Path,
) -> (
    AuthorityConfiguration,
    Value,
    Value,
    Arc<RpcService>,
    String,
) {
    assert!(!binding_ids.is_empty() && binding_ids.len() <= 2);
    let user = db
        .create_user("copy-owner@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let jwt = JwtKeys::random();
    let session = db.create_session(user, 3600, 1).await.unwrap();
    let session = db.validate_session(&session).await.unwrap().unwrap();
    let auth = format!(
        "Bearer {}",
        jwt.mint(
            &TokenAuth {
                token_id: format!("browser-session-{user}"),
                owner: Principal::user(user),
                owner_incarnation: Some(session.owner_incarnation),
                browser_session_id_hash: Some(session.session_id_hash),
                scope: Scope::root(),
                permissions: vec![
                    Permission::StorageManage,
                    Permission::PlacementManage,
                    Permission::PlacementRead,
                    Permission::BindingManage,
                    Permission::BindingRead
                ],
            },
            3600
        )
        .unwrap()
    );
    let http = reqwest::Client::new();
    let rpc = Arc::new(RpcService::new(
        db.clone(),
        jwt,
        "https://localhost".into(),
        Arc::new(crate::ratelimit::RateLimiter::new()),
        Arc::new(crate::coreports::HubSurfaceProvider::new(
            db.clone(),
            http.clone(),
            None,
        )),
        Arc::new(crate::coreports::HubSurfaceWriteProvider::new(
            db.clone(),
            http,
        )),
        Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        Arc::new(crate::coreports::HubReindexer::new(db.clone(), None)),
        Arc::new(aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(db.clone())),
        None,
    ));
    use pb::storage_authority_decision::Input;
    decision(
        &rpc,
        &auth,
        Input::Create(pb::CreatePhysicalStorageAuthorityDecision {
            authority_id: AUTHORITY.into(),
            guard_namespace_id: NAMESPACE.into(),
            physical_resource_evidence_digest: "1".repeat(64),
            qualification_digest: "2".repeat(64),
            qualified_managed_prefix: Some("managed".into()),
        }),
        "",
        "create",
    )
    .await;
    let authority = rpc
        .get_storage_authority(
            Some(&auth),
            pb::GetStorageAuthorityRequest {
                authority_id: AUTHORITY.into(),
            },
        )
        .await
        .unwrap();
    decision(
        &rpc,
        &auth,
        Input::ApproveAlias(pb::ApproveStorageAuthorityAliasDecision {
            alias_id: "copy-alias".into(),
            authority_id: AUTHORITY.into(),
            address: Some(pb::StorageAuthorityAddress {
                host: Some(pb::storage_authority_address::Host::DnsName(
                    "s3.fleet.test".into(),
                )),
                port: 443,
                bucket: "fixture-bucket".into(),
            }),
            equivalence_evidence_digest: "3".repeat(64),
        }),
        &authority.resource_version,
        "alias",
    )
    .await;
    let mut members = Vec::new();
    let mut association_ids = Vec::new();
    for (index, &binding_id) in binding_ids.iter().enumerate() {
        let association_id = if index == 0 {
            "copy-association".into()
        } else {
            format!("copy-association-{index}")
        };
        association_ids.push(association_id.clone());
        let binding = db.binding(binding_id).await.unwrap().unwrap();
        decision(
            &rpc,
            &auth,
            Input::AssociateBinding(pb::AssociateStorageAuthorityBindingDecision {
                association_id: association_id.clone(),
                authority_id: AUTHORITY.into(),
                alias_id: "copy-alias".into(),
                binding_id: binding_id.to_string(),
                binding_stable_id: binding.stable_id,
                binding_resource_version: binding.resource_version.to_string(),
                binding_write_revision: "1".into(),
                binding_prefix: binding.object_prefix.clone().unwrap(),
            }),
            &binding.resource_version.to_string(),
            &format!("association-{index}"),
        )
        .await;
        for purpose in ["list", "read", "write"] {
            let revision = db
                .current_binding_credential(binding_id, purpose)
                .await
                .unwrap()
                .unwrap();
            members.push(pb::StorageAuthorityCredentialMember {
                association_id: association_id.clone(),
                purpose: purpose.into(),
                generation: revision.generation.to_string(),
                secret_version_ref: revision.secret_version_ref,
                credential_fingerprint: revision.credential_fingerprint,
            });
        }
    }
    decision(
        &rpc,
        &auth,
        Input::Attest(pb::AttestStorageAuthorityExclusivityDecision {
            attestation_id: "copy-attestation".into(),
            authority_id: AUTHORITY.into(),
            managed_prefix: "managed".into(),
            qualification_digest: "2".repeat(64),
            provider_policy_evidence_digest: "4".repeat(64),
            executor_identity: EXECUTOR.into(),
            credentials: members,
            valid_until: aos_hub_core::clock::now_unix_secs() + 3600,
        }),
        &authority.resource_version,
        "attest",
    )
    .await;
    decision(
        &rpc,
        &auth,
        Input::SetAdmission(pb::SetStorageAuthorityAdmissionDecision {
            authority_id: AUTHORITY.into(),
            expected_generation: "0".into(),
            expected_digest: None,
            guard_namespace_id: NAMESPACE.into(),
            state: pb::StorageAuthorityDesiredState::Admitted as i32,
            attestation_id: Some("copy-attestation".into()),
            association_ids: association_ids.clone(),
        }),
        "0",
        "admit",
    )
    .await;
    let publication = db
        .storage_authority_publication(
            &PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap(),
            NAMESPACE,
            EXECUTOR,
        )
        .await
        .unwrap();
    let installation = IssuerInstallation {
        format_version: 1,
        authority: publication.authority.clone(),
        issuer_resource_id: "copy-fixture-retained-issuer".into(),
        runtime_identity: "copy-fixture-native-issuer".into(),
        executor_identity: EXECUTOR.into(),
    };
    let timing = LeaseTimingProfile {
        profile_id: "copy-controlled-clock-policy".into(),
        review_digest: "5".repeat(64),
        maximum_lifetime: LeaseInteger::new(30).unwrap(),
        maximum_clock_uncertainty: LeaseInteger::new(4).unwrap(),
    };
    let mut cohorts = Vec::new();
    let mut domains = Vec::new();
    for (index, association_id) in association_ids.iter().enumerate() {
        let binding = db.binding(binding_ids[index]).await.unwrap().unwrap();
        let cohort = |purpose, effects| {
            LeaseCohort::from_publication(
                &publication,
                EXECUTOR,
                association_id,
                purpose,
                binding.object_prefix.as_deref().unwrap(),
                effects,
            )
            .unwrap()
        };
        let read = cohort(
            LeasePurpose::Read,
            vec![LeaseEffect::Head, LeaseEffect::Read],
        );
        let list = cohort(LeasePurpose::List, vec![LeaseEffect::List]);
        let write = cohort(
            LeasePurpose::Write,
            vec![
                LeaseEffect::MultipartCreate,
                LeaseEffect::MultipartPart,
                LeaseEffect::MultipartComplete,
                LeaseEffect::MultipartAbort,
            ],
        );
        let mut contract = json!({"contract_id":"controlled-versioned-provider","evidence_digest":"7".repeat(64),
            "versioned_conditional_range_read":true,"versioned_multipart_complete":true,"private_incomplete_upload":true,
            "completed_upload_rejects_late_parts":true,"abort_closes_upload_id":true,"upload_part_checksum_enforced":true,"versioned_empty_put":false});
        if binding_ids.len() == 2 {
            // The controlled business gate exercises these actual 5 MiB source ranges.
            // This fixture declaration is not Hosted provider acceptance.
            contract["maximum_copy_read_range_bytes"] =
                json!(LeaseInteger::new(5 * 1024 * 1024).unwrap());
        }
        domains.push(
            json!({"issuer_installation":installation,"producer_profile_digest":"6".repeat(64),
            "provider_contract":contract,"read_cohort":read,"list_cohort":list,"write_cohort":write,
            "part_bytes":LeaseInteger::new(if index == 0 {5*1024*1024} else {8*1024*1024}).unwrap(),
            "provider_concurrency":if index == 0 {3} else {5},
            "maximum_list_page_objects":128,"maximum_list_pages":4}),
        );
        cohorts.extend([read, list, write]);
    }
    let object = json!({"version":1,"guard_namespace_id":NAMESPACE,"executor_identity":EXECUTOR,
        "issuer_key_id":"copy-fixture-issuer", "issuer_public_key":hex::encode(ed25519_dalek::SigningKey::from_bytes(&[17;32]).verifying_key().to_bytes()),
        "timing_profile":timing,"clock_uncertainty":2,"aliases":publication.aliases,"cohorts":cohorts,"publications":[publication]});
    let copy = json!({"version":if binding_ids.len() == 1 {1} else {2},"domains":domains});
    let configuration = AuthorityConfiguration {
        format_version: 1,
        listen: "127.0.0.1:0".parse().unwrap(),
        journal_file: root.join("issuer/state.db"),
        installation,
        hub_root: root.join("hub"),
        hub_sqlite_file: None,
        policy: BoundedLeaseRevocationPolicy {
            timing_profile: timing,
        },
        clock_uncertainty: LeaseInteger::new(2).unwrap(),
        clock_commit_latency: LeaseInteger::new(1).unwrap(),
        clock_recovery: None,
        issuance_enabled: true,
        publisher_key_file: root.join("publisher.key"),
        renewal_key_file: root.join("renewal.key"),
        signing_seed_file: root.join("signing.key"),
        signing_key_id: "copy-fixture-issuer".into(),
        tls: None,
    };
    (configuration, object, copy, rpc, auth)
}
