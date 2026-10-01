//! Signed installer chains and purpose-specific refusal before record publication.

use aos_hub_core::direct_upload::*;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::cloudflare::{HybridDirectUploadAcceptanceConfig, HybridDirectUploadDeployConfig};

mod fixtures;

pub(super) fn chain() -> (
    HybridDeployConfig,
    DirectWorkerDeploymentIdentity,
    HybridMirrorAcceptanceConfig,
    SigningKey,
) {
    let (mut direct, direct_public) = direct_worker_qualification_fixture();
    let evidence = &mut direct.evidence;
    evidence.runtime_measurement.maximum_verified_object_bytes =
        WireInteger::new(2 * 1024 * 1024 * 1024);
    evidence.runtime.maximum_object_bytes =
        evidence.runtime_measurement.maximum_verified_object_bytes;
    evidence.runtime.qualification_digest =
        direct_qualification_digest(&evidence.runtime_measurement).unwrap();
    evidence.bulk_queue.maximum_verified_object_bytes = evidence.runtime.maximum_object_bytes;
    evidence.metadata_queue.maximum_verified_object_bytes = evidence.runtime.maximum_object_bytes;
    direct.evidence_sha256 = direct_qualification_digest(evidence).unwrap();
    direct.signature = hex::encode(
        SigningKey::from_bytes(&[0x19; 32])
            .sign(&direct.signing_bytes().unwrap())
            .to_bytes(),
    );

    let raw = direct.evidence.managed_profile.as_ref().unwrap();
    let profile = DirectProtectedProfile::managed(
        raw.clone(),
        direct.evidence.private_stage_policy.clone().unwrap(),
        direct.evidence.runtime.clone(),
    )
    .unwrap();
    let mut cfg = crate::cloudflare::direct_upload::tests::config();
    cfg.bucket = raw.bucket_name.clone();
    cfg.direct_upload = Some(HybridDirectUploadDeployConfig {
        version: 1,
        deployment_id: raw.deployment_id.clone(),
        bucket_namespace: raw.bucket_namespace.clone(),
        account_id: raw.account_id.clone(),
        bucket_name: raw.bucket_name.clone(),
        credential_id: raw.credential_id.clone(),
        credential_generation: raw.credential_generation.get().to_string(),
        secret_version_ref: raw.secret_version_ref.clone(),
        checksum_algorithm: "md5".into(),
        clock_qualification: raw.clock_qualification.clone(),
        clock_uncertainty_seconds: raw.clock_uncertainty_seconds.get().to_string(),
        private_stage_policy: direct.evidence.private_stage_policy.clone().unwrap(),
    });
    cfg.direct_upload_trust.as_mut().unwrap().public_key = direct_public.clone();

    let identity = DirectWorkerDeploymentIdentity {
        version: 1,
        deployment_id: direct.deployment_id.clone(),
        public_origin: direct.public_origin.clone(),
        source_digest: direct.source_digest.clone(),
        script_version: direct.script_version.clone(),
        qualification_public_key: direct_public,
        clock_mode: direct.evidence.clock_policy.mode,
        clock_qualification: direct.evidence.clock_policy.commitment().unwrap(),
        clock_uncertainty_seconds: direct.evidence.clock.uncertainty_seconds,
        managed_profile: direct.evidence.managed_profile.clone(),
        private_stage_policy: direct.evidence.private_stage_policy.clone(),
        external_profiles: Vec::new(),
        bulk_queue: direct.evidence.bulk_queue.queue_name.clone(),
        metadata_queue: direct.evidence.metadata_queue.queue_name.clone(),
        bulk_queue_policy: direct.evidence.bulk_queue.delivery_policy.clone(),
        metadata_queue_policy: direct.evidence.metadata_queue.delivery_policy.clone(),
        maximum_parallel_objects: direct.evidence.runtime.maximum_parallel_objects,
        qualification_limits: None,
    };

    let reviewer = SigningKey::from_bytes(&[0xa1; 32]);
    cfg.mirror_trust = Some(HybridMirrorTrustConfig {
        public_key: hex::encode(reviewer.verifying_key().as_bytes()),
        namespace_id: "mirror-review-registry".into(),
    });
    let mut mirror = fixtures::artifact();
    mirror.public_origin = cfg.external_url.clone();
    mirror.source_digest = identity.source_digest.clone();
    mirror.script_version = identity.script_version.clone();
    mirror.protected_profile = Some(profile.clone());
    mirror.direct_evidence_sha256 = Some(direct.evidence_sha256.clone());
    mirror.evidence.roundtrips = ["none", "zstd", "metadata"]
        .into_iter()
        .map(|kind| fixtures::roundtrip(kind, &profile.digest().unwrap(), "final"))
        .collect();
    mirror.signature = hex::encode(reviewer.sign(&mirror.signing_bytes().unwrap()).to_bytes());
    let pack = fixtures::pack_artifact(&mirror, &reviewer);
    cfg.direct_upload_acceptance = Some(HybridDirectUploadAcceptanceConfig { artifact: direct });

    (
        cfg,
        identity,
        HybridMirrorAcceptanceConfig {
            mirror,
            pack: Some(pack),
        },
        reviewer,
    )
}

#[test]
fn signed_deployment_and_independent_purposes_produce_exact_bounded_records() {
    let (cfg, identity, acceptance, _) = chain();
    let guard = aos_hub_core::storage_work::StorageWorkKey::new(&[81; 32]).unwrap();
    let challenge = DirectWorkerDeploymentChallenge {
        version: 1,
        nonce: "ab".repeat(32),
        expires_at: WireInteger::new(175),
        external_selectors: Vec::new(),
    };
    let reply = DirectWorkerDeploymentReply {
        request: challenge.clone(),
        identity,
    };
    let signed = sign_direct_worker_deployment_reply(&guard, &reply).unwrap();
    let received = verify_direct_worker_deployment_reply(
        &guard,
        &signed.signature,
        &signed.body,
        &challenge,
        150,
    )
    .unwrap();

    let records = acceptance.records(&cfg, &received.identity, 150).unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].key,
        mirror_acceptance_key(
            &cfg.deployment_id,
            &received.identity.source_digest,
            &received.identity.script_version
        )
        .unwrap(),
    );
    assert_eq!(
        records[1].key,
        mirror_pack_acceptance_key(
            &cfg.deployment_id,
            &received.identity.source_digest,
            &received.identity.script_version
        )
        .unwrap(),
    );
    assert_ne!(records[0].key, records[1].key);
    assert_eq!(
        records[0].bytes,
        serde_json::to_vec(&acceptance.mirror).unwrap()
    );
    assert_eq!(
        records[1].bytes,
        serde_json::to_vec(acceptance.pack.as_ref().unwrap()).unwrap()
    );
    assert!(records.iter().all(|record| record.bytes.len() <= 64 * 1024));
}

#[test]
fn changed_source_profile_prerequisite_signature_and_cutoff_produce_no_records() {
    let (cfg, identity, acceptance, _) = chain();

    for change in 0..7 {
        let mut cfg = cfg.clone();
        let mut identity = identity.clone();
        let mut acceptance = acceptance.clone();
        match change {
            0 => identity.source_digest = "de".repeat(32),
            1 => {
                identity
                    .managed_profile
                    .as_mut()
                    .unwrap()
                    .credential_fingerprint = "ef".repeat(32)
            }
            2 => acceptance.mirror.direct_evidence_sha256 = Some("ad".repeat(32)),
            3 => acceptance.mirror.signature = "00".repeat(64),
            4 => acceptance.pack.as_mut().unwrap().mirror_artifact_sha256 = "ed".repeat(32),
            5 => {
                cfg.mirror_trust.as_mut().unwrap().public_key =
                    hex::encode(SigningKey::from_bytes(&[91; 32]).verifying_key().as_bytes())
            }
            _ => cfg.direct_upload_acceptance = None,
        }
        assert!(
            acceptance.records(&cfg, &identity, 150).is_err(),
            "changed chain {change}"
        );
    }
    assert!(acceptance.records(&cfg, &identity, 199).is_err());
}

#[test]
fn controlled_measurements_and_invalid_optional_pack_do_not_publish_ordinary_subset() {
    let (cfg, identity, mut acceptance, reviewer) = chain();
    acceptance.pack.as_mut().unwrap().signature.clear();
    assert!(acceptance.records(&cfg, &identity, 150).is_err());
    acceptance.pack = None;
    assert_eq!(acceptance.records(&cfg, &identity, 150).unwrap().len(), 1);

    acceptance.mirror.execution =
        aos_hub_core::mirror_acceptance::MirrorAcceptanceExecution::Controlled;
    acceptance.mirror.signature = hex::encode(
        reviewer
            .sign(&acceptance.mirror.signing_bytes().unwrap())
            .to_bytes(),
    );
    assert!(acceptance.records(&cfg, &identity, 150).is_err());
}

#[test]
fn renderer_selects_separate_review_binding_without_activating_a_purpose() {
    let (mut cfg, _, _, _) = chain();
    let rendered: toml::Value =
        toml::from_str(&super::super::render_hybrid_wrangler_toml(&cfg).unwrap()).unwrap();
    let vars = rendered["vars"].as_table().unwrap();
    assert_eq!(
        vars["HUB_MIRROR_QUALIFICATION_PUBLIC_KEY"].as_str(),
        Some(cfg.mirror_trust.as_ref().unwrap().public_key.as_str())
    );
    assert!(!vars.contains_key("HUB_MIRROR_ACCEPTED"));
    assert!(rendered["kv_namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["binding"].as_str() == Some("HUB_MIRROR_ACCEPTANCE")));

    cfg.direct_upload = None;
    assert!(super::super::render_hybrid_wrangler_toml(&cfg).is_err());
}

#[test]
fn closed_artifact_files_refuse_unknown_fields_and_oversized_documents() {
    let (_, _, acceptance, _) = chain();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mirror.json");
    std::fs::write(&path, serde_json::to_vec(&acceptance.mirror).unwrap()).unwrap();
    assert!(HybridMirrorAcceptanceConfig::from_files(&path, None).is_ok());

    let mut unknown = serde_json::to_value(&acceptance.mirror).unwrap();
    unknown["accepted"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(HybridMirrorAcceptanceConfig::from_files(&path, None).is_err());

    std::fs::write(&path, vec![b' '; MIRROR_ACCEPTANCE_MAX_BYTES + 1]).unwrap();
    assert!(HybridMirrorAcceptanceConfig::from_files(&path, None).is_err());
}
