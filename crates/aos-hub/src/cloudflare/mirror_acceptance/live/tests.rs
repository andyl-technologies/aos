//! Synthetic public-key closure tests, not empirical live qualification evidence.

use aos_hub_core::mirror_acceptance::live::{
    MirrorLiveCase, MirrorLiveMeasurement, MirrorLivePurpose,
};
use aos_hub_core::mirror_acceptance::MirrorAcceptanceExecution;
use aos_hub_core::mirror_work::digest;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn chain() -> (
    HybridDeployConfig,
    DirectWorkerDeploymentIdentity,
    HybridMirrorLiveAcceptanceConfig,
    SigningKey,
) {
    let (cfg, identity, prerequisites, reviewer) = super::super::tests::chain();
    use MirrorLiveCase::*;
    let cases = [
        FreshPointer,
        Head,
        FullPack,
        Missing,
        RedirectRefusal,
        UnsafeSourceRefusal,
        ExpiredDispatchRefusal,
        ForeignContextRefusal,
        EncodingRefusal,
        LengthRefusal,
        Cancellation,
        MetadataDuringBulk,
        BoundedMetadataQuery,
    ];
    let mut live = MirrorLiveAcceptanceArtifact {
        version: 1,
        purpose: MirrorLivePurpose::ManagedMirrorLiveDeliveryV1,
        execution: MirrorAcceptanceExecution::Hosted,
        mirror_artifact_sha256: digest(&prerequisites.mirror).unwrap(),
        maximum_bytes: 8 * 1024 * 1024,
        reader_bytes: 64 * 1024,
        stream_seconds: 600,
        measurements: cases
            .into_iter()
            .map(|case| MirrorLiveMeasurement {
                case,
                report_sha256: "aa".repeat(32),
                request_sha256: "bb".repeat(32),
                response_sha256: "cc".repeat(32),
                samples: 1,
                violations: 0,
                provider_dispatches: if matches!(
                    case,
                    UnsafeSourceRefusal | ExpiredDispatchRefusal | ForeignContextRefusal
                ) {
                    0
                } else {
                    1
                },
                client_bytes: match case {
                    FullPack => 8 * 1024 * 1024,
                    BoundedMetadataQuery => 128 * 1024,
                    _ => 0,
                },
            })
            .collect(),
        memory_report_sha256: "dd".repeat(32),
        peak_worker_bytes: 64 * 1024 * 1024,
        memory_samples: 2,
        native_bulk_bytes: 0,
        destination_mutations: 0,
        release_pack_sha256: prerequisites
            .mirror
            .evidence
            .release
            .release_pack_sha256
            .clone(),
        issued_at: 100,
        valid_until: 200,
        signature: String::new(),
    };
    live.signature = hex::encode(reviewer.sign(&live.signing_bytes().unwrap()).to_bytes());
    (
        cfg,
        identity,
        HybridMirrorLiveAcceptanceConfig {
            prerequisites,
            live,
        },
        reviewer,
    )
}

#[test]
fn separate_live_record_requires_the_complete_signed_prerequisite_chain() {
    let (cfg, identity, acceptance, _) = chain();
    let record = acceptance.record(&cfg, &identity, 150).unwrap();

    assert_eq!(
        record.key,
        mirror_live_acceptance_key(&digest(&acceptance.prerequisites.mirror).unwrap()).unwrap()
    );
    assert_eq!(record.bytes, serde_json::to_vec(&acceptance.live).unwrap());
    assert!(record.bytes.len() <= LIVE_ACCEPTANCE_MAX_BYTES);
    assert_ne!(
        record.key,
        super::super::mirror_acceptance_key(
            &cfg.deployment_id,
            &identity.source_digest,
            &identity.script_version
        )
        .unwrap()
    );
    assert_ne!(
        record.key,
        super::super::mirror_pack_acceptance_key(
            &cfg.deployment_id,
            &identity.source_digest,
            &identity.script_version
        )
        .unwrap()
    );
}

#[test]
fn invalid_prerequisites_identity_role_domain_and_original_cutoff_refuse_live_record() {
    let (cfg, identity, acceptance, reviewer) = chain();
    for change in 0..10 {
        let mut cfg = cfg.clone();
        let mut identity = identity.clone();
        let mut acceptance = acceptance.clone();
        match change {
            0 => acceptance.prerequisites.pack = None,
            1 => acceptance
                .prerequisites
                .pack
                .as_mut()
                .unwrap()
                .signature
                .clear(),
            2 => acceptance.live.signature = acceptance.prerequisites.mirror.signature.clone(),
            3 => acceptance.live.mirror_artifact_sha256 = "ab".repeat(32),
            4 => acceptance.live.release_pack_sha256 = "ba".repeat(32),
            5 => identity.source_digest = "ef".repeat(32),
            6 => {
                identity
                    .managed_profile
                    .as_mut()
                    .unwrap()
                    .credential_generation = aos_hub_core::direct_upload::WireInteger::new(2)
            }
            7 => {
                cfg.mirror_trust.as_mut().unwrap().public_key =
                    hex::encode(SigningKey::from_bytes(&[77; 32]).verifying_key().as_bytes())
            }
            8 => {
                acceptance.live.execution = MirrorAcceptanceExecution::Controlled;
                acceptance.live.signature = hex::encode(
                    reviewer
                        .sign(&acceptance.live.signing_bytes().unwrap())
                        .to_bytes(),
                );
            }
            _ => cfg.direct_upload_acceptance = None,
        }
        assert!(
            acceptance.record(&cfg, &identity, 150).is_err(),
            "changed chain {change}"
        );
    }
    // The verifier consumes the profile's conservative latest time (+1 here).
    assert!(acceptance.record(&cfg, &identity, 98).is_err());
    assert!(acceptance.record(&cfg, &identity, 99).is_ok());
    assert!(acceptance.record(&cfg, &identity, 199).is_err());
}

#[test]
fn thirteen_case_query_closure_and_independent_stream_geometry_are_required() {
    let (cfg, identity, acceptance, reviewer) = chain();
    for change in 0..6 {
        let mut bad = acceptance.clone();
        match change {
            0 => bad
                .live
                .measurements
                .retain(|case| case.case != MirrorLiveCase::BoundedMetadataQuery),
            1 => {
                bad.live
                    .measurements
                    .iter_mut()
                    .find(|case| case.case == MirrorLiveCase::BoundedMetadataQuery)
                    .unwrap()
                    .client_bytes = 256 * 1024 + 1
            }
            2 => {
                bad.live
                    .measurements
                    .iter_mut()
                    .find(|case| case.case == MirrorLiveCase::BoundedMetadataQuery)
                    .unwrap()
                    .provider_dispatches = 0
            }
            3 => bad.live.maximum_bytes = bad.prerequisites.mirror.maximum_object_bytes + 1,
            4 => bad.live.stream_seconds = 601,
            _ => bad.live.native_bulk_bytes = 1,
        }
        bad.live.signature =
            hex::encode(reviewer.sign(&bad.live.signing_bytes().unwrap()).to_bytes());
        assert!(
            bad.record(&cfg, &identity, 150).is_err(),
            "invalid closure {change}"
        );
    }

    // An independently measured stream ceiling need not equal the separate
    // pack-parser ceiling. Neither review changes the bounded query contract.
    let mut larger_stream = acceptance;
    larger_stream.live.maximum_bytes = 16 * 1024 * 1024;
    larger_stream
        .live
        .measurements
        .iter_mut()
        .find(|case| case.case == MirrorLiveCase::FullPack)
        .unwrap()
        .client_bytes = larger_stream.live.maximum_bytes;
    larger_stream.live.signature = hex::encode(
        reviewer
            .sign(&larger_stream.live.signing_bytes().unwrap())
            .to_bytes(),
    );
    assert!(larger_stream.record(&cfg, &identity, 150).is_ok());
}

#[tokio::test]
async fn bounded_closed_files_and_private_create_new_staging_preserve_existing_outputs() {
    let (_, _, acceptance, _) = chain();
    let directory = tempfile::tempdir().unwrap();
    let mirror = directory.path().join("mirror.json");
    let pack = directory.path().join("pack.json");
    let live = directory.path().join("live.json");
    std::fs::write(
        &mirror,
        serde_json::to_vec(&acceptance.prerequisites.mirror).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &pack,
        serde_json::to_vec(acceptance.prerequisites.pack.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    std::fs::write(&live, serde_json::to_vec(&acceptance.live).unwrap()).unwrap();
    assert!(HybridMirrorLiveAcceptanceConfig::from_files(&mirror, &pack, &live).is_ok());

    let mut unknown = serde_json::to_value(&acceptance.live).unwrap();
    unknown["accepted"] = serde_json::json!(true);
    std::fs::write(&live, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(HybridMirrorLiveAcceptanceConfig::from_files(&mirror, &pack, &live).is_err());
    std::fs::write(&live, vec![b' '; LIVE_ACCEPTANCE_MAX_BYTES + 1]).unwrap();
    assert!(HybridMirrorLiveAcceptanceConfig::from_files(&mirror, &pack, &live).is_err());

    let output = directory.path().join("new-output.json");
    let mut file = private_output(&output).await.unwrap();
    file.write_all(b"original").await.unwrap();
    drop(file);
    assert!(private_output(&output).await.is_err());
    assert_eq!(std::fs::read(&output).unwrap(), b"original");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn publication_arguments_expose_only_live_metadata_coordinates_and_a_file_path() {
    let (cfg, identity, acceptance, _) = chain();
    let record = acceptance.record(&cfg, &identity, 150).unwrap();
    let arguments = publication_arguments(
        &record.key,
        "reviewed-registry",
        Path::new("private/live.json"),
    );

    assert_eq!(
        arguments,
        [
            "kv",
            "key",
            "put",
            &record.key,
            "--namespace-id",
            "reviewed-registry",
            "--path",
            "private/live.json",
            "--remote"
        ]
    );
    assert!(!arguments
        .iter()
        .any(|argument| argument.contains(&acceptance.live.signature)));
}
