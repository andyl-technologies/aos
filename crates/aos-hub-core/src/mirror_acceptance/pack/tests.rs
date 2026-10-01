//! Synthetic reviewer contract tests, never provider qualification evidence.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

fn signed_mirror() -> (MirrorAcceptanceArtifact, SigningKey) {
    let mut mirror = super::super::tests::artifact();
    let key = SigningKey::from_bytes(&[37; 32]);
    mirror.signature = hex::encode(key.sign(&mirror.signing_bytes().unwrap()).to_bytes());
    (mirror, key)
}

fn artifact(mirror: &MirrorAcceptanceArtifact, key: &SigningKey) -> MirrorPackAcceptanceArtifact {
    use MirrorPackSafetyCase::*;
    let geometry = MirrorPackGeometry::current();
    let cases = [
        BaseSelection,
        OffsetDeltaSelection,
        ReferenceDeltaSelection,
        EncodedChecksumRefusal,
        IndexCrcRefusal,
        SelectedOidRefusal,
        EncodedLimitRefusal,
        DecodedLimitRefusal,
        ExpiredReadRefusal,
        MetadataDuringInspection,
    ];
    let mut result = MirrorPackAcceptanceArtifact {
        version: 1,
        purpose: MirrorPackAcceptancePurpose::ManagedR2PackInspectionV1,
        execution: mirror.execution,
        mirror_artifact_sha256: digest(mirror).unwrap(),
        source_digest: mirror.source_digest.clone(),
        script_version: mirror.script_version.clone(),
        report_sha256: "aa".repeat(32),
        pairs: cases[..3]
            .iter()
            .map(|case| MirrorPackPairMeasurement {
                case: *case,
                observation_sha256: "bb".repeat(32),
                pack_sha256: "cc".repeat(32),
                index_sha256: "dd".repeat(32),
                pack_trailer_sha256: "ee".repeat(32),
                pack_bytes: geometry.pack_bytes,
                index_bytes: 2 * 1024 * 1024,
                peak_decoded_graph_bytes: geometry.decoded_graph_bytes,
                maximum_object_bytes: geometry.object_bytes,
                selected_oids: vec!["ff".repeat(32)],
                selected_result_sha256: "11".repeat(32),
                selected_bytes: 128 * 1024,
            })
            .collect(),
        safety: cases
            .iter()
            .map(|case| MirrorPackSafetyMeasurement {
                case: *case,
                observation_sha256: "22".repeat(32),
                query_sha256: "33".repeat(32),
                result_sha256: "44".repeat(32),
                samples: 1,
                violations: 0,
                provider_dispatches: if *case == ExpiredReadRefusal { 0 } else { 2 },
            })
            .collect(),
        geometry,
        memory_observation_sha256: "55".repeat(32),
        peak_worker_bytes: 64 * 1024 * 1024,
        memory_samples: 3,
        peak_wasm_bytes: 32 * 1024 * 1024,
        peak_js_sdk_bytes: 16 * 1024 * 1024,
        metadata_completed_during_inspection: 2,
        maximum_provider_requests: 3,
        native_bulk_bytes: 0,
        maximum_cpu_millis: 500,
        maximum_wall_millis: 1500,
        cpu_limit_millis: 1000,
        release_pack_sha256: mirror.evidence.release.release_pack_sha256.clone(),
        issued_at: 100,
        valid_until: 200,
        signature: String::new(),
    };
    sign(&mut result, key);
    result
}

fn sign(artifact: &mut MirrorPackAcceptanceArtifact, key: &SigningKey) {
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
}

#[test]
fn pack_parser_requires_its_separate_signature_and_exact_prerequisite_build() {
    let (mirror, key) = signed_mirror();
    let public = hex::encode(key.verifying_key().as_bytes());
    let mut pack = artifact(&mirror, &key);
    pack.require_production(&mirror, &public, 150, 8 * 1024 * 1024)
        .unwrap();
    pack.signature = mirror.signature.clone();
    assert!(pack.verify(&mirror, &public, 150).is_err());
    pack = artifact(&mirror, &key);
    let foreign = SigningKey::from_bytes(&[38; 32]);
    assert!(pack
        .verify(
            &mirror,
            &hex::encode(foreign.verifying_key().as_bytes()),
            150
        )
        .is_err());
    let mut changed = mirror.clone();
    changed.evidence.report_sha256 = "66".repeat(32);
    changed.signature = hex::encode(key.sign(&changed.signing_bytes().unwrap()).to_bytes());
    assert!(pack.verify(&changed, &public, 150).is_err());
    pack.source_digest = "77".repeat(32);
    sign(&mut pack, &key);
    assert!(pack.verify(&mirror, &public, 150).is_err());
}

#[test]
fn signed_pack_report_requires_boundary_memory_capacity_and_every_parser_case() {
    let (mirror, key) = signed_mirror();
    let public = hex::encode(key.verifying_key().as_bytes());
    for change in 0..11 {
        let mut pack = artifact(&mirror, &key);
        match change {
            0 => pack.safety.pop().map(|_| ()).unwrap(),
            1 => pack.safety[8].provider_dispatches = 1,
            2 => pack.peak_worker_bytes = 128 * 1024 * 1024,
            3 => pack.metadata_completed_during_inspection = 1,
            4 => pack.native_bulk_bytes = 1,
            5 => pack.maximum_cpu_millis = 1001,
            6 => pack.geometry.decoded_graph_bytes += 1,
            7 => pack.pairs.iter_mut().for_each(|pair| pair.pack_bytes -= 1),
            8 => pack
                .pairs
                .iter_mut()
                .for_each(|pair| pair.peak_decoded_graph_bytes -= 1),
            9 => pack.peak_js_sdk_bytes = 0,
            _ => pack.pairs[0].selected_bytes = 128 * 1024 + 1,
        }
        sign(&mut pack, &key);
        assert!(
            pack.verify(&mirror, &public, 150).is_err(),
            "missing measured boundary {change}"
        );
    }
}

#[test]
fn dispatch_wait_never_renews_pack_or_prerequisite_review_cutoff() {
    let (mirror, key) = signed_mirror();
    let public = hex::encode(key.verifying_key().as_bytes());
    let mut pack = artifact(&mirror, &key);
    pack.valid_until = 180;
    sign(&mut pack, &key);
    pack.require_production(&mirror, &public, 179, 8 * 1024 * 1024)
        .unwrap();
    assert!(pack
        .require_production(&mirror, &public, 180, 8 * 1024 * 1024)
        .is_err());
    assert!(pack.validate_dispatch_time(180).is_err());
    assert!(pack
        .require_production(&mirror, &public, 150, 8 * 1024 * 1024 + 1)
        .is_err());
    assert!(pack.validate_dispatch_time(99).is_err());
    assert!(mirror_pack_acceptance_key(
        "deployment-1",
        &mirror.source_digest,
        &mirror.script_version
    )
    .unwrap()
    .starts_with("mirror-pack-inspection-v1:"));
}

#[test]
fn independently_signed_controlled_pair_report_never_admits_hosted_inspection() {
    let (mut mirror, key) = signed_mirror();
    let crate::direct_upload::DirectProtectedProfile::Managed {
        profile,
        private_stage_policy,
        ..
    } = mirror.protected_profile.take().unwrap()
    else {
        panic!("managed fixture");
    };
    let pin =
        super::super::mirror_candidate_profile_digest(&profile, &private_stage_policy).unwrap();
    mirror.candidate_profile = Some(super::super::MirrorCandidateProfile {
        profile,
        private_stage_policy,
    });
    mirror.direct_evidence_sha256 = None;
    mirror.execution = MirrorAcceptanceExecution::Controlled;
    mirror.script_version =
        crate::direct_upload::direct_worker_emulated_script_id(&mirror.source_digest).unwrap();
    mirror.evidence.roundtrips = ["none", "zstd", "metadata"]
        .into_iter()
        .map(|kind| {
            super::super::tests::roundtrip(
                kind,
                &pin,
                ".aos-mirror-qualification/abababababababababababababababab/final",
            )
        })
        .collect();
    mirror.signature = hex::encode(key.sign(&mirror.signing_bytes().unwrap()).to_bytes());
    let pack = artifact(&mirror, &key);
    let public = hex::encode(key.verifying_key().as_bytes());
    pack.verify(&mirror, &public, 150).unwrap();
    assert!(pack
        .require_production(&mirror, &public, 150, 8 * 1024 * 1024)
        .is_err());
}
