//! Synthetic review closure and signature tests, never empirical observations.

use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

fn fixture() -> (
    MirrorAcceptanceArtifact,
    MirrorLiveAcceptanceArtifact,
    SigningKey,
) {
    let mut mirror = super::super::tests::artifact();
    let key = SigningKey::from_bytes(&[41; 32]);
    mirror.signature = hex::encode(key.sign(&mirror.signing_bytes().unwrap()).to_bytes());
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
        execution: mirror.execution,
        mirror_artifact_sha256: digest(&mirror).unwrap(),
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
                    BoundedMetadataQuery => 175 * 1024,
                    _ => 0,
                },
            })
            .collect(),
        memory_report_sha256: "dd".repeat(32),
        peak_worker_bytes: 64 * 1024 * 1024,
        memory_samples: 2,
        native_bulk_bytes: 0,
        destination_mutations: 0,
        release_pack_sha256: mirror.evidence.release.release_pack_sha256.clone(),
        issued_at: mirror.issued_at,
        valid_until: mirror.valid_until,
        signature: String::new(),
    };
    live.signature = hex::encode(key.sign(&live.signing_bytes().unwrap()).to_bytes());
    (mirror, live, key)
}

#[test]
fn separate_live_review_checks_signature_prerequisite_and_dispatch_cutoff() {
    let (mirror, live, key) = fixture();
    let public = hex::encode(key.verifying_key().to_bytes());
    live.require_production(&mirror, &public, mirror.issued_at)
        .unwrap();
    assert!(live
        .require_production(&mirror, &"00".repeat(32), mirror.issued_at)
        .is_err());
    assert!(live
        .require_production(&mirror, &public, live.valid_until)
        .is_err());
    let mut foreign = live.clone();
    foreign.mirror_artifact_sha256 = "ff".repeat(32);
    assert!(foreign
        .require_production(&mirror, &public, mirror.issued_at)
        .is_err());
    foreign = live.clone();
    foreign.signature = mirror.signature.clone();
    assert!(foreign
        .require_production(&mirror, &public, mirror.issued_at)
        .is_err());
}

#[test]
fn live_reviews_require_full_real_report_closure_and_no_native_bulk_or_mutations() {
    let (mirror, live, _) = fixture();
    for field in [
        "geometry",
        "case",
        "dispatch",
        "body",
        "memory",
        "native",
        "mutation",
        "controlled",
        "query_missing",
        "query_no_dispatch",
        "query_oversize",
    ] {
        let mut bad = live.clone();
        match field {
            "geometry" => bad.reader_bytes *= 2,
            "case" => bad.measurements[0].case = bad.measurements[1].case,
            "dispatch" => {
                bad.measurements
                    .iter_mut()
                    .find(|m| m.case == MirrorLiveCase::ExpiredDispatchRefusal)
                    .unwrap()
                    .provider_dispatches = 1
            }
            "body" => {
                bad.measurements
                    .iter_mut()
                    .find(|m| m.case == MirrorLiveCase::FullPack)
                    .unwrap()
                    .client_bytes -= 1
            }
            "memory" => bad.peak_worker_bytes = 128 * 1024 * 1024,
            "native" => bad.native_bulk_bytes = 1,
            "mutation" => bad.destination_mutations = 1,
            "query_missing" => {
                bad.measurements
                    .retain(|m| m.case != MirrorLiveCase::BoundedMetadataQuery);
            }
            "query_no_dispatch" => {
                bad.measurements
                    .iter_mut()
                    .find(|m| m.case == MirrorLiveCase::BoundedMetadataQuery)
                    .unwrap()
                    .provider_dispatches = 0;
            }
            "query_oversize" => {
                bad.measurements
                    .iter_mut()
                    .find(|m| m.case == MirrorLiveCase::BoundedMetadataQuery)
                    .unwrap()
                    .client_bytes = 256 * 1024 + 1;
            }
            _ => bad.execution = MirrorAcceptanceExecution::Controlled,
        }
        assert!(
            bad.validate_unsigned(&mirror, mirror.issued_at).is_err(),
            "{field}"
        );
    }
}
