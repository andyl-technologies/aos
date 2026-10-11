//! Retained exact bootstrap/final controls without current permission.

use super::*;

fn upload() -> OciRequest {
    crate::oci::parse_oci_path(&format!("/v2/fixture/blobs/uploads/{}", "a".repeat(32))).unwrap()
}

#[test]
fn empty_bootstrap_status_cancel_and_final_use_the_actual_query_parsers() {
    let start = crate::oci::parse_oci_path("/v2/fixture/blobs/uploads/").unwrap();
    let decoded =
        decode_hybrid_oci_upload_control_observation(&start, "POST", None, None, b"", b"", 202)
            .unwrap();
    assert_eq!(decoded, HybridOciUploadControlObservation::Start);

    let direct = format!(
        "digest=sha256%3A{}&size=3&aos_operation_id={}",
        "b".repeat(64),
        "c".repeat(64)
    );
    assert!(
        decode_hybrid_oci_upload_control_observation(
            &start,
            "POST",
            None,
            Some(&direct),
            b"",
            b"",
            202,
        )
        .is_ok()
    );
    let object = upload();
    for method in ["GET", "HEAD", "DELETE"] {
        assert!(
            decode_hybrid_oci_upload_control_observation(
                &object, method, None, None, b"", b"", 204,
            )
            .is_ok()
        );
    }
    let query = format!("digest=sha256%3A{}", "d".repeat(64));
    let final_control = decode_hybrid_oci_upload_control_observation(
        &object,
        "PUT",
        None,
        Some(&query),
        b"",
        b"",
        201,
    )
    .unwrap();
    assert_eq!(
        final_control,
        HybridOciUploadControlObservation::Finalize {
            digest: Sha256Digest::parse(&format!("sha256:{}", "d".repeat(64))).unwrap(),
        }
    );
}

#[test]
fn final_authorization_is_only_a_closed_routing_hint_for_the_exact_digest() {
    let query = format!("digest=sha256%3A{}", "d".repeat(64));
    let object = upload();
    let admission = HybridOciFinalAdmission {
        external: true,
        completion_only: false,
    };
    let reply = serde_json::to_vec(&admission).unwrap();
    let observed = decode_hybrid_oci_upload_control_observation(
        &object,
        "PATCH",
        Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE),
        Some(&query),
        b"",
        &reply,
        200,
    )
    .unwrap();
    assert!(matches!(
        observed,
        HybridOciUploadControlObservation::FinalAuthorization {
            admission: HybridOciFinalAdmission {
                external: true,
                completion_only: false
            },
            ..
        }
    ));
    let duplicate = format!("{query}&{query}");
    for bad_query in ["digest=bad", "unknown=value", &duplicate] {
        assert!(
            decode_hybrid_oci_upload_control_observation(
                &object,
                "PATCH",
                Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE),
                Some(bad_query),
                b"",
                &reply,
                200,
            )
            .is_err()
        );
    }
}

#[test]
fn raw_chunk_unknown_metadata_and_substituted_phase_status_refuse() {
    let object = upload();
    let query = format!("digest=sha256%3A{}", "d".repeat(64));
    let decode = |phase, request: &[u8], reply: &[u8], status| {
        decode_hybrid_oci_upload_control_observation(
            &object,
            "PATCH",
            phase,
            Some(&query),
            request,
            reply,
            status,
        )
    };
    assert!(
        decode(
            Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE),
            b"blob",
            b"{}",
            200
        )
        .is_err()
    );
    assert!(
        decode(
            Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE),
            b"",
            br#"{"external":true,"permission":true}"#,
            200
        )
        .is_err()
    );
    assert!(
        decode(
            Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE),
            b"",
            &vec![b' '; 1025],
            200
        )
        .is_err()
    );
    assert!(decode(Some("complete"), b"", br#"{"external":true}"#, 200).is_err());
    assert!(
        decode(
            Some(HYBRID_OCI_FINAL_AUTHORIZATION_PHASE),
            b"",
            br#"{"external":true}"#,
            202
        )
        .is_err()
    );

    let start = crate::oci::parse_oci_path("/v2/fixture/blobs/uploads/").unwrap();
    for query in ["size=1&size=2", "unknown=value", "aos_operation_id=bad"] {
        assert!(
            decode_hybrid_oci_upload_control_observation(
                &start,
                "POST",
                None,
                Some(query),
                b"",
                b"",
                202,
            )
            .is_err()
        );
    }
}
