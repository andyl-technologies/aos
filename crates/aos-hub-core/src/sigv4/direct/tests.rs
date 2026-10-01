//! Typed provider checksum/source binding, redaction and bounds regressions.

use super::*;
use crate::direct_upload::{DirectChecksumAlgorithm, DirectPartChecksum, WireInteger};

fn params() -> PresignParams<'static> {
    PresignParams {
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region: "us-east-1",
        service: "s3",
        scheme: "https",
        host: "examplebucket.s3.amazonaws.com",
        path: "/bucket/.aos-direct-upload/source/key",
        expires_secs: 100,
        amz_date: "20130524T000000Z",
    }
}

fn part() -> DirectPart {
    DirectPart {
        part_number: 1,
        offset: WireInteger::new(0),
        byte_size: WireInteger::new(8 * 1024 * 1024),
        sha256: "00".repeat(32),
        checksum: DirectPartChecksum {
            algorithm: DirectChecksumAlgorithm::Md5,
            value: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
        },
    }
}

#[test]
fn upload_part_signature_binds_length_checksum_and_exact_provider_query() {
    let original =
        presign_direct_upload_part(&params(), "retained+/=upload", &part(), 100).unwrap();
    assert!(original.url.ends_with(
        "X-Amz-Signature=9f47da74ad38e573440b2d153496a1c9b05303f7a837a045a8798d6bd55bd10d"
    ));
    assert!(original
        .url
        .contains("X-Amz-SignedHeaders=content-length%3Bcontent-md5%3Bhost"));
    assert!(original.url.contains("uploadId=retained%2B%2F%3Dupload"));
    assert_eq!(original.required_headers[0].value, "8388608");
    let mut changed = part();
    changed.byte_size = WireInteger::new(1);
    assert_ne!(
        presign_direct_upload_part(&params(), "retained+/=upload", &changed, 100)
            .unwrap()
            .url,
        original.url
    );
    changed = part();
    changed.checksum.value = "AQEBAQEBAQEBAQEBAQEBAQ==".into();
    assert_ne!(
        presign_direct_upload_part(&params(), "retained+/=upload", &changed, 100)
            .unwrap()
            .url,
        original.url
    );
    assert!(presign_direct_upload_part(&params(), "retained+/=upload", &part(), 99).is_err());
}

#[test]
fn copy_signature_binds_encoded_source_and_inclusive_range() {
    let source = DirectPartCopySource {
        bucket: "private-bucket",
        full_key: ".aos-direct-upload/source/key with spaces",
        first_byte: 0,
        last_byte: 8388607,
    };
    let original = presign_direct_upload_part_copy(&params(), "upload", 1, &source, 100).unwrap();
    assert_eq!(original.required_headers[0].name, "x-amz-copy-source");
    assert_eq!(
        original.required_headers[0].value,
        "/private-bucket/.aos-direct-upload/source/key%20with%20spaces"
    );
    assert_eq!(original.required_headers[1].value, "bytes=0-8388607");
    let mut changed = source.clone();
    changed.last_byte = 8388606;
    assert_ne!(
        presign_direct_upload_part_copy(&params(), "upload", 1, &changed, 100)
            .unwrap()
            .url,
        original.url
    );
    changed.first_byte = u64::MAX;
    assert!(presign_direct_upload_part_copy(&params(), "upload", 1, &changed, 100).is_err());
}

#[test]
fn negotiated_creation_and_sparse_list_pages_are_closed() {
    let sha =
        presign_direct_create_multipart(&params(), DirectChecksumAlgorithm::Sha256, 100).unwrap();
    assert_eq!(
        sha.required_headers,
        vec![DirectRequiredHeader {
            name: "x-amz-checksum-algorithm".into(),
            value: "SHA256".into()
        }]
    );
    let md5 =
        presign_direct_create_multipart(&params(), DirectChecksumAlgorithm::Md5, 100).unwrap();
    assert!(md5.required_headers.is_empty());
    assert_ne!(sha.url, md5.url);
    let page = presign_direct_list_parts(&params(), "upload", 64, 64, 100).unwrap();
    assert!(page.url.contains("part-number-marker=64") && page.url.contains("max-parts=64"));
    assert!(presign_direct_list_parts(&params(), "upload", 10000, 64, 100).is_err());
    assert!(presign_direct_list_parts(&params(), "upload", 0, 1001, 100).is_err());
}

#[test]
fn credentials_raw_queries_and_capabilities_never_enter_debug_or_errors() {
    let mut p = params();
    p.access_key = "access-secret-canary";
    p.secret_key = "seed-secret-canary";
    p.path = "/canary?raw-secret-query";
    let debug = format!("{p:?}");
    for secret in [
        "access-secret-canary",
        "seed-secret-canary",
        "raw-secret-query",
    ] {
        assert!(!debug.contains(secret));
    }
    let error = presign_direct_upload_part(&p, "upload", &part(), 100).unwrap_err();
    assert!(!error.to_string().contains("canary"));
    let signed = presign_direct_upload_part(&params(), "upload", &part(), 100).unwrap();
    assert!(!format!("{signed:?}").contains("X-Amz"));
    assert!(presign_direct_upload_part(&params(), &"x".repeat(2049), &part(), 100).is_err());
}
