//! Positive provider receipts, malformed XML and exact sparse pagination checks.

use super::*;

fn page(parts: &str, marker: u32, next: u32, truncated: bool) -> String {
    format!(
        "<ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>private-bucket</Bucket><Key>.aos-direct-upload/key</Key><UploadId>retained-upload</UploadId><PartNumberMarker>{marker}</PartNumberMarker><NextPartNumberMarker>{next}</NextPartNumberMarker><MaxParts>64</MaxParts><IsTruncated>{truncated}</IsTruncated>{parts}</ListPartsResult>"
    )
}

fn part(number: u32, size: u64) -> String {
    format!(
        "<Part><PartNumber>{number}</PartNumber><ETag>&quot;part-{number}&quot;</ETag><Size>{size}</Size></Part>"
    )
}

fn parse(xml: &str, marker: u32) -> Result<DirectProviderPartsPage> {
    parse_direct_list_parts(
        xml,
        "private-bucket",
        ".aos-direct-upload/key",
        "retained-upload",
        marker,
        64,
    )
}

#[test]
fn exact_sparse_pages_require_positive_monotonic_continuation() {
    let first = parse(
        &page(&(part(1, 8388608) + &part(9, 8388608)), 0, 9, true),
        0,
    )
    .unwrap();
    assert_eq!(
        first
            .parts
            .iter()
            .map(|p| p.part_number)
            .collect::<Vec<_>>(),
        vec![1, 9]
    );
    assert_eq!(first.next_part_number, Some(9));
    let last = parse(&page(&part(10, 1), 9, 10, false), 9).unwrap();
    assert_eq!(last.parts[0].byte_size, 1);
    assert_eq!(last.next_part_number, None);
    assert!(parse(&page(&part(9, 1), 9, 9, true), 9).is_err());
    assert!(parse(&page(&part(1, 1), 0, 2, true), 0).is_err());
    assert!(parse(&page("", 0, 0, true), 0).is_err());
    assert!(parse(&page(&(part(2, 1) + &part(1, 1)), 0, 0, false), 0).is_err());
}

#[test]
fn list_parts_refuses_foreign_duplicate_unknown_and_excessive_fields() {
    let original = page(&part(1, 1), 0, 0, false);
    for xml in [
        original.replace(
            "<UploadId>retained-upload</UploadId>",
            "<UploadId>foreign</UploadId>",
        ),
        original.replace("<Size>1</Size>", "<Size>01</Size>"),
        original.replace("<Size>1</Size>", "<Size>1</Size><Size>2</Size>"),
        original.replace("<Size>1</Size>", "<Unknown>payload</Unknown><Size>1</Size>"),
        original.replace(
            "<ETag>&quot;part-1&quot;</ETag>",
            "<ETag>W/&quot;part-1&quot;</ETag>",
        ),
    ] {
        assert!(parse(&xml, 0).is_err());
    }
    let parts = (1..=65).map(|n| part(n, 1)).collect::<String>();
    assert!(parse(&page(&parts, 0, 0, false), 0).is_err());
    assert!(parse(&"x".repeat(MAX_DIRECT_MULTIPART_RESPONSE_BYTES + 1), 0).is_err());
}

#[test]
fn xml_dtd_entities_mixed_text_and_embedded_error_never_produce_receipts() {
    let original = page(&part(1, 1), 0, 0, false);
    for xml in [
        format!("<!DOCTYPE x [<!ENTITY e SYSTEM 'private'>]>{original}"),
        original.replace("private-bucket", "&external;"),
        original.replace("<Part>", "<Part>mixed"),
        original.replace(
            "<Size>1</Size>",
            "<Error><Code>InternalError</Code></Error>",
        ),
        format!("{original}<Error><Code>InternalError</Code></Error>"),
    ] {
        assert!(parse(&xml, 0).is_err());
    }
    for xml in [
        "",
        "<Error><Code>InternalError</Code></Error>",
        "<CopyPartResult><Error><Code>InternalError</Code></Error></CopyPartResult>",
        "<CopyPartResult><ETag>&quot;x&quot;</ETag><ETag>&quot;y&quot;</ETag></CopyPartResult>",
    ] {
        assert!(parse_direct_upload_part_copy(xml).is_err());
    }
}

#[test]
fn creation_and_completion_require_exact_positive_bucket_key_and_etag() {
    let create = "<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>stage</Key><UploadId>actual-id</UploadId></InitiateMultipartUploadResult>";
    assert_eq!(
        parse_direct_create_multipart(create, "bucket", "stage").unwrap(),
        "actual-id"
    );
    assert!(parse_direct_create_multipart(create, "bucket", "foreign").is_err());
    let complete = "<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>stage</Key><ETag>&quot;complete-2&quot;</ETag></CompleteMultipartUploadResult>";
    assert_eq!(
        parse_direct_complete_multipart(complete, "bucket", "stage")
            .unwrap()
            .etag,
        "\"complete-2\""
    );
    assert!(parse_direct_complete_multipart(complete, "bucket", "foreign").is_err());
    assert!(parse_direct_complete_multipart("", "bucket", "stage").is_err());
    assert_eq!(
        parse_direct_upload_part_copy(
            "<CopyPartResult><ETag>&quot;copy&quot;</ETag></CopyPartResult>"
        )
        .unwrap()
        .etag,
        "\"copy\""
    );
}

#[test]
fn composite_sha_metadata_is_explicit_and_never_part_or_full_source_proof() {
    let checksum = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let xml = format!(
        "<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>stage</Key><ETag>&quot;complete-2&quot;</ETag><ChecksumSHA256>{checksum}-2</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
    );
    let receipt = parse_direct_complete_multipart(&xml, "bucket", "stage").unwrap();
    assert_eq!(receipt.sha256_checksum.unwrap().part_count, Some(2));
    let xml = page(
        &part(1, 1).replace(
            "</Part>",
            &format!("<ChecksumSHA256>{checksum}-2</ChecksumSHA256></Part>"),
        ),
        0,
        0,
        false,
    );
    assert!(parse(&xml, 0).is_err());
}

#[test]
fn completion_xml_uses_exact_shared_manifest_and_explicit_empty_put_branch() {
    use crate::direct_upload::{
        DirectDependencyPhase, DirectPart, DirectTransferMode, DirectUploadTarget, WireInteger,
    };
    let mut intent = DirectUploadIntent {
        version: 1,
        client_operation_id: "11".repeat(32),
        target: DirectUploadTarget::CacheObject {
            cache_id: "cache".into(),
            path: "object".into(),
        },
        expected_sha256: "22".repeat(32),
        byte_size: WireInteger::new(1),
        part_size: WireInteger::new(8 * 1024 * 1024),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let mut placement = DirectPlacementRef {
        placement_id: WireInteger::new(1),
        placement_resource_version: WireInteger::new(2),
        write_spec_version: WireInteger::new(3),
        binding_id: WireInteger::new(4),
        binding_resource_version: WireInteger::new(5),
        binding_write_revision: WireInteger::new(6),
        placement_fingerprint: "33".repeat(32),
        profile_fingerprint: "44".repeat(32),
        private_policy_digest: "55".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Sha256,
    };
    let mut part = DirectManifestPart {
        part: DirectPart {
            part_number: 1,
            offset: WireInteger::new(0),
            byte_size: WireInteger::new(1),
            sha256: "00".repeat(32),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Sha256,
                value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            },
        },
        etag: "\"real-etag\"".into(),
    };
    let sha_xml = direct_complete_multipart_xml(&intent, &placement, &[part.clone()]).unwrap();
    assert!(sha_xml
        .contains("<ChecksumSHA256>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ChecksumSHA256>"));
    assert!(sha_xml.contains("<ETag>&quot;real-etag&quot;</ETag>"));
    part.part.byte_size = WireInteger::new(2);
    assert!(direct_complete_multipart_xml(&intent, &placement, &[part.clone()]).is_err());
    part.part.byte_size = WireInteger::new(1);
    placement.checksum_algorithm = DirectChecksumAlgorithm::Md5;
    part.part.checksum = DirectPartChecksum {
        algorithm: DirectChecksumAlgorithm::Md5,
        value: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
    };
    assert!(!direct_complete_multipart_xml(&intent, &placement, &[part])
        .unwrap()
        .contains("Checksum"));
    intent.byte_size = WireInteger::new(0);
    intent.expected_sha256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into();
    assert!(direct_complete_multipart_xml(&intent, &placement, &[]).is_err());
}
