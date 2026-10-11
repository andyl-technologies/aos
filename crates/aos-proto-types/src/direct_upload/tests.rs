//! Pure protocol vectors, bounds and redaction regressions.

use super::*;

fn intent(size: u64) -> DirectUploadIntent {
    DirectUploadIntent {
        version: 1,
        client_operation_id: "11".repeat(32),
        target: DirectUploadTarget::CacheObject {
            cache_id: "cache-one".into(),
            path: "object.nar".into(),
        },
        expected_sha256: if size == 0 {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()
        } else {
            "22".repeat(32)
        },
        byte_size: WireInteger::new(size),
        part_size: WireInteger::new(8 * 1024 * 1024),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    }
}

fn placement() -> DirectPlacementRef {
    DirectPlacementRef {
        placement_id: WireInteger::new(17),
        placement_fingerprint: "33".repeat(32),
        placement_resource_version: WireInteger::new(2),
        write_spec_version: WireInteger::new(3),
        binding_id: WireInteger::new(4),
        binding_resource_version: WireInteger::new(5),
        binding_write_revision: WireInteger::new(6),
        profile_fingerprint: "44".repeat(32),
        private_policy_digest: "55".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Sha256,
    }
}

fn member(intent: &DirectUploadIntent, number: u32) -> DirectManifestPart {
    let (offset, size) = intent.part_range(number).unwrap();
    DirectManifestPart {
        part: DirectPart {
            part_number: number,
            offset: WireInteger::new(offset),
            byte_size: WireInteger::new(size),
            sha256: "00".repeat(32),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Sha256,
                value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            },
        },
        etag: format!("\"part-{number}\""),
    }
}

#[test]
fn exact_integer_roundtrip_refuses_lossy_or_noncanonical_forms() {
    let value = WireInteger::new(9_007_199_254_740_993);
    let encoded = serde_json::to_string(&value).unwrap();
    assert_eq!(encoded, "\"9007199254740993\"");
    assert_eq!(
        serde_json::from_str::<WireInteger>(&encoded).unwrap(),
        value
    );

    for wire in [
        "9007199254740993",
        "\"01\"",
        "\"+1\"",
        "\"-1\"",
        "\"1e3\"",
        "\"18446744073709551616\"",
    ] {
        assert!(serde_json::from_str::<WireInteger>(wire).is_err(), "{wire}");
    }
}

#[test]
fn provider_geometry_handles_final_exception_and_zero_without_grants() {
    let object = intent(8 * 1024 * 1024 + 1);
    assert_eq!(object.part_count().unwrap(), 2);
    assert_eq!(object.part_range(1).unwrap(), (0, 8 * 1024 * 1024));
    assert_eq!(object.part_range(2).unwrap(), (8 * 1024 * 1024, 1));
    assert!(object.part_range(0).is_err());
    assert!(object.part_range(3).is_err());
    assert_eq!(intent(0).part_count().unwrap(), 0);
    assert!(intent(0).part_range(1).is_err());

    let mut invalid = intent(MAX_DIRECT_OBJECT_BYTES + 1);
    assert!(invalid.validate().is_err());
    invalid.byte_size = WireInteger::new(1);
    invalid.part_size = WireInteger::new(MIN_DIRECT_PART_BYTES - 1);
    assert!(invalid.validate().is_err());
    invalid.part_size = WireInteger::new(MAX_DIRECT_PART_BYTES + 1);
    assert!(invalid.validate().is_err());
}

#[test]
fn manifest_requires_exact_complete_geometry_and_destination() {
    let object = intent(8 * 1024 * 1024 + 1);
    let parts = vec![member(&object, 1), member(&object, 2)];
    let original = canonical_manifest_digest(&object, &placement(), &parts).unwrap();
    assert_eq!(original.len(), 64);
    assert!(canonical_manifest_digest(&object, &placement(), &parts[..1]).is_err());
    let mut changed = parts.clone();
    changed.swap(0, 1);
    assert!(canonical_manifest_digest(&object, &placement(), &changed).is_err());
    changed = parts.clone();
    changed[1].part.offset = WireInteger::new(1);
    assert!(canonical_manifest_digest(&object, &placement(), &changed).is_err());
    changed = parts.clone();
    changed[0].etag = "\"replacement\"".into();
    assert_ne!(
        canonical_manifest_digest(&object, &placement(), &changed).unwrap(),
        original
    );
    let mut another = placement();
    another.placement_id = WireInteger::new(18);
    assert_ne!(
        canonical_manifest_digest(&object, &another, &parts).unwrap(),
        original
    );
}

#[test]
fn stable_business_identity_is_independent_of_mutable_owner_and_source() {
    let original = intent(1);
    let mut changed = original.clone();
    changed.target = DirectUploadTarget::OciBlob {
        upload_id: "another-owner".into(),
    };
    changed.byte_size = WireInteger::new(2);
    assert_ne!(
        changed.fingerprint().unwrap(),
        original.fingerprint().unwrap()
    );
    assert_eq!(
        deterministic_business_operation_id(
            "deployment",
            "principal",
            &original.client_operation_id
        )
        .unwrap(),
        deterministic_business_operation_id(
            "deployment",
            "principal",
            &changed.client_operation_id
        )
        .unwrap()
    );
    assert_ne!(
        deterministic_business_operation_id("a", "bc", &original.client_operation_id).unwrap(),
        deterministic_business_operation_id("ab", "c", &original.client_operation_id).unwrap()
    );
}

#[test]
fn closed_owners_and_checksums_reject_unknown_or_changed_payloads() {
    let wire = serde_json::to_string(&intent(1)).unwrap();
    assert!(serde_json::from_str::<DirectUploadIntent>(
        &wire.replace("\"version\":1", "\"version\":1,\"unknown\":true")
    )
    .is_err());
    assert!(serde_json::from_str::<DirectUploadIntent>(
        &wire.replace("\"version\":1", "\"version\":1,\"version\":1")
    )
    .is_err());
    assert!(serde_json::from_str::<DirectUploadTarget>("{\"kind\":\"cache_object\",\"cache_id\":\"cache\",\"path\":\"object\",\"bucket\":\"attacker\"}").is_err());
    let mut part = member(&intent(1), 1).part;
    part.checksum.value.pop();
    assert!(part.validate(&intent(1)).is_err());
    part.checksum.value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
    part.sha256 = "01".repeat(32);
    assert!(part.validate(&intent(1)).is_err());
}

#[test]
fn grant_debug_never_exposes_bearer_url_or_required_header_values() {
    let grant = DirectPartGrant {
        session_id: "session".into(),
        logical_fingerprint: "55".repeat(32),
        placement: placement(),
        grant_id: "grant".into(),
        grant_revision: WireInteger::new(1),
        part: member(&intent(1), 1).part,
        method: "PUT".into(),
        url: "https://provider.test/private?X-Amz-Signature=secret-url-canary".into(),
        required_headers: vec![DirectRequiredHeader {
            name: "content-md5".into(),
            value: "header-canary".into(),
        }],
        expires_at: WireInteger::new(123),
    };
    let debug = format!("{grant:?}");
    for forbidden in [
        "secret-url-canary",
        "header-canary",
        "provider.test",
        "X-Amz-Signature",
    ] {
        assert!(!debug.contains(forbidden));
    }
    assert!(serde_json::to_string(&grant)
        .unwrap()
        .contains("secret-url-canary"));
}

#[test]
fn canonical_binary_vectors_match_independent_node_implementation() {
    let source = intent(8 * 1024 * 1024 + 1);
    assert_eq!(
        source.fingerprint().unwrap(),
        "c7d555fd5e57f1aefe86edd2575c6c77785dca50aee4b42e5414e69cf92d343f"
    );
    let parts = [member(&source, 1), member(&source, 2)];
    assert_eq!(
        canonical_manifest_digest(&source, &placement(), &parts).unwrap(),
        "f10226c14015cd379686f5a049168c22fc02f80096051df7e21f866e51a64e9b"
    );
    assert_eq!(
        deterministic_business_operation_id("deployment", "principal", &source.client_operation_id)
            .unwrap(),
        "92286f745e69a154f931021b4bf2f8e21bfc175b8fcccec633403c473016a928"
    );
    let mut stream = DirectManifestHasher::new(&source, &placement()).unwrap();
    assert!(stream.push(&parts[1]).is_err());
    stream.push(&parts[0]).unwrap();
    stream.push(&parts[1]).unwrap();
    assert_eq!(
        stream.finish().unwrap(),
        canonical_manifest_digest(&source, &placement(), &parts).unwrap()
    );
    assert!(DirectManifestHasher::new(&source, &placement())
        .unwrap()
        .finish()
        .is_err());
}

fn valid_grant() -> DirectPartGrant {
    let part = member(&intent(1), 1).part;
    DirectPartGrant {
        session_id: "session".into(),
        logical_fingerprint: "55".repeat(32),
        placement: placement(),
        grant_id: "66".repeat(32),
        grant_revision: WireInteger::new(1),
        part: part.clone(),
        method: "PUT".into(),
        url: format!(
            "https://provider.test/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access%2F19700101%2Fauto%2Fs3%2Faws4_request&X-Amz-Date=19700101T000000Z&X-Amz-Expires=100&X-Amz-Signature={}&X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-checksum-sha256&partNumber=1&uploadId=retained-upload",
            "00".repeat(32)
        ),
        required_headers: vec![
            DirectRequiredHeader {
                name: "content-length".into(),
                value: "1".into(),
            },
            DirectRequiredHeader {
                name: part.checksum.header_name().into(),
                value: part.checksum.value.clone(),
            },
        ],
        expires_at: WireInteger::new(100),
    }
}

fn check_grant(grant: &DirectPartGrant, now: u64, validity: u64) -> DirectUploadResult<()> {
    grant.validate_for(
        &DirectSessionRef {
            session_id: "session".into(),
            logical_fingerprint: "55".repeat(32),
        },
        &placement(),
        &intent(1),
        &member(&intent(1), 1).part,
        now,
        validity,
    )
}

#[test]
fn grants_reject_duplicate_queries_foreign_echo_headers_and_expiry() {
    let original = valid_grant();
    check_grant(&original, 1, 1).unwrap();
    for field in [
        "partNumber=1",
        "uploadId=another",
        "X-Amz-Credential=another",
        "X-Amz-Signature=another",
    ] {
        let mut changed = original.clone();
        changed.url.push('&');
        changed.url.push_str(field);
        assert!(check_grant(&changed, 1, 1).is_err());
    }
    for replacement in ["partNumber=2", "partNumber=01"] {
        let mut changed = original.clone();
        changed.url = changed.url.replace("partNumber=1", replacement);
        assert!(check_grant(&changed, 1, 1).is_err());
    }
    let mut changed = original.clone();
    changed.session_id = "foreign-session".into();
    assert!(check_grant(&changed, 1, 1).is_err());
    changed = original.clone();
    changed.required_headers[0].value = "2".into();
    assert!(check_grant(&changed, 1, 1).is_err());
    changed = original.clone();
    changed.required_headers.push(DirectRequiredHeader {
        name: "authorization".into(),
        value: "secret".into(),
    });
    assert!(check_grant(&changed, 1, 1).is_err());
    assert!(check_grant(&original, 99, 1).is_err());
    assert!(check_grant(&original, u64::MAX, 1).is_err());
}

#[test]
fn grants_refuse_http_userinfo_fragments_and_invalid_dates_without_disclosure() {
    let original = valid_grant();
    for url in [
        original.url.replace("https://", "http://"),
        original.url.replace("https://", "https://canary-secret@"),
        format!("{}#canary-secret", original.url),
        original.url.replace("19700101T000000Z", "19700230T000000Z"),
    ] {
        let mut changed = original.clone();
        changed.url = url;
        let error = check_grant(&changed, 1, 1).unwrap_err();
        assert!(!error.to_string().contains("canary-secret"));
    }
}

#[test]
fn whole_control_and_aggregate_status_limits_are_enforced() {
    assert!(encode_direct_control(&"x".repeat(MAX_DIRECT_CONTROL_BYTES)).is_err());
    assert!(
        decode_direct_control::<DirectUploadIntent>(&vec![b' '; MAX_DIRECT_CONTROL_BYTES + 1])
            .is_err()
    );
    let query = DirectStatusQuery {
        session: DirectSessionRef {
            session_id: "s1".into(),
            logical_fingerprint: "55".repeat(32),
        },
        after: None,
        maximum_parts: 33,
    };
    let mut second = query.clone();
    second.session.session_id = "s2".into();
    let mut batch = DirectBatch {
        operation_id: "66".repeat(32),
        items: vec![query, second],
    };
    assert!(DirectUploadRequest::StatusBatch(batch.clone())
        .validate()
        .is_err());
    batch.items[1].maximum_parts = 31;
    DirectUploadRequest::StatusBatch(batch.clone())
        .validate()
        .unwrap();
    batch.items[1].session = batch.items[0].session.clone();
    assert!(DirectUploadRequest::StatusBatch(batch).validate().is_err());
}

#[test]
fn generated_protojson_preserves_zero_ranges_and_large_exact_counters() {
    let portable = DirectBeginBatch {
        operation_id: "77".repeat(32),
        items: vec![intent(0), intent(1)],
    };
    let mut original = portable.clone();
    original.items[1].client_operation_id = "88".repeat(32);
    let generated = crate::hub_v1::DirectBeginBatch::try_from(original.clone()).unwrap();
    assert_eq!(DirectBeginBatch::try_from(generated).unwrap(), original);
    let mut source = intent(1);
    source.target = DirectUploadTarget::PublicationObject {
        publication_id: "publication".into(),
        surface_object_id: WireInteger::new(9_007_199_254_740_993),
        path: "file".into(),
    };
    let generated = crate::hub_v1::DirectUploadIntent::try_from(source.clone()).unwrap();
    assert!(serde_json::to_string(&generated)
        .unwrap()
        .contains("9007199254740993"));
    assert_eq!(DirectUploadIntent::try_from(generated).unwrap(), source);
    let mut invalid = crate::hub_v1::DirectUploadIntent::try_from(intent(1)).unwrap();
    invalid.target.as_mut().unwrap().upload_id = "foreign-variant".into();
    assert!(DirectUploadIntent::try_from(invalid).is_err());
}

#[test]
fn generated_debug_redacts_grant_url_and_header_values() {
    let grant = crate::hub_v1::DirectPartGrant {
        url: "secret-url-canary".into(),
        required_headers: vec![crate::hub_v1::DirectRequiredHeader {
            name: "header".into(),
            value: "secret-header-canary".into(),
        }],
        ..Default::default()
    };
    assert!(!format!("{grant:?}").contains("canary"));
    assert!(!format!("{:?}", grant.required_headers[0]).contains("canary"));
    assert!(serde_json::to_string(&grant)
        .unwrap()
        .contains("secret-url-canary"));
}

fn capabilities() -> DirectUploadCapabilities {
    let reference = placement();
    DirectUploadCapabilities {
        target: DirectCapabilitiesTarget::Cache {
            cache_id: "cache-one".into(),
        },
        version: 1,
        deployment_id: "deployment".into(),
        principal_id: "ab".repeat(32),
        requested_delivery_url: None,
        capability: DIRECT_UPLOAD_CAPABILITY.into(),
        transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
        config_generation: WireInteger::new(7),
        valid_until: WireInteger::new(1000),
        maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
        maximum_batch_items: MAX_DIRECT_BATCH_ITEMS as u32,
        maximum_batch_parts: MAX_DIRECT_BATCH_PARTS as u32,
        maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
        minimum_object_bytes: WireInteger::new(0),
        minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
        maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
        profiles: vec![DirectProviderProfile {
            placement_id: reference.placement_id,
            placement_resource_version: reference.placement_resource_version,
            write_spec_version: reference.write_spec_version,
            binding_id: reference.binding_id,
            binding_resource_version: reference.binding_resource_version,
            binding_write_revision: reference.binding_write_revision,
            checksum_algorithm: reference.checksum_algorithm,
            provider_origin: "https://provider.example".into(),
            profile_fingerprint: reference.profile_fingerprint,
            private_policy_digest: reference.private_policy_digest,
        }],
    }
}

#[test]
fn reusable_discovery_enforces_explicit_complete_object_minimum() {
    let mut discovery = capabilities();
    assert_eq!(discovery.minimum_object_bytes.get(), 0);
    discovery.minimum_object_bytes = WireInteger::new(1);
    discovery.validate().unwrap();
    let document = serde_json::to_value(&discovery).unwrap();
    assert_eq!(
        document["minimumObjectBytes"],
        serde_json::to_value(WireInteger::new(1)).unwrap()
    );
    let generated = crate::hub_v1::DirectUploadCapabilities::try_from(discovery.clone()).unwrap();
    assert_eq!(
        DirectUploadCapabilities::try_from(generated).unwrap(),
        discovery
    );

    discovery.minimum_object_bytes = WireInteger::new(discovery.maximum_object_bytes.get() + 1);
    assert!(discovery.validate().is_err());
}

#[test]
fn reusable_owner_discovery_binds_all_original_destination_revisions() {
    let original = capabilities();
    original
        .validate_actor_for("deployment", &"ab".repeat(32))
        .unwrap();
    assert!(original
        .validate_actor_for("other-deployment", &"ab".repeat(32))
        .is_err());
    assert!(original
        .validate_actor_for("deployment", "another-principal")
        .is_err());
    original
        .validate_placements_for(&original.target, &[placement()], 999)
        .unwrap();
    assert!(original.validate_at_for(&original.target, 1000).is_err());
    assert!(original
        .validate_placements_for(&original.target, &[], 999)
        .is_err());
    for index in 0..7 {
        let mut changed = placement();
        match index {
            0 => changed.placement_resource_version = WireInteger::new(99),
            1 => changed.write_spec_version = WireInteger::new(99),
            2 => changed.binding_id = WireInteger::new(99),
            3 => changed.binding_resource_version = WireInteger::new(99),
            4 => changed.binding_write_revision = WireInteger::new(99),
            5 => changed.profile_fingerprint = "66".repeat(32),
            _ => changed.private_policy_digest = "66".repeat(32),
        }
        assert!(original
            .validate_placements_for(&original.target, &[changed], 999)
            .is_err());
    }
    let mut legacy = original.clone();
    legacy.transfer_mode = DirectAdvertisedTransferMode::Legacy;
    assert!(legacy.validate_for(&legacy.target).is_err());
    legacy.profiles.clear();
    legacy.validate_for(&legacy.target).unwrap();
    assert!(legacy
        .validate_placements_for(&legacy.target, &[], 1)
        .is_err());
    let mut invalid = original.clone();
    invalid.profiles[0].provider_origin = "https://provider.example/private".into();
    assert!(invalid.validate_for(&invalid.target).is_err());

    let generated = crate::hub_v1::DirectUploadCapabilities::try_from(original.clone()).unwrap();
    assert_eq!(
        DirectUploadCapabilities::try_from(generated).unwrap(),
        original
    );
    assert!(decode_direct_control::<DirectGetCapabilities>(
        br#"{"target":{"kind":"cache","cacheId":"cache-one","path":"arbitrary"}}"#
    )
    .is_err());
}

#[test]
fn delivery_discovery_resolves_only_canonical_cache_with_exact_locator_echo() {
    assert_eq!(
        canonical_direct_delivery_url("http://localhost:8080/cache///").unwrap(),
        "http://localhost:8080/cache"
    );
    assert!(valid_direct_delivery_url("http://localhost:8080/cache"));
    assert!(!valid_direct_delivery_url("http://localhost:8080/cache/"));
    let requested = DirectCapabilitiesTarget::CacheDelivery {
        delivery_url: "https://hub.test/cache/ready".into(),
    };
    let mut reply = capabilities();
    assert!(reply.validate_for(&requested).is_err());
    reply.requested_delivery_url = Some("https://hub.test/cache/ready".into());
    reply.validate_for(&requested).unwrap();
    assert!(reply.validate_for(&reply.target).is_err());
    let generated = crate::hub_v1::DirectUploadCapabilities::try_from(reply.clone()).unwrap();
    assert_eq!(
        DirectUploadCapabilities::try_from(generated).unwrap(),
        reply
    );
    let request = DirectGetCapabilities {
        target: requested.clone(),
    };
    assert_eq!(
        DirectGetCapabilities::try_from(
            crate::hub_v1::DirectGetCapabilities::try_from(request.clone()).unwrap()
        )
        .unwrap(),
        request
    );
    reply.target = DirectCapabilitiesTarget::Publication {
        publication_id: "plan".into(),
    };
    assert!(reply.validate_for(&requested).is_err());
    for value in [
        "https://user@hub.test/cache",
        "https://hub.test/cache?q=secret",
        "https://hub.test/cache#fragment",
        "https://HUB.test/cache",
        "not-a-url",
    ] {
        assert!(!valid_direct_delivery_url(value));
    }
}

#[test]
fn compact_complete_identity_binds_original_cas_and_each_placement_manifest() {
    let source = intent(1);
    let original = DirectCompleteRequest {
        session: DirectSessionRef {
            session_id: "session".into(),
            logical_fingerprint: "66".repeat(32),
        },
        operation_id: "77".repeat(32),
        expected_resource_version: WireInteger::new(8),
        manifests: vec![DirectManifestCommitment {
            placement: placement(),
            manifest_digest: canonical_manifest_digest(
                &source,
                &placement(),
                &[member(&source, 1)],
            )
            .unwrap(),
            part_count: 1,
        }],
    };
    let fingerprint = original.fingerprint().unwrap();
    for index in 0..4 {
        let mut changed = original.clone();
        match index {
            0 => changed.operation_id = "88".repeat(32),
            1 => changed.expected_resource_version = WireInteger::new(9),
            2 => changed.manifests[0].manifest_digest = "99".repeat(32),
            _ => changed.manifests[0].placement.binding_write_revision = WireInteger::new(9),
        }
        assert_ne!(changed.fingerprint().unwrap(), fingerprint);
    }
    assert_eq!(
        decode_direct_public_request(
            "CompleteBatch",
            &encode_direct_control(&DirectBatch {
                operation_id: "aa".repeat(32),
                items: vec![original.clone()]
            })
            .unwrap()
        )
        .unwrap(),
        DirectUploadRequest::CompleteBatch(DirectBatch {
            operation_id: "aa".repeat(32),
            items: vec![original]
        })
    );
    assert!(decode_direct_public_request(
        "StatusBatch",
        br#"{"operationId":"unknown","items":[],"secret":"canary"}"#
    )
    .is_err());
    assert!(decode_direct_public_request("Unknown", b"{}").is_err());
}

#[test]
fn private_stage_detection_uses_resolved_key_segments_without_url_decoding() {
    assert!(is_direct_staging_key(
        "binding/.aos-direct-upload/hash/1/payload"
    ));
    assert!(is_direct_staging_key(".aos-direct-upload"));
    for key in [
        "binding/.aos-direct-upload-public/file",
        "binding/%2Eaos-direct-upload/file",
        "ordinary/file",
    ] {
        assert!(!is_direct_staging_key(key));
    }
    assert!(!valid_direct_path("binding/.aos-direct-upload/payload"));
}

#[test]
fn explicit_unconfigured_legacy_capabilities_do_not_invent_a_direct_actor() {
    let mut legacy = capabilities();
    legacy.transfer_mode = DirectAdvertisedTransferMode::Legacy;
    legacy.profiles.clear();
    legacy.deployment_id.clear();
    legacy.principal_id.clear();
    legacy.validate_for(&legacy.target).unwrap();
    legacy.validate_at_for(&legacy.target, 999).unwrap();
    assert!(legacy
        .validate_actor_for("deployment", &"ab".repeat(32))
        .is_err());
    assert!(legacy
        .validate_placements_for(&legacy.target, &[], 999)
        .is_err());
    let generated = crate::hub_v1::DirectUploadCapabilities::try_from(legacy.clone()).unwrap();
    assert_eq!(
        DirectUploadCapabilities::try_from(generated).unwrap(),
        legacy
    );
}

#[test]
fn legacy_actor_identity_is_either_fully_valid_or_fully_absent() {
    let mut legacy = capabilities();
    legacy.transfer_mode = DirectAdvertisedTransferMode::Legacy;
    legacy.profiles.clear();
    legacy.validate_for(&legacy.target).unwrap();
    for (deployment, principal) in [
        ("", "".to_owned()),
        ("deployment", "".to_owned()),
        ("", "ab".repeat(32)),
        (" deployment", "ab".repeat(32)),
        ("deployment", "AB".repeat(32)),
        ("deployment", "invalid".into()),
    ] {
        let mut changed = legacy.clone();
        changed.deployment_id = deployment.into();
        changed.principal_id = principal;
        assert_eq!(
            changed.validate_for(&changed.target).is_ok(),
            changed.deployment_id.is_empty() && changed.principal_id.is_empty()
        );
    }
    legacy.deployment_id.clear();
    legacy.principal_id.clear();
    legacy.profiles = capabilities().profiles;
    assert!(legacy.validate_for(&legacy.target).is_err());
}

#[test]
fn required_capabilities_never_accept_absent_or_partial_actor_identity() {
    let original = capabilities();
    original.validate_for(&original.target).unwrap();

    // ProtoJSON omits empty strings. Defaults preserve Legacy roundtrips while
    // the validated conversion still refuses omitted Required actor identity.
    let mut generated =
        crate::hub_v1::DirectUploadCapabilities::try_from(original.clone()).unwrap();
    generated.deployment_id.clear();
    generated.principal_id.clear();
    assert!(DirectUploadCapabilities::try_from(generated).is_err());

    for field in 0..3 {
        let mut changed = original.clone();
        if field != 1 {
            changed.deployment_id.clear();
        }
        if field != 0 {
            changed.principal_id.clear();
        }
        assert!(changed.validate_for(&changed.target).is_err());
    }
}
