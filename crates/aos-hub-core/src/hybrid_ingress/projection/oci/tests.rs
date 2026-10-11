//! Closed OCI projection and complete original-parser regressions.

use super::*;

fn fixture() -> (
    Vec<u8>,
    OciInspectionDescriptor,
    Vec<OciInspectionDescriptor>,
) {
    let diff_id = Sha256Digest::digest(b"uncompressed");
    let bytes = format!("{{ \"architecture\":\"amd64\",\"os\":\"linux\",\"config\":{{\"Env\":[\"TOKEN=private-original-value\"]}},\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{diff_id}\"]}} }}").into_bytes();
    let config = OciInspectionDescriptor {
        digest: Sha256Digest::digest(&bytes),
        size: bytes.len() as u64,
        media_type: MediaType::OciImageConfig,
    };
    let layers = vec![OciInspectionDescriptor {
        digest: Sha256Digest::digest(b"compressed"),
        size: 10,
        media_type: MediaType::OciLayerGzip,
    }];
    (bytes, config, layers)
}

#[test]
fn config_identity_names_original_bytes_and_omits_runtime_context() {
    let (bytes, config, layers) = fixture();
    let projection =
        OciImageConfigSemanticsV1::from_config_bytes(&bytes, &config, &layers, &[99]).unwrap();
    projection.validate().unwrap();
    let encoded = serde_json::to_vec(&projection).unwrap();
    assert_eq!(projection.source_sha256, config.digest.encoded());
    assert_eq!(u64::from(projection.source_size), config.size);
    assert_ne!(Sha256Digest::digest(&encoded), config.digest);
    assert!(!String::from_utf8(encoded)
        .unwrap()
        .contains("private-original-value"));
    assert_eq!(projection.aos_system(), "x86_64-linux");
    assert_eq!(
        projection.layers[0].measurement,
        OciLayerSizeMeasurement::GzipIsize32
    );
}

#[test]
fn omitted_runtime_and_history_are_still_validated_locally() {
    let (bytes, _, layers) = fixture();
    for bytes in [
        String::from_utf8(bytes.clone())
            .unwrap()
            .replace("TOKEN=private-original-value", "INVALID_ENV"),
        String::from_utf8(bytes).unwrap().replace(
            "\"rootfs\":",
            "\"history\":[{\"empty_layer\":true}],\"rootfs\":",
        ),
    ] {
        let config = OciInspectionDescriptor {
            digest: Sha256Digest::digest(bytes.as_bytes()),
            size: bytes.len() as u64,
            media_type: MediaType::OciImageConfig,
        };
        assert!(OciImageConfigSemanticsV1::from_config_bytes(
            bytes.as_bytes(),
            &config,
            &layers,
            &[99]
        )
        .is_err());
    }
}

#[test]
fn config_descriptor_order_size_media_and_measurements_are_fenced() {
    let (bytes, config, layers) = fixture();
    let projection =
        OciImageConfigSemanticsV1::from_config_bytes(&bytes, &config, &layers, &[99]).unwrap();
    let mut wrong = config.clone();
    wrong.size += 1;
    assert!(projection.validate_for(&wrong, &layers).is_err());
    wrong = config.clone();
    wrong.media_type = MediaType::DockerImageConfig;
    assert!(projection.validate_for(&wrong, &layers).is_err());
    wrong = config.clone();
    wrong.digest = Sha256Digest::digest(b"other");
    assert!(projection.validate_for(&wrong, &layers).is_err());
    let mut changed = layers.clone();
    changed[0].digest = Sha256Digest::digest(b"replacement");
    assert!(projection.validate_for(&config, &changed).is_err());
    let mut changed = projection.clone();
    changed.layers[0].unpacked_byte_size = u64::from(u32::MAX) + 1;
    assert!(changed.validate_for(&config, &layers).is_err());
    changed = projection.clone();
    changed.source_media_type = MediaType::DockerImageConfig;
    assert!(changed.validate().is_err());
    changed = projection;
    changed.version = 2;
    assert!(changed.validate_for(&config, &layers).is_err());
}

#[test]
fn encoded_summary_limit_refuses_valid_large_platform_without_truncation() {
    let (bytes, config, layers) = fixture();
    let projection =
        OciImageConfigSemanticsV1::from_config_bytes(&bytes, &config, &layers, &[99]).unwrap();
    let mut large = projection;
    large.platform.os_features = vec!["a".repeat(MAX_HYBRID_OCI_PROJECTION_BYTES)];
    assert!(large.validate_for(&config, &layers).is_err());
    assert_eq!(
        large.platform.os_features[0].len(),
        MAX_HYBRID_OCI_PROJECTION_BYTES
    );
}

#[test]
fn closed_config_wire_rejects_unknown_and_duplicate_nested_fields() {
    let (bytes, config, layers) = fixture();
    let projection =
        OciImageConfigSemanticsV1::from_config_bytes(&bytes, &config, &layers, &[99]).unwrap();
    let json = serde_json::to_string(&projection).unwrap();
    let unknown = json.replace("\"platform\":{", "\"platform\":{\"unknown\":true,");
    let duplicate = json.replace("\"platform\":{", "\"platform\":{\"os\":\"linux\",");
    for json in [unknown, duplicate] {
        assert!(serde_json::from_str::<OciImageConfigSemanticsV1>(&json).is_err());
    }
}

fn root_fixture() -> Vec<u8> {
    let (_, config, layers) = fixture();
    let mut annotations = Annotations::new();
    for (key, value) in [
        ("org.opencontainers.image.title", "AOS"),
        ("org.opencontainers.image.version", "1.0"),
        ("dev.andyl.aos.release.name", "AOS"),
        ("dev.andyl.aos.release.version", "1.0"),
        ("dev.andyl.aos.state-version", "1"),
        ("dev.andyl.aos.module-abi", "1"),
        ("dev.andyl.aos.release.tier", "staging"),
        ("dev.andyl.aos.registry", "https://hub.example"),
        ("dev.andyl.aos.channel", "stable"),
        ("dev.andyl.aos.registry-root-epoch", "1"),
    ] {
        annotations
            .insert(key.to_string(), value.to_string())
            .unwrap();
    }
    let descriptor = |source: &OciInspectionDescriptor| Descriptor {
        digest: source.digest,
        size: source.size,
        media_type: source.media_type,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    };
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: None,
        config: descriptor(&config),
        layers: layers.iter().map(descriptor).collect(),
        subject: None,
        annotations,
    };
    aos_oci_types::to_canonical_json(&manifest).unwrap()
}

#[test]
fn publisher_annotation_keys_survive_closed_root_projection() {
    let bytes = root_fixture();
    let projection =
        HybridOciManifestProjection::from_bytes(MediaType::OciImageManifest, &bytes).unwrap();
    assert_eq!(
        projection.source_sha256,
        Sha256Digest::digest(&bytes).encoded()
    );
    let parsed: HybridOciManifestProjection =
        serde_json::from_slice(&serde_json::to_vec(&projection).unwrap()).unwrap();
    assert_eq!(parsed, projection);
    let HybridOciDocumentProjection::Manifest(document) = parsed.document else {
        panic!("manifest required")
    };
    assert_eq!(
        document
            .annotations
            .get("dev.andyl.aos.registry-root-epoch"),
        Some("1")
    );
}

#[test]
fn opaque_annotations_urls_inline_data_and_unknown_root_wire_are_refused() {
    let bytes = root_fixture();
    let base =
        HybridOciManifestProjection::from_bytes(MediaType::OciImageManifest, &bytes).unwrap();
    for kind in 0..3 {
        let mut projection = base.clone();
        let HybridOciDocumentProjection::Manifest(document) = &mut projection.document else {
            panic!("manifest required")
        };
        match kind {
            0 => {
                document
                    .annotations
                    .insert("private.vendor.context".into(), "opaque".into())
                    .unwrap();
            }
            1 => document
                .config
                .urls
                .push("https://unexpected-provider.example/key".into()),
            _ => document.config.data = Some("e30=".into()),
        }
        assert!(projection.validate().is_err());
    }
    let json = serde_json::to_string(&base).unwrap();
    let unknown = json.replace(
        "\"schemaVersion\":2",
        "\"schemaVersion\":2,\"unknown\":true",
    );
    let duplicate = json.replace(
        "\"schemaVersion\":2",
        "\"schemaVersion\":2,\"schemaVersion\":2",
    );
    assert!(serde_json::from_str::<HybridOciManifestProjection>(&unknown).is_err());
    assert!(serde_json::from_str::<HybridOciManifestProjection>(&duplicate).is_err());
}

#[test]
fn shared_layer_measurements_preserve_plain_gzip_and_zstd_meaning() {
    let (_, _, layers) = fixture();
    assert_eq!(
        measure_oci_layer_metadata(&layers[0], &u32::MAX.to_le_bytes()).unwrap(),
        u64::from(u32::MAX)
    );
    let mut descriptor = layers[0].clone();
    descriptor.media_type = MediaType::OciLayerTar;
    assert_eq!(
        measure_oci_layer_metadata(&descriptor, &[]).unwrap(),
        descriptor.size
    );
    assert!(measure_oci_layer_metadata(&descriptor, &[1]).is_err());
    descriptor.media_type = MediaType::OciLayerZstd;
    descriptor.size = 6;
    assert_eq!(
        measure_oci_layer_metadata(&descriptor, &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 42]).unwrap(),
        42
    );
    assert!(measure_oci_layer_metadata(&descriptor, &[0; 6]).is_err());
}

#[test]
fn index_descriptor_reference_annotation_survives_closed_projection() {
    let root = root_fixture();
    let mut annotations = Annotations::new();
    annotations
        .insert("org.opencontainers.image.ref.name".into(), "latest".into())
        .unwrap();
    let index = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![Descriptor {
            digest: Sha256Digest::digest(&root),
            size: root.len() as u64,
            media_type: MediaType::OciImageManifest,
            urls: Vec::new(),
            annotations,
            data: None,
            artifact_type: None,
            platform: Some(Platform::linux_amd64()),
        }],
        subject: None,
        annotations: Annotations::new(),
    };
    let bytes = aos_oci_types::to_canonical_json(&index).unwrap();
    let projection =
        HybridOciManifestProjection::from_bytes(MediaType::OciImageIndex, &bytes).unwrap();
    let decoded: HybridOciManifestProjection =
        serde_json::from_slice(&serde_json::to_vec(&projection).unwrap()).unwrap();
    assert_eq!(decoded, projection);
    let HybridOciDocumentProjection::Index(index) = decoded.document else {
        panic!("index required")
    };
    assert_eq!(
        index.manifests[0]
            .annotations
            .get("org.opencontainers.image.ref.name"),
        Some("latest")
    );
}
