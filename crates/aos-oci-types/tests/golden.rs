//! Golden wire-format vectors for the frozen RFC-0015 contract.

#![allow(clippy::expect_used)]

use aos_oci_types::limits::SCHEMA_VERSION;
use aos_oci_types::{
    Annotations, Descriptor, DistributionError, DistributionErrorCode, DistributionErrorEnvelope,
    HistoryEntry, ImageConfig, ImageIndex, ImageManifest, ImageRuntimeConfig, MediaType, Platform,
    RootFs, RootFsType, Sha256Digest, to_canonical_json,
};

fn descriptor(media_type: MediaType, content: &[u8]) -> Descriptor {
    Descriptor {
        media_type,
        digest: Sha256Digest::digest(content),
        size: u64::try_from(content.len()).expect("fixture size fits u64"),
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    }
}

#[test]
fn descriptor_golden_vector() {
    let descriptor = Descriptor::canonical_empty();
    let json = to_canonical_json(&descriptor).expect("canonical descriptor");
    assert_eq!(
        json,
        br#"{"digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","mediaType":"application/vnd.oci.empty.v1+json","size":2}"#
    );
    assert_eq!(
        Descriptor::from_json(&json).expect("parse descriptor"),
        descriptor
    );
}

#[test]
fn image_config_golden_vector() {
    let config = ImageConfig {
        created: None,
        author: None,
        architecture: "amd64".to_string(),
        os: "linux".to_string(),
        os_version: None,
        os_features: Vec::new(),
        variant: None,
        config: Some(ImageRuntimeConfig {
            env: vec!["PATH=/usr/bin".to_string()],
            entrypoint: vec!["/usr/bin/aos".to_string()],
            working_dir: Some("/work".to_string()),
            ..ImageRuntimeConfig::default()
        }),
        rootfs: RootFs {
            rootfs_type: RootFsType::Layers,
            diff_ids: vec![Sha256Digest::digest(b"layer")],
        },
        history: vec![HistoryEntry {
            created_by: Some("aos container layer".to_string()),
            ..HistoryEntry::default()
        }],
    };

    config.validate().expect("valid image config");
    let json = to_canonical_json(&config).expect("canonical image config");
    assert_eq!(
        json,
        br#"{"architecture":"amd64","config":{"Entrypoint":["/usr/bin/aos"],"Env":["PATH=/usr/bin"],"WorkingDir":"/work"},"history":[{"created_by":"aos container layer"}],"os":"linux","rootfs":{"diff_ids":["sha256:dac1d7cfa95021764849fd102524e141488c5e3a90f861dbb5a12d9ac8584f85"],"type":"layers"}}"#
    );
    assert_eq!(ImageConfig::from_json(&json).expect("parse config"), config);
}

#[test]
fn manifest_and_index_golden_vectors() {
    let manifest = ImageManifest {
        schema_version: SCHEMA_VERSION,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: None,
        config: descriptor(MediaType::OciImageConfig, b"config"),
        layers: vec![descriptor(MediaType::OciLayerGzip, b"layer")],
        subject: None,
        annotations: Annotations::new(),
    };
    manifest.validate().expect("valid manifest");
    let manifest_json = to_canonical_json(&manifest).expect("canonical manifest");
    assert_eq!(
        manifest_json,
        br#"{"config":{"digest":"sha256:b79606fb3afea5bd1609ed40b622142f1c98125abcfe89a76a661b0e8e343910","mediaType":"application/vnd.oci.image.config.v1+json","size":6},"layers":[{"digest":"sha256:dac1d7cfa95021764849fd102524e141488c5e3a90f861dbb5a12d9ac8584f85","mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","size":5}],"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2}"#
    );
    assert_eq!(
        ImageManifest::from_json(&manifest_json).expect("parse manifest"),
        manifest
    );

    let mut manifest_descriptor = descriptor(MediaType::OciImageManifest, b"manifest");
    manifest_descriptor.platform = Some(Platform::linux_amd64());
    let index = ImageIndex {
        schema_version: SCHEMA_VERSION,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![manifest_descriptor],
        subject: None,
        annotations: Annotations::new(),
    };
    index.validate().expect("valid index");
    let index_json = to_canonical_json(&index).expect("canonical index");
    assert_eq!(
        index_json,
        br#"{"manifests":[{"digest":"sha256:05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f","mediaType":"application/vnd.oci.image.manifest.v1+json","platform":{"architecture":"amd64","os":"linux"},"size":8}],"mediaType":"application/vnd.oci.image.index.v1+json","schemaVersion":2}"#
    );
    assert_eq!(
        ImageIndex::from_json(&index_json).expect("parse index"),
        index
    );
}

#[test]
fn distribution_error_golden_vector() {
    let envelope = DistributionErrorEnvelope {
        errors: vec![DistributionError {
            code: DistributionErrorCode::ManifestInvalid,
            message: "manifest rejected".to_string(),
            detail: Some(serde_json::json!({"field": "layers", "limit": 64})),
        }],
    };
    envelope.validate().expect("valid error envelope");
    let json = to_canonical_json(&envelope).expect("canonical error envelope");
    assert_eq!(
        json,
        br#"{"errors":[{"code":"MANIFEST_INVALID","detail":{"field":"layers","limit":64},"message":"manifest rejected"}]}"#
    );
    assert_eq!(
        DistributionErrorEnvelope::from_json(&json).expect("parse error envelope"),
        envelope
    );
}
