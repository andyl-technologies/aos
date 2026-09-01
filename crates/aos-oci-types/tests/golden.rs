//! Golden wire-format vectors for the frozen RFC-0017 contract.

#![allow(clippy::expect_used)]

use aos_oci_types::limits::SCHEMA_VERSION;
use aos_oci_types::{
    Annotations, CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA, CONTAINER_RELEASE_SCHEMA_VERSION,
    ContainerEvidenceMappingQualification, ContainerEvidenceQualification,
    ContainerEvidenceQualificationCheck, ContainerNixProvenance, ContainerOciRelease,
    ContainerRelease, ContainerReleaseEvidence, ContainerReleaseIdentity, Descriptor,
    DistributionError, DistributionErrorCode, DistributionErrorEnvelope, HistoryEntry, ImageConfig,
    ImageIndex, ImageManifest, ImageRuntimeConfig, MediaType, NixDefinitionIdentity,
    NixOutputIdentity, Platform, RootFs, RootFsType, Sha256Digest, to_canonical_json,
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

fn artifact_descriptor(media_type: MediaType, content: &[u8]) -> Descriptor {
    Descriptor {
        artifact_type: Some(media_type),
        ..descriptor(MediaType::OciImageManifest, content)
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

#[test]
fn container_release_golden_vector() {
    let mut platform_manifest = descriptor(MediaType::OciImageManifest, b"amd64-manifest");
    platform_manifest.platform = Some(Platform::linux_amd64());
    let release = ContainerRelease {
        schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
        media_type: MediaType::AosContainerRelease,
        identity: ContainerReleaseIdentity {
            release: "1.0.0".to_string(),
            package: "aos".to_string(),
            package_version: "0.1.0".to_string(),
            image: "aos".to_string(),
        },
        oci: ContainerOciRelease {
            index: descriptor(MediaType::OciImageIndex, b"index"),
            platform_manifests: vec![platform_manifest],
        },
        nix: ContainerNixProvenance {
            definition: NixDefinitionIdentity {
                attribute: "containerImages.aos".to_string(),
                derivation_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv"
                    .to_string(),
            },
            output: NixOutputIdentity {
                name: "out".to_string(),
                store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container".to_string(),
            },
            closure: artifact_descriptor(MediaType::AosNixClosure, b"closure"),
        },
        qualification: ContainerEvidenceQualification {
            schema: CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA.to_string(),
            mapping: ContainerEvidenceMappingQualification {
                complete: true,
                unknown_paths: Vec::new(),
            },
            corresponding_source: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            licensing: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            ready_for_verified_publication: true,
        },
        evidence: ContainerReleaseEvidence {
            sbom: artifact_descriptor(MediaType::SpdxJson, b"sbom"),
            source: artifact_descriptor(MediaType::AosSourceClosure, b"source"),
            license: artifact_descriptor(MediaType::AosLicenseReport, b"license"),
            provenance: artifact_descriptor(MediaType::InTotoJson, b"provenance"),
            signature: artifact_descriptor(MediaType::DsseEnvelope, b"signature"),
        },
    };

    release.validate().expect("valid container release");
    let json = to_canonical_json(&release).expect("canonical container release");
    let expected = concat!(
        r#"{"evidence":{"license":{"artifactType":"application/vnd.aos.license-report.v1+json","digest":"sha256:cc1d3b0234846714b0aeda6cc34b057b4305bb83dd447fb88f816efeb59a4e96","mediaType":"application/vnd.oci.image.manifest.v1+json","size":7},"#,
        r#""provenance":{"artifactType":"application/vnd.in-toto+json","digest":"sha256:96d815328a42cb4ef89d5e0b7a1df6be43b484832c83a7b4596d8402c7c0b12b","mediaType":"application/vnd.oci.image.manifest.v1+json","size":10},"#,
        r#""sbom":{"artifactType":"application/spdx+json","digest":"sha256:98f3ae1ef67113d8140d4f6cb8d2830070e21ea48f091be519659846c771a374","mediaType":"application/vnd.oci.image.manifest.v1+json","size":4},"#,
        r#""signature":{"artifactType":"application/vnd.dsse.envelope.v1+json","digest":"sha256:1a2fc26dc7ea5a2a4748b7cb2b1ef193d96ab2c99f93092f69e63075b28d1278","mediaType":"application/vnd.oci.image.manifest.v1+json","size":9},"#,
        r#""source":{"artifactType":"application/vnd.aos.source-closure.v1+json","digest":"sha256:41cf6794ba4200b839c53531555f0f3998df4cbb01a4d5cb0b94e3ca5e23947d","mediaType":"application/vnd.oci.image.manifest.v1+json","size":6}},"#,
        r#""identity":{"image":"aos","package":"aos","packageVersion":"0.1.0","release":"1.0.0"},"mediaType":"application/vnd.aos.container-release.v1+json","#,
        r#""nix":{"closure":{"artifactType":"application/vnd.aos.nix-closure.v1+json","digest":"sha256:6d4cb937d6d22521566bba561458d0d1952df6df7a80e46ef5dab9014fbc3557","mediaType":"application/vnd.oci.image.manifest.v1+json","size":7},"#,
        r#""definition":{"attribute":"containerImages.aos","derivationPath":"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv"},"output":{"name":"out","storePath":"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container"}},"#,
        r#""oci":{"index":{"digest":"sha256:1bc04b5291c26a46d918139138b992d2de976d6851d0893b0476b85bfbdfc6e6","mediaType":"application/vnd.oci.image.index.v1+json","size":5},"#,
        r#""platformManifests":[{"digest":"sha256:8e7c7206e28f0d2a76643ceb44f86601b834c1dde73d45779114d7715c7dd7d7","mediaType":"application/vnd.oci.image.manifest.v1+json","platform":{"architecture":"amd64","os":"linux"},"size":14}]},"#,
        r#""qualification":{"correspondingSource":{"complete":true,"unknownPaths":[]},"licensing":{"complete":true,"unknownPaths":[]},"mapping":{"complete":true,"unknownPaths":[]},"readyForVerifiedPublication":true,"schema":"aos.container.evidence-qualification/v1"},"schemaVersion":1}"#,
    );
    assert_eq!(json, expected.as_bytes());
    assert_eq!(
        ContainerRelease::from_json(&json).expect("parse container release"),
        release
    );
}
