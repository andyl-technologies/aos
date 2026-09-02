//! Shared deterministic OCI fixture construction for integration tests.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use aos_oci_types::{
    Annotations, CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA, CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE,
    CONTAINER_SIGNATURE_INPUT_SCHEMA, ContainerEvidenceMappingQualification,
    ContainerEvidenceQualification, ContainerEvidenceQualificationCheck, ContainerNixProvenance,
    ContainerOciRelease, ContainerRelease, ContainerReleaseEvidence, ContainerReleaseIdentity,
    ContainerSignatureInput, ContainerSignatureInputEvidence, Descriptor, HistoryEntry,
    ImageConfig, ImageIndex, ImageManifest, ImageRuntimeConfig, MediaType, NixDefinitionIdentity,
    NixOutputIdentity, Platform, RootFs, RootFsType, Sha256Digest, to_canonical_json,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use tempfile::TempDir;

pub struct Fixture {
    pub temporary: TempDir,
    pub index: Vec<u8>,
    pub manifest: Vec<u8>,
    pub manifest_descriptor: Descriptor,
    pub blobs: BTreeMap<Sha256Digest, Vec<u8>>,
    pub layer_descriptor: Descriptor,
}

impl Fixture {
    pub fn root(&self) -> &Path {
        self.temporary.path()
    }
}

pub fn fixture() -> Fixture {
    let layer_tar = layer_tar();
    let diff_id = Sha256Digest::digest(&layer_tar);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder
        .write_all(&layer_tar)
        .expect("compress fixture layer");
    let layer = encoder.finish().expect("finish fixture gzip");
    let layer_descriptor = descriptor(MediaType::OciLayerGzip, &layer, None);

    let config = ImageConfig {
        created: Some("1970-01-01T00:00:01Z".to_string()),
        author: None,
        architecture: "amd64".to_string(),
        os: "linux".to_string(),
        os_version: None,
        os_features: Vec::new(),
        variant: None,
        config: Some(ImageRuntimeConfig {
            entrypoint: vec!["/usr/bin/test".to_string()],
            cmd: vec!["--help".to_string()],
            ..ImageRuntimeConfig::default()
        }),
        rootfs: RootFs {
            rootfs_type: RootFsType::Layers,
            diff_ids: vec![diff_id],
        },
        history: vec![HistoryEntry {
            created_by: Some("fixture".to_string()),
            ..HistoryEntry::default()
        }],
    };
    config.validate().expect("fixture config");
    let config = to_canonical_json(&config).expect("canonical fixture config");
    let config_descriptor = descriptor(MediaType::OciImageConfig, &config, None);

    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: None,
        config: config_descriptor.clone(),
        layers: vec![layer_descriptor.clone()],
        subject: None,
        annotations: Annotations::new(),
    };
    manifest.validate().expect("fixture manifest");
    let manifest = to_canonical_json(&manifest).expect("canonical fixture manifest");
    let manifest_descriptor = descriptor(
        MediaType::OciImageManifest,
        &manifest,
        Some(Platform::linux_amd64()),
    );

    let index = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![manifest_descriptor.clone()],
        subject: None,
        annotations: Annotations::new(),
    };
    index.validate().expect("fixture index");
    let index = to_canonical_json(&index).expect("canonical fixture index");

    let temporary = tempfile::tempdir().expect("fixture layout root");
    fs::create_dir_all(temporary.path().join("blobs/sha256")).expect("fixture blob directory");
    fs::write(
        temporary.path().join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .expect("fixture layout marker");
    fs::write(temporary.path().join("index.json"), &index).expect("fixture index file");

    let mut blobs = BTreeMap::new();
    blobs.insert(config_descriptor.digest, config);
    blobs.insert(layer_descriptor.digest, layer);
    blobs.insert(manifest_descriptor.digest, manifest.clone());
    for (digest, bytes) in &blobs {
        fs::write(
            temporary.path().join("blobs/sha256").join(digest.encoded()),
            bytes,
        )
        .expect("fixture blob");
    }

    Fixture {
        temporary,
        index,
        manifest,
        manifest_descriptor,
        blobs,
        layer_descriptor,
    }
}

pub fn add_signed_release_graph(fixture: &Fixture) -> ContainerRelease {
    let index = Descriptor {
        media_type: MediaType::OciImageIndex,
        digest: Sha256Digest::digest(&fixture.index),
        size: fixture.index.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    };
    let artifact = |role: &str, artifact_type: MediaType| {
        let payload_value = if artifact_type == MediaType::AosNixClosure {
            let uncompressed = layer_tar();
            let diff_id = Sha256Digest::digest(&uncompressed);
            let store_path = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container";
            serde_json::json!({
                "schema": "aos.container.nix-closure/v1",
                "subject": index,
                "roots": [store_path],
                "layers": [fixture.layer_descriptor],
                "paths": [{
                    "path": store_path,
                    "narHash": diff_id,
                    "narSize": uncompressed.len(),
                    "references": [],
                    "layer": {
                        "name": "runtime",
                        "digest": fixture.layer_descriptor.digest,
                        "diffID": diff_id,
                        "compressedSize": fixture.layer_descriptor.size,
                        "uncompressedSize": uncompressed.len(),
                    },
                    "package": {"name": "aos"},
                }],
            })
        } else {
            serde_json::json!({"role": role})
        };
        let payload = to_canonical_json(&payload_value).expect("canonical evidence payload");
        let payload_descriptor = content_descriptor(artifact_type, &payload);
        let empty = b"{}".to_vec();
        let empty_descriptor = content_descriptor(MediaType::OciEmptyJson, &empty);
        let source_archive = (artifact_type == MediaType::AosSourceClosure)
            .then(|| content_descriptor(MediaType::AosSourceArchive, b"source archive fixture"));
        let mut layers = vec![payload_descriptor.clone()];
        layers.extend(source_archive.clone());
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: Some(artifact_type),
            config: empty_descriptor.clone(),
            layers,
            subject: Some(index.clone()),
            annotations: Annotations::new(),
        };
        let manifest = to_canonical_json(&manifest).expect("canonical evidence manifest");
        let mut manifest_descriptor = content_descriptor(MediaType::OciImageManifest, &manifest);
        manifest_descriptor.artifact_type = Some(artifact_type);
        for (descriptor, bytes) in [
            (&empty_descriptor, empty.as_slice()),
            (&payload_descriptor, payload.as_slice()),
            (&manifest_descriptor, manifest.as_slice()),
        ] {
            fs::write(
                fixture
                    .root()
                    .join("blobs/sha256")
                    .join(descriptor.digest.encoded()),
                bytes,
            )
            .expect("release evidence blob");
        }
        if let Some(source_archive) = source_archive {
            fs::write(
                fixture
                    .root()
                    .join("blobs/sha256")
                    .join(source_archive.digest.encoded()),
                b"source archive fixture",
            )
            .expect("source archive blob");
        }
        manifest_descriptor
    };

    ContainerRelease {
        schema_version: 1,
        media_type: MediaType::AosContainerRelease,
        identity: ContainerReleaseIdentity {
            release: "1.0.0".to_string(),
            package: "aos".to_string(),
            package_version: "0.1.0".to_string(),
            image: "aos".to_string(),
        },
        oci: ContainerOciRelease {
            index: index.clone(),
            platform_manifests: vec![fixture.manifest_descriptor.clone()],
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
            closure: artifact("closure", MediaType::AosNixClosure),
        },
        qualification: ready_qualification(),
        evidence: ContainerReleaseEvidence {
            sbom: artifact("sbom", MediaType::SpdxJson),
            source: artifact("source", MediaType::AosSourceClosure),
            license: artifact("license", MediaType::AosLicenseReport),
            provenance: artifact("provenance", MediaType::InTotoJson),
            signature: artifact("signature", MediaType::DsseEnvelope),
        },
    }
}

pub fn publication_signature_input(release: &ContainerRelease) -> ContainerSignatureInput {
    ContainerSignatureInput {
        schema: CONTAINER_SIGNATURE_INPUT_SCHEMA.to_string(),
        identity: release.identity.clone(),
        oci: release.oci.clone(),
        nix: release.nix.clone(),
        evidence: ContainerSignatureInputEvidence {
            sbom: release.evidence.sbom.clone(),
            source: release.evidence.source.clone(),
            license: release.evidence.license.clone(),
            provenance: release.evidence.provenance.clone(),
        },
        qualification: release.qualification.clone(),
    }
}

pub fn write_publication_inputs(inputs: &Path, layout: &Path, input: &ContainerSignatureInput) {
    fs::create_dir(inputs).expect("inputs");
    copy_tree(layout, &inputs.join("oci-layout"));
    copy_tree(layout, &inputs.join("evidence-layout"));
    for name in ["oci-layout", "evidence-layout"] {
        fs::write(
            inputs
                .join(name)
                .join("blobs/sha256")
                .join(input.oci.index.digest.encoded()),
            fs::read(layout.join("index.json")).expect("read root index"),
        )
        .expect("write root index blob");
    }
    let input_bytes = to_canonical_json(input).expect("canonical input");
    fs::write(inputs.join("signature-input.json"), &input_bytes).expect("signature input");

    let unsigned = serde_json::to_value(input).expect("unsigned value");
    let mut unsigned = unsigned.as_object().expect("unsigned object").clone();
    unsigned.remove("schema");
    let signing_request = serde_json::json!({
        "schema": "aos.container.signing-request/v1",
        "input": {
            "mediaType": CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE,
            "digest": Sha256Digest::digest(&input_bytes),
            "size": input_bytes.len(),
        },
        "requiredOutput": {
            "payloadMediaType": "application/vnd.dsse.envelope.v1+json",
            "artifactManifestMediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactSubject": input.oci.index,
            "finalSidecarPath": "containers/v1/index.json",
            "finalSidecarMediaType": "application/vnd.aos.container-release.v1+json",
        },
        "constraints": {
            "exactInputBytesRequired": true,
            "privateMaterialPermittedInNixBuild": false,
            "finalizerMustRejectUnqualifiedInput": true,
            "finalizerMustVerifyEnvelope": true,
            "finalizerMustAddSignatureReferrerDescriptor": true,
            "releaseSurfaceMustSignFinalSidecar": true,
        },
        "qualified": true,
        "unsignedRelease": unsigned,
    });
    fs::write(
        inputs.join("signing-request.json"),
        to_canonical_json(&signing_request).expect("signing request"),
    )
    .expect("write signing request");
    let roots = serde_json::json!({
        "schema": "aos.container.publication-roots/v1",
        "image": input.oci.index,
        "referrers": [
            input.nix.closure,
            input.evidence.sbom,
            input.evidence.source,
            input.evidence.license,
            input.evidence.provenance,
        ],
    });
    fs::write(
        inputs.join("publication-roots.json"),
        to_canonical_json(&roots).expect("publication roots"),
    )
    .expect("write publication roots");
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("copy directory");
    for entry in fs::read_dir(source).expect("read copy source") {
        let entry = entry.expect("copy entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy file");
        }
    }
}

pub fn replace_signature_artifact(
    fixture: &Fixture,
    release: &mut ContainerRelease,
    envelope: &[u8],
) {
    let payload_descriptor = content_descriptor(MediaType::DsseEnvelope, envelope);
    let empty = b"{}".to_vec();
    let empty_descriptor = content_descriptor(MediaType::OciEmptyJson, &empty);
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: Some(MediaType::DsseEnvelope),
        config: empty_descriptor.clone(),
        layers: vec![payload_descriptor.clone()],
        subject: Some(release.oci.index.clone()),
        annotations: Annotations::new(),
    };
    let manifest = to_canonical_json(&manifest).expect("canonical signature artifact manifest");
    let mut descriptor = content_descriptor(MediaType::OciImageManifest, &manifest);
    descriptor.artifact_type = Some(MediaType::DsseEnvelope);
    for (object, bytes) in [
        (&empty_descriptor, empty.as_slice()),
        (&payload_descriptor, envelope),
        (&descriptor, manifest.as_slice()),
    ] {
        fs::write(
            fixture
                .root()
                .join("blobs/sha256")
                .join(object.digest.encoded()),
            bytes,
        )
        .expect("container signature artifact blob");
    }
    release.evidence.signature = descriptor;
}

pub fn ready_qualification() -> ContainerEvidenceQualification {
    ContainerEvidenceQualification {
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
    }
}

fn content_descriptor(media_type: MediaType, bytes: &[u8]) -> Descriptor {
    Descriptor {
        media_type,
        digest: Sha256Digest::digest(bytes),
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    }
}

fn descriptor(media_type: MediaType, bytes: &[u8], platform: Option<Platform>) -> Descriptor {
    Descriptor {
        media_type,
        digest: Sha256Digest::digest(bytes),
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform,
    }
}

fn layer_tar() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut bytes);
        builder.mode(tar::HeaderMode::Deterministic);
        let content = b"aos OCI fixture\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/share/aos-fixture", &content[..])
            .expect("fixture tar member");
        builder.finish().expect("fixture tar");
    }
    bytes
}
