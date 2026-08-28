//! Shared deterministic OCI fixture construction for integration tests.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use aos_oci_types::{
    Annotations, Descriptor, HistoryEntry, ImageConfig, ImageIndex, ImageManifest,
    ImageRuntimeConfig, MediaType, Platform, RootFs, RootFsType, Sha256Digest, to_canonical_json,
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
