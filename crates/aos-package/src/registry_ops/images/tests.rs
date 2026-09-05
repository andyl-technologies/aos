//! Tests for disk-image producer metadata validation and publication input inspection.

use super::{
    MAX_LOGICAL_DISK_BYTES, ProducerArtifactBudgets, ProducerPartitionInfo,
    inspect_published_image_with, validate_image_artifact_budgets, validate_logical_disk_geometry,
};
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::test_support::{
    inspect_test_image, write_direct_image_output, write_test_image_projections,
};
use crate::registry_ops::uki::SbFacts;
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn image_artifact_budgets_match_payload_and_partition_contracts() {
    let partitions = [
        ProducerPartitionInfo {
            number: 1,
            label: "ESP".into(),
            kind: "esp".into(),
            filesystem: "vfat".into(),
            size_mi_b: 384,
            offset_bytes: 0,
            size_bytes: 384 * 1024 * 1024,
        },
        ProducerPartitionInfo {
            number: 2,
            label: "root-a".into(),
            kind: "root".into(),
            filesystem: "erofs".into(),
            size_mi_b: 512,
            offset_bytes: 384 * 1024 * 1024,
            size_bytes: 512 * 1024 * 1024,
        },
        ProducerPartitionInfo {
            number: 3,
            label: "root-a-hash".into(),
            kind: "verity".into(),
            filesystem: "dm-verity".into(),
            size_mi_b: 16,
            offset_bytes: 896 * 1024 * 1024,
            size_bytes: 16 * 1024 * 1024,
        },
    ];
    let mut budgets = ProducerArtifactBudgets {
        root: 512,
        verity: 16,
        initrd: 128,
        uki: 160,
        esp: 384,
        runtime_closure: 768,
        download: 640,
    };

    assert!(
        validate_image_artifact_budgets(
            &budgets,
            590 * 1024 * 1024,
            108 * 1024 * 1024,
            &partitions,
        )
        .is_ok()
    );

    budgets.root = 511;
    assert!(
        validate_image_artifact_budgets(
            &budgets,
            590 * 1024 * 1024,
            108 * 1024 * 1024,
            &partitions,
        )
        .is_ok()
    );

    budgets.root = 513;
    assert!(
        validate_image_artifact_budgets(
            &budgets,
            590 * 1024 * 1024,
            108 * 1024 * 1024,
            &partitions,
        )
        .is_err()
    );

    budgets.root = 512;
    budgets.download = 589;
    assert!(
        validate_image_artifact_budgets(
            &budgets,
            590 * 1024 * 1024,
            108 * 1024 * 1024,
            &partitions,
        )
        .is_err()
    );
}

#[test]
fn logical_disk_geometry_bounds_decompression_before_materialization() {
    let mib = 1024 * 1024;
    assert!(validate_logical_disk_geometry(36 * mib, &[(mib, 35 * mib)]).is_ok());
    assert!(validate_logical_disk_geometry(35 * mib, &[(mib, 35 * mib)]).is_err());
    assert!(
        validate_logical_disk_geometry(
            MAX_LOGICAL_DISK_BYTES + mib,
            &[(mib, MAX_LOGICAL_DISK_BYTES)]
        )
        .is_err()
    );
}

#[test]
fn image_publisher_binds_exact_disk_and_metadata_bytes() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(
        temp.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let image = inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").unwrap();
    assert_eq!(image.delivery.byte_size, 36 * 1024 * 1024);
    assert_eq!(image.delivery.filename, "aos-test.qcow2");
    assert_eq!(image.delivery.image_info.filename, "image-info.json");
    assert_eq!(image.delivery.schema_version, 2);
    assert!(image.delivery.object_key.is_empty());
    assert_eq!(image.delivery.image_info.store_path, image.info_store.path);
    let update_payload = image.delivery.update_payload.as_ref().unwrap();
    assert_eq!(update_payload.store_path, image.payload.path);
    assert_eq!(update_payload.nar_hash, image.payload.nar_hash);
    assert_eq!(update_payload.nar_size, image.payload.nar_size);
    assert_eq!(image.disk.identity.len, image.delivery.byte_size);
    assert_eq!(
        image.uki.path.extension().and_then(|value| value.to_str()),
        Some("efi")
    );
    assert_eq!(image.uki.identity.len, 23);
    assert_eq!(image.delivery.uki.sha256.len(), 64);
    let mut public_info_file = image.image_info.file.try_clone().unwrap();
    public_info_file.seek(SeekFrom::Start(0)).unwrap();
    let mut public_info = String::new();
    public_info_file.read_to_string(&mut public_info).unwrap();
    assert!(!public_info.contains("ukiStorePath"));
    assert_eq!(image.image_info.identity.len, public_info.len() as u64);
}

#[test]
fn image_publisher_accepts_only_exact_target_platform_metadata() {
    let accepted = TempDir::new().unwrap();
    let store = write_direct_image_output(
        accepted.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let support = Path::new(&store.path).join("nix-support");
    fs::create_dir(&support).unwrap();
    fs::write(support.join("aos-target-platform"), "x86_64-linux\n").unwrap();
    inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").unwrap();

    let wrong = TempDir::new().unwrap();
    let store = write_direct_image_output(
        wrong.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let support = Path::new(&store.path).join("nix-support");
    fs::create_dir(&support).unwrap();
    fs::write(support.join("aos-target-platform"), "aarch64-linux\n").unwrap();
    assert!(inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").is_err());

    let extra = TempDir::new().unwrap();
    let store = write_direct_image_output(
        extra.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let support = Path::new(&store.path).join("nix-support");
    fs::create_dir(&support).unwrap();
    fs::write(support.join("aos-target-platform"), "x86_64-linux\n").unwrap();
    fs::write(support.join("unexpected"), "metadata\n").unwrap();
    assert!(inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").is_err());

    let oversized = TempDir::new().unwrap();
    let store = write_direct_image_output(
        oversized.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let support = Path::new(&store.path).join("nix-support");
    fs::create_dir(&support).unwrap();
    fs::write(support.join("aos-target-platform"), "x".repeat(129)).unwrap();
    assert!(inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").is_err());
}

#[test]
fn image_publisher_rejects_tamper_ambiguity_and_wrong_targets() {
    let tamper = TempDir::new().unwrap();
    let store = write_direct_image_output(tamper.path(), "raw", serde_json::json!(["bare-metal"]));
    fs::write(
        Path::new(&store.path).join("aos-test.img.zst"),
        b"changed bytes",
    )
    .unwrap();
    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());

    let ambiguous = TempDir::new().unwrap();
    let store =
        write_direct_image_output(ambiguous.path(), "raw", serde_json::json!(["bare-metal"]));
    fs::write(Path::new(&store.path).join("another.img"), b"ambiguous").unwrap();
    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());

    let wrong_target = TempDir::new().unwrap();
    let store = write_direct_image_output(
        wrong_target.path(),
        "qcow2",
        serde_json::json!(["bare-metal"]),
    );
    assert!(inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").is_err());
}

#[test]
fn image_publisher_rejects_path_traversal_and_parent_drift() {
    let traversal = TempDir::new().unwrap();
    let store =
        write_direct_image_output(traversal.path(), "raw", serde_json::json!(["bare-metal"]));
    let info_path = Path::new(&store.path).join("image-info.json");
    let mut info: serde_json::Value =
        serde_json::from_slice(&fs::read(&info_path).unwrap()).unwrap();
    info["filename"] = serde_json::json!("../disk.img");
    fs::write(&info_path, serde_json::to_vec(&info).unwrap()).unwrap();
    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());

    let drift = TempDir::new().unwrap();
    let store = write_direct_image_output(drift.path(), "raw", serde_json::json!(["bare-metal"]));
    assert!(inspect_test_image("raw", store, "2026.09", "x86_64-linux").is_err());
    let store = StorePathInfo {
        path: drift
            .path()
            .join("00000000000000000000000000000000-image-output")
            .display()
            .to_string(),
        nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
        nar_size: 128,
        references: Vec::new(),
        closure_size: 128,
    };
    assert!(inspect_test_image("raw", store, "2026.08", "aarch64-linux").is_err());
}

#[cfg(unix)]
#[test]
fn image_publisher_rejects_symlinked_artifacts() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let target = TempDir::new().unwrap();
    let external = target.path().join("real.img");
    let image_path = Path::new(&store.path).join("aos-test.img.zst");
    fs::rename(&image_path, &external).unwrap();
    symlink(&external, &image_path).unwrap();
    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
}

#[cfg(unix)]
#[test]
fn image_publisher_rejects_hardlinked_artifacts() {
    let temp = TempDir::new().unwrap();
    let mut store =
        write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let ordinary_output = temp.path().join("image-output");
    fs::rename(&store.path, &ordinary_output).unwrap();
    store.path = ordinary_output.display().to_string();
    fs::hard_link(
        Path::new(&store.path).join("aos-test.img.zst"),
        temp.path().join("disk-alias.img"),
    )
    .unwrap();
    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
}

#[test]
fn pinned_image_recheck_detects_namespace_replacement() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();
    let image_path = image.disk.path.clone();
    fs::rename(&image_path, temp.path().join("original.img")).unwrap();
    fs::write(&image_path, b"replacement bytes").unwrap();
    assert!(image.recheck_for_commit().is_err());
}

#[test]
fn image_publisher_distinguishes_transfer_and_logical_disk_identity() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();
    assert!(image.delivery.byte_size < image.virtual_size_bytes);
    assert_ne!(image.delivery.sha256, image.delivery.logical_disk_sha256);
}

#[test]
fn image_publisher_rejects_unknown_or_private_metadata() {
    for (field, value) in [
        ("publisherToken", serde_json::json!("secret")),
        ("buildPath", serde_json::json!("/nix/store/secret-input")),
    ] {
        let temp = TempDir::new().unwrap();
        let store =
            write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
        let info_path = Path::new(&store.path).join("image-info.json");
        let mut info: serde_json::Value =
            serde_json::from_slice(&fs::read(&info_path).unwrap()).unwrap();
        info[field] = value;
        fs::write(&info_path, serde_json::to_vec(&info).unwrap()).unwrap();
        assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
    }
}

#[test]
fn image_publisher_rejects_uki_input_or_signature_state_drift() {
    let input_drift = TempDir::new().unwrap();
    let store =
        write_direct_image_output(input_drift.path(), "raw", serde_json::json!(["bare-metal"]));
    let wrong_uki = input_drift.path().join("uki-output/other.efi");
    fs::write(&wrong_uki, b"other").unwrap();
    let (disk_store, info_store) = write_test_image_projections(&store).unwrap();
    let result = inspect_published_image_with(
        "raw",
        store,
        disk_store,
        info_store,
        &wrong_uki,
        "test",
        "2026.08",
        "x86_64-linux",
        None,
        |_uki, _db_cert| Ok(SbFacts::default()),
    );
    assert!(result.is_err());

    let signature_drift = TempDir::new().unwrap();
    let store = write_direct_image_output(
        signature_drift.path(),
        "raw",
        serde_json::json!(["bare-metal"]),
    );
    let uki_path = signature_drift.path().join("uki-output/aos-test.efi");
    let (disk_store, info_store) = write_test_image_projections(&store).unwrap();
    let result = inspect_published_image_with(
        "raw",
        store,
        disk_store,
        info_store,
        &uki_path,
        "test",
        "2026.08",
        "x86_64-linux",
        None,
        |_uki, _db_cert| {
            Ok(SbFacts {
                signer_cert_sha256: Some("c".repeat(64)),
                ..SbFacts::default()
            })
        },
    );
    assert!(result.is_err());
}
