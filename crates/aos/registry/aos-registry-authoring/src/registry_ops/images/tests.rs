//! Tests for provider-neutral image publication identities.

use crate::registry_ops::test_support::{
    inspect_test_image, rewrite_test_image_parent, write_direct_image_output,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn image_publisher_binds_disk_and_opaque_contract_bytes() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(
        temp.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let image = inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").unwrap();

    assert_eq!(image.delivery.byte_size, 36 * 1024 * 1024);
    assert_eq!(image.delivery.filename, "aos-test.qcow2");
    assert_eq!(image.delivery.schema_version, 2);
    assert_eq!(
        image.delivery.artifact_contract.schema,
        "aos.test-boot-artifacts/v1"
    );
    assert_eq!(
        image.delivery.artifact_contract.document.store_path,
        image.info_store.path
    );
    let artifacts = image.delivery.artifact_contract.artifacts.as_ref().unwrap();
    assert_eq!(artifacts.store_path, image.payload.path);
    assert_eq!(artifacts.nar_hash, image.payload.nar_hash);
    assert_eq!(image.disk.identity.len, image.delivery.byte_size);
}

#[test]
fn image_publisher_accepts_provider_owned_contract_fields() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(
        temp.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let info_path = Path::new(&store.path).join("image-info.json");
    let mut info: serde_json::Value =
        serde_json::from_slice(&fs::read(&info_path).unwrap()).unwrap();
    info["selectedProviderFacts"] = serde_json::json!({"shape": ["opaque", 1]});
    fs::write(&info_path, serde_json::to_vec(&info).unwrap()).unwrap();

    inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").unwrap();
}

#[test]
fn image_publisher_rejects_disk_tamper_and_wrong_targets() {
    let tamper = TempDir::new().unwrap();
    let store = write_direct_image_output(tamper.path(), "raw", serde_json::json!(["bare-metal"]));
    fs::write(
        Path::new(&store.path).join("aos-test.img.zst"),
        b"changed bytes",
    )
    .unwrap();
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
fn image_publisher_rejects_path_traversal_parent_drift_and_private_paths() {
    let traversal = TempDir::new().unwrap();
    let store =
        write_direct_image_output(traversal.path(), "raw", serde_json::json!(["bare-metal"]));
    let info_path = Path::new(&store.path).join("image-delivery.json");
    let mut info: serde_json::Value =
        serde_json::from_slice(&fs::read(&info_path).unwrap()).unwrap();
    info["filename"] = serde_json::json!("../disk.img");
    fs::write(&info_path, serde_json::to_vec(&info).unwrap()).unwrap();
    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());

    let drift = TempDir::new().unwrap();
    let store = write_direct_image_output(drift.path(), "raw", serde_json::json!(["bare-metal"]));
    assert!(inspect_test_image("raw", store, "2026.09", "x86_64-linux").is_err());

    let platform_drift = TempDir::new().unwrap();
    let store = write_direct_image_output(
        platform_drift.path(),
        "raw",
        serde_json::json!(["bare-metal"]),
    );
    rewrite_test_image_parent(&store, "2026.08", "aarch64-linux");
    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
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
fn image_publisher_rejects_private_paths_inside_the_opaque_contract() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let info_path = Path::new(&store.path).join("image-info.json");
    let mut info: serde_json::Value =
        serde_json::from_slice(&fs::read(&info_path).unwrap()).unwrap();
    info["selectedProviderFacts"] = serde_json::json!({"buildPath": "/nix/store/private"});
    fs::write(&info_path, serde_json::to_vec(&info).unwrap()).unwrap();

    assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
}

#[test]
fn delivery_replacement_cannot_change_a_pinned_publication() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();
    let original = image.producer_delivery.path.clone();
    fs::rename(&original, temp.path().join("original-delivery.json")).unwrap();
    fs::write(&original, b"replacement envelope").unwrap();

    assert!(image.recheck_for_commit().is_err());
}

#[test]
fn provider_document_is_not_accepted_as_a_delivery_envelope() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let (disk, info) =
        crate::registry_ops::test_support::write_test_image_projections(&store).unwrap();
    let root = Path::new(&store.path);
    fs::copy(
        root.join("image-info.json"),
        root.join("image-delivery.json"),
    )
    .unwrap();

    let result = super::inspect_published_image(
        "raw",
        store,
        disk,
        info,
        "aos.test-boot-artifacts/v1",
        "test",
        "2026.08",
        "x86_64-linux",
    );
    assert!(result.is_err());
}

#[test]
fn explicit_provider_document_must_match_the_pinned_artifact_set() {
    let temp = TempDir::new().unwrap();
    let store = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let (disk, info) =
        crate::registry_ops::test_support::write_test_image_projections(&store).unwrap();
    fs::write(&info.path, b"different opaque provider document").unwrap();

    let result = super::inspect_published_image(
        "raw",
        store,
        disk,
        info,
        "aos.test-boot-artifacts/v1",
        "test",
        "2026.08",
        "x86_64-linux",
    );
    assert!(result.is_err());
}

fn copy_store_info(record: &super::StorePathInfo) -> super::StorePathInfo {
    super::StorePathInfo {
        path: record.path.clone(),
        nar_hash: record.nar_hash.clone(),
        nar_size: record.nar_size,
        references: record.references.clone(),
        closure_size: record.closure_size,
    }
}

#[test]
fn image_encodings_share_one_pinned_artifact_set_and_contract() {
    let raw_temp = TempDir::new().unwrap();
    let raw = write_direct_image_output(raw_temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let qcow_temp = TempDir::new().unwrap();
    let qcow = write_direct_image_output(
        qcow_temp.path(),
        "qcow2",
        serde_json::json!(["qemu-kvm", "openstack"]),
    );
    let (raw_disk, info) =
        crate::registry_ops::test_support::write_test_image_projections(&raw).unwrap();
    let (qcow_disk, _) =
        crate::registry_ops::test_support::write_test_image_projections(&qcow).unwrap();
    let root = Path::new(&raw.path);
    fs::copy(
        root.join("image-delivery.json"),
        root.join("image-delivery-raw.json"),
    )
    .unwrap();
    fs::copy(
        Path::new(&qcow.path).join("image-delivery.json"),
        root.join("image-delivery-qcow2.json"),
    )
    .unwrap();
    fs::copy(
        Path::new(&qcow.path).join("aos-test.qcow2"),
        root.join("aos-test.qcow2"),
    )
    .unwrap();

    let inspect = |format, disk| {
        super::inspect_published_image(
            format,
            copy_store_info(&raw),
            disk,
            copy_store_info(&info),
            "aos.test-boot-artifacts/v1",
            "test",
            "2026.08",
            "x86_64-linux",
        )
    };
    let raw_image = inspect("raw", raw_disk).unwrap();
    let qcow_image = inspect("qcow2", qcow_disk).unwrap();

    assert_eq!(
        raw_image.delivery.artifact_contract,
        qcow_image.delivery.artifact_contract
    );
    assert_eq!(
        raw_image.delivery.logical_disk_sha256,
        qcow_image.delivery.logical_disk_sha256
    );
    assert_ne!(raw_image.delivery.sha256, qcow_image.delivery.sha256);
    raw_image.recheck_for_commit().unwrap();
    qcow_image.recheck_for_commit().unwrap();

    let selected = root.join("image-delivery-qcow2.json");
    fs::rename(&selected, qcow_temp.path().join("retained-delivery.json")).unwrap();
    fs::write(selected, b"replacement envelope").unwrap();
    assert!(qcow_image.recheck_for_commit().is_err());
}

#[cfg(unix)]
#[test]
fn a_present_invalid_format_envelope_cannot_fall_back_to_legacy() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let payload = write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
    let (disk, info) =
        crate::registry_ops::test_support::write_test_image_projections(&payload).unwrap();
    symlink(
        "image-delivery.json",
        Path::new(&payload.path).join("image-delivery-raw.json"),
    )
    .unwrap();

    let inspect = |format| {
        super::inspect_published_image(
            format,
            copy_store_info(&payload),
            copy_store_info(&disk),
            copy_store_info(&info),
            "aos.test-boot-artifacts/v1",
            "test",
            "2026.08",
            "x86_64-linux",
        )
    };
    assert!(inspect("raw").is_err());
    assert!(inspect("../raw").is_err());
}
