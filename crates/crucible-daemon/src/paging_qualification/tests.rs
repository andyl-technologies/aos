//! Canonical receipt rejection tests without native qualification claims.

use super::*;

fn receipt() -> serde_json::Value {
    serde_json::json!({
        "edition": 1,
        "host_kernel_build_id": "ab".repeat(20),
        "host_kernel_blake3": "01".repeat(32),
        "qemu_blake3": "02".repeat(32),
        "plugin_blake3": "03".repeat(32),
        "topology_blake3": "04".repeat(32),
        "build_graph_sha256": "05".repeat(32),
        "profile": {
            "machine": "pc-q35-9.2", "accelerator": "sim", "thread_mode": "single",
            "architecture": "x86_64", "guest_ram_bytes": 64 * 1024 * 1024,
            "vcpu_count": 1, "page_bytes": 4096,
        },
        "operations": {
            "full_peak_paused_reclamation": true, "read_first_faults": true,
            "write_first_faults": true, "authenticated_spill": true,
            "logical_state_unchanged": true, "strict_low_peak": false,
            "hot_fork": false, "lazy_restore": false, "transfer": false,
        },
        "activity": {
            "successful_missing_installs": 2,
            "successful_missing_read_installs": 1,
            "successful_missing_write_installs": 1,
            "write_protect_transitions": 1,
            "preservation_reads": 1,
            "preservation_writes": 1,
            "physical_discards": 1,
        },
    })
}

fn encode(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_else(|error| panic!("canonical receipt fixture: {error}"))
}

#[test]
fn receipt_codec_binds_all_bytes_without_enabling_successor_capabilities() {
    let bytes = encode(&receipt());
    let receipt = ValidatedReceipt::decode(&bytes)
        .unwrap_or_else(|error| panic!("codec-only valid receipt: {error}"));

    assert_eq!(receipt.evidence, *blake3::hash(&bytes).as_bytes());
    let scope = receipt.qualification();
    assert_eq!(scope.backend, HostRamBackend::PausedPager);
    assert!(scope.authenticated_pages);
    assert!(!scope.fault_safe_progress);
    assert!(!scope.bounded_execution_peak);
    assert!(!scope.hot_fork);
    assert!(!scope.lazy_restore);
    assert!(!scope.authenticated_transfer);
}

#[test]
fn receipt_refuses_noncanonical_unknown_truncated_and_oversized_json() {
    let value = receipt();
    let bytes = encode(&value);
    for length in 0..bytes.len() {
        assert!(ValidatedReceipt::decode(&bytes[..length]).is_err());
    }
    assert!(
        ValidatedReceipt::decode(
            &serde_json::to_vec_pretty(&value)
                .unwrap_or_else(|error| panic!("pretty JSON: {error}"))
        )
        .is_err()
    );
    assert!(ValidatedReceipt::decode(&vec![b' '; MAX_RECEIPT_BYTES + 1]).is_err());

    let mut value = receipt();
    value["unrecognized"] = serde_json::json!(true);
    assert!(ValidatedReceipt::decode(&encode(&value)).is_err());
    let duplicate = String::from_utf8(bytes)
        .unwrap_or_else(|error| panic!("ASCII JSON: {error}"))
        .replacen("\"edition\":1", "\"edition\":1,\"edition\":1", 1);
    assert!(ValidatedReceipt::decode(duplicate.as_bytes()).is_err());
}

#[test]
fn receipt_refuses_unproved_operations_profiles_and_inconsistent_activity() {
    for field in ["strict_low_peak", "hot_fork", "lazy_restore", "transfer"] {
        let mut value = receipt();
        value["operations"][field] = serde_json::json!(true);
        assert!(ValidatedReceipt::decode(&encode(&value)).is_err());
    }
    for field in [
        "read_first_faults",
        "write_first_faults",
        "authenticated_spill",
        "logical_state_unchanged",
        "full_peak_paused_reclamation",
    ] {
        let mut value = receipt();
        value["operations"][field] = serde_json::json!(false);
        assert!(ValidatedReceipt::decode(&encode(&value)).is_err());
    }
    for (field, changed) in [
        ("machine", serde_json::json!("pc-q35-10.0")),
        ("accelerator", serde_json::json!("tcg")),
        ("thread_mode", serde_json::json!("multi")),
        ("architecture", serde_json::json!("aarch64")),
        ("guest_ram_bytes", serde_json::json!(128 * 1024 * 1024)),
        ("vcpu_count", serde_json::json!(2)),
        ("page_bytes", serde_json::json!(8192)),
    ] {
        let mut value = receipt();
        value["profile"][field] = changed;
        assert!(ValidatedReceipt::decode(&encode(&value)).is_err());
    }
    for (field, changed) in [
        ("successful_missing_installs", 3),
        ("successful_missing_write_installs", 0),
        ("preservation_writes", 0),
        ("physical_discards", 0),
    ] {
        let mut value = receipt();
        value["activity"][field] = serde_json::json!(changed);
        assert!(ValidatedReceipt::decode(&encode(&value)).is_err());
    }
    let mut value = receipt();
    value["qemu_blake3"] = serde_json::json!("AB".repeat(32));
    assert!(ValidatedReceipt::decode(&encode(&value)).is_err());
}

#[test]
fn observed_kernel_and_artifact_mismatches_never_match_a_codec_fixture() {
    let value = ValidatedReceipt::decode(&encode(&receipt()))
        .unwrap_or_else(|error| panic!("codec-only receipt: {error}"));
    let node = crucible::WorldNode {
        id: crucible::NodeId {
            name: String::from("memory"),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: String::new(),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 1 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    };
    let config = ProductionVmLifecycleConfig::new(
        "/missing/qemu",
        "/missing/plugin",
        "/missing/kernel",
        "/missing/root",
        "/missing/state",
    );
    let mut boundary_called = false;
    assert!(
        !value
            .matches_launch(&config, &node, &mut || {
                boundary_called = true;
                Ok(())
            })
            .unwrap_or_else(|error| panic!("profile mismatch: {error}"))
    );
    assert!(!boundary_called);
}

#[test]
fn mutable_or_escaping_artifact_paths_cannot_qualify_a_launch() {
    for path in [
        "qemu",
        "/tmp/qemu",
        "/nix/store/../tmp/qemu",
        "/usr/bin/qemu",
    ] {
        assert!(
            !artifacts::immutable_store_artifact(std::path::Path::new(path))
                .unwrap_or_else(|error| panic!("artifact path refusal: {error}"))
        );
    }
}
