//! Real selected-store regressions for physical artifact verification.

use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const CHILD_MARKER: &str = "AOS_VERIFICATION_TEST_CHILD";

#[test]
fn real_selected_store_checks_registration_references_and_physical_bytes() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        // The child gives the production verifier its ordinary store-selection
        // environment without mutating the parallel test runner's environment.
        let store = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::verification::tests::real_selected_store_checks_registration_references_and_physical_bytes",
                "--nocapture",
            ])
            .env(CHILD_MARKER, store.path())
            .env("AOS_NIX_EVAL_STORE", format!("local?root={}", store.path().display()))
            .env_remove("AOS_TEST_ABILITY_NIX_STORE_DIR")
            .env_remove("AOS_TEST_ABILITY_NIX_STATE_DIR")
            .env_remove("AOS_TEST_ABILITY_NIX_LOG_DIR")
            .env_remove("AOS_TEST_ABILITY_NIX_REMOTE")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "selected-store test child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }

    let executable = std::env::var_os("AOS_NIX_STORE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::split_paths(&std::env::var_os("PATH")?)
                .filter(|directory| directory.starts_with("/nix/store"))
                .map(|directory| directory.join("nix-store"))
                .find(|candidate| candidate.is_file())
        })
        .expect("source-built AOS Nix must be available");
    assert!(executable.is_absolute());
    assert!(
        std::fs::canonicalize(&executable)
            .unwrap()
            .starts_with("/nix/store")
    );
    let source = tempfile::tempdir().unwrap();
    let input = source.path().join("physical-input");
    std::fs::write(&input, b"original authenticated fixture bytes\n").unwrap();
    let output = live_store_command(Some(&executable))
        .unwrap()
        .args(["--add-fixed", "sha256"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = String::from_utf8(output.stdout).unwrap().trim().to_string();
    let (hash, size) = dump_store_path_identity_in(&root, Some(&executable)).unwrap();

    verify_store_object_in(&root, hash, size, &[], Some(&executable))
        .expect("registered original object verifies through the selected store");

    let error = verify_store_object_in(&root, hash, size + 1, &[], Some(&executable))
        .expect_err("correct physical digest does not excuse an incorrect NAR size");
    assert!(error.to_string().contains("NAR size mismatch"));

    let error = verify_store_object_in(&root, hash, size, &["a".repeat(32)], Some(&executable))
        .expect_err("wrong authenticated references");
    assert!(error.to_string().contains("direct references differ"));

    let private_root = PathBuf::from(std::env::var_os(CHILD_MARKER).unwrap());
    let unregistered = format!("/nix/store/{}-unregistered", "0".repeat(32));
    let unregistered_file = private_root.join(unregistered.trim_start_matches('/'));
    std::fs::write(&unregistered_file, std::fs::read(&input).unwrap()).unwrap();
    let error = verify_store_object_in(&unregistered, hash, size, &[], Some(&executable))
        .expect_err("physical presence does not establish registration");
    assert!(error.to_string().contains("--query --references"));
    assert!(unregistered_file.is_file());

    let physical_root = private_root.join(root.trim_start_matches('/'));
    std::fs::set_permissions(&physical_root, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
        &physical_root,
        b"changed bytes under the original registered identity\n",
    )
    .unwrap();
    let error = verify_store_object_in(&root, hash, size, &[], Some(&executable))
        .expect_err("database validity cannot replace physical NAR verification");
    assert!(error.to_string().contains("NAR mismatch"));
}
