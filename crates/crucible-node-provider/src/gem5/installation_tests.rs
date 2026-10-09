//! Checks atomic private native installation under a permissive process umask.

// Test failures intentionally panic; the subprocess isolates the global umask.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    process::Command,
};

use crucible_node_contract::canonical;

use super::{Gem5LaunchArtifact, install};

const CHILD_MARKER: &str = "CRUCIBLE_PRIVATE_INSTALLATION_TEST_CHILD";
const TEST_NAME: &str = "gem5::process::installation_tests::native_artifacts_are_created_private_under_permissive_umask";

#[test]
fn native_artifacts_are_created_private_under_permissive_umask() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--test-threads=1"])
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    // This process runs only this case, so the ambient mask cannot affect
    // concurrent tests. The old installer would create world-readable 0666.
    rustix::process::umask(rustix::fs::Mode::empty());
    let root = std::env::temp_dir().join(format!(
        "crucible-private-native-installation-{}",
        std::process::id()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let bytes = b"installed original native artifact";
    let source = root.join("source");
    fs::write(&source, bytes).unwrap();
    let artifact = Gem5LaunchArtifact {
        path: source,
        content: canonical::content_ref(bytes, "application/octet-stream").unwrap(),
    };

    for name in ["native-owner.py", "native-owner-model.py", "guest.elf"] {
        let target = root.join(name);
        install(&artifact, &target).unwrap();

        let metadata = fs::symlink_metadata(&target).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert!(install(&artifact, &target).is_err());
    }

    fs::remove_dir_all(root).unwrap();
}
