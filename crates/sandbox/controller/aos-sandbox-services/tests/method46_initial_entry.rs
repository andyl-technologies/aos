//! Checks that fixed initializers reject standalone execution before authority IO.
//!
//! These subprocesses have no genuine Parent06/Source original. Their negative
//! exit is not installed positive provisioning or enforcing-MAC qualification.

#![cfg(all(target_os = "linux", feature = "method46-initial"))]

use std::process::Command;

#[test]
fn fixed_initializers_require_genuine_source_even_with_mode_or_path_arguments() {
    let executables = [
        env!("CARGO_BIN_EXE_aos-sandbox-controller-floor-initialize"),
        env!("CARGO_BIN_EXE_aos-sandbox-storage-floor-initialize"),
    ];
    let arguments: &[&[&str]] = &[
        &[],
        &["initialize"],
        &["recover"],
        &["--help"],
        &["--profile", "/untrusted/profile"],
    ];
    for executable in executables {
        for arguments in arguments {
            let result = Command::new(executable)
                .env_clear()
                .args(*arguments)
                .output()
                .unwrap();

            assert_eq!(result.status.code(), Some(1), "{executable} {arguments:?}");
            assert!(result.stdout.is_empty());
            assert!(result.stderr.is_empty());
        }
    }
}
