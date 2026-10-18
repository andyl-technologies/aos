//! Supervises and inventories real fresh-process native transport fixtures.
//!
//! Actual confinement is installed by the publication example before role
//! dispatch. These ignored libtest cases never install it inside a test thread.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "tokio")]

#[test]
#[ignore = "requires dedicated verity-enabled ext4 and distinct VM role identities"]
fn publisher_local_native_lifecycle_vm() {
    #[cfg(feature = "native-test-fixtures")]
    terrane_fs::publisher_local::supervise_native_fixture();

    #[cfg(not(feature = "native-test-fixtures"))]
    panic!("native lifecycle proof requires native-test-fixtures and the fresh-process example");
}

#[test]
#[ignore = "requires actual fresh-process publication fixture executable"]
fn publisher_local_native_role() {
    let executable = std::env::var_os("TERRANE_PUBLICATION_FIXTURE").unwrap();
    let output = std::process::Command::new(executable)
        .arg("--list")
        .output()
        .unwrap();
    assert!(output.status.success());
    let listed = String::from_utf8(output.stdout).unwrap();
    let mut selectors = listed
        .lines()
        .filter(|line| line.starts_with("transport:"))
        .collect::<Vec<_>>();
    selectors.sort_unstable();
    assert_eq!(
        selectors,
        ["transport:native-client", "transport:native-publisher"]
    );
}
