//! Tests for package-contract publication transparency.

use super::{
    PACKAGE_CONTRACT_TRANSPARENCY_LOG, append_package_contract_transparency_log,
    package_contract_transparency_sequence,
};
use crate::registry_ops::git::git;
use crate::registry_ops::test_support::init_test_transparency_repo;
use std::fs;

const PACKAGE: &str = "postgresql";
const VERSION: &str = "17.6";
const PLATFORM: &str = "x86_64-linux";
const PACKAGE_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const RETENTION_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const PROVENANCE: &str = "provenance/p/postgresql/contract.intoto.jsonl";
const STATEMENT: &[u8] = b"{\"payload\":\"signed package contract\"}\n";

#[test]
fn append_is_idempotent_and_lookup_binds_exact_publication() {
    let registry = tempfile::tempdir().unwrap();
    init_test_transparency_repo(registry.path());
    let first = append_package_contract_transparency_log(
        registry.path(),
        PACKAGE,
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        PROVENANCE,
        STATEMENT,
    )
    .unwrap();
    let initial = fs::read(&first).unwrap();

    let second = append_package_contract_transparency_log(
        registry.path(),
        PACKAGE,
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        PROVENANCE,
        STATEMENT,
    )
    .unwrap();
    assert_eq!(fs::read(&second).unwrap(), initial);
    assert_eq!(
        package_contract_transparency_sequence(
            &initial,
            PACKAGE_CONTRACT_TRANSPARENCY_LOG,
            PACKAGE,
            VERSION,
            PLATFORM,
            PACKAGE_DIGEST,
            RETENTION_DIGEST,
            PROVENANCE,
            STATEMENT,
        )
        .unwrap(),
        0
    );
}

#[test]
fn lookup_rejects_statement_and_contract_substitution() {
    let registry = tempfile::tempdir().unwrap();
    init_test_transparency_repo(registry.path());
    let path = append_package_contract_transparency_log(
        registry.path(),
        PACKAGE,
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        PROVENANCE,
        STATEMENT,
    )
    .unwrap();
    let log = fs::read(path).unwrap();

    let statement_error = package_contract_transparency_sequence(
        &log,
        PACKAGE_CONTRACT_TRANSPARENCY_LOG,
        PACKAGE,
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        PROVENANCE,
        b"different statement",
    )
    .unwrap_err();
    assert!(format!("{statement_error:#}").contains("does not match"));

    let contract_error = package_contract_transparency_sequence(
        &log,
        PACKAGE_CONTRACT_TRANSPARENCY_LOG,
        PACKAGE,
        VERSION,
        PLATFORM,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        RETENTION_DIGEST,
        PROVENANCE,
        STATEMENT,
    )
    .unwrap_err();
    assert!(format!("{contract_error:#}").contains("does not match"));
}

#[test]
fn append_rejects_corrupt_history() {
    let registry = tempfile::tempdir().unwrap();
    init_test_transparency_repo(registry.path());
    let path = append_package_contract_transparency_log(
        registry.path(),
        PACKAGE,
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        PROVENANCE,
        STATEMENT,
    )
    .unwrap();
    let mut corrupt = fs::read_to_string(&path).unwrap();
    corrupt = corrupt.replace(PACKAGE_DIGEST, RETENTION_DIGEST);
    fs::write(&path, corrupt).unwrap();

    let error = append_package_contract_transparency_log(
        registry.path(),
        "redis",
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        "provenance/r/redis/contract.intoto.jsonl",
        STATEMENT,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("hash mismatch"));
}

#[test]
fn append_rejects_rewriting_committed_history() {
    let registry = tempfile::tempdir().unwrap();
    init_test_transparency_repo(registry.path());
    let path = append_package_contract_transparency_log(
        registry.path(),
        PACKAGE,
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        PROVENANCE,
        STATEMENT,
    )
    .unwrap();
    git(
        registry.path(),
        &["add", "registry.toml", "keys.toml", "transparency"],
    )
    .unwrap();
    git(
        registry.path(),
        &["commit", "-m", "initial contract publication"],
    )
    .unwrap();
    fs::write(&path, b"").unwrap();

    let error = append_package_contract_transparency_log(
        registry.path(),
        "redis",
        VERSION,
        PLATFORM,
        PACKAGE_DIGEST,
        RETENTION_DIGEST,
        "provenance/r/redis/contract.intoto.jsonl",
        STATEMENT,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("does not extend committed HEAD"));
}
