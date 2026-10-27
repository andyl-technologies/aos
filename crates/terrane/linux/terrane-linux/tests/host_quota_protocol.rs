//! Exercises the closed quota schema without granting kernel privilege.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use prost::Message;
use terrane_linux::host_quota::{HostQuotaClient, QuotaObservation, QuotaQuery};

#[test]
fn query_rejects_ambiguous_extended_or_truncated_packets() {
    let valid = QuotaQuery {
        version: 1,
        request_id: 7,
        configuration_epoch: vec![1; 16],
        owner_id: "public-owner".into(),
        domain: "public".into(),
    }
    .encode_to_vec();
    assert!(QuotaQuery::decode_strict(&valid).is_ok());

    for suffix in [&[8, 1][..], &[48, 1], &[10, 1, 1], &[0], &[255]] {
        let mut bytes = valid.clone();
        bytes.extend_from_slice(suffix);
        assert!(
            QuotaQuery::decode_strict(&bytes).is_err(),
            "suffix {suffix:?}"
        );
    }
    for length in 0..valid.len() {
        assert!(QuotaQuery::decode_strict(&valid[..length]).is_err());
    }
}

#[test]
fn error_response_cannot_smuggle_quota_evidence() {
    let response = QuotaObservation {
        version: 1,
        request_id: 7,
        configuration_epoch: vec![1; 16],
        owner_id: "public-owner".into(),
        domain: "public".into(),
        query_sequence: 1,
        result: 4,
        ..QuotaObservation::default()
    };
    assert!(QuotaObservation::decode_strict(&response.encode_to_vec()).is_ok());

    let mut explicit_default = response.encode_to_vec();
    explicit_default.extend_from_slice(&[72, 0]);
    assert!(QuotaObservation::decode_strict(&explicit_default).is_err());

    let mut invalid = response;
    invalid.hard_limit_bytes = 4096;
    assert!(QuotaObservation::decode_strict(&invalid.encode_to_vec()).is_err());
}

#[test]
fn nonroot_helper_identity_cannot_mint_native_evidence() {
    assert!(HostQuotaClient::connect(std::path::Path::new("/unused"), 65534, [1; 16]).is_err());
}

#[test]
fn provisioning_guard_excludes_factories_until_exclusive_custody_ends() {
    use std::fs::{self, File};
    use terrane_linux::host_quota::DomainProvisioningGuard;

    let directory =
        std::env::temp_dir().join(format!("terrane-quota-guard-{}", std::process::id()));
    fs::create_dir(&directory).expect("isolated guard fixture");
    let root = File::open(&directory).expect("retained root");
    let exclusive = DomainProvisioningGuard::exclusive(&root).expect("exclusive provisioning");
    assert!(DomainProvisioningGuard::shared(&root).is_err());
    assert!(DomainProvisioningGuard::exclusive(&root).is_err());
    drop(exclusive);

    let first = DomainProvisioningGuard::shared(&root).expect("first factory");
    let second = DomainProvisioningGuard::shared(&root).expect("second factory");
    assert_eq!(
        first.identity().expect("first identity"),
        second.identity().expect("second identity")
    );
    assert!(DomainProvisioningGuard::exclusive(&root).is_err());
    drop(first);
    assert!(DomainProvisioningGuard::exclusive(&root).is_err());
    drop(second);
    drop(DomainProvisioningGuard::exclusive(&root).expect("quiescent provisioning"));
    drop(root);
    fs::remove_dir(directory).expect("guard fixture cleanup");
}
