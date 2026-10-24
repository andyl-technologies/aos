//! Checks original cleanup-key custody and exact signed bytes without native authority.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Operational key and signature refusal assertions deliberately panic on a failed invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

const KEY_NAME: &str = "capability-native-retirement-key-v1";

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn reopened_original_key_authenticates_exact_same_body() {
    let directory = private_directory();
    let original = Authenticator::open(directory.path()).unwrap();
    let body = b"data-only original cleanup relation, no native permit";
    let authentication = original.sign(body).unwrap();
    let reopened = Authenticator::open(directory.path()).unwrap();

    reopened.verify(body, &authentication).unwrap();
    assert_eq!(reopened.sign(body).unwrap(), authentication);
    assert_eq!(
        fs::metadata(directory.path().join(KEY_NAME)).unwrap().len(),
        32
    );
}

#[test]
fn changed_body_foreign_archive_and_malformed_signature_refuse() {
    let directory = private_directory();
    let foreign_directory = private_directory();
    let original = Authenticator::open(directory.path()).unwrap();
    let foreign = Authenticator::open(foreign_directory.path()).unwrap();
    let body = b"original request/artifact/activation/proof bytes";
    let authentication = original.sign(body).unwrap();

    assert!(
        original
            .verify(
                b"another request/artifact/activation/proof",
                &authentication
            )
            .is_err()
    );
    assert!(foreign.verify(body, &authentication).is_err());
    assert!(original.verify(body, &authentication[..63]).is_err());
}

#[test]
fn exact_signing_credit_succeeds_and_one_extra_byte_refuses() {
    let directory = private_directory();
    let original = Authenticator::open(directory.path()).unwrap();
    let mut body = vec![0x35; 128 * 1024];
    let authentication = original.sign(&body).unwrap();

    original.verify(&body, &authentication).unwrap();
    body.push(0x35);
    assert!(original.sign(&body).is_err());
    assert!(original.verify(&body, &authentication).is_err());
}

#[test]
fn public_archive_or_key_permissions_refuse() {
    let directory = private_directory();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Authenticator::open(directory.path()).is_err());
    assert!(!directory.path().join(KEY_NAME).exists());

    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let _original = Authenticator::open(directory.path()).unwrap();
    fs::set_permissions(
        directory.path().join(KEY_NAME),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(Authenticator::open(directory.path()).is_err());
}

#[test]
fn symlink_hardlink_or_partial_key_refuse_without_replacement() {
    let directory = private_directory();
    let foreign_directory = private_directory();
    let _foreign = Authenticator::open(foreign_directory.path()).unwrap();
    let key = directory.path().join(KEY_NAME);
    let foreign_key = foreign_directory.path().join(KEY_NAME);
    let retained = fs::read(&foreign_key).unwrap();
    symlink(&foreign_key, &key).unwrap();
    assert!(Authenticator::open(directory.path()).is_err());
    assert_eq!(fs::read(&foreign_key).unwrap(), retained);

    fs::remove_file(&key).unwrap();
    fs::hard_link(&foreign_key, &key).unwrap();
    assert!(Authenticator::open(directory.path()).is_err());
    assert_eq!(fs::read(&foreign_key).unwrap(), retained);

    fs::remove_file(&key).unwrap();
    fs::write(&key, [0_u8; 31]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Authenticator::open(directory.path()).is_err());
    assert_eq!(fs::read(&key).unwrap(), vec![0; 31]);
}
