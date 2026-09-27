//! Bounded systemd credential reads for the publisher service and policy source.

use std::path::Path;

use crate::fixed_role_credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};

/// Reports an absent or unsafe required publisher credential.
pub(super) struct PublisherCredentialErrorV1;

/// Reads one private regular credential by its fixed deployment name.
pub(super) fn read_required_credential(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, PublisherCredentialErrorV1> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(PublisherCredentialErrorV1)?;
    let directory = Path::new(&directory);
    if !directory.is_absolute() {
        return Err(PublisherCredentialErrorV1);
    }
    read_optional_bounded_role_credential_v1(
        directory,
        name,
        minimum,
        maximum,
        true,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| PublisherCredentialErrorV1)?
    .ok_or(PublisherCredentialErrorV1)
}
