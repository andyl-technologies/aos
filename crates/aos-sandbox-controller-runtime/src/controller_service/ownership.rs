//! Protected controller inputs for explicit ownership-gate resumption.
//!
//! The controller receives the same authority policy and public key as the
//! Host broker, plus a distinct local record MAC key shared only with the
//! ownership daemon. A missing complete set disables this optional path;
//! partial or inconsistent credentials fail startup. No public request can
//! supply a socket path, authority generation, trust policy, or secret.

use std::path::Path;
use std::time::Duration;

use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;
use aos_sandbox_core::DecodeLimits;
use aos_sandbox_ownership_protocol::trusted_policy::{
    OwnershipTrustConfigurationErrorV1, verifier_from_protected_policy_v1,
};
use aos_sandbox_ownership_protocol::protocol::session_client::OwnershipSessionTransportError;
use zeroize::Zeroizing;

use aos_sandbox_linux::credential::CredentialOwnerPolicyV1;
use super::credential_receiving::{
    CredentialMetadataV1, CredentialSourceV1, OrdinaryCredentialSourceV1,
};
use aos_sandbox_broker_session_security::ownership_authority_client::LocalOwnershipAuthorityClientV1;

const SOCKET_PATH: &str = "/run/aos/sandbox-ownership/control.sock";
const SESSION_KEY_CREDENTIAL: &str = "ownership-session-key";
const POLICY_CREDENTIAL: &str = "ownership-lease-policy.cbor";
const PUBLIC_KEY_CREDENTIAL: &str = "ownership-lease-public-key";
const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Reports an absent, unsafe, or inconsistent protected ownership configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("controller ownership credentials are incomplete or invalid")]
pub(crate) struct ControllerOwnershipCredentialErrorV1;

/// Pins one authority generation and the independent local session secret.
pub(crate) struct ControllerOwnershipConfigurationV1 {
    verifier: OwnershipAuthorityVerifier,
    secret: Zeroizing<[u8; 32]>,
}

impl ControllerOwnershipConfigurationV1 {
    /// Loads the complete optional credential set from systemd's fixed names.
    pub(crate) fn from_process_credentials_optional()
    -> Result<Option<Self>, ControllerOwnershipCredentialErrorV1> {
        Self::from_process_credentials_with_source(&mut OrdinaryCredentialSourceV1)
    }

    pub(super) fn from_process_credentials_with_source(
        source: &mut impl CredentialSourceV1,
    ) -> Result<Option<Self>, ControllerOwnershipCredentialErrorV1> {
        let Some(directory) = source.process_directory() else {
            return Ok(None);
        };
        source.directory(&directory);
        let directory = Path::new(&directory);
        if !directory.is_absolute() {
            return Err(ControllerOwnershipCredentialErrorV1);
        }
        Self::from_directory_with_source(directory, source)
    }

    #[cfg(test)]
    fn from_directory(
        directory: &Path,
    ) -> Result<Option<Self>, ControllerOwnershipCredentialErrorV1> {
        Self::from_directory_with_source(directory, &mut OrdinaryCredentialSourceV1)
    }

    fn from_directory_with_source(
        directory: &Path,
        source: &mut impl CredentialSourceV1,
    ) -> Result<Option<Self>, ControllerOwnershipCredentialErrorV1> {
        let secret = read_credential_with_source(source, directory, SESSION_KEY_CREDENTIAL, 32)?;
        let policy_bytes = read_credential_with_source(source, directory, POLICY_CREDENTIAL, MAXIMUM_POLICY_BYTES)?;
        let public_key = read_credential_with_source(source, directory, PUBLIC_KEY_CREDENTIAL, 32)?;
        if secret.is_none() && policy_bytes.is_none() && public_key.is_none() {
            return Ok(None);
        }
        let (Some(secret), Some(policy_bytes), Some(public_key)) =
            (secret, policy_bytes, public_key)
        else {
            return Err(ControllerOwnershipCredentialErrorV1);
        };
        let secret = Zeroizing::new(secret);
        let secret: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|cause| {
                source.retain(cause);
                ControllerOwnershipCredentialErrorV1
            })?;
        if secret == [0; 32] {
            return Err(ControllerOwnershipCredentialErrorV1);
        }
        let public_key: [u8; 32] = public_key
            .as_slice()
            .try_into()
            .map_err(|cause| {
                source.retain(cause);
                ControllerOwnershipCredentialErrorV1
            })?;
        let verifier = verifier_from_protected_policy_v1(policy_bytes, public_key, DecodeLimits::default())
            .map_err(|cause| {
                // Preserve each existing retained source's concrete decoder
                // cause; ordinary readers keep their original drop behavior.
                match cause {
                    OwnershipTrustConfigurationErrorV1::Canonical(cause) => source.retain(cause),
                    OwnershipTrustConfigurationErrorV1::Features(cause) => source.retain(cause),
                    OwnershipTrustConfigurationErrorV1::MediaType(cause) => source.retain(cause),
                    OwnershipTrustConfigurationErrorV1::Trust(cause) => source.retain(cause),
                    OwnershipTrustConfigurationErrorV1::Binding => {},
                }
                ControllerOwnershipCredentialErrorV1
            })?;

        Ok(Some(Self {
            verifier,
            secret: Zeroizing::new(secret),
        }))
    }

    pub(crate) const fn verifier(&self) -> &OwnershipAuthorityVerifier {
        &self.verifier
    }

    pub(crate) fn into_verifier(self) -> OwnershipAuthorityVerifier {
        self.verifier
    }

    pub(crate) fn connect(
        &self,
    ) -> Result<LocalOwnershipAuthorityClientV1, OwnershipSessionTransportError> {
        LocalOwnershipAuthorityClientV1::connect(
            Path::new(SOCKET_PATH),
            self.verifier.authority().clone(),
            0,
            0,
            self.secret.clone(),
            SESSION_TIMEOUT,
        )
    }
}

#[cfg(test)]
fn read_credential(
    directory: &Path,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Option<Vec<u8>>, ControllerOwnershipCredentialErrorV1> {
    read_credential_with_source(&mut OrdinaryCredentialSourceV1, directory, name, maximum_bytes)
}

fn read_credential_with_source(
    source: &mut impl CredentialSourceV1,
    directory: &Path,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Option<Vec<u8>>, ControllerOwnershipCredentialErrorV1> {
    source.read(
        directory, name, 1, maximum_bytes,
        CredentialMetadataV1::Protected {
            private: true,
            owner: CredentialOwnerPolicyV1::RootOrCurrent,
        },
    ).map_err(|_| ControllerOwnershipCredentialErrorV1)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn missing_credentials_are_optional_but_partial_credentials_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            ControllerOwnershipConfigurationV1::from_directory(directory.path())
                .unwrap()
                .is_none()
        );

        let secret = directory.path().join(SESSION_KEY_CREDENTIAL);
        fs::write(&secret, [9; 32]).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            ControllerOwnershipConfigurationV1::from_directory(directory.path()),
            Err(ControllerOwnershipCredentialErrorV1),
        ));
    }

    #[test]
    fn retained_malformed_policy_keeps_original_decoder_after_closed_reentry() {
        use super::super::credential_receiving::CredentialAttemptV1;
        use aos_sandbox_core::format::CanonicalCborError;

        let directory = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            (SESSION_KEY_CREDENTIAL, vec![9; 32]),
            (POLICY_CREDENTIAL, vec![0]),
            (PUBLIC_KEY_CREDENTIAL, vec![7; 32]),
        ] {
            let path = directory.path().join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(ControllerOwnershipConfigurationV1::from_directory(directory.path()).is_err());

        let mut attempt = CredentialAttemptV1::new();
        assert!(!attempt.capture_once(|source| {
            ControllerOwnershipConfigurationV1::from_directory_with_source(directory.path(), source)
        }));
        let original = attempt.failure().unwrap();
        assert!(original.downcast_ref::<CanonicalCborError>().is_some());
        let original_address = std::ptr::from_ref(original).cast::<()>();

        assert!(!attempt.capture_once(|_| {
            panic!("closed retained construction must not reread or replace its first cause")
        }));
        assert!(attempt.take_completed().is_none());
        assert_eq!(std::ptr::from_ref(attempt.failure().unwrap()).cast::<()>(), original_address);
    }

    #[test]
    fn credential_reader_rejects_symlink_leaves() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, [9; 32]).unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join(SESSION_KEY_CREDENTIAL)).unwrap();

        assert!(matches!(
            read_credential(directory.path(), SESSION_KEY_CREDENTIAL, 32),
            Err(ControllerOwnershipCredentialErrorV1),
        ));
    }
}
