//! Protected controller inputs for explicit ownership-gate resumption.
//!
//! The controller receives the same authority policy and public key as the
//! Host broker, plus a distinct local record MAC key shared only with the
//! ownership daemon. A missing complete set disables this optional path;
//! partial or inconsistent credentials fail startup. No public request can
//! supply a socket path, authority generation, trust policy, or secret.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::Duration;

use aos_sandbox::ownership_authority::OwnershipAuthorityVerifier;
use aos_sandbox::ownership_resume::OwnershipClockObservationError;
use aos_sandbox_core::format::decode_trust_policy;
use aos_sandbox_core::{
    DecodeLimits, KeyUsage, MediaType, OwnershipLeaseTrustAnchor, PortableMediaType,
    RawClockProvenance, RawPairedClockSample, SignaturePurpose, descriptor_for_bytes,
};
use aos_sandbox_linux::boot::KernelBootId;
use rustix::fs::{Mode, OFlags, open};
use zeroize::Zeroizing;

use crate::ownership_authority_client::LocalOwnershipAuthorityClientV1;

const SOCKET_PATH: &str = "/run/aos/sandbox-ownership/control.sock";
const SESSION_KEY_CREDENTIAL: &str = "ownership-session-key";
const POLICY_CREDENTIAL: &str = "ownership-lease-policy.cbor";
const PUBLIC_KEY_CREDENTIAL: &str = "ownership-lease-public-key";
const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const CLOCK_PROVENANCE: [u8; 16] = *b"AOSOWNCTRLCLKV1!";

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
        let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Ok(None);
        };
        let directory = Path::new(&directory);
        if !directory.is_absolute() {
            return Err(ControllerOwnershipCredentialErrorV1);
        }
        Self::from_directory(directory)
    }

    fn from_directory(
        directory: &Path,
    ) -> Result<Option<Self>, ControllerOwnershipCredentialErrorV1> {
        let secret = read_credential(directory, SESSION_KEY_CREDENTIAL, 32)?;
        let policy_bytes = read_credential(directory, POLICY_CREDENTIAL, MAXIMUM_POLICY_BYTES)?;
        let public_key = read_credential(directory, PUBLIC_KEY_CREDENTIAL, 32)?;
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
            .map_err(|_| ControllerOwnershipCredentialErrorV1)?;
        if secret == [0; 32] {
            return Err(ControllerOwnershipCredentialErrorV1);
        }
        let public_key: [u8; 32] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| ControllerOwnershipCredentialErrorV1)?;
        let policy = decode_trust_policy(&policy_bytes, DecodeLimits::default())
            .map_err(|_| ControllerOwnershipCredentialErrorV1)?;
        aos_sandbox_core::validate_required_features(policy.required_features())
            .map_err(|_| ControllerOwnershipCredentialErrorV1)?;
        let [authority] = policy.allowed_keys() else {
            return Err(ControllerOwnershipCredentialErrorV1);
        };
        if policy.purpose() != SignaturePurpose::OwnershipLease
            || authority.usage() != KeyUsage::OwnershipLease
        {
            return Err(ControllerOwnershipCredentialErrorV1);
        }
        let authority = authority.clone();
        let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .map_err(|_| ControllerOwnershipCredentialErrorV1)?;
        let descriptor = descriptor_for_bytes(media_type, &policy_bytes);
        let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            policy_bytes,
            descriptor,
            policy.trust_scope(),
            authority.clone(),
            public_key,
            DecodeLimits::default(),
        )
        .map_err(|_| ControllerOwnershipCredentialErrorV1)?;

        Ok(Some(Self {
            verifier: OwnershipAuthorityVerifier::new(anchor, authority),
            secret: Zeroizing::new(secret),
        }))
    }

    pub(crate) const fn verifier(&self) -> &OwnershipAuthorityVerifier {
        &self.verifier
    }

    pub(crate) fn connect(
        &self,
    ) -> Result<LocalOwnershipAuthorityClientV1, aos_sandbox::OwnershipSessionTransportError> {
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

fn read_credential(
    directory: &Path,
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<Vec<u8>>, ControllerOwnershipCredentialErrorV1> {
    let descriptor = match open(
        &directory.join(name),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ControllerOwnershipCredentialErrorV1),
    };
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| ControllerOwnershipCredentialErrorV1)?;
    let size = usize::try_from(metadata.len()).map_err(|_| ControllerOwnershipCredentialErrorV1)?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || size == 0
        || size > maximum_bytes
    {
        return Err(ControllerOwnershipCredentialErrorV1);
    }
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes)
        .map_err(|_| ControllerOwnershipCredentialErrorV1)?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|_| ControllerOwnershipCredentialErrorV1)?
        != 0
    {
        return Err(ControllerOwnershipCredentialErrorV1);
    }
    Ok(Some(bytes))
}

/// Samples paired host clocks without accepting clock facts from a caller.
pub(crate) fn sample_ownership_clock()
-> Result<RawPairedClockSample, OwnershipClockObservationError> {
    let boot_before = KernelBootId::current()
        .map_err(|_| OwnershipClockObservationError)?
        .into_bytes();
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let boot_after = KernelBootId::current()
        .map_err(|_| OwnershipClockObservationError)?
        .into_bytes();
    if boot_before != boot_after {
        return Err(OwnershipClockObservationError);
    }
    let seconds = u64::try_from(boottime.tv_sec).map_err(|_| OwnershipClockObservationError)?;
    let nanoseconds =
        u64::try_from(boottime.tv_nsec).map_err(|_| OwnershipClockObservationError)?;
    let boottime_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(OwnershipClockObservationError)?;
    let provenance = RawClockProvenance::new_untrusted(CLOCK_PROVENANCE)
        .map_err(|_| OwnershipClockObservationError)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        boot_before,
        realtime.tv_sec,
        boottime_nanoseconds,
    )
    .map_err(|_| OwnershipClockObservationError)
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
