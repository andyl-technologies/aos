//! Image-pinned mode and separately loaded, noncreating TPM provisioning.
//!
//! The immutable image always installs an explicit legacy-closed or required
//! mode. Required mode never discovers or adopts an index, epoch, journal, or
//! salt key. Its public systemd credential has this fixed shape:
//!
//! ```text
//! AOSBTD01 | version:1u16be | reserved:0u16be | AOSBTP01:112 |
//! salt-key-Name:34 | reserved:0u16be                  (160 bytes)
//! broker-method46-tpm-index-auth-v1 = exact 32 secret bytes (no header)
//! ```

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{StatVfsMountFlags, fstatvfs};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::format::{FloorEndpointV1, PROFILE_BYTES};
use super::{FloorErrorV1, FloorProfileV1};
use crate::fixed_role_credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};

const PROVISION_BYTES: usize = 160;
const PUBLIC_CREDENTIAL: &str = "broker-method46-tpm-provision-v1";
const AUTH_CREDENTIAL: &str = "broker-method46-tpm-index-auth-v1";
const LEGACY_MODE: &[u8] = b"legacy-closed-v1\n";
const REQUIRED_MODE: &[u8] = b"required-v1\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImageFloorModeV1 {
    LegacyClosed,
    Required,
}

/// Retains one fixed immutable mode through the shared file-admission engine.
pub(crate) struct ModePinV1 {
    path: PathBuf,
    target: PathBuf,
    file: File,
    identity: (u64, u64),
    mode: ImageFloorModeV1,
}

impl ModePinV1 {
    pub(super) fn open(endpoint: FloorEndpointV1) -> Result<Self, FloorErrorV1> {
        let basename = match endpoint {
            FloorEndpointV1::ControllerStorageClient => "controller-mode",
            FloorEndpointV1::StorageBroker => "storage-mode",
        };
        let path = Path::new("/etc/aos/method46-tpm-floor").join(basename);
        Self::open_fixed(path)
    }

    /// Retains the fixed Storage mode for worker-only startup image routing.
    ///
    /// This is immutable comparison DATA, not a floor owner or permission to
    /// adopt an extra image through the ordinary method-46 capture path.
    ///
    /// # Errors
    /// Rejects absent, unsafe, noncanonical or changed fixed Storage mode data.
    pub(crate) fn open_storage_worker_image_mode() -> Result<Self, FloorErrorV1> {
        Self::open(FloorEndpointV1::StorageBroker)
    }

    /// Retains only the immutable mode named by the signed Host contract.
    ///
    /// # Errors
    /// Rejects absent, unsafe, noncanonical or changed fixed mode files.
    pub(crate) fn open_runtime_deployment() -> Result<Self, FloorErrorV1> {
        Self::open_fixed(PathBuf::from("/etc/aos/runtime-deployment-tpm-floor/mode"))
    }

    // Both fixed entries use this same retained-file engine. No caller path
    // crosses the module boundary or selects a provisioning purpose.
    fn open_fixed(path: PathBuf) -> Result<Self, FloorErrorV1> {
        let target = std::fs::canonicalize(&path).map_err(|_| FloorErrorV1::Provisioning)?;
        if !target.starts_with("/nix/store") {
            return Err(FloorErrorV1::Provisioning);
        }
        let file = File::from(
            rustix::fs::openat(
                rustix::fs::CWD,
                &target,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| FloorErrorV1::Provisioning)?,
        );
        let metadata = file.metadata().map_err(|_| FloorErrorV1::Provisioning)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7222 != 0
            || !fstatvfs(&file)
                .map_err(|_| FloorErrorV1::Provisioning)?
                .f_flag
                .contains(StatVfsMountFlags::RDONLY)
        {
            return Err(FloorErrorV1::Provisioning);
        }
        let bytes = read_mode(&target)?;
        let mode = decode_mode(&bytes)?;
        let pin = Self {
            path,
            target,
            file,
            identity: (metadata.dev(), metadata.ino()),
            mode,
        };
        pin.revalidate()?;
        Ok(pin)
    }

    pub(super) const fn mode(&self) -> ImageFloorModeV1 {
        self.mode
    }

    /// Reports the exact decoded required spelling, not deployment readiness.
    pub(crate) const fn is_required(&self) -> bool {
        matches!(self.mode, ImageFloorModeV1::Required)
    }

    /// Rechecks the original immutable mode name, inode and decoded bytes.
    ///
    /// # Errors
    /// Rejects any path, metadata, mount or content drift.
    pub(crate) fn revalidate(&self) -> Result<(), FloorErrorV1> {
        if std::fs::canonicalize(&self.path).map_err(|_| FloorErrorV1::Provisioning)? != self.target
        {
            return Err(FloorErrorV1::Provisioning);
        }
        let retained = self
            .file
            .metadata()
            .map_err(|_| FloorErrorV1::Provisioning)?;
        let named =
            std::fs::symlink_metadata(&self.target).map_err(|_| FloorErrorV1::Provisioning)?;
        if !named.is_file()
            || named.uid() != 0
            || named.gid() != 0
            || named.nlink() != 1
            || named.mode() & 0o7222 != 0
            || (named.dev(), named.ino()) != self.identity
            || (retained.dev(), retained.ino()) != self.identity
            || !fstatvfs(&self.file)
                .map_err(|_| FloorErrorV1::Provisioning)?
                .f_flag
                .contains(StatVfsMountFlags::RDONLY)
            || decode_mode(&read_mode(&self.target)?)? != self.mode
        {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
    }
}

pub(super) struct ProvisionPinV1 {
    endpoint: FloorEndpointV1,
    bytes: [u8; PROVISION_BYTES],
    auth_digest: [u8; 32],
    profile: FloorProfileV1,
    salt_name: [u8; 34],
}

impl ProvisionPinV1 {
    pub(super) fn open(endpoint: FloorEndpointV1) -> Result<Self, FloorErrorV1> {
        let bytes = read_public(endpoint)?;
        let (profile, salt_name) = decode_provision(&bytes, endpoint)?;
        let auth = read_auth(endpoint)?;
        Ok(Self {
            endpoint,
            bytes,
            auth_digest: Sha256::digest(&auth[..]).into(),
            profile,
            salt_name,
        })
    }

    pub(super) const fn profile(&self) -> FloorProfileV1 {
        self.profile
    }

    pub(super) const fn salt_name(&self) -> [u8; 34] {
        self.salt_name
    }

    pub(super) fn current_auth(&self) -> Result<Zeroizing<[u8; 32]>, FloorErrorV1> {
        if read_public(self.endpoint)? != self.bytes {
            return Err(FloorErrorV1::Provisioning);
        }
        let auth = read_auth(self.endpoint)?;
        if Sha256::digest(&auth[..]).as_slice() != self.auth_digest {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(auth)
    }

    pub(super) fn revalidate(&self) -> Result<(), FloorErrorV1> {
        drop(self.current_auth()?);
        Ok(())
    }
}

fn decode_mode(bytes: &[u8]) -> Result<ImageFloorModeV1, FloorErrorV1> {
    match bytes {
        LEGACY_MODE => Ok(ImageFloorModeV1::LegacyClosed),
        REQUIRED_MODE => Ok(ImageFloorModeV1::Required),
        _ => Err(FloorErrorV1::Provisioning),
    }
}

fn read_mode(target: &Path) -> Result<Vec<u8>, FloorErrorV1> {
    read_optional_bounded_role_credential_v1(
        target.parent().ok_or(FloorErrorV1::Provisioning)?,
        target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(FloorErrorV1::Provisioning)?,
        REQUIRED_MODE.len(),
        LEGACY_MODE.len(),
        false,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| FloorErrorV1::Provisioning)?
    .ok_or(FloorErrorV1::Provisioning)
}

fn credential_directory(endpoint: FloorEndpointV1) -> &'static Path {
    Path::new(match endpoint {
        FloorEndpointV1::ControllerStorageClient => "/run/credentials/aos-sandboxd.service",
        FloorEndpointV1::StorageBroker => "/run/credentials/aos-storaged.service",
    })
}

fn read_public(endpoint: FloorEndpointV1) -> Result<[u8; PROVISION_BYTES], FloorErrorV1> {
    read_optional_bounded_role_credential_v1(
        credential_directory(endpoint),
        PUBLIC_CREDENTIAL,
        PROVISION_BYTES,
        PROVISION_BYTES,
        false,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| FloorErrorV1::Provisioning)?
    .ok_or(FloorErrorV1::Provisioning)?
    .try_into()
    .map_err(|_| FloorErrorV1::Provisioning)
}

fn read_auth(endpoint: FloorEndpointV1) -> Result<Zeroizing<[u8; 32]>, FloorErrorV1> {
    let bytes = Zeroizing::new(
        read_optional_bounded_role_credential_v1(
            credential_directory(endpoint),
            AUTH_CREDENTIAL,
            32,
            32,
            true,
            CredentialOwnerPolicyV1::RootOrCurrent,
        )
        .map_err(|_| FloorErrorV1::Provisioning)?
        .ok_or(FloorErrorV1::Provisioning)?,
    );
    let mut auth = Zeroizing::new([0; 32]);
    auth.copy_from_slice(&bytes);
    if *auth == [0; 32] {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(auth)
}

fn decode_provision(
    bytes: &[u8],
    endpoint: FloorEndpointV1,
) -> Result<(FloorProfileV1, [u8; 34]), FloorErrorV1> {
    if bytes.len() != PROVISION_BYTES
        || &bytes[..8] != b"AOSBTD01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..12] != [0; 2]
        || bytes[158..160] != [0; 2]
    {
        return Err(FloorErrorV1::Encoding);
    }
    let profile = FloorProfileV1::decode(&bytes[12..12 + PROFILE_BYTES])?;
    let salt_name: [u8; 34] = bytes[124..158]
        .try_into()
        .map_err(|_| FloorErrorV1::Encoding)?;
    if profile.endpoint() != endpoint
        || salt_name[..2] != 0x000b_u16.to_be_bytes()
        || salt_name[2..] == [0; 32]
        || Sha256::digest(salt_name).as_slice() != profile.salt_key_name_digest()
    {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok((profile, salt_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_floor_image_mode_never_infers_required_or_legacy() {
        assert_eq!(
            decode_mode(LEGACY_MODE).unwrap(),
            ImageFloorModeV1::LegacyClosed
        );
        assert_eq!(
            decode_mode(REQUIRED_MODE).unwrap(),
            ImageFloorModeV1::Required
        );
        for bytes in [
            b"".as_slice(),
            b"legacy-closed-v1",
            b"required-v1\n\0",
            b"optional-v1\n",
        ] {
            assert!(decode_mode(bytes).is_err());
        }
    }

    #[test]
    fn tpm_floor_provision_is_canonical_role_and_salt_name_bound() {
        let endpoint = FloorEndpointV1::ControllerStorageClient;
        let mut name = [8; 34];
        name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        let profile = FloorProfileV1::new(
            endpoint,
            [1; 16],
            [2; 16],
            [3; 32],
            Sha256::digest(name).into(),
        )
        .unwrap();
        let mut bytes = [0; PROVISION_BYTES];
        bytes[..8].copy_from_slice(b"AOSBTD01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..124].copy_from_slice(&profile.encode());
        bytes[124..158].copy_from_slice(&name);
        assert_eq!(decode_provision(&bytes, endpoint).unwrap().0, profile);
        for offset in [0, 8, 9, 10, 11, 124, 125, 126, 157, 158, 159] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(
                decode_provision(&changed, endpoint).is_err(),
                "offset {offset}"
            );
        }
        assert!(decode_provision(&bytes, FloorEndpointV1::StorageBroker).is_err());
        assert!(decode_provision(&bytes[..159], endpoint).is_err());
        assert!(decode_provision(&[bytes.as_slice(), &[0]].concat(), endpoint).is_err());
    }
}
