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

mod initial;
pub(crate) use initial::{InitialModeOriginalV1, mode_initial_receiving_demand_v1};
pub(in crate::recovery::journal) use initial::{
    InitialProvisionOriginalV1, INITIAL_MODE_RESULT_CELLS_V1,
    INITIAL_PROVISION_RESULT_CELLS_V1,
};

mod receiving;
pub(crate) use receiving::{ModeRevalidationOriginalV1, mode_revalidation_receiving_demand_v1};
pub(in crate::recovery::journal) use receiving::{
    AbsentFloorNamesOriginalV1, CredentialReadCustodyV1,
    ProvisionRevalidationOriginalV1, MAXIMUM_MODE_PATH_BYTES_V1,
    auxiliary_currentness_work_bytes_v1, canonical_currentness_work_bytes_v1,
    MODE_REVALIDATION_RESULT_CELLS_V1,
};

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{StatVfsMountFlags, fstatvfs};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::format::FloorEndpointV1;
use super::{FloorErrorV1, FloorProfileV1};
use aos_sandbox_linux::credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};

use aos_sandbox_protocol::method46_provisioning::PROVISION_BYTES;
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
    currentness: Option<super::super::floor_revalidation::FloorCurrentnessSharedV1>,
    path: PathBuf,
    target: PathBuf,
    file: File,
    identity: (u64, u64),
    mode: ImageFloorModeV1,
}

impl ModePinV1 {
    pub(super) fn open(endpoint: FloorEndpointV1) -> Result<Self, FloorErrorV1> {
        Self::open_fixed(mode_path(endpoint))
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

    /// Captures fixed Storage mode data into the prepaid original destination.
    ///
    /// # Errors
    /// Rejects a repeated capture or unsafe, absent, changed or malformed mode.
    pub(crate) fn open_storage_worker_image_mode_retaining(
        original: &mut InitialModeOriginalV1,
    ) -> Result<Self, FloorErrorV1> {
        Self::open_retaining(FloorEndpointV1::StorageBroker, original)
    }

    /// Compares this exact pin while retaining reached native observations.
    ///
    /// # Errors
    /// Rejects repeated observation, changed identity, mount or mode data.
    pub(crate) fn revalidate_retaining(
        &self,
        original: &mut ModeRevalidationOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        original.observe_once(self, CredentialReadCustodyV1::Retained)
    }

    /// Compares fixed Storage launch presence into its prepaid original owner.
    ///
    /// # Errors
    /// Rejects another fixed mode purpose, mismatched launch presence or any
    /// failed original confinement/mode observation. Reentry stays closed.
    pub(crate) fn require_storage_worker_launch_image_presence_retaining(
        &self,
        supplied: bool,
        original: &mut super::runtime::ModePresenceOriginalV1,
    ) -> Result<(), FloorErrorV1> {
        if self.path != Path::new("/etc/aos/method46-tpm-floor/storage-mode") {
            return Err(FloorErrorV1::Provisioning);
        }
        super::runtime::require_storage_worker_launch_image_presence_retaining(
            self, supplied, original,
        )
    }

    /// Checks Storage launch presence through this same fixed original mode.
    ///
    /// This borrows comparison data; it creates no floor or Required permission.
    ///
    /// # Errors
    /// Rejects another fixed purpose, mismatched presence, changed mode data or
    /// the unchanged Required owner-confinement failure.
    pub(crate) fn require_storage_worker_launch_image_presence(
        &self,
        supplied: bool,
    ) -> Result<(), FloorErrorV1> {
        if self.path != Path::new("/etc/aos/method46-tpm-floor/storage-mode") {
            return Err(FloorErrorV1::Provisioning);
        }
        super::runtime::require_storage_worker_launch_image_presence(self, supplied)
    }

    /// Retains only the immutable mode named by the signed Host contract.
    ///
    /// # Errors
    /// Rejects absent, unsafe, noncanonical or changed fixed mode files.
    pub(crate) fn open_runtime_deployment() -> Result<Self, FloorErrorV1> {
        Self::open_fixed(PathBuf::from("/etc/aos/runtime-deployment-tpm-floor/mode"))
    }

    /// Captures the same compiled Host mode into its already parked owner.
    pub(crate) fn open_runtime_deployment_retaining(
        original: &mut InitialModeOriginalV1,
    ) -> Result<Self, FloorErrorV1> {
        original.capture_once(
            PathBuf::from("/etc/aos/runtime-deployment-tpm-floor/mode"),
            CredentialReadCustodyV1::Retained,
        )?;
        original.take_pin_once().ok_or(FloorErrorV1::Provisioning)
    }

    /// Supplies the same fixed Host mode's initial read and final readback.
    pub(crate) fn runtime_deployment_initial_receiving_demand_v1(
    ) -> Option<aos_sandbox_model::ResourceVector> {
        let input = u64::try_from(LEGACY_MODE.len().checked_add(1)?).ok()?.checked_mul(2)?;
        Some(mode_initial_receiving_demand_v1()?
            .with(aos_sandbox_model::ResourceDimension::OutputBytes, input))
    }

    /// Supplies this same fixed mode's bounded retained comparison input.
    pub(crate) fn runtime_deployment_revalidation_receiving_demand_v1(
        &self,
    ) -> Option<aos_sandbox_model::ResourceVector> {
        if self.path != Path::new("/etc/aos/runtime-deployment-tpm-floor/mode") {
            return None;
        }
        let input = u64::try_from(LEGACY_MODE.len().checked_add(1)?).ok()?;
        Some(mode_revalidation_receiving_demand_v1()?
            .with(aos_sandbox_model::ResourceDimension::OutputBytes, input))
    }

    // Both fixed entries use this same retained-file engine. No caller path
    // crosses the module boundary or selects a provisioning purpose.
    fn open_fixed(path: PathBuf) -> Result<Self, FloorErrorV1> {
        let mut original = InitialModeOriginalV1::new();
        original.capture_once(path, CredentialReadCustodyV1::Ordinary)?;
        original.take_pin_once().ok_or(FloorErrorV1::Provisioning)
    }

    pub(super) fn open_retaining(
        endpoint: FloorEndpointV1,
        original: &mut InitialModeOriginalV1,
    ) -> Result<Self, FloorErrorV1> {
        original.capture_once(mode_path(endpoint), CredentialReadCustodyV1::Retained)?;
        original.take_pin_once().ok_or(FloorErrorV1::Provisioning)
    }

    pub(super) fn has_currentness_archive_v1(&self) -> bool {
        self.currentness.is_some()
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
        match self.currentness.as_ref() {
            Some(archive) => super::super::floor_revalidation::validate_mode(archive, self),
            None => {
                let mut original = ModeRevalidationOriginalV1::new();
                original.observe_once(self, CredentialReadCustodyV1::Ordinary)
            }
        }
    }

    pub(super) fn require_no_floor_names(&self, directory: &Path) -> Result<(), FloorErrorV1> {
        super::super::floor_revalidation::validate_absent(self.currentness.as_ref(), directory)
    }

    pub(super) fn install_currentness_archive_v1(
        &mut self,
        archive: &super::super::floor_revalidation::FloorCurrentnessSharedV1,
    ) -> Result<(), FloorErrorV1> {
        // The installed closed mode paths are bounded before new native work;
        // this is comparison DATA, not a new owner or a path-derived grant.
        if self.currentness.is_some()
            || self.path.as_os_str().as_encoded_bytes().len() > MAXIMUM_MODE_PATH_BYTES_V1
            || self.target.as_os_str().as_encoded_bytes().len() > MAXIMUM_MODE_PATH_BYTES_V1
        {
            return Err(FloorErrorV1::Provisioning);
        }
        self.currentness = Some(archive.clone());
        Ok(())
    }
}

pub(in crate::recovery::journal) struct ProvisionPinV1 {
    currentness: Option<super::super::floor_revalidation::FloorCurrentnessSharedV1>,
    endpoint: FloorEndpointV1,
    bytes: [u8; PROVISION_BYTES],
    auth_digest: [u8; 32],
    profile: FloorProfileV1,
    salt_name: [u8; 34],
}

impl ProvisionPinV1 {
    pub(super) fn open(endpoint: FloorEndpointV1) -> Result<Self, FloorErrorV1> {
        let mut original = InitialProvisionOriginalV1::new();
        original.capture_once(endpoint, CredentialReadCustodyV1::Ordinary)?;
        original.take_pin_once().ok_or(FloorErrorV1::Provisioning)
    }

    pub(super) fn open_retaining(
        endpoint: FloorEndpointV1,
        original: &mut InitialProvisionOriginalV1,
    ) -> Result<Self, FloorErrorV1> {
        original.capture_once(endpoint, CredentialReadCustodyV1::Retained)?;
        original.take_pin_once().ok_or(FloorErrorV1::Provisioning)
    }

    pub(super) const fn profile(&self) -> FloorProfileV1 {
        self.profile
    }

    pub(super) const fn salt_name(&self) -> [u8; 34] {
        self.salt_name
    }

    pub(super) fn current_auth(&self) -> Result<Zeroizing<[u8; 32]>, FloorErrorV1> {
        match &self.currentness {
            Some(archive) => super::super::floor_revalidation::validate_provision(archive, self),
            None => {
                let mut original = ProvisionRevalidationOriginalV1::new();
                original.observe_once(self, CredentialReadCustodyV1::Ordinary)?;
                original.take_completed().map(|(_, auth)| auth)
                    .ok_or(FloorErrorV1::Provisioning)
            }
        }
    }

    pub(super) fn install_currentness_archive_v1(
        &mut self,
        archive: &super::super::floor_revalidation::FloorCurrentnessSharedV1,
    ) -> Result<(), FloorErrorV1> {
        if self.currentness.is_some() {
            return Err(FloorErrorV1::Provisioning);
        }
        self.currentness = Some(archive.clone());
        Ok(())
    }

    pub(super) fn revalidate(&self) -> Result<(), FloorErrorV1> {
        drop(self.current_auth()?);
        Ok(())
    }
}

fn mode_path(endpoint: FloorEndpointV1) -> PathBuf {
    let basename = match endpoint {
        FloorEndpointV1::ControllerStorageClient => "controller-mode",
        FloorEndpointV1::StorageBroker => "storage-mode",
    };
    Path::new("/etc/aos/method46-tpm-floor").join(basename)
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

/// Decodes the single canonical public record without admitting a live owner.
///
/// Both normal-owner custody and the Source-paid manual readback use this DATA
/// operation. It neither reads private auth nor creates provisioning authority.
///
/// # Errors
/// Refuses wrong framing, width, reserved bytes, endpoint, sentinel profile
/// fields or a salt Name that differs from the profile's SHA-256 commitment.
pub(crate) fn decode_provision(
    bytes: &[u8],
    endpoint: FloorEndpointV1,
) -> Result<(FloorProfileV1, [u8; 34]), FloorErrorV1> {
    aos_sandbox_protocol::method46_provisioning::decode_provision_v1(bytes, endpoint)
        .map(|(profile, salt_name)| (FloorProfileV1::from_data(profile), salt_name))
        .map_err(Into::into)
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
