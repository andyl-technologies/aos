//! Exact handoff comparison input for the closed report ingress process.
//!
//! ```text
//! kernel-export-report-handoff-v1[344] = canonical AOSKGH01 frame
//! ```
//!
//! The handoff ID is unkeyed. This credential can select a tuple for a
//! read-only comparison, but cannot authenticate Storage or authorize Stage.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use crate::handoff::{DenyStageHandoff, HANDOFF_BYTES};

const CREDENTIAL_DIRECTORY: &str =
    "/run/credentials/aos-sandbox-kernel-export-owner-report-ingressd.service";
const HANDOFF_FILE: &str = "kernel-export-report-handoff-v1";

/// Reports absent or redirected comparison-record custody.
#[derive(Debug, thiserror::Error)]
pub enum ReportIngressCredentialError {
    /// The selected credential directory differs from the fixed service path.
    #[error("report ingress credential directory is unavailable or unprotected")]
    Directory,
    /// The handoff record is absent, redirected, or malformed.
    #[error("report ingress handoff comparison record is unavailable or noncanonical")]
    Handoff,
}

/// Loads one protected, nonauthorizing handoff comparison record.
///
/// # Errors
///
/// Rejects another credential directory, changed ownership or permissions,
/// redirected or wrongly sized files, and noncanonical AOSKGH01 bytes.
pub fn handoff_from_systemd_credential() -> Result<DenyStageHandoff, ReportIngressCredentialError> {
    let selected =
        std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(ReportIngressCredentialError::Directory)?;
    if Path::new(&selected) != Path::new(CREDENTIAL_DIRECTORY) {
        return Err(ReportIngressCredentialError::Directory);
    }

    read_handoff(Path::new(CREDENTIAL_DIRECTORY), 0, 0)
}

fn read_handoff(
    directory: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<DenyStageHandoff, ReportIngressCredentialError> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|_| ReportIngressCredentialError::Directory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(ReportIngressCredentialError::Directory);
    }

    let path = directory.join(HANDOFF_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ReportIngressCredentialError::Handoff)?;
    require_protected_file(&file, owner_uid, owner_gid)?;

    let mut bytes = [0_u8; HANDOFF_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| ReportIngressCredentialError::Handoff)?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| ReportIngressCredentialError::Handoff)?
        != 0
    {
        return Err(ReportIngressCredentialError::Handoff);
    }
    DenyStageHandoff::parse(&bytes).map_err(|_| ReportIngressCredentialError::Handoff)
}

fn require_protected_file(
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), ReportIngressCredentialError> {
    let metadata = file
        .metadata()
        .map_err(|_| ReportIngressCredentialError::Handoff)?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || ![0o400, 0o600].contains(&(metadata.mode() & 0o7777))
        || metadata.len() != HANDOFF_BYTES as u64
        || metadata.nlink() != 1
    {
        return Err(ReportIngressCredentialError::Handoff);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::origin::tests::fixture;

    #[test]
    fn protected_exact_handoff_is_only_a_comparison_input() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("credentials");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = directory.join(HANDOFF_FILE);
        std::fs::write(&file, fixture().handoff).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        assert!(read_handoff(&directory, uid, gid).is_ok());
        assert!(read_handoff(&directory, uid.wrapping_add(1), gid).is_err());

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read_handoff(&directory, uid, gid).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_handoff(&directory, uid, gid).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

        let duplicate = directory.join("duplicate");
        std::fs::hard_link(&file, &duplicate).unwrap();
        assert!(read_handoff(&directory, uid, gid).is_err());
        std::fs::remove_file(&duplicate).unwrap();

        let mut corrupt = fixture().handoff;
        corrupt[72] ^= 1;
        std::fs::write(&file, corrupt).unwrap();
        assert!(read_handoff(&directory, uid, gid).is_err());

        std::fs::write(&file, &fixture().handoff[..HANDOFF_BYTES - 1]).unwrap();
        assert!(read_handoff(&directory, uid, gid).is_err());
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/dev/null", &file).unwrap();
        assert!(read_handoff(&directory, uid, gid).is_err());
    }
}
