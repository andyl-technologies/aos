//! Durable, nonauthorizing stop point for an offline Cache journal migration.
//!
//! The fixed hold is root-owned outside the Controller-owned object tree. It
//! blocks this Controller and the root journal view until an offline migration
//! can prove a rollback fence and re-establish authority at the new scope.
//!
//! The 116-byte on-disk format is:
//!
//! ```text
//! AOSCMH01 | version:u16 | reserved:[u8;6] | Controller UID:u32
//! old owner scope:[u8;32] | new owner scope:[u8;32]
//! SHA-256(domain || preceding 84 bytes):[u8;32]
//! ```
//!
//! The checksum detects corruption; root-owned placement supplies custody,
//! and neither property makes this hold an authority certificate.

use std::{fs, fs::File, io, io::Read as _, io::Write as _, path::Path};

use rustix::{
    fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat, openat2},
    io::Errno,
};
use sha2::{Digest as _, Sha256};

use crate::{cache_residency::CacheResidencyProtectedJournalErrorV1, journal::JournalError};

use super::{
    cache_owner_scope,
    offline_migration_preflight::{
        LegacyCacheJournalPreflightReportV1, legacy_cache_owner_scope,
        preflight_fixed_legacy_cache_journals_for_uid,
    },
};

const HOLD_PARENT: &str = "/var/lib/aos/sandbox";
const HOLD_NAME: &str = "cache-residency-migration.hold";
const HOLD_MAGIC: &[u8; 8] = b"AOSCMH01";
const HOLD_DOMAIN: &[u8] = b"aos.sandbox.cache-residency.migration-hold.v1\0";
const HOLD_BYTES: usize = 116;

/// Durably stages or resumes a nonauthorizing hold, then replays the old journals.
///
/// The hold is created before replay and remains if replay or the process
/// fails. Repeating this call accepts only the exact recorded owner UID and
/// old/new scope pair. The return value is diagnostic: it does not permit a
/// rename, scope rewrite, authority renewal, or Controller startup.
///
/// # Errors
///
/// Returns an error for an unsafe or altered hold, unsafe parent, failed
/// durability operation, or any legacy journal preflight failure. Errors
/// after hold creation deliberately leave the hold in place.
pub fn stage_fixed_legacy_cache_migration_hold_for_uid(
    owner_uid: u32,
) -> Result<LegacyCacheJournalPreflightReportV1, CacheResidencyProtectedJournalErrorV1> {
    stage_or_resume_hold_at(Path::new(HOLD_PARENT), 0, owner_uid)?;
    preflight_fixed_legacy_cache_journals_for_uid(owner_uid)
}

pub(super) fn reject_pending_fixed_migration_hold() -> Result<(), JournalError> {
    reject_pending_migration_hold_at(Path::new(HOLD_PARENT))
}

fn reject_pending_migration_hold_at(parent: &Path) -> Result<(), JournalError> {
    let path = parent.join(HOLD_NAME);
    match fs::symlink_metadata(path) {
        Ok(_) => Err(JournalError::ProtectedBoundary),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(JournalError::Io(error)),
    }
}

fn stage_or_resume_hold_at(
    parent_path: &Path,
    parent_uid: u32,
    owner_uid: u32,
) -> Result<(), JournalError> {
    let parent: File = openat2(
        rustix::fs::CWD,
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(rustix_io)?
    .into();
    let parent_stat = fstat(&parent).map_err(rustix_io)?;
    if FileType::from_raw_mode(parent_stat.st_mode) != FileType::Directory
        || parent_stat.st_uid != parent_uid
        || parent_stat.st_mode & 0o022 != 0
    {
        return Err(JournalError::ProtectedBoundary);
    }

    let expected = encoded_hold(owner_uid);
    match openat(
        &parent,
        HOLD_NAME,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(descriptor) => {
            let mut file = File::from(descriptor);
            file.write_all(&expected)?;
            file.sync_all()?;
            parent.sync_all()?;
        }
        Err(Errno::EXIST) => {}
        Err(error) => return Err(rustix_io(error)),
    }

    let descriptor = openat(
        &parent,
        HOLD_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    let stat = fstat(&descriptor).map_err(rustix_io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != parent_uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size != HOLD_BYTES as i64
    {
        return Err(JournalError::ProtectedBoundary);
    }

    let mut file = File::from(descriptor);
    let mut actual = [0_u8; HOLD_BYTES];
    file.read_exact(&mut actual)?;
    if actual != expected {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn encoded_hold(owner_uid: u32) -> [u8; HOLD_BYTES] {
    let mut bytes = [0_u8; HOLD_BYTES];
    bytes[..8].copy_from_slice(HOLD_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..20].copy_from_slice(&owner_uid.to_be_bytes());
    bytes[20..52].copy_from_slice(legacy_cache_owner_scope().as_bytes());
    bytes[52..84].copy_from_slice(cache_owner_scope().as_bytes());
    let checksum = Sha256::new()
        .chain_update(HOLD_DOMAIN)
        .chain_update(&bytes[..84])
        .finalize();
    bytes[84..].copy_from_slice(&checksum);
    bytes
}

fn rustix_io(error: Errno) -> JournalError {
    JournalError::Io(io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use super::*;

    #[test]
    fn hold_is_create_once_and_resumes_without_rewriting() {
        let parent = tempfile::tempdir().expect("parent");
        let uid = rustix::process::geteuid().as_raw();
        assert!(reject_pending_migration_hold_at(parent.path()).is_ok());
        stage_or_resume_hold_at(parent.path(), uid, 37).expect("stage");

        let path = parent.path().join(HOLD_NAME);
        assert!(matches!(
            reject_pending_migration_hold_at(parent.path()),
            Err(JournalError::ProtectedBoundary)
        ));
        let before = fs::read(&path).expect("hold");
        stage_or_resume_hold_at(parent.path(), uid, 37).expect("resume");
        assert_eq!(fs::read(&path).expect("unchanged hold"), before);
        assert_eq!(before, encoded_hold(37));
        assert!(matches!(
            stage_or_resume_hold_at(parent.path(), uid, 38),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn partial_or_altered_hold_stays_fail_closed() {
        let parent = tempfile::tempdir().expect("parent");
        let uid = rustix::process::geteuid().as_raw();
        let path = parent.path().join(HOLD_NAME);
        fs::write(&path, b"partial").expect("partial hold");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");

        assert!(matches!(
            stage_or_resume_hold_at(parent.path(), uid, 37),
            Err(JournalError::ProtectedBoundary)
        ));
        assert_eq!(fs::read(&path).expect("unchanged partial hold"), b"partial");

        fs::write(&path, encoded_hold(37)).expect("valid hold");
        let mut altered = fs::read(&path).expect("hold");
        altered[52] ^= 1;
        fs::write(&path, &altered).expect("alter hold");
        assert!(matches!(
            stage_or_resume_hold_at(parent.path(), uid, 37),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn unsafe_hold_and_parent_are_rejected() {
        let parent = tempfile::tempdir().expect("parent");
        let uid = rustix::process::geteuid().as_raw();
        let path = parent.path().join(HOLD_NAME);
        std::os::unix::fs::symlink("missing", &path).expect("symlink");
        assert!(stage_or_resume_hold_at(parent.path(), uid, 37).is_err());
        fs::remove_file(&path).expect("remove fixture");

        stage_or_resume_hold_at(parent.path(), uid, 37).expect("stage hold");
        let alias = parent.path().join("alias");
        fs::hard_link(&path, &alias).expect("hard link");
        assert!(matches!(
            stage_or_resume_hold_at(parent.path(), uid, 37),
            Err(JournalError::ProtectedBoundary)
        ));
        fs::remove_file(&alias).expect("remove alias");
        fs::remove_file(&path).expect("remove fixture");

        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o777)).expect("widen");
        assert!(matches!(
            stage_or_resume_hold_at(parent.path(), uid, 37),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(!path.exists());
    }
}
