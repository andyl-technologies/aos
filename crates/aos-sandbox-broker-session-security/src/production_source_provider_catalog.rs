//! Fail-closed installation of the nonauthorizing SourceProvider catalog pair.
//!
//! PID 1 supplies the canonical signed publication and matching row manifest
//! as separate named credentials. The content-addressed manifest is synced
//! first, then the publication locator is atomically replaced. A crash between
//! them can only leave an unusable pair; the fixed owner still authenticates
//! the signature and exact protected journal head after RootMount handshake.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_source_provider_protocol::ProviderCatalogManifestV1;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, Stat, fchmod, fstat, fsync, open, openat, renameat, unlinkat,
};
use rustix::rand::{GetRandomFlags, getrandom};

const STATE_ROOT: &str = "/var/lib/aos/source-provider";
const CREDENTIAL_NAME: &str = "current-catalog-publication";
const MANIFEST_CREDENTIAL_NAME: &str = "current-catalog-manifest";
const PUBLICATION_BYTES: usize = 520;
const MAXIMUM_MANIFEST_BYTES: usize = 54 + 64 * 232;

/// Reports rejection while installing the nonauthorizing catalog locator.
#[derive(Debug, thiserror::Error)]
pub enum ProductionSourceProviderCatalogInstallErrorV1 {
    /// The installer was not invoked as root.
    #[error("SourceProvider catalog installer requires real and effective UID zero")]
    Identity,
    /// The systemd credential is absent, malformed, or unprotected.
    #[error("SourceProvider catalog credential is invalid: {0}")]
    Credential(&'static str),
    /// The fixed state directory or publication entry is unprotected.
    #[error("SourceProvider catalog state is invalid: {0}")]
    State(&'static str),
    /// Atomic publication or durable sync failed.
    #[error("SourceProvider catalog publication failed: {0}")]
    Publication(&'static str),
}

/// Installs a matching manifest before atomically replacing the publication.
///
/// The installer accepts only a root-owned, singly linked, private regular
/// 520-byte publication, bounded canonical manifest, and a root-owned,
/// mode-0700 state directory. This is storage hygiene, not a signature or
/// currentness decision: the fixed owner still verifies the publication and
/// journal before selecting any resource row.
///
/// # Errors
///
/// Rejects missing root identity, credential or state protection failures,
/// malformed length, unsafe existing entries, or an unsuccessful durable
/// write/rename. The old publication is retained until the atomic rename.
pub fn install_fixed_source_provider_catalog_credential()
-> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Identity);
    }

    let publication = read_systemd_credential(CREDENTIAL_NAME, PUBLICATION_BYTES)?;
    let manifest_bytes = read_systemd_credential(MANIFEST_CREDENTIAL_NAME, MAXIMUM_MANIFEST_BYTES)?;
    let manifest =
        ProviderCatalogManifestV1::from_canonical_bytes(&manifest_bytes).map_err(|_| {
            ProductionSourceProviderCatalogInstallErrorV1::Credential("manifest is noncanonical")
        })?;
    if !publication_matches_manifest(&publication, &manifest) {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
            "manifest does not match publication head",
        ));
    }
    let state = open_private_state_directory()?;
    let manifest_name = manifest_filename(manifest.digest());
    install_in_directory(state.as_fd(), &manifest_name, &manifest_bytes, 0)?;
    install_in_directory(state.as_fd(), CREDENTIAL_NAME, &publication, 0)
}

fn publication_matches_manifest(publication: &[u8], manifest: &ProviderCatalogManifestV1) -> bool {
    publication.len() == PUBLICATION_BYTES
        && publication[0..8] == *b"AOSPCP01"
        && publication[72..104] == *manifest.namespace_digest().as_bytes()
        && publication[104..112] == manifest.generation().to_be_bytes()
        && publication[112..144] == *manifest.digest().as_bytes()
}

pub(crate) fn manifest_filename(digest: aos_sandbox_core::ObjectDigest) -> String {
    let mut filename = String::from("catalog-manifest-");
    for octet in digest.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut filename, "{octet:02x}");
    }
    filename
}

fn read_systemd_credential(
    name: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ProductionSourceProviderCatalogInstallErrorV1> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(
        ProductionSourceProviderCatalogInstallErrorV1::Credential("directory is absent"),
    )?;
    let directory = Path::new(&directory);
    if !directory.is_absolute() {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
            "directory is not absolute",
        ));
    }
    let directory_fd = open(
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Credential("directory"))?;
    let directory_stat = fstat(&directory_fd).map_err(|_| {
        ProductionSourceProviderCatalogInstallErrorV1::Credential("directory metadata")
    })?;
    if FileType::from_raw_mode(directory_stat.st_mode) != FileType::Directory
        || directory_stat.st_uid != 0
        || !matches!(directory_stat.st_mode & 0o7777, 0o500 | 0o700)
    {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
            "directory protection",
        ));
    }

    let descriptor = openat(
        &directory_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Credential("publication file"))?;
    let before = fstat(&descriptor).map_err(|_| {
        ProductionSourceProviderCatalogInstallErrorV1::Credential("publication metadata")
    })?;
    if !valid_credential(&before, maximum_bytes) {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
            "publication protection",
        ));
    }

    let mut file = File::from(descriptor);
    let byte_count = usize::try_from(before.st_size).map_err(|_| {
        ProductionSourceProviderCatalogInstallErrorV1::Credential("publication length")
    })?;
    let mut bytes = vec![0; byte_count];
    file.read_exact(&mut bytes).map_err(|_| {
        ProductionSourceProviderCatalogInstallErrorV1::Credential("publication bytes")
    })?;
    let mut trailing = [0];
    if file.read(&mut trailing).map_err(|_| {
        ProductionSourceProviderCatalogInstallErrorV1::Credential("publication tail")
    })? != 0
        || !same_stable_metadata(
            &before,
            &fstat(file.as_fd()).map_err(|_| {
                ProductionSourceProviderCatalogInstallErrorV1::Credential("publication recheck")
            })?,
        )
    {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
            "publication changed",
        ));
    }
    Ok(bytes)
}

fn valid_credential(stat: &Stat, maximum_bytes: usize) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == 0
        && stat.st_nlink == 1
        && stat.st_size > 0
        && stat.st_size <= maximum_bytes as i64
        && matches!(stat.st_mode & 0o7777, 0o400 | 0o600)
}

fn same_stable_metadata(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn open_private_state_directory()
-> Result<std::os::fd::OwnedFd, ProductionSourceProviderCatalogInstallErrorV1> {
    let filesystem_root = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("filesystem root"))?;
    let root = BeneathRoot::from_owned(filesystem_root)
        .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("filesystem root"))?;
    let relative = Path::new(STATE_ROOT)
        .strip_prefix("/")
        .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("fixed path"))?;
    let resolved = root
        .resolve(
            relative,
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("directory"))?;
    let path_stat = fstat(resolved.as_fd())
        .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("directory metadata"))?;
    if !valid_state_directory(&path_stat) {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
            "directory protection",
        ));
    }
    let directory = openat(
        resolved.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("readable directory"))?;
    let readable_stat = fstat(&directory)
        .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::State("readable metadata"))?;
    if path_stat.st_dev != readable_stat.st_dev
        || path_stat.st_ino != readable_stat.st_ino
        || !valid_state_directory(&readable_stat)
    {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
            "directory changed",
        ));
    }
    Ok(directory)
}

fn valid_state_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_mode & 0o7777 == 0o700
}

fn install_in_directory(
    directory: std::os::fd::BorrowedFd<'_>,
    name: &str,
    bytes: &[u8],
    expected_uid: u32,
) -> Result<(), ProductionSourceProviderCatalogInstallErrorV1> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_MANIFEST_BYTES {
        return Err(ProductionSourceProviderCatalogInstallErrorV1::Credential(
            "publication length",
        ));
    }
    match openat(
        directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(existing) => {
            let stat = fstat(&existing).map_err(|_| {
                ProductionSourceProviderCatalogInstallErrorV1::State("existing metadata")
            })?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != expected_uid
                || stat.st_nlink != 1
                || stat.st_mode & 0o7777 != 0o600
            {
                return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                    "existing publication protection",
                ));
            }
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(_) => {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::State(
                "existing publication",
            ));
        }
    }

    let mut nonce = [0; 16];
    let mut filled = 0;
    while filled < nonce.len() {
        let count = getrandom(&mut nonce[filled..], GetRandomFlags::empty())
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Publication("nonce"))?;
        if count == 0 {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Publication(
                "nonce short read",
            ));
        }
        filled += count;
    }
    let mut temporary_name = format!(".{name}-");
    for octet in nonce {
        write!(&mut temporary_name, "{octet:02x}").map_err(|_| {
            ProductionSourceProviderCatalogInstallErrorV1::Publication("nonce format")
        })?;
    }
    let descriptor = openat(
        directory,
        temporary_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Publication("temporary file"))?;
    let result = (|| {
        fchmod(&descriptor, Mode::from_raw_mode(0o600))
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Publication("file mode"))?;
        let mut file = File::from(descriptor);
        file.write_all(bytes)
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Publication("write"))?;
        let stat = fstat(file.as_fd()).map_err(|_| {
            ProductionSourceProviderCatalogInstallErrorV1::Publication("file metadata")
        })?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != expected_uid
            || stat.st_nlink != 1
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_size != bytes.len() as i64
        {
            return Err(ProductionSourceProviderCatalogInstallErrorV1::Publication(
                "temporary file changed",
            ));
        }
        file.sync_all()
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Publication("file sync"))?;
        renameat(directory, temporary_name.as_str(), directory, name)
            .map_err(|_| ProductionSourceProviderCatalogInstallErrorV1::Publication("rename"))?;
        fsync(directory).map_err(|_| {
            ProductionSourceProviderCatalogInstallErrorV1::Publication("directory sync")
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_source_provider_protocol::{ProviderCatalogRowV1, StorageLiveExportSelectorV1};

    fn manifest() -> ProviderCatalogManifestV1 {
        let selector = StorageLiveExportSelectorV1::new(
            [1; 16],
            1,
            [2; 32],
            ObjectDigest::from_bytes([3; 32]),
        )
        .unwrap();
        let row = ProviderCatalogRowV1::new(
            ObjectDigest::from_bytes([4; 32]),
            [5; 32],
            1,
            ObjectDigest::from_bytes([6; 32]),
            1,
            ObjectDigest::from_bytes([7; 32]),
            selector,
        )
        .unwrap();
        ProviderCatalogManifestV1::new(2, ObjectDigest::from_bytes([8; 32]), vec![row]).unwrap()
    }

    #[test]
    fn manifest_pair_rejects_downgrade_and_fork_before_installation() {
        let manifest = manifest();
        let mut publication = vec![0; PUBLICATION_BYTES];
        publication[0..8].copy_from_slice(b"AOSPCP01");
        publication[72..104].copy_from_slice(manifest.namespace_digest().as_bytes());
        publication[104..112].copy_from_slice(&manifest.generation().to_be_bytes());
        publication[112..144].copy_from_slice(manifest.digest().as_bytes());
        assert!(publication_matches_manifest(&publication, &manifest));

        publication[104..112].copy_from_slice(&1_u64.to_be_bytes());
        assert!(!publication_matches_manifest(&publication, &manifest));
        publication[104..112].copy_from_slice(&manifest.generation().to_be_bytes());
        publication[112] ^= 1;
        assert!(!publication_matches_manifest(&publication, &manifest));
    }

    #[test]
    fn atomic_installer_replaces_exact_private_publication() {
        let temporary = tempfile::tempdir().expect("temporary state directory");
        let directory = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open state directory");
        let uid = rustix::process::geteuid().as_raw();
        install_in_directory(
            directory.as_fd(),
            CREDENTIAL_NAME,
            &[1; PUBLICATION_BYTES],
            uid,
        )
        .expect("first publication");
        install_in_directory(
            directory.as_fd(),
            CREDENTIAL_NAME,
            &[2; PUBLICATION_BYTES],
            uid,
        )
        .expect("replacement publication");

        let installed = std::fs::read(temporary.path().join(CREDENTIAL_NAME))
            .expect("read installed publication");
        assert_eq!(installed, [2; PUBLICATION_BYTES]);
        assert_eq!(
            std::fs::read_dir(temporary.path())
                .expect("list state")
                .count(),
            1
        );
    }

    #[test]
    fn atomic_installer_rejects_length_and_existing_symlink() {
        let temporary = tempfile::tempdir().expect("temporary state directory");
        let directory = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open state directory");
        let uid = rustix::process::geteuid().as_raw();
        assert!(install_in_directory(directory.as_fd(), CREDENTIAL_NAME, &[], uid).is_err());
        std::os::unix::fs::symlink("elsewhere", temporary.path().join(CREDENTIAL_NAME))
            .expect("place unsafe existing entry");
        assert!(
            install_in_directory(
                directory.as_fd(),
                CREDENTIAL_NAME,
                &[0; PUBLICATION_BYTES],
                uid
            )
            .is_err()
        );
    }

    #[test]
    fn atomic_installer_rejects_linked_or_public_existing_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary state directory");
        let directory = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open state directory");
        let uid = rustix::process::geteuid().as_raw();
        let publication = temporary.path().join(CREDENTIAL_NAME);
        std::fs::write(&publication, [3; PUBLICATION_BYTES]).expect("existing publication");

        std::fs::set_permissions(&publication, std::fs::Permissions::from_mode(0o644))
            .expect("public mode");
        assert!(
            install_in_directory(
                directory.as_fd(),
                CREDENTIAL_NAME,
                &[4; PUBLICATION_BYTES],
                uid
            )
            .is_err()
        );

        std::fs::set_permissions(&publication, std::fs::Permissions::from_mode(0o600))
            .expect("private mode");
        std::fs::hard_link(&publication, temporary.path().join("linked-publication"))
            .expect("existing hard link");
        assert!(
            install_in_directory(
                directory.as_fd(),
                CREDENTIAL_NAME,
                &[4; PUBLICATION_BYTES],
                uid
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(publication).expect("unchanged publication"),
            [3; PUBLICATION_BYTES]
        );
    }
}
