//! Instance-key loading for the hub's at-rest secret sealing.
//!
//! The sealing crypto — the [`SecretSealer`] trait, the production
//! [`AesGcmSealer`], the dev/test [`XorSealer`], and the [`parse_key`] decoder —
//! lives in [`aos_hub_core::auth::seal`] (RFC-0004 Phase 5) so the
//! Cloudflare Worker shares it; they are re-exported here so the hub's
//! `auth::seal::…` paths are unchanged. What stays native is the IO-bound
//! [`instance_sealer`], which loads (or creates) the per-instance key from the
//! filesystem and returns a sealer bound to it.
//!
//! # Instance key
//!
//! The 256-bit instance key is sourced, in order:
//!
//! 1. from the file named by the `AOS_HUB_SECRET_KEY_FILE` environment
//!    variable (32 raw bytes, or 64 hex characters), if set; otherwise
//! 2. from `{root}/secret.key`, generated with `0600` permissions on first
//!    `serve` if absent and reloaded verbatim thereafter.
//!
//! Because the key is persisted, secrets sealed by one process unseal in the
//! next. Signing-key generations use explicit external custody and never store
//! private material behind this instance sealer.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::Rng as _;
use zeroize::Zeroizing;

pub use aos_hub_core::auth::seal::{
    dev_sealer, parse_key, AesGcmSealer, SecretSealer, XorSealer, KEY_LEN,
};

const MAX_SECRET_FILE_BYTES: u64 = 1024 * 1024;

/// Loads or creates the per-instance key and returns an [`AesGcmSealer`].
///
/// The key is read from `AOS_HUB_SECRET_KEY_FILE` if that environment variable
/// is set, otherwise from `{root}/secret.key`, which is generated with `0600`
/// permissions on first call when absent. See the [module docs](self) for the
/// key-sourcing rules.
///
/// # Errors
///
/// Returns an error if the configured key file cannot be read or parsed, if a
/// new key cannot be written, or if the loaded key is not exactly 32 bytes
/// (or 64 hex characters).
pub fn instance_sealer(root: &Path) -> Result<Box<dyn SecretSealer>> {
    let key = load_or_create_key(root)?;
    Ok(Box::new(AesGcmSealer::new(&key)?))
}

/// Resolves the 32-byte instance key per the [module docs](self) ordering.
fn load_or_create_key(root: &Path) -> Result<Vec<u8>> {
    if let Some(path) = std::env::var_os("AOS_HUB_SECRET_KEY_FILE") {
        let path = Path::new(&path);
        let raw = read_secret_file(path)
            .with_context(|| format!("reading AOS_HUB_SECRET_KEY_FILE at {}", path.display()))?;
        return parse_key(&raw)
            .with_context(|| format!("parsing instance key at {}", path.display()));
    }

    let path = root.join("secret.key");
    if path.exists() {
        let raw = read_secret_file(&path)?;
        parse_key(&raw).with_context(|| format!("parsing instance key at {}", path.display()))
    } else {
        let key: [u8; KEY_LEN] = rand::rng().random();
        match write_key_0600(&path, &key) {
            Ok(()) => Ok(key.to_vec()),
            Err(error) if is_already_exists(&error) => {
                let raw = read_secret_file(&path)?;
                parse_key(&raw)
                    .with_context(|| format!("parsing instance key at {}", path.display()))
            }
            Err(error) => Err(error),
        }
    }
}

fn is_already_exists(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
        || error
            .downcast_ref::<rustix::io::Errno>()
            .is_some_and(|errno| *errno == rustix::io::Errno::EXIST)
}

/// Reads one native secret from a non-symlink regular file in a trusted directory.
///
/// The opened file's device/inode is compared with the path metadata, closing
/// the check/open replacement race without relying on a host-specific command.
/// On Unix, the secret itself cannot grant group/other access. The sole
/// exception is systemd's ACL-backed `0440` representation inside the exact
/// directory named by `$CREDENTIALS_DIRECTORY`. A parent may grant read or
/// traversal access, but cannot be group/other-writable because that would
/// permit replacement. Ownership by either the effective user or root is
/// accepted so `LoadCredential=` mounts can be consumed by an unprivileged
/// service.
///
/// # Errors
///
/// Returns an error for a symlink, non-regular file, replacement race,
/// insecure ownership or permissions, or I/O failure.
pub fn read_secret_file(path: &Path) -> Result<Vec<u8>> {
    Ok(read_secret_file_zeroizing(path)?.to_vec())
}

/// Reads a secret into an allocation that is zeroized on every exit path.
pub(crate) fn read_secret_file_zeroizing(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(unix)]
    {
        return read_secret_file_unix(path);
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!(
            "secure secret-file loading is unsupported on this operating system: {}",
            path.display()
        )
    }
}

#[cfg(unix)]
fn read_secret_file_unix(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let (parent_fd, name) = open_secure_secret_parent(path)?;
    let fd = rustix::fs::openat(
        &parent_fd,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| {
        format!(
            "opening secret file {} without following links",
            path.display()
        )
    })?;
    let metadata = rustix::fs::fstat(&fd)
        .with_context(|| format!("inspecting secret file {}", path.display()))?;
    anyhow::ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::RegularFile,
        "secret file {} must be regular",
        path.display()
    );
    anyhow::ensure!(
        trusted_secret_owner(metadata.st_uid),
        "secret file {} is not owned by root or the effective user",
        path.display()
    );
    anyhow::ensure!(
        secret_file_mode_is_secure(path, metadata.st_mode),
        "secret file {} grants group/other permissions",
        path.display()
    );
    anyhow::ensure!(
        metadata.st_nlink == 1,
        "secret file {} must not have hard links",
        path.display()
    );
    anyhow::ensure!(
        metadata.st_size >= 0 && metadata.st_size as u64 <= MAX_SECRET_FILE_BYTES,
        "secret file {} exceeds the size limit",
        path.display()
    );
    let mut file = fs::File::from(fd);
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading secret file {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_SECRET_FILE_BYTES,
        "secret file {} grew past the size limit",
        path.display()
    );
    let final_metadata = rustix::fs::fstat(&file)
        .with_context(|| format!("re-inspecting secret file {}", path.display()))?;
    anyhow::ensure!(
        metadata.st_dev == final_metadata.st_dev
            && metadata.st_ino == final_metadata.st_ino
            && metadata.st_nlink == final_metadata.st_nlink
            && metadata.st_size == final_metadata.st_size
            && metadata.st_mtime == final_metadata.st_mtime
            && metadata.st_mtime_nsec == final_metadata.st_mtime_nsec
            && metadata.st_ctime == final_metadata.st_ctime
            && metadata.st_ctime_nsec == final_metadata.st_ctime_nsec,
        "secret file {} changed while it was read",
        path.display()
    );
    Ok(bytes)
}

#[cfg(unix)]
fn open_secure_secret_parent(path: &Path) -> Result<(std::os::fd::OwnedFd, &std::ffi::OsStr)> {
    let parent = path
        .parent()
        .context("secret path has no parent directory")?;
    let name = path.file_name().context("secret path has no filename")?;
    anyhow::ensure!(name != "." && name != "..", "secret filename is invalid");
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOFOLLOW;
    let mut parent_fd = rustix::fs::openat(
        rustix::fs::CWD,
        if parent.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        flags,
        rustix::fs::Mode::empty(),
    )
    .context("opening secret path traversal root")?;
    for component in parent.components() {
        let component = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(component) => component,
            std::path::Component::ParentDir => {
                anyhow::bail!("secret parent path cannot contain '..'")
            }
            std::path::Component::Prefix(_) => {
                anyhow::bail!("secret parent path has an unsupported prefix")
            }
        };
        parent_fd = rustix::fs::openat(&parent_fd, component, flags, rustix::fs::Mode::empty())
            .with_context(|| {
                format!(
                    "walking secret parent {} without following links",
                    parent.display()
                )
            })?;
    }
    let metadata = rustix::fs::fstat(&parent_fd)
        .with_context(|| format!("inspecting secret parent {}", parent.display()))?;
    anyhow::ensure!(
        rustix::fs::FileType::from_raw_mode(metadata.st_mode) == rustix::fs::FileType::Directory
            && trusted_secret_owner(metadata.st_uid)
            && secret_parent_mode_is_secure(metadata.st_mode),
        "secret parent {} must be a non-writable directory owned by root or the effective user",
        parent.display()
    );
    Ok((parent_fd, name))
}

#[cfg(unix)]
fn trusted_secret_owner(owner: u32) -> bool {
    trusted_secret_owner_for(owner, rustix::process::geteuid().as_raw())
}

#[cfg(unix)]
fn trusted_secret_owner_for(owner: u32, effective_user: u32) -> bool {
    owner == 0 || owner == effective_user
}

#[cfg(unix)]
fn secret_parent_mode_is_secure(mode: u32) -> bool {
    mode & 0o022 == 0
}

#[cfg(unix)]
fn secret_file_mode_is_secure(path: &Path, mode: u32) -> bool {
    if mode & 0o077 == 0 {
        return true;
    }

    let is_systemd_credential = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .is_some_and(|directory| path.parent() == Some(directory.as_path()));
    is_systemd_credential && mode & 0o077 == 0o040
}

/// Writes `key` to `path` with `0600` permissions, creating parent dirs.
///
/// # Errors
///
/// Returns an error if the parent directory or the file cannot be created or
/// its permissions cannot be set.
fn write_key_0600(path: &Path, key: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

            if !parent.exists() {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder
                    .create(parent)
                    .with_context(|| format!("creating private directory {}", parent.display()))?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).with_context(
                    || format!("setting private permissions on {}", parent.display()),
                )?;
            }
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    #[cfg(unix)]
    {
        let (parent_fd, name) = open_secure_secret_parent(path)?;
        let temporary_name = format!(
            ".{}.{}.tmp",
            name.to_string_lossy(),
            uuid::Uuid::new_v4().simple()
        );
        let fd = rustix::fs::openat(
            &parent_fd,
            &temporary_name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .with_context(|| format!("creating a temporary key beside {}", path.display()))?;
        let mut file = fs::File::from(fd);
        let result = (|| {
            std::io::Write::write_all(&mut file, key)
                .with_context(|| format!("writing temporary key for {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing temporary key for {}", path.display()))?;
            rustix::fs::renameat_with(
                &parent_fd,
                &temporary_name,
                &parent_fd,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .with_context(|| format!("installing {} without replacement", path.display()))?;
            rustix::fs::fsync(&parent_fd)
                .with_context(|| format!("syncing parent of {}", path.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&parent_fd, &temporary_name, rustix::fs::AtFlags::empty());
        }
        return result;
    }
    #[cfg(not(unix))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        std::io::Write::write_all(&mut file, key)
            .with_context(|| format!("writing {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    #[cfg(unix)]
    #[test]
    fn secret_owner_accepts_service_and_root_custody() {
        assert!(trusted_secret_owner_for(802, 802));
        assert!(trusted_secret_owner_for(0, 802));
        assert!(!trusted_secret_owner_for(803, 802));
    }

    #[cfg(unix)]
    #[test]
    fn systemd_credential_mode_exception_is_narrow() {
        let path = Path::new("/run/credentials/aos-hub.service/key");
        let previous = std::env::var_os("CREDENTIALS_DIRECTORY");
        std::env::set_var("CREDENTIALS_DIRECTORY", "/run/credentials/aos-hub.service");

        assert!(secret_file_mode_is_secure(path, 0o100400));
        assert!(secret_file_mode_is_secure(path, 0o100440));
        assert!(!secret_file_mode_is_secure(path, 0o100460));
        assert!(!secret_file_mode_is_secure(path, 0o100444));
        assert!(!secret_file_mode_is_secure(
            Path::new("/var/lib/aos-hub/key"),
            0o100440
        ));

        match previous {
            Some(value) => std::env::set_var("CREDENTIALS_DIRECTORY", value),
            None => std::env::remove_var("CREDENTIALS_DIRECTORY"),
        }
    }

    #[test]
    fn instance_sealer_creates_and_reloads_persistent_key() {
        let dir = private_tempdir();
        let root = dir.path();
        // No env override for this test.
        std::env::remove_var("AOS_HUB_SECRET_KEY_FILE");

        let first = instance_sealer(root).unwrap();
        let sealed = first.seal("persisted").unwrap();
        assert!(root.join("secret.key").exists());

        // A second sealer over the same root loads the same key and unseals.
        let second = instance_sealer(root).unwrap();
        assert_eq!(second.unseal(&sealed).unwrap(), "persisted");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(root.join("secret.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be 0600");
        }
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_rejects_symlinks_and_group_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = private_tempdir();
        let key = dir.path().join("key");
        fs::write(&key, [3_u8; KEY_LEN]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_secret_file(&key).is_err());

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("key-link");
        symlink(&key, &link).unwrap();
        assert!(read_secret_file(&link).is_err());
        assert_eq!(read_secret_file(&key).unwrap(), [3_u8; KEY_LEN]);
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_rejects_hard_links_and_writable_parents() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = private_tempdir();
        let key = dir.path().join("key");
        let hard_link = dir.path().join("key-hard-link");
        fs::write(&key, [5_u8; KEY_LEN]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&key, &hard_link).unwrap();
        assert!(read_secret_file(&key).is_err());

        fs::remove_file(&hard_link).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(read_secret_file(&key).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_accepts_traversable_non_writable_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = private_tempdir();
        let key = dir.path().join("key");
        fs::write(&key, [6_u8; KEY_LEN]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(read_secret_file(&key).unwrap(), [6_u8; KEY_LEN]);
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_rejects_a_symlinked_parent() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = private_tempdir();
        let private = dir.path().join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let key = private.join("key");
        fs::write(&key, [7_u8; KEY_LEN]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let linked_parent = dir.path().join("linked-parent");
        symlink(&private, &linked_parent).unwrap();
        assert!(read_secret_file(&linked_parent.join("key")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_rejects_oversized_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = private_tempdir();
        let secret = dir.path().join("oversized");
        fs::write(&secret, vec![0_u8; MAX_SECRET_FILE_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_secret_file(&secret).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_rejects_an_intermediate_symlink_component() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = private_tempdir();
        let private = dir.path().join("private");
        let nested = private.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        let key = nested.join("key");
        fs::write(&key, [13_u8; KEY_LEN]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

        let linked = dir.path().join("linked");
        symlink(&private, &linked).unwrap();
        assert!(read_secret_file(&linked.join("nested/key")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_key_creation_returns_the_single_persisted_key() {
        use std::sync::{Arc, Barrier};

        std::env::remove_var("AOS_HUB_SECRET_KEY_FILE");
        let dir = private_tempdir();
        let root = dir.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                load_or_create_key(&root)
            }));
        }
        let keys = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(read_secret_file(&root.join("secret.key")).unwrap(), keys[0]);
    }

    #[cfg(unix)]
    #[test]
    fn secret_reader_never_follows_a_racing_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        use std::sync::{Arc, Barrier};

        let dir = private_tempdir();
        let key = dir.path().join("key");
        let parked = dir.path().join("key.parked");
        let target = dir.path().join("attacker-target");
        fs::write(&key, [17_u8; KEY_LEN]).unwrap();
        fs::write(&target, [99_u8; KEY_LEN]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let attacker_barrier = Arc::clone(&barrier);
        let attacker_key = key.clone();
        let attacker_parked = parked.clone();
        let attacker_target = target.clone();
        let attacker = std::thread::spawn(move || {
            attacker_barrier.wait();
            for _ in 0..500 {
                if fs::rename(&attacker_key, &attacker_parked).is_ok() {
                    let _ = symlink(&attacker_target, &attacker_key);
                    let _ = fs::remove_file(&attacker_key);
                    let _ = fs::rename(&attacker_parked, &attacker_key);
                }
            }
        });
        barrier.wait();
        for _ in 0..500 {
            if let Ok(bytes) = read_secret_file(&key) {
                assert_eq!(bytes, [17_u8; KEY_LEN]);
            }
        }
        attacker.join().unwrap();
        if parked.exists() && !key.exists() {
            fs::rename(&parked, &key).unwrap();
        }
        assert_eq!(read_secret_file(&key).unwrap(), [17_u8; KEY_LEN]);
    }
}
