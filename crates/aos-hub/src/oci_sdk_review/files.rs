//! Bounded private evidence custody, installed byte hashing and new outputs.

use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
    process::{Command, Stdio},
};

use anyhow::{ensure, Result};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::selection::ReviewedFile;

pub(super) const DOCUMENT_LIMIT: u64 = 64 * 1024;
const INSTALLED_LIMIT: u64 = 512 * 1024 * 1024;
const NAR_LIMIT: u64 = 16 * 1024 * 1024 * 1024;

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn private_bytes(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    crate::auth::seal::read_secret_file_zeroizing_capped(path, limit)
        .map_err(|_| anyhow::anyhow!("OCI review input custody, size or bytes changed"))
}

pub(super) fn selected_bytes(base: &Path, selected: &ReviewedFile) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = private_bytes(&base.join(&selected.path), DOCUMENT_LIMIT)?;
    ensure!(
        digest(&bytes) == selected.sha256,
        "OCI review selected bytes differ"
    );
    Ok(bytes)
}

pub(super) fn document<T: DeserializeOwned>(base: &Path, selected: &ReviewedFile) -> Result<T> {
    serde_json::from_slice(&selected_bytes(base, selected)?)
        .map_err(|_| anyhow::anyhow!("OCI review document is not a closed supported format"))
}

pub(super) fn hash_installed(path: &Path) -> Result<(String, u64)> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| anyhow::anyhow!("OCI installed file cannot be opened"))?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() > 0 && before.len() <= INSTALLED_LIMIT,
        "OCI installed file is not bounded regular input"
    );
    let (hash, size) = stream_hash(&mut file, INSTALLED_LIMIT)?;
    let after = file.metadata()?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && size == before.len(),
        "OCI installed bytes changed during observation"
    );
    Ok((hash, size))
}

pub(super) fn selected_installed(base: &Path, selected: &ReviewedFile) -> Result<u64> {
    let (hash, size) = hash_installed(&base.join(&selected.path))?;
    ensure!(
        hash == selected.sha256,
        "OCI installed file commitment differs"
    );
    Ok(size)
}

fn stream_hash(reader: &mut impl Read, maximum: u64) -> Result<(String, u64)> {
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .ok_or_else(|| anyhow::anyhow!("OCI installed byte count overflows"))?;
        ensure!(size <= maximum, "OCI installed input exceeds its bound");
        hash.update(&buffer[..count]);
    }
    Ok((hex::encode(hash.finalize()), size))
}

pub(super) fn nar_hash(nix: &Path, store: &Path, expected: &str) -> Result<()> {
    ensure!(
        store.parent() == Some(Path::new("/nix/store"))
            && store.file_name().is_some_and(|name| !name.is_empty())
            && aos_hub_core::direct_upload::valid_direct_digest(expected),
        "OCI immutable NAR selection differs"
    );
    let mut child = Command::new(nix)
        .args([
            "--extra-experimental-features",
            "nix-command",
            "store",
            "dump-path",
        ])
        .arg(store)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| anyhow::anyhow!("OCI NAR observer cannot start"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("OCI NAR observer has no output"))?;
        rustix::fs::fcntl_setfl(&stdout, rustix::fs::OFlags::NONBLOCK)?;
        let mut hash = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            ensure!(
                std::time::Instant::now() < deadline,
                "OCI NAR observer exceeded original deadline"
            );
            let count = match stdout.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(_) => anyhow::bail!("OCI NAR observer output failed"),
            };
            if count == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(count)?)
                .ok_or_else(|| anyhow::anyhow!("OCI NAR byte count overflows"))?;
            ensure!(size <= NAR_LIMIT, "OCI NAR exceeds its byte bound");
            hash.update(&buffer[..count]);
        }
        let hash = hex::encode(hash.finalize());
        ensure!(
            size > 0 && hash == expected,
            "OCI immutable NAR bytes differ"
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return result;
    }
    // EOF does not establish child completion. Keep the same deadline while
    // waiting for the selected observer to exit after its output has closed.
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("OCI NAR observer exceeded original deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    ensure!(status.success(), "OCI NAR observer failed");
    Ok(())
}

pub(super) fn public_key(bytes: &[u8]) -> Result<String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("OCI reviewer key malformed"))?;
    let public = text.strip_suffix('\n').unwrap_or(text);
    ensure!(
        aos_hub_core::direct_upload::valid_direct_digest(public),
        "OCI reviewer key malformed"
    );
    Ok(public.into())
}

// Open every ancestor without following links; a root sticky /tmp is allowed,
// while the final parent must be owner-private and is retained by descriptor.
fn output_parent(path: &Path) -> Result<(std::os::fd::OwnedFd, &std::ffi::OsStr)> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("OCI output has no filename"))?;
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOFOLLOW;
    let mut descriptor = rustix::fs::openat(
        rustix::fs::CWD,
        if parent.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        flags,
        rustix::fs::Mode::empty(),
    )?;
    let inspect = |fd: &std::os::fd::OwnedFd, final_parent: bool| -> Result<()> {
        let metadata = rustix::fs::fstat(fd)?;
        let mode = u32::from(metadata.st_mode);
        ensure!(
            (metadata.st_uid == 0 || metadata.st_uid == rustix::process::geteuid().as_raw())
                && if final_parent {
                    mode & 0o077 == 0
                } else {
                    mode & 0o022 == 0 || metadata.st_uid == 0 && mode & 0o1000 != 0
                },
            "OCI output ancestor custody differs"
        );
        Ok(())
    };
    inspect(&descriptor, false)?;
    for component in parent.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                descriptor =
                    rustix::fs::openat(&descriptor, part, flags, rustix::fs::Mode::empty())?;
                inspect(&descriptor, false)?;
            }
            _ => anyhow::bail!("OCI output path traversal differs"),
        }
    }
    inspect(&descriptor, true)?;
    Ok((descriptor, name))
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let (parent, name) = output_parent(path)?;
    let temporary = format!(".oci-review-{}.tmp", uuid::Uuid::new_v4().simple());
    let descriptor = rustix::fs::openat(
        &parent,
        &temporary,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    let mut file = File::from(descriptor);
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        rustix::fs::renameat_with(
            &parent,
            &temporary,
            &parent,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        rustix::fs::fsync(&parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&parent, &temporary, rustix::fs::AtFlags::empty());
    }
    result.map_err(|_: anyhow::Error| {
        anyhow::anyhow!("OCI output already exists or custody/write failed")
    })
}
