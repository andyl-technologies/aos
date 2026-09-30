//! Owns native instance resource receipts and bounded host-side dispatch.
//!
//! Receipts retain exact unit definitions before dispatch. A receipt never grants
//! authority over a foreign file or manager unit, even when its name matches.

mod credential;
mod identity;
mod listener;
mod packaged_unit;
mod unit;
mod watchdog;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use serde_json::Value;
use sha2::{Digest, Sha256};

const STATE_ROOT: &str = "/var/lib/aos/systemd-resources";

/// Executes or observes one admitted ancillary operation.
///
/// # Errors
/// Returns an error for invalid invocation values, unavailable host resources,
/// lost ownership, or failed convergence. Observation reports uncertain state.
pub(super) async fn execute(
    invocation: &Invocation,
    action: &str,
    creds: Option<&str>,
    shells: Option<(&str, &str)>,
) -> Result<Value> {
    ensure!(
        action == "observe" || (action == "apply") == (invocation.action == Action::Apply),
        "action differs from admitted invocation"
    );
    let identity = &invocation.effect.identity;
    ensure!(identity.len() >= 3, "effect identity has no operation");
    let ability = &identity[identity.len() - 3];
    let operation = &identity[identity.len() - 2];
    ensure!(
        invocation.revision.len() == 64
            && invocation
                .revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid effect revision"
    );

    private_directory(Path::new(STATE_ROOT))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(Path::new(STATE_ROOT).join(".lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;

    let result = match (ability.as_str(), operation.as_str()) {
        ("credential", "deliver") => credential::execute(invocation, action, creds),
        ("identity", "group" | "principal" | "membership") => {
            identity::execute(invocation, action, operation, shells)
        }
        ("listener", "claim") => listener::execute(invocation, action),
        ("packagedUnit", "ensure") => packaged_unit::execute(invocation, action).await,
        ("managerWatchdog", "ensure") => watchdog::execute(invocation, action).await,
        ("swap" | "mount" | "scheduledActivation", "ensure") => {
            unit::execute(invocation, action, ability).await
        }
        _ => bail!("unsupported ancillary operation"),
    };
    if action == "observe" && result.is_err() {
        return Ok(serde_json::json!({"status":"indeterminate"}));
    }
    result
}

fn key(id: &str) -> String {
    hex::encode(Sha256::digest(id.as_bytes()))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn normalized_path(value: &str) -> Result<&Path> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute()
            && !value.contains(['\0', '\n', '\r'])
            && !value.contains("//")
            && !value.ends_with('/'),
        "resource path must be normalized and absolute"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && !value.split('/').any(|part| part == "." || part == ".."),
        "resource path contains traversal"
    );
    Ok(path)
}

fn reject_symlink_ancestors(path: &Path) -> Result<()> {
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        match fs::symlink_metadata(directory) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "resource ancestor is not a real directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ancestor = directory.parent();
    }
    Ok(())
}

fn read_regular(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    reject_symlink_ancestors(path)?;
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("cannot open owned regular file"),
    };
    ensure!(file.metadata()?.is_file(), "resource is not a regular file");
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "resource exceeds byte limit");
    Ok(Some(bytes))
}

fn private_directory(path: &Path) -> Result<()> {
    reject_symlink_ancestors(path)?;
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.uid() == 0,
        "private state directory is not owned by root"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    reject_symlink_ancestors(path)?;
    let parent = path.parent().context("resource has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn state_path(invocation: &Invocation, kind: &str) -> std::path::PathBuf {
    Path::new(STATE_ROOT).join(format!("{}-{kind}.json", key(&invocation.id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_paths_reject_traversal_and_ambiguous_spellings() {
        for path in ["relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\nb"] {
            assert!(normalized_path(path).is_err(), "{path}");
        }
        assert!(normalized_path("/dev/mapper/cryptswap").is_ok());
    }

    #[test]
    fn receipts_do_not_follow_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        fs::write(&target, b"secret").unwrap();
        let link = temporary.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_regular(&link, 64).is_err());
    }
}
