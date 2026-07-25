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
//! next, and the CLI subcommands that seal (`idp set`, `hosted-key create`) use
//! the same [`instance_sealer`] as `serve` so values round-trip.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rand::Rng as _;

pub use aos_hub_core::auth::seal::{
    dev_sealer, parse_key, AesGcmSealer, SecretSealer, XorSealer, KEY_LEN,
};

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
        let raw = fs::read(path)
            .with_context(|| format!("reading AOS_HUB_SECRET_KEY_FILE at {}", path.display()))?;
        return parse_key(&raw)
            .with_context(|| format!("parsing instance key at {}", path.display()));
    }

    let path = root.join("secret.key");
    if path.exists() {
        let raw = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        parse_key(&raw).with_context(|| format!("parsing instance key at {}", path.display()))
    } else {
        let key: [u8; KEY_LEN] = rand::rng().random();
        write_key_0600(&path, &key)?;
        Ok(key.to_vec())
    }
}

/// Writes `key` to `path` with `0600` permissions, creating parent dirs.
///
/// # Errors
///
/// Returns an error if the parent directory or the file cannot be created or
/// its permissions cannot be set.
fn write_key_0600(path: &Path, key: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    fs::write(path, key).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_sealer_creates_and_reloads_persistent_key() {
        let dir = tempfile::tempdir().unwrap();
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
}
