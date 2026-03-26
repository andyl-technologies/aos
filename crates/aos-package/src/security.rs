//! Security primitives: TOFU key management, commit signature verification,
//! and downgrade checking.
//!
//! This module provides reusable building blocks consumed by registry sync
//! (Phase 2) and the registry add command (Phase 6D).  It does not wire
//! any CLI commands itself.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Where a trusted key came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Shipped in `/etc/apm/trusted-keys.d/` or pre-provisioned by an admin.
    PreInstalled,
    /// Accepted on first use from a registry's `signing.public_key` field.
    Tofu,
}

/// A trusted signing key for a registry.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// Registry name this key belongs to (e.g. `"aos-core"`).
    pub registry: String,
    /// Algorithm identifier — currently only `"Ed25519"`.
    pub algorithm: String,
    /// Base64-encoded public key bytes.
    pub public_key: String,
    /// Short display fingerprint (first 8 hex chars of SHA-256 of key bytes).
    pub fingerprint: String,
    /// How this key was obtained.
    pub source: KeySource,
}

// ---------------------------------------------------------------------------
// Key store
// ---------------------------------------------------------------------------

/// Manages trusted signing keys stored on disk.
///
/// Keys are looked up from multiple directories in order.  The first
/// directory is considered writable (for TOFU persistence); the rest are
/// read-only (pre-installed keys).
pub struct KeyStore {
    trusted_dirs: Vec<PathBuf>,
}

impl KeyStore {
    /// Create a key store backed by the given directories.
    ///
    /// The first entry in `trusted_dirs` is the writable store where
    /// TOFU-accepted keys are persisted.  Subsequent entries are searched
    /// in order for pre-installed keys.
    pub fn new(trusted_dirs: Vec<PathBuf>) -> Self {
        Self { trusted_dirs }
    }

    /// Look up a trusted key for `registry`.
    ///
    /// Searches all `trusted_dirs` for a file named `{registry}.pub`.
    /// Returns `None` if no key file is found.
    pub fn lookup(&self, registry: &str) -> Option<TrustedKey> {
        for (i, dir) in self.trusted_dirs.iter().enumerate() {
            let path = dir.join(format!("{registry}.pub"));
            if let Ok(content) = fs::read_to_string(&path) {
                let line = content.trim();
                if let Ok((reg, algo, pubkey)) = parse_signing_key(line) {
                    let source = if i == 0 {
                        KeySource::Tofu
                    } else {
                        KeySource::PreInstalled
                    };
                    return Some(TrustedKey {
                        registry: reg,
                        algorithm: algo,
                        public_key: pubkey.clone(),
                        fingerprint: key_fingerprint(&pubkey),
                        source,
                    });
                }
            }
        }
        None
    }

    /// Persist a trusted key to the first (writable) directory.
    ///
    /// Creates the directory if it does not exist.
    pub fn store(&self, key: &TrustedKey) -> Result<()> {
        let dir = self
            .trusted_dirs
            .first()
            .ok_or_else(|| anyhow::anyhow!("no trusted key directories configured"))?;

        fs::create_dir_all(dir)
            .with_context(|| format!("creating trusted keys directory {}", dir.display()))?;

        let path = dir.join(format!("{}.pub", key.registry));
        let line = format!("{}:{}:{}\n", key.registry, key.algorithm, key.public_key);

        fs::write(&path, &line)
            .with_context(|| format!("writing trusted key to {}", path.display()))?;

        Ok(())
    }

    /// Remove a trusted key for `registry`.
    ///
    /// Searches all writable directories (index 0) and read-only
    /// directories for the key file.  Returns `true` if a file was
    /// found and removed; `false` otherwise.
    pub fn remove(&self, registry: &str) -> Result<bool> {
        for dir in &self.trusted_dirs {
            let path = dir.join(format!("{registry}.pub"));
            if path.exists() {
                fs::remove_file(&path)
                    .with_context(|| format!("removing {}", path.display()))?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// TOFU decision
// ---------------------------------------------------------------------------

/// Outcome of a Trust-On-First-Use check.
#[derive(Debug)]
pub enum TofuDecision {
    /// The received key matches a key we already trust.
    AlreadyTrusted(TrustedKey),
    /// No key is on file — the caller should prompt the user.
    NewKey {
        key: TrustedKey,
        needs_confirmation: bool,
    },
    /// A different key is already trusted for this registry.
    KeyMismatch {
        stored: TrustedKey,
        received: TrustedKey,
    },
}

/// Perform a Trust-On-First-Use check.
///
/// 1. Parse the `received_key` string (`registry:algorithm:base64key`).
/// 2. Look up any existing key in `key_store`.
/// 3. Return the appropriate [`TofuDecision`].
pub fn tofu_check(
    key_store: &KeyStore,
    registry: &str,
    received_key: &str,
) -> Result<TofuDecision> {
    let (reg, algo, pubkey) = parse_signing_key(received_key)?;

    let received = TrustedKey {
        registry: reg.clone(),
        algorithm: algo,
        public_key: pubkey.clone(),
        fingerprint: key_fingerprint(&pubkey),
        source: KeySource::Tofu,
    };

    match key_store.lookup(registry) {
        None => Ok(TofuDecision::NewKey {
            key: received,
            needs_confirmation: true,
        }),
        Some(existing) if existing.public_key == received.public_key => {
            Ok(TofuDecision::AlreadyTrusted(existing))
        }
        Some(existing) => Ok(TofuDecision::KeyMismatch {
            stored: existing,
            received,
        }),
    }
}

// ---------------------------------------------------------------------------
// Commit signature verification
// ---------------------------------------------------------------------------

/// Verify a git commit's SSH signature against an expected Ed25519 public key.
///
/// Creates a temporary `allowed_signers` file and invokes
/// `git verify-commit`.  Returns `Ok(true)` if the signature is valid,
/// `Ok(false)` if the signature is invalid or missing, and `Err` if
/// the git command itself could not be executed.
pub fn verify_commit_signature(
    repo_path: &Path,
    commit: &str,
    expected_key: &str,
) -> Result<bool> {
    let (_reg, _algo, pubkey) = parse_signing_key(expected_key)?;

    // Build a temporary allowed-signers file.
    // Format: <principal> <key-type> <base64-key>
    let signers_content = format!("registry ssh-ed25519 {pubkey}\n");

    let tmp_dir = std::env::temp_dir();
    let signers_path = tmp_dir.join(format!("apm-signers-{}", std::process::id()));
    fs::write(&signers_path, &signers_content)
        .context("writing temporary allowed-signers file")?;

    // Configure git to use SSH signing verification with our signers file.
    let output = std::process::Command::new("git")
        .args([
            "-c",
            &format!(
                "gpg.ssh.allowedSignersFile={}",
                signers_path.display()
            ),
            "verify-commit",
            commit,
        ])
        .current_dir(repo_path)
        .output()
        .context("running git verify-commit")?;

    // Clean up the temporary file (best-effort).
    let _ = fs::remove_file(&signers_path);

    Ok(output.status.success())
}

// ---------------------------------------------------------------------------
// Downgrade check
// ---------------------------------------------------------------------------

/// Relationship between two git commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowngradeStatus {
    /// `new` is a descendant of `current` — safe to advance.
    FastForward,
    /// Both SHAs are identical — nothing changed.
    SameCommit,
    /// `new` is an ancestor of `current` — a downgrade, reject.
    Downgrade,
    /// Neither commit is an ancestor of the other (force-push or branch switch).
    Diverged,
}

/// Check the relationship between `current_commit` and `new_commit`.
///
/// Uses `git merge-base --is-ancestor` to determine whether the
/// transition is a fast-forward, downgrade, divergence, or no-op.
pub fn check_downgrade(
    current_commit: &str,
    new_commit: &str,
    repo_path: &Path,
) -> Result<DowngradeStatus> {
    if current_commit == new_commit {
        return Ok(DowngradeStatus::SameCommit);
    }

    // Is current an ancestor of new? (fast-forward)
    let ff = std::process::Command::new("git")
        .args(["merge-base", "--is-ancestor", current_commit, new_commit])
        .current_dir(repo_path)
        .output()
        .with_context(|| {
            format!(
                "running git merge-base --is-ancestor {current_commit} {new_commit}"
            )
        })?;

    if ff.status.success() {
        return Ok(DowngradeStatus::FastForward);
    }

    // Is new an ancestor of current? (downgrade)
    let dg = std::process::Command::new("git")
        .args(["merge-base", "--is-ancestor", new_commit, current_commit])
        .current_dir(repo_path)
        .output()
        .with_context(|| {
            format!(
                "running git merge-base --is-ancestor {new_commit} {current_commit}"
            )
        })?;

    if dg.status.success() {
        return Ok(DowngradeStatus::Downgrade);
    }

    Ok(DowngradeStatus::Diverged)
}

// ---------------------------------------------------------------------------
// Key parsing / fingerprinting
// ---------------------------------------------------------------------------

/// Parse a signing key string in `registry:algorithm:base64key` format.
///
/// Returns `(registry, algorithm, public_key)`.
/// Rejects any algorithm other than `"Ed25519"`.
pub fn parse_signing_key(key_str: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = key_str.splitn(3, ':').collect();
    if parts.len() != 3 {
        bail!(
            "malformed signing key: expected 'registry:algorithm:base64key', got '{key_str}'"
        );
    }

    let registry = parts[0].to_string();
    let algorithm = parts[1].to_string();
    let public_key = parts[2].to_string();

    if registry.is_empty() {
        bail!("malformed signing key: registry name is empty");
    }
    if public_key.is_empty() {
        bail!("malformed signing key: public key is empty");
    }
    if algorithm != "Ed25519" {
        bail!(
            "unsupported signing algorithm '{algorithm}': only Ed25519 is supported"
        );
    }

    Ok((registry, algorithm, public_key))
}

/// Compute a short fingerprint from a base64-encoded public key.
///
/// Returns the first 8 hexadecimal characters of the SHA-256 hash of
/// the decoded key bytes.  If the key cannot be decoded, the hash is
/// computed over the raw base64 string instead.
pub fn key_fingerprint(public_key: &str) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine
        .decode(public_key)
        .unwrap_or_else(|_| public_key.as_bytes().to_vec());

    let hash = Sha256::digest(&bytes);
    let full_hex = hex::encode(hash);
    full_hex[..8].to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -- parse_signing_key --------------------------------------------------

    #[test]
    fn parse_signing_key_valid() {
        let (reg, algo, key) =
            parse_signing_key("aos-core:Ed25519:Xk9m2base64Qp4=").unwrap();
        assert_eq!(reg, "aos-core");
        assert_eq!(algo, "Ed25519");
        assert_eq!(key, "Xk9m2base64Qp4=");
    }

    #[test]
    fn parse_signing_key_invalid_algorithm() {
        let result = parse_signing_key("aos-core:RSA2048:AAAA");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unsupported signing algorithm"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_signing_key_malformed() {
        // Too few colons.
        assert!(parse_signing_key("aos-core:Ed25519").is_err());
        // No colons at all.
        assert!(parse_signing_key("justonestring").is_err());
        // Empty string.
        assert!(parse_signing_key("").is_err());
    }

    // -- key_fingerprint ----------------------------------------------------

    #[test]
    fn key_fingerprint_deterministic() {
        let fp1 = key_fingerprint("Xk9m2base64Qp4=");
        let fp2 = key_fingerprint("Xk9m2base64Qp4=");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 8);
    }

    #[test]
    fn key_fingerprint_different_keys() {
        let fp1 = key_fingerprint("AAAAAAAAAA==");
        let fp2 = key_fingerprint("BBBBBBBBBB==");
        assert_ne!(fp1, fp2);
    }

    // -- KeyStore -----------------------------------------------------------

    #[test]
    fn key_store_lookup_found() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("aos-core.pub"),
            "aos-core:Ed25519:Xk9m2base64Qp4=\n",
        )
        .unwrap();

        let store = KeyStore::new(vec![dir]);
        let key = store.lookup("aos-core").expect("key should be found");
        assert_eq!(key.registry, "aos-core");
        assert_eq!(key.algorithm, "Ed25519");
        assert_eq!(key.public_key, "Xk9m2base64Qp4=");
    }

    #[test]
    fn key_store_lookup_not_found() {
        let tmp = TempDir::new().unwrap();
        let store = KeyStore::new(vec![tmp.path().to_path_buf()]);
        assert!(store.lookup("nonexistent").is_none());
    }

    #[test]
    fn key_store_store_and_lookup() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");
        let store = KeyStore::new(vec![dir.clone()]);

        let key = TrustedKey {
            registry: "my-reg".into(),
            algorithm: "Ed25519".into(),
            public_key: "AAAAAAAAAA==".into(),
            fingerprint: key_fingerprint("AAAAAAAAAA=="),
            source: KeySource::Tofu,
        };

        store.store(&key).unwrap();

        // The key should now be discoverable.
        let found = store.lookup("my-reg").expect("key should be found");
        assert_eq!(found.registry, "my-reg");
        assert_eq!(found.public_key, "AAAAAAAAAA==");
    }

    #[test]
    fn key_store_remove() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("aos-core.pub"),
            "aos-core:Ed25519:Xk9m2base64Qp4=\n",
        )
        .unwrap();

        let store = KeyStore::new(vec![dir]);
        assert!(store.remove("aos-core").unwrap());
        assert!(store.lookup("aos-core").is_none());
        // Removing again should return false.
        assert!(!store.remove("aos-core").unwrap());
    }

    // -- tofu_check ---------------------------------------------------------

    #[test]
    fn tofu_new_key() {
        let tmp = TempDir::new().unwrap();
        let store = KeyStore::new(vec![tmp.path().to_path_buf()]);

        let decision =
            tofu_check(&store, "aos-core", "aos-core:Ed25519:Xk9m2base64Qp4=")
                .unwrap();
        match decision {
            TofuDecision::NewKey {
                key,
                needs_confirmation,
            } => {
                assert!(needs_confirmation);
                assert_eq!(key.registry, "aos-core");
                assert_eq!(key.public_key, "Xk9m2base64Qp4=");
            }
            other => panic!("expected NewKey, got {other:?}"),
        }
    }

    #[test]
    fn tofu_already_trusted() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("aos-core.pub"),
            "aos-core:Ed25519:Xk9m2base64Qp4=\n",
        )
        .unwrap();

        let store = KeyStore::new(vec![dir]);
        let decision =
            tofu_check(&store, "aos-core", "aos-core:Ed25519:Xk9m2base64Qp4=")
                .unwrap();
        match decision {
            TofuDecision::AlreadyTrusted(key) => {
                assert_eq!(key.registry, "aos-core");
                assert_eq!(key.public_key, "Xk9m2base64Qp4=");
            }
            other => panic!("expected AlreadyTrusted, got {other:?}"),
        }
    }

    #[test]
    fn tofu_key_mismatch() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("aos-core.pub"),
            "aos-core:Ed25519:AAAAAAAAAA==\n",
        )
        .unwrap();

        let store = KeyStore::new(vec![dir]);
        let decision =
            tofu_check(&store, "aos-core", "aos-core:Ed25519:BBBBBBBBBB==")
                .unwrap();
        match decision {
            TofuDecision::KeyMismatch { stored, received } => {
                assert_eq!(stored.public_key, "AAAAAAAAAA==");
                assert_eq!(received.public_key, "BBBBBBBBBB==");
            }
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }
}
