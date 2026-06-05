//! Security primitives: TOFU key management, commit signature verification,
//! and downgrade checking.
//!
//! This module provides reusable building blocks consumed by registry sync
//! (Phase 2) and the registry add command (Phase 6D).  It does not wire
//! any CLI commands itself.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
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
    /// Accepted on first use from a registry trust prompt.
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
        self.lookup_all(registry).into_iter().next()
    }

    /// Look up every trusted key for `registry`.
    ///
    /// A registry key file may contain multiple `registry:Ed25519:<base64>`
    /// lines during rotation overlap. Older single-line files still parse.
    pub fn lookup_all(&self, registry: &str) -> Vec<TrustedKey> {
        let mut keys = Vec::new();
        for (i, dir) in self.trusted_dirs.iter().enumerate() {
            let path = dir.join(format!("{registry}.pub"));
            if let Ok(content) = fs::read_to_string(&path) {
                for line in content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                {
                    let Ok((reg, algo, pubkey)) = parse_signing_key(line) else {
                        continue;
                    };
                    if reg != registry {
                        continue;
                    }
                    let source = if i == 0 {
                        KeySource::Tofu
                    } else {
                        KeySource::PreInstalled
                    };
                    keys.push(TrustedKey {
                        registry: reg,
                        algorithm: algo,
                        public_key: pubkey.clone(),
                        fingerprint: key_fingerprint(&pubkey),
                        source,
                    });
                }
            }
        }
        keys
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
        let new_line = format!("{}:{}:{}", key.registry, key.algorithm, key.public_key);
        let mut lines: Vec<String> = if path.exists() {
            fs::read_to_string(&path)
                .with_context(|| format!("reading trusted key file {}", path.display()))?
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .filter_map(|line| {
                    parse_signing_key(line)
                        .ok()
                        .map(|(registry, algorithm, public_key)| {
                            format!("{registry}:{algorithm}:{public_key}")
                        })
                })
                .collect()
        } else {
            Vec::new()
        };

        if !lines.iter().any(|line| line == &new_line) {
            lines.push(new_line);
        }
        let mut content = lines.join("\n");
        content.push('\n');

        fs::write(&path, &content)
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
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
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
pub fn verify_commit_signature(repo_path: &Path, commit: &str, expected_key: &str) -> Result<bool> {
    let (_reg, _algo, pubkey) = parse_signing_key(expected_key)?;

    // Build a temporary allowed-signers file.
    // Format: <principal> <key-type> <base64-key>
    let signers_content = format!("registry ssh-ed25519 {pubkey}\n");

    let mut signers_file =
        tempfile::NamedTempFile::new().context("creating temporary allowed-signers file")?;
    std::io::Write::write_all(&mut signers_file, signers_content.as_bytes())
        .context("writing temporary allowed-signers file")?;
    let signers_path = signers_file.path();

    // Configure git to use SSH signing verification with our signers file.
    let output = std::process::Command::new("git")
        .args([
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", signers_path.display()),
            "verify-commit",
            commit,
        ])
        .current_dir(repo_path)
        .output()
        .context("running git verify-commit")?;

    // signers_file is dropped here, which removes the temp file automatically.
    Ok(output.status.success())
}

/// Verify a git tag object's SSH signature against an expected Ed25519 key.
///
/// This mirrors [`verify_commit_signature`] but invokes `git verify-tag`.
/// Returns `Ok(true)` when the signature is valid, `Ok(false)` when it is
/// invalid or missing, and `Err` only for local execution/setup failures.
pub fn verify_tag_signature(repo_path: &Path, tag: &str, expected_key: &str) -> Result<bool> {
    let (_reg, _algo, pubkey) = parse_signing_key(expected_key)?;

    let signers_content = format!("registry ssh-ed25519 {pubkey}\n");

    let mut signers_file =
        tempfile::NamedTempFile::new().context("creating temporary allowed-signers file")?;
    std::io::Write::write_all(&mut signers_file, signers_content.as_bytes())
        .context("writing temporary allowed-signers file")?;
    let signers_path = signers_file.path();

    let output = std::process::Command::new("git")
        .args([
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", signers_path.display()),
            "verify-tag",
            tag,
        ])
        .current_dir(repo_path)
        .output()
        .context("running git verify-tag")?;

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
            format!("running git merge-base --is-ancestor {current_commit} {new_commit}")
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
            format!("running git merge-base --is-ancestor {new_commit} {current_commit}")
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
        bail!("malformed signing key: expected 'registry:algorithm:base64key', got '{key_str}'");
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
        bail!("unsupported signing algorithm '{algorithm}': only Ed25519 is supported");
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
    use aos_core::nar::cache::{
        NarCompression, NarInfoSigner, StaticNarInfoInput, render_static_narinfo,
    };
    use aos_core::nar::info;
    use std::process::Command;
    use tempfile::TempDir;

    // -- parse_signing_key --------------------------------------------------

    #[test]
    fn parse_signing_key_valid() {
        let (reg, algo, key) = parse_signing_key("aos-core:Ed25519:Xk9m2base64Qp4=").unwrap();
        assert_eq!(reg, "aos-core");
        assert_eq!(algo, "Ed25519");
        assert_eq!(key, "Xk9m2base64Qp4=");
    }

    #[test]
    fn parse_signing_key_invalid_algorithm() {
        let result = parse_signing_key("aos-core:RSA2048:AAAA");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported signing algorithm"), "got: {err}");
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

    #[test]
    fn same_ed25519_key_material_verifies_git_tag_and_narinfo_sig() {
        let registry = "registry";
        let seed = [7_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let raw_public_key = signing_key.verifying_key().to_bytes();
        let ssh_public_blob = ssh_ed25519_public_key_blob(&raw_public_key);
        let ssh_public_b64 = base64::engine::general_purpose::STANDARD.encode(&ssh_public_blob);
        let nix_public_b64 = base64::engine::general_purpose::STANDARD.encode(raw_public_key);

        let aos_trust_key = format!("{registry}:Ed25519:{ssh_public_b64}");
        let nix_trusted_public_key = format!("{registry}:{nix_public_b64}");
        let (parsed_registry, algorithm, parsed_ssh_public_b64) =
            parse_signing_key(&aos_trust_key).unwrap();
        assert_eq!(parsed_registry, registry);
        assert_eq!(algorithm, "Ed25519");
        assert_eq!(parsed_ssh_public_b64, ssh_public_b64);
        assert_ne!(parsed_ssh_public_b64, nix_public_b64);
        assert!(nix_trusted_public_key.starts_with("registry:"));

        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init"]);
        git(&repo, &["config", "user.name", registry]);
        git(&repo, &["config", "user.email", registry]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"registry\"\n",
        )
        .unwrap();
        git(&repo, &["add", "registry.toml"]);
        git(&repo, &["commit", "-m", "init"]);

        let private_key_path = temp.path().join("registry_signing_key");
        fs::write(
            &private_key_path,
            openssh_ed25519_private_key(&seed, &raw_public_key, registry),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        git(
            &repo,
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={}", private_key_path.display()),
                "tag",
                "-s",
                "1.0.0",
                "-m",
                "release 1.0.0",
            ],
        );
        assert!(verify_tag_signature(&repo, "1.0.0", &aos_trust_key).unwrap());

        let signer_secret_b64 = base64::engine::general_purpose::STANDARD.encode(seed);
        let signer =
            NarInfoSigner::from_key_content(&format!("{registry}:{signer_secret_b64}")).unwrap();
        let refs = vec!["/nix/store/ref111-libc".to_string()];
        let input = StaticNarInfoInput {
            store_path: "/nix/store/abc123-hello",
            nar_hash: "sha256:def456",
            nar_size: 42,
            references: &refs,
            deriver: None,
            signatures: &[],
            file_hash: "sha256:file789",
            file_size: 24,
            compression: NarCompression::Zstd,
        };
        let rendered = render_static_narinfo(&input, "/nix/store", Some(&signer));
        let parsed = info::parse(&rendered).unwrap();
        let (sig_name, sig_b64) = parsed.signatures[0].split_once(':').unwrap();
        assert_eq!(sig_name, registry);

        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();
        let signature = ed25519_dalek::Signature::try_from(signature_bytes.as_slice()).unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&raw_public_key).unwrap();
        let fingerprint = NarInfoSigner::fingerprint(
            &parsed.store_path,
            &parsed.nar_hash,
            parsed.nar_size as i64,
            &parsed.references,
        );
        use ed25519_dalek::Verifier as _;
        verifying_key
            .verify(fingerprint.as_bytes(), &signature)
            .unwrap();
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
    fn key_store_stores_multiple_rotation_keys() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("keys");
        let store = KeyStore::new(vec![dir]);

        for public_key in ["AAAAAAAAAA==", "BBBBBBBBBB=="] {
            store
                .store(&TrustedKey {
                    registry: "my-reg".into(),
                    algorithm: "Ed25519".into(),
                    public_key: public_key.into(),
                    fingerprint: key_fingerprint(public_key),
                    source: KeySource::Tofu,
                })
                .unwrap();
        }

        let keys = store.lookup_all("my-reg");
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|key| key.public_key == "AAAAAAAAAA=="));
        assert!(keys.iter().any(|key| key.public_key == "BBBBBBBBBB=="));
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

        let decision = tofu_check(&store, "aos-core", "aos-core:Ed25519:Xk9m2base64Qp4=").unwrap();
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
        let decision = tofu_check(&store, "aos-core", "aos-core:Ed25519:Xk9m2base64Qp4=").unwrap();
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
        fs::write(dir.join("aos-core.pub"), "aos-core:Ed25519:AAAAAAAAAA==\n").unwrap();

        let store = KeyStore::new(vec![dir]);
        let decision = tofu_check(&store, "aos-core", "aos-core:Ed25519:BBBBBBBBBB==").unwrap();
        match decision {
            TofuDecision::KeyMismatch { stored, received } => {
                assert_eq!(stored.public_key, "AAAAAAAAAA==");
                assert_eq!(received.public_key, "BBBBBBBBBB==");
            }
            other => panic!("expected KeyMismatch, got {other:?}"),
        }
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .unwrap_or_else(|err| panic!("running git {args:?}: {err}"));
        assert!(
            output.status.success(),
            "git {args:?} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn ssh_ed25519_public_key_blob(public_key: &[u8; 32]) -> Vec<u8> {
        let mut blob = Vec::new();
        push_ssh_string(&mut blob, b"ssh-ed25519");
        push_ssh_string(&mut blob, public_key);
        blob
    }

    fn openssh_ed25519_private_key(
        seed: &[u8; 32],
        public_key: &[u8; 32],
        comment: &str,
    ) -> String {
        let public_blob = ssh_ed25519_public_key_blob(public_key);
        let mut private_key = Vec::new();
        private_key.extend_from_slice(seed);
        private_key.extend_from_slice(public_key);

        let mut private = Vec::new();
        push_u32(&mut private, 0x1234_5678);
        push_u32(&mut private, 0x1234_5678);
        push_ssh_string(&mut private, b"ssh-ed25519");
        push_ssh_string(&mut private, public_key);
        push_ssh_string(&mut private, &private_key);
        push_ssh_string(&mut private, comment.as_bytes());
        for pad in 1..=(8 - private.len() % 8) {
            if private.len() % 8 == 0 {
                break;
            }
            private.push(pad as u8);
        }

        let mut blob = b"openssh-key-v1\0".to_vec();
        push_ssh_string(&mut blob, b"none");
        push_ssh_string(&mut blob, b"none");
        push_ssh_string(&mut blob, b"");
        push_u32(&mut blob, 1);
        push_ssh_string(&mut blob, &public_blob);
        push_ssh_string(&mut blob, &private);

        let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
        let mut out = "-----BEGIN OPENSSH PRIVATE KEY-----\n".to_string();
        for chunk in encoded.as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
        out
    }

    fn push_ssh_string(out: &mut Vec<u8>, value: &[u8]) {
        push_u32(out, value.len() as u32);
        out.extend_from_slice(value);
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }
}
