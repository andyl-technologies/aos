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
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

use crate::registry::repo;

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

impl TrustedKey {
    /// Render the key in its canonical `registry:algorithm:base64key` line
    /// form, as stored in `trusted-keys.d` files and accepted by
    /// [`parse_signing_key`].
    pub fn key_line(&self) -> String {
        format!("{}:{}:{}", self.registry, self.algorithm, self.public_key)
    }
}

/// Prefix marking a revoked-key exclusion line in a `trusted-keys.d` file.
///
/// A writable trusted-keys file may contain comment lines of the form
/// `# revoked: registry:Ed25519:<base64>`. Keys listed this way are
/// filtered out of [`KeyStore::lookup_all`] results even when the same key
/// is still present in a read-only anchor directory (e.g. baked into the
/// image under `/etc/apm/trusted-keys.d`).
const REVOKED_LINE_PREFIX: &str = "# revoked:";

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
    ///
    /// Keys named on `# revoked:` exclusion lines (in any scanned file; in
    /// practice only the writable store contains them) are filtered from
    /// the entire result, masking revoked keys that still appear in
    /// read-only anchor directories. A key found in several directories is
    /// returned once, with the earliest directory determining its
    /// [`KeySource`].
    pub fn lookup_all(&self, registry: &str) -> Vec<TrustedKey> {
        let mut keys = Vec::new();
        let mut revoked: Vec<String> = Vec::new();
        for (i, dir) in self.trusted_dirs.iter().enumerate() {
            let path = dir.join(format!("{registry}.pub"));
            if let Ok(content) = fs::read_to_string(&path) {
                for line in content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                {
                    if let Some(excluded) = parse_revoked_line(line) {
                        revoked.push(excluded);
                        continue;
                    }
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
        keys.retain(|key| !revoked.contains(&key.key_line()));
        let mut seen: Vec<String> = Vec::new();
        keys.retain(|key| {
            let line = key.key_line();
            if seen.contains(&line) {
                false
            } else {
                seen.push(line);
                true
            }
        });
        keys
    }

    /// Returns the fingerprints explicitly masked as revoked for `registry`.
    pub fn revoked_fingerprints(&self, registry: &str) -> Vec<String> {
        let mut fingerprints = Vec::new();
        for dir in &self.trusted_dirs {
            let path = dir.join(format!("{registry}.pub"));
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines().map(str::trim) {
                    let Some(key_line) = parse_revoked_line(line) else {
                        continue;
                    };
                    let Ok((key_registry, _, public_key)) = parse_signing_key(&key_line) else {
                        continue;
                    };
                    if key_registry == registry {
                        let fingerprint = key_fingerprint(&public_key);
                        if !fingerprints.contains(&fingerprint) {
                            fingerprints.push(fingerprint);
                        }
                    }
                }
            }
        }
        fingerprints
    }

    /// Persist a trusted key to the first (writable) directory.
    ///
    /// Creates the directory if it does not exist. `# revoked:` exclusion
    /// lines already present in the file are preserved — except an
    /// exclusion naming the key being pinned, which is dropped (explicitly
    /// pinning a key un-revokes it).
    ///
    /// # Errors
    ///
    /// Returns an error when no writable directory is configured, or the
    /// directory or key file cannot be created, read, or written.
    pub fn store(&self, key: &TrustedKey) -> Result<()> {
        let dir = self
            .trusted_dirs
            .first()
            .ok_or_else(|| anyhow::anyhow!("no trusted key directories configured"))?;

        fs::create_dir_all(dir)
            .with_context(|| format!("creating trusted keys directory {}", dir.display()))?;

        let path = dir.join(format!("{}.pub", key.registry));
        let new_line = key.key_line();
        let mut lines: Vec<String> = if path.exists() {
            fs::read_to_string(&path)
                .with_context(|| format!("reading trusted key file {}", path.display()))?
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .filter_map(|line| {
                    if let Some(excluded) = parse_revoked_line(line) {
                        if excluded == new_line {
                            return None;
                        }
                        return Some(format!("{REVOKED_LINE_PREFIX} {excluded}"));
                    }
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

    /// Synchronize the writable store for `registry` with a roster's active
    /// key set.
    ///
    /// Performs one atomic rewrite of the writable
    /// `trusted-keys.d/<registry>.pub` file so that it contains exactly:
    ///
    /// - one key line per entry of `active`, and
    /// - one `# revoked:` exclusion line for every key visible in a
    ///   read-only directory that is *not* in `active`, masking revoked
    ///   keys baked into image anchors.
    ///
    /// Keys previously pinned in the writable file but absent from
    /// `active` are removed; exclusion lines for keys that re-entered
    /// `active` are dropped. Read-only directories are never modified.
    ///
    /// # Errors
    ///
    /// Returns an error when no writable directory is configured or the
    /// file cannot be read or written.
    pub fn sync_registry_keys(
        &self,
        registry: &str,
        active: &[TrustedKey],
    ) -> Result<KeySyncReport> {
        let dir = self
            .trusted_dirs
            .first()
            .ok_or_else(|| anyhow::anyhow!("no trusted key directories configured"))?;

        let active_lines: Vec<String> = active.iter().map(TrustedKey::key_line).collect();

        // Keys previously pinned or masked in the writable file.
        let path = dir.join(format!("{registry}.pub"));
        let mut previously_pinned: Vec<String> = Vec::new();
        let mut previously_masked: Vec<String> = Vec::new();
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                if let Some(excluded) = parse_revoked_line(line) {
                    if !previously_masked.contains(&excluded) {
                        previously_masked.push(excluded);
                    }
                    continue;
                }
                if let Ok((reg, algo, pubkey)) = parse_signing_key(line)
                    && reg == registry
                {
                    previously_pinned.push(format!("{reg}:{algo}:{pubkey}"));
                }
            }
        }

        // Keys visible in read-only directories that are no longer active
        // must be masked with an exclusion line.
        let mut masked: Vec<String> = Vec::new();
        for dir in self.trusted_dirs.iter().skip(1) {
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
                    let key_line = format!("{reg}:{algo}:{pubkey}");
                    if !active_lines.contains(&key_line) && !masked.contains(&key_line) {
                        masked.push(key_line);
                    }
                }
            }
        }

        let pinned = active_lines
            .iter()
            .filter(|line| !previously_pinned.contains(line))
            .count();
        let unpinned = previously_pinned
            .iter()
            .filter(|line| !active_lines.contains(line))
            .count();
        let newly_masked = masked
            .iter()
            .filter(|line| !previously_masked.contains(line))
            .count();

        let mut lines = active_lines;
        for excluded in &masked {
            lines.push(format!("{REVOKED_LINE_PREFIX} {excluded}"));
        }
        let mut content = lines.join("\n");
        content.push('\n');

        fs::create_dir_all(dir)
            .with_context(|| format!("creating trusted keys directory {}", dir.display()))?;
        fs::write(&path, &content)
            .with_context(|| format!("writing trusted keys to {}", path.display()))?;

        Ok(KeySyncReport {
            pinned,
            unpinned,
            masked: newly_masked,
        })
    }

    /// Remove trusted keys for `registry` from the effective trust set.
    ///
    /// Deletes keys from the writable directory (index 0). Keys that remain
    /// visible from read-only anchor directories are masked by writing
    /// `# revoked:` exclusion lines into the writable directory, leaving the
    /// anchor files untouched.
    ///
    /// # Errors
    ///
    /// Returns an error if the writable trust file cannot be removed or
    /// rewritten, or if an existing anchor file cannot be read.
    pub fn remove(&self, registry: &str) -> Result<bool> {
        let Some(dir) = self.trusted_dirs.first() else {
            return Ok(false);
        };

        let had_effective_keys = !self.lookup_all(registry).is_empty();
        let path = dir.join(format!("{registry}.pub"));
        let mut anchored = Vec::new();
        for anchor_dir in self.trusted_dirs.iter().skip(1) {
            for line in
                trusted_key_lines_from_file(&anchor_dir.join(format!("{registry}.pub")), registry)?
            {
                if !anchored.contains(&line) {
                    anchored.push(line);
                }
            }
        }

        if anchored.is_empty() {
            if path.exists() {
                fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            }
            return Ok(had_effective_keys);
        }

        fs::create_dir_all(dir)
            .with_context(|| format!("creating trusted keys directory {}", dir.display()))?;
        let mut content = anchored
            .iter()
            .map(|line| format!("{REVOKED_LINE_PREFIX} {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        content.push('\n');
        fs::write(&path, &content)
            .with_context(|| format!("writing trusted keys to {}", path.display()))?;

        Ok(had_effective_keys)
    }
}

/// Read canonical trusted-key lines for `registry` from `path`.
fn trusted_key_lines_from_file(path: &Path, registry: &str) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut lines = Vec::new();
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
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
        let key_line = format!("{reg}:{algo}:{pubkey}");
        if !lines.contains(&key_line) {
            lines.push(key_line);
        }
    }
    Ok(lines)
}

/// Summary of a [`KeyStore::sync_registry_keys`] rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySyncReport {
    /// Keys newly written to the writable store.
    pub pinned: usize,
    /// Previously pinned keys removed from the writable store.
    pub unpinned: usize,
    /// Read-only anchor keys newly masked with `# revoked:` exclusion lines.
    pub masked: usize,
}

impl KeySyncReport {
    /// `true` when the rewrite changed nothing observable.
    pub fn is_noop(&self) -> bool {
        self.pinned == 0 && self.unpinned == 0 && self.masked == 0
    }
}

/// Parse a `# revoked: <key>` exclusion line.
///
/// Returns the canonical key line when `line` is a well-formed exclusion
/// (the embedded key must itself parse via [`parse_signing_key`]), and
/// `None` otherwise. Other comment lines are not exclusions.
fn parse_revoked_line(line: &str) -> Option<String> {
    let rest = line.strip_prefix(REVOKED_LINE_PREFIX)?.trim();
    let (registry, algorithm, public_key) = parse_signing_key(rest).ok()?;
    Some(format!("{registry}:{algorithm}:{public_key}"))
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
        /// The received key, ready to persist once the user accepts it.
        key: TrustedKey,
        /// Whether the caller must obtain confirmation before trusting.
        needs_confirmation: bool,
    },
    /// A different key is already trusted for this registry.
    KeyMismatch {
        /// The key currently on file.
        stored: TrustedKey,
        /// The conflicting key received from the registry.
        received: TrustedKey,
    },
}

/// Perform a Trust-On-First-Use check.
///
/// 1. Parse the `received_key` string (`registry:algorithm:base64key`).
/// 2. Look up any existing key in `key_store`.
/// 3. Return the appropriate [`TofuDecision`].
///
/// # Errors
///
/// Returns an error if `received_key` is malformed or uses an algorithm
/// other than Ed25519 (see [`parse_signing_key`]).
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

/// Parse a `registry:Ed25519:<base64>` trust line into an OpenSSH public key.
///
/// The base64 field is the same key blob that follows `ssh-ed25519 ` in an
/// `authorized_keys` line, so we reconstruct that one-line form and let
/// `ssh-key` decode it.
///
/// # Errors
///
/// Returns an error when the trust line is malformed or the key blob is not a
/// valid OpenSSH ed25519 public key.
fn trusted_ssh_public_key(trusted_key: &str) -> Result<PublicKey> {
    let (_registry, _algorithm, public_key) = parse_signing_key(trusted_key)?;
    PublicKey::from_openssh(&format!("ssh-ed25519 {public_key}"))
        .with_context(|| "parsing trusted ssh-ed25519 public key")
}

/// Verify an armored SSHSIG over `message` in `namespace` against any key in
/// `trusted_keys`.
///
/// An empty key set is a hard error: verification against nothing must never
/// pass. A malformed or non-matching signature returns `Ok(false)`.
fn verify_sshsig_any(
    signature_pem: &[u8],
    message: &[u8],
    namespace: &str,
    trusted_keys: &[String],
) -> Result<bool> {
    if trusted_keys.is_empty() {
        bail!("empty trusted key set; refusing to verify signatures against no keys");
    }
    let Ok(signature) = SshSig::from_pem(signature_pem) else {
        return Ok(false);
    };
    for key in trusted_keys {
        let public_key = trusted_ssh_public_key(key)?;
        if public_key.verify(namespace, message, &signature).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Verify a git commit's SSH signature against a set of trusted Ed25519
/// keys.
///
/// Extracts the commit's `gpgsig` SSH signature and the exact signed payload
/// (the commit object with the signature header removed) via libgit2, then
/// checks it in the `git` SSHSIG namespace against each key (in
/// `registry:Ed25519:<base64>` form). Returns `Ok(true)` when the signature
/// matches *any* trusted key, `Ok(false)` when it is invalid or missing.
///
/// # Errors
///
/// Returns an error when `trusted_keys` is empty, a key fails to parse, or the
/// commit cannot be read.
pub fn verify_commit_signature(
    repo_path: &Path,
    commit: &str,
    trusted_keys: &[String],
) -> Result<bool> {
    let Some((signature, signed)) = repo::commit_signature(repo_path, commit)? else {
        return Ok(false);
    };
    verify_sshsig_any(&signature, &signed, "git", trusted_keys)
}

/// Verify a git tag object's SSH signature against a set of trusted Ed25519
/// keys.
///
/// Mirrors [`verify_commit_signature`] for annotated tags: the signed payload
/// is the tag object up to its appended SSH signature block.
///
/// # Errors
///
/// Returns an error when `trusted_keys` is empty, a key fails to parse, or the
/// tag cannot be read.
pub fn verify_tag_signature(repo_path: &Path, tag: &str, trusted_keys: &[String]) -> Result<bool> {
    let Some((signature, signed)) = repo::tag_signature(repo_path, tag)? else {
        return Ok(false);
    };
    verify_sshsig_any(&signature, &signed, "git", trusted_keys)
}

/// Read an unencrypted OpenSSH private key, tolerating surrounding whitespace
/// the way `ssh-keygen` does.
///
/// # Errors
///
/// Returns an error when the file cannot be read or does not contain an
/// unencrypted OpenSSH private key.
fn read_openssh_private_key(key_path: &Path) -> Result<PrivateKey> {
    let contents = fs::read_to_string(key_path)
        .with_context(|| format!("reading signing key {}", key_path.display()))?;
    PrivateKey::from_openssh(contents.trim())
        .with_context(|| format!("reading signing key {}", key_path.display()))
}

/// Derive the base64 SSH wire-format public key of an OpenSSH Ed25519 private
/// key — the `<base64>` field of a `ssh-ed25519 <base64>` line, which is the
/// material a `registry:Ed25519:<base64>` trust line carries.
///
/// # Errors
///
/// Returns an error when the key cannot be read, is not Ed25519, or cannot be
/// encoded.
pub fn public_ed25519_blob(key_path: &Path) -> Result<String> {
    let key = read_openssh_private_key(key_path)?;
    let public = key.public_key();
    if public.algorithm() != ssh_key::Algorithm::Ed25519 {
        anyhow::bail!("unsupported signing key type; registry keys must be Ed25519");
    }
    let openssh = public.to_openssh().context("encoding public key")?;
    openssh
        .split_whitespace()
        .nth(1)
        .map(ToString::to_string)
        .context("public key has no key material")
}

/// Sign an arbitrary payload with an OpenSSH Ed25519 private key.
///
/// Produces an armored SSHSIG over `payload` in `namespace` — the same
/// OpenSSH format (`-----BEGIN SSH SIGNATURE-----`) that `ssh-keygen -Y sign`
/// emits and that the verification helpers above accept.
///
/// # Errors
///
/// Returns an error when the private key cannot be read, is not an unencrypted
/// OpenSSH key, or signing fails.
pub fn sign_payload_signature(key_path: &Path, namespace: &str, payload: &[u8]) -> Result<String> {
    let key = read_openssh_private_key(key_path)?;
    let signature = key
        .sign(namespace, HashAlg::Sha512, payload)
        .context("creating SSH signature")?;
    signature
        .to_pem(LineEnding::LF)
        .context("encoding SSH signature")
}

/// Verify an OpenSSH detached signature over an arbitrary payload.
///
/// `trusted_key` uses the `registry:Ed25519:<base64>` trust-line format.
/// Verification succeeds only when `signature` validates over `payload` in
/// `namespace` for that exact key.
///
/// # Errors
///
/// Returns an error when the trusted key is malformed.
pub fn verify_payload_signature(
    payload: &[u8],
    signature: &str,
    trusted_key: &str,
    namespace: &str,
) -> Result<bool> {
    let Ok(signature) = SshSig::from_pem(signature.as_bytes()) else {
        return Ok(false);
    };
    let public_key = trusted_ssh_public_key(trusted_key)?;
    Ok(public_key.verify(namespace, payload, &signature).is_ok())
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
///
/// # Errors
///
/// Returns an error only when git itself cannot be executed; ancestry
/// outcomes (including divergence) are encoded in [`DowngradeStatus`].
pub fn check_downgrade(
    current_commit: &str,
    new_commit: &str,
    repo_path: &Path,
) -> Result<DowngradeStatus> {
    if current_commit == new_commit {
        return Ok(DowngradeStatus::SameCommit);
    }

    // Is current an ancestor of new? (fast-forward)
    if repo::is_ancestor_blocking(repo_path, current_commit, new_commit)
        .with_context(|| format!("checking ancestry of {current_commit}..{new_commit}"))?
    {
        return Ok(DowngradeStatus::FastForward);
    }

    // Is new an ancestor of current? (downgrade)
    if repo::is_ancestor_blocking(repo_path, new_commit, current_commit)
        .with_context(|| format!("checking ancestry of {new_commit}..{current_commit}"))?
    {
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
///
/// # Errors
///
/// Returns an error when the string does not have three colon-separated
/// fields, the registry or key field is empty, or the algorithm is not
/// `"Ed25519"`.
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

    // -- read_openssh_private_key (whitespace tolerance) --------------------

    /// A valid key with a non-canonical tail must still be read. The most
    /// common offender is the double trailing newline `op item get ... |
    /// jq -r .value` produces (1Password stores the key already newline-
    /// terminated and `jq -r` appends a second one), but trailing spaces and
    /// CRLF are equally fatal to the strict `ssh-key` reader. Both the
    /// public-key derivation and the signing path trim before parsing.
    ///
    /// Regression test for the `keys register` / signing "PEM error in
    /// pre-encapsulation boundary" failure introduced when the `ssh-keygen -y`
    /// shell-out was replaced with the in-process reader.
    #[test]
    fn reads_openssh_key_with_noncanonical_trailing_whitespace() {
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([23_u8; 32]);
        let canonical = keypair.to_openssh_private_key("louis");
        // The writer emits exactly one trailing newline; the bug only appears
        // once something perturbs that tail.
        assert!(canonical.ends_with("-----\n") && !canonical.ends_with("-----\n\n"));

        let expected_blob = keypair.public_key_base64();
        let temp = TempDir::new().unwrap();

        for (label, contents) in [
            ("double newline (jq -r)", format!("{canonical}\n")),
            ("trailing spaces", format!("{canonical}   ")),
            ("crlf blank line", format!("{canonical}\r\n\r\n")),
            ("no trailing newline", canonical.trim_end().to_string()),
        ] {
            let path = temp.path().join("key");
            fs::write(&path, &contents).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }

            let blob = public_ed25519_blob(&path)
                .unwrap_or_else(|err| panic!("public_ed25519_blob failed for {label}: {err:#}"));
            assert_eq!(blob, expected_blob, "wrong blob for {label}");

            // The signing path reads the same key; it must tolerate the tail too.
            sign_payload_signature(&path, "git", b"payload")
                .unwrap_or_else(|err| panic!("sign_payload_signature failed for {label}: {err:#}"));
        }
    }

    #[test]
    fn same_ed25519_key_material_verifies_git_tag_and_narinfo_sig() {
        let registry = "registry";
        let seed = [7_u8; 32];
        let keypair = crate::sshkey::Ed25519Keypair::from_seed(seed);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let raw_public_key = signing_key.verifying_key().to_bytes();
        let ssh_public_b64 = keypair.public_key_base64();
        let nix_public_b64 = base64::engine::general_purpose::STANDARD.encode(raw_public_key);

        let aos_trust_key = keypair.trust_key_line(registry);
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
        fs::write(&private_key_path, keypair.to_openssh_private_key(registry)).unwrap();
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
        assert!(
            verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&aos_trust_key)).unwrap()
        );

        let signer_secret_b64 = base64::engine::general_purpose::STANDARD.encode(seed);
        let signer =
            NarInfoSigner::from_key_content(&format!("{registry}:{signer_secret_b64}")).unwrap();
        let refs = vec!["/nix/store/ref111-libc".to_string()];
        let input = StaticNarInfoInput {
            store_path: "/nix/store/abc123-hello",
            nar_hash: "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
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
        let fingerprint_refs = vec!["/nix/store/ref111-libc".to_string()];
        let fingerprint = NarInfoSigner::fingerprint(
            &parsed.store_path,
            &parsed.nar_hash,
            parsed.nar_size as i64,
            &fingerprint_refs,
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

    #[test]
    fn key_store_remove_masks_anchor_keys() {
        let tmp = TempDir::new().unwrap();
        let writable = tmp.path().join("writable");
        let anchors = tmp.path().join("anchors");
        fs::create_dir_all(&writable).unwrap();
        fs::create_dir_all(&anchors).unwrap();
        fs::write(anchors.join("core.pub"), "core:Ed25519:AAAA\n").unwrap();

        let store = KeyStore::new(vec![writable.clone(), anchors.clone()]);
        assert!(store.remove("core").unwrap());
        assert_eq!(
            fs::read_to_string(anchors.join("core.pub")).unwrap(),
            "core:Ed25519:AAAA\n"
        );
        assert_eq!(
            fs::read_to_string(writable.join("core.pub")).unwrap(),
            "# revoked: core:Ed25519:AAAA\n"
        );
        assert!(store.lookup_all("core").is_empty());
        assert!(!store.remove("core").unwrap());
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

    // -- multi-key verification ----------------------------------------------

    /// Build a `registry:Ed25519:<base64>` trust key line and write the
    /// matching OpenSSH private key file, returning `(trust_key, key_path)`.
    fn test_keypair(dir: &Path, registry: &str, seed: [u8; 32], name: &str) -> (String, PathBuf) {
        let keypair = crate::sshkey::Ed25519Keypair::from_seed(seed);
        let trust_key = keypair.trust_key_line(registry);

        let key_path = dir.join(name);
        fs::write(&key_path, keypair.to_openssh_private_key(registry)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        (trust_key, key_path)
    }

    #[test]
    fn verify_tag_signature_accepts_any_key_in_set() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init"]);
        git(&repo, &["config", "user.name", "registry"]);
        git(&repo, &["config", "user.email", "registry"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        fs::write(repo.join("file"), "content").unwrap();
        git(&repo, &["add", "file"]);
        git(&repo, &["commit", "-m", "init"]);

        let (key_a, _path_a) = test_keypair(temp.path(), "registry", [1_u8; 32], "key_a");
        let (key_b, path_b) = test_keypair(temp.path(), "registry", [2_u8; 32], "key_b");

        // Tag signed by B.
        git(
            &repo,
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={}", path_b.display()),
                "tag",
                "-s",
                "1.0.0",
                "-m",
                "release 1.0.0",
            ],
        );

        // Verifies when B is anywhere in the trusted set.
        assert!(verify_tag_signature(&repo, "1.0.0", &[key_a.clone(), key_b.clone()]).unwrap());
        assert!(verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_b)).unwrap());
        // Fails when the set lacks B.
        assert!(!verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_a)).unwrap());
        // An empty trusted set is a hard error, never a pass.
        let err = verify_tag_signature(&repo, "1.0.0", &[]).unwrap_err();
        assert!(
            format!("{err:#}").contains("empty trusted key set"),
            "{err:#}"
        );
    }

    #[test]
    fn verify_commit_signature_accepts_any_key_in_set() {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        // SHA-256 repo, matching the registry's object format.
        git(&repo, &["init", "--object-format=sha256"]);
        git(&repo, &["config", "user.name", "registry"]);
        git(&repo, &["config", "user.email", "registry"]);

        let (key_a, _path_a) = test_keypair(temp.path(), "registry", [1_u8; 32], "key_a");
        let (key_b, path_b) = test_keypair(temp.path(), "registry", [2_u8; 32], "key_b");

        fs::write(repo.join("file"), "content").unwrap();
        git(&repo, &["add", "file"]);
        // Commit signed by B with an SSH key (gpg.format=ssh), the same way the
        // registry head commit is signed.
        git(
            &repo,
            &[
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={}", path_b.display()),
                "-c",
                "commit.gpgsign=true",
                "commit",
                "-m",
                "signed commit",
            ],
        );
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repo)
            .output()
            .unwrap();
        let head = String::from_utf8(out.stdout).unwrap().trim().to_string();

        assert!(
            verify_commit_signature(&repo, &head, &[key_a.clone(), key_b.clone()]).unwrap(),
            "commit signed by B must verify when B is in the trusted set"
        );
        assert!(
            !verify_commit_signature(&repo, &head, std::slice::from_ref(&key_a)).unwrap(),
            "must not verify when the signing key is absent"
        );
    }

    // -- revoked-key exclusions ----------------------------------------------

    #[test]
    fn lookup_all_filters_revoked_exclusions_across_dirs() {
        let tmp = TempDir::new().unwrap();
        let writable = tmp.path().join("writable");
        let anchors = tmp.path().join("anchors");
        fs::create_dir_all(&writable).unwrap();
        fs::create_dir_all(&anchors).unwrap();

        // Read-only anchor still lists a revoked key A alongside B.
        fs::write(
            anchors.join("core.pub"),
            "core:Ed25519:AAAA\ncore:Ed25519:BBBB\n",
        )
        .unwrap();
        // The writable store pins B and masks A.
        fs::write(
            writable.join("core.pub"),
            "core:Ed25519:BBBB\n# revoked: core:Ed25519:AAAA\n",
        )
        .unwrap();

        let store = KeyStore::new(vec![writable, anchors]);
        let keys = store.lookup_all("core");
        let lines: Vec<String> = keys.iter().map(TrustedKey::key_line).collect();
        assert!(
            !lines.contains(&"core:Ed25519:AAAA".to_string()),
            "{lines:?}"
        );
        assert!(lines.contains(&"core:Ed25519:BBBB".to_string()));
        assert_eq!(
            store.revoked_fingerprints("core"),
            vec![key_fingerprint("AAAA")]
        );
    }

    #[test]
    fn store_preserves_exclusion_lines() {
        let tmp = TempDir::new().unwrap();
        let writable = tmp.path().join("writable");
        fs::create_dir_all(&writable).unwrap();
        fs::write(
            writable.join("core.pub"),
            "core:Ed25519:BBBB\n# revoked: core:Ed25519:AAAA\n",
        )
        .unwrap();

        let store = KeyStore::new(vec![writable.clone()]);
        store
            .store(&TrustedKey {
                registry: "core".into(),
                algorithm: "Ed25519".into(),
                public_key: "CCCC".into(),
                fingerprint: key_fingerprint("CCCC"),
                source: KeySource::Tofu,
            })
            .unwrap();

        let content = fs::read_to_string(writable.join("core.pub")).unwrap();
        assert!(
            content.contains("# revoked: core:Ed25519:AAAA"),
            "{content}"
        );
        assert!(content.contains("core:Ed25519:CCCC"));
    }

    #[test]
    fn store_unrevokes_explicitly_pinned_key() {
        let tmp = TempDir::new().unwrap();
        let writable = tmp.path().join("writable");
        fs::create_dir_all(&writable).unwrap();
        fs::write(writable.join("core.pub"), "# revoked: core:Ed25519:AAAA\n").unwrap();

        let store = KeyStore::new(vec![writable.clone()]);
        store
            .store(&TrustedKey {
                registry: "core".into(),
                algorithm: "Ed25519".into(),
                public_key: "AAAA".into(),
                fingerprint: key_fingerprint("AAAA"),
                source: KeySource::Tofu,
            })
            .unwrap();

        let content = fs::read_to_string(writable.join("core.pub")).unwrap();
        assert!(!content.contains("# revoked:"), "{content}");
        let keys = store.lookup_all("core");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].public_key, "AAAA");
    }

    #[test]
    fn sync_registry_keys_pins_unpins_and_masks() {
        let tmp = TempDir::new().unwrap();
        let writable = tmp.path().join("writable");
        let anchors = tmp.path().join("anchors");
        fs::create_dir_all(&writable).unwrap();
        fs::create_dir_all(&anchors).unwrap();

        // Image anchor ships A; the writable store pinned A earlier.
        fs::write(anchors.join("core.pub"), "core:Ed25519:AAAA\n").unwrap();
        fs::write(writable.join("core.pub"), "core:Ed25519:AAAA\n").unwrap();

        let store = KeyStore::new(vec![writable.clone(), anchors]);
        // Roster rotated to B only: A must be unpinned and masked.
        let active = vec![TrustedKey {
            registry: "core".into(),
            algorithm: "Ed25519".into(),
            public_key: "BBBB".into(),
            fingerprint: key_fingerprint("BBBB"),
            source: KeySource::Tofu,
        }];
        let report = store.sync_registry_keys("core", &active).unwrap();
        assert_eq!(report.pinned, 1);
        assert_eq!(report.unpinned, 1);
        assert_eq!(report.masked, 1);

        let keys = store.lookup_all("core");
        let lines: Vec<String> = keys.iter().map(TrustedKey::key_line).collect();
        assert_eq!(lines, vec!["core:Ed25519:BBBB".to_string()]);
        let masked_content = fs::read_to_string(writable.join("core.pub")).unwrap();

        let report = store.sync_registry_keys("core", &active).unwrap();
        assert!(report.is_noop(), "{report:?}");
        let repeat_content = fs::read_to_string(writable.join("core.pub")).unwrap();
        assert_eq!(repeat_content, masked_content);

        // Re-enrolling A drops its exclusion and reports the pin.
        let active = vec![
            active[0].clone(),
            TrustedKey {
                registry: "core".into(),
                algorithm: "Ed25519".into(),
                public_key: "AAAA".into(),
                fingerprint: key_fingerprint("AAAA"),
                source: KeySource::Tofu,
            },
        ];
        let report = store.sync_registry_keys("core", &active).unwrap();
        assert_eq!(report.pinned, 1);
        assert_eq!(report.unpinned, 0);
        assert_eq!(report.masked, 0);
        let content = fs::read_to_string(writable.join("core.pub")).unwrap();
        assert!(!content.contains("# revoked:"), "{content}");
        assert_eq!(store.lookup_all("core").len(), 2);
    }

    fn git(repo: &Path, args: &[&str]) {
        crate::testutil::git(repo, args);
    }
}
