//! Stage-2 authenticity gate for `host.nix`.
//!
//! The initrd `aos metadata` agent is **transport-only**: it fetches the
//! operator's `host.nix` (literal Nix or a `sha256`-pinned URL pointer) and
//! stashes the *untrusted* bytes at `/run/aos-metadata/host.nix` plus an
//! optional detached SSHSIG at `host.nix.sig` (see
//! [`crate::metadata::stash`]). It performs **no** signature check — the
//! `trusted-config-keys.d` anchors live in the measured `/etc` that is only
//! assembled in stage-2.
//!
//! This module is the trust gate `aos-eval.service` runs **before** driving the
//! config fixpoint: it verifies the stashed `host.nix` bytes against an
//! image-baked `trusted-config-keys.d/<op>.pub` set, reusing
//! [`crate::security::KeyStore`] and
//! [`crate::security::verify_payload_signature`] unchanged. An unsigned,
//! badly-signed, or untrusted-key `host.nix` yields no [`HostNixTrust`] and the
//! caller emits **no manifest** — the box stays on the prior generation
//! (gen-0 on first boot). This is the single fail-closed seam that turns CS8's
//! untrusted transport into a trusted eval input.
//!
//! ```text
//! authenticate_host_nix(bytes, detached_sig, trusted_dirs):
//!   keys = every trusted-config-keys.d/<op>.pub line across trusted_dirs
//!   if keys empty                       -> Err(NoTrustedKeys)
//!   if detached_sig absent              -> Err(MissingSignature)
//!   for key in keys:
//!     if verify(bytes, sig, key, "aos-config"): return Trusted{operator_key, operator_id}
//!   Err(Untrusted)
//! ```
//!
//! The SSHSIG namespace is the literal [`CONFIG_SIGNATURE_NAMESPACE`]
//! (`aos-config`), distinct from the `git` namespace used for tag/commit
//! signatures, so a config signature can never be replayed as a tag signature
//! and vice versa.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::security::{KeyStore, verify_payload_signature};

/// SSHSIG namespace for operator `host.nix` signatures (build-spec §3.3).
///
/// Distinct from the `git` namespace used by
/// [`crate::security::verify_commit_signature`] /
/// [`crate::security::verify_tag_signature`]; a namespace mismatch causes the
/// underlying verifier to return `Ok(false)` and the gate to fail closed.
pub const CONFIG_SIGNATURE_NAMESPACE: &str = "aos-config";

/// The image-baked operator trust-anchor directory (build-spec §3.2).
pub const TRUSTED_CONFIG_KEYS_DIR: &str = "/etc/apm/trusted-config-keys.d";

/// A successful `host.nix` authentication (build-spec §3.2 `Trusted`).
///
/// Carries exactly the provenance the manifest's `inputs.host_nix` and the
/// `gen-attestation/v1` record need: the operator id whose key file matched and
/// that key's short fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNixTrust {
    /// The `trusted-config-keys.d/<op>.pub` operator id that verified the
    /// signature (the `KeyStore` "registry" field).
    pub operator_id: String,
    /// Short fingerprint of the matching key
    /// ([`crate::security::key_fingerprint`], 8 hex chars). Recorded as
    /// `host_nix.operator_key`.
    pub operator_key: String,
}

/// Why a `host.nix` failed the stage-2 authenticity gate (build-spec §3.4).
///
/// Every variant is fail-closed: the caller emits no manifest and the box stays
/// on the prior generation. The variants are distinguished so the operability
/// surface can name the precise reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostNixTrustError {
    /// No `trusted-config-keys.d/<op>.pub` anchor exists at all — the image was
    /// built without any operator config key, so no `host.nix` can be trusted.
    NoTrustedKeys,
    /// The operator supplied `host.nix` but no detached `host.nix.sig`.
    MissingSignature,
    /// A signature was present but matched no trusted operator key (wrong key,
    /// tampered bytes, wrong namespace, or malformed armor).
    Untrusted,
}

impl fmt::Display for HostNixTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostNixTrustError::NoTrustedKeys => f.write_str(
                "no trusted config key is baked into the image (trusted-config-keys.d is empty); \
                 refusing to trust any host.nix",
            ),
            HostNixTrustError::MissingSignature => {
                f.write_str("host.nix has no detached signature (host.nix.sig); refusing to eval")
            }
            HostNixTrustError::Untrusted => f.write_str(
                "host.nix signature does not match any trusted config key; refusing to eval",
            ),
        }
    }
}

impl std::error::Error for HostNixTrustError {}

/// Authenticate `host.nix` bytes against an image-baked trust-anchor set
/// (build-spec §3.2).
///
/// `trusted_dirs` are the directories that hold `trusted-config-keys.d/<op>.pub`
/// files (typically `[<writable>, /etc/apm/trusted-config-keys.d]`). Every
/// operator key across every file is collected — `# revoked:` masking and
/// rotation overlap come for free from [`KeyStore::lookup_all`]. The detached
/// signature is an armored SSHSIG (`-----BEGIN SSH SIGNATURE-----`) produced by
/// `ssh-keygen -Y sign -n aos-config` (or
/// [`crate::security::sign_payload_signature`] with
/// [`CONFIG_SIGNATURE_NAMESPACE`]).
///
/// Verification succeeds the moment any trusted key validates the signature
/// over `host_nix` in the `aos-config` namespace, returning the matching
/// operator's id and key fingerprint.
///
/// # Errors
///
/// Returns [`HostNixTrustError::NoTrustedKeys`] when no operator anchor exists,
/// [`HostNixTrustError::MissingSignature`] when `detached_sig` is `None`, and
/// [`HostNixTrustError::Untrusted`] when a present signature matches no trusted
/// key. The function never returns `Ok` for an unverified payload — it is
/// fail-closed by construction.
pub fn authenticate_host_nix(
    host_nix: &[u8],
    detached_sig: Option<&str>,
    trusted_dirs: &[PathBuf],
) -> Result<HostNixTrust, HostNixTrustError> {
    let candidates = collect_trusted_config_keys(trusted_dirs);
    if candidates.is_empty() {
        return Err(HostNixTrustError::NoTrustedKeys);
    }
    let Some(sig) = detached_sig else {
        return Err(HostNixTrustError::MissingSignature);
    };
    for (operator_id, key_line, fingerprint) in candidates {
        // `verify_payload_signature` returns Err only on a malformed *trusted*
        // key line; we built `key_line` from a parsed KeyStore entry, so treat
        // any Err defensively as a non-match and keep scanning.
        if matches!(
            verify_payload_signature(host_nix, sig, &key_line, CONFIG_SIGNATURE_NAMESPACE),
            Ok(true)
        ) {
            return Ok(HostNixTrust {
                operator_id,
                operator_key: fingerprint,
            });
        }
    }
    Err(HostNixTrustError::Untrusted)
}

/// Authenticate the `host.nix` file at `host_nix_path`, reading the sibling
/// `host.nix.sig` when present (the on-disk shape `aos-eval.service` stages).
///
/// `host_nix_path` points at the verified-bytes file (the stash payload staged
/// into the evaluator root); the detached signature is read from
/// `<host_nix_path>.sig` if it exists. The bytes hashed and verified are the
/// exact file contents, matching the `host_nix.content_hash` definition
/// (build-spec §1.3).
///
/// # Errors
///
/// Returns [`HostNixTrustError`] for every gate failure. An unreadable
/// `host.nix` file or signature is treated as a missing payload and maps to
/// [`HostNixTrustError::MissingSignature`] (no signature could be read), keeping
/// the gate fail-closed without surfacing an I/O error to the trust decision.
pub fn authenticate_host_nix_file(
    host_nix_path: &Path,
    trusted_dirs: &[PathBuf],
) -> Result<HostNixTrust, HostNixTrustError> {
    let Ok(bytes) = std::fs::read(host_nix_path) else {
        return Err(HostNixTrustError::MissingSignature);
    };
    let sig_path = sig_path_for(host_nix_path);
    let sig = std::fs::read_to_string(&sig_path).ok();
    authenticate_host_nix(&bytes, sig.as_deref(), trusted_dirs)
}

/// The detached-signature path for a `host.nix` file: `<path>.sig`.
fn sig_path_for(host_nix_path: &Path) -> PathBuf {
    let mut name = host_nix_path.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// Collect every `(operator_id, key_line, fingerprint)` triple from the
/// `trusted-config-keys.d/<op>.pub` files across `trusted_dirs`.
///
/// Each `<op>.pub` file is an operator anchor; its lines are
/// `<op>:Ed25519:<base64>`, parsed and revocation-filtered by
/// [`KeyStore::lookup_all`]. Operator ids are discovered by enumerating `*.pub`
/// filenames, so the gate need not be told which operator signed.
fn collect_trusted_config_keys(trusted_dirs: &[PathBuf]) -> Vec<(String, String, String)> {
    let store = KeyStore::new(trusted_dirs.to_vec());
    let mut seen_keys: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for operator_id in operator_ids(trusted_dirs) {
        for key in store.lookup_all(&operator_id) {
            let line = key.key_line();
            if seen_keys.contains(&line) {
                continue;
            }
            seen_keys.push(line.clone());
            out.push((operator_id.clone(), line, key.fingerprint.clone()));
        }
    }
    out
}

/// Operator ids present across `trusted_dirs`, derived from `<op>.pub`
/// filenames. Deduplicated, sorted for deterministic scan order.
fn operator_ids(trusted_dirs: &[PathBuf]) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for dir in trusted_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(op) = name.strip_suffix(".pub") {
                if !op.is_empty() && !ids.iter().any(|existing| existing == op) {
                    ids.push(op.to_string());
                }
            }
        }
    }
    ids.sort();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sign_payload_signature;
    use crate::sshkey::Ed25519Keypair;
    use tempfile::TempDir;

    /// Generate an Ed25519 keypair, write its OpenSSH private key to
    /// `key_store/<op>.key` and the `<op>:Ed25519:<base64>` anchor to
    /// `keys_dir/<op>.pub`, and return the private-key path.
    fn enroll_operator(keys_dir: &Path, key_store: &Path, op: &str) -> PathBuf {
        let key = Ed25519Keypair::generate();
        let priv_path = key_store.join(format!("{op}.key"));
        std::fs::write(&priv_path, key.to_openssh_private_key(op)).expect("write private key");
        std::fs::create_dir_all(keys_dir).expect("mkdir keys");
        std::fs::write(
            keys_dir.join(format!("{op}.pub")),
            format!("{}\n", key.trust_key_line(op)),
        )
        .expect("write anchor");
        priv_path
    }

    fn sign(priv_path: &Path, payload: &[u8]) -> String {
        sign_payload_signature(priv_path, CONFIG_SIGNATURE_NAMESPACE, payload).expect("sign")
    }

    #[test]
    fn good_signature_is_trusted() {
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("trusted-config-keys.d");
        let priv_path = enroll_operator(&keys, tmp.path(), "ops");
        let host_nix = b"{ aos.host.hostname = \"web-1\"; }";
        let sig = sign(&priv_path, host_nix);

        let trust = authenticate_host_nix(host_nix, Some(&sig), &[keys]).expect("trusted");
        assert_eq!(trust.operator_id, "ops");
        assert_eq!(trust.operator_key.len(), 8);
    }

    #[test]
    fn tampered_bytes_are_untrusted() {
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("trusted-config-keys.d");
        let priv_path = enroll_operator(&keys, tmp.path(), "ops");
        let sig = sign(&priv_path, b"original");

        let err = authenticate_host_nix(b"tampered", Some(&sig), &[keys]).unwrap_err();
        assert_eq!(err, HostNixTrustError::Untrusted);
    }

    #[test]
    fn wrong_key_is_untrusted() {
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("trusted-config-keys.d");
        // Enroll the trusted operator, but sign with a DIFFERENT (untrusted) key.
        let _trusted = enroll_operator(&keys, tmp.path(), "ops");
        let attacker = Ed25519Keypair::generate();
        let attacker_path = tmp.path().join("attacker.key");
        std::fs::write(&attacker_path, attacker.to_openssh_private_key("attacker")).unwrap();
        let host_nix = b"payload";
        let sig = sign(&attacker_path, host_nix);

        let err = authenticate_host_nix(host_nix, Some(&sig), &[keys]).unwrap_err();
        assert_eq!(err, HostNixTrustError::Untrusted);
    }

    #[test]
    fn missing_signature_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("trusted-config-keys.d");
        enroll_operator(&keys, tmp.path(), "ops");
        let err = authenticate_host_nix(b"payload", None, &[keys]).unwrap_err();
        assert_eq!(err, HostNixTrustError::MissingSignature);
    }

    #[test]
    fn no_anchor_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("empty");
        std::fs::create_dir_all(&keys).unwrap();
        let err = authenticate_host_nix(b"payload", Some("sig"), &[keys]).unwrap_err();
        assert_eq!(err, HostNixTrustError::NoTrustedKeys);
    }

    #[test]
    fn git_namespace_signature_is_rejected() {
        // A signature made in the `git` namespace must not verify as a config
        // signature — replay resistance across namespaces.
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("trusted-config-keys.d");
        let priv_path = enroll_operator(&keys, tmp.path(), "ops");
        let host_nix = b"payload";
        let git_sig =
            sign_payload_signature(&priv_path, "git", host_nix).expect("sign in git namespace");

        let err = authenticate_host_nix(host_nix, Some(&git_sig), &[keys]).unwrap_err();
        assert_eq!(err, HostNixTrustError::Untrusted);
    }

    #[test]
    fn file_helper_reads_sibling_sig() {
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("trusted-config-keys.d");
        let priv_path = enroll_operator(&keys, tmp.path(), "ops");
        let host_nix = b"{ services.web.enable = true; }";
        let sig = sign(&priv_path, host_nix);
        let host_path = tmp.path().join("host.nix");
        std::fs::write(&host_path, host_nix).unwrap();
        std::fs::write(tmp.path().join("host.nix.sig"), &sig).unwrap();

        let trust = authenticate_host_nix_file(&host_path, &[keys]).expect("trusted");
        assert_eq!(trust.operator_id, "ops");
    }

    #[test]
    fn multiple_operators_match_the_signer() {
        let tmp = TempDir::new().unwrap();
        let keys = tmp.path().join("trusted-config-keys.d");
        enroll_operator(&keys, tmp.path(), "alice");
        let bob = enroll_operator(&keys, tmp.path(), "bob");
        let host_nix = b"payload";
        let sig = sign(&bob, host_nix);

        let trust = authenticate_host_nix(host_nix, Some(&sig), &[keys]).expect("trusted");
        assert_eq!(trust.operator_id, "bob");
    }
}
