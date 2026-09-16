//! Domain-separated configuration signature authentication.
//!
//! Secure first-boot provisioning verifies exact `host.nix` bytes in the
//! initrd before complete evaluation for either initrd or stage 2.
//! Manual configuration-evaluation commands can use the same implementation
//! to verify a detached signature over a standalone `host.nix`.
//!
//! Both paths verify delivered bytes against an image-baked
//! `trusted-config-keys.d/<op>.pub` set. An unsigned, badly signed, or
//! untrusted input yields no [`HostNixTrust`].
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
//! Host modules use [`CONFIG_SIGNATURE_NAMESPACE`], which is distinct from the
//! `git` namespace and therefore prevents cross-protocol signature replay.

use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use ssh_key::{PublicKey, SshSig};

const REVOKED_LINE_PREFIX: &str = "# revoked:";

/// SSHSIG namespace for operator `host.nix` signatures.
///
/// A namespace mismatch causes verification to fail, preventing a signature
/// created for another protocol from authorizing host configuration.
pub const CONFIG_SIGNATURE_NAMESPACE: &str = "aos-config";

/// The image-baked operator trust-anchor directory.
pub const TRUSTED_CONFIG_KEYS_DIR: &str = "/etc/apm/trusted-config-keys.d";

/// A successful `host.nix` authentication.
///
/// Carries exactly the provenance the manifest's `inputs.host_nix` and the
/// `gen-attestation/v1` record need: the operator id whose key file matched and
/// that key's short fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNixTrust {
    /// The `trusted-config-keys.d/<op>.pub` operator id that verified the
    /// signature.
    pub operator_id: String,
    /// Short fingerprint of the matching key
    /// (8 hex chars). Recorded as `host_nix.operator_key`.
    pub operator_key: String,
}

/// Why a `host.nix` failed detached-signature authentication.
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

/// Authenticate `host.nix` bytes against an image-baked trust-anchor set.
///
/// `trusted_dirs` are the directories that hold `trusted-config-keys.d/<op>.pub`
/// files (typically `[<writable>, /etc/apm/trusted-config-keys.d]`). Every
/// operator key across every file is collected with `# revoked:` masking and
/// rotation overlap. The detached
/// signature is an armored SSHSIG (`-----BEGIN SSH SIGNATURE-----`) produced by
/// `ssh-keygen -Y sign -n aos-config`.
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
    authenticate_config_payload(
        host_nix,
        detached_sig,
        trusted_dirs,
        CONFIG_SIGNATURE_NAMESPACE,
    )
}

/// Authenticate arbitrary configuration bytes in a caller-selected SSHSIG
/// namespace.
///
/// Callers must use a stable, domain-separated namespace. First boot uses
/// [`CONFIG_SIGNATURE_NAMESPACE`] over the exact host module bytes.
///
/// # Errors
///
/// Returns the same fail-closed errors as [`authenticate_host_nix`].
pub fn authenticate_config_payload(
    payload: &[u8],
    detached_sig: Option<&str>,
    trusted_dirs: &[PathBuf],
    namespace: &str,
) -> Result<HostNixTrust, HostNixTrustError> {
    let candidates = collect_trusted_config_keys(trusted_dirs);
    authenticate_candidates(payload, detached_sig, candidates, namespace)
}

/// Authenticates configuration bytes against exact immutable anchor files.
///
/// This form is used when a checked provider input already names each anchor;
/// it avoids copying those files into a synthetic directory before verifying
/// the payload.
///
/// # Errors
///
/// Returns the same fail-closed errors as [`authenticate_config_payload`].
pub fn authenticate_config_payload_files(
    payload: &[u8],
    detached_sig: Option<&str>,
    trusted_files: &[PathBuf],
    namespace: &str,
) -> Result<HostNixTrust, HostNixTrustError> {
    let candidates = collect_trusted_config_key_files(trusted_files);
    authenticate_candidates(payload, detached_sig, candidates, namespace)
}

fn authenticate_candidates(
    payload: &[u8],
    detached_sig: Option<&str>,
    candidates: Vec<(String, PublicKey, String)>,
    namespace: &str,
) -> Result<HostNixTrust, HostNixTrustError> {
    if candidates.is_empty() {
        return Err(HostNixTrustError::NoTrustedKeys);
    }
    let Some(sig) = detached_sig else {
        return Err(HostNixTrustError::MissingSignature);
    };
    let Ok(signature) = SshSig::from_pem(sig.as_bytes()) else {
        return Err(HostNixTrustError::Untrusted);
    };
    for (operator_id, public_key, fingerprint) in candidates {
        if public_key.verify(namespace, payload, &signature).is_ok() {
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
/// `host_nix_path` points at the exact bytes staged into the evaluator root;
/// the detached signature is read from
/// `<host_nix_path>.sig` if it exists. The bytes hashed and verified are the
/// exact file contents, matching the recorded `host_nix.content_hash`.
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
/// Operator ids are discovered by enumerating `*.pub` filenames, so the gate
/// need not be told which operator signed.
fn collect_trusted_config_keys(trusted_dirs: &[PathBuf]) -> Vec<(String, PublicKey, String)> {
    let files = operator_ids(trusted_dirs)
        .into_iter()
        .flat_map(|operator_id| {
            trusted_dirs
                .iter()
                .map(move |directory| directory.join(format!("{operator_id}.pub")))
        })
        .collect::<Vec<_>>();
    collect_trusted_config_key_files(&files)
}

fn collect_trusted_config_key_files(trusted_files: &[PathBuf]) -> Vec<(String, PublicKey, String)> {
    let mut revoked = Vec::new();
    let mut candidates = Vec::new();
    for path in trusted_files {
        let Some(operator_id) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".pub"))
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if let Some(line) = revoked_key_line(line) {
                if !revoked.contains(&line) {
                    revoked.push(line);
                }
                continue;
            }
            let Ok((declared_operator, public_key)) = parse_trusted_key(line) else {
                continue;
            };
            if declared_operator == operator_id {
                candidates.push((declared_operator, line.to_string(), public_key));
            }
        }
    }

    let mut seen = Vec::new();
    let mut out = Vec::new();
    for (operator_id, line, public_key) in candidates {
        if revoked.contains(&line) || seen.contains(&line) {
            continue;
        }
        seen.push(line.clone());
        out.push((operator_id, public_key, key_fingerprint(&line)));
    }
    out
}

fn revoked_key_line(line: &str) -> Option<String> {
    let key = line.strip_prefix(REVOKED_LINE_PREFIX)?.trim();
    parse_trusted_key(key).ok()?;
    Some(key.to_string())
}

fn parse_trusted_key(line: &str) -> Result<(String, PublicKey), ()> {
    let mut fields = line.splitn(3, ':');
    let operator_id = fields.next().filter(|value| !value.is_empty()).ok_or(())?;
    let algorithm = fields.next().ok_or(())?;
    let public_key = fields.next().filter(|value| !value.is_empty()).ok_or(())?;
    if algorithm != "Ed25519" {
        return Err(());
    }
    let parsed = PublicKey::from_openssh(&format!("ssh-ed25519 {public_key}")).map_err(|_| ())?;
    Ok((operator_id.to_string(), parsed))
}

fn key_fingerprint(key_line: &str) -> String {
    let encoded = key_line
        .rsplit_once(':')
        .map_or(key_line, |(_, value)| value);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap_or_else(|_| encoded.as_bytes().to_vec());
    let hash = hex::encode(Sha256::digest(bytes));
    hash[..8].to_string()
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
    use ssh_key::private::Ed25519Keypair;
    use ssh_key::{HashAlg, LineEnding, PrivateKey};
    use tempfile::TempDir;

    use super::*;

    fn enrolled_operator(directory: &Path, operator_id: &str, seed: u8) -> PrivateKey {
        let private = PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
        let public = private
            .public_key()
            .to_openssh()
            .expect("encode public key");
        let encoded = public
            .split_whitespace()
            .nth(1)
            .expect("public key material");

        std::fs::create_dir_all(directory).expect("create trust directory");
        std::fs::write(
            directory.join(format!("{operator_id}.pub")),
            format!("{operator_id}:Ed25519:{encoded}\n"),
        )
        .expect("write trust anchor");
        private
    }

    fn signature(private: &PrivateKey, namespace: &str, payload: &[u8]) -> String {
        private
            .sign(namespace, HashAlg::Sha512, payload)
            .expect("sign payload")
            .to_pem(LineEnding::LF)
            .expect("encode signature")
    }

    #[test]
    fn exact_payload_and_namespace_select_the_enrolled_operator() {
        let temporary = TempDir::new().expect("temporary trust directory");
        let keys = temporary.path().join("trusted-config-keys.d");
        enrolled_operator(&keys, "alice", 7);
        let bob = enrolled_operator(&keys, "bob", 11);
        let payload = b"{ aos.host.hostname = \"node\"; }";
        let detached = signature(&bob, CONFIG_SIGNATURE_NAMESPACE, payload);

        let trusted = authenticate_host_nix(payload, Some(&detached), &[keys.clone()])
            .expect("enrolled operator authenticates the exact payload");
        assert_eq!(trusted.operator_id, "bob");
        let trusted = authenticate_config_payload_files(
            payload,
            Some(&detached),
            &[keys.join("alice.pub"), keys.join("bob.pub")],
            CONFIG_SIGNATURE_NAMESPACE,
        )
        .expect("exact anchor files authenticate without directory materialization");
        assert_eq!(trusted.operator_id, "bob");

        assert_eq!(
            authenticate_host_nix(b"changed", Some(&detached), &[keys.clone()]),
            Err(HostNixTrustError::Untrusted)
        );
        let wrong_namespace = signature(&bob, "git", payload);
        assert_eq!(
            authenticate_host_nix(payload, Some(&wrong_namespace), &[keys]),
            Err(HostNixTrustError::Untrusted)
        );
    }

    #[test]
    fn revoked_and_missing_anchors_cannot_authorize_configuration() {
        let temporary = TempDir::new().expect("temporary trust directory");
        let keys = temporary.path().join("trusted-config-keys.d");
        let private = enrolled_operator(&keys, "operator", 19);
        let anchor = std::fs::read_to_string(keys.join("operator.pub")).expect("trust anchor");
        std::fs::write(
            keys.join("operator.pub"),
            format!("{anchor}# revoked: {}", anchor.trim()),
        )
        .expect("revoke trust anchor");
        let payload = b"configuration";
        let detached = signature(&private, CONFIG_SIGNATURE_NAMESPACE, payload);

        assert_eq!(
            authenticate_host_nix(payload, Some(&detached), &[keys]),
            Err(HostNixTrustError::NoTrustedKeys)
        );
        assert_eq!(
            authenticate_host_nix(payload, Some(&detached), &[temporary.path().join("empty")]),
            Err(HostNixTrustError::NoTrustedKeys)
        );
    }
}
