//! Pure-Rust SSHSIG verification for registry signatures.
//!
//! `apr` signs tags and commits with `git -c gpg.format=ssh`, producing
//! OpenSSH SSHSIG armored signatures. `apm` verifies them by shelling out
//! to git/ssh-keygen; the hub verifies the same format in-process so it
//! works on every runtime (native, Workers, browser).
//!
//! The armored blob decodes to:
//!
//! ```text
//! byte[6]  "SSHSIG"
//! uint32   version (1)
//! string   public key blob   = string "ssh-ed25519" + string key(32)
//! string   namespace         = "git"
//! string   reserved
//! string   hash algorithm    = "sha512" | "sha256"
//! string   signature blob    = string "ssh-ed25519" + string sig(64)
//! ```
//!
//! The Ed25519 signature covers `"SSHSIG" + string namespace +
//! string reserved + string hash_alg + string H(message)` where `H` is the
//! declared hash over the signed payload.
//!
//! Trusted keys use the registry's `name:Ed25519:<base64>` form, where the
//! base64 is the full SSH wire public-key blob — the same encoding embedded
//! in the signature, so trust comparison is byte equality.

use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----";
const MAGIC: &[u8; 6] = b"SSHSIG";
const KEY_TYPE: &str = "ssh-ed25519";

/// A parsed SSHSIG signature.
#[derive(Debug, Clone)]
pub struct SshSig {
    /// The full SSH wire public-key blob embedded in the signature.
    pub public_key_blob: Vec<u8>,
    /// The raw 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// The signature namespace (must be `git` for registry artifacts).
    pub namespace: String,
    /// The declared payload hash algorithm (`sha512` or `sha256`).
    pub hash_algorithm: String,
    /// The raw 64-byte Ed25519 signature.
    pub signature: [u8; 64],
}

impl SshSig {
    /// The embedded public key in the registry's base64 trusted-key form.
    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.public_key_blob)
    }
}

/// Parse an armored SSHSIG block.
///
/// # Errors
///
/// Returns an error on malformed armor, a bad magic/version, a key or
/// signature type other than `ssh-ed25519`, or truncated wire data.
pub fn parse_armored(armored: &str) -> Result<SshSig> {
    let body: String = armored
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != ARMOR_BEGIN)
        .skip(1)
        .take_while(|l| *l != ARMOR_END)
        .collect();
    if body.is_empty() {
        bail!("missing or empty SSH signature armor");
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(body)
        .context("invalid SSH signature base64")?;

    let mut cursor = &blob[..];
    let magic = take(&mut cursor, 6).context("SSHSIG magic")?;
    if magic != MAGIC {
        bail!("bad SSHSIG magic");
    }
    let version = read_u32(&mut cursor).context("SSHSIG version")?;
    if version != 1 {
        bail!("unsupported SSHSIG version {version}");
    }
    let public_key_blob = read_string(&mut cursor).context("SSHSIG public key")?;
    let namespace = String::from_utf8(read_string(&mut cursor).context("SSHSIG namespace")?)
        .context("SSHSIG namespace is not UTF-8")?;
    let _reserved = read_string(&mut cursor).context("SSHSIG reserved")?;
    let hash_algorithm =
        String::from_utf8(read_string(&mut cursor).context("SSHSIG hash algorithm")?)
            .context("SSHSIG hash algorithm is not UTF-8")?;
    let signature_blob = read_string(&mut cursor).context("SSHSIG signature")?;

    let public_key = parse_ed25519_key_blob(&public_key_blob)?;
    let signature = parse_ed25519_sig_blob(&signature_blob)?;

    Ok(SshSig {
        public_key_blob,
        public_key,
        namespace,
        hash_algorithm,
        signature,
    })
}

/// Verify an armored SSHSIG over `payload` against a trusted key set.
///
/// `trusted_keys` entries are in the registry's `name:Ed25519:<base64>`
/// form (bare `<base64>` blobs are also accepted). Verification checks, in
/// order: the `git` namespace, the Ed25519 signature against the *embedded*
/// key, and finally that the embedded key is one of the trusted keys — so a
/// valid signature from an untrusted key is rejected, not just unmatched.
///
/// Returns the trusted-key base64 that matched.
///
/// # Errors
///
/// Returns an error when `trusted_keys` is empty, the armor or signature is
/// invalid, the namespace is not `git`, the hash algorithm is unsupported,
/// the cryptographic verification fails, or the signing key is untrusted.
pub fn verify_armored(armored: &str, payload: &[u8], trusted_keys: &[String]) -> Result<String> {
    if trusted_keys.is_empty() {
        bail!("cannot verify signature: trusted key set is empty");
    }
    let sig = parse_armored(armored)?;
    if sig.namespace != "git" {
        bail!("unexpected SSHSIG namespace '{}'", sig.namespace);
    }

    let hashed: Vec<u8> = match sig.hash_algorithm.as_str() {
        "sha512" => Sha512::digest(payload).to_vec(),
        "sha256" => Sha256::digest(payload).to_vec(),
        other => bail!("unsupported SSHSIG hash algorithm '{other}'"),
    };

    let mut signed_data = Vec::with_capacity(hashed.len() + 64);
    signed_data.extend_from_slice(MAGIC);
    write_string(&mut signed_data, "git".as_bytes());
    write_string(&mut signed_data, b"");
    write_string(&mut signed_data, sig.hash_algorithm.as_bytes());
    write_string(&mut signed_data, &hashed);

    let key = VerifyingKey::from_bytes(&sig.public_key).context("invalid Ed25519 public key")?;
    let signature = Signature::from_bytes(&sig.signature);
    key.verify(&signed_data, &signature)
        .context("SSH signature verification failed")?;

    let embedded = sig.public_key_base64();
    for trusted in trusted_keys {
        if trusted_key_base64(trusted) == embedded {
            return Ok(embedded);
        }
    }
    bail!("signature is valid but the signing key is not trusted");
}

/// Sign `payload` as an armored SSHSIG with namespace `git`.
///
/// The hub never signs registry artifacts in production (signing is
/// client-side, per RFC-0004); this exists for fixture construction in
/// tests and for the future hosted-key path.
pub fn sign_armored(payload: &[u8], signing_key: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer;

    let hashed = Sha512::digest(payload);
    let mut signed_data = Vec::with_capacity(96);
    signed_data.extend_from_slice(MAGIC);
    write_string(&mut signed_data, b"git");
    write_string(&mut signed_data, b"");
    write_string(&mut signed_data, b"sha512");
    write_string(&mut signed_data, &hashed);
    let signature = signing_key.sign(&signed_data);

    let key_blob = ed25519_key_blob(&signing_key.verifying_key());
    let mut sig_blob = Vec::new();
    write_string(&mut sig_blob, KEY_TYPE.as_bytes());
    write_string(&mut sig_blob, &signature.to_bytes());

    let mut blob = Vec::new();
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&1u32.to_be_bytes());
    write_string(&mut blob, &key_blob);
    write_string(&mut blob, b"git");
    write_string(&mut blob, b"");
    write_string(&mut blob, b"sha512");
    write_string(&mut blob, &sig_blob);

    let body = base64::engine::general_purpose::STANDARD.encode(&blob);
    let mut armored = String::from(ARMOR_BEGIN);
    armored.push('\n');
    // Standard base64 output is pure ASCII, so rebuilding each 70-byte
    // chunk character-by-character is lossless and infallible.
    for chunk in body.as_bytes().chunks(70) {
        armored.extend(chunk.iter().map(|&b| char::from(b)));
        armored.push('\n');
    }
    armored.push_str(ARMOR_END);
    armored
}

/// Encode a verifying key as the SSH wire public-key blob.
pub fn ed25519_key_blob(key: &VerifyingKey) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    write_string(&mut blob, KEY_TYPE.as_bytes());
    write_string(&mut blob, key.as_bytes());
    blob
}

/// Render a verifying key in the registry's `name:Ed25519:<base64>` form.
pub fn trusted_key_line(name: &str, key: &VerifyingKey) -> String {
    let blob = ed25519_key_blob(key);
    format!(
        "{name}:Ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

/// Extract the base64 blob from a `name:Ed25519:<base64>` trusted key.
///
/// Bare base64 strings pass through unchanged so callers may mix forms.
fn trusted_key_base64(trusted: &str) -> &str {
    trusted.rsplit(':').next().unwrap_or(trusted)
}

/// Decode a `name:Ed25519:<base64>` trusted key into its name and raw
/// 32-byte Ed25519 public key.
///
/// The base64 blob is the full SSH wire public-key blob (`string
/// "ssh-ed25519" + string key(32)`), so this unwraps it to the bare key
/// bytes a [`VerifyingKey`] is built from. The name is everything before the
/// first `:`; a bare base64 blob (no `name:Ed25519:` prefix) yields an empty
/// name. This is the raw key narinfo `Sig:` signatures verify against — see
/// `aos-core`'s narinfo signing, which signs with the same Ed25519 key the
/// registry roster pins.
///
/// # Errors
///
/// Returns an error when the base64 cannot be decoded or does not unwrap to
/// a 32-byte `ssh-ed25519` key blob.
pub fn trusted_key_ed25519(trusted: &str) -> Result<(String, [u8; 32])> {
    let name = match trusted.split_once(':') {
        Some((name, _)) => name.to_string(),
        None => String::new(),
    };
    let blob = base64::engine::general_purpose::STANDARD
        .decode(trusted_key_base64(trusted))
        .context("decoding trusted key base64")?;
    let key = parse_ed25519_key_blob(&blob)?;
    Ok((name, key))
}

fn parse_ed25519_key_blob(blob: &[u8]) -> Result<[u8; 32]> {
    let mut cursor = blob;
    let key_type = read_string(&mut cursor).context("public key type")?;
    if key_type != KEY_TYPE.as_bytes() {
        bail!(
            "unsupported public key type '{}'",
            String::from_utf8_lossy(&key_type)
        );
    }
    let key = read_string(&mut cursor).context("public key bytes")?;
    key.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes, got {}", key.len()))
}

fn parse_ed25519_sig_blob(blob: &[u8]) -> Result<[u8; 64]> {
    let mut cursor = blob;
    let sig_type = read_string(&mut cursor).context("signature type")?;
    if sig_type != KEY_TYPE.as_bytes() {
        bail!(
            "unsupported signature type '{}'",
            String::from_utf8_lossy(&sig_type)
        );
    }
    let sig = read_string(&mut cursor).context("signature bytes")?;
    sig.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must be 64 bytes, got {}", sig.len()))
}

fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if cursor.len() < n {
        bail!("truncated SSH wire data");
    }
    let (head, rest) = cursor.split_at(n);
    *cursor = rest;
    Ok(head)
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32> {
    // `take` guarantees exactly four bytes, making the indexing infallible.
    let bytes = take(cursor, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_string(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    let len = read_u32(cursor)? as usize;
    Ok(take(cursor, len)?.to_vec())
}

fn write_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = test_key();
        let trusted = trusted_key_line("test", &key.verifying_key());
        let armored = sign_armored(b"payload bytes", &key);
        let matched =
            verify_armored(&armored, b"payload bytes", std::slice::from_ref(&trusted)).unwrap();
        assert_eq!(matched, trusted.rsplit(':').next().unwrap());
    }

    #[test]
    fn trusted_key_ed25519_unwraps_name_and_raw_key() {
        let key = test_key();
        let trusted = trusted_key_line("demo", &key.verifying_key());
        let (name, raw) = trusted_key_ed25519(&trusted).unwrap();
        assert_eq!(name, "demo");
        assert_eq!(&raw, key.verifying_key().as_bytes());
        // A non-key string is rejected rather than yielding a bogus key.
        assert!(trusted_key_ed25519("not:a:realkey").is_err());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = test_key();
        let trusted = trusted_key_line("test", &key.verifying_key());
        let armored = sign_armored(b"payload", &key);
        assert!(verify_armored(&armored, b"tampered", &[trusted]).is_err());
    }

    #[test]
    fn verify_rejects_untrusted_signer() {
        let signer = test_key();
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let trusted = trusted_key_line("other", &other.verifying_key());
        let armored = sign_armored(b"payload", &signer);
        let err = verify_armored(&armored, b"payload", &[trusted]).unwrap_err();
        assert!(err.to_string().contains("not trusted"));
    }

    #[test]
    fn verify_requires_trusted_keys() {
        let key = test_key();
        let armored = sign_armored(b"p", &key);
        assert!(verify_armored(&armored, b"p", &[]).is_err());
    }

    #[test]
    fn trusted_key_line_matches_openssh_prefix() {
        // The SSH wire blob for ssh-ed25519 always starts with the type
        // string, which is the well-known AAAAC3NzaC1lZDI1NTE5 prefix.
        let line = trusted_key_line("x", &test_key().verifying_key());
        let b64 = line.rsplit(':').next().unwrap();
        assert!(b64.starts_with("AAAAC3NzaC1lZDI1NTE5"));
    }
}
