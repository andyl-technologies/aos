//! Nix binary-cache narinfo signing: the `Sig:` line and `trusted-public-keys`
//! entry a cache emits for a retained signing-key generation.
//!
//! This is the **Nix** signature scheme — distinct from the SSHSIG armor
//! [`crate::signing`] uses for git tags/partitions. Nix signs a deterministic
//! *fingerprint* of the store path's metadata with a raw Ed25519 key and
//! advertises the verifying key as `name:base64(pubkey)`.
//!
//! # Fingerprint
//!
//! Nix's narinfo fingerprint (see `nix/libstore` `fingerprint`) is:
//!
//! ```text
//! 1;<storePath>;<narHash>;<narSize>;<ref1>,<ref2>,…
//! ```
//!
//! where `<storePath>` is the absolute store path, `<narHash>` is the
//! `sha256:<base32>` string verbatim from the narinfo, `<narSize>` is the
//! decimal byte count, and the references are the **absolute** store paths of
//! the direct references, comma-joined (empty when there are none). The raw
//! Ed25519 signature over the fingerprint bytes, base64-encoded, becomes
//! `Sig: <key-name>:<base64-sig>`.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};

/// The `name:base64(pubkey)` line a client pins in `trusted-public-keys`.
///
/// The base64 is of the raw 32-byte Ed25519 verifying key — the Nix cache
/// public-key format, **not** the SSH wire format
/// [`crate::signing`]/`sshsig` uses.
#[must_use]
pub fn nix_public_key_line(key_name: &str, key: &VerifyingKey) -> String {
    format!(
        "{key_name}:{}",
        base64::engine::general_purpose::STANDARD.encode(key.to_bytes())
    )
}

/// Converts a canonical retained raw public key into Nix's padded key line.
///
/// # Errors
///
/// Returns an error when the public key is not canonical unpadded base64 or
/// does not contain one valid 32-byte Ed25519 verification key.
pub fn nix_public_key_from_raw(key_name: &str, public_key: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(public_key)
        .context("signing-key public key is not canonical base64")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing-key public key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes).context("signing-key public key is invalid")?;
    Ok(nix_public_key_line(key_name, &key))
}

/// Derives the Nix cache public-key line from an SSH trusted-key line.
///
/// A signing-key generation may publish its public half as an SSHSIG trusted-key line
/// `name:Ed25519:<base64 ssh-wire-blob>` (used for git tag/partition
/// verification). A Nix substituter instead pins `name:<base64 raw-32-byte-key>`.
/// This converts the former to the latter by parsing the SSH `ssh-ed25519` wire
/// blob (`string "ssh-ed25519"` then `string <32-byte key>`) and re-encoding the
/// raw key — no secret material involved, so it needs no sealer.
///
/// Returns `None` when the line is not a well-formed `name:Ed25519:<base64>` or
/// the decoded blob is not a valid `ssh-ed25519` public key.
#[must_use]
pub fn nix_public_key_from_ssh_line(ssh_line: &str) -> Option<String> {
    // `name:Ed25519:<base64>` — the name may itself contain no ':'.
    let (name, rest) = ssh_line.split_once(':')?;
    let b64 = rest.strip_prefix("Ed25519:")?;
    let blob = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    // SSH wire: u32 len + "ssh-ed25519", then u32 len(32) + 32-byte key.
    let read_field = |buf: &[u8], at: usize| -> Option<(usize, usize)> {
        let end = at.checked_add(4)?;
        let len = u32::from_be_bytes(buf.get(at..end)?.try_into().ok()?) as usize;
        let field_end = end.checked_add(len)?;
        if field_end > buf.len() {
            return None;
        }
        Some((end, field_end))
    };
    let (a0, a1) = read_field(&blob, 0)?;
    if &blob[a0..a1] != b"ssh-ed25519" {
        return None;
    }
    let (k0, k1) = read_field(&blob, a1)?;
    let key = &blob[k0..k1];
    if key.len() != 32 {
        return None;
    }
    Some(format!(
        "{name}:{}",
        base64::engine::general_purpose::STANDARD.encode(key)
    ))
}

/// Build the Nix narinfo fingerprint for a store path.
///
/// `references` are the **absolute** store paths of the direct references.
#[must_use]
pub fn fingerprint(
    store_path: &str,
    nar_hash: &str,
    nar_size: i64,
    references: &[String],
) -> String {
    format!(
        "1;{store_path};{nar_hash};{nar_size};{}",
        references.join(",")
    )
}

/// The narinfo fields a signature is computed over, parsed from narinfo text.
struct NarinfoFields {
    store_path: String,
    nar_hash: String,
    nar_size: i64,
    /// Absolute store paths of the direct references.
    references: Vec<String>,
}

/// Parse the signing-relevant fields out of narinfo text.
///
/// `References` entries are basenames relative to the store; they are resolved
/// to absolute paths against the store directory (the dirname of `StorePath`).
fn parse_fields(narinfo: &str) -> Result<NarinfoFields> {
    let mut store_path = None;
    let mut nar_hash = None;
    let mut nar_size = None;
    let mut references: Vec<String> = Vec::new();
    for line in narinfo.lines() {
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        match key {
            "StorePath" => store_path = Some(value.trim().to_string()),
            "NarHash" => nar_hash = Some(value.trim().to_string()),
            "NarSize" => {
                nar_size = Some(
                    value
                        .trim()
                        .parse::<i64>()
                        .context("narinfo NarSize is not an integer")?,
                );
            }
            "References" => {
                references = value.split_whitespace().map(str::to_string).collect();
            }
            _ => {}
        }
    }
    let store_path = store_path.context("narinfo missing StorePath")?;
    let nar_hash = nar_hash.context("narinfo missing NarHash")?;
    let nar_size = nar_size.context("narinfo missing NarSize")?;
    // Resolve reference basenames to absolute paths against the store dir.
    let store_dir = store_path
        .rsplit_once('/')
        .map(|(dir, _)| dir.to_string())
        .unwrap_or_default();
    let references = references
        .into_iter()
        .map(|r| {
            if r.starts_with('/') {
                r
            } else {
                format!("{store_dir}/{r}")
            }
        })
        .collect();
    Ok(NarinfoFields {
        store_path,
        nar_hash,
        nar_size,
        references,
    })
}

/// Verifies that a narinfo carries a valid signature from one exact public key.
///
/// Other producers' `Sig:` lines are ignored. The selected key's line must be
/// present and must verify over Nix's canonical narinfo fingerprint.
///
/// # Errors
///
/// Returns an error for malformed narinfo fields, malformed public key or
/// signature bytes, a missing selected-key signature, or failed verification.
pub fn verify_narinfo(narinfo: &str, key_name: &str, public_key: &str) -> Result<()> {
    let public_key = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(public_key)
        .context("signing-key public key is not canonical base64")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing-key public key is not 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).context("signing-key public key is invalid")?;
    let fields = parse_fields(narinfo)?;
    let fingerprint = fingerprint(
        &fields.store_path,
        &fields.nar_hash,
        fields.nar_size,
        &fields.references,
    );
    let prefix = format!("Sig: {key_name}:");
    let encoded = narinfo
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .context("narinfo is missing the selected signing-key signature")?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("narinfo signature is not base64")?;
    let signature = ed25519_dalek::Signature::from_slice(&signature)
        .context("narinfo signature is not Ed25519")?;
    verifying_key
        .verify(fingerprint.as_bytes(), &signature)
        .context("narinfo signature verification failed")
}

/// Compute the `Sig: <name>:<base64>` line for a narinfo with `signing_key`.
///
/// # Errors
///
/// Returns an error when the narinfo is missing `StorePath`/`NarHash`/`NarSize`
/// or `NarSize` is not an integer.
pub fn sig_line(narinfo: &str, key_name: &str, signing_key: &SigningKey) -> Result<String> {
    let fields = parse_fields(narinfo)?;
    let fp = fingerprint(
        &fields.store_path,
        &fields.nar_hash,
        fields.nar_size,
        &fields.references,
    );
    let sig = signing_key.sign(fp.as_bytes());
    Ok(format!(
        "Sig: {key_name}:{}",
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    ))
}

/// Append a hub `Sig:` line to narinfo text, signing it with `signing_key`.
///
/// Idempotent for the same key: an existing `Sig:` line carrying `key_name`'s
/// signature is replaced rather than duplicated, so re-uploading or re-signing
/// the same narinfo does not accumulate stale lines. Other keys' `Sig:` lines
/// (e.g. a client's own signature) are preserved.
///
/// # Errors
///
/// Returns an error when the narinfo cannot be parsed for signing (see
/// [`sig_line`]).
pub fn sign_narinfo(narinfo: &str, key_name: &str, signing_key: &SigningKey) -> Result<String> {
    if narinfo.is_empty() {
        bail!("cannot sign empty narinfo");
    }
    let new_sig = sig_line(narinfo, key_name, signing_key)?;
    let prefix = format!("Sig: {key_name}:");
    // Drop any prior signature from this same key; keep all other lines.
    let mut out: String = narinfo
        .lines()
        .filter(|line| !line.starts_with(&prefix))
        .map(|line| format!("{line}\n"))
        .collect();
    out.push_str(&new_sig);
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NARINFO: &str = "StorePath: /nix/store/aaaa-foo-1.0\n\
        URL: nar/bbbb.nar.zst\n\
        Compression: zstd\n\
        NarHash: sha256:1xyz\n\
        NarSize: 100\n\
        References: cccc-bar-2.0 dddd-baz-3.0\n";

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn fingerprint_matches_nix_format() {
        let fp = fingerprint(
            "/nix/store/aaaa-foo-1.0",
            "sha256:1xyz",
            100,
            &[
                "/nix/store/cccc-bar-2.0".to_string(),
                "/nix/store/dddd-baz-3.0".to_string(),
            ],
        );
        assert_eq!(
            fp,
            "1;/nix/store/aaaa-foo-1.0;sha256:1xyz;100;\
             /nix/store/cccc-bar-2.0,/nix/store/dddd-baz-3.0"
        );
    }

    #[test]
    fn no_references_yields_empty_ref_segment() {
        let fp = fingerprint("/nix/store/x-a", "sha256:z", 1, &[]);
        assert_eq!(fp, "1;/nix/store/x-a;sha256:z;1;");
    }

    #[test]
    fn parse_resolves_reference_basenames_to_absolute() {
        let f = parse_fields(NARINFO).unwrap();
        assert_eq!(f.store_path, "/nix/store/aaaa-foo-1.0");
        assert_eq!(f.nar_hash, "sha256:1xyz");
        assert_eq!(f.nar_size, 100);
        assert_eq!(
            f.references,
            vec![
                "/nix/store/cccc-bar-2.0".to_string(),
                "/nix/store/dddd-baz-3.0".to_string()
            ]
        );
    }

    #[test]
    fn signature_verifies_against_the_public_key() {
        let key = test_key();
        let line = sig_line(NARINFO, "acme-cache", &key).unwrap();
        let b64 = line
            .strip_prefix("Sig: acme-cache:")
            .expect("sig line shape");
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        let fp = fingerprint(
            "/nix/store/aaaa-foo-1.0",
            "sha256:1xyz",
            100,
            &[
                "/nix/store/cccc-bar-2.0".to_string(),
                "/nix/store/dddd-baz-3.0".to_string(),
            ],
        );
        key.verifying_key()
            .verify(fp.as_bytes(), &sig)
            .expect("hub signature verifies against the cache public key");
    }

    #[test]
    fn selected_public_generation_verifies_narinfo() {
        let key = test_key();
        let signed = sign_narinfo(NARINFO, "acme-cache", &key).unwrap();
        let public_key =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(key.verifying_key().to_bytes());
        verify_narinfo(&signed, "acme-cache", &public_key).unwrap();
        assert!(verify_narinfo(NARINFO, "acme-cache", &public_key).is_err());
    }

    #[test]
    fn sign_narinfo_appends_and_is_idempotent_per_key() {
        let key = test_key();
        let signed = sign_narinfo(NARINFO, "acme-cache", &key).unwrap();
        let count = signed.matches("Sig: acme-cache:").count();
        assert_eq!(count, 1, "exactly one hub sig line");
        // Re-signing replaces rather than duplicates.
        let resigned = sign_narinfo(&signed, "acme-cache", &key).unwrap();
        assert_eq!(resigned.matches("Sig: acme-cache:").count(), 1);
        // The original fields survive.
        assert!(resigned.contains("StorePath: /nix/store/aaaa-foo-1.0"));
        assert!(resigned.contains("URL: nar/bbbb.nar.zst"));
    }

    #[test]
    fn sign_narinfo_preserves_other_keys_signatures() {
        let key = test_key();
        let with_client_sig = format!("{NARINFO}Sig: client-key:deadbeef\n");
        let signed = sign_narinfo(&with_client_sig, "acme-cache", &key).unwrap();
        assert!(signed.contains("Sig: client-key:deadbeef"));
        assert_eq!(signed.matches("Sig: acme-cache:").count(), 1);
    }

    #[test]
    fn ssh_line_converts_to_the_same_nix_public_key() {
        let key = test_key();
        // The SSHSIG trusted-key line for the generation...
        let ssh_line =
            aos_registry_surface::sshsig::trusted_key_line("acme-cache", &key.verifying_key());
        // ...converts to the Nix cache public-key line for the same raw key.
        let nix_line = nix_public_key_from_ssh_line(&ssh_line).expect("valid ssh line converts");
        assert_eq!(
            nix_line,
            nix_public_key_line("acme-cache", &key.verifying_key())
        );
    }

    #[test]
    fn ssh_line_conversion_rejects_malformed_input() {
        assert!(nix_public_key_from_ssh_line("not-a-line").is_none());
        assert!(nix_public_key_from_ssh_line("name:Ed25519:!!!notbase64").is_none());
        assert!(nix_public_key_from_ssh_line("name:RSA:AAAA").is_none());
    }

    #[test]
    fn public_key_line_is_name_colon_base64() {
        let key = test_key();
        let line = nix_public_key_line("acme-cache", &key.verifying_key());
        assert!(line.starts_with("acme-cache:"));
        let b64 = line.strip_prefix("acme-cache:").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert_eq!(decoded.len(), 32, "raw Ed25519 public key is 32 bytes");
        let retained =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(key.verifying_key().to_bytes());
        assert_eq!(
            nix_public_key_from_raw("acme-cache", &retained).unwrap(),
            line
        );
    }
}
