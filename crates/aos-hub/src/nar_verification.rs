//! Signature and content verification for mirrored Nix archive payloads.
//!
//! Narinfo signatures authenticate the signed `NarHash`; NAR verification
//! decompresses the downloaded bytes and checks that hash. The mirror and
//! pull-through paths use these helpers before accepting cache content.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Verifies that a narinfo carries a valid Ed25519 signature by a trusted key.
///
/// A narinfo signature covers the Nix fingerprint formed from its store path,
/// NAR hash, NAR size, and references. Trusted keys use the registry roster
/// form `name:Ed25519:<base64-wire-key>`; the key name must also match the
/// signature name.
///
/// # Errors
///
/// Returns an error when the trusted-key set is empty, the narinfo cannot be
/// parsed, it has no signature, or no signature verifies with a trusted key.
pub fn verify_narinfo_signature(narinfo: &str, trusted_keys: &[String]) -> Result<()> {
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if trusted_keys.is_empty() {
        anyhow::bail!("cannot verify narinfo signature: trusted key set is empty");
    }

    let info =
        aos_core::nar::info::parse(narinfo).context("parsing narinfo for signature check")?;
    if info.signatures.is_empty() {
        anyhow::bail!("narinfo for {} carries no Sig", info.store_path);
    }

    let store_dir = info
        .store_path
        .rsplit_once('/')
        .map(|(directory, _)| directory.to_string())
        .unwrap_or_default();
    let references: Vec<String> = info
        .references
        .iter()
        .map(|reference| {
            let basename = reference.rsplit('/').next().unwrap_or(reference);
            if store_dir.is_empty() {
                basename.to_string()
            } else {
                format!("{store_dir}/{basename}")
            }
        })
        .collect();
    let fingerprint = aos_core::nar::cache::NarInfoSigner::fingerprint(
        &info.store_path,
        &info.nar_hash,
        info.nar_size as i64,
        &references,
    );

    for signature_line in &info.signatures {
        let Some((signature_name, signature_base64)) = signature_line.split_once(':') else {
            continue;
        };
        let Ok(signature_bytes) =
            base64::engine::general_purpose::STANDARD.decode(signature_base64)
        else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            continue;
        };

        for trusted_key in trusted_keys {
            let Ok((key_name, raw_key)) =
                aos_registry_surface::sshsig::trusted_key_ed25519(trusted_key)
            else {
                continue;
            };
            if key_name != signature_name {
                continue;
            }

            let Ok(verifying_key) = VerifyingKey::from_bytes(&raw_key) else {
                continue;
            };
            if verifying_key
                .verify(fingerprint.as_bytes(), &signature)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    anyhow::bail!(
        "narinfo for {} has no valid Sig by a trusted key",
        info.store_path
    )
}

/// Verifies downloaded NAR bytes against a narinfo's signed `NarHash`.
///
/// The downloaded bytes are decompressed according to `Compression` before
/// hashing because `NarHash` authenticates the uncompressed archive. A present
/// `FileHash` is also checked as an early consistency test, but it is never the
/// authoritative check because the narinfo signature does not cover it.
///
/// # Errors
///
/// Returns an error when a required field is absent or unsupported, a declared
/// hash is malformed or mismatched, decompression fails, or decompressed output
/// exceeds the NAR size limit.
pub fn verify_nar_against_narinfo(narinfo: &str, bytes: &[u8]) -> Result<()> {
    let nar_hash =
        narinfo_field(narinfo, "NarHash").context("narinfo has no signed NarHash to verify")?;

    if let Some(file_hash) = narinfo_field(narinfo, "FileHash") {
        let compressed_digest = Sha256::digest(bytes);
        if sha256_hash_matches(&file_hash, &compressed_digest) != Some(true) {
            anyhow::bail!("NAR bytes do not match the narinfo FileHash");
        }
    }

    let compression = nar_compression(narinfo)
        .context("narinfo has a missing or unsupported Compression value")?;
    let plain = decompress_nar_bounded(bytes, compression, crate::fetch::MAX_NAR_BYTES as usize)?;
    let digest = Sha256::digest(&plain);

    if sha256_hash_matches(&nar_hash, &digest) != Some(true) {
        anyhow::bail!("NAR bytes do not match the narinfo's signed NarHash");
    }

    Ok(())
}

fn narinfo_field(text: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NarCompression {
    None,
    Zstd,
    Xz,
    Bzip2,
    Gzip,
}

fn nar_compression(narinfo: &str) -> Option<NarCompression> {
    match narinfo_field(narinfo, "Compression")?.as_str() {
        "none" => Some(NarCompression::None),
        "zstd" => Some(NarCompression::Zstd),
        "xz" | "lzma" => Some(NarCompression::Xz),
        "bzip2" => Some(NarCompression::Bzip2),
        "gzip" | "gz" => Some(NarCompression::Gzip),
        _ => None,
    }
}

fn decompress_nar_bounded(
    bytes: &[u8],
    compression: NarCompression,
    size_limit: usize,
) -> Result<Vec<u8>> {
    match compression {
        NarCompression::None => {
            if bytes.len() > size_limit {
                anyhow::bail!("NAR exceeds the {size_limit}-byte size limit");
            }
            Ok(bytes.to_vec())
        }
        NarCompression::Zstd => {
            let decoder = zstd::Decoder::new(bytes).context("opening zstd NAR decoder")?;
            read_to_end_bounded(decoder, size_limit)
        }
        NarCompression::Xz => {
            let mut output = Vec::new();
            let mut input = std::io::Cursor::new(bytes);
            if lzma_rs::xz_decompress(&mut input, &mut output).is_err() {
                output.clear();
                let mut input = std::io::Cursor::new(bytes);
                lzma_rs::lzma_decompress(&mut input, &mut output)
                    .context("decompressing xz/lzma NAR")?;
            }
            if output.len() > size_limit {
                anyhow::bail!("decompressed NAR exceeds the {size_limit}-byte size limit");
            }
            Ok(output)
        }
        NarCompression::Bzip2 => {
            read_to_end_bounded(bzip2_rs::DecoderReader::new(bytes), size_limit)
        }
        NarCompression::Gzip => {
            read_to_end_bounded(flate2::read::GzDecoder::new(bytes), size_limit)
        }
    }
}

fn read_to_end_bounded<R: std::io::Read>(reader: R, size_limit: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let mut output = Vec::new();
    reader
        .take((size_limit as u64).saturating_add(1))
        .read_to_end(&mut output)
        .context("decompressing NAR")?;
    if output.len() > size_limit {
        anyhow::bail!("decompressed NAR exceeds the {size_limit}-byte size limit");
    }

    Ok(output)
}

fn sha256_hash_matches(declared: &str, digest: &[u8]) -> Option<bool> {
    if let Some(encoded) = declared.strip_prefix("sha256:") {
        if encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Some(encoded.eq_ignore_ascii_case(&hex::encode(digest)));
        }
        return Some(encoded == encode_nix_base32(digest));
    }
    if let Some(encoded) = declared.strip_prefix("sha256-") {
        use base64::Engine as _;

        return Some(encoded == base64::engine::general_purpose::STANDARD.encode(digest));
    }
    None
}

const NIX_BASE32: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

fn encode_nix_base32(bytes: &[u8]) -> String {
    let length = (bytes.len() * 8).div_ceil(5);
    let mut encoded = String::with_capacity(length);

    for digit in (0..length).rev() {
        let bit = digit * 5;
        let byte_index = bit / 8;
        let shift = bit % 8;
        let mut value = (bytes[byte_index] >> shift) as u16;
        if byte_index + 1 < bytes.len() {
            value |= (bytes[byte_index + 1] as u16) << (8 - shift);
        }
        encoded.push(NIX_BASE32[(value & 0x1f) as usize] as char);
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;

    fn signed_narinfo(nar_bytes: &[u8]) -> (String, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let trusted_key =
            aos_registry_surface::sshsig::trusted_key_line("demo", &key.verifying_key());

        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&key.to_bytes());
        secret.extend_from_slice(key.verifying_key().as_bytes());
        let secret = base64::engine::general_purpose::STANDARD.encode(secret);
        let signer =
            aos_core::nar::cache::NarInfoSigner::from_key_content(&format!("demo:{secret}"))
                .expect("fixture signing key is valid");

        let store_path = "/var/lib/store/abc123-pkg";
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(nar_bytes)));
        let size = nar_bytes.len() as i64;
        let fingerprint =
            aos_core::nar::cache::NarInfoSigner::fingerprint(store_path, &hash, size, &[]);
        let signature = signer.sign(&fingerprint).expect("fixture signing succeeds");
        let narinfo = format!(
            "StorePath: {store_path}\nURL: nar/abc.nar\nCompression: none\n\
             FileHash: {hash}\nFileSize: {size}\nNarHash: {hash}\nNarSize: {size}\nSig: {signature}\n"
        );

        (narinfo, trusted_key)
    }

    #[test]
    fn signature_requires_a_trusted_signer() {
        let (narinfo, trusted_key) = signed_narinfo(b"narbytes");

        verify_narinfo_signature(&narinfo, &[trusted_key]).expect("trusted signature verifies");
        assert!(verify_narinfo_signature(&narinfo, &[]).is_err());
    }

    #[test]
    fn archive_must_match_the_signed_nar_hash() {
        let bytes = b"narbytes";
        let (narinfo, _) = signed_narinfo(bytes);

        verify_nar_against_narinfo(&narinfo, bytes).expect("matching archive verifies");
        assert!(verify_nar_against_narinfo(&narinfo, b"tampered").is_err());
    }

    #[test]
    fn hash_encodings_match_sha256() {
        let digest =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("fixture digest is valid hex");

        assert_eq!(
            sha256_hash_matches(
                "sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s",
                &digest
            ),
            Some(true)
        );
    }
}
