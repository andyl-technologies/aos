//! Independent verification of Linux appended module signatures.
//!
//! Linux stores a detached PKCS#7 object immediately before a fixed magic
//! trailer. The finalizer requires the signed module to preserve every
//! unsigned byte, parses the trailer with checked arithmetic, and asks the
//! assembly-pinned OpenSSL to verify the PKCS#7 object against only the
//! captured module certificate.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

use crate::tools::PinnedTool;

const MODULE_SIGNATURE_MAGIC: &[u8] = b"~Module signature appended~\n";
const MODULE_SIGNATURE_HEADER_BYTES: usize = 12;
const PKCS7_ID_TYPE: u8 = 2;
const MAX_PKCS7_BYTES: usize = 4 * 1024 * 1024;

/// Verifies a provider-produced signed module against its exact predecessor.
///
/// # Errors
///
/// Returns an error when the signed module changes predecessor bytes, carries
/// a malformed or oversized trailer, uses a non-PKCS#7 signature, or fails
/// cryptographic verification against `certificate`.
pub async fn verify_signed_module(
    unsigned: &Path,
    signed: &Path,
    certificate: &Path,
    openssl: &PinnedTool,
    scratch: &Path,
) -> Result<()> {
    let unsigned_bytes = fs::read(unsigned)
        .with_context(|| format!("reading unsigned module {}", unsigned.display()))?;
    let signed_bytes =
        fs::read(signed).with_context(|| format!("reading signed module {}", signed.display()))?;
    if !signed_bytes.starts_with(&unsigned_bytes) {
        bail!("module signer changed bytes preceding the appended signature");
    }
    let pkcs7 = appended_pkcs7(&signed_bytes, unsigned_bytes.len())?;

    let signature_path = scratch.join("module-signature.der");
    let verified_path = scratch.join("verified-module-content");
    fs::write(&signature_path, pkcs7)?;
    let _ = openssl
        .run(
            [
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                path_text(&signature_path)?,
                "-content",
                path_text(unsigned)?,
                "-nointern",
                "-certfile",
                path_text(certificate)?,
                "-noverify",
                "-out",
                path_text(&verified_path)?,
            ],
            0,
        )
        .await?;
    if fs::read(&verified_path)? != unsigned_bytes {
        bail!("OpenSSL recovered content differs from the unsigned module");
    }
    fs::remove_file(signature_path)?;
    fs::remove_file(verified_path)?;
    Ok(())
}

fn appended_pkcs7(bytes: &[u8], unsigned_length: usize) -> Result<&[u8]> {
    let magic_start = bytes
        .len()
        .checked_sub(MODULE_SIGNATURE_MAGIC.len())
        .context("signed module is shorter than its magic trailer")?;
    if &bytes[magic_start..] != MODULE_SIGNATURE_MAGIC {
        bail!("signed module lacks the Linux module-signature trailer");
    }
    let header_start = magic_start
        .checked_sub(MODULE_SIGNATURE_HEADER_BYTES)
        .context("signed module is shorter than its signature header")?;
    let header = &bytes[header_start..magic_start];
    let signer_length = usize::from(header[3]);
    let key_id_length = usize::from(header[4]);
    if header[2] != PKCS7_ID_TYPE || header[5..8] != [0, 0, 0] {
        bail!("module signer returned an unsupported signature header");
    }
    let signature_length = usize::try_from(u32::from_be_bytes([
        header[8], header[9], header[10], header[11],
    ]))?;
    if signature_length == 0 || signature_length > MAX_PKCS7_BYTES {
        bail!("module PKCS#7 signature is empty or oversized");
    }
    let payload_bytes = signer_length
        .checked_add(key_id_length)
        .and_then(|length| length.checked_add(signature_length))
        .context("module signature length overflow")?;
    let payload_start = header_start
        .checked_sub(payload_bytes)
        .context("module signature lengths exceed the signed file")?;
    if payload_start != unsigned_length {
        bail!("module signature does not immediately follow the unsigned predecessor");
    }
    let signature_start = payload_start
        .checked_add(signer_length)
        .and_then(|offset| offset.checked_add(key_id_length))
        .context("module signature offset overflow")?;
    Ok(&bytes[signature_start..header_start])
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("module verification path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bounded_appended_pkcs7_object() -> Result<()> {
        let unsigned = b"module";
        let signature = b"der";
        let mut bytes = unsigned.to_vec();
        bytes.extend_from_slice(signature);
        bytes.extend_from_slice(&[0, 0, PKCS7_ID_TYPE, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&u32::try_from(signature.len())?.to_be_bytes());
        bytes.extend_from_slice(MODULE_SIGNATURE_MAGIC);
        assert_eq!(appended_pkcs7(&bytes, unsigned.len())?, signature);
        Ok(())
    }

    #[test]
    fn rejects_changed_predecessor_boundary() -> Result<()> {
        let mut bytes = b"moduleder".to_vec();
        bytes.extend_from_slice(&[0, 0, PKCS7_ID_TYPE, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(MODULE_SIGNATURE_MAGIC);
        assert!(appended_pkcs7(&bytes, 5).is_err());
        Ok(())
    }
}
