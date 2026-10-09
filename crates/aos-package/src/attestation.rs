//! TPM quote primitives and durable publication for native package generations.
//!
//! [`native`] binds checked profile generations to immutable evaluation inputs,
//! their original release or image admission, and independently measured image
//! expectations. [`QuoteChecker`] keeps TPM signature verification separate from
//! source replay; quote records never provide their own trust anchors.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod native;
pub(crate) mod native_cli;

/// Identifies evidence for which hardware or authenticated image pins are unavailable.
pub const QUOTE_STATUS_UNQUOTED: &str = "unquoted-tpm-unavailable";
/// Identifies a complete TPM quote over the canonical native record.
pub const QUOTE_STATUS_QUOTED: &str = "quoted";

/// Produces a TPM2 quote binding a record hash to PCR {7, 11, 12, 15}.
///
/// The production implementation extends `record_hash` into PCR 15 and runs
/// `tpm2_quote` (reusing the
/// [`crate::package_attestation`] machinery); tests inject a deterministic
/// mock so the record/compute logic is exercised off-host.
pub trait TpmQuoter {
    /// Extend PCR 15 with `record_hash`, then quote PCR {7, 11, 12, 15} with
    /// `nonce`. Returns the opaque quote blob.
    ///
    /// # Errors
    ///
    /// Returns an error when the TPM cannot be driven (no device, tool failure).
    fn quote(&self, record_hash: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The PCR values a verifier recovered from a checked quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedPcrs {
    /// SB-state PCR 7, lowercase hex.
    pub pcr7: String,
    /// Measured-boot PCR 11, lowercase hex.
    pub pcr11: String,
    /// Boot-input PCR 12, lowercase hex.
    pub pcr12: String,
    /// Application PCR 15 (record binding), lowercase hex.
    pub pcr15: String,
}

/// Verifies a quote signature under an attestation key and recovers its PCRs.
///
/// The production implementation checks the TPM2B_ATTEST + signature under the
/// AK public key over `(PCR{7,11,12,15}, nonce)`; tests inject a mock that returns
/// scripted PCRs (or an error to model a bad signature).
pub trait QuoteChecker {
    /// Verify `quote` over `nonce` and return the quoted PCR values.
    ///
    /// # Errors
    ///
    /// Returns an error when the quote signature is invalid under the verifier's
    /// pinned AK, the nonce does not match, or the blob cannot be parsed.
    fn check(&self, quote: &[u8], nonce: &[u8]) -> anyhow::Result<QuotedPcrs>;
}

fn generation_quote_status(
    quote_required: bool,
    has_tpm: bool,
    has_root_verity: bool,
) -> Result<Option<&'static str>> {
    if !has_tpm {
        if quote_required {
            bail!("measured boot requires a TPM-backed generation attestation quote");
        }
        return Ok(Some(QUOTE_STATUS_UNQUOTED));
    }
    if !has_root_verity {
        if quote_required {
            bail!("TPM-backed generation attestation requires image root verity metadata");
        }
        return Ok(Some(QUOTE_STATUS_UNQUOTED));
    }
    Ok(None)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddedQuote {
    schema: String,
    nonce: String,
    pcr_selection: String,
    quoted_pcr15: String,
    ak_public: String,
    quote_message: String,
    quote_signature: String,
    quote_pcrs: String,
}

fn remove_private_quote_dir_if_exists(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "generation attestation quote path is not a private directory: {}",
            path.display()
        );
    }
    std::fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))
}

fn remove_file_durable_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("removing {}", path.display())),
    }
    let parent = path
        .parent()
        .with_context(|| format!("path has no parent: {}", path.display()))?;
    File::open(parent)
        .with_context(|| format!("opening {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", parent.display()))
}

fn read_hex(path: &Path) -> Result<String> {
    std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))
        .map(hex::encode)
}

fn write_canonical_json_atomic<T: Serialize>(path: &Path, record: &T) -> Result<()> {
    let value = serde_json::to_value(record).context("serializing generation attestation")?;
    let bytes = aos_contract::canonical::canonical_json(&value)?;
    let parent = path
        .parent()
        .context("generation attestation path has no parent")?;
    let temporary = parent.join(format!(".gen-attestation.json.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("writing {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("publishing {}", path.display()))?;
    File::open(parent)
        .with_context(|| format!("opening {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", parent.display()))
}

// Authenticated dm-verity roots are canonical lowercase SHA-256 values.
fn is_verity_roothash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn expected_app_pcr_after(
    baseline: Option<&str>,
    prior: &[String],
    digest: &[u8; 32],
) -> Result<String> {
    let mut pcr = match baseline {
        Some(value) => hex::decode(strip_sha256(value))
            .with_context(|| format!("decoding PCR 15 baseline {value:?}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("PCR 15 baseline is not SHA-256"))?,
        None => [0_u8; 32],
    };
    for event in prior {
        let decoded = hex::decode(strip_sha256(event))
            .with_context(|| format!("decoding prior PCR 15 event digest {event:?}"))?;
        let event: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("prior PCR 15 event digest is not SHA-256"))?;
        pcr = extend_app_pcr(&pcr, &event);
    }
    Ok(hex::encode(extend_app_pcr(&pcr, digest)))
}

fn extend_app_pcr(pcr: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(*pcr);
    hasher.update(digest);
    hasher.finalize().into()
}

fn strip_sha256(s: &str) -> &str {
    s.strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("sha256-"))
        .unwrap_or(s)
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
