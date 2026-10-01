//! Explicit archive custody from bounded private files and external signer pins.
//!
//! Raw signing/wrapping/exclusion material is exactly 32 bytes. No Hub/runtime
//! key, environment fallback, key creation, provider lookup or source unsealing
//! occurs here. Known exclusions do not establish global key separation.
//!
//! ```json
//! {"version":1,"signers":[{"id":"offline-export","ed25519_public_key_hex":"<64 lowercase hex digits>"}]}
//! ```

use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};
use aos_hub_core::snapshot::archive::root::{
    ArchiveSignerTrust, ArchiveSigningKey, ArchiveWrappingKey, ArchiveWrappingKeys,
    ExcludedArchiveKey,
};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Explicit paths and identities for independent metadata/private wrapping.
pub struct WrappingFiles {
    /// Opaque metadata wrapping identity, never used as a filesystem name.
    pub metadata_id: String,
    /// Existing owner-private file containing exactly 32 raw bytes.
    pub metadata_file: PathBuf,
    /// Opaque private wrapping identity distinct from metadata identity.
    pub private_id: String,
    /// Existing owner-private file containing exactly 32 raw bytes.
    pub private_file: PathBuf,
}

/// Dedicated producer signing custody and externally supplied trust.
pub struct CaptureCredentials {
    /// Dedicated export signer identity admitted by the external trust file.
    pub signer_id: String,
    /// Existing owner-private file containing a raw 32-byte Ed25519 seed.
    pub signing_seed_file: PathBuf,
    /// Separate archive wrapping custody.
    pub wrapping: WrappingFiles,
    /// Existing bounded, closed version-one external signer trust document.
    pub signer_trust_file: PathBuf,
    /// Explicit known nonarchive raw keys, capped at 32; never discovered.
    pub exclusion_files: Vec<PathBuf>,
}

/// Explicit reader custody, without any private export signing material.
pub struct VerifyCredentials {
    /// Separate reader wrapping custody.
    pub wrapping: WrappingFiles,
    /// Existing externally provisioned signer pins.
    pub signer_trust_file: PathBuf,
    /// Explicit known nonarchive raw keys, capped at 32.
    pub exclusion_files: Vec<PathBuf>,
}

pub(super) struct LoadedCapture {
    pub signer: ArchiveSigningKey,
    pub wrapping: ArchiveWrappingKeys,
    pub trust: ArchiveSignerTrust,
    pub exclusions: Vec<ExcludedArchiveKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustDocument {
    version: u8,
    signers: TrustPins,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustPin {
    id: String,
    ed25519_public_key_hex: String,
}

struct TrustPins(Vec<TrustPin>);

impl<'de> Deserialize<'de> for TrustPins {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = TrustPins;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("at most 32 signer pins")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut pins = Vec::new();
                loop {
                    if pins.len() == 32 {
                        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(
                                "snapshot signer count exceeds limits",
                            ));
                        }
                        break;
                    }
                    match sequence.next_element::<TrustPin>()? {
                        Some(pin) => pins.push(pin),
                        None => break,
                    }
                }
                Ok(TrustPins(pins))
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

fn key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(path, 32)
        .map_err(|_| anyhow::anyhow!("snapshot private credential is unavailable"))?;
    let material: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("snapshot private credential must contain 32 raw bytes"))?;
    Ok(Zeroizing::new(material))
}

fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "snapshot credential identity is invalid"
    );
    Ok(())
}

fn trust_material(path: &Path) -> Result<Vec<(String, [u8; 32])>> {
    let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(path, 64 * 1024)
        .map_err(|_| anyhow::anyhow!("snapshot signer trust is unavailable"))?;
    let document: TrustDocument = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("snapshot signer trust document is invalid"))?;
    ensure!(
        document.version == 1 && !document.signers.0.is_empty() && document.signers.0.len() <= 32,
        "snapshot signer trust shape is invalid"
    );
    let mut pins = Vec::with_capacity(document.signers.0.len());
    for pin in document.signers.0 {
        identifier(&pin.id)?;
        ensure!(
            pin.ed25519_public_key_hex.len() == 64
                && pin
                    .ed25519_public_key_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "snapshot signer trust key is invalid"
        );
        let mut public = [0u8; 32];
        hex::decode_to_slice(&pin.ed25519_public_key_hex, &mut public)
            .map_err(|_| anyhow::anyhow!("snapshot signer trust key is invalid"))?;
        pins.push((pin.id, public));
    }
    Ok(pins)
}

pub(super) fn load_trust(path: &Path) -> Result<ArchiveSignerTrust> {
    ArchiveSignerTrust::new(trust_material(path)?)
}

pub(super) fn load_wrapping(paths: &WrappingFiles) -> Result<ArchiveWrappingKeys> {
    identifier(&paths.metadata_id)?;
    identifier(&paths.private_id)?;
    ensure!(
        paths.metadata_id != paths.private_id,
        "snapshot wrapping identities must differ"
    );
    let metadata = key(&paths.metadata_file)?;
    let private = key(&paths.private_file)?;
    ArchiveWrappingKeys::new(
        ArchiveWrappingKey::from_bytes(&paths.metadata_id, *metadata)?,
        ArchiveWrappingKey::from_bytes(&paths.private_id, *private)?,
    )
}

pub(super) fn load_exclusions(paths: &[PathBuf]) -> Result<Vec<ExcludedArchiveKey>> {
    ensure!(paths.len() <= 32, "snapshot exclusions exceed limits");
    paths
        .iter()
        .map(|path| {
            let material = key(path)?;
            Ok(ExcludedArchiveKey::from_bytes(*material))
        })
        .collect()
}

pub(super) fn load_capture(paths: &CaptureCredentials) -> Result<LoadedCapture> {
    identifier(&paths.signer_id)?;
    let pins = trust_material(&paths.signer_trust_file)?;
    let trust = ArchiveSignerTrust::new(pins.iter().cloned())?;
    let seed = key(&paths.signing_seed_file)?;
    let signer = ArchiveSigningKey::from_seed(&paths.signer_id, *seed)?;
    ensure!(
        pins.iter()
            .any(|(id, public)| id == signer.id() && public == &signer.public_key()),
        "snapshot producer signer is not externally trusted"
    );
    Ok(LoadedCapture {
        signer,
        wrapping: load_wrapping(&paths.wrapping)?,
        trust,
        exclusions: load_exclusions(&paths.exclusion_files)?,
    })
}
