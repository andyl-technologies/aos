//! Signer-private Source seed paired with the independently provisioned pin.
//!
//! ```text
//! source-hold-signing-seed: Ed25519 seed[32]
//! source-hold-public-key: AOSSPK01 pin[80]
//! ```



mod validation;
mod retained;

pub(crate) use retained::SourceSignerCredentialCaptureV1;

const SEED_NAME: &str = "source-hold-signing-seed";
const PIN_NAME: &str = "source-hold-public-key";

/// Reports an unsafe or inconsistent Source signer credential set.
#[derive(Debug, thiserror::Error)]
#[error("Source signer credentials are missing, unsafe, or inconsistent")]
pub(crate) struct SourceSignerCredentialErrorV1;
