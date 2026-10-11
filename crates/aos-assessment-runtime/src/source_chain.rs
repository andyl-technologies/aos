//! Closed compact source-chain custody, separate from raw provider response bodies.

use anyhow::{Result, bail};
use aos_assessment::observation::SourceEvidenceRef;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};

use crate::provider::ProviderOperation;

/// Retains an exact upstream question and its ordered immutable evidence references.
///
/// This contains no source response bodies, URLs chosen outside typed profiles,
/// or secret values. Its byte digest remains an ordinary evidence identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceChainCustodyV1 {
    /// Exact compact custody discriminator.
    pub schema: String,
    /// Exact initial admitted upstream question.
    pub operation: ProviderOperation,
    /// Sorted unique evidence references, at most one hundred twenty-eight.
    pub sources: Vec<SourceEvidenceRef>,
}

impl SourceChainCustodyV1 {
    /// Parses only bounded, closed compact upstream custody.
    ///
    /// # Errors
    /// Returns an error for unsupported schema, source question, references or bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let chain: Self = JsonLimits {
            max_bytes: 262_144,
            max_depth: 16,
            max_items: 16_384,
            max_string_bytes: 4096,
        }
        .decode(bytes, "compact source-chain custody")?;
        chain.operation.validate()?;
        if chain.schema != "aos.source-chain-custody/v1"
            || !matches!(
                chain.operation,
                ProviderOperation::ObserveReleases { .. }
                    | ProviderOperation::ObserveTags { .. }
                    | ProviderOperation::ObserveGoReleases
                    | ProviderOperation::ObserveRepology { .. }
            )
            || chain.sources.len() > 128
            || chain
                .sources
                .windows(2)
                .any(|pair| pair[0] >= pair[1] || pair[0].digest == pair[1].digest)
            || chain.sources.iter().any(|source| {
                source.byte_length > 8 * 1024 * 1024 || source.origin != chain.operation.provider()
            })
        {
            bail!("compact source-chain custody differs from its exact upstream question");
        }
        Ok(chain)
    }
}
