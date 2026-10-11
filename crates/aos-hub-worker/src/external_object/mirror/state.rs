//! Compact mirror pointer into the full original and positive-only journal.
//!
//! ```text
//! owner = {original_digest, configuration, destination}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// Identifies one retained mirror session without copying its object manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Owner {
    /// Commitment to the complete independently selected original.
    pub original_digest: String,
    /// Commitment to its installed mirror transport domain.
    pub configuration: String,
    /// Selects the original private stage or final destination physical key.
    pub destination: bool,
}

impl Owner {
    /// Checks the closed pointer independently of journal loading.
    ///
    /// # Errors
    /// Refuses malformed original or installed-domain commitments.
    pub(in crate::external_object) fn validate(&self) -> Result<()> {
        ensure!(
            aos_hub_core::direct_upload::valid_direct_digest(&self.original_digest)
                && aos_hub_core::direct_upload::valid_direct_digest(&self.configuration),
            "external mirror ownership pointer malformed"
        );
        Ok(())
    }
}
