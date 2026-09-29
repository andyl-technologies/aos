//! Secret-free transport clock selection for an external-only direct broker.
//!
//! ```json
//! {"version":1,"deploymentId":"aos-hybrid-staging","qualification":"<64 lowercase hex>","uncertaintySeconds":"1"}
//! ```
//!
//! The operator selects reviewed evidence here. This file does not establish
//! clock qualification or qualify an external provider's mutation clock.

use std::path::Path;

use anyhow::{ensure, Result};
use serde::Deserialize;

/// Reviewed transport clock coordinates for a direct upload broker.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HybridDirectUploadClockConfig {
    /// Closed operator-file format, currently one.
    pub version: u8,
    /// Exact paired deployment covered by the reviewed evidence.
    pub deployment_id: String,
    /// Commitment to separately reviewed clock qualification evidence.
    pub qualification: String,
    /// Canonical decimal uncertainty in seconds, positive and below thirty.
    pub uncertainty_seconds: String,
}

impl HybridDirectUploadClockConfig {
    /// Reads a bounded closed operator file containing no signing secrets.
    ///
    /// # Errors
    /// Returns an error for nonregular files, I/O, oversized or malformed JSON,
    /// unknown fields or secret-bearing additions. Error text excludes values.
    pub fn from_file(path: &Path) -> Result<Self> {
        super::read_config_file(path)
    }

    pub(in crate::cloudflare) fn validate(&self, deployment: &str) -> Result<()> {
        let uncertainty = self
            .uncertainty_seconds
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("direct upload clock uncertainty is invalid"))?;
        ensure!(
            self.version == 1
                && self.deployment_id == deployment
                && aos_hub_core::direct_upload::valid_direct_digest(&self.qualification)
                && (1..30).contains(&uncertainty)
                && self.uncertainty_seconds == uncertainty.to_string(),
            "direct upload transport clock coordinates are invalid"
        );
        Ok(())
    }

    pub(in crate::cloudflare) fn render_variables(&self) -> String {
        format!(
            "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION = {}\nHUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS = {}\n",
            crate::cloudflare::toml_string(&self.qualification),
            crate::cloudflare::toml_string(&self.uncertainty_seconds)
        )
    }
}
