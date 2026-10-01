//! Secret-free transport clock selection for an external-only direct broker.
//!
//! ```json
//! {"version":1,"deploymentId":"deployment-1","mode":"bounded_utc","qualification":"<stable policy commitment>","uncertaintySeconds":"1"}
//! ```
//!
//! This fixed conservative policy is installed before measuring the current
//! script. Actual clock observations require independently signed acceptance.

use std::path::Path;

use anyhow::{ensure, Result};
use serde::Deserialize;

/// Installed transport clock policy for a direct upload broker.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HybridDirectUploadClockConfig {
    /// Closed operator-file format, currently one.
    pub version: u8,
    /// Exact paired deployment covered by the installed policy.
    pub deployment_id: String,
    /// Closed conservative clock mode installed before measurement.
    pub mode: aos_hub_core::direct_upload::DirectClockPolicyMode,
    /// Stable commitment to the installed mode and uncertainty policy.
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
                && self.qualification
                    == aos_hub_core::direct_upload::DirectClockPolicy {
                        version: 1,
                        mode: self.mode,
                        uncertainty_seconds: aos_hub_core::direct_upload::WireInteger::new(
                            uncertainty
                        ),
                    }
                    .commitment()?
                && (1..30).contains(&uncertainty)
                && self.uncertainty_seconds == uncertainty.to_string(),
            "direct upload transport clock coordinates are invalid"
        );
        Ok(())
    }

    pub(in crate::cloudflare) fn render_variables(&self) -> String {
        format!(
            "HUB_DIRECT_UPLOAD_CLOCK_MODE = \"bounded_utc\"\nHUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION = {}\nHUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS = {}\n",
            crate::cloudflare::toml_string(&self.qualification),
            crate::cloudflare::toml_string(&self.uncertainty_seconds)
        )
    }
}
