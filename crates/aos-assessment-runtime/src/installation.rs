//! Closed Worker coordinator installation independent of host bindings.
//!
//! Deployment tools and the Worker validate the same routes, credentials,
//! conservative global budgets and decision policy before installing effects.

use anyhow::{Result, bail};
use aos_assessment::input::AssessmentPolicyV1;
use serde::{Deserialize, Serialize};

use crate::credentials::SourceCredentialSetV1;
use crate::routes::{InstalledSourceBudget, InstalledSourceRoutesV1, validate_source_budgets};

/// Installs a bounded logical coordinator on a Worker-only Hub.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkerAssessmentInstallationV1 {
    /// Exact supported installation discriminator.
    pub schema: String,
    /// Independently paired physical source profiles and authority partitions.
    pub routes: InstalledSourceRoutesV1,
    /// Complete sorted set of durable global provider/account quota domains.
    pub budgets: Vec<InstalledSourceBudget>,
    /// Reviewed immutable source grants containing references, never secret bytes.
    pub credentials: SourceCredentialSetV1,
    /// Shared deterministic assessment decision and freshness policy.
    pub policy: AssessmentPolicyV1,
}

impl WorkerAssessmentInstallationV1 {
    /// Validates the closed installation before deployment or source effects.
    ///
    /// # Errors
    /// Returns an error for incompatible contracts, incomplete quota domains,
    /// conflicting credential authority, or invalid assessment policy.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-worker-installation/v1" {
            bail!("unsupported Worker assessment installation");
        }
        self.routes.validate()?;
        validate_source_budgets(&self.routes, &self.budgets)?;
        self.credentials.validate()?;
        self.routes.validate_credentials(&self.credentials)?;
        self.policy.validate()
    }
}
