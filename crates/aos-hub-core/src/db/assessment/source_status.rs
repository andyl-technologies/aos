//! Scoped source availability from current installation and shared quota rows.
//!
//! The installed catalog is transient deployment metadata. SQL remains the
//! authoritative quota and health store. This read never installs quota, resets
//! a window, consumes work, reads credentials or selects an obsolete task route.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::credentials::SourceCredentialSetV1;
use aos_assessment_runtime::routes::InstalledSourceRoutesV1;
use aos_assessment_runtime::source_status::{
    SourceAvailability, SourceBudgetWindow, SourceStatus, SOURCE_PROFILES,
};

use crate::db::Database;

#[derive(Clone, Eq, PartialEq)]
pub(in crate::db) struct SourceStatusCatalog {
    routes: InstalledSourceRoutesV1,
    credentials: SourceCredentialSetV1,
}

impl Database {
    /// Registers validated deployment routes for secret-free source status reads.
    ///
    /// Registration installs no permission, credential, quota or scan authority.
    /// Native registers its controller configuration before polling; Worker
    /// request adapters register their current deployment configuration.
    ///
    /// # Errors
    /// Returns an error for invalid configuration or a different existing catalog.
    pub fn register_assessment_source_status(
        &self,
        routes: InstalledSourceRoutesV1,
        credentials: SourceCredentialSetV1,
    ) -> Result<()> {
        routes.validate_credentials(&credentials)?;
        let catalog = SourceStatusCatalog {
            routes,
            credentials,
        };
        let retained = self
            .assessment_source_catalog
            .get_or_init(|| catalog.clone());
        ensure!(
            retained == &catalog,
            "assessment source status installation already differs"
        );
        Ok(())
    }

    /// Reads reservation availability for the exact authorized partition.
    ///
    /// An empty projection means this handle has no installed status catalog.
    /// A configured catalog reports every supported profile, including missing
    /// routes. Shared account identifiers and usage never leave this method.
    ///
    /// # Errors
    /// Returns an error for invalid scope, unavailable SQL or inconsistent quotas.
    pub async fn assessment_source_status(
        &self,
        partition: &str,
        now: &Timestamp,
    ) -> Result<Vec<SourceStatus>> {
        ensure!(
            !partition.is_empty()
                && partition.len() <= 128
                && !partition.chars().any(char::is_control),
            "invalid source status partition"
        );
        let Some(catalog) = self.assessment_source_catalog.get() else {
            return Ok(vec![]);
        };
        let mut statuses = Vec::with_capacity(SOURCE_PROFILES.len());
        for provider in SOURCE_PROFILES {
            let Some(route) = catalog
                .routes
                .routes
                .iter()
                .find(|route| route.partition == partition && route.provider == provider)
            else {
                statuses.push(SourceStatus {
                    provider: provider.into(),
                    availability: SourceAvailability::Unconfigured {},
                });
                continue;
            };
            let mut authority_until = route.expires_at.clone();
            if let Some(reference) = &route.credential_ref {
                let grant = catalog
                    .credentials
                    .grants
                    .iter()
                    .find(|grant| &grant.reference == reference)
                    .context("installed source status credential grant is absent")?;
                authority_until = authority_until.min(grant.expires_at.clone());
            }
            let availability = if &authority_until <= now {
                SourceAvailability::AuthorityUnavailable {}
            } else if let Some(row) = self.backend.query_opt(
                "SELECT window_start, window_seconds, allowance, consumed,
                    next_eligible_at, circuit_until FROM assessment_source_budgets WHERE budget_key = ?1",
                &vals![route.budget_key],
            ).await? {
                SourceBudgetWindow {
                    window_start: row.get(0)?, window_seconds: row.get(1)?,
                    allowance: row.get(2)?, consumed: row.get(3)?,
                    next_eligible_at: row.get(4)?, circuit_until: row.get(5)?,
                }.availability(now, &authority_until)?
            } else {
                SourceAvailability::Unconfigured {}
            };
            let status = SourceStatus {
                provider: provider.into(),
                availability,
            };
            status.validate(now)?;
            statuses.push(status);
        }
        Ok(statuses)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
