//! Installed source routes shared by Native, Worker and Hybrid coordinators.
//!
//! Package metadata selects typed source questions. Only deployment configuration
//! selects executor identities, credential versions and global quota domains.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use aos_assessment::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::credentials::SourceCredentialSetV1;
use crate::provider::{ProviderLimits, ProviderOperation};
use crate::validation::{decode, encoded, text};

/// Binds a source profile and partition to one installed physical executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstalledSourceRoute {
    /// Exact non-reusable authorization partition.
    pub partition: String,
    /// Exact supported provider profile.
    pub provider: String,
    /// Installed global provider/account quota domain, shared across fan-out.
    pub budget_key: String,
    /// Optional immutable installed source grant, never raw credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// Exclusive installed route authority deadline.
    pub expires_at: Timestamp,
    /// Effective ceilings no greater than the shared executor contract.
    pub limits: ProviderLimits,
}

/// Selects one independently paired executor without permitting fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstalledSourceRoutesV1 {
    /// Exact installed route discriminator.
    pub schema: String,
    /// Non-reusable deployment incarnation.
    pub deployment_id: String,
    /// Installed logical coordinator identity.
    pub coordinator_id: String,
    /// Installed provider executor identity, local or remote.
    pub executor_id: String,
    /// Sorted unique partition/profile entries, at most 128.
    pub routes: Vec<InstalledSourceRoute>,
}

/// Declares one global provider/account allowance shared by all execution modes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InstalledSourceBudget {
    /// Exact quota domain selected only by installed source routes.
    pub key: String,
    /// Fixed UTC window length, one to eighty-six thousand seconds.
    pub window_seconds: u32,
    /// Conservatively consumed requests per window, at most one million.
    pub allowance: u32,
    /// Minimum reservation spacing, at most one hour.
    pub min_interval_seconds: u32,
}

/// Validates a complete finite quota declaration for exact installed routes.
///
/// # Errors
/// Returns an error for unbounded, missing, repeated or unused quota domains.
pub fn validate_source_budgets(
    routes: &InstalledSourceRoutesV1,
    budgets: &[InstalledSourceBudget],
) -> Result<()> {
    routes.validate()?;
    if budgets.is_empty()
        || budgets.len() > 128
        || budgets.windows(2).any(|pair| pair[0].key >= pair[1].key)
    {
        bail!("installed source budgets require sorted unique bounded quota domains");
    }
    for budget in budgets {
        text(&budget.key, 128, "installed source quota domain")?;
        if !(1..=86400).contains(&budget.window_seconds)
            || !(1..=1_000_000).contains(&budget.allowance)
            || budget.min_interval_seconds > 3600
        {
            bail!("installed source budget exceeds its effect ceilings");
        }
    }
    let declared: std::collections::BTreeSet<_> =
        budgets.iter().map(|budget| budget.key.as_str()).collect();
    let required: std::collections::BTreeSet<_> = routes
        .routes
        .iter()
        .map(|route| route.budget_key.as_str())
        .collect();
    if declared != required {
        bail!("installed source quota domains differ from exact routed accounts");
    }
    Ok(())
}

impl InstalledSourceRoutesV1 {
    /// Decodes the closed deployment route configuration before physical effects.
    ///
    /// # Errors
    /// Returns an error for unknown fields, unsupported sources or route bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let routes: Self = decode(bytes, "installed assessment source routes")?;
        routes.validate()?;
        Ok(routes)
    }

    /// Validates exact source profiles, identity scope and bounded effect ceilings.
    ///
    /// # Errors
    /// Returns an error for malformed configuration or repeated/excessive routes.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-source-routes/v1"
            || self.routes.is_empty()
            || self.routes.len() > 128
        {
            bail!("invalid installed assessment source route schema or count");
        }
        for (identity, label) in [
            (&self.deployment_id, "assessment deployment"),
            (&self.coordinator_id, "assessment coordinator"),
            (&self.executor_id, "assessment executor"),
        ] {
            text(identity, 128, label)?;
        }
        if self.routes.windows(2).any(|pair| {
            (&pair[0].partition, &pair[0].provider) >= (&pair[1].partition, &pair[1].provider)
        }) {
            bail!("installed assessment routes must be sorted and unique");
        }
        for route in &self.routes {
            text(&route.partition, 128, "installed source partition")?;
            text(&route.budget_key, 128, "installed source quota domain")?;
            if !matches!(
                route.provider.as_str(),
                "github-tags"
                    | "github-releases"
                    | "go-releases"
                    | "repology"
                    | "osv"
                    | "nvd"
                    | "cisa-kev"
            ) {
                bail!("installed assessment route names an unsupported source");
            }
            if let Some(reference) = &route.credential_ref {
                text(reference, 128, "installed source credential version")?;
            }
            route.limits.validate()?;
        }
        encoded(self)?;
        Ok(())
    }

    /// Validates exact credential bindings and shared quota domains before installation.
    ///
    /// # Errors
    /// Returns an error for missing grants or quota forks across partitions.
    pub fn validate_credentials(&self, credentials: &SourceCredentialSetV1) -> Result<()> {
        self.validate()?;
        credentials.validate()?;
        let mut budgets = BTreeMap::new();
        for route in &self.routes {
            let account = if let Some(reference) = &route.credential_ref {
                let grant = credentials
                    .grants
                    .iter()
                    .find(|grant| {
                        &grant.reference == reference
                            && grant.partition == route.partition
                            && grant.provider == route.provider
                    })
                    .context("installed route lacks its exact source credential grant")?;
                grant.secret_binding.as_str()
            } else {
                "anonymous"
            };
            let family = match route.provider.as_str() {
                "github-tags" | "github-releases" => "github",
                other => other,
            };
            if let Some(previous) = budgets.insert((family, account), &route.budget_key)
                && previous != &route.budget_key
            {
                bail!("installed source quota differs across authorization partitions");
            }
        }
        Ok(())
    }

    /// Resolves exact current source scope and prevents partition-local quota forks.
    ///
    /// Each credential binding/provider pair uses the same quota domain across
    /// partitions. Anonymous source profiles likewise share a global quota key.
    /// The executor independently rechecks credential custody before dispatch.
    ///
    /// # Errors
    /// Returns an error for absent/expired routes, unsupported operations,
    /// revoked credential scope or inconsistent installed global quota domains.
    pub fn resolve<'a>(
        &'a self,
        partition: &str,
        operation: &ProviderOperation,
        credentials: &SourceCredentialSetV1,
        now: &Timestamp,
    ) -> Result<&'a InstalledSourceRoute> {
        self.validate_credentials(credentials)?;
        operation.validate()?;
        let route = self
            .routes
            .iter()
            .find(|route| route.partition == partition && route.provider == operation.provider())
            .context("installed assessment source route is absent")?;
        if now >= &route.expires_at {
            bail!("installed assessment source route expired");
        }
        if let Some(reference) = &route.credential_ref {
            credentials.resolve_operation(reference, partition, operation, now)?;
        }
        Ok(route)
    }
}
