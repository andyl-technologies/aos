//! Database-clock adapter for installed shared provider routing policy.

use anyhow::{bail, Context as _, Result};
use aos_assessment_runtime::credentials::SourceCredentialSetV1;
use aos_assessment_runtime::provider::ProviderOperation;
use aos_assessment_runtime::routes::InstalledSourceRoutesV1;
use std::sync::Arc;

use super::{AssessmentSourceRoute, AssessmentSourceRoutes};
use crate::db::{AssessmentScanRecord, Database};

/// Routes source work using deployment policy and the authoritative database clock.
///
/// Runtime mode selects the paired transport. Hybrid's executor identity remains
/// Worker-owned; this adapter never substitutes another executor on failure.
pub struct InstalledAssessmentRoutes {
    db: Arc<Database>,
    routes: InstalledSourceRoutesV1,
    credentials: SourceCredentialSetV1,
}

impl InstalledAssessmentRoutes {
    /// Binds a database and closed deployment configuration for a coordinator.
    ///
    /// # Errors
    /// Returns an error for invalid route or credential declarations.
    pub fn new(
        db: Arc<Database>,
        routes: InstalledSourceRoutesV1,
        credentials: SourceCredentialSetV1,
    ) -> Result<Self> {
        routes.validate()?;
        credentials.validate()?;
        routes.validate_credentials(&credentials)?;
        Ok(Self {
            db,
            routes,
            credentials,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl AssessmentSourceRoutes for InstalledAssessmentRoutes {
    async fn route(
        &self,
        scan: &AssessmentScanRecord,
        operation: &ProviderOperation,
    ) -> Result<AssessmentSourceRoute> {
        let resource = self
            .db
            .assessment_resource(scan.registry_id)
            .await?
            .context("assessment route resource is absent")?;
        if resource.partition != scan.request.authorization_partition
            || resource.inventory_revision != scan.request.inventory_revision
            || resource.inventory_digest != scan.request.inventory_digest
            || resource.policy_digest != scan.request.policy_digest
            || resource.authorization_revision != scan.authorization_revision
        {
            bail!("assessment source route lost its current resource fence");
        }
        let now = self.db.assessment_database_time().await?;
        let route = self
            .routes
            .resolve(&resource.partition, operation, &self.credentials, &now)?;
        let mut expires_at = route.expires_at.clone();
        if let Some(reference) = &route.credential_ref {
            let grant = self.credentials.resolve_operation(
                reference,
                &resource.partition,
                operation,
                &now,
            )?;
            expires_at = expires_at.min(grant.expires_at.clone());
        }
        Ok(AssessmentSourceRoute {
            deployment_id: self.routes.deployment_id.clone(),
            issuer: self.routes.coordinator_id.clone(),
            audience: self.routes.executor_id.clone(),
            budget_key: route.budget_key.clone(),
            credential_ref: route.credential_ref.clone(),
            expires_at,
            limits: route.limits.clone(),
        })
    }
}
