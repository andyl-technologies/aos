//! Native notification installation, current credential checks and paired Hybrid execution.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use aos_assessment_http::notifications::{
    NativeNotificationTransport, NotificationCredentials, RemoteNotificationExecutor,
};
use aos_assessment_http::PhysicalClock;
use aos_assessment_runtime::notifications::{
    execute_notification, NotificationDestinationV1, NotificationInstallationV1,
    NotificationWorkAuth, NotificationWorkPlanV1, NotificationWorkReceiptV1,
};
use aos_hub_core::assessment_execution::AssessmentNotificationExecutor;
use aos_hub_core::db::{AssessmentNotificationWork, Database};
use aos_hub_core::secret_version::{validate_secret_version_ref, SecretVersionResolver};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::AssessmentExecutorInstallation;
use crate::server::AppState;

/// Installs independently reviewed notification routes and an optional remote pairing key.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentNotificationInstallation {
    /// Closed shared route, quota and service identity installation.
    pub installation: NotificationInstallationV1,
    /// Dedicated owner-private notification-work key, required only in Hybrid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_key_file: Option<PathBuf>,
}

impl AssessmentNotificationInstallation {
    pub(super) fn validate(&self, executor: &AssessmentExecutorInstallation) -> Result<()> {
        self.installation.validate()?;
        for route in &self.installation.destinations {
            validate_secret_version_ref(&route.destination.secret_version_reference)?;
        }
        match executor {
            AssessmentExecutorInstallation::Native { .. } => ensure!(
                self.work_key_file.is_none(),
                "Native notifications do not accept a remote work key"
            ),
            AssessmentExecutorInstallation::Worker { work_key_file, .. } => {
                let notification_key = self
                    .work_key_file
                    .as_ref()
                    .context("Hybrid notifications require a dedicated notification-work key")?;
                ensure!(
                    notification_key.is_absolute() && notification_key != work_key_file,
                    "notification authentication requires an independent absolute key file"
                );
            }
        }
        Ok(())
    }
}

struct NativeNotificationCredentials {
    db: Arc<Database>,
    installation: NotificationInstallationV1,
    resolver: Arc<dyn SecretVersionResolver>,
}

impl NativeNotificationCredentials {
    fn require_installed(&self, destination: &NotificationDestinationV1) -> Result<()> {
        ensure!(
            self.installation
                .destinations
                .iter()
                .any(|route| &route.destination == destination),
            "notification destination is not independently installed"
        );
        Ok(())
    }
}

#[async_trait::async_trait]
impl NotificationCredentials for NativeNotificationCredentials {
    async fn authorize(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
    ) -> Result<()> {
        self.require_installed(destination)?;
        ensure!(
            plan.deployment_id == self.installation.deployment_id
                && plan.issuer == self.installation.coordinator_id
                && plan.audience == self.installation.executor_id,
            "notification work differs from the installed pairing"
        );
        let registry_id = self
            .db
            .assessment_registry_for_partition(&destination.resource_scope)
            .await?
            .context("notification resource is absent")?;
        self.db
            .check_assessment_notification_work(&AssessmentNotificationWork {
                registry_id,
                plan: plan.clone(),
                destination: destination.clone(),
            })
            .await
    }

    async fn resolve(&self, destination: &NotificationDestinationV1) -> Result<Zeroizing<Vec<u8>>> {
        self.require_installed(destination)?;
        let registry = self
            .db
            .assessment_registry_for_partition(&destination.resource_scope)
            .await?
            .context("notification resource is absent")?;
        let current = self
            .db
            .assessment_notification_destination(
                registry,
                &destination.destination_reference,
                &destination.expires_at,
            )
            .await?;
        ensure!(
            &current == destination,
            "notification key authority changed before resolution"
        );
        let resolved = self
            .resolver
            .resolve(&destination.secret_version_reference)
            .await?;
        Ok(Zeroizing::new(resolved.expose_bytes().to_vec()))
    }
}

pub(super) enum InstalledNotificationExecutor {
    Native(NativeNotificationTransport),
    Worker(RemoteNotificationExecutor),
}

impl InstalledNotificationExecutor {
    pub(super) fn install(
        state: &AppState,
        configuration: &AssessmentNotificationInstallation,
        executor: &AssessmentExecutorInstallation,
    ) -> Result<Self> {
        configuration.validate(executor)?;
        ensure!(
            state.deployment_id.as_deref()
                == Some(configuration.installation.deployment_id.as_str()),
            "notification installation differs from the active deployment incarnation"
        );
        match executor {
            AssessmentExecutorInstallation::Native { .. } => {
                let credentials = Arc::new(NativeNotificationCredentials {
                    db: Arc::clone(&state.db),
                    installation: configuration.installation.clone(),
                    resolver: Arc::clone(&state.secret_versions),
                });
                Ok(Self::Native(NativeNotificationTransport::new(credentials)?))
            }
            AssessmentExecutorInstallation::Worker {
                origin,
                work_key_file,
            } => {
                let notification_key = Zeroizing::new(crate::auth::seal::read_secret_file(
                    configuration
                        .work_key_file
                        .as_ref()
                        .context("notification work key is absent")?,
                )?);
                let provider_key =
                    Zeroizing::new(crate::auth::seal::read_secret_file(work_key_file)?);
                ensure!(
                    notification_key != provider_key,
                    "notification and provider work keys must differ"
                );
                let auth = Arc::new(NotificationWorkAuth::new(
                    notification_key.to_vec(),
                    configuration.installation.deployment_id.clone(),
                    configuration.installation.coordinator_id.clone(),
                    configuration.installation.executor_id.clone(),
                )?);
                Ok(Self::Worker(RemoteNotificationExecutor::new(origin, auth)?))
            }
        }
    }
}

#[async_trait::async_trait]
impl AssessmentNotificationExecutor for InstalledNotificationExecutor {
    async fn execute(
        &self,
        work: &AssessmentNotificationWork,
    ) -> Result<NotificationWorkReceiptV1> {
        match self {
            Self::Native(transport) => {
                execute_notification(transport, &PhysicalClock, &work.destination, &work.plan).await
            }
            Self::Worker(transport) => transport.execute(&work.plan).await,
        }
    }
}
