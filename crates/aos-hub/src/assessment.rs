//! Installed Native and Hybrid assessment controllers over the shared SQL journal.
//!
//! Installation selects physical ports, never scan policy or principal authority.
//! Hybrid sends compact authenticated work to its paired Worker and retains only
//! compact source-chain references in the authoritative Native database.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use aos_assessment::input::AssessmentPolicyV1;
use aos_assessment_http::credentials::{InstalledSourceCredentials, SourceSecretBindings};
use aos_assessment_http::evidence::NativeEvidenceStore;
use aos_assessment_http::executor::{NativeExecutorIdentity, NativeProviderExecutor};
use aos_assessment_http::remote::RemoteProviderTransport;
use aos_assessment_runtime::credentials::{SourceCredentialGrant, SourceCredentialSetV1};
use aos_assessment_runtime::ports::ProviderTransport;
use aos_assessment_runtime::provider::{
    CapabilityChallenge, ProviderCapabilitiesV1, ProviderLimits, ProviderWorkAuth,
    ProviderWorkPlanV1, ProviderWorkResultV1,
};
use aos_assessment_runtime::routes::{
    validate_source_budgets, InstalledSourceBudget, InstalledSourceRoutesV1,
};
use aos_contract::limits::JsonLimits;
use aos_hub_core::assessment_execution::{
    run_assessment_controller_pass, run_assessment_notification_pass, AssessmentControllerPorts,
    CoordinatorEvidenceStore, DatabaseAssessmentAuthority, InstalledAssessmentRoutes,
};
use aos_hub_core::secret_version::{validate_secret_version_ref, SecretVersionResolver};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::server::AppState;

mod authority;
pub(crate) use authority::notification_effect;
pub use authority::NotificationAuthorityService;
mod notifications;
pub use notifications::AssessmentNotificationInstallation;
use notifications::InstalledNotificationExecutor;

/// Declares bounded physical controller installation without containing secrets.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentInstallationV1 {
    /// Exact installation discriminator.
    pub schema: String,
    /// Explicit physical provider placement.
    pub executor: AssessmentExecutorInstallation,
    /// Installed routes and independent service identities.
    pub routes: InstalledSourceRoutesV1,
    /// Complete sorted global quota declarations; restart never refunds allowance.
    pub budgets: Vec<InstalledSourceBudget>,
    /// Exact source grants, rechecked before every physical request.
    pub credentials: SourceCredentialSetV1,
    /// Installed independent decision policy for authenticated release inventories.
    pub policy: AssessmentPolicyV1,
    /// Native binding names mapped to immutable provider version references.
    pub secret_versions: BTreeMap<String, String>,
    /// Journal polling interval, one to sixty seconds.
    pub poll_seconds: u32,
    /// Maximum concurrent logical controller passes, one to eight.
    pub coordinator_concurrency: u32,
    /// Provider observation freshness, one to eighty-six thousand seconds.
    pub source_ttl_seconds: u32,
    /// Independent notification destination and quota installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<AssessmentNotificationInstallation>,
}

/// Selects an installed executor without permitting topology fallback.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AssessmentExecutorInstallation {
    /// Uses Native HTTP and private filesystem source custody.
    Native {
        /// Absolute private source evidence directory.
        #[serde(rename = "evidenceRoot")]
        evidence_root: PathBuf,
    },
    /// Uses one independently authenticated paired Worker.
    Worker {
        /// Exact HTTPS Worker origin.
        origin: String,
        /// Owner-private dedicated provider-work key file.
        #[serde(rename = "workKeyFile")]
        work_key_file: PathBuf,
    },
}

impl AssessmentInstallationV1 {
    /// Parses a closed installation and refuses unknown or unbounded settings.
    ///
    /// # Errors
    /// Returns an error for malformed schemas, physical limits or secret references.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let installation: Self = JsonLimits {
            max_bytes: 262_144,
            max_depth: 16,
            max_items: 16_384,
            max_string_bytes: 4096,
        }
        .decode(bytes, "assessment installation")?;
        ensure!(
            installation.schema == "aos.assessment-installation/v1"
                && (1..=60).contains(&installation.poll_seconds)
                && (1..=8).contains(&installation.coordinator_concurrency)
                && (1..=86400).contains(&installation.source_ttl_seconds)
                && installation.secret_versions.len() <= 128,
            "assessment installation exceeds its schema or bounds"
        );
        installation.routes.validate()?;
        validate_source_budgets(&installation.routes, &installation.budgets)?;
        installation.credentials.validate()?;
        installation
            .routes
            .validate_credentials(&installation.credentials)?;
        installation.policy.validate()?;
        for version in installation.secret_versions.values() {
            validate_secret_version_ref(version)?;
        }
        match &installation.executor {
            AssessmentExecutorInstallation::Native { evidence_root } => {
                ensure!(
                    evidence_root.is_absolute(),
                    "assessment evidence root must be absolute"
                );
                for grant in &installation.credentials.grants {
                    ensure!(
                        installation
                            .secret_versions
                            .contains_key(&grant.secret_binding),
                        "assessment source grant lacks its immutable Native secret binding"
                    );
                }
            }
            AssessmentExecutorInstallation::Worker {
                origin,
                work_key_file,
            } => {
                let origin = url::Url::parse(origin)?;
                ensure!(
                    origin.scheme() == "https"
                        && origin.host_str().is_some()
                        && origin.username().is_empty()
                        && origin.password().is_none()
                        && origin.path() == "/"
                        && origin.query().is_none()
                        && origin.fragment().is_none(),
                    "assessment Worker origin must be an exact HTTPS service origin"
                );
                ensure!(
                    work_key_file.is_absolute(),
                    "provider-work key path must be absolute"
                );
                ensure!(
                    installation.secret_versions.is_empty(),
                    "remote source credentials belong to Worker custody"
                );
            }
        }
        if let Some(notifications) = &installation.notifications {
            notifications.validate(&installation.executor)?;
            ensure!(
                notifications
                    .installation
                    .budgets
                    .iter()
                    .all(|notification| {
                        installation
                            .budgets
                            .iter()
                            .all(|source| source.key != notification.key)
                    }),
                "notification and source quota domains must be independent"
            );
            ensure!(
                notifications.installation.deployment_id == installation.routes.deployment_id,
                "assessment and notification deployment incarnations differ"
            );
        }
        Ok(installation)
    }
}

struct NativeSecretBindings {
    versions: BTreeMap<String, String>,
    resolver: Arc<dyn SecretVersionResolver>,
}

#[async_trait::async_trait]
impl SourceSecretBindings for NativeSecretBindings {
    async fn read(&self, grant: &SourceCredentialGrant) -> Result<Zeroizing<String>> {
        let version = self
            .versions
            .get(&grant.secret_binding)
            .context("installed source secret binding is unavailable")?;
        let resolved = self.resolver.resolve(version).await?;
        let text = resolved.expose_utf8()?;
        ensure!(
            !text.is_empty() && text.len() <= 2048 && !text.chars().any(char::is_control),
            "installed source credential exceeds its header profile"
        );
        Ok(Zeroizing::new(text.to_owned()))
    }
}

enum InstalledTransport {
    Native(NativeProviderExecutor<NativeEvidenceStore>),
    Worker(RemoteProviderTransport),
}

#[async_trait::async_trait]
impl ProviderTransport for InstalledTransport {
    async fn capabilities(
        &self,
        challenge: &CapabilityChallenge,
    ) -> Result<ProviderCapabilitiesV1> {
        match self {
            Self::Native(transport) => transport.capabilities(challenge).await,
            Self::Worker(transport) => transport.capabilities(challenge).await,
        }
    }

    async fn execute(&self, plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
        match self {
            Self::Native(transport) => transport.execute(plan).await,
            Self::Worker(transport) => transport.execute(plan).await,
        }
    }
}

/// Installs a bounded background controller with exact topology and deployment scope.
///
/// Each lane visits one installed partition and at most one claimable scan. SQL
/// owns claims and authorization, so overlapping processes and duplicate wakeups
/// cannot create new scan generations or replace current results. Only private
/// authenticated admissions are executed; installation grants no user permission.
///
/// # Errors
/// Returns an error for unavailable configuration, mismatched topology/deployment,
/// invalid source custody or unavailable dedicated provider authentication.
pub async fn install_controller(
    state: &AppState,
    path: &Path,
    topology: &str,
    paired_worker_origin: Option<&str>,
) -> Result<tokio::task::JoinHandle<()>> {
    let bytes = crate::auth::seal::read_secret_file(path)?;
    let installation = AssessmentInstallationV1::from_slice(&bytes)?;
    ensure!(
        state.deployment_id.as_deref() == Some(installation.routes.deployment_id.as_str()),
        "assessment installation differs from the active deployment incarnation"
    );
    let transport = match &installation.executor {
        AssessmentExecutorInstallation::Native { evidence_root } => {
            ensure!(
                topology == "native",
                "Native provider placement requires Native topology"
            );
            let credentials = Arc::new(InstalledSourceCredentials::new(
                installation.credentials.clone(),
                Arc::new(NativeSecretBindings {
                    versions: installation.secret_versions.clone(),
                    resolver: Arc::clone(&state.secret_versions),
                }),
            )?);
            InstalledTransport::Native(NativeProviderExecutor::new(
                NativeExecutorIdentity {
                    deployment_id: installation.routes.deployment_id.clone(),
                    issuer: installation.routes.coordinator_id.clone(),
                    audience: installation.routes.executor_id.clone(),
                    build: format!("aos-hub/{}", env!("CARGO_PKG_VERSION")),
                },
                credentials,
                Arc::new(NativeEvidenceStore::open(evidence_root.clone()).await?),
                ProviderLimits::default(),
                installation.source_ttl_seconds,
            )?)
        }
        AssessmentExecutorInstallation::Worker {
            origin,
            work_key_file,
        } => {
            ensure!(
                topology == "hybrid" && paired_worker_origin == Some(origin.as_str()),
                "assessment executor differs from the active Hybrid Worker pairing"
            );
            let auth = Arc::new(ProviderWorkAuth::new(
                crate::auth::seal::read_secret_file(work_key_file)?,
                installation.routes.deployment_id.clone(),
                installation.routes.coordinator_id.clone(),
                installation.routes.executor_id.clone(),
            )?);
            InstalledTransport::Worker(RemoteProviderTransport::new(origin, auth)?)
        }
    };
    let notification_executor = installation
        .notifications
        .as_ref()
        .map(|configuration| {
            InstalledNotificationExecutor::install(state, configuration, &installation.executor)
        })
        .transpose()?;
    if let Some(authority) = notification_executor
        .as_ref()
        .and_then(InstalledNotificationExecutor::authority)
    {
        ensure!(
            state
                .assessment_notification_authority
                .set(authority)
                .is_ok(),
            "notification effect authority is already installed"
        );
    }
    let db = Arc::clone(&state.db);
    if let Some(configuration) = &installation.notifications {
        for budget in &configuration.installation.budgets {
            db.install_assessment_source_budget(&budget.into()).await?;
        }
    }
    for budget in &installation.budgets {
        db.install_assessment_source_budget(&budget.into()).await?;
    }
    let authority = DatabaseAssessmentAuthority::new(Arc::clone(&db));
    let evidence = CoordinatorEvidenceStore::new(Arc::clone(&db));
    db.register_assessment_source_status(installation.routes.clone(), installation.credentials.clone())?;
    let routes = InstalledAssessmentRoutes::new(
        Arc::clone(&db),
        installation.routes.clone(),
        installation.credentials,
    )?;
    let partitions: Vec<_> = installation
        .routes
        .routes
        .iter()
        .map(|route| route.partition.clone())
        .chain(installation.notifications.iter().flat_map(|configuration| {
            configuration
                .installation
                .destinations
                .iter()
                .map(|route| route.destination.resource_scope.clone())
        }))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let lanes = partitions
        .len()
        .min(installation.coordinator_concurrency as usize);
    let runtime = Arc::new(ControllerRuntime {
        db,
        authority,
        evidence,
        routes,
        transport,
        notifications: installation
            .notifications
            .map(|configuration| configuration.installation),
        notification_executor,
        policy: installation.policy,
        poll_seconds: installation.poll_seconds,
    });
    Ok(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for lane in 0..lanes {
            let runtime = Arc::clone(&runtime);
            let partitions = partitions
                .iter()
                .skip(lane)
                .step_by(lanes)
                .cloned()
                .collect();
            tasks.spawn(async move { runtime.run_lane(partitions).await });
        }
        while tasks.join_next().await.is_some() {
            tracing::error!("assessment controller lane exited unexpectedly");
        }
    }))
}

struct ControllerRuntime {
    db: Arc<aos_hub_core::db::Database>,
    authority: DatabaseAssessmentAuthority,
    evidence: CoordinatorEvidenceStore,
    routes: InstalledAssessmentRoutes,
    transport: InstalledTransport,
    notifications: Option<aos_assessment_runtime::notifications::NotificationInstallationV1>,
    notification_executor: Option<InstalledNotificationExecutor>,
    policy: AssessmentPolicyV1,
    poll_seconds: u32,
}

impl ControllerRuntime {
    async fn run_lane(&self, partitions: Vec<String>) {
        let mut tick = tokio::time::interval(Duration::from_secs(u64::from(self.poll_seconds)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut position = 0;
        let mut cursors = BTreeMap::<String, String>::new();
        loop {
            tick.tick().await;
            let partition = &partitions[position];
            position = (position + 1) % partitions.len();
            let registry = match self.db.assessment_registry_for_partition(partition).await {
                Ok(Some(registry)) => registry,
                Ok(None) => continue,
                Err(_) => {
                    tracing::warn!("assessment controller resource lookup unavailable");
                    continue;
                }
            };
            if let (Some(installation), Some(executor)) =
                (&self.notifications, &self.notification_executor)
            {
                if run_assessment_notification_pass(&self.db, registry, installation, 1, executor)
                    .await
                    .is_err()
                {
                    tracing::warn!("assessment notification journal pass unavailable");
                }
            }
            let cursor = cursors.get(partition).map(String::as_str).unwrap_or("");
            if self
                .db
                .reconcile_assessment_scans(registry, cursor, 1)
                .await
                .is_err()
            {
                tracing::warn!("assessment journal recovery unavailable");
                continue;
            }
            match self
                .db
                .refresh_assessment_publication(registry, &self.policy)
                .await
            {
                Ok(publication) if publication.resource.is_some() => {}
                Ok(_) => continue,
                Err(_) => {
                    tracing::warn!("assessment publication refresh unavailable");
                    continue;
                }
            }
            match run_assessment_controller_pass(
                &self.db,
                registry,
                cursor,
                1,
                AssessmentControllerPorts {
                    authority: &self.authority,
                    transport: &self.transport,
                    evidence: &self.evidence,
                    routes: &self.routes,
                },
            )
            .await
            {
                Ok(pass) => {
                    cursors.insert(partition.clone(), pass.next_scan.unwrap_or_default());
                }
                Err(_) => tracing::warn!("assessment controller journal pass unavailable"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration() -> serde_json::Value {
        serde_json::json!({
            "schema": "aos.assessment-installation/v1",
            "executor": {"kind": "native", "evidenceRoot": "/fixture/private/evidence"},
            "routes": {
                "schema": "aos.assessment-source-routes/v1",
                "deploymentId": "deployment", "coordinatorId": "coordinator", "executorId": "executor",
                "routes": [{"partition": "partition", "provider": "osv", "budgetKey": "osv-global",
                    "expiresAt": "2026-10-10T00:00:00Z", "limits": ProviderLimits::default()}]
            },
            "credentials": {"schema": "aos.assessment-source-credentials/v1", "grants": []},
            "budgets": [{"key": "osv-global", "windowSeconds": 3600, "allowance": 100, "minIntervalSeconds": 0}],
            "policy": {"schema": "aos.assessment-policy/v1", "upstreamMaxAgeSeconds": 86400,
                "advisoryMaxAgeSeconds": 86400, "requiredAdvisorySources": ["osv"], "requireDependencyCoverage": true},
            "secretVersions": {}, "pollSeconds": 5, "coordinatorConcurrency": 2, "sourceTtlSeconds": 3600
        })
    }

    #[test]
    fn installation_refuses_unknown_fields_unbounded_polling_and_ambient_secret_versions(
    ) -> Result<()> {
        let configuration = configuration();
        AssessmentInstallationV1::from_slice(&serde_json::to_vec(&configuration)?)?;
        for changed in [
            {
                let mut value = configuration.clone();
                value["fallback"] = true.into();
                value
            },
            {
                let mut value = configuration.clone();
                value["pollSeconds"] = 0.into();
                value
            },
            {
                let mut value = configuration.clone();
                value["pollSeconds"] = 61.into();
                value
            },
            {
                let mut value = configuration.clone();
                value["executor"]["evidenceRoot"] = "relative".into();
                value
            },
            {
                let mut value = configuration.clone();
                value["secretVersions"]["GITHUB"] = "latest".into();
                value
            },
        ] {
            assert!(AssessmentInstallationV1::from_slice(&serde_json::to_vec(&changed)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn remote_installation_separates_worker_credential_custody_from_native() -> Result<()> {
        let mut configuration = configuration();
        configuration["executor"] = serde_json::json!({
            "kind": "worker", "origin": "https://assessment.example/", "workKeyFile": "/fixture/provider-work-key"
        });
        AssessmentInstallationV1::from_slice(&serde_json::to_vec(&configuration)?)?;
        configuration["secretVersions"]["GITHUB"] = "native://assessment/github/version-one".into();
        assert!(
            AssessmentInstallationV1::from_slice(&serde_json::to_vec(&configuration)?).is_err()
        );
        Ok(())
    }
}

#[cfg(test)]
mod notification_installation_tests {
    use super::{AssessmentExecutorInstallation, AssessmentNotificationInstallation};
    use aos_assessment::time::Timestamp;
    use aos_assessment_runtime::notifications::{
        InstalledNotificationDestination, NotificationDestinationV1, NotificationInstallationV1,
    };
    use aos_assessment_runtime::routes::InstalledSourceBudget;
    use aos_contract::Sha256Digest;

    fn fixture() -> AssessmentNotificationInstallation {
        AssessmentNotificationInstallation {
            installation: NotificationInstallationV1 {
                schema: "aos.assessment-notification-installation/v1".into(),
                deployment_id: "deployment".into(),
                coordinator_id: "notification-coordinator".into(),
                executor_id: "notification-executor".into(),
                destinations: vec![InstalledNotificationDestination {
                    destination: NotificationDestinationV1 {
                        schema: "aos.assessment-notification-destination/v1".into(),
                        destination_reference: "webhook:42".into(),
                        revision: 3,
                        resource_scope: "registry-incarnation".into(),
                        url: "https://receiver.example/callback".into(),
                        secret_version_reference: "native://assessment/notification/v1".into(),
                        credential_fingerprint: Sha256Digest::of_bytes([7; 32]),
                        expires_at: Timestamp::from_unix_seconds(2_000_000_000).unwrap(),
                    },
                    budget_key: "notification:account".into(),
                }],
                budgets: vec![InstalledSourceBudget {
                    key: "notification:account".into(),
                    window_seconds: 60,
                    allowance: 10,
                    min_interval_seconds: 1,
                }],
            },
            work_key_file: None,
        }
    }

    #[test]
    fn notification_installation_requires_exact_topology_and_immutable_key_custody() {
        let native = AssessmentExecutorInstallation::Native {
            evidence_root: "/fixture/private/evidence".into(),
        };
        let worker = AssessmentExecutorInstallation::Worker {
            origin: "https://worker.example/".into(),
            work_key_file: "/fixture/private/provider-key".into(),
        };
        let mut installation = fixture();
        installation.validate(&native).unwrap();
        assert!(installation.validate(&worker).is_err());
        installation.work_key_file = Some("/fixture/private/provider-key".into());
        assert!(installation.validate(&worker).is_err());
        installation.work_key_file = Some("/fixture/private/notification-key".into());
        installation.validate(&worker).unwrap();
        assert!(installation.validate(&native).is_err());
        installation.installation.destinations[0]
            .destination
            .secret_version_reference = "native://assessment/notification/latest".into();
        assert!(installation.validate(&worker).is_err());
    }
}
