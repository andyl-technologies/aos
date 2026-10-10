//! Worker-only bounded logical assessment passes outside the global database object.
//!
//! Queue messages are wakeups, never authority. Shared SQL claims, immutable job
//! admission and current IAM authorize each effect. Hybrid coordination stays Native.

use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::credentials::SourceCredentialSetV1;
use aos_assessment_runtime::installation::WorkerAssessmentInstallationV1 as Installation;
use aos_assessment_runtime::ports::ProviderTransport;
use aos_assessment_runtime::provider::{
    CapabilityChallenge, ProviderCapabilitiesV1, ProviderWorkAuth, ProviderWorkPlanV1,
    ProviderWorkResultV1, PROVIDER_CAPABILITIES_PATH, PROVIDER_SIGNATURE_HEADER,
    PROVIDER_WORK_PATH,
};
use aos_contract::limits::JsonLimits;
use aos_hub_core::assessment_execution::{
    run_assessment_controller_pass, AssessmentControllerPorts, CoordinatorEvidenceStore,
    DatabaseAssessmentAuthority, InstalledAssessmentRoutes,
};
use aos_hub_core::db::Database;
use aos_hub_core::jobs::{Job, JobEnvelope};
use worker::{Env, Headers, Method, Request, RequestInit};

fn installation(env: &Env) -> Result<Option<Installation>> {
    let Ok(configuration) = env.var("HUB_ASSESSMENT_CONFIG") else {
        return Ok(None);
    };
    let installation: Installation = JsonLimits {
        max_bytes: 262_144,
        max_depth: 16,
        max_items: 16_384,
        max_string_bytes: 4096,
    }
    .decode(
        configuration.to_string().as_bytes(),
        "Worker assessment installation",
    )?;
    installation.validate()?;
    ensure!(
        installation.routes.deployment_id == env.var("HUB_DEPLOYMENT_ID")?.to_string()
            && installation.routes.coordinator_id
                == env.var("HUB_ASSESSMENT_COORDINATOR_ID")?.to_string()
            && installation.routes.executor_id
                == env.var("HUB_ASSESSMENT_EXECUTOR_ID")?.to_string(),
        "Worker assessment installation differs from its service pairing"
    );
    let credentials = env
        .var("HUB_ASSESSMENT_CREDENTIALS")
        .map(|value| value.to_string())
        .unwrap_or_else(|_| {
            "{\"schema\":\"aos.assessment-source-credentials/v1\",\"grants\":[]}".into()
        });
    ensure!(
        SourceCredentialSetV1::from_slice(credentials.as_bytes())? == installation.credentials,
        "Worker coordinator and executor credential grants differ"
    );
    Ok(Some(installation))
}

/// Builds bounded per-partition queue wakeups from installed configuration.
///
/// # Errors
/// Returns an error for invalid or conflicting deployment installation.
pub(crate) fn installed_partitions(env: &Env) -> Result<Vec<String>> {
    let Some(installation) = installation(env)? else {
        return Ok(vec![]);
    };
    let scopes: std::collections::BTreeSet<_> = installation
        .routes
        .routes
        .iter()
        .map(|route| route.partition.clone())
        .collect();
    // Registry keys are resolved by the dispatcher from the current logical
    // database. Configuration cannot guess a key or grant scope via a label.
    Ok(scopes.into_iter().collect())
}

fn now() -> Result<Timestamp> {
    Timestamp::from_unix_seconds(u64::try_from(aos_hub_core::clock::now_unix_secs())?)
}

struct WorkerProviderTransport {
    env: Env,
    auth: ProviderWorkAuth,
}

impl WorkerProviderTransport {
    fn new(env: &Env, installation: &Installation) -> Result<Self> {
        Ok(Self {
            env: env.clone(),
            auth: ProviderWorkAuth::new(
                env.secret("HUB_ASSESSMENT_WORK_KEY")?
                    .to_string()
                    .into_bytes(),
                installation.routes.deployment_id.clone(),
                installation.routes.coordinator_id.clone(),
                installation.routes.executor_id.clone(),
            )?,
        })
    }

    async fn exchange(
        &self,
        route: &str,
        body: &[u8],
        signature: &str,
    ) -> Result<(Vec<u8>, String)> {
        let headers = Headers::new();
        headers.set(PROVIDER_SIGNATURE_HEADER, signature)?;
        headers.set("content-type", "application/json")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body).into()));
        // This synthetic URL is never fetched. It selects the authenticated
        // in-process router, which dispatches exact reservations to their DO.
        let request = Request::new_with_init(&format!("https://assessment.invalid{route}"), &init)?;
        let response = crate::assessment_provider::fetch(request, &self.env).await?;
        ensure!(
            response.status_code() == 200,
            "Worker assessment provider refused work"
        );
        let signature = response
            .headers()
            .get(PROVIDER_SIGNATURE_HEADER)?
            .context("Worker assessment receipt authentication is absent")?;
        let bytes = crate::hybrid::read_bounded_response(response, 262_144)
            .await?
            .context("Worker assessment receipt exceeds its envelope")?;
        Ok((bytes, signature))
    }
}

#[async_trait::async_trait(?Send)]
impl ProviderTransport for WorkerProviderTransport {
    async fn capabilities(
        &self,
        challenge: &CapabilityChallenge,
    ) -> Result<ProviderCapabilitiesV1> {
        let (bytes, signature) = self.auth.sign_challenge(challenge, &now()?)?;
        let (bytes, signature) = self
            .exchange(PROVIDER_CAPABILITIES_PATH, &bytes, &signature)
            .await?;
        self.auth
            .verify_capabilities(&bytes, &signature, challenge, &now()?)
    }

    async fn execute(&self, plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
        let (bytes, signature) = self.auth.sign_plan(plan, &now()?)?;
        let (bytes, signature) = self
            .exchange(PROVIDER_WORK_PATH, &bytes, &signature)
            .await?;
        self.auth.verify_result(&bytes, &signature, plan, &now()?)
    }
}

/// Executes and continues one independently authorized Worker journal page.
///
/// # Errors
/// Returns an error for mismatched installation/scope, journal failure or queue failure.
pub(crate) async fn run(
    db: Arc<Database>,
    env: &Env,
    parent: &JobEnvelope,
    registry_id: i64,
    resource_scope: &str,
    after_scan: &str,
) -> Result<()> {
    let installation =
        installation(env)?.context("Worker assessment controller is not installed")?;
    ensure!(
        installation
            .routes
            .routes
            .iter()
            .any(|route| route.partition == resource_scope),
        "Worker assessment partition is not installed"
    );
    ensure!(
        db.assessment_registry_for_partition(resource_scope).await? == Some(registry_id),
        "Worker assessment wakeup lost its registry incarnation"
    );
    for budget in &installation.budgets {
        db.install_assessment_source_budget(&budget.into()).await?;
    }
    if db
        .refresh_assessment_publication(registry_id, &installation.policy)
        .await?
        .resource
        .is_none()
    {
        db.reconcile_assessment_scans(registry_id, after_scan, 1)
            .await?;
        return Ok(());
    }
    let authority = DatabaseAssessmentAuthority::new(Arc::clone(&db));
    let evidence = CoordinatorEvidenceStore::new(Arc::clone(&db));
    let transport = WorkerProviderTransport::new(env, &installation)?;
    let routes = InstalledAssessmentRoutes::new(
        Arc::clone(&db),
        installation.routes,
        installation.credentials,
    )?;
    let pass = run_assessment_controller_pass(
        &db,
        registry_id,
        after_scan,
        1,
        AssessmentControllerPorts {
            authority: &authority,
            evidence: &evidence,
            transport: &transport,
            routes: &routes,
        },
    )
    .await?;
    if let Some(after_scan) = pass.next_scan {
        let job = Job::AssessmentRegistry {
            registry_id,
            resource_scope: resource_scope.to_owned(),
            after_scan: after_scan.clone(),
        };
        let child = parent.continued(job, format!("assessment:{resource_scope}:{after_scan}"))?;
        crate::workerqueue::WorkerQueue::from_env(env)?
            .enqueue_envelopes(&[child])
            .await?;
    }
    Ok(())
}
