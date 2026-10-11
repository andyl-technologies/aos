//! Separately authenticated callbacks with durable per-attempt replay fences.
//!
//! Logical admission stays in Hub SQL. This object pins one exact attempt before
//! any confirmation or callback effect and retains only its compact signed receipt.
//! An interrupted attempt never repeats a physical effect on replay.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::notifications::{
    execute_notification, CallbackSignature, NotificationDestinationV1, NotificationEffectGrantV1,
    NotificationEffectQueryV1, NotificationTransport, NotificationWorkAuth, NotificationWorkPlanV1,
    WorkerNotificationInstallationV1, NOTIFICATION_EFFECT_PATH, NOTIFICATION_WORK_PATH,
};
use aos_assessment_runtime::ports::Clock;
use aos_contract::Sha256Digest;
use aos_hub_core::assessment_execution::confirm_assessment_notification_effect;
use aos_hub_core::db::Database;
use base64::Engine as _;
use futures_util::future::{select, Either};
use futures_util::lock::Mutex;
use futures_util::pin_mut;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use worker::{
    durable_object, DurableObject, Env, Fetch, Headers, Method, Request, RequestInit,
    RequestRedirect, Response, State,
};
use zeroize::Zeroizing;

pub(crate) const SIGNATURE_HEADER: &str = "X-AOS-Assessment-Notification-Signature";

struct WorkerClock;

impl Clock for WorkerClock {
    fn now(&self) -> Result<Timestamp> {
        Timestamp::from_unix_seconds(u64::try_from(aos_hub_core::clock::now_unix_secs())?)
    }
}

/// Reads closed non-secret callback installation and validates immutable key references.
///
/// # Errors
/// Returns an error for malformed configuration, wrong service pairing or key versions.
pub(crate) fn installation(env: &Env) -> Result<Option<WorkerNotificationInstallationV1>> {
    let Ok(value) = env.var("HUB_ASSESSMENT_NOTIFICATION_CONFIG") else {
        return Ok(None);
    };
    let installation = WorkerNotificationInstallationV1::from_slice(value.to_string().as_bytes())?;
    ensure!(
        installation.installation.deployment_id == env.var("HUB_DEPLOYMENT_ID")?.to_string()
            && installation.installation.coordinator_id
                == env
                    .var("HUB_ASSESSMENT_NOTIFICATION_COORDINATOR_ID")?
                    .to_string()
            && installation.installation.executor_id
                == env
                    .var("HUB_ASSESSMENT_NOTIFICATION_EXECUTOR_ID")?
                    .to_string(),
        "notification installation differs from its service pairing"
    );
    for version in &installation.secret_bindings {
        aos_hub_core::secret_version::validate_secret_version_ref(&version.version_reference)?;
    }
    Ok(Some(installation))
}

/// Creates purpose-separated notification work authentication from its installed binding.
///
/// # Errors
/// Returns an error for missing or malformed independent work authentication.
pub(crate) fn auth(env: &Env) -> Result<NotificationWorkAuth> {
    NotificationWorkAuth::new(
        env.secret("HUB_ASSESSMENT_NOTIFICATION_WORK_KEY")?
            .to_string()
            .into_bytes(),
        env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        env.var("HUB_ASSESSMENT_NOTIFICATION_COORDINATOR_ID")?
            .to_string(),
        env.var("HUB_ASSESSMENT_NOTIFICATION_EXECUTOR_ID")?
            .to_string(),
    )
}

/// Routes exact signed callback work to its durable attempt object.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    respond(&mut request, env, None).await
}

async fn respond(
    request: &mut Request,
    env: &Env,
    state: Option<&State>,
) -> worker::Result<Response> {
    match authenticated(request, env, state).await {
        Ok(receipt) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            headers.set(SIGNATURE_HEADER, &receipt.signature)?;
            Ok(Response::from_bytes(receipt.bytes)?.with_headers(headers))
        }
        Err(_) => {
            let headers = Headers::new();
            headers.set("cache-control", "no-store")?;
            Ok(Response::error("assessment notification work refused", 409)?.with_headers(headers))
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedReceipt {
    plan_digest: Sha256Digest,
    bytes: Vec<u8>,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedAttempt {
    digest: Sha256Digest,
    collect_after: u64,
}

async fn authenticated(
    request: &mut Request,
    env: &Env,
    state: Option<&State>,
) -> Result<RetainedReceipt> {
    ensure!(
        request.method() == Method::Post
            && request.url()?.path() == NOTIFICATION_WORK_PATH
            && request.url()?.query().is_none(),
        "notification work requires its exact POST route"
    );
    ensure!(
        request.headers().get("content-type")?.as_deref() == Some("application/json")
            && request.headers().get("content-encoding")?.is_none(),
        "notification work requires its identity JSON envelope"
    );
    let auth = auth(env)?;
    let signature = request
        .headers()
        .get(SIGNATURE_HEADER)?
        .context("notification work MAC is absent")?;
    let bytes = crate::hybrid::read_bounded_body(request, 262_144)
        .await?
        .context("notification work exceeds its envelope")?;
    // MAC and complete plan validation precede configuration, storage or callback keys.
    let plan = auth.verify_plan(&bytes, &signature, &WorkerClock.now()?)?;
    let installation = installation(env)?.context("notification execution is not installed")?;
    let route = installation
        .installation
        .destinations
        .iter()
        .find(|route| {
            route.destination.resource_scope == plan.body.resource_scope
                && route.destination.destination_reference == plan.destination_reference
                && route
                    .destination
                    .digest()
                    .is_ok_and(|digest| digest == plan.destination_digest)
        })
        .context("notification destination is not independently installed")?;
    plan.require_destination(&route.destination)?;
    let namespace = env.durable_object("ASSESSMENT_NOTIFICATION_TASKS")?;
    let name = Sha256Digest::of_canonical(
        "aos.assessment-notification-attempt/v1",
        &(
            &plan.deployment_id,
            &plan.claim_token,
            &plan.reservation_digest,
        ),
    )?
    .to_string();
    let id = namespace.id_from_name(&name)?;
    let digest = plan.digest()?;
    let Some(state) = state else {
        let forwarded = work_request(request.url()?.as_str(), &bytes, &signature)?;
        let response = id.get_stub()?.fetch_with_request(forwarded).await?;
        ensure!(
            response.status_code() == 200,
            "notification object refused work"
        );
        let signature = response
            .headers()
            .get(SIGNATURE_HEADER)?
            .context("notification receipt MAC is absent")?;
        let bytes = crate::hybrid::read_bounded_response(response, 4096)
            .await?
            .context("notification receipt exceeds its compact bound")?;
        auth.verify_receipt(&bytes, &signature, &plan, &WorkerClock.now()?)?;
        return Ok(RetainedReceipt {
            plan_digest: digest,
            bytes,
            signature,
        });
    };
    ensure!(
        state.id().to_string() == id.to_string(),
        "notification reached another attempt object"
    );
    if let Some(previous) = state.storage().get::<PinnedAttempt>("plan").await? {
        ensure!(
            previous.digest == digest,
            "notification attempt is pinned to another plan"
        );
        let receipt = state
            .storage()
            .get::<RetainedReceipt>("receipt")
            .await?
            .context("notification attempt has an uncertain physical outcome")?;
        ensure!(
            receipt.plan_digest == digest && receipt.bytes.len() <= 4096,
            "retained notification receipt differs from the attempt"
        );
        auth.verify_receipt(
            &receipt.bytes,
            &receipt.signature,
            &plan,
            &WorkerClock.now()?,
        )?;
        return Ok(receipt);
    }
    // This admission survives crashes. Unknown effects require a new SQL claim
    // after the old deadline; the old attempt can never be dispatched again.
    state
        .storage()
        .put(
            "plan",
            PinnedAttempt {
                digest,
                collect_after: plan.deadline.unix_seconds().saturating_add(604800),
            },
        )
        .await?;
    state
        .storage()
        .set_alarm(Duration::from_secs(604860))
        .await?;
    let transport = WorkerNotificationTransport {
        env: env.clone(),
        installation,
        auth,
    };
    let destination = transport
        .installation
        .installation
        .destinations
        .iter()
        .find(|route| {
            route
                .destination
                .digest()
                .is_ok_and(|value| value == plan.destination_digest)
        })
        .context("notification destination changed")?;
    let result =
        execute_notification(&transport, &WorkerClock, &destination.destination, &plan).await?;
    let (bytes, signature) = transport
        .auth
        .sign_receipt(&result, &plan, &WorkerClock.now()?)?;
    ensure!(
        bytes.len() <= 4096,
        "notification receipt exceeds its compact bound"
    );
    let receipt = RetainedReceipt {
        plan_digest: digest,
        bytes,
        signature,
    };
    state.storage().put("receipt", &receipt).await?;
    Ok(receipt)
}

/// Constructs a bounded internal work or confirmation request without dispatching it.
///
/// # Errors
/// Returns an error for invalid runtime URL or headers.
pub(crate) fn work_request(url: &str, bytes: &[u8], signature: &str) -> Result<Request> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(SIGNATURE_HEADER, signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        // workerd supports manual/follow modes. Callers reject every redirect
        // response before admitting an authenticated result.
        .with_redirect(RequestRedirect::Manual)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(bytes).into()));
    Ok(Request::new_with_init(url, &init)?)
}

struct WorkerNotificationTransport {
    env: Env,
    installation: WorkerNotificationInstallationV1,
    auth: NotificationWorkAuth,
}

impl WorkerNotificationTransport {
    async fn confirm(
        &self,
        plan: &NotificationWorkPlanV1,
    ) -> Result<(NotificationEffectQueryV1, NotificationEffectGrantV1)> {
        let mut random = [0_u8; 32];
        rand::rng().fill(&mut random);
        let query = NotificationEffectQueryV1 {
            schema: "aos.assessment-notification-effect-query/v1".into(),
            deployment_id: plan.deployment_id.clone(),
            issuer: plan.issuer.clone(),
            audience: plan.audience.clone(),
            resource_scope: plan.body.resource_scope.clone(),
            plan_digest: plan.digest()?,
            claim_token: plan.claim_token.clone(),
            nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
            issued_at: WorkerClock.now()?,
        };
        let topology = self
            .env
            .var("HUB_TOPOLOGY")
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "worker_only".into());
        let grant = match topology.as_str() {
            "worker_only" => {
                let db = Database::attach(Box::new(crate::remotebackend::RemoteHubBackend::new(
                    &self.env,
                )));
                confirm_assessment_notification_effect(&db, &self.installation.installation, &query)
                    .await?
            }
            "hybrid" => {
                let mut origin =
                    url::Url::parse(&self.env.var("HUB_HYBRID_ORIGIN_URL")?.to_string())?;
                ensure!(
                    origin.scheme() == "https"
                        && origin.host_str().is_some()
                        && origin.path() == "/"
                        && origin.query().is_none()
                        && origin.fragment().is_none()
                        && origin.username().is_empty()
                        && origin.password().is_none(),
                    "notification coordinator requires the installed exact HTTPS origin"
                );
                origin.set_path(NOTIFICATION_EFFECT_PATH);
                let (bytes, signature) =
                    self.auth.sign_effect_query(&query, &WorkerClock.now()?)?;
                let request = work_request(origin.as_str(), &bytes, &signature)?;
                let abort = AbortOnDrop(worker::web_sys::AbortController::new().map_err(|_| {
                    anyhow::anyhow!("notification confirmation cancellation is unavailable")
                })?);
                let signal = worker::AbortSignal::from(abort.0.signal());
                let dispatch = Fetch::Request(request);
                let effect = async {
                    let response = dispatch.send_with_signal(&signal).await?;
                    ensure!(
                        response.status_code() == 200,
                        "notification coordinator refused confirmation"
                    );
                    let signature = response
                        .headers()
                        .get(SIGNATURE_HEADER)?
                        .context("notification confirmation MAC is absent")?;
                    ensure!(
                        response
                            .headers()
                            .get("content-encoding")?
                            .is_none_or(|value| value == "identity"),
                        "notification confirmation encoding differs"
                    );
                    let bytes = crate::hybrid::read_bounded_response(response, 4096)
                        .await?
                        .context("notification confirmation exceeds its compact bound")?;
                    self.auth.verify_effect_grant(
                        &bytes,
                        &signature,
                        &query,
                        plan,
                        &WorkerClock.now()?,
                    )
                };
                let timeout = worker::Delay::from(Duration::from_secs(5));
                pin_mut!(effect, timeout);
                match select(effect, timeout).await {
                    Either::Left((result, _)) => result?,
                    Either::Right(_) => anyhow::bail!("notification confirmation timed out"),
                }
            }
            _ => anyhow::bail!("notification topology is not installed"),
        };
        grant.validate_for(&query, plan, &WorkerClock.now()?)?;
        Ok((query, grant))
    }
}

#[async_trait::async_trait(?Send)]
impl NotificationTransport for WorkerNotificationTransport {
    async fn sign_callback(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
    ) -> Result<CallbackSignature> {
        let (query, grant) = self.confirm(plan).await?;
        let binding = self
            .installation
            .secret_bindings
            .iter()
            .find(|binding| binding.version_reference == destination.secret_version_reference)
            .context("notification key version is not installed")?;
        let secret = Zeroizing::new(self.env.secret(&binding.binding)?.to_string());
        grant.validate_for(&query, plan, &WorkerClock.now()?)?;
        CallbackSignature::sign(destination, plan, body, secret.as_bytes())
    }

    async fn post(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
        signature: &CallbackSignature,
    ) -> Result<(Option<u16>, Option<u32>)> {
        let (query, grant) = self.confirm(plan).await?;
        let gateway_key = Zeroizing::new(self.env.secret("HUB_EGRESS_GATEWAY_KEY")?.to_string());
        let egress = crate::consoleports::WorkerEgressClient::gateway(
            self.installation.egress_gateway_url.clone(),
            &gateway_key,
        )?;
        egress
            .send_notification(destination, plan, body, signature, &query, &grant)
            .await
    }
}

/// Serializes one pinned notification attempt without moving coordination from Hub SQL.
#[durable_object]
pub struct AssessmentNotificationObject {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
}

impl DurableObject for AssessmentNotificationObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        let _permit = self.gate.lock().await;
        respond(&mut request, &self.env, Some(&self.state)).await
    }

    async fn alarm(&self) -> worker::Result<Response> {
        let _permit = self.gate.lock().await;
        if let Some(pin) = self.state.storage().get::<PinnedAttempt>("plan").await? {
            let now = u64::try_from(aos_hub_core::clock::now_unix_secs()).map_err(|_| {
                worker::Error::RustError("notification clock is unavailable".into())
            })?;
            if now < pin.collect_after {
                self.state
                    .storage()
                    .set_alarm(Duration::from_secs(pin.collect_after - now))
                    .await?;
                return Response::empty();
            }
        }
        // Plans expire in at most sixty seconds. Collection after seven days
        // cannot make any old signed attempt eligible for another dispatch.
        self.state.storage().delete_all().await?;
        Response::empty()
    }
}

struct AbortOnDrop(worker::web_sys::AbortController);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
