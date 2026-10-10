//! Bounded provider effects and independent authentication on Worker executors.
//!
//! Shared adapters parse the exact source bytes retained in the dedicated R2
//! evidence binding. Native receives compact authenticated normalized receipts.
//! The provider-work key is independent of ingress, storage and database seals.

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use aos_assessment::observation::HttpValidators;
use aos_assessment::time::Timestamp;
use aos_assessment_providers::{kev, nvd, osv, UPSTREAM_ADAPTER_VERSION};
use aos_assessment_runtime::ports::{Clock, EvidenceStore};
use aos_assessment_runtime::provider::{
    execute_source, ProviderCapabilitiesV1, ProviderLimits, ProviderWorkAuth, ProviderWorkPlanV1,
    SourceMethod, SourceRequest, SourceResponse, SourceTransport, PROVIDER_CAPABILITIES_PATH,
    PROVIDER_SIGNATURE_HEADER, PROVIDER_WORK_PATH,
};
use aos_contract::Sha256Digest;
use base64::Engine as _;
use futures_util::future::{select, Either};
use futures_util::lock::Mutex;
use futures_util::{pin_mut, StreamExt as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use worker::{
    durable_object, Bucket, DurableObject, Env, Fetch, Headers, Method, Request, RequestInit,
    RequestRedirect, Response, State,
};
use zeroize::Zeroizing;

const EVIDENCE_LIMIT: u64 = 8 * 1024 * 1024;

struct WorkerClock;

impl Clock for WorkerClock {
    fn now(&self) -> Result<Timestamp> {
        let seconds = u64::try_from(aos_hub_core::clock::now_unix_secs())
            .context("Worker clock is before the epoch")?;
        Timestamp::from_unix_seconds(seconds)
    }
}

/// Executes only the installed internal provider routes, with generic refusals.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    respond(&mut request, env, None).await
}

async fn respond(
    request: &mut Request,
    env: &Env,
    state: Option<&State>,
) -> worker::Result<Response> {
    match authenticated(request, env, state).await {
        Ok((body, signature)) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            headers.set(PROVIDER_SIGNATURE_HEADER, &signature)?;
            Ok(Response::from_bytes(body)?.with_headers(headers))
        }
        Err(_) => Response::error("assessment provider work refused", 409),
    }
}

async fn authenticated(
    request: &mut Request,
    env: &Env,
    state: Option<&State>,
) -> Result<(Vec<u8>, String)> {
    if request.method() != Method::Post {
        bail!("provider work requires POST");
    }
    let path = request.url()?.path().to_owned();
    if ![PROVIDER_CAPABILITIES_PATH, PROVIDER_WORK_PATH].contains(&path.as_str()) {
        bail!("unsupported provider work route");
    }
    let auth = ProviderWorkAuth::new(
        env.secret("HUB_ASSESSMENT_WORK_KEY")?
            .to_string()
            .into_bytes(),
        env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        env.var("HUB_ASSESSMENT_COORDINATOR_ID")?.to_string(),
        env.var("HUB_ASSESSMENT_EXECUTOR_ID")?.to_string(),
    )?;
    let signature = request
        .headers()
        .get(PROVIDER_SIGNATURE_HEADER)?
        .context("provider work signature is absent")?;
    let body = crate::hybrid::read_bounded_body(request, 256 * 1024)
        .await?
        .context("provider work request exceeds its closed envelope")?;
    let now = WorkerClock.now()?;
    let limits = ProviderLimits::default();
    let build = format!("aos-hub-worker/{}", env!("CARGO_PKG_VERSION"));
    if path == PROVIDER_CAPABILITIES_PATH {
        let challenge = auth.verify_challenge(&body, &signature, &now)?;
        let mut adapters = vec![
            UPSTREAM_ADAPTER_VERSION.into(),
            osv::ADAPTER_VERSION.into(),
            nvd::ADAPTER_VERSION.into(),
            kev::ADAPTER_VERSION.into(),
        ];
        adapters.sort();
        adapters.dedup();
        return auth.sign_capabilities(
            &ProviderCapabilitiesV1 {
                schema: "aos.provider-capabilities/v1".into(),
                challenge,
                executor_build: build,
                adapters,
                limits,
            },
            &WorkerClock.now()?,
        );
    }
    // Authentication and exact plan bounds precede R2 or credential lookup.
    let plan = auth.verify_plan(&body, &signature, &now)?;
    plan.limits.require_within(&limits)?;
    let source_ttl = env
        .var("HUB_ASSESSMENT_SOURCE_TTL_SECONDS")
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "3600".into())
        .parse::<u32>()
        .context("invalid assessment source freshness policy")?;
    anyhow::ensure!(
        (1..=86400).contains(&source_ttl),
        "assessment source freshness exceeds its bounds"
    );
    let namespace = env.durable_object("ASSESSMENT_PROVIDER_TASKS")?;
    let name = Sha256Digest::of_canonical(
        "aos.assessment-provider-attempt/v1",
        &(
            plan.deployment_id.as_str(),
            plan.budget_reservation.reservation_id.as_str(),
        ),
    )?
    .to_string();
    let id = namespace.id_from_name(&name)?;
    let Some(state) = state else {
        let headers = Headers::new();
        headers.set(PROVIDER_SIGNATURE_HEADER, &signature)?;
        headers.set("content-type", "application/json")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
        let forwarded = Request::new_with_init(request.url()?.as_str(), &init)?;
        let response = id.get_stub()?.fetch_with_request(forwarded).await?;
        if response.status_code() != 200 {
            bail!("provider attempt was not positively acknowledged");
        }
        let signature = response
            .headers()
            .get(PROVIDER_SIGNATURE_HEADER)?
            .context("provider attempt receipt signature is absent")?;
        let body = crate::hybrid::read_bounded_response(response, 256 * 1024)
            .await?
            .context("provider attempt receipt exceeds envelope")?;
        auth.verify_result(&body, &signature, &plan, &WorkerClock.now()?)?;
        return Ok((body, signature));
    };
    if state.id().to_string() != id.to_string() {
        bail!("provider attempt reached the wrong object");
    }
    let digest = plan.digest()?;
    if let Some(previous) = state.storage().get::<Sha256Digest>("plan").await? {
        if previous != digest {
            bail!("provider reservation is already pinned to a different plan");
        }
        let receipt = read_receipt(state, digest).await?;
        auth.verify_result(&receipt.0, &receipt.1, &plan, &WorkerClock.now()?)?;
        return Ok(receipt);
    }
    // This fence never expires or refunds. A crash after dispatch leaves an
    // unknown physical outcome; replay cannot consume the reservation twice.
    state.storage().put("plan", digest).await?;
    let evidence = WorkerEvidenceStore {
        bucket: env.bucket("ASSESSMENT_EVIDENCE")?,
    };
    let source = WorkerSourceTransport { env: env.clone() };
    let result =
        execute_source(&source, &evidence, &WorkerClock, &plan, &build, source_ttl).await?;
    let receipt = auth.sign_result(&result, &plan, &WorkerClock.now()?)?;
    store_receipt(state, digest, &receipt.0, &receipt.1).await?;
    Ok(receipt)
}

/// Serializes one physical reservation while keeping coordination in Hub SQL.
#[durable_object]
pub struct AssessmentProviderObject {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
}

impl DurableObject for AssessmentProviderObject {
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptHead {
    plan_digest: Sha256Digest,
    body_digest: Sha256Digest,
    byte_length: u32,
    shards: u32,
    signature: String,
}

async fn store_receipt(
    state: &State,
    plan: Sha256Digest,
    body: &[u8],
    signature: &str,
) -> Result<()> {
    if body.is_empty() || body.len() > 256 * 1024 || signature.len() != 64 {
        bail!("invalid compact provider receipt");
    }
    // Base64 shards keep each KV value below the Durable Object per-value
    // limit. The receipt head and every shard commit in one local transaction.
    let shards = body
        .chunks(32 * 1024)
        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
        .collect::<Vec<_>>();
    let head = ReceiptHead {
        plan_digest: plan,
        body_digest: Sha256Digest::of_bytes(body),
        byte_length: body.len() as u32,
        shards: shards.len() as u32,
        signature: signature.into(),
    };
    state
        .storage()
        .transaction(move |transaction| async move {
            for (index, shard) in shards.iter().enumerate() {
                transaction.put(&format!("receipt-{index}"), shard).await?;
            }
            transaction.put("receipt", &head).await
        })
        .await?;
    Ok(())
}

async fn read_receipt(state: &State, plan: Sha256Digest) -> Result<(Vec<u8>, String)> {
    let head = state
        .storage()
        .get::<ReceiptHead>("receipt")
        .await?
        .context("provider physical outcome is unknown; a new reservation is required")?;
    if head.plan_digest != plan
        || head.byte_length == 0
        || head.byte_length > 256 * 1024
        || !(1..=8).contains(&head.shards)
        || head.signature.len() != 64
    {
        bail!("provider receipt metadata is inconsistent");
    }
    let mut body = Vec::with_capacity(head.byte_length as usize);
    for index in 0..head.shards {
        let shard = state
            .storage()
            .get::<String>(&format!("receipt-{index}"))
            .await?
            .context("provider receipt shard is unavailable")?;
        if shard.len() > 44 * 1024 {
            bail!("provider receipt shard exceeds its bound");
        }
        let bytes = base64::engine::general_purpose::STANDARD.decode(shard)?;
        if bytes.len() > 32 * 1024 || body.len() + bytes.len() > head.byte_length as usize {
            bail!("provider receipt shard exceeds the exact receipt length");
        }
        body.extend_from_slice(&bytes);
    }
    if body.len() != head.byte_length as usize || Sha256Digest::of_bytes(&body) != head.body_digest
    {
        bail!("provider receipt custody differs from its admitted identity");
    }
    Ok((body, head.signature))
}

struct WorkerSourceTransport {
    env: Env,
}

impl WorkerSourceTransport {
    fn credential_headers(&self, plan: &ProviderWorkPlanV1, headers: &Headers) -> Result<()> {
        if plan.credential_ref.is_none() {
            return Ok(());
        }
        let configuration = self
            .env
            .var("HUB_ASSESSMENT_CREDENTIALS")
            .map_err(|_| anyhow::anyhow!("installed source credential grants are unavailable"))?
            .to_string();
        let grants = aos_assessment_runtime::credentials::SourceCredentialSetV1::from_slice(
            configuration.as_bytes(),
        )?;
        let grant = grants.resolve(plan, &WorkerClock.now()?)?;
        let secret = Zeroizing::new(
            self.env
                .secret(&grant.secret_binding)
                .map_err(|_| anyhow::anyhow!("source credential custody is unavailable"))?
                .to_string(),
        );
        if secret.is_empty() || secret.len() > 2048 || secret.chars().any(char::is_control) {
            bail!("source credential exceeds the installed header bound");
        }
        match grant.provider.as_str() {
            "github-releases" | "github-tags" => {
                let header = Zeroizing::new(format!("Bearer {}", secret.as_str()));
                headers.set("authorization", header.as_str())?;
            }
            "nvd" => headers.set("apiKey", secret.as_str())?,
            _ => bail!("source credential provider is unsupported"),
        }
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl SourceTransport for WorkerSourceTransport {
    async fn fetch(
        &self,
        plan: &ProviderWorkPlanV1,
        request: &SourceRequest,
    ) -> Result<SourceResponse> {
        plan.validate_at(&WorkerClock.now()?)?;
        if !plan.operation.source_requests()?.contains(request) {
            bail!("source request exceeds the installed profile");
        }
        let headers = Headers::new();
        headers.set("accept", "application/json")?;
        headers.set("accept-encoding", "identity")?;
        headers.set("user-agent", "aos-assessment/1")?;
        self.credential_headers(plan, &headers)?;
        if matches!(
            plan.operation,
            aos_assessment_runtime::provider::ProviderOperation::ObserveReleases { .. }
                | aos_assessment_runtime::provider::ProviderOperation::ObserveTags { .. }
        ) {
            headers.set("x-github-api-version", "2022-11-28")?;
        }
        if let Some(cache) = &plan.cache_ref {
            if let Some(etag) = &cache.validators.etag {
                headers.set("if-none-match", etag)?;
            }
            if let Some(modified) = &cache.validators.last_modified {
                headers.set("if-modified-since", modified)?;
            }
        }
        let mut init = RequestInit::new();
        init.with_method(match request.method {
            SourceMethod::Get => Method::Get,
            SourceMethod::Post => Method::Post,
        })
        .with_redirect(RequestRedirect::Manual)
        .with_headers(headers);
        if let Some(body) = &request.body {
            init.headers.set("content-type", "application/json")?;
            init.with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
        }
        let request = Request::new_with_init(request.url.as_str(), &init)?;
        let cancellation = AbortOnDrop(
            worker::web_sys::AbortController::new()
                .map_err(|_| anyhow::anyhow!("source cancellation owner is unavailable"))?,
        );
        let signal = worker::AbortSignal::from(cancellation.0.signal());
        let remaining = plan
            .expires_at
            .unix_seconds()
            .checked_sub(WorkerClock.now()?.unix_seconds())
            .filter(|seconds| *seconds > 0)
            .context("source work expired before dispatch")?;
        let effect = async {
            let dispatched = Fetch::Request(request);
            let fetch = dispatched.send_with_signal(&signal);
            let connect =
                worker::Delay::from(Duration::from_secs(u64::from(plan.limits.connect_seconds)));
            pin_mut!(fetch, connect);
            let response = match select(fetch, connect).await {
                Either::Left((response, _)) => {
                    response.map_err(|_| anyhow::anyhow!("source HTTP request failed"))?
                }
                Either::Right(_) => bail!("source connection/header deadline elapsed"),
            };
            if response
                .headers()
                .get("content-encoding")?
                .is_some_and(|value| value != "identity")
            {
                bail!("source ignored the installed identity encoding profile");
            }
            let status = response.status_code();
            let validators = HttpValidators {
                etag: safe_validator(response.headers().get("etag")?)?,
                last_modified: safe_validator(response.headers().get("last-modified")?)?,
            };
            let body =
                crate::hybrid::read_bounded_response(response, plan.limits.response_bytes as usize)
                    .await?
                    .context("source stream exceeds the response byte ceiling")?;
            plan.validate_at(&WorkerClock.now()?)?;
            Ok(SourceResponse {
                status,
                transferred_bytes: body.len() as u64,
                body,
                validators: (validators.etag.is_some() || validators.last_modified.is_some())
                    .then_some(validators),
            })
        };
        let deadline = worker::Delay::from(Duration::from_secs(
            remaining.min(u64::from(plan.limits.request_seconds)),
        ));
        pin_mut!(effect, deadline);
        match select(effect, deadline).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => bail!("source HTTP deadline elapsed"),
        }
    }
}

fn safe_validator(value: Option<String>) -> Result<Option<String>> {
    if value.as_ref().is_some_and(|value| {
        value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control)
    }) {
        bail!("source validator exceeds the closed header profile");
    }
    Ok(value)
}

struct AbortOnDrop(worker::web_sys::AbortController);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Retains bounded immutable raw evidence in the dedicated executor R2 binding.
pub(crate) struct WorkerEvidenceStore {
    pub(crate) bucket: Bucket,
}

fn evidence_key(partition: &str, digest: Sha256Digest) -> Result<String> {
    if partition.is_empty() || partition.len() > 128 || partition.chars().any(char::is_control) {
        bail!("invalid assessment evidence partition");
    }
    Ok(format!(
        "assessment-evidence/v1/{}/{}",
        Sha256Digest::of_bytes(partition),
        digest
    ))
}

#[async_trait::async_trait(?Send)]
impl EvidenceStore for WorkerEvidenceStore {
    async fn retain(&self, partition: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        if bytes.len() as u64 > EVIDENCE_LIMIT {
            bail!("raw source evidence exceeds custody limit");
        }
        let digest = Sha256Digest::of_bytes(bytes);
        self.bucket
            .put(evidence_key(partition, digest)?, bytes.to_vec())
            .execute()
            .await?;
        Ok(digest)
    }

    async fn read(&self, partition: &str, digest: Sha256Digest, max_bytes: u64) -> Result<Vec<u8>> {
        if max_bytes > EVIDENCE_LIMIT {
            bail!("source evidence read exceeds custody limit");
        }
        let object = self
            .bucket
            .get(evidence_key(partition, digest)?)
            .execute()
            .await?
            .context("retained source evidence is unavailable")?;
        if object.size() > max_bytes {
            bail!("retained source evidence exceeds read limit");
        }
        let mut stream = object
            .body()
            .context("retained source evidence body is absent")?
            .stream()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let length = bytes
                .len()
                .checked_add(chunk.len())
                .filter(|length| *length as u64 <= max_bytes)
                .context("source custody stream exceeds read limit")?;
            bytes
                .try_reserve(length - bytes.len())
                .context("source custody allocation failed")?;
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() as u64 != object.size() || Sha256Digest::of_bytes(&bytes) != digest {
            bail!("retained source evidence differs from its immutable identity");
        }
        Ok(bytes)
    }
}
