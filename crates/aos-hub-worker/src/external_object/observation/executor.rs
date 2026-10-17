//! Fresh guarded HEAD execution; positive terminal history never renews freshness.

use anyhow::{ensure, Result};
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::storage_authority::external_object::{
    observation::{
        ExternalObservation, ExternalObservationOutcome, ExternalObservationRequest,
        MAX_OBSERVATION_REQUEST_BYTES,
    },
    ExternalObjectHead,
};
use aos_hub_core::storage_work::{
    StorageCredentialSelector, StorageWorkKey, StorageWorkOperation, STORAGE_WORK_SIGNATURE_HEADER,
};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response};

use super::super::{
    config::{configured, Config},
    executor::select_cohort,
    protocol::{digest, Effect, Intent as ObjectIntent, GUARD_HEADER, SCOPE_HEADER},
    storage as object_storage,
};
use super::protocol::{
    self, Intent, Operation, Receipt, Reply, Request as GuardRequest, MAX_MESSAGE,
};
use super::reply::ReplyBinding;

/// Returns exact-request authenticated metadata observation or generic refusal.
///
/// # Errors
/// Returns an error only when the runtime cannot construct a bounded response.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok((body, mac)) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            headers.set(STORAGE_WORK_SIGNATURE_HEADER, &mac)?;
            Ok(
                Response::ok(String::from_utf8(body).map_err(object_storage::error)?)?
                    .with_headers(headers),
            )
        }
        Err(_) => Response::error("external observation refused", 409),
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<(Vec<u8>, String)> {
    ensure!(
        request.method() == Method::Post,
        "invalid observation method"
    );
    let config = configured(env)?.ok_or_else(|| anyhow::anyhow!("consumer disabled"))?;
    let mac = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("application signature missing"))?;
    let body = crate::hybrid::read_bounded_body(request, MAX_OBSERVATION_REQUEST_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("observation request oversized"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    let request = ExternalObservationRequest::authenticate(
        &key,
        &mac,
        &body,
        &deployment,
        config.clock().observed_at,
    )?;
    execute_authorized(
        env,
        &config,
        &deployment,
        &key,
        &request,
        ReplyBinding::Existing(&body),
    )
    .await
}

/// Executes the already authenticated caller's exact guarded HEAD authorization.
///
/// # Errors
/// Returns an error for changed binding, scope, lease, guard or provider outcome.
pub(super) async fn execute_authorized(
    env: &Env,
    config: &Config,
    deployment: &str,
    key: &StorageWorkKey,
    request: &ExternalObservationRequest,
    reply: ReplyBinding<'_>,
) -> Result<(Vec<u8>, String)> {
    let work = &request.authorization;
    let publication = crate::hybrid_binding::resolve_for_plan(env, &work.plan).await?;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, config.clock().observed_at)?;
    let StorageWorkOperation::Head { path } = &work.plan.operation else {
        anyhow::bail!("observation is not HEAD");
    };
    let cohort = select_cohort(
        &config,
        &publication,
        "read",
        work.binding_write_revision.get(),
    )?;
    reply.validate_cohort(cohort)?;
    let full_key = [
        &publication.snapshot.object_prefix,
        &work.plan.placement_prefix,
        path,
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .map(String::as_str)
    .collect::<Vec<_>>()
    .join("/");
    let scope = config.scope(cohort, full_key)?;
    let intent = Intent {
        object: ObjectIntent {
            scope: scope.clone(),
            operation_id: work.operation_id.clone(),
            context: digest(&(
                cohort,
                work.plan.placement_id,
                work.plan.placement_resource_version,
                &work.plan.placement_prefix,
            ))?,
            cohort_digest: digest(cohort)?,
            effect: Effect::Head,
        },
        expectation: request.expectation.clone(),
    };
    intent.validate()?;
    let begin = GuardRequest {
        domain: protocol::DOMAIN.into(),
        scope: scope.clone(),
        operation: Operation::Begin {
            intent: intent.clone(),
            lease: work.lease.clone(),
        },
    };
    let (turn, floor) = match call(env, &begin, || {
        reply.check_begin_time(work, &publication.snapshot, config.clock().observed_at)
    })
    .await?
    {
        Reply::Historical { receipt } => {
            ensure!(receipt.turn.intent == intent, "historical intent differs");
            return reply.sign(
                key,
                ExternalObservationOutcome::HistoricalObservation(receipt.observation),
            );
        }
        Reply::Dispatch { turn, floor } => (turn, floor),
        _ => anyhow::bail!("observation Begin did not acknowledge dispatch"),
    };
    turn.validate()?;
    ensure!(
        turn.intent == intent
            && floor.full_key == scope.full_key
            && floor.authority == cohort.authority
            && floor.executor_identity == config.executor_identity,
        "observation dispatch domain differs"
    );

    let now = config.clock().observed_at;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, now)?;
    let selector = StorageCredentialSelector {
        purpose: "read".into(),
        generation: cohort.credential.generation.get(),
    };
    let secret = publication.credential_text(&selector, &deployment, now)?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        &work.plan.placement_prefix,
        Some(secret.as_str()),
        now,
    )?;
    let url = surface.object_url(S3Method::Head, path, now)?;
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Head)
        .with_redirect(RequestRedirect::Manual);
    let provider = Request::new_with_init(&url, &init)?;
    let validated = config.verifier()?.validate_lease(
        work.lease.as_bytes(),
        cohort,
        &config.timing_profile,
        &floor,
        &scope.full_key,
        aos_hub_core::storage_authority::lease::LeaseEffect::Head,
        config.clock(),
    )?;
    let observed_clock = config.clock();
    work.check_dispatch_time(&publication.snapshot, &validated, &floor, observed_clock)?;
    // Fetch invokes the provider synchronously before its first await. The slot
    // owns this exact physical identity until positive terminal acknowledgement.
    let response = Fetch::Request(provider).send().await?;
    let object = match response.status_code() {
        404 => None,
        200 => Some(ExternalObjectHead {
            provider_version: None,
            bytes: response
                .headers()
                .get("content-length")?
                .ok_or_else(|| anyhow::anyhow!("HEAD size absent"))?,
            etag: response
                .headers()
                .get("etag")?
                .ok_or_else(|| anyhow::anyhow!("HEAD ETag absent"))?,
        }),
        _ => anyhow::bail!("HEAD not positively acknowledged"),
    };
    let observation = ExternalObservation {
        operation_id: intent.object.operation_id.clone(),
        intent_digest: intent.fingerprint()?,
        turn_digest: digest(&turn)?,
        guard_stamp: turn.stamp.clone(),
        observed_at: observed_clock.observed_at.to_string(),
        object,
    };
    let receipt = Receipt { turn, observation };
    receipt.validate()?;
    let terminal = GuardRequest {
        domain: protocol::DOMAIN.into(),
        scope: scope.clone(),
        operation: Operation::Terminal {
            receipt: receipt.clone(),
        },
    };
    match call(env, &terminal, || Ok(())).await? {
        Reply::TerminalAcknowledged {
            receipt: acknowledged,
        } if acknowledged == receipt => {}
        _ => anyhow::bail!("observation terminal acknowledgement differs"),
    }

    // A late acknowledgement retains truth, not fresh permission. Recheck full
    // read authority after the await and scalar time after verification CPU.
    let freshness = (|| -> Result<()> {
        publication
            .snapshot
            .authorizes(&work.plan, &deployment, config.clock().observed_at)?;
        let validated = config.verifier()?.validate_lease(
            work.lease.as_bytes(),
            cohort,
            &config.timing_profile,
            &floor,
            &scope.full_key,
            aos_hub_core::storage_authority::lease::LeaseEffect::Head,
            config.clock(),
        )?;
        work.check_dispatch_time(&publication.snapshot, &validated, &floor, config.clock())
    })();
    let fresh = freshness.is_ok();
    let outcome = if fresh {
        ExternalObservationOutcome::ObservedThisInvocation(receipt.observation.clone())
    } else {
        ExternalObservationOutcome::HistoricalObservation(receipt.observation.clone())
    };
    let signed = reply.sign(key, outcome)?;
    // Canonical reply/MAC CPU must not turn a late acknowledgement into renewed
    // freshness either. A downgrade keeps the original observation unchanged.
    if fresh
        && work
            .check_dispatch_time(&publication.snapshot, &validated, &floor, config.clock())
            .is_err()
    {
        return reply.sign(
            key,
            ExternalObservationOutcome::HistoricalObservation(receipt.observation),
        );
    }
    Ok(signed)
}

async fn call(
    env: &Env,
    request: &GuardRequest,
    check_before_send: impl FnOnce() -> Result<()>,
) -> Result<Reply> {
    let body = serde_json::to_vec(request)?;
    ensure!(body.len() <= MAX_MESSAGE, "observation turn oversized");
    let mac = object_storage::key(env)?.sign_body(&body)?;
    let name = request.scope.guard_name()?;
    let stub = env
        .durable_object(object_storage::BINDING)?
        .id_from_name(&name)?
        .get_stub()?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &mac)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let invocation = Request::new_with_init("https://external-object/observation-turn", &init)?;
    check_before_send()?;
    let response = stub.fetch_with_request(invocation).await?;
    ensure!(
        response.status_code() == 200,
        "guard refused observation turn"
    );
    let body = crate::direct_digest::read_bounded_native(response, MAX_MESSAGE).await?;
    let value: Reply = serde_json::from_slice(&body)?;
    ensure!(
        serde_json::to_vec(&value)? == body,
        "noncanonical observation guard reply"
    );
    Ok(value)
}
