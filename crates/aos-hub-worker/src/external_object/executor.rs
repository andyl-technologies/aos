//! Authenticated byte executor; actual provider invocation follows final lease check.
//!
//! Bodies, provider URLs and secrets never enter compact object DO messages.
//! Ambiguous provider failure leaves the retained turn untouched. Successful
//! terminal replay returns historical acknowledgement without provider access.

use anyhow::{ensure, Result};
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::storage_authority::{
    external_object::{
        ExternalObjectRequest, ExternalObjectResult, EXTERNAL_OBJECT_PATH,
        MAX_EXTERNAL_OBJECT_REQUEST_BYTES,
    },
    lease::LeaseCohort,
};
use aos_hub_core::storage_work::{
    StorageBindingPublication, StorageBindingSnapshot, StorageCredentialSelector, StorageWorkKey,
    StorageWorkOperation, STORAGE_WORK_SIGNATURE_HEADER,
};
use base64::Engine as _;
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response};

use super::{
    config::{configured, coordinates, Config},
    protocol::{
        self, Effect, GuardOperation, GuardReply, GuardRequest, HeadValue, Intent, Outcome,
        Receipt, DOMAIN, GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER,
    },
    storage,
};

pub(crate) const PATH: &str = EXTERNAL_OBJECT_PATH;

/// Refuses configured physical aliases on legacy Hybrid paths before egress.
///
/// # Errors
/// Returns an error for managed coordinates or malformed consumer configuration.
pub(crate) fn deny_legacy(env: &Env, snapshot: &StorageBindingSnapshot) -> Result<()> {
    if let Some(config) = configured(env)? {
        ensure!(
            !config.manages(snapshot)?,
            "managed external alias requires compact object consumer"
        );
    }
    Ok(())
}

/// Executes only authenticated bounded metadata PUT or historical guarded HEAD.
///
/// # Errors
/// Returns a generic response for invalid grants, unknown turns or provider I/O.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok(value) => {
            let headers = Headers::new();
            headers.set("cache-control", "private, no-store")?;
            Ok(Response::from_json(&value)?.with_headers(headers))
        }
        Err(_) => Ok(Response::error("external object request refused", 409)?),
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<ExternalObjectResult> {
    ensure!(request.method() == Method::Post, "invalid consumer method");
    let config =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("application signature missing"))?;
    let body = crate::hybrid::read_bounded_body(request, MAX_EXTERNAL_OBJECT_REQUEST_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("oversized application request"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let application_key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    let work = ExternalObjectRequest::authenticate(
        &application_key,
        &signature,
        &body,
        &deployment,
        config.clock().observed_at,
    )?;
    let publication = crate::hybrid_binding::resolve_for_plan(env, &work.plan).await?;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, config.clock().observed_at)?;
    let (path, effect, bytes, purpose) = match &work.plan.operation {
        StorageWorkOperation::PutMetadata {
            path,
            content_base64,
            sha256,
        } => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(content_base64)?;
            ensure!(
                bytes.len() <= aos_hub_core::storage_work::MAX_METADATA_BYTES
                    && hex::encode(Sha256::digest(&bytes)) == *sha256,
                "metadata commitment differs"
            );
            (
                path,
                Effect::Put {
                    sha256: sha256.clone(),
                    bytes: u32::try_from(bytes.len())?,
                },
                Some(bytes),
                "write",
            )
        }
        StorageWorkOperation::Head { path } => (path, Effect::Head, None, "read"),
        _ => anyhow::bail!("unsupported compact external operation"),
    };
    let cohort = select_cohort(
        &config,
        &publication,
        purpose,
        work.binding_write_revision.get(),
    )?;
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
    let context = protocol::digest(&(
        cohort,
        work.plan.placement_id,
        work.plan.placement_resource_version,
        &work.plan.placement_prefix,
    ))?;
    let intent = Intent {
        scope: scope.clone(),
        operation_id: work.operation_id.clone(),
        context,
        cohort_digest: protocol::digest(cohort)?,
        effect,
    };
    intent.validate()?;
    let begin = GuardRequest {
        domain: DOMAIN.into(),
        scope: scope.clone(),
        operation: GuardOperation::Begin {
            intent: intent.clone(),
            lease: work.lease.clone(),
        },
    };
    let reply = call(env, &begin).await?;
    let (turn, floor) = match reply {
        GuardReply::Terminal { receipt } => return result(&intent, &receipt),
        GuardReply::Dispatch { turn, floor } => (turn, floor),
    };
    ensure!(
        turn.intent == intent && protocol::digest_string(&turn.dispatch_nonce),
        "guard acknowledged another turn"
    );
    ensure!(
        floor.full_key == scope.full_key
            && floor.authority == cohort.authority
            && floor.executor_identity == config.executor_identity,
        "guard floor differs from configured execution domain"
    );

    // All async resolution and guard acknowledgement has finished. Provider
    // credentials are request-local; the URL is minted only for this dispatch.
    let now = config.clock().observed_at;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, now)?;
    let selector = StorageCredentialSelector {
        purpose: purpose.into(),
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
    let method = match intent.effect {
        Effect::Put { .. } => S3Method::Put,
        Effect::Head => S3Method::Head,
    };
    let url = surface.object_url(method, path, now)?;
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let mut init = RequestInit::new();
    init.with_method(if bytes.is_some() {
        Method::Put
    } else {
        Method::Head
    })
    .with_redirect(RequestRedirect::Manual);
    if let Some(bytes) = bytes.as_ref() {
        init.with_body(Some(js_sys::Uint8Array::from(bytes.as_slice()).into()));
    }
    let provider = Request::new_with_init(&url, &init)?;

    // No awaited helper lies between this validation and actual provider Fetch.
    // This is bounded new-dispatch revocation, not immediate global deny/drain.
    let validated = config.verifier()?.validate_lease(
        work.lease.as_bytes(),
        cohort,
        &config.timing_profile,
        &floor,
        &scope.full_key,
        intent.effect.lease_effect(),
        config.clock(),
    )?;
    work.check_dispatch_time(&publication.snapshot, &validated, &floor, config.clock())?;
    let response = Fetch::Request(provider).send().await?;
    let outcome = match &intent.effect {
        Effect::Put { .. } => {
            ensure!(
                response.status_code() == 200,
                "provider PUT lacks exact S3 completion acknowledgement"
            );
            Outcome::PutAcknowledged
        }
        Effect::Head => match response.status_code() {
            404 => Outcome::HistoricalHead { object: None },
            200 => {
                let bytes = response
                    .headers()
                    .get("content-length")?
                    .ok_or_else(|| anyhow::anyhow!("HEAD length missing"))?;
                let etag = response
                    .headers()
                    .get("etag")?
                    .ok_or_else(|| anyhow::anyhow!("HEAD ETag missing"))?;
                Outcome::HistoricalHead {
                    object: Some(HeadValue { bytes, etag }),
                }
            }
            _ => anyhow::bail!("provider HEAD not positively acknowledged"),
        },
    };
    let receipt = Receipt { turn, outcome };
    receipt.validate()?;
    let terminal = GuardRequest {
        domain: DOMAIN.into(),
        scope,
        operation: GuardOperation::Terminal {
            receipt: receipt.clone(),
        },
    };
    match call(env, &terminal).await? {
        GuardReply::Terminal {
            receipt: acknowledged,
        } if acknowledged == receipt => result(&intent, &acknowledged),
        _ => anyhow::bail!("terminal acknowledgement differs"),
    }
}

pub(super) fn select_cohort<'a>(
    config: &'a Config,
    publication: &StorageBindingPublication,
    purpose: &str,
    binding_write_revision: i64,
) -> Result<&'a LeaseCohort> {
    let snapshot = &publication.snapshot;
    let coordinates = coordinates(snapshot)?;
    let candidates = config
        .cohorts
        .iter()
        .filter(|cohort| {
            let association = &cohort.association;
            let credential = &cohort.credential;
            cohort.alias.spec == coordinates
                && association.binding_write_revision.get() == binding_write_revision
                && association.binding_id.get() == snapshot.binding_id
                && association.binding_stable_id == snapshot.binding_stable_id
                && association.binding_resource_version.get() == snapshot.binding_resource_version
                && association.binding_prefix == snapshot.object_prefix
                && snapshot.credentials.iter().any(|reference| {
                    reference.purpose == purpose
                        && reference.generation == credential.generation.get()
                        && reference.secret_version_ref == credential.secret_version_ref
                        && reference.fingerprint == credential.credential_fingerprint
                })
                && matches!(
                    (purpose, credential.purpose),
                    (
                        "read",
                        aos_hub_core::storage_authority::lease::LeasePurpose::Read
                    ) | (
                        "write",
                        aos_hub_core::storage_authority::lease::LeasePurpose::Write
                    )
                )
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 1,
        "binding does not select one configured cohort"
    );
    Ok(candidates[0])
}

fn result(intent: &Intent, receipt: &Receipt) -> Result<ExternalObjectResult> {
    receipt.validate()?;
    ensure!(
        receipt.turn.intent == *intent,
        "terminal replay context differs"
    );
    Ok(ExternalObjectResult {
        version: 1,
        operation_id: intent.operation_id.clone(),
        intent_digest: intent.fingerprint()?,
        outcome: receipt.outcome.clone(),
    })
}

async fn call(env: &Env, message: &GuardRequest) -> Result<GuardReply> {
    let body = serde_json::to_vec(message)?;
    ensure!(body.len() <= MAX_MESSAGE, "oversized compact turn");
    let signature = storage::key(env)?.sign_body(&body)?;
    let name = message.scope.guard_name()?;
    let namespace = env.durable_object(storage::BINDING)?;
    let stub = namespace.id_from_name(&name)?.get_stub()?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &signature)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = Request::new_with_init("https://external-object/turn", &init)?;
    let mut response = stub.fetch_with_request(request).await?;
    ensure!(
        response.status_code() == 200,
        "object journal refused compact turn"
    );
    let mut stream = response.stream()?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            body.len()
                .checked_add(chunk.len())
                .is_some_and(|n| n <= MAX_MESSAGE),
            "oversized guard reply"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}
