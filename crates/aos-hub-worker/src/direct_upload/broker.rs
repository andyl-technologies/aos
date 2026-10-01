//! Bounded authenticated Native control transport and direct part delegation.
//!
//! Native rechecks the logical owner for every public action and each Complete
//! boundary. The broker retains originals before provider effects and returns
//! only sparse logical status and exact private-stage UploadPart capabilities.

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::*,
    storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER},
};
use wasm_bindgen::JsValue;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use super::{
    batches::{bounded, item_error, merge_reply, merge_status},
    complete,
    config::QualifiedConfig,
    control::{self, Transport},
    effects::{abort_one, begin, grant},
    journal,
    storage::{self, Operation, Reply},
};

pub(super) use super::control::LogicalReply;
pub(crate) use super::effects::{created, AbortPlacementReceipt};

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok(response) => Response::from_json(&response),
        Err(_) => Response::error("direct upload control unavailable", 409),
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<DirectUploadResponse> {
    ensure!(
        request.method() == Method::Post,
        "direct public method invalid"
    );
    let entry = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    let foreground = DirectForegroundBudget {
        invocation_id: journal::digest(&uuid::Uuid::new_v4().to_string())?,
        issued_at: WireInteger::new(entry),
        expires_at: WireInteger::new(
            entry
                .checked_add(30)
                .ok_or_else(|| anyhow::anyhow!("direct foreground clock overflow"))?,
        ),
    };
    // The fixed entry budget precedes the first body read and all durable/queue waits.
    let bytes = crate::hybrid::read_bounded_body(request, MAX_DIRECT_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct public control exceeds bound"))?;
    let public = decode_public(request.url()?.path(), &bytes)?;
    public.validate()?;
    let qualified = match QualifiedConfig::load(env).await {
        Ok(qualified) => qualified,
        Err(error) => {
            let DirectUploadRequest::CompleteBatch(batch) = public else {
                return Err(error);
            };
            let context = context_at(
                request,
                env,
                &bytes,
                foreground,
                super::config::guard_latest_now(env)?,
            )?;
            let mut response = DirectUploadResponse {
                operation_id: batch.operation_id,
                sessions: Vec::new(),
                grants: Vec::new(),
                errors: Vec::new(),
            };
            // This runtime can only read exact retained positives and exchange
            // fresh Native controls. Missing evidence never enters a provider phase.
            complete::execute_historical(
                request,
                env,
                &context,
                &bytes,
                batch.items,
                &mut response,
            )
            .await;
            return Ok(response);
        }
    };
    let context = context(request, env, &bytes, foreground, &qualified)?;
    let operation_id = public_operation_id(&public).to_owned();
    let mut response = DirectUploadResponse {
        operation_id,
        sessions: Vec::new(),
        grants: Vec::new(),
        errors: Vec::new(),
    };
    let maximum = parallelism(&qualified);
    match public {
        DirectUploadRequest::BeginBatch(batch) => {
            let reply = logical(
                request,
                env,
                &qualified,
                &context,
                DirectUploadLogicalRequest::Admission {
                    intents: batch.items,
                },
            )
            .await?
            .reply;
            response.sessions = reply.sessions.clone();
            response.errors = reply.errors.clone();
            let outcomes = bounded(
                reply.admissions.iter().map(|admission| async {
                    (
                        &admission.intent.client_operation_id,
                        begin(env, &qualified, admission, &context).await,
                    )
                }),
                maximum,
            )
            .await;
            for (identity, result) in outcomes {
                if let Err(error) = result {
                    response.errors.push(item_error(identity, &error));
                }
            }
        }
        DirectUploadRequest::StatusBatch(batch) => {
            let sessions = batch
                .items
                .iter()
                .map(|item| authorization(&item.session, &batch.operation_id, None, None))
                .collect();
            let reply = logical(
                request,
                env,
                &qualified,
                &context,
                authorize(DirectLogicalAction::Status, None, sessions),
            )
            .await?
            .reply;
            response.sessions = reply.sessions.clone();
            response.errors = reply.errors.clone();
            let outcomes = bounded(
                batch.items.iter().filter_map(|query| {
                    let admission = admitted(
                        &reply,
                        &authorization(&query.session, &batch.operation_id, None, None),
                    )?;
                    let mut status = response
                        .sessions
                        .iter()
                        .find(|value| value.session == query.session)?
                        .clone();
                    Some(async move {
                        let result = sparse_status(env, admission, query, &mut status).await;
                        (&query.session.session_id, status, result)
                    })
                }),
                maximum,
            )
            .await;
            for (identity, status, result) in outcomes {
                match result {
                    Ok(()) => merge_status(&mut response, status),
                    Err(error) => response.errors.push(item_error(identity, &error)),
                }
            }
        }
        DirectUploadRequest::GrantPartsBatch(batch) => {
            let sessions = batch
                .items
                .iter()
                .map(|item| authorization(&item.session, &item.operation_id, None, None))
                .collect();
            let reply = logical(
                request,
                env,
                &qualified,
                &context,
                authorize(DirectLogicalAction::GrantParts, None, sessions),
            )
            .await?
            .reply;
            response.sessions = reply.sessions.clone();
            response.errors = reply.errors.clone();
            let outcomes = bounded(
                batch.items.iter().filter_map(|item| {
                    let admission = admitted(
                        &reply,
                        &authorization(&item.session, &item.operation_id, None, None),
                    )?;
                    let qualified = &qualified;
                    let context = &context;
                    Some(async move {
                        (
                            &item.operation_id,
                            grant(env, qualified, admission, item, context).await,
                        )
                    })
                }),
                maximum,
            )
            .await;
            for (identity, result) in outcomes {
                match result {
                    Ok(grant) => response.grants.push(grant),
                    Err(error) => response.errors.push(item_error(identity, &error)),
                }
            }
        }
        DirectUploadRequest::ReportPartsBatch(batch) => {
            let sessions = batch
                .items
                .iter()
                .map(|item| authorization(&item.session, &item.operation_id, None, None))
                .collect();
            let reply = logical(
                request,
                env,
                &qualified,
                &context,
                authorize(DirectLogicalAction::ReportParts, None, sessions),
            )
            .await?
            .reply;
            response.sessions = reply.sessions.clone();
            response.errors = reply.errors.clone();
            let outcomes = bounded(
                batch.items.iter().filter_map(|report| {
                    let admission = admitted(
                        &reply,
                        &authorization(&report.session, &report.operation_id, None, None),
                    )?;
                    let qualified = &qualified;
                    let context = &context;
                    Some(async move {
                        let result = async {
                            current(qualified, context, admission)?;
                            storage::call(
                                env,
                                admission,
                                Operation::Report {
                                    report: report.clone(),
                                },
                            )
                            .await?;
                            Ok(())
                        }
                        .await;
                        (&report.operation_id, result)
                    })
                }),
                maximum,
            )
            .await;
            for (identity, result) in outcomes {
                if let Err(error) = result {
                    response.errors.push(item_error(identity, &error));
                }
            }
        }
        DirectUploadRequest::CompleteBatch(batch) => {
            complete::execute(
                request,
                env,
                &qualified,
                &context,
                &bytes,
                batch.items,
                &mut response,
            )
            .await;
        }
        DirectUploadRequest::Abort(batch) => {
            let sessions = batch
                .items
                .iter()
                .map(|item| {
                    authorization(
                        &item.session,
                        &item.operation_id,
                        Some(item.expected_resource_version),
                        None,
                    )
                })
                .collect();
            let reply = logical(
                request,
                env,
                &qualified,
                &context,
                authorize(DirectLogicalAction::Abort, None, sessions),
            )
            .await?
            .reply;
            response.sessions = reply.sessions.clone();
            response.errors = reply.errors.clone();
            let finished = bounded(
                batch.items.iter().filter_map(|abort| {
                    let admission = admitted(
                        &reply,
                        &authorization(
                            &abort.session,
                            &abort.operation_id,
                            Some(abort.expected_resource_version),
                            None,
                        ),
                    )?;
                    let qualified = &qualified;
                    let context = &context;
                    Some(async move {
                        (
                            &abort.operation_id,
                            abort_one(env, qualified, admission, abort, context).await,
                        )
                    })
                }),
                maximum,
            )
            .await;
            let mut outcomes = Vec::new();
            for (identity, result) in finished {
                match result {
                    Ok(evidence) => outcomes.push(evidence),
                    Err(error) => response.errors.push(item_error(identity, &error)),
                }
            }
            if !outcomes.is_empty() {
                let identities = outcomes
                    .iter()
                    .map(|outcome| outcome.operation_id.clone())
                    .collect::<Vec<_>>();
                let settled = logical(
                    request,
                    env,
                    &qualified,
                    &context,
                    DirectUploadLogicalRequest::AbortReport { outcomes },
                )
                .await;
                match settled {
                    Ok(reply) => merge_reply(&mut response, reply.reply),
                    Err(error) => {
                        for identity in identities {
                            response.errors.push(item_error(&identity, &error));
                        }
                    }
                }
            }
        }
    }
    response.validate()?;
    Ok(response)
}

async fn sparse_status(
    env: &Env,
    admission: &DirectUploadAdmission,
    query: &DirectStatusQuery,
    status: &mut DirectSessionStatus,
) -> Result<()> {
    let mut remaining = query.maximum_parts;
    let after_placement = query
        .after
        .as_ref()
        .map_or(0, |cursor| cursor.placement.placement_id.get());
    let mut last = None;
    status.next_cursor = None;
    for placement in &admission.placements {
        if placement.placement_id.get() < after_placement {
            continue;
        }
        let mut after = query
            .after
            .as_ref()
            .filter(|cursor| cursor.placement.placement_id == placement.placement_id)
            .map_or(0, |cursor| cursor.part_number);
        loop {
            // Read one extra retained record to distinguish a terminal page;
            // sparse absent grants never imply pending provider work.
            let maximum = remaining.saturating_add(1).min(64);
            let Reply::Parts { parts } = storage::call(
                env,
                admission,
                Operation::PartPage {
                    placement_id: placement.placement_id,
                    after,
                    maximum,
                },
            )
            .await?
            else {
                anyhow::bail!("direct sparse page differs");
            };
            let count = parts.len();
            for part in parts {
                if remaining == 0 {
                    status.next_cursor = last;
                    return Ok(());
                }

                after = part.part.part_number;
                last = Some(DirectPartCursor {
                    placement: part.placement.clone(),
                    part_number: after,
                });
                status.parts.push(DirectPartStatus {
                    placement: part.placement,
                    part_number: after,
                    observed: part.observed,
                    pending_operation_id: None,
                    unknown: false,
                });
                remaining -= 1;
            }
            if count < maximum as usize {
                break;
            }
        }
    }
    Ok(())
}

fn admitted<'a>(
    reply: &'a DirectUploadLogicalReply,
    authorization: &DirectSessionAuthorization,
) -> Option<&'a DirectUploadAdmission> {
    if !reply.authorizations.contains(authorization) {
        return None;
    }

    reply.admissions.iter().find(|admission| {
        admission.session_id == authorization.session.session_id
            && admission.logical_fingerprint == authorization.session.logical_fingerprint
    })
}

pub(super) fn current(
    qualified: &QualifiedConfig,
    context: &DirectRequestContext,
    admission: &DirectUploadAdmission,
) -> Result<()> {
    let latest = qualified.latest_now()?;
    context.foreground.validate_at(latest)?;
    ensure!(
        latest < admission.expires_at.get()
            && admission.intent.byte_size.get() <= qualified.runtime.maximum_object_bytes.get(),
        "direct original admission no longer eligible"
    );
    Ok(())
}

pub(super) fn parallelism(qualified: &QualifiedConfig) -> usize {
    qualified
        .runtime
        .maximum_parallel_objects
        .get()
        .min(qualified.runtime.maximum_parallel_provider_requests.get()) as usize
}

pub(super) fn authorization(
    session: &DirectSessionRef,
    operation: &str,
    version: Option<WireInteger>,
    complete: Option<DirectCompleteRequest>,
) -> DirectSessionAuthorization {
    DirectSessionAuthorization {
        session: session.clone(),
        expected_resource_version: version,
        operation_id: operation.into(),
        complete_intent: complete,
    }
}

fn authorize(
    action: DirectLogicalAction,
    complete_step: Option<DirectCompleteStep>,
    sessions: Vec<DirectSessionAuthorization>,
) -> DirectUploadLogicalRequest {
    DirectUploadLogicalRequest::Authorize {
        action,
        complete_step,
        stage_evidence: Vec::new(),
        retained_stage_digests: Vec::new(),
        baseline_evidence: Vec::new(),
        baseline_witnesses: Vec::new(),
        baseline_witness_refs: Vec::new(),
        settled_placements: Vec::new(),
        sessions,
    }
}

pub(super) async fn logical(
    request: &Request,
    env: &Env,
    qualified: &QualifiedConfig,
    original: &DirectRequestContext,
    value: DirectUploadLogicalRequest,
) -> Result<LogicalReply> {
    let context = fresh_context(qualified, original)?;
    logical_with_context(request, env, qualified, &context, value).await
}

pub(super) fn fresh_context(
    qualified: &QualifiedConfig,
    original: &DirectRequestContext,
) -> Result<DirectRequestContext> {
    fresh_context_at(original, qualified.latest_now()?)
}

pub(super) fn fresh_context_at(
    original: &DirectRequestContext,
    latest_now: u64,
) -> Result<DirectRequestContext> {
    let mut context = original.clone();
    context.issued_at = WireInteger::new(u64::try_from(aos_hub_core::clock::now_unix_secs())?);
    context.request_nonce = journal::digest(&uuid::Uuid::new_v4().to_string())?;
    context.validate(
        &original.deployment_id,
        &original.executor_public_origin,
        latest_now,
    )?;
    Ok(context)
}

pub(super) async fn logical_with_context(
    request: &Request,
    env: &Env,
    qualified: &QualifiedConfig,
    context: &DirectRequestContext,
    value: DirectUploadLogicalRequest,
) -> Result<LogicalReply> {
    logical_with_clock(request, env, context, value, || qualified.latest_now()).await
}

pub(super) async fn logical_with_clock(
    request: &Request,
    env: &Env,
    context: &DirectRequestContext,
    value: DirectUploadLogicalRequest,
    latest_now: impl Fn() -> Result<u64>,
) -> Result<LogicalReply> {
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    control::exchange(
        &WorkerTransport { request, env },
        &key,
        context,
        value,
        latest_now,
    )
    .await
}

struct WorkerTransport<'a> {
    request: &'a Request,
    env: &'a Env,
}

#[async_trait::async_trait(?Send)]
impl Transport for WorkerTransport<'_> {
    async fn post(&self, phase: &str, signed: SignedDirectControl) -> Result<SignedDirectControl> {
        let headers = self.request.headers().clone();
        headers.set(DIRECT_LOGICAL_SIGNATURE_HEADER, &signed.signature)?;
        headers.set("content-type", "application/json")?;
        headers.delete("content-length")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(JsValue::from(js_sys::Uint8Array::from(
                signed.body.as_slice(),
            ))));
        let internal = Request::new_with_init(self.request.url()?.as_str(), &init)?;
        let response = crate::hybrid::proxy_upload_phase(internal, self.env, phase).await?;
        ensure!(
            response.status_code() == 200,
            "direct Native logical authorization refused"
        );
        let signature = response
            .headers()
            .get(DIRECT_LOGICAL_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("direct Native reply authentication absent"))?;
        let bytes = crate::hybrid::read_bounded_response(response, MAX_DIRECT_CONTROL_BYTES)
            .await?
            .ok_or_else(|| anyhow::anyhow!("direct Native logical reply exceeds bound"))?;
        Ok(SignedDirectControl {
            body: bytes,
            signature,
        })
    }
}

fn context(
    request: &Request,
    env: &Env,
    body: &[u8],
    foreground: DirectForegroundBudget,
    qualified: &QualifiedConfig,
) -> Result<DirectRequestContext> {
    context_at(request, env, body, foreground, qualified.latest_now()?)
}

fn context_at(
    request: &Request,
    env: &Env,
    body: &[u8],
    foreground: DirectForegroundBudget,
    latest_now: u64,
) -> Result<DirectRequestContext> {
    use sha2::{Digest as _, Sha256};
    let url = request.url()?;
    ensure!(
        url.scheme() == "https" && url.query().is_none(),
        "direct public origin or query invalid"
    );
    let origin = url.origin().ascii_serialization();
    let public_authority = origin
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("direct public authority absent"))?
        .to_owned();
    let context = DirectRequestContext {
        deployment_id: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        executor_public_origin: env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
        public_authority,
        request_nonce: journal::digest(&uuid::Uuid::new_v4().to_string())?,
        request_body_sha256: hex::encode(Sha256::digest(body)),
        public_method: "POST".into(),
        public_path: url.path().into(),
        issued_at: foreground.issued_at,
        expires_at: foreground.expires_at,
        foreground,
    };
    context.validate(
        &context.deployment_id,
        &context.executor_public_origin,
        latest_now,
    )?;
    Ok(context)
}

fn decode_public(path: &str, body: &[u8]) -> Result<DirectUploadRequest> {
    match path.strip_prefix("/aos.hub.v1.DirectUploadService/") {
        Some("BeginBatch") => Ok(DirectUploadRequest::BeginBatch(decode_direct_control(
            body,
        )?)),
        Some("StatusBatch") => Ok(DirectUploadRequest::StatusBatch(decode_direct_control(
            body,
        )?)),
        Some("GrantPartsBatch") => Ok(DirectUploadRequest::GrantPartsBatch(decode_direct_control(
            body,
        )?)),
        Some("ReportPartsBatch") => Ok(DirectUploadRequest::ReportPartsBatch(
            decode_direct_control(body)?,
        )),
        Some("CompleteBatch") => Ok(DirectUploadRequest::CompleteBatch(decode_direct_control(
            body,
        )?)),
        Some("Abort") => Ok(DirectUploadRequest::Abort(decode_direct_control(body)?)),
        _ => anyhow::bail!("direct method unsupported"),
    }
}

fn public_operation_id(request: &DirectUploadRequest) -> &str {
    match request {
        DirectUploadRequest::BeginBatch(value) => &value.operation_id,
        DirectUploadRequest::StatusBatch(value) => &value.operation_id,
        DirectUploadRequest::GrantPartsBatch(value) => &value.operation_id,
        DirectUploadRequest::ReportPartsBatch(value) => &value.operation_id,
        DirectUploadRequest::CompleteBatch(value) => &value.operation_id,
        DirectUploadRequest::Abort(value) => &value.operation_id,
    }
}

pub(crate) async fn capabilities(
    request: &Request,
    env: &Env,
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
) -> worker::Result<Response> {
    match capabilities_inner(request, env, key, signature, body).await {
        Ok(signed) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signed.signature)?;
            let response = Response::from_bytes(signed.body)?.with_headers(headers);
            crate::control_receipt::emit_buffered_response(
                aos_hub_core::storage_work::STORAGE_CAPABILITIES_PATH,
                body,
                &response,
            )
            .await;
            Ok(response)
        }
        Err(_) => Response::error("direct protected capability unavailable", 409),
    }
}

async fn capabilities_inner(
    request: &Request,
    env: &Env,
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
) -> Result<SignedDirectControl> {
    let qualified = QualifiedConfig::load(env).await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let origin = request.url()?.origin().ascii_serialization();
    let challenge = verify_direct_storage_capabilities_request(
        key,
        signature,
        body,
        &deployment,
        &origin,
        qualified.latest_now()?,
    )?;
    let (profile, policy, runtime) = if challenge.managed {
        let (protected, _) = qualified.managed(env)?;
        let DirectProtectedProfile::Managed {
            profile,
            private_stage_policy,
            runtime_qualification,
        } = protected
        else {
            anyhow::bail!("direct managed protected profile differs");
        };
        (
            Some(profile),
            Some(private_stage_policy),
            Some(runtime_qualification),
        )
    } else {
        (None, None, None)
    };
    let profiles =
        crate::external_object::resolve_external_profiles(env, &challenge.external_selectors)
            .await?;
    let external_profiles = profiles
        .into_iter()
        .map(|profile| DirectProtectedExternalProfile::new(profile, qualified.runtime.clone()))
        .collect::<Result<Vec<_>>>()?;
    challenge.validate(&deployment, &origin, qualified.latest_now()?)?;
    sign_direct_storage_capabilities_reply(
        key,
        &DirectStorageCapabilitiesReply {
            request: challenge,
            capabilities: DirectStorageCapabilities {
                version: 2,
                capability: DIRECT_UPLOAD_CAPABILITY.into(),
                profile,
                private_stage_policy: policy,
                runtime_qualification: runtime,
                external_profiles,
            },
        },
    )
}
