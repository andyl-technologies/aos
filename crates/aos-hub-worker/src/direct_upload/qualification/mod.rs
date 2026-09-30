//! Protected isolated provider and queue measurements before runtime acceptance.
//!
//! Original plans and actual material precede provider effects. Only private
//! stage operations are exposed; signed observations never authorize ordinary
//! upload admission or publication. Unknown mutations keep their permanent
//! source journals, while exact immutable verification can recover and requeue.

mod fixture;
pub(crate) mod protocol;
mod queue;

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{Env, Headers, Method, Request, RequestInit, Response, State};

use super::{
    config, effects, journal, storage,
    verification::{self, VerificationJob},
};
use protocol::{Action, Control, Original, HEADER, REPLY_DOMAIN, REQUEST_DOMAIN};

pub(crate) use protocol::PATH as QUALIFICATION_PATH;
pub(crate) use queue::consume_message;
pub(crate) use queue::physical as queue_physical;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Closed {
    object_id: String,
    job: VerificationJob,
    closed_at_millis: WireInteger,
    settlement_millis: WireInteger,
}

pub(crate) fn key(env: &Env) -> Result<StorageWorkKey> {
    ensure!(
        config::qualification_limits(env)?.is_some(),
        "isolated qualification disabled"
    );
    let control = env.secret("HUB_DIRECT_UPLOAD_CONFORMANCE_KEY")?.to_string();
    ensure!(
        control != env.secret("HUB_DIRECT_UPLOAD_JOURNAL_KEY")?.to_string(),
        "qualification control cannot authenticate queue journals"
    );
    Ok(StorageWorkKey::new(control)?)
}

async fn authenticate(request: &mut Request, env: &Env) -> Result<(Control, Vec<u8>)> {
    ensure!(
        request.method() == Method::Post,
        "qualification method invalid"
    );
    let signature = request
        .headers()
        .get(HEADER)?
        .ok_or_else(|| anyhow::anyhow!("qualification authentication absent"))?;
    let bytes = crate::hybrid::read_bounded_body(request, MAX_DIRECT_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("qualification control exceeds bound"))?;
    key(env)?.verify_body(&signature, &[REQUEST_DOMAIN, &bytes].concat())?;
    let control: Control = decode_direct_control(&bytes)?;
    ensure!(
        encode_direct_control(&control)? == bytes,
        "qualification noncanonical control"
    );
    control.validate(fixture::now()?)?;
    Ok((control, bytes))
}

fn address(env: &Env, run_id: &str) -> Result<String> {
    Ok(format!(
        "isolated-qualification:{}",
        journal::digest(&(env.var("HUB_DEPLOYMENT_ID")?.to_string(), run_id))?
    ))
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match forward(&mut request, env).await {
        Ok(response) => Ok(response),
        Err(_) => Response::error("isolated qualification control refused", 409),
    }
}

async fn forward(request: &mut Request, env: &Env) -> Result<Response> {
    let (control, bytes) = authenticate(request, env).await?;
    let headers = Headers::new();
    headers.set(
        HEADER,
        &key(env)?.sign_body(&[REQUEST_DOMAIN, &bytes].concat())?,
    )?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from(js_sys::Uint8Array::from(
            bytes.as_slice(),
        ))));
    let stub = env
        .durable_object(storage::BINDING)?
        .id_from_name(&address(env, &control.run_id)?)?
        .get_stub()?;
    Ok(stub
        .fetch_with_request(Request::new_with_init(
            "https://qualification/qualification",
            &init,
        )?)
        .await?)
}

pub(crate) async fn physical(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> worker::Result<Response> {
    let (control, body) = match authenticate(request, env).await {
        Ok(value) => value,
        Err(_) => return Response::error("qualification authentication refused", 409),
    };
    let outcome = execute(&control, env, state).await;
    let (status, result) = match outcome {
        Ok(result) => (200, result),
        // No provider exception or bearer capability is persisted as a cause.
        Err(_) => (409, serde_json::json!({"state":"refused_or_unknown"})),
    };
    let reply = serde_json::json!({"version":1,"requestSha256":hex::encode(sha2::Sha256::digest(&body)),
        "nonce":control.nonce,"sourceDigest":fixture::source().map_err(runtime_error)?,
        "scriptVersion":config::runtime_script_version(env).map_err(runtime_error)?,
        "observedAtMillis":worker::Date::now().as_millis().to_string(),"result":result});
    let bytes = encode_direct_control(&reply).map_err(runtime_error)?;
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "no-store")?;
    headers.set(
        HEADER,
        &key(env)
            .map_err(runtime_error)?
            .sign_body(&[REPLY_DOMAIN, &bytes].concat())
            .map_err(runtime_error)?,
    )?;
    Ok(Response::from_bytes(bytes)?
        .with_headers(headers)
        .with_status(status))
}

use super::authority::StageAuthority as _;
use sha2::Digest as _;

fn runtime_error(_: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError("isolated qualification bounded runtime refused".into())
}

async fn execute(control: &Control, env: &Env, state: &State) -> Result<serde_json::Value> {
    ensure!(
        env.durable_object(storage::BINDING)?
            .id_from_name(&address(env, &control.run_id)?)?
            .to_string()
            == state.id().to_string(),
        "qualification original owner differs"
    );
    let current_source = fixture::source()?;
    let current_script = config::runtime_script_version(env)?;
    let inspection = matches!(control.action, Action::Status | Action::Inspect { .. });
    ensure!(
        inspection
            || (control.source_digest == current_source
                && control.script_version == current_script),
        "qualification current source or script changed"
    );
    if matches!(control.action, Action::Clock) {
        return Ok(
            serde_json::json!({"kind":"clock","observedAtMillis":worker::Date::now().as_millis().to_string(),
            "uncertaintySeconds":fixture::uncertainty(env)?.to_string(),"nonce":control.nonce}),
        );
    }
    let storage = state.storage();
    let retained: Option<Original> = storage::read(&storage, "qualification/original/v1").await?;
    let original = if let Some(original) = retained {
        ensure!(
            original.run_id == control.run_id
                && (inspection
                    || (original.source_digest == current_source
                        && original.script_version == current_script)),
            "qualification immutable original changed"
        );
        if let Action::Start { provider, objects } = &control.action {
            ensure!(
                &original.provider == provider && &original.objects == objects,
                "qualification original plans changed"
            );
        }
        original
    } else {
        let Action::Start { provider, objects } = &control.action else {
            anyhow::bail!("qualification original absent");
        };
        let original = fixture::original(env, control, provider, objects).await?;
        storage::write(&storage, "qualification/original/v1", &original).await?;
        original
    };
    if matches!(control.action, Action::Start { .. }) {
        return Ok(serde_json::json!({"state":"original_retained","original":original}));
    }
    if let Action::ExpiredMutation { cutoff } = control.action {
        let authority = fixture::Fixture {
            original: &original,
            uncertainty: fixture::uncertainty(env)?,
        };
        let observed = super::authority::StageAuthority::latest_now(&authority)?;
        ensure!(
            observed >= cutoff.get(),
            "qualification cutoff has not elapsed"
        );
        let object = original
            .objects
            .first()
            .ok_or_else(|| anyhow::anyhow!("qualification source absent"))?;
        let resolved = fixture::admission(&original, object, &original.deployment_id)?;
        let admission = &resolved;
        let mut context = fixture::context(env, control, admission)?;
        context.foreground.issued_at = WireInteger::new(cutoff.get().saturating_sub(30));
        context.foreground.expires_at = cutoff;
        let before = super::provider_capacity::observation();
        let refused = effects::begin(env, &authority, admission, &context)
            .await
            .is_err();
        let after = super::provider_capacity::observation();
        ensure!(
            refused
                && before.isolate_id == after.isolate_id
                && before.dispatches == after.dispatches,
            "qualification expired stage dispatched a provider operation"
        );
        return Ok(
            serde_json::json!({"kind":"expired_mutation_refused","cutoff":cutoff,
            "observedAt":observed.to_string(),"providerBefore":before,"providerAfter":after}),
        );
    }
    if inspection {
        if let Action::Inspect {
            object_id,
            after_attempt,
        } = &control.action
        {
            ensure!(
                original.objects.iter().any(|o| &o.object_id == object_id) && *after_attempt <= 128,
                "qualification inspection cursor invalid"
            );
            let count = queue::attempt_count(&storage, object_id).await?;
            // A metadata proof can contain a large bounded semantic projection.
            // Keep each proof independently retrievable within the control cap.
            let attempts = queue::attempt_page(&storage, object_id, *after_attempt, 1).await?;
            let closed: Option<Closed> =
                storage::read(&storage, &format!("qualification/closed/{object_id}")).await?;
            return Ok(
                serde_json::json!({"original":original,"objectId":object_id,"closed":closed,
                "attempts":attempts,"nextAttempt":if after_attempt.saturating_add(1)<count {Some(after_attempt+1)} else {None}}),
            );
        }
        let mut results = Vec::new();
        for plan in &original.objects {
            let closed: Option<Closed> = storage::read(
                &storage,
                &format!("qualification/closed/{}", plan.object_id),
            )
            .await?;
            let result: Option<queue::QueueReceipt> = storage::read(
                &storage,
                &format!("qualification/verified/{}", plan.object_id),
            )
            .await?;
            let count = queue::attempt_count(&storage, &plan.object_id).await?;
            results.push(
                serde_json::json!({"objectId":plan.object_id,"closed":closed.is_some(),
                "verified":result.is_some(),"attemptCount":count}),
            );
        }
        return Ok(serde_json::json!({"original":original,"objects":results,
            "inspectionOnly":original.source_digest != current_source || original.script_version != current_script}));
    }
    if let Action::Enqueue { object_ids } = &control.action {
        fixture::installed(env, &original)?;
        let mut closed = Vec::new();
        for object_id in object_ids {
            let record: Closed =
                storage::read(&storage, &format!("qualification/closed/{object_id}"))
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!("qualification positive close absent before enqueue")
                    })?;
            verification::admit_read(env, &record.job).await?;
            closed.push(record);
        }
        queue::enqueue_many(env, &original, &closed).await?;
        return Ok(
            serde_json::json!({"state":"immutable_originals_enqueued","objects":object_ids}),
        );
    }
    let object_id = match &control.action {
        Action::Begin { object_id }
        | Action::Grant { object_id, .. }
        | Action::Report { object_id, .. }
        | Action::Close { object_id, .. } => object_id,
        _ => anyhow::bail!("qualification action invalid"),
    };
    let index = original
        .objects
        .iter()
        .position(|plan| &plan.object_id == object_id)
        .ok_or_else(|| anyhow::anyhow!("qualification object not in original"))?;
    let resolved =
        fixture::admission(&original, &original.objects[index], &original.deployment_id)?;
    let admission = &resolved;
    let authority = fixture::Fixture {
        original: &original,
        uncertainty: fixture::uncertainty(env)?,
    };
    fixture::installed(env, &original)?;
    authority
        .protected_material(env, &admission.placements[0])
        .await?;
    super::provider_capacity::configure(u32::try_from(
        original.limits.maximum_provider_requests.get(),
    )?)?;
    let context = fixture::context(env, control, admission)?;
    match &control.action {
        Action::Begin { .. } => {
            effects::begin(env, &authority, admission, &context).await?;
            Ok(
                serde_json::json!({"state":"created","session":session(admission),
                "placement":admission.placements[0].public_ref(&context.deployment_id)?}),
            )
        }
        Action::Grant { parts, .. } => {
            let mut grants = Vec::new();
            for part in parts {
                grants.push(
                    effects::grant(
                        env,
                        &authority,
                        admission,
                        &DirectGrantPartRequest {
                            session: session(admission),
                            placement: admission.placements[0]
                                .public_ref(&context.deployment_id)?,
                            operation_id: journal::digest(&(object_id, part))?,
                            part: part.clone(),
                        },
                        &context,
                    )
                    .await?,
                );
            }
            Ok(serde_json::json!({"grants":grants}))
        }
        Action::Report { reports, .. } => {
            super::authority::current(&authority, &context, admission)?;
            for report in reports {
                ensure!(
                    report.session == session(admission),
                    "qualification report original differs"
                );
                storage::call(
                    env,
                    admission,
                    storage::Operation::Report {
                        report: report.clone(),
                    },
                )
                .await?;
            }
            Ok(serde_json::json!({"state":"reports_retained"}))
        }
        Action::Close { defer_enqueue, .. } => {
            let key = format!("qualification/closed/{object_id}");
            let closed = if let Some(closed) = storage::read::<Closed>(&storage, &key).await? {
                closed
            } else {
                super::authority::current(&authority, &context, admission)?;
                let parts =
                    verification::load_parts(env, admission, WireInteger::new(1), None).await?;
                let placement = admission.placements[0].public_ref(&context.deployment_id)?;
                let complete = DirectCompleteRequest {
                    session: session(admission),
                    operation_id: journal::digest(&(object_id, "close"))?,
                    expected_resource_version: WireInteger::new(1),
                    manifests: vec![DirectManifestCommitment {
                        placement: placement.clone(),
                        part_count: admission.intent.part_count()?,
                        manifest_digest: canonical_manifest_digest(
                            &admission.intent,
                            &placement,
                            &parts,
                        )?,
                    }],
                };
                storage::call(
                    env,
                    admission,
                    storage::Operation::Freeze {
                        complete: complete.clone(),
                    },
                )
                .await?;
                let created = effects::created(env, admission, WireInteger::new(1)).await?;
                let started = worker::Date::now().as_millis();
                let closed = verification::close_checked(
                    env,
                    admission,
                    &complete,
                    WireInteger::new(1),
                    &created,
                    context.foreground.expires_at,
                    || super::authority::current(&authority, &context, admission),
                )
                .await?;
                let ended = worker::Date::now().as_millis();
                let record = Closed {
                    object_id: object_id.clone(),
                    job: VerificationJob {
                        version: 1,
                        admission: admission.clone(),
                        complete,
                        placement_id: WireInteger::new(1),
                        closed,
                    },
                    closed_at_millis: WireInteger::new(ended),
                    settlement_millis: WireInteger::new(ended.saturating_sub(started)),
                };
                storage::write(&storage, &key, &record).await?;
                record
            };
            verification::admit_read(env, &closed.job).await?;
            if !defer_enqueue {
                queue::enqueue(env, &original, &closed).await?;
            }
            Ok(
                serde_json::json!({"state":if *defer_enqueue {"closed_read_admitted"} else {"closed_and_enqueued"},"closed":closed}),
            )
        }
        _ => anyhow::bail!("qualification action invalid"),
    }
}

fn session(admission: &DirectUploadAdmission) -> DirectSessionRef {
    DirectSessionRef {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
    }
}
