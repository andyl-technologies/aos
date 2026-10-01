//! Authenticated fixture delivery through the ordinary verification queues.
//!
//! The producer retains a positive close before enqueue. Delivery confirms the
//! exact original against its durable owner, executes the production immutable
//! integrity path, and retains the proof and observations before acknowledgement.

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{Env, Headers, Method, Request, RequestInit, Response, State, Storage};

use super::{address, fixture, protocol, Closed};
use crate::direct_upload::{config, journal, provider_capacity, storage, verification};

const TURN_DOMAIN: &[u8] = b"aos.direct-upload.qualification-queue-turn.v1\0";
const TURN_HEADER: &str = "x-aos-direct-qualification-queue-turn";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Queued {
    kind: String,
    run_id: String,
    object_id: String,
    original_digest: String,
    source_digest: String,
    script_version: String,
    job: verification::VerificationJob,
    signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QueueAttempt {
    pub(crate) nonce: String,
    pub(crate) started_at_millis: WireInteger,
    pub(crate) provider_before: provider_capacity::Observation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QueueReceipt {
    pub(crate) attempt: QueueAttempt,
    pub(crate) finished_at_millis: WireInteger,
    pub(crate) queue_name: String,
    pub(crate) message_id: String,
    pub(crate) queued_at_millis: WireInteger,
    pub(crate) objects: verification::ObjectObservation,
    /// Indicates that this delivery returned a retained hash without source dispatch.
    pub(crate) verification_replayed: bool,
    pub(crate) provider_after: provider_capacity::Observation,
    pub(crate) proof: verification::VerifiedPlacement,
    pub(crate) proof_digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QueueAttemptRecord {
    pub(crate) attempt: QueueAttempt,
    pub(crate) receipt: Option<QueueReceipt>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Turn {
    Begin {
        queued: Queued,
        attempt: QueueAttempt,
    },
    Finish {
        queued: Queued,
        receipt: QueueReceipt,
    },
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    expires_at: WireInteger,
    turn: Turn,
}

fn key(env: &Env) -> Result<StorageWorkKey> {
    super::key(env)?;
    Ok(StorageWorkKey::new(
        env.secret("HUB_DIRECT_UPLOAD_JOURNAL_KEY")?.to_string(),
    )?)
}

fn signing_bytes(queued: &Queued) -> Result<Vec<u8>> {
    Ok([
        protocol::QUEUE_DOMAIN,
        encode_direct_control(&(
            &queued.kind,
            &queued.run_id,
            &queued.object_id,
            &queued.original_digest,
            &queued.source_digest,
            &queued.script_version,
            &queued.job,
        ))?
        .as_slice(),
    ]
    .concat())
}

pub(crate) async fn enqueue(
    env: &Env,
    original: &protocol::Original,
    closed: &Closed,
) -> Result<()> {
    enqueue_many(env, original, std::slice::from_ref(closed)).await
}

pub(crate) async fn enqueue_many(
    env: &Env,
    original: &protocol::Original,
    closed: &[Closed],
) -> Result<()> {
    let mut bulk = Vec::new();
    let mut metadata = Vec::new();
    for closed in closed {
        let mut queued = Queued {
            kind: "isolated_qualification_v1".into(),
            run_id: original.run_id.clone(),
            object_id: closed.object_id.clone(),
            original_digest: journal::digest(original)?,
            source_digest: original.source_digest.clone(),
            script_version: original.script_version.clone(),
            job: closed.job.clone(),
            signature: String::new(),
        };
        queued.signature = key(env)?.sign_body(&signing_bytes(&queued)?)?;
        ensure!(
            encode_direct_control(&queued)?.len() <= 64 * 1024,
            "qualification queue job exceeds bound"
        );
        let binding =
            if queued.job.admission.intent.dependency_phase == DirectDependencyPhase::Content {
                verification::BULK_QUEUE
            } else {
                verification::METADATA_QUEUE
            };
        if binding == verification::BULK_QUEUE {
            bulk.push(queued);
        } else {
            metadata.push(queued);
        }
    }
    for (binding, jobs) in [
        (verification::BULK_QUEUE, bulk),
        (verification::METADATA_QUEUE, metadata),
    ] {
        let mut chunk = Vec::new();
        let mut bytes = 0;
        for job in jobs {
            let size = encode_direct_control(&job)?.len();
            if bytes + size > 240 * 1024 && !chunk.is_empty() {
                env.queue(binding)?
                    .send_batch(std::mem::take(&mut chunk))
                    .await?;
                bytes = 0;
            }
            bytes += size;
            chunk.push(job);
        }
        if !chunk.is_empty() {
            env.queue(binding)?.send_batch(chunk).await?;
        }
    }
    Ok(())
}

async fn call(env: &Env, run: &str, turn: Turn) -> Result<protocol::Original> {
    let envelope = Envelope {
        expires_at: WireInteger::new(fixture::now()?.saturating_add(30)),
        turn,
    };
    let body = encode_direct_control(&envelope)?;
    let headers = Headers::new();
    headers.set(
        TURN_HEADER,
        &key(env)?.sign_body(&[TURN_DOMAIN, &body].concat())?,
    )?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from(js_sys::Uint8Array::from(
            body.as_slice(),
        ))));
    let response = env
        .durable_object(storage::BINDING)?
        .id_from_name(&address(env, run)?)?
        .get_stub()?
        .fetch_with_request(Request::new_with_init(
            "https://qualification/qualification-queue",
            &init,
        )?)
        .await?;
    ensure!(
        response.status_code() == 200,
        "qualification queue owner refused"
    );
    let bytes =
        crate::direct_digest::read_bounded_native(response, MAX_DIRECT_CONTROL_BYTES).await?;
    let original: protocol::Original = decode_direct_control(&bytes)?;
    Ok(original)
}

pub(crate) async fn physical(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> worker::Result<Response> {
    match physical_turn(request, env, state).await {
        Ok(original) => Response::from_json(&original),
        Err(_) => Response::error("qualification queue journal refused", 409),
    }
}

async fn physical_turn(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> Result<protocol::Original> {
    ensure!(
        request.method() == Method::Post,
        "qualification queue method invalid"
    );
    let signature = request
        .headers()
        .get(TURN_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("qualification queue auth absent"))?;
    let body = crate::hybrid::read_bounded_body(request, MAX_DIRECT_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("qualification queue turn exceeds bound"))?;
    key(env)?.verify_body(&signature, &[TURN_DOMAIN, &body].concat())?;
    let message: Envelope = decode_direct_control(&body)?;
    let now = fixture::now()?;
    ensure!(
        now < message.expires_at.get() && message.expires_at.get() <= now.saturating_add(30),
        "qualification queue turn expired"
    );
    let queued = match &message.turn {
        Turn::Begin { queued, .. } | Turn::Finish { queued, .. } => queued.clone(),
    };
    key(env)?.verify_body(&queued.signature, &signing_bytes(&queued)?)?;
    let state_storage = state.storage();
    let original: protocol::Original = storage::read(&state_storage, "qualification/original/v1")
        .await?
        .ok_or_else(|| anyhow::anyhow!("qualification queue original absent"))?;
    ensure!(
        original.run_id == queued.run_id
            && journal::digest(&original)? == queued.original_digest
            && original.source_digest == fixture::source()?
            && original.script_version == config::runtime_script_version(env)?
            && env
                .durable_object(storage::BINDING)?
                .id_from_name(&address(env, &queued.run_id)?)?
                .to_string()
                == state.id().to_string(),
        "qualification queue original or current runtime differs"
    );
    let closed: Closed = storage::read(
        &state_storage,
        &format!("qualification/closed/{}", queued.object_id),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("qualification positive close absent"))?;
    ensure!(
        encode_direct_control(&closed.job)? == encode_direct_control(&queued.job)?,
        "qualification queue original job changed"
    );
    match message.turn {
        Turn::Begin { attempt, .. } => {
            let nonce_key = format!(
                "qualification/attempt-by-nonce/{}/{}",
                queued.object_id, attempt.nonce
            );
            if let Some(retained) =
                storage::read::<QueueAttempt>(&state_storage, &nonce_key).await?
            {
                ensure!(
                    encode_direct_control(&retained)? == encode_direct_control(&attempt)?,
                    "qualification immutable delivery attempt changed"
                );
                return Ok(original);
            }
            ensure!(
                valid_direct_digest(&attempt.nonce),
                "qualification attempt nonce invalid"
            );
            let count: u32 = storage::read(
                &state_storage,
                &format!("qualification/attempt-count/{}", queued.object_id),
            )
            .await?
            .unwrap_or(0);
            ensure!(count < 128, "qualification immutable attempt bound reached");
            storage::write(
                &state_storage,
                &format!("qualification/attempt/{}/{count:03}", queued.object_id),
                &attempt,
            )
            .await?;
            storage::write(
                &state_storage,
                &format!("qualification/attempt-count/{}", queued.object_id),
                &(count + 1),
            )
            .await?;
            storage::write(&state_storage, &nonce_key, &attempt).await?;
        }
        Turn::Finish { receipt, .. } => {
            let proof = verification::retained(
                env,
                &closed.job.admission,
                &closed.job.complete,
                closed.job.placement_id,
            )
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("qualification independently retained source proof absent")
            })?;
            ensure!(
                proof == receipt.proof && journal::digest(&proof)? == receipt.proof_digest,
                "qualification exact positive source proof changed"
            );
            let attempt: QueueAttempt = storage::read(
                &state_storage,
                &format!(
                    "qualification/attempt-by-nonce/{}/{}",
                    closed.object_id, receipt.attempt.nonce
                ),
            )
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("qualification delivery attempt absent before finish")
            })?;
            ensure!(
                encode_direct_control(&attempt)? == encode_direct_control(&receipt.attempt)?,
                "qualification delivery attempt absent before finish"
            );
            let attempt_key = format!(
                "qualification/completed-attempt/{}/{}",
                closed.object_id, receipt.attempt.nonce
            );
            if let Some(retained) =
                storage::read::<QueueReceipt>(&state_storage, &attempt_key).await?
            {
                ensure!(
                    encode_direct_control(&retained)? == encode_direct_control(&receipt)?,
                    "qualification immutable delivery result changed"
                );
            } else {
                storage::write(&state_storage, &attempt_key, &receipt).await?;
            }
            if storage::read::<QueueReceipt>(
                &state_storage,
                &format!("qualification/verified/{}", closed.object_id),
            )
            .await?
            .is_none()
            {
                storage::write(
                    &state_storage,
                    &format!("qualification/verified/{}", closed.object_id),
                    &receipt,
                )
                .await?;
            }
        }
    }
    Ok(original)
}

pub(crate) async fn attempt_count(storage: &Storage, object: &str) -> Result<u32> {
    let count: u32 = storage::read(storage, &format!("qualification/attempt-count/{object}"))
        .await?
        .unwrap_or(0);
    ensure!(count <= 128, "qualification attempt journal bound invalid");
    Ok(count)
}

pub(crate) async fn attempt_page(
    storage: &Storage,
    object: &str,
    after: u32,
    maximum: u32,
) -> Result<Vec<QueueAttemptRecord>> {
    let count = attempt_count(storage, object).await?;
    ensure!(
        after <= count && maximum <= 8,
        "qualification attempt cursor invalid"
    );
    let mut values = Vec::new();
    for index in after..count.min(after.saturating_add(maximum)) {
        if let Some(value) = storage::read::<QueueAttempt>(
            storage,
            &format!("qualification/attempt/{object}/{index:03}"),
        )
        .await?
        {
            let receipt = storage::read(
                storage,
                &format!("qualification/completed-attempt/{object}/{}", value.nonce),
            )
            .await?;
            values.push(QueueAttemptRecord {
                attempt: value,
                receipt,
            });
        }
    }
    Ok(values)
}

/// Returns None for ordinary jobs; isolated jobs require exact authenticated originals.
pub(crate) async fn consume_message(
    body: JsValue,
    env: &Env,
    queue_name: &str,
    message_id: String,
    queued_at_millis: u64,
) -> Option<Result<()>> {
    let queued: Queued = match serde_wasm_bindgen::from_value(body) {
        Ok(value) => value,
        Err(_) => return None,
    };
    Some(consume(queued, env, queue_name, message_id, queued_at_millis).await)
}

async fn consume(
    queued: Queued,
    env: &Env,
    queue_name: &str,
    message_id: String,
    queued_at_millis: u64,
) -> Result<()> {
    ensure!(
        queued.kind == "isolated_qualification_v1",
        "qualification queue kind unknown"
    );
    key(env)?.verify_body(&queued.signature, &signing_bytes(&queued)?)?;
    let limits = config::qualification_limits(env)?
        .ok_or_else(|| anyhow::anyhow!("qualification queue disabled"))?;
    provider_capacity::configure(u32::try_from(limits.maximum_provider_requests.get())?)?;
    let binding = if queued.job.admission.intent.dependency_phase == DirectDependencyPhase::Content
    {
        verification::BULK_QUEUE
    } else {
        verification::METADATA_QUEUE
    };
    ensure!(
        env.var(&format!("{binding}_NAME"))?.to_string() == queue_name,
        "qualification queue class changed"
    );
    let attempt = QueueAttempt {
        nonce: journal::digest(&uuid::Uuid::new_v4().to_string())?,
        started_at_millis: WireInteger::new(worker::Date::now().as_millis()),
        provider_before: provider_capacity::observation(),
    };
    let provider_interval = provider_capacity::observe_interval()?;
    let original = call(
        env,
        &queued.run_id,
        Turn::Begin {
            queued: queued.clone(),
            attempt: attempt.clone(),
        },
    )
    .await?;
    fixture::installed(env, &original)?;
    let authority = fixture::Fixture {
        original: &original,
        uncertainty: fixture::uncertainty(env)?,
    };
    let (proof, objects, verification_replayed) = verification::run_fixture(
        env,
        &queued.job,
        &authority,
        u32::try_from(original.maximum_parallel_objects.get())?,
    )
    .await?;
    let receipt = QueueReceipt {
        attempt,
        finished_at_millis: WireInteger::new(worker::Date::now().as_millis()),
        queue_name: queue_name.into(),
        message_id,
        queued_at_millis: WireInteger::new(queued_at_millis),
        objects,
        verification_replayed,
        provider_after: provider_interval.finish(),
        proof_digest: journal::digest(&proof)?,
        proof,
    };
    call(
        env,
        &queued.run_id,
        Turn::Finish {
            queued: queued.clone(),
            receipt,
        },
    )
    .await?;
    Ok(())
}
