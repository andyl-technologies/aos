//! Short authenticated durable journal turns for the direct-upload broker.
//!
//! Provider requests run in the broker or queue isolate. The journal retains
//! canonical JSON strings and never copies upload bytes or provider credentials.
//! Unknown mutations retain their exact attempts across object eviction.

use std::sync::Arc;

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use futures_util::lock::Mutex;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::{
    durable_object, DurableObject, Env, Headers, ListOptions, Method, Request, RequestInit,
    Response, State, Storage,
};

use super::journal::{self, Effect, PartRecord};

pub(crate) const BINDING: &str = "HYBRID_DIRECT_UPLOAD";
const SIGNATURE: &str = "x-aos-direct-journal-signature";
const DOMAIN: &[u8] = b"aos.direct-upload.durable-journal.v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRequest {
    admission: DirectUploadAdmission,
    expires_at: WireInteger,
    operation: Operation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Admit,
    Begin {
        effect: Effect,
        nonce: String,
    },
    Finish {
        operation_id: String,
        nonce: String,
        terminal: serde_json::Value,
    },
    Register {
        part: PartRecord,
    },
    Report {
        report: DirectPartReport,
    },
    Freeze {
        complete: DirectCompleteRequest,
    },
    RetainAbort {
        abort: DirectAbortRequest,
    },
    PartPage {
        placement_id: WireInteger,
        after: u32,
        maximum: u32,
    },
    ReadEffect {
        operation_id: String,
    },
    ReadAbort,
    ReadOriginal,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Reply {
    Acknowledged,
    Begin {
        terminal: Option<serde_json::Value>,
    },
    Parts {
        parts: Vec<PartRecord>,
    },
    Effect {
        effect: Option<Effect>,
    },
    Abort {
        abort: Option<DirectAbortRequest>,
    },
    Original {
        admission: DirectUploadAdmission,
        complete: Option<DirectCompleteRequest>,
    },
}

/// Retains original logical admissions and exact provider effect attempts.
#[durable_object]
pub struct HybridDirectUpload {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
}

impl DurableObject for HybridDirectUpload {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        if request.url()?.path() == "/qualification" {
            let _gate = self.gate.lock().await;
            return super::qualification::physical(&mut request, &self.env, &self.state).await;
        }
        if request.url()?.path() == "/qualification-queue" {
            let _gate = self.gate.lock().await;
            return super::qualification::queue_physical(&mut request, &self.env, &self.state)
                .await;
        }
        if request.url()?.path() == "/conformance" {
            let _gate = self.gate.lock().await;
            return super::conformance::physical(&mut request, &self.env, &self.state).await;
        }
        match self.handle(&mut request).await {
            Ok(reply) => Response::from_json(&reply),
            Err(_) => Response::error("direct upload journal refused", 409),
        }
    }
}

impl HybridDirectUpload {
    async fn handle(&self, request: &mut Request) -> Result<Reply> {
        ensure!(
            request.method() == Method::Post && request.url()?.path() == "/journal",
            "direct journal route invalid"
        );
        let bytes = crate::hybrid::read_bounded_body(request, MAX_DIRECT_CONTROL_BYTES)
            .await?
            .ok_or_else(|| anyhow::anyhow!("direct journal body exceeds bound"))?;
        let signature = request
            .headers()
            .get(SIGNATURE)?
            .ok_or_else(|| anyhow::anyhow!("direct journal authentication missing"))?;
        journal_key(&self.env)?.verify_body(&signature, &[DOMAIN, &bytes].concat())?;
        let message: JournalRequest = decode_direct_control(&bytes)?;
        ensure!(
            encode_direct_control(&message)? == bytes,
            "direct journal request noncanonical"
        );
        let deployment = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
        message.admission.validate(&deployment)?;
        let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
        ensure!(
            now < message.expires_at.get() && message.expires_at.get() <= now.saturating_add(30),
            "direct journal transport expired"
        );
        let address = address(&deployment, &message.admission)?;
        ensure!(
            self.env
                .durable_object(BINDING)?
                .id_from_name(&address)?
                .to_string()
                == self.state.id().to_string(),
            "direct journal owner differs"
        );

        let _gate = self.gate.lock().await;
        let storage = self.state.storage();
        // A clock step backwards cannot renew any original transport or grant.
        let floor = read::<WireInteger>(&storage, "clock-floor/v1").await?;
        ensure!(
            floor.is_none_or(|floor| now >= floor.get()),
            "direct durable clock regressed"
        );
        write(&storage, "clock-floor/v1", &WireInteger::new(now)).await?;
        let original: Option<DirectUploadAdmission> = read(&storage, "admission/v1").await?;
        if let Some(original) = original {
            ensure!(
                original == message.admission,
                "direct original admission changed"
            );
        } else {
            ensure!(
                matches!(message.operation, Operation::Admit),
                "direct original admission absent"
            );
            write(&storage, "admission/v1", &message.admission).await?;
        }
        let admission = &message.admission;
        match message.operation {
            Operation::Admit => Ok(Reply::Acknowledged),
            Operation::Begin { effect, nonce } => {
                let key = effect_key(&effect.operation_id)?;
                let original = read(&storage, &key)
                    .await?
                    .unwrap_or_else(|| effect.clone());
                let (next, terminal) = original.begin(&effect, &nonce)?;
                if terminal.is_none() {
                    // The attempt is separately retained before permission to dispatch.
                    write(
                        &storage,
                        &format!("attempt/v1/{}/{}", effect.operation_id, nonce),
                        &next,
                    )
                    .await?;
                    write(&storage, &key, &next).await?;
                }
                Ok(Reply::Begin { terminal })
            }
            Operation::Finish {
                operation_id,
                nonce,
                terminal,
            } => {
                let key = effect_key(&operation_id)?;
                let effect: Effect = read(&storage, &key)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("direct dispatched effect absent"))?;
                write(&storage, &key, &effect.finish(&nonce, terminal)?).await?;
                Ok(Reply::Acknowledged)
            }
            Operation::ReadEffect { operation_id } => Ok(Reply::Effect {
                effect: read(&storage, &effect_key(&operation_id)?).await?,
            }),
            Operation::ReadAbort => Ok(Reply::Abort {
                abort: read(&storage, "abort/v1").await?,
            }),
            Operation::ReadOriginal => Ok(Reply::Original {
                admission: admission.clone(),
                complete: read(&storage, "complete/v1").await?,
            }),
            Operation::RetainAbort { abort } => {
                ensure!(
                    abort.session.session_id == admission.session_id
                        && abort.session.logical_fingerprint == admission.logical_fingerprint
                        && valid_direct_digest(&abort.operation_id)
                        && abort.expected_resource_version.get() > 0,
                    "direct original Abort differs"
                );
                if let Some(original) = read::<DirectAbortRequest>(&storage, "abort/v1").await? {
                    ensure!(original == abort, "direct retained Abort changed");
                } else {
                    write(&storage, "abort/v1", &abort).await?;
                }
                Ok(Reply::Acknowledged)
            }
            Operation::Register { part } => {
                ensure!(
                    read::<DirectCompleteRequest>(&storage, "complete/v1")
                        .await?
                        .is_none(),
                    "direct grants frozen"
                );
                let placement = placement(admission, part.placement.placement_id)?;
                part.part.validate(&admission.intent)?;
                ensure!(
                    part.session.session_id == admission.session_id
                        && part.session.logical_fingerprint == admission.logical_fingerprint
                        && part.placement == placement.public_ref(&deployment)?
                        && part.part.checksum.algorithm == placement.checksum_algorithm
                        && valid_direct_digest(&part.grant_id)
                        && part.grant_revision.get() > 0
                        && part.issued_at.get() < part.expires_at.get()
                        && part.expires_at <= admission.expires_at
                        && part.observed.is_none(),
                    "direct grant original invalid"
                );
                let key = part_key(part.placement.placement_id, part.part.part_number);
                if let Some(existing) = read::<PartRecord>(&storage, &key).await? {
                    let mut original = existing;
                    original.observed = None;
                    ensure!(original == part, "direct grant original changed");
                } else {
                    write(&storage, &key, &part).await?;
                }
                Ok(Reply::Acknowledged)
            }
            Operation::Report { report } => {
                ensure!(
                    read::<DirectCompleteRequest>(&storage, "complete/v1")
                        .await?
                        .is_none(),
                    "direct reports frozen"
                );
                let key = part_key(
                    report.placement.placement_id,
                    report.observed.part.part_number,
                );
                let mut part: PartRecord = read(&storage, &key)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("direct grant absent"))?;
                part.validate_report(&report)?;
                part.observed = Some(report.observed);
                write(&storage, &key, &part).await?;
                Ok(Reply::Acknowledged)
            }
            Operation::Freeze { complete } => {
                ensure!(
                    complete.session.session_id == admission.session_id
                        && complete.session.logical_fingerprint == admission.logical_fingerprint,
                    "direct Complete owner differs"
                );
                complete.fingerprint()?;
                ensure!(
                    complete.manifests.len() == admission.placements.len(),
                    "direct Complete required set incomplete"
                );
                for (manifest, placement) in complete.manifests.iter().zip(&admission.placements) {
                    ensure!(
                        manifest.placement == placement.public_ref(&deployment)?
                            && manifest.part_count == admission.intent.part_count()?,
                        "direct Complete placement differs"
                    );
                }
                if let Some(original) =
                    read::<DirectCompleteRequest>(&storage, "complete/v1").await?
                {
                    ensure!(original == complete, "direct original Complete changed");
                } else {
                    write(&storage, "complete/v1", &complete).await?;
                }
                Ok(Reply::Acknowledged)
            }
            Operation::PartPage {
                placement_id,
                after,
                maximum,
            } => {
                placement(admission, placement_id)?;
                ensure!(
                    maximum > 0 && maximum <= 64 && after <= MAX_DIRECT_PARTS,
                    "direct part page bound invalid"
                );
                let prefix = format!("part/v1/{}/", placement_id.get());
                let start = part_key(placement_id, after.saturating_add(1));
                let page = storage
                    .list_with_options(
                        ListOptions::new()
                            .prefix(&prefix)
                            .start(&start)
                            .limit(maximum as usize),
                    )
                    .await?;
                let entries = js_sys::try_iter(&page.entries())
                    .map_err(|_| anyhow::anyhow!("direct retained page iteration failed"))?
                    .ok_or_else(|| anyhow::anyhow!("direct retained page not iterable"))?;
                let mut parts = Vec::new();
                for entry in entries {
                    let entry =
                        js_sys::Array::from(&entry.map_err(|_| {
                            anyhow::anyhow!("direct retained entry iteration failed")
                        })?);
                    let key = entry
                        .get(0)
                        .as_string()
                        .ok_or_else(|| anyhow::anyhow!("direct part key malformed"))?;
                    let raw = entry
                        .get(1)
                        .as_string()
                        .ok_or_else(|| anyhow::anyhow!("direct retained part malformed"))?;
                    let part: PartRecord = serde_json::from_str(&raw)?;
                    ensure!(
                        part.placement.placement_id == placement_id
                            && part.part.part_number > after
                            && part.part.part_number <= admission.intent.part_count()?
                            && key == part_key(placement_id, part.part.part_number),
                        "direct retained sparse part differs"
                    );
                    parts.push(part);
                }
                Ok(Reply::Parts { parts })
            }
        }
    }
}

pub(crate) fn placement(
    admission: &DirectUploadAdmission,
    id: WireInteger,
) -> Result<&DirectPlacement> {
    admission
        .placements
        .iter()
        .find(|item| item.placement_id == id)
        .ok_or_else(|| anyhow::anyhow!("direct destination absent"))
}

fn address(deployment: &str, admission: &DirectUploadAdmission) -> Result<String> {
    Ok(format!(
        "direct-original:{}",
        journal::digest(&(
            deployment,
            &admission.actor_slot,
            &admission.intent.client_operation_id
        ))?
    ))
}

fn effect_key(operation_id: &str) -> Result<String> {
    ensure!(
        valid_direct_digest(operation_id),
        "direct effect key invalid"
    );
    Ok(format!("effect/v1/{operation_id}"))
}

fn part_key(placement_id: WireInteger, part: u32) -> String {
    format!("part/v1/{}/{part:05}", placement_id.get())
}

pub(crate) async fn read<T: serde::de::DeserializeOwned>(
    storage: &Storage,
    key: &str,
) -> Result<Option<T>> {
    let raw: Option<String> = storage.get(key).await?;
    raw.map(|raw| {
        serde_json::from_str(&raw).map_err(|_| anyhow::anyhow!("direct retained record malformed"))
    })
    .transpose()
}

pub(crate) async fn write<T: Serialize>(storage: &Storage, key: &str, value: &T) -> Result<()> {
    let encoded = encode_direct_control(value)?;
    ensure!(
        encoded.len() <= 128 * 1024,
        "direct retained record exceeds bound"
    );
    storage.put(key, String::from_utf8(encoded)?).await?;
    Ok(())
}

fn journal_key(env: &Env) -> Result<StorageWorkKey> {
    Ok(StorageWorkKey::new(
        env.secret("HUB_DIRECT_UPLOAD_JOURNAL_KEY")?.to_string(),
    )?)
}

pub(crate) async fn call(
    env: &Env,
    admission: &DirectUploadAdmission,
    operation: Operation,
) -> Result<Reply> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let message = JournalRequest {
        admission: admission.clone(),
        expires_at: WireInteger::new(
            u64::try_from(aos_hub_core::clock::now_unix_secs())?
                .checked_add(30)
                .ok_or_else(|| anyhow::anyhow!("direct transport clock overflow"))?,
        ),
        operation,
    };
    let body = encode_direct_control(&message)?;
    let headers = Headers::new();
    headers.set(
        SIGNATURE,
        &journal_key(env)?.sign_body(&[DOMAIN, &body].concat())?,
    )?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from(js_sys::Uint8Array::from(
            body.as_slice(),
        ))));
    let namespace = env.durable_object(BINDING)?;
    let mut response = namespace
        .id_from_name(&address(&deployment, admission)?)?
        .get_stub()?
        .fetch_with_request(Request::new_with_init(
            "https://direct-upload/journal",
            &init,
        )?)
        .await?;
    ensure!(
        response.status_code() == 200,
        "direct original journal refused"
    );
    response.json().await.map_err(Into::into)
}

pub(crate) async fn effect<F, Fut, T>(
    env: &Env,
    admission: &DirectUploadAdmission,
    operation_id: String,
    intent: &impl Serialize,
    immutable_read: bool,
    dispatch: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
    T: Serialize + serde::de::DeserializeOwned,
{
    let nonce = journal::digest(&uuid::Uuid::new_v4().to_string())?;
    let effect = Effect::new(operation_id.clone(), intent, immutable_read)?;
    let Reply::Begin { terminal } = call(
        env,
        admission,
        Operation::Begin {
            effect,
            nonce: nonce.clone(),
        },
    )
    .await?
    else {
        anyhow::bail!("direct effect admission differs");
    };
    if let Some(terminal) = terminal {
        return serde_json::from_value(terminal)
            .map_err(|_| anyhow::anyhow!("direct effect receipt malformed"));
    }
    let result = dispatch().await?;
    let terminal = serde_json::to_value(&result)?;
    call(
        env,
        admission,
        Operation::Finish {
            operation_id,
            nonce,
            terminal,
        },
    )
    .await?;
    Ok(result)
}
