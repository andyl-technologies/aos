//! Signed authority admission and its durable physical reservation ledger.
//!
//! This control-only Durable Object uses an operator-configured actual guard
//! namespace identity. It neither dispatches S3 effects nor grants deletion
//! capability. Object bodies and provider secrets never enter its storage.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_hub_core::storage_authority::control::{
    sign_authority_message, verify_authority_message, StorageAuthorityRequest,
    MAX_AUTHORITY_CONTROL_BYTES,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};
use futures_util::lock::{Mutex, OwnedMutexGuard};
use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::{
    durable_object, DurableObject, Env, Headers, Method, Request, RequestInit, Response, State,
    Storage,
};

use crate::hybrid_authority_state as ledger;

const BINDING: &str = "HYBRID_AUTHORITY_STATE";
const NAMESPACE_VARIABLE: &str = "HUB_EXTERNAL_GUARD_NAMESPACE_ID";
const EXECUTOR_VARIABLE: &str = "HUB_EXTERNAL_STORAGE_EXECUTOR_ID";

/// Permanently reserves approved physical identities and their admission floors.
#[durable_object]
pub struct HybridAuthorityState {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
}

impl DurableObject for HybridAuthorityState {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        if request.method() != Method::Post || request.url()?.path() != "/control" {
            return Response::error("not found", 404);
        }
        let Some((namespace, executor)) = configured_domain(&self.env) else {
            return Response::error("physical authority domain is not configured", 503);
        };
        let namespace_binding = self.env.durable_object(BINDING)?;
        let expected = namespace_binding.id_from_name(LEDGER_NAME)?;
        if expected.to_string() != self.state.id().to_string() {
            return Response::error("authority ledger address differs", 400);
        }
        let Some(signature) = request.headers().get(STORAGE_WORK_SIGNATURE_HEADER)? else {
            return Response::error("authority signature is required", 401);
        };
        let Some(body) =
            crate::hybrid::read_bounded_body(&mut request, MAX_AUTHORITY_CONTROL_BYTES).await?
        else {
            return Response::error("authority body is too large", 413);
        };
        let key = StorageWorkKey::new(self.env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
            .map_err(storage_error)?;
        if verify_authority_message(&key, false, &signature, &body).is_err() {
            return Response::error("authority signature is invalid", 401);
        }
        let Ok(control) = serde_json::from_slice::<StorageAuthorityRequest>(&body) else {
            return Response::error("authority request is invalid", 400);
        };
        let deployment = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        let mut journal = DurableAuthorityJournal {
            storage: self.state.storage(),
        };
        let reply = match ledger::handle(
            &mut journal,
            &control,
            &deployment,
            &namespace,
            &executor,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await
        {
            Ok(reply) => reply,
            Err(error) => {
                worker::console_error!("hybrid_authority_control_rejected: {error:#}");
                return Response::error("authority control requires reconciliation", 409);
            }
        };
        let bytes = serde_json::to_vec(&reply)?;
        let signature = sign_authority_message(&key, true, &bytes).map_err(storage_error)?;
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        headers.set("cache-control", "private, no-store")?;
        headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
        Ok(Response::from_bytes(bytes)?.with_headers(headers))
    }
}

// The SDK bulk API serializes maps into JS Map by default, while DO storage
// enumerates plain-object properties. Preserve the explicitly encoded object.
#[derive(Serialize)]
#[serde(transparent)]
struct StorageBatch(#[serde(with = "serde_wasm_bindgen::preserve")] JsValue);

struct DurableAuthorityJournal {
    storage: Storage,
}

impl ledger::AuthorityJournal for DurableAuthorityJournal {
    async fn get(&mut self, key: &str) -> Result<Option<Value>> {
        let encoded = self
            .storage
            .get::<String>(key)
            .await
            .context("reading versioned authority storage string")?;
        encoded
            .map(|encoded| ledger::decode_journal_value(&encoded))
            .transpose()
    }

    async fn put_atomic(&mut self, values: BTreeMap<String, Value>) -> Result<()> {
        self.storage
            .transaction(move |transaction| async move {
                for batch in ledger::write_batches(values) {
                    // The 128-pair limit is per API call. All batches, the head and
                    // its receipt share this SQLite-backed explicit transaction.
                    let encoded = batch
                        .into_iter()
                        .map(|(key, value)| {
                            ledger::encode_journal_value(&value)
                                .map(|value| (key, value))
                                .map_err(storage_error)
                        })
                        .collect::<worker::Result<BTreeMap<_, _>>>()?;
                    let values =
                        encoded.serialize(&serde_wasm_bindgen::Serializer::json_compatible())?;
                    transaction.put_multiple(StorageBatch(values)).await?;
                }
                Ok(())
            })
            .await
            .context("persisting authority reservations, head and receipt")
    }
}

/// Forwards exact signed bytes to the configured control-plane DO.
///
/// # Errors
/// Returns an error when configured DO storage is unavailable. Missing physical
/// domain configuration rejects control without affecting ordinary R2 routes.
pub(crate) async fn control(mut request: Request, env: &Env) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error("method not allowed", 405);
    }
    let Some((namespace, _)) = configured_domain(env) else {
        return Response::error("physical authority domain is not configured", 503);
    };
    let Some(signature) = request.headers().get(STORAGE_WORK_SIGNATURE_HEADER)? else {
        return Response::error("authority signature is required", 401);
    };
    let Some(body) =
        crate::hybrid::read_bounded_body(&mut request, MAX_AUTHORITY_CONTROL_BYTES).await?
    else {
        return Response::error("authority body is too large", 413);
    };
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())
        .map_err(storage_error)?;
    if verify_authority_message(&key, false, &signature, &body).is_err() {
        return Response::error("authority signature is invalid", 401);
    }
    let Ok(control) = serde_json::from_slice::<StorageAuthorityRequest>(&body) else {
        return Response::error("authority request is invalid", 400);
    };
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    if control
        .validate(
            &deployment,
            &namespace,
            aos_hub_core::clock::now_unix_secs(),
        )
        .is_err()
    {
        return Response::error("authority request is outside configured domain", 400);
    }
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(
            worker::js_sys::Uint8Array::from(body.as_slice()).into(),
        ));
    let forwarded = Request::new_with_init("https://hybrid-authority/control", &init)?;
    let namespace_binding = env.durable_object(BINDING)?;
    let id = namespace_binding.id_from_name(LEDGER_NAME)?;
    id.get_stub()?.fetch_with_request(forwarded).await
}

fn configured_domain(env: &Env) -> Option<(String, String)> {
    let namespace = env.var(NAMESPACE_VARIABLE).ok()?.to_string();
    let executor = env.var(EXECUTOR_VARIABLE).ok()?.to_string();
    if namespace.is_empty() || executor.is_empty() {
        return None;
    }
    Some((namespace, executor))
}

// The fixed name makes changing a configured namespace label hit the existing
// durable domain pin instead of silently creating an empty admission ledger.
const LEDGER_NAME: &str = "physical-authority-ledger-v1";

async fn acquire_gate(gate: Arc<Mutex<()>>) -> OwnedMutexGuard<()> {
    loop {
        if let Some(permit) = gate.try_lock_owned() {
            return permit;
        }
        worker::Delay::from(Duration::from_millis(50)).await;
    }
}

fn storage_error(error: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError(error.to_string())
}
