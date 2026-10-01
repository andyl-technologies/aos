//! Actual addressed SQLite DO adapter for compact external object turns.
//!
//! Lossless versioned JSON strings are committed atomically. A dispatch permit
//! is returned only after pending and floor commit; retries of unknown begins
//! never regenerate it. Provider execution happens outside this object.
//!
//! ```text
//! external-object/head/v1 -> JSON string of the closed Head record
//! external-object/receipt/v1/<operation SHA-256> -> JSON string of Receipt
//! ```

use std::sync::Arc;

use anyhow::{ensure, Result};
use aos_hub_core::storage_work::StorageWorkKey;
use futures_util::lock::Mutex;
use rand::TryRngCore as _;
use worker::{
    durable_object, DurableObject, Env, Method, Request, Response, State, Storage, Transaction,
};

use super::{
    config::configured,
    protocol::{
        self, GuardOperation, GuardReply, Receipt, GUARD_HEADER, MAX_MESSAGE, MAX_RECEIPT,
        SCOPE_HEADER,
    },
    state::Head,
};

pub(super) const BINDING: &str = "EXTERNAL_OBJECT_GUARD";
pub(super) const HEAD: &str = "external-object/head/v1";
const GUARD_KEY: &str = "HUB_EXTERNAL_OBJECT_GUARD_KEY";

/// Retains one permanent physical full-key floor, pending turn and receipts.
///
/// Namespace/provider exclusivity qualification remains an external prerequisite.
#[durable_object]
pub struct ExternalObjectGuard {
    pub(super) state: State,
    pub(super) env: Env,
    pub(super) gate: Arc<Mutex<()>>,
}

impl DurableObject for ExternalObjectGuard {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        let path = request.url()?.path().to_owned();
        if path == "/frozen-cleanup-ready" {
            // Binding custody holds its own gate during this observation.
            // An active physical turn can need that binding; refuse a busy
            // physical guard immediately instead of inverting the lock order.
            let Some(_gate) = self.gate.try_lock() else {
                return Response::error("frozen physical key is busy", 409);
            };
            return super::frozen::readiness(&mut request, &self.env, &self.state).await;
        }
        if path == "/direct-guard-turn" {
            let _gate = self.gate.lock().await;
            return crate::direct_guard::physical_fetch(&mut request, &self.env, &self.state).await;
        }
        if matches!(
            path.as_str(),
            aos_hub_core::direct_upload::DIRECT_FINAL_GUARD_PATH
                | aos_hub_core::direct_upload::DIRECT_AUTHORITY_LOOKUP_PATH
        ) {
            let _gate = self.gate.lock().await;
            return crate::direct_guard::physical_lookup(&mut request, &self.env, &self.state)
                .await;
        }
        if request.url()?.path() == "/observation-turn" {
            return self.observation_fetch(&mut request).await;
        }
        if request.url()?.path() == "/stage-turn" {
            return self.stage_fetch(&mut request).await;
        }

        match self.handle(&mut request).await {
            Ok(reply) => {
                let headers = worker::Headers::new();
                headers.set("cache-control", "private, no-store")?;
                Ok(Response::from_json(&reply)?.with_headers(headers))
            }
            Err(_) => Response::error("external object turn refused", 409),
        }
    }
}

impl ExternalObjectGuard {
    async fn handle(&self, request: &mut Request) -> Result<GuardReply> {
        ensure!(
            request.method() == Method::Post && request.url()?.path() == "/turn",
            "invalid guard route"
        );
        let bytes = crate::hybrid::read_bounded_body(request, MAX_MESSAGE)
            .await?
            .ok_or_else(|| anyhow::anyhow!("oversized guard body"))?;
        let signature = request
            .headers()
            .get(GUARD_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("missing guard signature"))?;
        let message = protocol::authenticated(&key(&self.env)?, &signature, &bytes)?;
        let config = configured(&self.env)?
            .ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
        let name = message.scope.guard_name()?;
        ensure!(
            message.scope.guard_namespace_id == config.guard_namespace_id
                && request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str()),
            "guard namespace differs from configured binding"
        );
        let binding = self.env.durable_object(BINDING)?;
        ensure!(
            binding.id_from_name(&name)?.to_string() == self.state.id().to_string(),
            "request not addressed to this physical guard"
        );

        let _gate = self.gate.lock().await;
        let storage = self.state.storage();
        let prior = load_head(&storage).await?;
        match message.operation {
            GuardOperation::Lookup { intent } => {
                ensure!(intent.scope == message.scope, "lookup scope differs");
                intent.validate()?;
                let existing = load_receipt(&storage, &intent.operation_id).await?;
                match &prior {
                    Some(head) => {
                        head.validate(&config, &message.scope)?;
                        if let Some(receipt) = existing {
                            ensure!(receipt.turn.intent == intent, "lookup original changed");
                            return Ok(GuardReply::Terminal { receipt });
                        }
                        head.require_cleanup_ready()?;
                        Ok(GuardReply::Unseen)
                    }
                    None => {
                        ensure!(existing.is_none(), "receipt without retained head");
                        Ok(GuardReply::Unseen)
                    }
                }
            }
            GuardOperation::Begin { intent, lease } => {
                crate::direct_guard::deny_legacy(&storage).await?;
                ensure!(intent.scope == message.scope, "begin scope differs");
                intent.validate()?;
                let existing = load_receipt(&storage, &intent.operation_id).await?;
                let head = match &prior {
                    Some(value) => value.clone(),
                    None => {
                        ensure!(existing.is_none(), "receipt without retained head");
                        Head::initialize(&config, &intent, config.clock())?
                    }
                };
                head.validate(&config, &message.scope)?;
                let (next, reply) = if let Some(receipt) = &existing {
                    head.replay(&intent, receipt)?
                } else {
                    // Clock is observed after all storage awaits. Provider-side
                    // final validation follows the durable begin response.
                    let mut nonce = [0_u8; 32];
                    rand::rngs::OsRng
                        .try_fill_bytes(&mut nonce)
                        .map_err(|_| anyhow::anyhow!("dispatch randomness unavailable"))?;
                    head.begin(
                        &config,
                        intent.clone(),
                        lease.as_bytes(),
                        hex::encode(nonce),
                        config.clock(),
                    )?
                };
                commit(&storage, prior, next, intent.operation_id, existing, None).await?;
                Ok(reply)
            }
            GuardOperation::Terminal { receipt } => {
                receipt.validate()?;
                ensure!(
                    receipt.turn.intent.scope == message.scope,
                    "terminal scope differs"
                );
                let head = prior
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("terminal without retained head"))?;
                head.validate(&config, &message.scope)?;
                let existing = load_receipt(&storage, &receipt.turn.intent.operation_id).await?;
                let next = if let Some(old) = &existing {
                    ensure!(*old == receipt, "terminal receipt changed");
                    head.replay(&receipt.turn.intent, old)?.0
                } else {
                    head.terminal(&receipt)?
                };
                commit(
                    &storage,
                    prior,
                    next,
                    receipt.turn.intent.operation_id.clone(),
                    existing,
                    Some(receipt.clone()),
                )
                .await?;
                Ok(GuardReply::Terminal { receipt })
            }
        }
    }
}

pub(super) fn key(env: &Env) -> Result<StorageWorkKey> {
    let secret = env.secret(GUARD_KEY)?.to_string();
    ensure!(
        secret != env.secret("HUB_STORAGE_WORK_KEY")?.to_string(),
        "guard and public application keys must differ"
    );
    Ok(StorageWorkKey::new(secret)?)
}

fn receipt_key(operation: &str) -> Result<String> {
    Ok(format!(
        "external-object/receipt/v1/{}",
        protocol::digest(&operation)?
    ))
}

pub(super) async fn load_head(storage: &Storage) -> Result<Option<Head>> {
    let raw = storage.get::<String>(HEAD).await?;
    decode(raw, MAX_MESSAGE)
}

pub(super) async fn load_receipt(storage: &Storage, operation: &str) -> Result<Option<Receipt>> {
    let raw = storage.get::<String>(&receipt_key(operation)?).await?;
    let receipt: Option<Receipt> = decode(raw, MAX_RECEIPT)?;
    if let Some(value) = &receipt {
        value.validate()?;
    }
    Ok(receipt)
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(
    raw: Option<String>,
    cap: usize,
) -> Result<Option<T>> {
    raw.map(|raw| {
        ensure!(raw.len() <= cap, "retained compact record too large");
        Ok(serde_json::from_str(&raw)?)
    })
    .transpose()
}

pub(super) async fn transaction_string(
    transaction: &Transaction,
    key: &str,
) -> worker::Result<Option<String>> {
    let values = transaction.get_multiple(vec![key]).await?;
    let value = values.get(&wasm_bindgen::JsValue::from_str(key));
    if value.is_undefined() {
        Ok(None)
    } else {
        serde_wasm_bindgen::from_value(value)
            .map(Some)
            .map_err(error)
    }
}

async fn commit(
    storage: &Storage,
    expected: Option<Head>,
    next: Head,
    operation: String,
    expected_receipt: Option<Receipt>,
    new_receipt: Option<Receipt>,
) -> Result<()> {
    storage
        .transaction(move |transaction| {
            let expected = expected.clone();
            let next = next.clone();
            let operation = operation.clone();
            let expected_receipt = expected_receipt.clone();
            let new_receipt = new_receipt.clone();
            async move {
                let current: Option<Head> =
                    decode(transaction_string(&transaction, HEAD).await?, MAX_MESSAGE)
                        .map_err(error)?;
                let receipt_key = receipt_key(&operation).map_err(error)?;
                let current_receipt: Option<Receipt> = decode(
                    transaction_string(&transaction, &receipt_key).await?,
                    MAX_RECEIPT,
                )
                .map_err(error)?;
                if current != expected || current_receipt != expected_receipt {
                    return Err(error("compact object CAS refused"));
                }
                // Ordinary JS strings preserve every integer exactly. Single-key
                // puts avoid the SDK's JS Map/put_multiple enumeration mismatch.
                if let Some(receipt) = new_receipt {
                    transaction
                        .put(
                            &receipt_key,
                            serde_json::to_string(&receipt).map_err(error)?,
                        )
                        .await?;
                }
                transaction
                    .put(HEAD, serde_json::to_string(&next).map_err(error)?)
                    .await?;
                Ok(())
            }
        })
        .await?;
    Ok(())
}

pub(super) fn error(_: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError("external object journal unavailable".into())
}
