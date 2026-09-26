//! Object-scoped R2 mutation coordination for the hybrid Worker.
//!
//! One Durable Object owns the visible mutations of one physical R2 key. It
//! serializes writes, multipart completion, and identity-checked deletion
//! without moving object bytes through the Native Hub. A durable delete
//! receipt prevents a retried claim from deleting a later write at the key.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::surface_write::PartTag;
use futures_util::lock::{Mutex, OwnedMutexGuard};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsValue;
use worker::{
    durable_object, DurableObject, Env, Headers, Method, Request, RequestInit, Response, State,
};

const BINDING: &str = "HYBRID_OBJECT_GUARD";
const KEY_HEADER: &str = "x-aos-hybrid-object-key";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteClaim {
    pub claim_id: String,
    pub expected_etag: String,
    pub expected_size: u64,
    pub expected_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DeleteOutcome {
    Deleted { etag: String },
    NotFound,
    PreconditionFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    upload_id: String,
    parts: Vec<PartTag>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteReceipt {
    claim: DeleteClaim,
    outcome: DeleteOutcome,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GuardReply {
    Acknowledged,
    MultipartCompleted { etag: String },
    Delete { outcome: DeleteOutcome },
}

/// Coordinates visible writes and reviewed deletion for one R2 object key.
#[durable_object]
pub struct HybridObjectGuard {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
}

impl DurableObject for HybridObjectGuard {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        let Some(key) = request.headers().get(KEY_HEADER)? else {
            return Response::error("object key is required", 400);
        };
        if !valid_key(&key) || !self.matches_key(&key)? {
            return Response::error("object key does not match its guard", 400);
        }

        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        let bucket = self
            .env
            .bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
        let result = match request.url()?.path() {
            "/put" if request.method() == Method::Put => {
                if self.pending_delete().await?.is_some() {
                    return Response::error("object deletion is pending", 503);
                }
                let bytes = request.bytes().await?;
                if !bytes.is_empty() {
                    return Response::error(
                        "visible object bytes must be staged as multipart",
                        400,
                    );
                }
                crate::surface::hybrid_r2_put(bucket, &key, &bytes)
                    .await
                    .map_err(storage_error)?;
                GuardReply::Acknowledged
            }
            "/complete" if request.method() == Method::Post => {
                if self.pending_delete().await?.is_some() {
                    return Response::error("object deletion is pending", 503);
                }
                let completion: CompleteRequest = request.json().await?;
                let etag = crate::surface::hybrid_r2_complete(
                    bucket,
                    &key,
                    &completion.upload_id,
                    &completion.parts,
                )
                .await
                .map_err(storage_error)?;
                GuardReply::MultipartCompleted { etag }
            }
            "/delete" if request.method() == Method::Post => {
                let claim: DeleteClaim = request.json().await?;
                let outcome = self.delete_if_matches(bucket, &key, claim).await?;
                GuardReply::Delete { outcome }
            }
            "/delete-staging" if request.method() == Method::Delete => {
                if self.pending_delete().await?.is_some() {
                    return Response::error("object deletion is pending", 503);
                }
                crate::surface::hybrid_r2_delete(bucket, &key)
                    .await
                    .map_err(storage_error)?;
                GuardReply::Acknowledged
            }
            _ => return Response::error("not found", 404),
        };
        Response::from_json(&result)
    }
}

impl HybridObjectGuard {
    fn matches_key(&self, key: &str) -> worker::Result<bool> {
        let binding = self.env.durable_object(BINDING)?;
        let expected = binding.id_from_name(&guard_name(&self.env, key)?)?;
        Ok(expected.to_string() == self.state.id().to_string())
    }

    async fn pending_delete(&self) -> worker::Result<Option<DeleteClaim>> {
        self.state.storage().get("pending-delete").await
    }

    async fn delete_if_matches(
        &self,
        bucket: worker::Bucket,
        key: &str,
        claim: DeleteClaim,
    ) -> worker::Result<DeleteOutcome> {
        if !valid_claim(&claim) {
            return Err(worker::Error::RustError("invalid delete claim".into()));
        }

        // Keep receipts per claim so a frequently reused object key never
        // grows one storage value past Durable Object limits.
        let receipt_key = format!("delete-receipt:{}", claim.claim_id);
        if let Some(receipt) = self
            .state
            .storage()
            .get::<DeleteReceipt>(&receipt_key)
            .await?
        {
            if receipt.claim != claim {
                return Err(worker::Error::RustError(
                    "delete claim changed identity".into(),
                ));
            }
            if self.pending_delete().await?.as_ref() == Some(&claim) {
                self.state.storage().delete("pending-delete").await?;
            }
            return Ok(receipt.outcome);
        }
        let pending = self.pending_delete().await?;
        if pending.as_ref().is_some_and(|previous| previous != &claim) {
            return Err(worker::Error::RustError(
                "another object deletion is pending".into(),
            ));
        }

        let head = crate::surface::hybrid_r2_head(bucket.clone(), key)
            .await
            .map_err(storage_error)?;
        let outcome = match head {
            None => DeleteOutcome::NotFound,
            Some(head) if head.size != claim.expected_size || head.etag != claim.expected_etag => {
                DeleteOutcome::PreconditionFailed
            }
            Some(_) => {
                if pending.is_none() {
                    self.state.storage().put("pending-delete", &claim).await?;
                }
                crate::surface::hybrid_r2_delete(bucket, key)
                    .await
                    .map_err(storage_error)?;
                DeleteOutcome::Deleted {
                    etag: claim.expected_etag.clone(),
                }
            }
        };

        self.state
            .storage()
            .put(
                &receipt_key,
                DeleteReceipt {
                    claim,
                    outcome: outcome.clone(),
                },
            )
            .await?;
        if pending.is_some() || matches!(outcome, DeleteOutcome::Deleted { .. }) {
            self.state.storage().delete("pending-delete").await?;
        }
        Ok(outcome)
    }
}

async fn acquire_gate(gate: Arc<Mutex<()>>) -> OwnedMutexGuard<()> {
    loop {
        if let Some(permit) = gate.try_lock_owned() {
            return permit;
        }
        // Workerd needs a runtime event while a request waits on local state.
        worker::Delay::from(Duration::from_millis(25)).await;
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 2048
        && !key.starts_with('/')
        && !key.chars().any(char::is_control)
        && key.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn valid_claim(claim: &DeleteClaim) -> bool {
    !claim.claim_id.is_empty()
        && claim.claim_id.len() <= 128
        && claim
            .claim_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && aos_hub_core::surface_write::strong_if_match_etag(&claim.expected_etag).is_ok()
        && claim
            .expected_hash
            .as_ref()
            .is_none_or(|hash| !hash.is_empty() && hash.len() <= 128)
}

fn guard_name(env: &Env, key: &str) -> worker::Result<String> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    Ok(format!("{deployment}:{}", hex::encode(Sha256::digest(key))))
}

fn storage_error(error: anyhow::Error) -> worker::Error {
    worker::Error::RustError(format!("hybrid R2 mutation failed: {error:#}"))
}

async fn call(
    env: &Env,
    key: &str,
    path: &str,
    method: Method,
    body: JsValue,
) -> Result<GuardReply> {
    if !valid_key(key) {
        bail!("invalid hybrid R2 object key");
    }
    let namespace = env.durable_object(BINDING)?;
    let stub = namespace.id_from_name(&guard_name(env, key)?)?.get_stub()?;
    let headers = Headers::new();
    headers.set(KEY_HEADER, key)?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_body(Some(body));
    let request = Request::new_with_init(&format!("https://hybrid-object{path}"), &init)?;
    let mut response = stub.fetch_with_request(request).await?;
    if !(200..300).contains(&response.status_code()) {
        bail!(
            "hybrid object guard returned status {}",
            response.status_code()
        );
    }
    response.json::<GuardReply>().await.map_err(Into::into)
}

/// Stages bytes in R2 and commits the visible object through its guard.
pub(crate) async fn put(env: &Env, key: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        let reply = call(
            env,
            key,
            "/put",
            Method::Put,
            js_sys::Uint8Array::new_with_length(0).into(),
        )
        .await?;
        anyhow::ensure!(
            matches!(reply, GuardReply::Acknowledged),
            "unexpected put reply"
        );
        return Ok(());
    }
    anyhow::ensure!(
        bytes.len() <= aos_hub_core::hybrid_ingress::MAX_HYBRID_OCI_CHUNK_BYTES,
        "hybrid object body exceeds the upload limit"
    );
    let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    let upload_id = crate::surface::hybrid_r2_create_multipart(bucket.clone(), key).await?;
    let staged =
        crate::surface::hybrid_r2_upload_part(bucket.clone(), key, &upload_id, 1, bytes).await;
    let result = match staged {
        Ok(etag) => complete(
            env,
            key,
            &upload_id,
            &[PartTag {
                part_number: 1,
                etag,
            }],
        )
        .await
        .map(|_| ()),
        Err(error) => Err(error),
    };
    if result.is_err() {
        let _ = crate::surface::hybrid_r2_abort_multipart(bucket, key, &upload_id).await;
    }
    result
}

/// Completes multipart storage while serializing the new visible object.
pub(crate) async fn complete(
    env: &Env,
    key: &str,
    upload_id: &str,
    parts: &[PartTag],
) -> Result<String> {
    let body = serde_json::to_string(&CompleteRequest {
        upload_id: upload_id.to_owned(),
        parts: parts.to_vec(),
    })?;
    let reply = call(
        env,
        key,
        "/complete",
        Method::Post,
        JsValue::from_str(&body),
    )
    .await?;
    match reply {
        GuardReply::MultipartCompleted { etag } => Ok(etag),
        _ => bail!("unexpected multipart completion reply"),
    }
}

/// Deletes a terminal staging key without crossing the Native byte boundary.
pub(crate) async fn delete_staging(env: &Env, key: &str) -> Result<()> {
    let reply = call(env, key, "/delete-staging", Method::Delete, JsValue::NULL).await?;
    anyhow::ensure!(
        matches!(reply, GuardReply::Acknowledged),
        "unexpected delete reply"
    );
    Ok(())
}

/// Executes one reviewed physical deletion with an exact durable claim.
pub(crate) async fn delete_if_matches(
    env: &Env,
    key: &str,
    claim: &DeleteClaim,
) -> Result<DeleteOutcome> {
    let body = serde_json::to_string(claim).context("encoding hybrid delete claim")?;
    let reply = call(env, key, "/delete", Method::Post, JsValue::from_str(&body)).await?;
    match reply {
        GuardReply::Delete { outcome } => Ok(outcome),
        _ => bail!("unexpected conditional deletion reply"),
    }
}
