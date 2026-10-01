//! Object-scoped R2 mutation coordination for the hybrid Worker.
//!
//! One Durable Object owns the visible mutations of one physical R2 key. It
//! serializes writes, multipart completion, and identity-checked deletion
//! without moving object bytes through the Native Hub. A durable delete
//! receipt prevents a retried claim from deleting a later write at the key.
//! Every visible provider mutation records its unknown-outcome fence before
//! dispatch and its terminal receipt before unlocking. Fences never expire;
//! HEAD absence cannot settle an outstanding mutation. External S3 and the
//! frozen cleanup route are not connected to this coordinator yet.
//!
//! The guard namespace and storage authority ID must remain stable for the
//! lifetime of a bucket/prefix. Rotating either while reusing that storage loses
//! its durable fences and receipts. An upload version cannot settle an already
//! dispatched unconditional R2 DELETE; authority rotation requires draining and
//! settling outstanding effects or moving to a never-reused bucket/prefix.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::storage_work::StorageObjectIdentity;
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

use crate::hybrid_object_state::{
    matches_delete_observation, observe_when_ready, recover_delete, recover_mutation,
    DeleteReceipt, Mutation, MutationKind, MutationOutcome, MutationReceipt,
};
pub(crate) use crate::hybrid_object_state::{DeleteClaim, DeleteOutcome};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    operation_id: String,
    upload_id: String,
    parts: Vec<PartTag>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRequest {
    operation_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GuardReply {
    Acknowledged,
    MultipartCompleted {
        etag: String,
    },
    Delete {
        outcome: DeleteOutcome,
    },
    Head {
        object: Option<StorageObjectIdentity>,
    },
}

/// Coordinates visible writes and reviewed deletion for one R2 object key.
#[durable_object]
pub struct HybridObjectGuard {
    pub(crate) state: State,
    pub(crate) env: Env,
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

        let path = request.url()?.path().to_owned();
        if path == crate::oci_projection::PHYSICAL_PATH {
            return crate::oci_projection::physical_fetch(
                self,
                &key,
                &mut request,
                Arc::clone(&self.gate),
            )
            .await;
        }
        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        if key.starts_with(crate::mirror_import::inventory::CACHE_PREFIX) {
            if matches!(
                path.as_str(),
                crate::mirror_import::membership::PHYSICAL_PATH
                    | crate::mirror_import::membership::CANDIDATE_PHYSICAL_PATH
            ) {
                return crate::mirror_import::membership::physical_fetch(self, &key, &mut request)
                    .await;
            }
            if path == crate::mirror_import::inventory::PHYSICAL_PATH {
                return crate::mirror_import::inventory::physical_fetch(self, &key, &mut request)
                    .await;
            }
            return Response::error("semantic cache keys admit no provider operations", 403);
        }
        if matches!(
            path.as_str(),
            "/mirror-final-guard-batch" | "/mirror-candidate-final-guard-batch"
        ) {
            return crate::mirror_import::guard_proof::batch::physical_fetch(
                self,
                &key,
                &mut request,
                path == "/mirror-candidate-final-guard-batch",
            )
            .await;
        }
        if matches!(
            path.as_str(),
            "/mirror-final-guard" | "/mirror-candidate-final-guard"
        ) {
            return crate::mirror_import::guard_proof::physical_fetch(
                self,
                &key,
                &mut request,
                path == "/mirror-candidate-final-guard",
            )
            .await;
        }
        if matches!(
            path.as_str(),
            "/mirror-transfer"
                | "/mirror-source"
                | "/mirror-stage-ack"
                | "/mirror-candidate-transfer"
                | "/mirror-candidate-source"
                | "/mirror-candidate-stage-ack"
        ) {
            return crate::mirror_import::runtime::fetch(self, &key, &mut request).await;
        }
        #[cfg(feature = "do-e2e")]
        if path == "/_e2e/direct-guard" {
            return crate::direct_guard::conformance_physical_fetch(
                &mut request,
                &self.env,
                &self.state,
            )
            .await;
        }
        if path == "/direct-guard-turn" {
            return crate::direct_guard::physical_fetch(&mut request, &self.env, &self.state).await;
        }
        if matches!(
            path.as_str(),
            aos_hub_core::direct_upload::DIRECT_FINAL_GUARD_PATH
                | aos_hub_core::direct_upload::DIRECT_AUTHORITY_LOOKUP_PATH
        ) {
            return crate::direct_guard::physical_lookup(&mut request, &self.env, &self.state)
                .await;
        }
        crate::direct_guard::deny_legacy(&self.state.storage())
            .await
            .map_err(storage_error)?;
        crate::mirror_import::runtime::deny_other_owner(&self.state.storage())
            .await
            .map_err(storage_error)?;
        let bucket = self
            .env
            .bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
        let result = match request.url()?.path() {
            // This is an internal metadata RPC: POST preserves its JSON reply,
            // unlike HTTP HEAD, whose response body may be stripped.
            "/head" if request.method() == Method::Post => {
                let pending = self.pending_mutation().await?;
                let legacy = self.pending_delete().await?;
                let object = observe_when_ready(pending.as_ref(), legacy.as_ref(), || {
                    crate::surface::hybrid_r2_head(bucket, &key)
                })
                .await
                .map_err(storage_error)?;
                GuardReply::Head {
                    object: object.map(|head| StorageObjectIdentity {
                        key,
                        size: head.size,
                        etag: head.etag,
                        provider_version: Some(head.version),
                    }),
                }
            }
            "/put" if request.method() == Method::Put => {
                let operation: OperationRequest = request.json().await?;
                let mutation =
                    mutation(&key, &operation.operation_id, MutationKind::EmptyPut, &())?;
                if self.begin_mutation(&mutation).await?.is_none() {
                    crate::surface::hybrid_r2_put(bucket, &key, &[])
                        .await
                        .map_err(storage_error)?;
                    self.finish_mutation(mutation, MutationOutcome::Acknowledged)
                        .await?;
                }
                GuardReply::Acknowledged
            }
            "/complete" if request.method() == Method::Post => {
                let completion: CompleteRequest = request.json().await?;
                if completion.upload_id.is_empty()
                    || completion.upload_id.len() > 2048
                    || completion.parts.is_empty()
                    || completion.parts.len() > 10_000
                {
                    return Response::error("invalid multipart completion", 400);
                }
                let mutation = mutation(
                    &key,
                    &completion.operation_id,
                    MutationKind::MultipartCompletion,
                    &(&completion.upload_id, &completion.parts),
                )?;
                let outcome = match self.begin_mutation(&mutation).await? {
                    Some(outcome) => outcome,
                    None => {
                        let etag = crate::surface::hybrid_r2_complete(
                            bucket,
                            &key,
                            &completion.upload_id,
                            &completion.parts,
                        )
                        .await
                        .map_err(storage_error)?;
                        let outcome = MutationOutcome::MultipartCompleted { etag };
                        self.finish_mutation(mutation, outcome.clone()).await?;
                        outcome
                    }
                };
                let MutationOutcome::MultipartCompleted { etag } = outcome else {
                    return Response::error("invalid completion receipt", 500);
                };
                GuardReply::MultipartCompleted { etag }
            }
            "/delete" if request.method() == Method::Post => {
                let claim: DeleteClaim = request.json().await?;
                let outcome = self.delete_if_matches(bucket, &key, claim).await?;
                GuardReply::Delete { outcome }
            }
            "/delete-staging" if request.method() == Method::Delete => {
                let operation: OperationRequest = request.json().await?;
                let mutation = mutation(
                    &key,
                    &operation.operation_id,
                    MutationKind::StagingDelete,
                    &(),
                )?;
                if self.begin_mutation(&mutation).await?.is_none() {
                    crate::surface::hybrid_r2_delete(bucket, &key)
                        .await
                        .map_err(storage_error)?;
                    self.finish_mutation(mutation, MutationOutcome::Acknowledged)
                        .await?;
                }
                GuardReply::Acknowledged
            }
            _ => return Response::error("not found", 404),
        };
        Response::from_json(&result)
    }

    async fn alarm(&self) -> worker::Result<Response> {
        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        if self
            .state
            .storage()
            .get::<bool>(crate::mirror_import::membership::MARKER)
            .await?
            == Some(true)
        {
            return crate::mirror_import::membership::expire(self).await;
        }
        crate::mirror_import::inventory::expire(self).await
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

    async fn pending_mutation(&self) -> worker::Result<Option<Mutation>> {
        self.state.storage().get("pending-mutation").await
    }

    pub(crate) async fn begin_mutation(
        &self,
        mutation: &Mutation,
    ) -> worker::Result<Option<MutationOutcome>> {
        let receipt = self
            .state
            .storage()
            .get::<MutationReceipt>(&receipt_key(mutation))
            .await?;
        let pending = self.pending_mutation().await?;
        let legacy = self.pending_delete().await?;
        let replay = recover_mutation(
            mutation,
            receipt.as_ref(),
            pending.as_ref(),
            legacy.as_ref(),
        )
        .map_err(storage_error)?;
        if replay.is_some() {
            if pending.as_ref() == Some(mutation) {
                self.state.storage().delete("pending-mutation").await?;
            }
        } else {
            // Persist before dispatch: process eviction must not unlock a late effect.
            self.state
                .storage()
                .put("pending-mutation", mutation)
                .await?;
        }
        Ok(replay)
    }

    pub(crate) async fn finish_mutation(
        &self,
        mutation: Mutation,
        outcome: MutationOutcome,
    ) -> worker::Result<()> {
        let receipt = MutationReceipt { mutation, outcome };
        self.state
            .storage()
            .put(&receipt_key(&receipt.mutation), &receipt)
            .await?;
        // A crash between these writes leaves a replayable receipt and its fence.
        // Never let replay/late recovery clear a different operation's fence.
        if self.pending_mutation().await?.as_ref() == Some(&receipt.mutation) {
            self.state.storage().delete("pending-mutation").await?;
        }
        Ok(())
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
        let receipt = self
            .state
            .storage()
            .get::<DeleteReceipt>(&receipt_key)
            .await?;
        let pending = self.pending_delete().await?;

        // Recovery runs before any provider call. A pending claim without a
        // terminal receipt may still have an outstanding R2 request.
        if let Some(outcome) =
            recover_delete(&claim, receipt.as_ref(), pending.as_ref()).map_err(storage_error)?
        {
            if pending.as_ref() == Some(&claim) {
                self.state.storage().delete("pending-delete").await?;
            }
            return Ok(outcome);
        }

        // GC observation shares the mutation boundary. A provider HEAD (even
        // absence) cannot authorize GC while an older write/delete may finish.
        let mutation = self.pending_mutation().await?;
        let head = observe_when_ready(mutation.as_ref(), pending.as_ref(), || {
            crate::surface::hybrid_r2_head(bucket.clone(), key)
        })
        .await
        .map_err(storage_error)?;
        let outcome = match head {
            None => DeleteOutcome::NotFound,
            Some(head) if !matches_delete_observation(&claim, &head) => {
                DeleteOutcome::PreconditionFailed
            }
            Some(_) => {
                self.state.storage().put("pending-delete", &claim).await?;
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
        if matches!(outcome, DeleteOutcome::Deleted { .. }) {
            self.state.storage().delete("pending-delete").await?;
        }
        Ok(outcome)
    }
}

fn mutation<T: Serialize>(
    key: &str,
    operation_id: &str,
    kind: MutationKind,
    payload: &T,
) -> worker::Result<Mutation> {
    Mutation::new(key, operation_id, kind, payload).map_err(storage_error)
}

pub(crate) fn receipt_key(mutation: &Mutation) -> String {
    format!("mutation-receipt:{}", mutation.operation_id)
}

pub(crate) async fn acquire_gate(gate: Arc<Mutex<()>>) -> OwnedMutexGuard<()> {
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
            .expected_provider_version
            .as_deref()
            .is_none_or(aos_hub_core::storage_work::valid_provider_version)
        && claim
            .expected_hash
            .as_ref()
            .is_none_or(|hash| !hash.is_empty() && hash.len() <= 128)
}

pub(crate) fn guard_name(env: &Env, key: &str) -> worker::Result<String> {
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

/// Observes metadata while denying unknown mutation outcomes before provider I/O.
///
/// # Errors
/// Returns an error while any mutation is fenced, for an invalid exact key,
/// or for failed guard/provider access. Absence never retires a fence or receipt.
pub(crate) async fn head(env: &Env, key: &str) -> Result<Option<crate::r2_adapter::R2HeadObject>> {
    let reply = call(env, key, "/head", Method::Post, JsValue::NULL).await?;
    match reply {
        GuardReply::Head { object } => object
            .map(|object| {
                anyhow::ensure!(
                    object.key == key,
                    "guard HEAD returned a different object key"
                );
                Ok(crate::r2_adapter::R2HeadObject {
                    size: object.size,
                    etag: object.etag,
                    version: object
                        .provider_version
                        .context("guard HEAD returned no upload version")?,
                })
            })
            .transpose(),
        _ => bail!("unexpected object HEAD reply"),
    }
}

/// Stages bytes in R2 and commits the visible object through its guard.
///
/// Each invocation stages a new multipart upload (or allocates a new empty-PUT
/// operation ID). Repeating this helper is not a logical idempotency protocol:
/// an unknown earlier effect fences the key and rejects the new attempt.
pub(crate) async fn put(env: &Env, key: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return put_empty_with_operation(env, key, &uuid::Uuid::new_v4().to_string()).await;
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

/// Commits an empty object with a caller-retained replay identity.
///
/// # Errors
/// Returns an error for changed operation identity, an unknown prior mutation,
/// or a provider/storage failure. The caller must reuse this ID only for the
/// same operation; a later intentional write needs a new ID.
pub(crate) async fn put_empty_with_operation(
    env: &Env,
    key: &str,
    operation_id: &str,
) -> Result<()> {
    let body = serde_json::to_string(&OperationRequest {
        operation_id: operation_id.into(),
    })?;
    let reply = call(env, key, "/put", Method::Put, JsValue::from_str(&body)).await?;
    anyhow::ensure!(
        matches!(reply, GuardReply::Acknowledged),
        "unexpected put reply"
    );
    Ok(())
}

/// Completes multipart storage while serializing the new visible object.
pub(crate) async fn complete(
    env: &Env,
    key: &str,
    upload_id: &str,
    parts: &[PartTag],
) -> Result<String> {
    // Excluding parts from the ID lets the guard reject changed parts rather
    // than treating them as a new operation for the same provider upload.
    let operation_id = format!("complete:{}", hex::encode(Sha256::digest(upload_id)));
    complete_with_operation(env, key, &operation_id, upload_id, parts).await
}

/// Completes one exact upload/parts payload with a caller-retained identity.
///
/// # Errors
/// Returns an error for a changed payload, unknown prior mutation, or failed
/// provider/storage operation. A matching receipt replays without provider I/O.
pub(crate) async fn complete_with_operation(
    env: &Env,
    key: &str,
    operation_id: &str,
    upload_id: &str,
    parts: &[PartTag],
) -> Result<String> {
    let body = serde_json::to_string(&CompleteRequest {
        operation_id: operation_id.into(),
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
///
/// Each invocation allocates a fresh attempt ID. An unknown previous attempt
/// remains fenced; callers needing receipt replay must retain an explicit ID.
pub(crate) async fn delete_staging(env: &Env, key: &str) -> Result<()> {
    delete_staging_with_operation(env, key, &uuid::Uuid::new_v4().to_string()).await
}

/// Deletes a staging key with a caller-retained replay identity.
///
/// # Errors
/// Returns an error for a changed identity, unknown prior mutation, or failed
/// provider/storage operation. Receipts do not expire or authorize settlement
/// of any other operation.
pub(crate) async fn delete_staging_with_operation(
    env: &Env,
    key: &str,
    operation_id: &str,
) -> Result<()> {
    let body = serde_json::to_string(&OperationRequest {
        operation_id: operation_id.into(),
    })?;
    let reply = call(
        env,
        key,
        "/delete-staging",
        Method::Delete,
        JsValue::from_str(&body),
    )
    .await?;
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
