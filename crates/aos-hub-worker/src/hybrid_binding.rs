//! Per-binding snapshot and credential state for the hybrid storage executor.
//!
//! Each external binding has one Durable Object that holds only its current
//! provider coordinates and purpose-scoped secrets. A monotonic watermark
//! prevents an old signed publication from restoring a revoked credential.
//! Storage work reads this small state; object bodies never pass through it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::storage_work::{
    StorageBindingAcknowledgement, StorageBindingControl, StorageBindingPublication,
    StorageCredentialReference, StorageWorkPlan, MAX_BINDING_CONTROL_BYTES,
};
use futures_util::lock::{Mutex, OwnedMutexGuard};
use serde::{Deserialize, Serialize};
use worker::{
    durable_object, DurableObject, Env, Headers, Method, Request, RequestInit, Response, State,
};

const BINDING: &str = "HYBRID_BINDING_STATE";
const BINDING_ID_HEADER: &str = "x-aos-storage-binding-id";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingLookup {
    binding_id: i64,
    revision: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryBindingLookup {
    binding_id: i64,
    binding_resource_version: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFence {
    generation: i64,
    secret_version_ref: String,
    fingerprint: String,
}

impl CredentialFence {
    fn matches_or_precedes(&self, reference: &StorageCredentialReference) -> bool {
        reference.generation > self.generation
            || (reference.generation == self.generation
                && reference.secret_version_ref == self.secret_version_ref
                && reference.fingerprint == self.fingerprint)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingWatermark {
    binding_stable_id: String,
    binding_resource_version: i64,
    binding_spec_revision: String,
    credential_fences: BTreeMap<String, CredentialFence>,
    issued_at: i64,
    revision: String,
    active: bool,
}

/// Owns one external binding's current revision and its replay floor.
#[durable_object]
pub struct HybridBindingState {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
}

impl DurableObject for HybridBindingState {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        let Some(binding_id) = request.headers().get(BINDING_ID_HEADER)? else {
            return Response::error("binding identity is required", 400);
        };
        let Ok(binding_id) = binding_id.parse::<i64>() else {
            return Response::error("binding identity is invalid", 400);
        };
        if binding_id <= 0 || !self.matches_binding(binding_id)? {
            return Response::error("binding identity does not match its state", 400);
        }

        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        if crate::binding_custody::is_path(request.url()?.path()) {
            // Retention alarms survive a lost reply or a failed provider probe.
            crate::binding_custody::schedule_expiry(&self.state.storage())
                .await
                .map_err(|_| {
                    worker::Error::RustError("binding custody expiry unavailable".into())
                })?;
            let active = self
                .state
                .storage()
                .get::<StorageBindingPublication>("active")
                .await?;
            let result = crate::binding_custody::handle(
                &mut request,
                &self.env,
                &self.state.storage(),
                active,
                binding_id,
            )
            .await;
            let reply = match result {
                Ok(crate::binding_custody::Outcome::Reply(reply)) => reply,
                Ok(crate::binding_custody::Outcome::Adoption {
                    request,
                    publication,
                }) => {
                    let acknowledged = publication.snapshot.clone();
                    if self
                        .publish(publication, aos_hub_core::clock::now_unix_secs())
                        .await
                        .is_err()
                    {
                        return Response::error("binding custody adoption refused", 409);
                    }
                    match crate::binding_custody::reply_adoption(&self.env, request, acknowledged) {
                        Ok(reply) => reply,
                        Err(_) => return Response::error("binding custody adoption refused", 409),
                    }
                }
                Err(_) => return Response::error("binding custody control refused", 409),
            };
            crate::binding_custody::schedule_expiry(&self.state.storage())
                .await
                .map_err(|_| {
                    worker::Error::RustError("binding custody expiry unavailable".into())
                })?;
            return crate::binding_custody::response(reply);
        }
        match (request.method(), request.url()?.path()) {
            (Method::Post, "/control") => {
                let bytes = request.bytes().await?;
                if bytes.len() > MAX_BINDING_CONTROL_BYTES {
                    return Response::error("binding control body is too large", 413);
                }
                let control: StorageBindingControl = serde_json::from_slice(&bytes)?;
                let deployment_id = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
                let now = aos_hub_core::clock::now_unix_secs();
                if control.binding_id() != binding_id
                    || control.validate(&deployment_id, now).is_err()
                {
                    return Response::error("binding control is invalid", 400);
                }
                let acknowledgement = match control {
                    StorageBindingControl::Publish { publication } => {
                        self.publish(publication, now).await?
                    }
                    StorageBindingControl::Revoke {
                        revision,
                        issued_at,
                        ..
                    } => self.revoke(revision, issued_at).await?,
                };
                Response::from_json(&acknowledgement)
            }
            (Method::Post, "/resolve") => {
                let lookup: BindingLookup = request.json().await?;
                if lookup.binding_id != binding_id || !valid_revision(&lookup.revision) {
                    return Response::error("binding lookup is invalid", 400);
                }
                let Some(publication) = self.resolve(&lookup.revision).await? else {
                    return Response::error("binding snapshot is unavailable", 404);
                };
                let headers = Headers::new();
                headers.set("cache-control", "private, no-store")?;
                Ok(Response::from_json(&publication)?.with_headers(headers))
            }
            (Method::Post, "/resolve-delivery") => {
                let lookup: DeliveryBindingLookup = request.json().await?;
                if lookup.binding_id != binding_id || lookup.binding_resource_version <= 0 {
                    return Response::error("delivery binding lookup is invalid", 400);
                }
                let Some(publication) = self
                    .resolve_delivery(lookup.binding_resource_version)
                    .await?
                else {
                    return Response::error("delivery binding is unavailable", 404);
                };
                let headers = Headers::new();
                headers.set("cache-control", "private, no-store")?;
                Ok(Response::from_json(&publication)?.with_headers(headers))
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn alarm(&self) -> worker::Result<Response> {
        let _permit = acquire_gate(Arc::clone(&self.gate)).await;
        let custody_expiry = crate::binding_custody::expire_material(&self.state.storage())
            .await
            .map_err(|_| worker::Error::RustError("binding custody expiry unavailable".into()))?;
        let Some(publication) = self
            .state
            .storage()
            .get::<StorageBindingPublication>("active")
            .await?
        else {
            return Response::ok("binding snapshot absent");
        };
        let now = aos_hub_core::clock::now_unix_secs();
        if publication.snapshot.expires_at > now {
            self.state
                .storage()
                .set_alarm(Duration::from_secs(
                    ((publication.snapshot.expires_at - now) as u64)
                        .min(custody_expiry.unwrap_or(u64::MAX)),
                ))
                .await?;
            return Response::ok("binding snapshot still active");
        }
        if let Some(mut watermark) = self
            .state
            .storage()
            .get::<BindingWatermark>("watermark")
            .await?
        {
            watermark.issued_at = watermark.issued_at.max(publication.snapshot.expires_at);
            watermark.active = false;
            self.state.storage().put("watermark", &watermark).await?;
        }
        self.state.storage().delete("active").await?;
        Response::ok("binding snapshot expired")
    }
}

impl HybridBindingState {
    fn matches_binding(&self, binding_id: i64) -> worker::Result<bool> {
        let namespace = self.env.durable_object(BINDING)?;
        let expected = namespace.id_from_name(&binding_name(&self.env, binding_id)?)?;
        Ok(expected.to_string() == self.state.id().to_string())
    }

    async fn publish(
        &self,
        publication: StorageBindingPublication,
        now: i64,
    ) -> worker::Result<StorageBindingAcknowledgement> {
        let snapshot = &publication.snapshot;
        let revision = snapshot.revision().map_err(storage_error)?;
        let spec_revision = snapshot.binding_spec_revision().map_err(storage_error)?;
        let existing = self
            .state
            .storage()
            .get::<BindingWatermark>("watermark")
            .await?;
        if let Some(watermark) = &existing {
            if watermark.active
                && watermark.issued_at == snapshot.issued_at
                && watermark.revision == revision
                && self
                    .state
                    .storage()
                    .get::<StorageBindingPublication>("active")
                    .await?
                    .is_some_and(|active| {
                        active.snapshot.revision().ok().as_deref() == Some(revision.as_str())
                    })
            {
                return Ok(StorageBindingAcknowledgement { revision });
            }
            if snapshot.issued_at <= watermark.issued_at
                || (!watermark.binding_stable_id.is_empty()
                    && snapshot.binding_stable_id != watermark.binding_stable_id)
                || snapshot.binding_resource_version < watermark.binding_resource_version
                || (snapshot.binding_resource_version == watermark.binding_resource_version
                    && !watermark.binding_spec_revision.is_empty()
                    && spec_revision != watermark.binding_spec_revision)
                || snapshot.credentials.iter().any(|reference| {
                    watermark
                        .credential_fences
                        .get(&reference.purpose)
                        .is_some_and(|fence| !fence.matches_or_precedes(reference))
                })
            {
                return Err(worker::Error::RustError(
                    "binding publication is stale or changes frozen identity".into(),
                ));
            }
        }

        let mut watermark = existing.unwrap_or(BindingWatermark {
            binding_stable_id: String::new(),
            binding_resource_version: 0,
            binding_spec_revision: String::new(),
            credential_fences: BTreeMap::new(),
            issued_at: 0,
            revision: String::new(),
            active: false,
        });
        for reference in &snapshot.credentials {
            watermark.credential_fences.insert(
                reference.purpose.clone(),
                CredentialFence {
                    generation: reference.generation,
                    secret_version_ref: reference.secret_version_ref.clone(),
                    fingerprint: reference.fingerprint.clone(),
                },
            );
        }
        watermark.binding_stable_id = snapshot.binding_stable_id.clone();
        watermark.binding_resource_version = snapshot.binding_resource_version;
        watermark.binding_spec_revision = spec_revision;
        watermark.issued_at = snapshot.issued_at;
        watermark.revision = revision.clone();
        watermark.active = true;

        self.state
            .storage()
            .set_alarm(Duration::from_secs(
                (snapshot.expires_at - now).max(1) as u64
            ))
            .await?;
        self.state.storage().put("watermark", &watermark).await?;
        self.state
            .storage()
            .put("last-snapshot/v1", &publication.snapshot)
            .await?;
        self.state.storage().put("active", &publication).await?;
        Ok(StorageBindingAcknowledgement { revision })
    }

    async fn revoke(
        &self,
        revision: String,
        issued_at: i64,
    ) -> worker::Result<StorageBindingAcknowledgement> {
        let existing = self
            .state
            .storage()
            .get::<BindingWatermark>("watermark")
            .await?;
        if let Some(watermark) = &existing {
            if !watermark.active
                && watermark.revision == revision
                && watermark.issued_at == issued_at
            {
                return Ok(StorageBindingAcknowledgement { revision });
            }
            if issued_at <= watermark.issued_at
                || (watermark.active && watermark.revision != revision)
            {
                return Err(worker::Error::RustError(
                    "binding revocation is stale or names another revision".into(),
                ));
            }
        }
        let mut watermark = existing.unwrap_or(BindingWatermark {
            binding_stable_id: String::new(),
            binding_resource_version: 0,
            binding_spec_revision: String::new(),
            credential_fences: BTreeMap::new(),
            issued_at: 0,
            revision: String::new(),
            active: false,
        });
        watermark.issued_at = issued_at;
        watermark.revision = revision.clone();
        watermark.active = false;

        if let Some(snapshot) = self
            .state
            .storage()
            .get::<aos_hub_core::storage_work::StorageBindingSnapshot>("last-snapshot/v1")
            .await?
        {
            crate::binding_custody::revoke_material(&self.state.storage(), &snapshot)
                .await
                .map_err(|_| {
                    worker::Error::RustError("binding custody revocation unavailable".into())
                })?;
        }
        self.state.storage().put("watermark", &watermark).await?;
        self.state.storage().delete("active").await?;
        Ok(StorageBindingAcknowledgement { revision })
    }

    async fn resolve(&self, revision: &str) -> worker::Result<Option<StorageBindingPublication>> {
        let Some(watermark) = self
            .state
            .storage()
            .get::<BindingWatermark>("watermark")
            .await?
        else {
            return Ok(None);
        };
        if !watermark.active || watermark.revision != revision {
            return Ok(None);
        }
        let Some(publication) = self
            .state
            .storage()
            .get::<StorageBindingPublication>("active")
            .await?
        else {
            return Ok(None);
        };
        let now = aos_hub_core::clock::now_unix_secs();
        let deployment_id = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
        if publication.snapshot.issued_at != watermark.issued_at
            || publication.snapshot.binding_stable_id != watermark.binding_stable_id
            || publication.snapshot.binding_resource_version != watermark.binding_resource_version
            || publication
                .snapshot
                .binding_spec_revision()
                .map_err(storage_error)?
                != watermark.binding_spec_revision
            || publication.snapshot.revision().map_err(storage_error)? != revision
            || publication.validate(&deployment_id, now).is_err()
        {
            return Ok(None);
        }
        Ok(Some(publication))
    }

    async fn resolve_delivery(
        &self,
        binding_resource_version: i64,
    ) -> worker::Result<Option<StorageBindingPublication>> {
        let Some(watermark) = self
            .state
            .storage()
            .get::<BindingWatermark>("watermark")
            .await?
        else {
            return Ok(None);
        };
        if !watermark.active || watermark.binding_resource_version != binding_resource_version {
            return Ok(None);
        }
        self.resolve(&watermark.revision).await
    }
}

async fn acquire_gate(gate: Arc<Mutex<()>>) -> OwnedMutexGuard<()> {
    loop {
        if let Some(permit) = gate.try_lock_owned() {
            return permit;
        }
        // A runtime timer keeps requests alive while the object is busy.
        worker::Delay::from(Duration::from_millis(25)).await;
    }
}

fn binding_name(env: &Env, binding_id: i64) -> worker::Result<String> {
    let deployment_id = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    Ok(format!("{deployment_id}:binding:{binding_id}"))
}

fn valid_revision(revision: &str) -> bool {
    revision.len() == 64
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn storage_error(error: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError(format!("binding state failed: {error}"))
}

fn stub(env: &Env, binding_id: i64) -> Result<worker::Stub> {
    let namespace = env.durable_object(BINDING)?;
    Ok(namespace
        .id_from_name(&binding_name(env, binding_id)?)?
        .get_stub()?)
}

/// Applies one authenticated publication or revocation to its binding state.
///
/// # Errors
///
/// Returns an error when the object rejects a stale update or cannot persist it.
pub(crate) async fn apply_control(
    env: &Env,
    binding_id: i64,
    body: &[u8],
) -> Result<StorageBindingAcknowledgement> {
    let headers = Headers::new();
    headers.set(BINDING_ID_HEADER, &binding_id.to_string())?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body).into()));
    let request = Request::new_with_init("https://hybrid-binding/control", &init)?;
    let mut response = stub(env, binding_id)?.fetch_with_request(request).await?;
    if response.status_code() != 200 {
        bail!(
            "hybrid binding state returned status {}",
            response.status_code()
        );
    }
    response
        .json::<StorageBindingAcknowledgement>()
        .await
        .context("decoding hybrid binding acknowledgement")
}

/// Resolves one exact, currently admitted snapshot for Worker-side I/O.
///
/// # Errors
///
/// Returns an error when binding state is unavailable or its response is invalid.
async fn resolve(
    env: &Env,
    binding_id: i64,
    revision: &str,
) -> Result<Option<StorageBindingPublication>> {
    if binding_id <= 0 || !valid_revision(revision) {
        bail!("invalid hybrid binding lookup");
    }
    let body = serde_json::to_vec(&BindingLookup {
        binding_id,
        revision: revision.to_owned(),
    })?;
    let headers = Headers::new();
    headers.set(BINDING_ID_HEADER, &binding_id.to_string())?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = Request::new_with_init("https://hybrid-binding/resolve", &init)?;
    let mut response = stub(env, binding_id)?.fetch_with_request(request).await?;
    if response.status_code() == 404 {
        return Ok(None);
    }
    if response.status_code() != 200 {
        bail!(
            "hybrid binding state returned status {}",
            response.status_code()
        );
    }
    response
        .json::<StorageBindingPublication>()
        .await
        .map(Some)
        .context("decoding hybrid binding snapshot")
}

/// Resolves the current publication only when it still matches Native's signed binding version.
///
/// # Errors
///
/// Returns an error when the Worker binding state is unavailable or malformed.
pub(crate) async fn resolve_for_delivery(
    env: &Env,
    binding_id: i64,
    binding_resource_version: i64,
) -> Result<StorageBindingPublication> {
    if binding_id <= 0 || binding_resource_version <= 0 {
        bail!("invalid delivery binding identity");
    }
    let body = serde_json::to_vec(&DeliveryBindingLookup {
        binding_id,
        binding_resource_version,
    })?;
    let headers = Headers::new();
    headers.set(BINDING_ID_HEADER, &binding_id.to_string())?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = Request::new_with_init("https://hybrid-binding/resolve-delivery", &init)?;
    let mut response = stub(env, binding_id)?.fetch_with_request(request).await?;
    if response.status_code() != 200 {
        bail!(
            "delivery binding state returned status {}",
            response.status_code()
        );
    }
    let publication = response
        .json::<StorageBindingPublication>()
        .await
        .context("decoding delivery binding snapshot")?;
    let now = aos_hub_core::clock::now_unix_secs();
    let deployment_id = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    publication.validate(&deployment_id, now)?;
    anyhow::ensure!(
        publication.snapshot.binding_id == binding_id
            && publication.snapshot.binding_resource_version == binding_resource_version,
        "delivery binding snapshot changed after Native admission"
    );
    Ok(publication)
}

/// Resolves only the exact snapshot and credential set named by a signed plan.
///
/// # Errors
///
/// Returns an error when the plan is stale, the binding is absent, or its
/// current snapshot does not admit every required credential purpose.
pub(crate) async fn resolve_for_plan(
    env: &Env,
    plan: &StorageWorkPlan,
) -> Result<StorageBindingPublication> {
    let revision = plan
        .binding_snapshot_revision
        .as_deref()
        .context("external storage plan has no binding snapshot revision")?;
    let publication = resolve(env, plan.binding_id, revision)
        .await?
        .context("external binding snapshot is unavailable")?;
    let deployment_id = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    publication
        .snapshot
        .authorizes(plan, &deployment_id, aos_hub_core::clock::now_unix_secs())?;
    Ok(publication)
}
