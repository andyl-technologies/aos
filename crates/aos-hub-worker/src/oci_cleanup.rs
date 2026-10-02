//! Current terminal SQL cleanup through the existing same-key R2 guard.
//!
//! Full SHA is streamed beside storage under an actual conditional R2 read.
//! New Delete uses ordinary accepted provider permission and terminal SQL, not
//! an OCI anchor artifact. Cold positive replay performs no provider operation.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    oci_cleanup::*,
    storage_work::{StorageObjectIdentity, StorageWorkKey},
};
use futures_util::{
    FutureExt as _,
    lock::{Mutex, OwnedMutexGuard},
};
use js_sys::{Function, Object, Promise, Reflect};
use sha2::{Digest as _, Sha256};
use std::{rc::Rc, sync::Arc, time::Duration};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use crate::{
    direct_upload::{config, managed, provider_capacity},
    hybrid_object::HybridObjectGuard,
    hybrid_object_state::MutationOutcome,
    oci_cleanup_state::Record,
    oci_projection::lifetime::{Owner, Scope},
};

mod permission;

pub(crate) const PHYSICAL_PATH: &str = "/terminal-oci-cleanup";
const PHYSICAL_HEADER: &str = "x-aos-managed-oci-cleanup-guard";
const PHYSICAL_DOMAIN: &[u8] = b"aos.managed-oci-cleanup-physical.v1\0";

async fn authenticate(
    request: &mut Request,
    env: &Env,
) -> Result<(ManagedOciCleanupRequest, Vec<u8>, String)> {
    ensure!(
        request.method() == Method::Post,
        "Managed OCI cleanup requires POST"
    );
    let signature = request
        .headers()
        .get(MANAGED_OCI_CLEANUP_HEADER)?
        .context("Managed OCI cleanup application signature absent")?;
    let body = crate::hybrid::read_bounded_body(request, MAX_MANAGED_OCI_CLEANUP_BYTES)
        .await?
        .context("Managed OCI cleanup metadata exceeds bound")?;
    let work = ManagedOciCleanupRequest::authenticate(
        &StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?,
        &signature,
        &body,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        config::guard_latest_now(env)?,
    )?;
    ensure!(
        work.issuer.source_digest == option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or("")
            && work.issuer.script_version == config::runtime_script_version(env)?
            && work.clock_uncertainty_seconds
                == config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?.get(),
        "Managed OCI cleanup actual guard implementation or clock changed"
    );
    Ok((work, body, signature))
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        let (work, body, signature) = authenticate(&mut request, env).await?;
        let role = crate::oci_projection::guard_key(env)?;
        let headers = Headers::new();
        headers.set(MANAGED_OCI_CLEANUP_HEADER, &signature)?;
        headers.set(
            PHYSICAL_HEADER,
            &role.sign_body(&[PHYSICAL_DOMAIN, &body].concat())?,
        )?;
        headers.set("x-aos-hybrid-object-key", &work.original.key())?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
        let address = format!(
            "{}:{}",
            work.deployment_id,
            hex::encode(Sha256::digest(work.original.key()))
        );
        let response = env
            .durable_object("HYBRID_OBJECT_GUARD")?
            .id_from_name(&address)?
            .get_stub()?
            .fetch_with_request(Request::new_with_init(
                &format!("https://physical-guard{PHYSICAL_PATH}"),
                &init,
            )?)
            .await?;
        work.validate(&work.deployment_id, config::guard_latest_now(env)?)?;
        ensure!(
            response.status_code() == 200,
            "Managed OCI cleanup unavailable or unknown"
        );
        let signature = response
            .headers()
            .get(MANAGED_OCI_CLEANUP_HEADER)?
            .context("Managed OCI cleanup physical positive signature absent")?;
        let body = crate::hybrid::read_bounded_response(response, MAX_MANAGED_OCI_CLEANUP_BYTES)
            .await?
            .context("Managed OCI cleanup positive metadata exceeds bound")?;
        let reply = ManagedOciCleanupReply::authenticate(&work, &role, &signature, &body)?;
        work.validate(&work.deployment_id, config::guard_latest_now(env)?)?;
        signed_reply(&work, &reply, &role)
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("managed_oci_cleanup_refused: {error:#}");
            Response::error("Managed terminal cleanup unavailable", 409)
        }
    }
}

pub(crate) async fn physical_fetch(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
    gate: Arc<Mutex<()>>,
) -> worker::Result<Response> {
    let result = async {
        let (work, body, _) = authenticate(request, &guard.env).await?;
        ensure!(
            work.original.key() == key,
            "Managed cleanup selected another physical key"
        );
        let role = crate::oci_projection::guard_key(&guard.env)?;
        role.verify_body(
            &request
                .headers()
                .get(PHYSICAL_HEADER)?
                .context("Managed cleanup physical role absent")?,
            &[PHYSICAL_DOMAIN, &body].concat(),
        )?;
        let gate = loop {
            work.validate(&work.deployment_id, config::guard_latest_now(&guard.env)?)?;
            if let Some(gate) = gate.try_lock_owned() {
                break gate;
            }
            worker::Delay::from(Duration::from_millis(50)).await;
        };
        let reply = physical_reply(guard, &work, gate).await?;
        work.validate(&work.deployment_id, config::guard_latest_now(&guard.env)?)?;
        signed_reply(&work, &reply, &role)
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("managed_oci_physical_cleanup_refused: {error:#}");
            Response::error("Managed terminal cleanup unsettled", 409)
        }
    }
}

async fn physical_reply(
    guard: &HybridObjectGuard,
    work: &ManagedOciCleanupRequest,
    gate: OwnedMutexGuard<()>,
) -> Result<ManagedOciCleanupReply> {
    let storage = guard.state.storage();
    let record_key = format!("terminal-oci-cleanup:{}", work.original.fingerprint()?);
    let prior: Option<Record> = storage.get(&record_key).await?;
    work.validate(&work.deployment_id, config::guard_latest_now(&guard.env)?)?;
    if let Some(prior) = prior {
        // A pending cell never authorizes another read, lease or delete.
        let receipt = storage
            .get(&crate::hybrid_object::receipt_key(&prior.mutation))
            .await?;
        work.validate(&work.deployment_id, config::guard_latest_now(&guard.env)?)?;
        return prior.reply(work, receipt.as_ref());
    }

    crate::direct_guard::deny_legacy(&storage).await?;
    crate::mirror_import::runtime::deny_other_owner(&storage).await?;
    let pending = storage.get("pending-mutation").await?;
    let deleting = storage.get("pending-delete").await?;
    crate::hybrid_object_state::ensure_ready(pending.as_ref(), deleting.as_ref())?;
    let permission = permission::Permission::load(&guard.env, work).await?;
    let check = || {
        work.validate(&work.deployment_id, config::guard_latest_now(&guard.env)?)?;
        permission.check(&guard.env, work)?;
        Ok(())
    };
    let capacity =
        provider_capacity::acquire_class_checked(1, provider_capacity::Class::Metadata, &check)
            .await?;
    let owner = Owner::new((gate, capacity));
    let _scope = Scope(Rc::clone(&owner));
    let bucket = managed::bucket(&guard.env)?;
    let key = work.original.key();
    let head = invoke(
        guard,
        &bucket,
        "head",
        &[JsValue::from_str(&key)],
        work,
        Rc::clone(&owner),
        &check,
    )
    .await?;
    ensure!(
        !head.is_null() && !head.is_undefined(),
        "Managed cleanup positive source is absent"
    );
    let identity = managed::identity(&head)?;
    let object = StorageObjectIdentity {
        key: key.clone(),
        size: identity.byte_size.get(),
        etag: identity.etag,
        provider_version: Some(identity.version),
    };
    let record = Record::new(work.original.clone(), object.clone())?;

    let only_if = Object::new();
    Reflect::set(
        &only_if,
        &JsValue::from_str("etagMatches"),
        &JsValue::from_str(object.etag.trim_matches('"')),
    )
    .map_err(|_| anyhow::anyhow!("Managed cleanup conditional read unavailable"))?;
    let options = Object::new();
    Reflect::set(&options, &JsValue::from_str("onlyIf"), &only_if)
        .map_err(|_| anyhow::anyhow!("Managed cleanup conditional read unavailable"))?;
    let read = invoke(
        guard,
        &bucket,
        "get",
        &[JsValue::from_str(&key), options.into()],
        work,
        Rc::clone(&owner),
        &check,
    )
    .await?;
    // Attach cancellation ownership before rejecting any returned identity.
    let reader = owner.attach(crate::direct_digest::Reader::new(
        Reflect::get(&read, &JsValue::from_str("body"))
            .map_err(|_| anyhow::anyhow!("Managed cleanup body absent"))?,
    )?)?;
    let actual = managed::identity(&read)?;
    ensure!(
        actual.byte_size.get() == object.size
            && actual.etag == object.etag
            && Some(actual.version) == object.provider_version,
        "Managed cleanup source incarnation changed"
    );
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    loop {
        check()?;
        let remaining = remaining(work, &guard.env)?;
        let next = futures_util::future::select(
            Box::pin(reader.read()),
            Box::pin(worker::Delay::from(Duration::from_secs(remaining))),
        )
        .await;
        let (view, done) = match next {
            futures_util::future::Either::Left((result, _)) => result?,
            futures_util::future::Either::Right(_) => {
                anyhow::bail!("Managed cleanup read cutoff expired")
            }
        };
        check()?;
        bytes = bytes
            .checked_add(u64::from(view.length()))
            .context("Managed cleanup byte overflow")?;
        ensure!(
            bytes <= work.original.size,
            "Managed cleanup source exceeds retained SQL size"
        );
        hash.update(view.to_vec());
        if done {
            break;
        }
    }
    ensure!(
        bytes == work.original.size && hex::encode(hash.finalize()) == work.original.sha256,
        "Managed cleanup source does not match immutable SQL chunk bytes"
    );
    check()?;
    storage.put(&record_key, &record).await?;
    check()?;
    ensure!(
        guard.begin_mutation(&record.mutation).await?.is_none(),
        "Managed cleanup new turn unexpectedly replayed"
    );
    check()?;
    // The existing pending fence is permanent. The owner retains its actual
    // full-key turn and provider capacity through SDK promise settlement.
    invoke(
        guard,
        &bucket,
        "delete",
        &[JsValue::from_str(&key)],
        work,
        Rc::clone(&owner),
        &check,
    )
    .await?;
    guard
        .finish_mutation(record.mutation.clone(), MutationOutcome::Acknowledged)
        .await?;
    let receipt = storage
        .get(&crate::hybrid_object::receipt_key(&record.mutation))
        .await?;
    record.reply(work, receipt.as_ref())
}

async fn invoke<R: 'static>(
    guard: &HybridObjectGuard,
    object: &JsValue,
    method: &str,
    arguments: &[JsValue],
    work: &ManagedOciCleanupRequest,
    owner: Rc<Owner<R>>,
    check: &impl Fn() -> Result<()>,
) -> Result<JsValue> {
    check()?;
    let function: Function = Reflect::get(object, &JsValue::from_str(method))
        .map_err(|_| anyhow::anyhow!("Managed cleanup SDK method unavailable"))?
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("Managed cleanup SDK method unavailable"))?;
    let arguments = arguments.iter().cloned().collect::<js_sys::Array>();
    check()?;
    provider_capacity::record_dispatch();
    let promise: Promise = function
        .apply(object, &arguments)
        .map_err(|_| anyhow::anyhow!("Managed cleanup SDK dispatch failed"))?
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("Managed cleanup SDK promise unavailable"))?;
    let pending = async move {
        JsFuture::from(promise)
            .await
            .map_err(|_| "Managed cleanup SDK acknowledgement unknown")
    }
    .shared();
    let retained = pending.clone();
    let retained_owner = Rc::clone(&owner);
    let returned_body = method == "get";
    guard.state.wait_until(async move {
        let result = retained.await;
        if returned_body && retained_owner.check_open().is_err() {
            if let Ok(object) = result {
                if let Ok(body) = Reflect::get(&object, &JsValue::from_str("body")) {
                    if !body.is_null() && !body.is_undefined() {
                        if let Ok(reader) = crate::direct_digest::Reader::new(body) {
                            drop(reader);
                        }
                    }
                }
            }
        }
        drop(retained_owner);
    });
    let result = futures_util::future::select(
        Box::pin(pending),
        Box::pin(worker::Delay::from(Duration::from_secs(remaining(
            work, &guard.env,
        )?))),
    )
    .await;
    let value = match result {
        futures_util::future::Either::Left((result, _)) => result.map_err(anyhow::Error::msg)?,
        futures_util::future::Either::Right(_) => {
            anyhow::bail!("Managed cleanup SDK outcome remains unknown after cutoff")
        }
    };
    // GET handoff attaches its reader in the caller before the post-read check.
    if !returned_body {
        check()?;
    }
    owner.check_open()?;
    Ok(value)
}

fn remaining(work: &ManagedOciCleanupRequest, env: &Env) -> Result<u64> {
    work.expires_at
        .checked_sub(config::guard_latest_now(env)?)
        .filter(|seconds| *seconds > 0)
        .context("Managed OCI cleanup deadline expired")
}

fn signed_reply(
    work: &ManagedOciCleanupRequest,
    reply: &ManagedOciCleanupReply,
    role: &StorageWorkKey,
) -> Result<Response> {
    let (body, signature) = reply.sign(work, role)?;
    let mut response = Response::from_bytes(body)?;
    response.headers().set("content-type", "application/json")?;
    response
        .headers()
        .set(MANAGED_OCI_CLEANUP_HEADER, &signature)?;
    Ok(response)
}
