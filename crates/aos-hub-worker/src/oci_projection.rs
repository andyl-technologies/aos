//! Storage-side OCI parser and independently authenticated exact readback.
//!
//! The physical object gate remains held through conditional GET, original
//! byte verification and parsing. A pending mutation or publication owner
//! refuses the read; this route never settles a journal or creates an effect.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    oci_projection::{guard::*, OciDocumentProjection},
    storage_work::{StorageObjectIdentity, StorageWorkKey},
};
use futures_util::{
    lock::{Mutex, OwnedMutexGuard},
    FutureExt as _,
};
use js_sys::{Function, Object, Promise, Reflect};
use sha2::{Digest as _, Sha256};
use std::{rc::Rc, sync::Arc};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use crate::{
    direct_upload::{config, managed, provider_capacity},
    hybrid_object::HybridObjectGuard,
};

mod lifetime;

pub(crate) const PHYSICAL_PATH: &str = "/oci-document-projection";

fn guard_key(env: &Env) -> Result<StorageWorkKey> {
    let guard = env.secret("HUB_DIRECT_UPLOAD_GUARD_KEY")?.to_string();
    ensure!(
        guard != env.secret("HUB_STORAGE_WORK_KEY")?.to_string(),
        "OCI guard authority must differ from the logical producer"
    );
    Ok(StorageWorkKey::new(guard)?)
}

async fn authenticate(
    request: &mut Request,
    env: &Env,
) -> Result<(OciProjectionLookup, Vec<u8>, String)> {
    ensure!(
        request.method() == Method::Post,
        "OCI projection requires POST"
    );
    let signature = request
        .headers()
        .get(OCI_PROJECTION_SIGNATURE_HEADER)?
        .context("OCI projection signature absent")?;
    let body = crate::hybrid::read_bounded_body(request, MAX_OCI_PROJECTION_LOOKUP_BYTES)
        .await?
        .context("OCI projection lookup exceeds bound")?;
    let lookup = verify_oci_projection_lookup(
        &guard_key(env)?,
        &signature,
        &body,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        config::guard_latest_now(env)?,
    )?;
    ensure!(
        lookup.issuer.source_digest == option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or("")
            && lookup.issuer.script_version == config::runtime_script_version(env)?
            && lookup.clock_uncertainty_seconds
                == config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?.get(),
        "OCI projection selected another guard implementation or clock"
    );
    Ok((lookup, body, signature))
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match relay(&mut request, env).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("oci_projection_refused: {error:#}");
            Response::error("OCI document projection unavailable", 409)
        }
    }
}

async fn relay(request: &mut Request, env: &Env) -> Result<Response> {
    let (lookup, body, signature) = authenticate(request, env).await?;
    let address = format!(
        "{}:{}",
        lookup.deployment_id,
        hex::encode(Sha256::digest(&lookup.key))
    );
    let headers = Headers::new();
    headers.set(OCI_PROJECTION_SIGNATURE_HEADER, &signature)?;
    headers.set("x-aos-hybrid-object-key", &lookup.key)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    Ok(env
        .durable_object("HYBRID_OBJECT_GUARD")?
        .id_from_name(&address)?
        .get_stub()?
        .fetch_with_request(Request::new_with_init(
            &format!("https://physical-guard{PHYSICAL_PATH}"),
            &init,
        )?)
        .await?)
}

pub(crate) async fn physical_fetch(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
    gate: Arc<Mutex<()>>,
) -> worker::Result<Response> {
    let operation = async {
        let (lookup, _, _) = authenticate(request, &guard.env).await?;
        ensure!(
            lookup.key == key,
            "OCI projection addressed another physical guard"
        );
        bounded(&guard.env, &lookup, async {
            let gate = crate::hybrid_object::acquire_gate(gate).await;
            physical_reply(guard, key, &lookup, gate).await
        })
        .await
    };
    match operation.await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("oci_physical_projection_refused: {error:#}");
            Response::error("OCI document is unavailable or unsettled", 409)
        }
    }
}

async fn physical_reply(
    guard: &HybridObjectGuard,
    key: &str,
    lookup: &OciProjectionLookup,
    gate: OwnedMutexGuard<()>,
) -> Result<Response> {
    ensure!(
        lookup.key == key,
        "OCI projection addressed another physical guard"
    );
    let storage = guard.state.storage();
    crate::direct_guard::deny_legacy(&storage).await?;
    crate::mirror_import::runtime::deny_other_owner(&storage).await?;
    let pending: Option<crate::hybrid_object_state::Mutation> =
        storage.get("pending-mutation").await?;
    let deleting: Option<crate::hybrid_object_state::DeleteClaim> =
        storage.get("pending-delete").await?;
    crate::hybrid_object_state::ensure_ready(pending.as_ref(), deleting.as_ref())?;

    let qualified = config::QualifiedConfig::load(&guard.env).await?;
    ensure!(
        qualified.managed(&guard.env)?.0.digest()? == lookup.protected_profile_digest,
        "OCI projection actual provider/runtime/policy changed"
    );
    let before_dispatch = || {
        lookup.validate(&lookup.deployment_id, config::guard_latest_now(&guard.env)?)?;
        qualified.latest_now()?;
        ensure!(
            qualified.managed(&guard.env)?.0.digest()? == lookup.protected_profile_digest,
            "OCI projection actual provider/runtime/policy changed"
        );
        Ok(())
    };
    // A 4 MiB buffered parser does not fit the reserved 256 KiB metadata
    // producers. Share the existing one full-window budget with bulk decoders;
    // retain it through SDK settlement, reader cancellation and serialization.
    let buffer = crate::mirror_import::buffers::acquire(false, &before_dispatch).await?;
    let capacity = provider_capacity::acquire_class_checked(
        1,
        provider_capacity::Class::Metadata,
        &before_dispatch,
    )
    .await?;
    let owner = lifetime::Owner::new((gate, capacity, buffer));
    let _scope = lifetime::Scope(Rc::clone(&owner));
    let bucket = managed::bucket(&guard.env)?;
    before_dispatch()?;
    let head_object = sdk_read(&guard.state, &bucket, "head", key, None, Rc::clone(&owner)).await?;
    ensure!(
        !head_object.is_null() && !head_object.is_undefined(),
        "stored OCI document is absent"
    );
    let head = managed::identity(&head_object)?;
    ensure!(
        head.byte_size.get() == lookup.descriptor.size,
        "stored OCI document differs from its declared byte size"
    );
    let only_if = Object::new();
    Reflect::set(
        &only_if,
        &JsValue::from_str("etagMatches"),
        &JsValue::from_str(head.etag.trim_matches('"')),
    )
    .map_err(|_| anyhow::anyhow!("OCI conditional read unavailable"))?;
    let options = Object::new();
    Reflect::set(&options, &JsValue::from_str("onlyIf"), &only_if)
        .map_err(|_| anyhow::anyhow!("OCI conditional read unavailable"))?;
    before_dispatch()?;
    let object = sdk_read(
        &guard.state,
        &bucket,
        "get",
        key,
        Some(options.into()),
        Rc::clone(&owner),
    )
    .await?;
    let stream = Reflect::get(&object, &JsValue::from_str("body"))
        .map_err(|_| anyhow::anyhow!("OCI document body unavailable"))?
        .dyn_into::<worker::web_sys::ReadableStream>()
        .map_err(|_| anyhow::anyhow!("OCI document body unavailable"))?;
    let reader = owner.attach(crate::direct_digest::Reader::new(stream.into())?)?;
    ensure!(
        managed::identity(&object)? == head,
        "OCI conditional read returned another incarnation"
    );
    let mut bytes = Vec::new();
    loop {
        owner.check_open()?;
        lookup.validate(&lookup.deployment_id, config::guard_latest_now(&guard.env)?)?;
        let (view, done) = reader.read().await?;
        owner.check_open()?;
        ensure!(
            bytes
                .len()
                .checked_add(view.length() as usize)
                .is_some_and(|length| length <= aos_oci_types::limits::MAX_JSON_BYTES),
            "OCI document exceeds its shared bound"
        );
        bytes.extend_from_slice(&view.to_vec());
        if done {
            break;
        }
    }

    let projection = OciDocumentProjection::from_stored_bytes(&lookup.descriptor, &bytes)?;
    let observed_at = config::guard_latest_now(&guard.env)?;
    let reply = OciProjectionReply {
        request: lookup.clone(),
        object: StorageObjectIdentity {
            key: key.into(),
            size: head.byte_size.get(),
            etag: head.etag,
            provider_version: Some(head.version),
        },
        projection,
        observed_at,
    };
    let signed = sign_oci_projection_reply(&guard_key(&guard.env)?, &reply)?;
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(OCI_PROJECTION_SIGNATURE_HEADER, &signed.signature)?;
    Ok(Response::from_bytes(signed.body)?.with_headers(headers))
}

// The caller holds one metadata SDK permit across HEAD, conditional GET and
// body consumption, and checks current qualification immediately before each
// dispatch. This helper creates no object or business authority.
async fn sdk_read(
    state: &worker::State,
    bucket: &JsValue,
    method: &str,
    key: &str,
    options: Option<JsValue>,
    owner: Rc<
        lifetime::Owner<(
            OwnedMutexGuard<()>,
            provider_capacity::Permit,
            crate::mirror_import::buffers::Permit,
        )>,
    >,
) -> Result<JsValue> {
    owner.check_open()?;
    let function: Function = Reflect::get(bucket, &JsValue::from_str(method))
        .map_err(|_| anyhow::anyhow!("OCI SDK read unavailable"))?
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("OCI SDK read unavailable"))?;
    provider_capacity::record_dispatch();
    let value = match options {
        Some(options) => function.call2(bucket, &JsValue::from_str(key), &options),
        None => function.call1(bucket, &JsValue::from_str(key)),
    }
    .map_err(|_| anyhow::anyhow!("OCI SDK read failed"))?;
    let promise: Promise = value
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("OCI SDK read unavailable"))?;
    let pending = async move {
        JsFuture::from(promise)
            .await
            .map_err(|_| "OCI SDK read failed")
    }
    .shared();
    let retained = pending.clone();
    let retained_owner = Rc::clone(&owner);
    // R2 exposes no native abort handle for these calls. Keep the exact key
    // and provider slot while the real SDK promise remains unresolved, even
    // when the bounded lookup future is dropped. This is not a drain receipt.
    state.wait_until(async move {
        let result = retained.await;
        if retained_owner.check_open().is_err() {
            if let Ok(object) = &result {
                if let Ok(body) = Reflect::get(object, &JsValue::from_str("body")) {
                    if !body.is_null() && !body.is_undefined() {
                        // Initiate cancellation of this exact late response.
                        // Neither cancellation nor timeout settles a journal.
                        if let Ok(reader) = crate::direct_digest::Reader::new(body) {
                            drop(reader);
                        }
                    }
                }
            }
        }
    });
    let result = pending.await.map_err(anyhow::Error::msg)?;
    owner.check_open()?;
    Ok(result)
}

async fn bounded<T>(
    env: &Env,
    lookup: &OciProjectionLookup,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let remaining = lookup
        .expires_at
        .checked_sub(config::guard_latest_now(env)?)
        .filter(|seconds| *seconds > 0)
        .context("OCI original deadline expired")?;
    let timer = worker::Delay::from(std::time::Duration::from_secs(remaining));
    match futures_util::future::select(Box::pin(operation), Box::pin(timer)).await {
        futures_util::future::Either::Left((result, _)) => {
            lookup.validate(&lookup.deployment_id, config::guard_latest_now(env)?)?;
            result
        }
        futures_util::future::Either::Right(_) => anyhow::bail!("OCI original deadline expired"),
    }
}
