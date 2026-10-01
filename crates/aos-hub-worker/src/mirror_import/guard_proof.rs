//! Independently authenticated read-only final mirror guard lookup.
//!
//! Only the physical guard's held original and positive completion receipt may
//! produce a proof. The lookup needs no producer acceptance or provider request;
//! expiration therefore cannot strand an already completed publication.

use anyhow::{ensure, Result};
use aos_hub_core::{mirror_guard::*, mirror_work::digest, storage_work::StorageWorkKey};
use sha2::{Digest as _, Sha256};
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use crate::{direct_upload::config, hybrid_object::HybridObjectGuard};

pub(crate) mod batch;

pub(crate) const PHYSICAL_PATH: &str = "/mirror-final-guard";
pub(crate) const CANDIDATE_PHYSICAL_PATH: &str = "/mirror-candidate-final-guard";

fn key(env: &Env) -> Result<StorageWorkKey> {
    let secret = env.secret("HUB_MIRROR_GUARD_KEY")?.to_string();
    ensure!(
        secret != env.secret("HUB_STORAGE_WORK_KEY")?.to_string(),
        "mirror guard role must differ from producer authority"
    );
    if let Ok(candidate) = env.secret("HUB_MIRROR_CANDIDATE_KEY") {
        ensure!(
            secret != candidate.to_string(),
            "mirror guard role must differ from candidate producer authority"
        );
    }
    Ok(StorageWorkKey::new(secret)?)
}

fn issuer(env: &Env) -> Result<MirrorGuardIssuer> {
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| aos_hub_core::direct_upload::valid_direct_digest(source))
        .ok_or_else(|| anyhow::anyhow!("compiled mirror guard identity absent"))?;
    Ok(MirrorGuardIssuer {
        source_digest: source.into(),
        script_version: config::runtime_script_version(env)?,
    })
}

/// Uses the installed bounded UTC projection without renewing dispatch approval.
fn latest_now(env: &Env) -> Result<u64> {
    config::guard_latest_now(env)
}

async fn authenticate(
    request: &mut Request,
    env: &Env,
    candidate: bool,
) -> Result<(MirrorGuardLookup, Vec<u8>, String)> {
    ensure!(
        request.method() == Method::Post,
        "mirror guard requires POST"
    );
    ensure!(
        !candidate || cfg!(feature = "do-e2e"),
        "controlled mirror guard absent from production"
    );
    let signature = request
        .headers()
        .get(MIRROR_GUARD_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("mirror guard signature absent"))?;
    let body = crate::hybrid::read_bounded_body(request, MIRROR_GUARD_MAX_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("mirror guard control exceeds bound"))?;
    let lookup = verify_mirror_guard_lookup(
        &key(env)?,
        &signature,
        &body,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        latest_now(env)?,
    )?;
    ensure!(
        lookup.clock_uncertainty_seconds
            == config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?.get(),
        "mirror guard challenge changed independently selected clock uncertainty"
    );
    let execution = if candidate {
        MirrorGuardExecution::ControlledCandidate
    } else {
        MirrorGuardExecution::Hosted
    };
    ensure!(
        lookup.execution == execution && lookup.issuer == issuer(env)?,
        "mirror guard challenge selected another execution or implementation"
    );
    Ok((lookup, body, signature))
}

/// Relays an exact authenticated lookup to the same final-key physical guard.
pub(crate) async fn fetch(
    mut request: Request,
    env: &Env,
    candidate: bool,
) -> worker::Result<Response> {
    match relay(&mut request, env, candidate).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("mirror_final_guard_refused: {error:#}");
            Response::error("mirror final guard unavailable or unsettled", 409)
        }
    }
}

async fn relay(request: &mut Request, env: &Env, candidate: bool) -> Result<Response> {
    let (lookup, body, signature) = authenticate(request, env, candidate).await?;
    let full_key =
        aos_hub_core::keymap::r2_key(&lookup.original.placement_prefix, &lookup.original.path);
    let address = format!(
        "{}:{}",
        lookup.deployment_id,
        hex::encode(Sha256::digest(&full_key))
    );
    let headers = Headers::new();
    headers.set(MIRROR_GUARD_SIGNATURE_HEADER, &signature)?;
    headers.set("x-aos-hybrid-object-key", &full_key)?;
    let path = if candidate {
        CANDIDATE_PHYSICAL_PATH
    } else {
        PHYSICAL_PATH
    };
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let internal = Request::new_with_init(&format!("https://physical-guard{path}"), &init)?;
    let mut response = env
        .durable_object("HYBRID_OBJECT_GUARD")?
        .id_from_name(&address)?
        .get_stub()?
        .fetch_with_request(internal)
        .await?;
    if !candidate {
        crate::control_receipt::emit_forwarded_response(
            MIRROR_GUARD_LOOKUP_PATH,
            &body,
            &mut response,
        )
        .await;
    }
    Ok(response)
}

/// Signs only actual held positive progress while the existing guard gate is held.
pub(crate) async fn physical_fetch(
    guard: &HybridObjectGuard,
    physical_key: &str,
    request: &mut Request,
    candidate: bool,
) -> worker::Result<Response> {
    match retained_reply(guard, physical_key, request, candidate).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("mirror_physical_guard_refused: {error:#}");
            Response::error("mirror final guard unavailable or unsettled", 409)
        }
    }
}

async fn retained_reply(
    guard: &HybridObjectGuard,
    physical_key: &str,
    request: &mut Request,
    candidate: bool,
) -> Result<Response> {
    let (lookup, _, _) = authenticate(request, &guard.env, candidate).await?;
    let (original, progress) = super::runtime::retained_final(guard, physical_key).await?;
    ensure!(
        original == lookup.original && progress == lookup.expected,
        "mirror physical guard retained a different original or final receipt"
    );
    // Recheck the original deadline after durable reads; these reads neither
    // renew provider permission nor clear pending/unknown journals.
    let observed_at = latest_now(&guard.env)?;
    lookup.validate(
        &guard.env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        observed_at,
    )?;
    let reply = MirrorGuardReply {
        version: 1,
        request_digest: digest(&lookup)?,
        request_nonce: lookup.request_nonce.clone(),
        original_digest: digest(&original)?,
        issuer: issuer(&guard.env)?,
        progress,
        observed_at,
    };
    let signed = sign_mirror_guard_reply(&key(&guard.env)?, &reply, &lookup)?;
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    headers.set(MIRROR_GUARD_SIGNATURE_HEADER, &signed.signature)?;
    Ok(Response::from_bytes(signed.body)?.with_headers(headers))
}
