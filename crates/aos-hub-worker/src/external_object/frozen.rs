//! Authenticated observational lookup of actual per-key uncertainty for GC HEAD.

use super::{
    config::{configured, coordinates, Config},
    storage::{load_head, BINDING},
};
use anyhow::{ensure, Result};
use aos_hub_core::{
    storage_authority::control::StorageAuthorityObjectScope,
    storage_work::{binding_custody::*, StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER},
};
use serde::{Deserialize, Serialize};
use worker::{Env, Headers, Method, Request, RequestInit, Response, State};

const PATH: &str = "/frozen-cleanup-ready";
const DOMAIN: &[u8] = b"aos.storage-frozen-cleanup.physical-ready-reply.v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    request: StorageFrozenCleanupCustodyRequest,
}

fn scope(
    config: &Config,
    request: &StorageFrozenCleanupCustodyRequest,
) -> Result<StorageAuthorityObjectScope> {
    let coordinates = coordinates(&request.snapshot)?;
    let aliases: Vec<_> = config
        .aliases
        .iter()
        .filter(|alias| alias.spec == coordinates)
        .collect();
    ensure!(
        aliases.len() == 1,
        "frozen physical alias missing or ambiguous"
    );
    let relative = aos_hub_core::keymap::r2_key(&request.access.placement_prefix, &request.path);
    let scope = StorageAuthorityObjectScope {
        guard_namespace_id: config.guard_namespace_id.clone(),
        physical_authority_id: aliases[0].authority_id.clone(),
        full_key: aos_hub_core::keymap::r2_key(&request.snapshot.object_prefix, &relative),
    };
    scope.guard_name()?;
    Ok(scope)
}

/// Reads the exact protected physical guard before a frozen cleanup observation.
///
/// # Errors
/// Returns an error for ambiguous aliases, held owners, unknown effects, expired
/// originals, unavailable storage or changed authenticated replies.
pub(crate) async fn check_cleanup_ready(
    env: &Env,
    request: &StorageFrozenCleanupCustodyRequest,
) -> Result<()> {
    let Some(config) = configured(env)? else {
        return Ok(());
    };
    if !config.manages(&request.snapshot)? {
        return Ok(());
    }
    let scope = scope(&config, request)?;
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    let signed = sign_storage_frozen_cleanup_custody(&key, request)?;
    let headers = Headers::new();
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signed.signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(
            js_sys::Uint8Array::from(signed.body.as_slice()).into(),
        ));
    let forwarded = Request::new_with_init(&format!("https://physical-guard{PATH}"), &init)?;
    let response = env
        .durable_object(BINDING)?
        .id_from_name(&scope.guard_name()?)?
        .get_stub()?
        .fetch_with_request(forwarded)
        .await?;
    ensure!(
        response.status_code() == 200,
        "frozen physical key remains held or unknown"
    );
    let signature = response
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("frozen physical readiness authentication absent"))?;
    let bytes =
        crate::direct_digest::read_bounded_native(response, MAX_BINDING_CUSTODY_BYTES).await?;
    key.verify_body(&signature, &[DOMAIN, &bytes].concat())?;
    let ready: Ready = serde_json::from_slice(&bytes)?;
    ensure!(
        ready.request == *request,
        "frozen physical readiness original changed"
    );
    request.validate(
        &request.snapshot.deployment_id,
        aos_hub_core::clock::now_unix_secs(),
    )?;
    Ok(())
}

pub(super) async fn readiness(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> worker::Result<Response> {
    let result = async {
        ensure!(
            request.method() == Method::Post,
            "frozen physical lookup method differs"
        );
        let body = crate::hybrid::read_bounded_body(request, MAX_BINDING_CUSTODY_BYTES)
            .await?
            .ok_or_else(|| anyhow::anyhow!("frozen physical lookup exceeds bound"))?;
        let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
        let signature = request
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("frozen physical authentication absent"))?;
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let original = verify_storage_frozen_cleanup_custody(
            &key,
            &signature,
            &body,
            &deployment,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let config = configured(env)?
            .ok_or_else(|| anyhow::anyhow!("frozen physical authority unavailable"))?;
        let scope = scope(&config, &original)?;
        ensure!(
            env.durable_object(BINDING)?
                .id_from_name(&scope.guard_name()?)?
                .to_string()
                == state.id().to_string(),
            "frozen physical lookup address differs"
        );
        crate::direct_guard::deny_legacy(&state.storage()).await?;
        if let Some(head) = load_head(&state.storage()).await? {
            head.validate(&config, &scope)?;
            head.require_cleanup_ready()?;
        }
        original.validate(&deployment, aos_hub_core::clock::now_unix_secs())?;
        let body = serde_json::to_vec(&Ready { request: original })?;
        let signature = key.sign_body(&[DOMAIN, &body].concat())?;
        let headers = Headers::new();
        headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
        headers.set("cache-control", "private, no-store")?;
        Ok::<_, anyhow::Error>(Response::from_bytes(body)?.with_headers(headers))
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(_) => Response::error("frozen physical key unavailable", 409),
    }
}
