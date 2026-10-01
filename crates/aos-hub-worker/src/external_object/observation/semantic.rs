//! Paired HEAD preparation with protected Worker-owned epoch renewal.
//!
//! No local admission queue or coalescing capacity is implied. Existing cohort
//! caching amortizes issuance; every effect still uses the permanent object floor.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::external_object::{
    observation::{
        semantic::{SemanticExternalObservationRequest, MAX_SEMANTIC_OBSERVATION_BYTES},
        ExternalObservationRequest, ObservationExpectation, OBSERVATION_APPLICATION_DOMAIN,
    },
    ExternalObjectRequest, EXTERNAL_OBJECT_APPLICATION_DOMAIN,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};
use worker::{Env, Headers, Method, Request, Response};

use super::super::{config::configured, stage};
use super::{executor::execute_authorized, reply::ReplyBinding};

/// Returns an authenticated semantic reply or a value-free refusal.
///
/// # Errors
/// Returns an error only when a bounded runtime response cannot be constructed.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok((body, mac)) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            headers.set(STORAGE_WORK_SIGNATURE_HEADER, &mac)?;
            Ok(
                Response::ok(String::from_utf8(body).map_err(super::super::storage::error)?)?
                    .with_headers(headers),
            )
        }
        Err(_) => Response::error("semantic external observation refused", 409),
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<(Vec<u8>, String)> {
    ensure!(
        request.method() == Method::Post,
        "invalid semantic observation method"
    );
    let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("external consumer disabled"))?;
    let mac = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("semantic application signature absent"))?;
    let body = crate::hybrid::read_bounded_body(request, MAX_SEMANTIC_OBSERVATION_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("semantic observation request oversized"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    let semantic = SemanticExternalObservationRequest::authenticate(
        &key,
        &mac,
        &body,
        &deployment,
        object.clock().observed_at,
    )?;
    let mut profiles =
        stage::resolve_external_profiles(env, std::slice::from_ref(&semantic.profile_selector))
            .await?;
    ensure!(profiles.len() == 1, "semantic profile resolution differs");
    let profile = profiles
        .pop()
        .ok_or_else(|| anyhow::anyhow!("semantic profile absent"))?;
    ensure!(
        profile.fingerprint()? == semantic.expected_profile_fingerprint,
        "semantic profile commitment differs"
    );
    semantic.validate(&deployment, object.clock().observed_at)?;

    let lease = stage::prepare_observation_read_lease(env, &object, &profile).await?;
    // Profile resolution, issuer queue and reply verification cannot extend the
    // original application authorization. Never manufacture a replacement plan.
    semantic.validate(&deployment, object.clock().observed_at)?;
    let authorized = ExternalObservationRequest {
        version: 1,
        domain: OBSERVATION_APPLICATION_DOMAIN.into(),
        authorization: ExternalObjectRequest {
            version: 1,
            domain: EXTERNAL_OBJECT_APPLICATION_DOMAIN.into(),
            operation_id: semantic.operation_id.clone(),
            binding_write_revision: semantic.binding_write_revision,
            plan: semantic.plan.clone(),
            lease,
        },
        expectation: ObservationExpectation::KnownStamp {
            stamp: semantic.expected_guard_stamp.clone(),
        },
    };
    authorized.validate(&deployment, object.clock().observed_at)?;
    execute_authorized(
        env,
        &object,
        &deployment,
        &key,
        &authorized,
        ReplyBinding::Semantic {
            bytes: &body,
            cohort: &profile.read_cohort,
        },
    )
    .await
}
