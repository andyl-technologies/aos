//! Installed-profile and genuine retained-owner metadata routing.
//!
//! This path does no provider I/O or lease renewal. It cannot initialize a copy
//! session, drain an unknown turn or expose private continuations/part receipts.

use anyhow::{ensure, Result};
use aos_hub_core::{
    storage_authority::external_object::copy::metadata::{
        CopyMetadataProfile, CopyMetadataReply, CopyMetadataRequest, RetainedCopyOriginal,
        EXTERNAL_COPY_METADATA_PATH,
    },
    storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER},
};
use rand::TryRngCore as _;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use super::super::{
    config::configured,
    protocol::{digest, GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER},
    storage,
};
use super::{config, discovery};

/// Returns only an installed projection and an authenticated genuine guard record.
///
/// # Errors
/// Returns a bounded refusal for unsupported bindings, changed queries or corrupt state.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        ensure!(
            request.method() == Method::Post
                && request.url()?.path() == EXTERNAL_COPY_METADATA_PATH,
            "copy metadata route requires POST"
        );
        let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
        let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
        let signature = request
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("copy metadata signature absent"))?;
        let body = crate::hybrid::read_bounded_body(&mut request, MAX_MESSAGE)
            .await?
            .ok_or_else(|| anyhow::anyhow!("copy metadata oversized"))?;
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let query = CopyMetadataRequest::authenticate(
            &key,
            &signature,
            &body,
            &deployment,
            object.clock().observed_at,
        )?;
        let publication = crate::hybrid_binding::resolve_for_plan(env, &query.plan).await?;
        publication
            .snapshot
            .authorizes(&query.plan, &deployment, object.clock().observed_at)?;
        let config = config::configured(env, &object)?
            .ok_or_else(|| anyhow::anyhow!("copy consumer disabled"))?;
        let domain = config
            .domains
            .iter()
            .find(|domain| {
                domain.write_cohort.association.binding_id.get() == query.plan.binding_id
            })
            .ok_or_else(|| anyhow::anyhow!("copy domain absent"))?;
        let association = &domain.write_cohort.association;
        ensure!(
            association.binding_stable_id == publication.snapshot.binding_stable_id
                && association.binding_resource_version.get()
                    == query.plan.binding_resource_version
                && association.binding_prefix == publication.snapshot.object_prefix,
            "copy metadata current physical binding differs"
        );
        let mut reply = CopyMetadataReply {
            version: 1,
            request_digest: digest(&query)?,
            profile: CopyMetadataProfile {
                binding_stable_id: association.binding_stable_id.clone(),
                binding_write_revision: association.binding_write_revision,
                profile_digest: domain.commitment()?,
                part_bytes: domain.part_bytes,
                read_generation: domain.read_cohort.credential.generation,
                write_generation: domain.write_cohort.credential.generation,
                protected_versionless: domain.provider_contract.protected_versionless.is_some(),
            },
            retained: None,
            source_closure: None,
        };
        if query.profile_only {
            query.validate(&deployment, object.clock().observed_at)?;
            publication.snapshot.authorizes(
                &query.plan, &deployment, object.clock().observed_at,
            )?;
            return reply.sign(&key, &query);
        }
        let selector = reply.selector(&query)?;
        let scope = domain.selector_scope(&object, &selector)?;
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| anyhow::anyhow!("copy lookup correlation unavailable"))?;
        let message = discovery::Request {
            domain: discovery::DOMAIN.into(),
            nonce: hex::encode(nonce),
            scope,
            selector,
        };
        if let Some(retained) = call(env, &message).await? {
            reply.retained = Some(RetainedCopyOriginal {
                original: retained.original,
                progress: retained.progress,
            });
        }
        if reply.retained.is_none() && reply.profile.protected_versionless {
            let selector = reply.selector(&query)?;
            let message = super::source::request(
                &query.plan,
                domain.commitment()?,
                domain.selector_scope_for(&object, &selector, false)?,
                Some(selector),
                super::source_protocol::Operation::Lookup,
            )?;
            reply.source_closure = Some(super::source::lookup(env, &message).await?);
        }
        // Metadata lookup never turns historical bytes into fresh permission.
        // The application query must remain live after the guard await.
        query.validate(&deployment, object.clock().observed_at)?;
        publication
            .snapshot
            .authorizes(&query.plan, &deployment, object.clock().observed_at)?;
        reply.sign(&key, &query)
    }
    .await;
    match result {
        Ok((body, signature)) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
            Ok(Response::from_bytes(body)?.with_headers(headers))
        }
        Err(_) => Response::error("external copy metadata refused", 409),
    }
}

async fn call(env: &Env, message: &discovery::Request) -> Result<Option<discovery::Retained>> {
    message.validate()?;
    let key = storage::key(env)?;
    let body = serde_json::to_vec(message)?;
    let name = message.scope.guard_name()?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &key.sign_body(&body)?)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = Request::new_with_init(
        &format!("https://external-object{}", discovery::PATH),
        &init,
    )?;
    let response = env
        .durable_object(storage::BINDING)?
        .id_from_name(&name)?
        .get_stub()?
        .fetch_with_request(request)
        .await?;
    ensure!(
        response.status_code() == 200,
        "copy retained original lookup refused"
    );
    let signature = response
        .headers()
        .get(GUARD_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("copy lookup signature absent"))?;
    let body = crate::direct_digest::read_bounded_native(response, MAX_MESSAGE).await?;
    discovery::verify_reply(&key, message, &signature, &body)
}
