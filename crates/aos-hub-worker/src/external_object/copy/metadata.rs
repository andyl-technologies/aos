//! Installed-profile and genuine retained-owner metadata routing.
//!
//! This path does no provider I/O or lease renewal. It cannot initialize a copy
//! session, drain an unknown turn or expose private continuations/part receipts.

use anyhow::{Result, ensure};
use aos_hub_core::{
    storage_authority::external_object::copy::metadata::{
        CopyMetadataProfile, CopyMetadataReply, CopyMetadataRequest, EXTERNAL_COPY_METADATA_PATH,
        RetainedCopyOriginal,
    },
    storage_work::{STORAGE_WORK_SIGNATURE_HEADER, StorageBindingPublication, StorageWorkKey},
};
use rand::TryRngCore as _;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use super::super::{
    config::configured,
    protocol::{GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER, digest},
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
        let source_publication = if let Some(plan) = &query.source_plan {
            ensure!(
                config.version == 2,
                "paired copy requires the new configured capacity contract"
            );
            let source = crate::hybrid_binding::resolve_for_plan(env, plan).await?;
            source
                .snapshot
                .authorizes(plan, &deployment, object.clock().observed_at)?;
            Some(source)
        } else {
            None
        };
        let source_domain = if let Some(plan) = &query.source_plan {
            config
                .domains
                .iter()
                .find(|domain| domain.read_cohort.association.binding_id.get() == plan.binding_id)
                .ok_or_else(|| anyhow::anyhow!("independent copy source Read domain absent"))?
        } else {
            domain
        };
        if let Some(source) = &source_publication {
            check_source_publication(&object, source_domain, &query, source, &deployment)?;
        }
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
            transfer: match (&query.source_plan, &source_publication) {
                (Some(plan), Some(source)) => {
                    use aos_hub_core::storage_authority::external_object::copy::{
                        CopyIncarnationMode, CopySourceBindingPin, CopyTransferPins,
                    };
                    let mode = |domain: &config::Domain| {
                        if domain.provider_contract.protected_versionless.is_some() {
                            CopyIncarnationMode::GuardedClosure
                        } else {
                            CopyIncarnationMode::ProviderVersion
                        }
                    };
                    let association = &source_domain.read_cohort.association;
                    Some(CopyTransferPins {
                        source_binding: CopySourceBindingPin {
                            binding_id: association.binding_id,
                            binding_stable_id: source.snapshot.binding_stable_id.clone(),
                            binding_resource_version: association.binding_resource_version,
                            snapshot_revision: plan
                                .binding_snapshot_revision
                                .clone()
                                .ok_or_else(|| anyhow::anyhow!("source snapshot absent"))?,
                            profile_digest: source_domain.commitment()?,
                            binding_read_revision: association.binding_write_revision,
                            read_generation: source_domain.read_cohort.credential.generation,
                            physical_authority_id: source_domain
                                .read_cohort
                                .authority
                                .authority_id
                                .clone(),
                        },
                        source_incarnation: mode(source_domain),
                        destination_incarnation: mode(domain),
                        destination_physical_authority_id: domain
                            .write_cohort
                            .authority
                            .authority_id
                            .clone(),
                        maximum_source_range_bytes: source_domain
                            .provider_contract
                            .maximum_copy_read_range_bytes
                            .ok_or_else(|| {
                                anyhow::anyhow!("accepted copy source range bound absent")
                            })?,
                    })
                }
                (None, None) => None,
                _ => anyhow::bail!("paired source publication absent"),
            },
        };
        if query.profile_only {
            query.validate(&deployment, object.clock().observed_at)?;
            publication.snapshot.authorizes(
                &query.plan,
                &deployment,
                object.clock().observed_at,
            )?;
            if let Some(source) = &source_publication {
                check_source_publication(&object, source_domain, &query, source, &deployment)?;
            }
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
        let source_protected = source_domain
            .provider_contract
            .protected_versionless
            .is_some();
        if reply.retained.is_none() && source_protected {
            let selector = reply.selector(&query)?;
            let message = super::source::request(
                query.source_plan.as_ref().unwrap_or(&query.plan),
                source_domain.commitment()?,
                source_domain.selector_scope_for(&object, &selector, false)?,
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
        if let Some(source) = &source_publication {
            check_source_publication(&object, source_domain, &query, source, &deployment)?;
        }
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

fn check_source_publication(
    object: &super::super::config::Config,
    domain: &config::Domain,
    query: &CopyMetadataRequest,
    publication: &StorageBindingPublication,
    deployment: &str,
) -> Result<()> {
    let plan = query
        .source_plan
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("source Read plan absent"))?;
    publication
        .snapshot
        .authorizes(plan, deployment, object.clock().observed_at)?;
    let cohort = &domain.read_cohort;
    ensure!(
        publication.snapshot.binding_stable_id == cohort.association.binding_stable_id
            && publication.snapshot.object_prefix == cohort.association.binding_prefix
            && plan
                .credential_references
                .first()
                .is_some_and(|selected| selected.generation == cohort.credential.generation.get())
            && super::super::executor::select_cohort(
                object,
                publication,
                "read",
                cohort.association.binding_write_revision.get()
            )? == cohort,
        "copy metadata independent current Read cohort differs"
    );
    Ok(())
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
