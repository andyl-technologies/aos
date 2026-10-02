//! Read-only retained-original discovery on the existing physical OCI guard.
//!
//! Both edge and physical handlers authenticate the original independent guard
//! challenge. They read actual durable positive receipts, never SDK HEAD, and
//! grant no mutation or producer renewal.

use std::time::Duration;
use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::external_object::oci::source::*;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use super::super::{config::configured, storage::{ExternalObjectGuard, BINDING}};
use super::{config, storage::Journal};

const PHYSICAL: &str = "/oci-source";

fn latest(env: &Env) -> Result<i64> {
    i64::try_from(crate::direct_upload::config::guard_latest_now(env)?)
        .context("OCI source clock exceeds UTC")
}

async fn authenticate(request: &mut Request, env: &Env)
    -> Result<(OciSourceLookup, Vec<u8>, String)> {
    ensure!(request.method() == Method::Post, "OCI source requires POST");
    let signature = request.headers().get(OCI_SOURCE_SIGNATURE_HEADER)?
        .context("OCI source signature absent")?;
    let body = crate::hybrid::read_bounded_body(request, MAX_OCI_SOURCE_BYTES).await?
        .context("OCI source challenge oversized")?;
    let role = super::super::storage::key(env)?;
    let lookup = OciSourceLookup::authenticate(&role, &signature, &body,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(), latest(env)?)?;
    ensure!(lookup.issuer.source_digest == option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or("")
        && lookup.issuer.script_version == crate::direct_upload::config::runtime_script_version(env)?
        && lookup.clock_uncertainty_seconds
            == crate::direct_upload::config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?.get(),
        "OCI source selected another guard or clock");
    Ok((lookup, body, signature))
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        let (lookup, body, signature) = authenticate(&mut request, env).await?;
        let headers = Headers::new();
        headers.set(OCI_SOURCE_SIGNATURE_HEADER, &signature)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post).with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
        lookup.validate(&lookup.deployment_id, latest(env)?)?;
        let response = env.durable_object(BINDING)?.id_from_name(&lookup.scope.guard_name()?)?
            .get_stub()?.fetch_with_request(Request::new_with_init(
                &format!("https://guard.invalid{PHYSICAL}"), &init)?).await?;
        lookup.validate(&lookup.deployment_id, latest(env)?)?;
        Ok::<_, anyhow::Error>(response)
    }.await;
    match result { Ok(response) => Ok(response), Err(_) => Response::error("OCI source unavailable or unsettled", 409) }
}

impl ExternalObjectGuard {
    pub(in crate::external_object) async fn oci_source_fetch(&self, request: &mut Request)
        -> worker::Result<Response> {
        let operation = async {
            ensure!(request.url()?.path() == PHYSICAL, "OCI source physical route differs");
            let (lookup, _, _) = authenticate(request, &self.env).await?;
            let object = configured(&self.env)?.context("external object consumer disabled")?;
            let name = lookup.scope.guard_name()?;
            ensure!(lookup.scope.guard_namespace_id == object.guard_namespace_id
                && self.env.durable_object(BINDING)?.id_from_name(&name)?.to_string()
                    == self.state.id().to_string(), "OCI source addressed another guard");
            let gate = loop {
                lookup.validate(&lookup.deployment_id, latest(&self.env)?)?;
                if let Some(gate) = self.gate.try_lock_owned() { break gate; }
                worker::Delay::from(Duration::from_millis(50)).await;
            };
            crate::direct_guard::deny_legacy(&self.state.storage()).await?;
            let session = Journal::visible(&self.state.storage(), &object, &lookup).await?;
            let config = config::configured(&self.env, &object)?;
            let profile = config.profile(&session.original)?;
            let publication = crate::hybrid_binding::resolve_for_delivery(&self.env,
                lookup.writer.binding_id.get(), lookup.writer.binding_resource_version.get()).await?;
            profile.validate_snapshot(&publication.snapshot, latest(&self.env)?)?;
            let reply = OciSourceReply {
                request_digest: super::super::protocol::digest(&lookup)?, nonce: lookup.nonce.clone(),
                original: session.original, closed: session.closed.context("OCI source closure absent")?,
                observed_at: object.clock().observed_at,
            };
            if lookup.range.is_some() {
                return self.oci_source_range(lookup, reply, object, profile.clone(), publication, gate).await;
            }
            let role = super::super::storage::key(&self.env)?;
            let (body, signature) = reply.sign(&lookup, &role, latest(&self.env)?)?;
            let response = Response::from_bytes(body)?;
            response.headers().set(OCI_SOURCE_SIGNATURE_HEADER, &signature)?;
            response.headers().set("content-type", "application/json")?;
            response.headers().set("cache-control", "private, no-store")?;
            Ok::<_, anyhow::Error>(response)
        }.await;
        match operation { Ok(response) => Ok(response), Err(_) => Response::error("OCI source unavailable or unsettled", 409) }
    }
}

impl ExternalObjectGuard {
    async fn oci_source_range(
        &self,
        lookup: OciSourceLookup,
        reply: OciSourceReply,
        object: super::super::config::Config,
        profile: aos_hub_core::storage_authority::external_object::oci::qualification::ExternalOciProfile,
        publication: aos_hub_core::storage_work::StorageBindingPublication,
        gate: futures_util::lock::OwnedMutexGuard<()>,
    ) -> Result<Response> {
        use std::rc::Rc;
        use aos_hub_core::{storage_authority::{external_object::oci::OciProviderIncarnation,
            lease::LeaseEffect}, s3surface::S3Surface, storage_work::StorageCredentialSelector};
        use crate::{oci_projection::lifetime::{Owner, Scope},
            direct_upload::provider_capacity::{self, Class}};
        let range = lookup.range.as_ref().context("OCI source range absent")?.clone();
        let accepted = config::require(&self.env, &object, &profile, &lookup.writer.placement_prefix).await?;
        lookup.validate(&lookup.deployment_id, latest(&self.env)?)?;
        let token = super::super::stage::acquire_configured_lease(&self.env, &object,
            &profile.issuer_installation, &profile.read_cohort, &profile.read_cohort.admitted_prefix).await?;
        let head = super::storage::closed_for_lookup(&self.state.storage(), &object,
            &reply.original, &reply.closed).await?;
        let validated = object.verifier()?.validate_lease(token.as_bytes(), &profile.read_cohort,
            &object.timing_profile, &head.floor, &lookup.scope.full_key, LeaseEffect::Read, object.clock())?;
        let head = super::storage::retain_read_floor(&self.state.storage(), &reply.original,
            head, validated.next_floor).await?;
        let selected = lookup.clone();
        let current_object = object.clone();
        let current_profile = profile.clone();
        let snapshot = publication.snapshot.clone();
        let fresh: Rc<dyn Fn() -> Result<()>> = Rc::new(move || {
            let now = current_object.clock();
            let latest = now.observed_at.checked_add(now.uncertainty).context("OCI source clock overflow")?;
            selected.validate(&selected.deployment_id, latest)?;
            current_profile.validate_snapshot(&snapshot, latest)?;
            accepted.current(&current_object)?;
            current_object.verifier()?.validate_lease(token.as_bytes(), &current_profile.read_cohort,
                &current_object.timing_profile, &head.floor, &selected.scope.full_key,
                LeaseEffect::Read, now)?;
            Ok(())
        });
        // No part buffer is acquired here: the destination owns the sole 8 MiB
        // buffer. This source retains only one BYOB view and its provider/key.
        let capacity = provider_capacity::acquire_class_checked(1, Class::Bulk, &|| fresh()).await?;
        let owner = Owner::new((gate, capacity));
        let guard_scope = Scope(Rc::clone(&owner));
        fresh()?;
        let credential = publication.credential_text(&StorageCredentialSelector {
            purpose: "read".into(), generation: profile.read_cohort.credential.generation.get(),
        }, &lookup.deployment_id, object.clock().observed_at)?;
        let surface = S3Surface::from_snapshot(&publication.snapshot, &lookup.deployment_id,
            &lookup.writer.placement_prefix, Some(&credential), object.clock().observed_at)?;
        let prefix = aos_hub_core::keymap::r2_key(&lookup.writer.binding_prefix, &lookup.writer.placement_prefix);
        let path = if prefix.is_empty() { lookup.scope.full_key.as_str() } else {
            lookup.scope.full_key.strip_prefix(&format!("{prefix}/")).context("OCI source range escaped writer")?
        };
        let version = match &reply.closed.incarnation {
            OciProviderIncarnation::Versioned { provider_version, .. } => Some(provider_version.as_str()),
            OciProviderIncarnation::Guarded { .. } => None,
        };
        let signed = surface.oci_conditional_read_request(path, false, &reply.closed.etag, version,
            Some((range.start, range.length)), object.clock().observed_at)?;
        aos_hub_core::url_guard::is_safe_remote_url(&signed.url)?;
        let headers = Headers::new();
        for header in signed.required_headers { headers.set(&header.name, &header.value)?; }
        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_redirect(worker::RequestRedirect::Manual).with_headers(headers);
        let (response, reader) = super::transport::fetch_owned(&self.state,
            Request::new_with_init(&signed.url, &init)?, Rc::clone(&owner), Rc::clone(&fresh)).await?;
        ensure!(response.status_code() == 206
            && response.headers().get("content-length")?.as_deref() == Some(range.length.to_string().as_str())
            && response.headers().get("content-range")?.as_deref() == Some(format!("bytes {}-{}/{}",
                range.start, range.start + range.length - 1, lookup.expected.size).as_str())
            && response.headers().get("etag")?.as_deref() == Some(reply.closed.etag.as_str())
            && response.headers().get("content-encoding")?.as_deref().is_none_or(|value| value.eq_ignore_ascii_case("identity")),
            "OCI source provider range identity differs");
        let observed_version = response.headers().get("x-amz-version-id")?;
        ensure!(match version {
            Some(version) => observed_version.as_deref() == Some(version),
            None => observed_version.as_deref().is_none_or(|value| value == "null"),
        }, "OCI source range provider incarnation differs");
        let reader = reader.context("OCI source range body absent")?;
        super::storage::closed_for_lookup(&self.state.storage(), &object, &reply.original, &reply.closed).await?;
        fresh()?;
        let role = super::super::storage::key(&self.env)?;
        let (receipt, signature) = reply.sign(&lookup, &role, latest(&self.env)?)?;
        let state = RangeStream { scope: guard_scope, reader, fresh, counted: 0,
            length: range.length, ended: false };
        let stream = futures_util::stream::try_unfold(state, |mut state| async move {
            if state.ended { return Ok(None); }
            state.scope.0.check_open().map_err(|_| worker::Error::RustError("OCI source closed".into()))?;
            let (view, done) = super::transport::bounded(state.reader.read(), &|| (state.fresh)())
                .await.map_err(|_| worker::Error::RustError("OCI source range read refused".into()))?;
            state.counted = state.counted.checked_add(u64::from(view.length()))
                .ok_or_else(|| worker::Error::RustError("OCI range byte count overflow".into()))?;
            if state.counted > state.length || (done && state.counted != state.length) {
                return Err(worker::Error::RustError("OCI source range length differs".into()));
            }
            state.ended = done;
            if done && view.length() == 0 { return Ok(None); }
            Ok(Some((view.to_vec(), state)))
        });
        let response = super::byte_stream::adapt(Response::from_stream(stream)?)?;
        response.headers().set(OCI_SOURCE_SIGNATURE_HEADER, &signature)?;
        response.headers().set("x-aos-external-oci-source-receipt", &base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD, &receipt))?;
        response.headers().set("content-length", &range.length.to_string())?;
        response.headers().set("cache-control", "private, no-store")?;
        Ok(response)
    }
}

struct RangeStream {
    scope: crate::oci_projection::lifetime::Scope<(
        futures_util::lock::OwnedMutexGuard<()>, crate::direct_upload::provider_capacity::Permit)>,
    reader: std::rc::Rc<crate::direct_digest::Reader>,
    fresh: std::rc::Rc<dyn Fn() -> Result<()>>,
    counted: u64,
    length: u64,
    ended: bool,
}
