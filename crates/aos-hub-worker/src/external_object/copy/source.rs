//! Guard-held reads of a previously closed versionless physical source.
//!
//! Lookup projects permanent receipt metadata. Only a separately leased range
//! touches the provider; its exact source gate stays held through EOF/cancel.
//! The receipt header is a pre-read closure, never a declaration of stream EOF.

use super::super::{
    config::configured,
    protocol::{GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER},
    state::Head,
    storage::{self, ExternalObjectGuard, BINDING, HEAD},
};
use super::{
    config,
    lifetime::{Lifetime, Registration},
    source_protocol::{self, Operation},
    stream::Reader,
};
use anyhow::{ensure, Result};
use aos_hub_core::{
    s3surface::S3Surface,
    storage_authority::{
        external_object::copy::{original_lookup::CopyOriginalSelector, source::CopySourceClosure},
        lease::{LeaseEffect, LeaseInteger},
    },
    storage_work::{StorageCredentialSelector, StorageWorkOperation, StorageWorkPlan},
};
use base64::Engine as _;
use futures_util::future::{select, Either};
use std::{rc::Rc, time::Duration};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, Response, ResponseBody};

/// Constructs a private selector using the actual authenticated application plan.
///
/// # Errors
/// Refuses malformed plans, original pins or unavailable correlation randomness.
pub(super) fn request(
    plan: &StorageWorkPlan,
    profile_digest: String,
    scope: aos_hub_core::storage_authority::control::StorageAuthorityObjectScope,
    selector: Option<CopyOriginalSelector>,
    operation: Operation,
) -> Result<source_protocol::Request> {
    use rand::TryRngCore as _;
    let mut nonce = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| anyhow::anyhow!("protected source correlation unavailable"))?;
    let value = source_protocol::Request {
        domain: source_protocol::DOMAIN.into(),
        nonce: hex::encode(nonce),
        profile_digest,
        expires_at: LeaseInteger::new(plan.expires_at)?,
        scope,
        selector,
        plan: plan.clone(),
        capacity_transfer: None,
        operation,
    };
    value.validate()?;
    Ok(value)
}

/// Hands off a real reserved GET slot without reacquiring it in the source guard.
///
/// # Errors
/// Refuses original cutoff/cancellation, mismatched request or unavailable capacity.
pub(super) async fn reserve(
    message: &mut source_protocol::Request,
    initial: Option<crate::direct_upload::provider_capacity::Permit>,
    window: &super::window::DispatchWindow<'_>,
) -> Result<crate::direct_upload::provider_capacity::transfer::Reservation> {
    use crate::direct_upload::provider_capacity::{self, transfer, Class};
    window.check()?;
    let permit = match initial {
        Some(permit) => permit,
        None => {
            provider_capacity::acquire_class_checked(1, Class::Bulk, &|| window.check()).await?
        }
    };
    let reservation = transfer::register(permit, message.capacity_digest()?)?;
    message.capacity_transfer = Some(reservation.ticket());
    message.validate()?;
    window
        .lifetime
        .retain_transfer(reservation.cancellation())?;
    Ok(reservation)
}

/// Reads authenticated closure metadata without a provider or mutation effect.
///
/// # Errors
/// Refuses missing/changed permanent provenance or a corrupt/mismatched reply.
pub(super) async fn lookup(
    env: &Env,
    message: &source_protocol::Request,
) -> Result<CopySourceClosure> {
    let response = call(env, message, None).await?;
    let signature = response
        .headers()
        .get(GUARD_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("protected source signature absent"))?;
    let body = crate::direct_digest::read_bounded_native(response, MAX_MESSAGE).await?;
    source_protocol::verify_reply(&storage::key(env)?, message, &signature, &body)
}

/// Opens one exact range and verifies its retained closure before handing off bytes.
///
/// # Errors
/// Refuses a changed source guard, current lease/cutoff or unauthenticated reply.
pub(super) async fn range(
    env: &Env,
    message: &source_protocol::Request,
    signal: &worker::web_sys::AbortSignal,
) -> Result<Response> {
    let response = call(env, message, Some(signal)).await?;
    // A rejected closure header must cancel the already-open source stream;
    // dropping a JS response handle alone is not a guard-release acknowledgement.
    let mut unhanded = match response.body() {
        ResponseBody::Stream(body) => Some(super::super::oci::byte_stream::UnhandedStream::new(
            body.clone().into(),
        )),
        _ => None,
    };
    let signature = response
        .headers()
        .get(GUARD_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("protected source signature absent"))?;
    let encoded = response
        .headers()
        .get(source_protocol::RECEIPT_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("protected source receipt absent"))?;
    ensure!(
        encoded.len() <= MAX_MESSAGE * 2,
        "protected source receipt oversized"
    );
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?;
    source_protocol::verify_reply(&storage::key(env)?, message, &signature, &body)?;
    if let Some(owner) = &mut unhanded {
        owner.disarm();
    }
    Ok(response)
}

async fn call(
    env: &Env,
    message: &source_protocol::Request,
    signal: Option<&worker::web_sys::AbortSignal>,
) -> Result<Response> {
    message.validate()?;
    let body = serde_json::to_vec(message)?;
    let key = storage::key(env)?;
    let name = message.scope.guard_name()?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &key.sign_body(&body)?)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let native: worker::web_sys::RequestInit = (&init).into();
    native.set_signal(signal);
    let request = worker::web_sys::Request::new_with_str_and_init(
        &format!("https://external-object{}", source_protocol::PATH),
        &native,
    )
    .map_err(|_| anyhow::anyhow!("protected source request unavailable"))?;
    let response = env
        .durable_object(BINDING)?
        .id_from_name(&name)?
        .get_stub()?
        .fetch_with_request(request.into())
        .await?;
    ensure!(
        response.status_code() == 200 || response.status_code() == 206,
        "protected source refused"
    );
    Ok(response)
}

impl ExternalObjectGuard {
    /// Handles a bounded read under exact current key ownership without minting a source.
    ///
    /// # Errors
    /// Refuses unprotected discoveries, changed producer receipts, unknown owners or stale leases.
    pub(crate) async fn copy_source_fetch(
        &self,
        request: &mut Request,
    ) -> worker::Result<Response> {
        let result = async {
            ensure!(
                request.method() == Method::Post,
                "protected source requires POST"
            );
            let body = crate::hybrid::read_bounded_body(request, MAX_MESSAGE)
                .await?
                .ok_or_else(|| anyhow::anyhow!("protected source oversized"))?;
            let signature = request
                .headers()
                .get(GUARD_HEADER)?
                .ok_or_else(|| anyhow::anyhow!("protected source authentication absent"))?;
            let key = storage::key(&self.env)?;
            let message = source_protocol::authenticate(&key, &signature, &body)?;
            let object = configured(&self.env)?
                .ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
            let config = config::configured(&self.env, &object)?
                .ok_or_else(|| anyhow::anyhow!("copy consumer disabled"))?;
            let domain = config
                .domains
                .iter()
                .find(|domain| {
                    domain
                        .commitment()
                        .is_ok_and(|digest| digest == message.profile_digest)
                })
                .ok_or_else(|| anyhow::anyhow!("protected source profile absent"))?;
            ensure!(
                domain.provider_contract.protected_versionless.is_some(),
                "protected source provider contract absent"
            );
            let deployment = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
            message
                .plan
                .validate(&deployment, object.clock().observed_at)?;
            message.current(object.clock().observed_at)?;
            let (prefix, path) = source_path(&message)?;
            let selected_scope = if let Some(selector) = &message.selector {
                domain.selector_scope_for(&object, selector, false)?
            } else {
                object.scope(
                    &domain.read_cohort,
                    aos_hub_core::keymap::r2_key(
                        &domain.read_cohort.association.binding_prefix,
                        &aos_hub_core::keymap::r2_key(&prefix, &path),
                    ),
                )?
            };
            ensure!(
                selected_scope == message.scope
                    && message.plan.binding_id == domain.read_cohort.association.binding_id.get()
                    && message.plan.binding_resource_version
                        == domain
                            .read_cohort
                            .association
                            .binding_resource_version
                            .get(),
                "protected source current physical binding differs"
            );
            let name = message.scope.guard_name()?;
            ensure!(
                request.headers().get(SCOPE_HEADER)?.as_deref() == Some(&name)
                    && self
                        .env
                        .durable_object(BINDING)?
                        .id_from_name(&name)?
                        .to_string()
                        == self.state.id().to_string(),
                "protected source addressed another guard"
            );
            let gate = loop {
                message.current(object.clock().observed_at)?;
                if let Some(gate) = self.gate.try_lock_owned() {
                    break gate;
                }
                worker::Delay::from(Duration::from_millis(50)).await;
            };
            crate::direct_guard::deny_legacy(&self.state.storage()).await?;
            let mut head = storage::load_head(&self.state.storage())
                .await?
                .ok_or_else(|| anyhow::anyhow!("protected source has no permanent head"))?;
            head.validate(&object, &message.scope)?;
            let closure =
                super::closure::current(&self.env, &self.state.storage(), &head, &object).await?;
            // Metadata authentication checks the exact retained original before any provider work.
            let (receipt, signature) =
                source_protocol::sign_reply(&key, &message, closure.clone())?;
            let range = match &message.operation {
                Operation::Lookup | Operation::Check { .. } => None,
                Operation::Range {
                    read_lease,
                    offset,
                    bytes,
                    ..
                }
                | Operation::InspectRange {
                    read_lease,
                    offset,
                    bytes,
                    ..
                } => Some((read_lease.clone(), *offset, *bytes)),
            };
            let Some((token, offset, bytes)) = range else {
                message.current(object.clock().observed_at)?;
                let headers = Headers::new();
                headers.set(GUARD_HEADER, &signature)?;
                headers.set("cache-control", "private, no-store")?;
                return Ok(Response::from_bytes(receipt)?.with_headers(headers));
            };
            let publication =
                crate::hybrid_binding::resolve_for_plan(&self.env, &message.plan).await?;
            publication.snapshot.authorizes(
                &message.plan,
                &deployment,
                object.clock().observed_at,
            )?;
            ensure!(
                publication.snapshot.binding_stable_id
                    == domain.read_cohort.association.binding_stable_id
                    && publication.snapshot.object_prefix
                        == domain.read_cohort.association.binding_prefix
                    && super::super::executor::select_cohort(
                        &object,
                        &publication,
                        "read",
                        domain.read_cohort.association.binding_write_revision.get()
                    )? == &domain.read_cohort,
                "protected source current read cohort differs"
            );
            let prior = head.clone();
            head.floor = object
                .verifier()?
                .validate_lease(
                    token.as_bytes(),
                    &domain.read_cohort,
                    &object.timing_profile,
                    &head.floor,
                    &head.scope.full_key,
                    LeaseEffect::Read,
                    object.clock(),
                )?
                .next_floor;
            let encoded = serde_json::to_string(&head)?;
            self.state
                .storage()
                .transaction(move |transaction| {
                    let prior = prior.clone();
                    let encoded = encoded.clone();
                    async move {
                        let current: Option<Head> = storage::decode(
                            storage::transaction_string(&transaction, HEAD).await?,
                            MAX_MESSAGE,
                        )
                        .map_err(storage::error)?;
                        if current.as_ref() != Some(&prior) {
                            return Err(storage::error("protected source floor CAS refused"));
                        }
                        transaction.put(HEAD, encoded).await
                    }
                })
                .await?;
            let lifetime = Rc::new(Lifetime::new(request.inner().signal())?);
            lifetime.retain_source_gate(gate)?;
            // The application reserves GET+PUT atomically. Consume its real
            // GET slot only after exact MAC, source, closure and lease checks.
            crate::direct_upload::provider_capacity::configure(u32::from(
                domain.provider_concurrency,
            ))?;
            message.current(
                object
                    .clock()
                    .observed_at
                    .checked_add(object.clock().uncertainty)
                    .ok_or_else(|| anyhow::anyhow!("protected source clock overflow"))?,
            )?;
            let transferred = match &message.operation {
                Operation::Range { .. } => {
                    let ticket = message
                        .capacity_transfer
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("protected copy source capacity absent"))?;
                    crate::direct_upload::provider_capacity::transfer::accept(
                        ticket,
                        &message.capacity_digest()?,
                    )?
                }
                _ => None,
            };
            let origin_cancellation = transferred
                .as_ref()
                .map(|source| source.cancellation.clone());
            let lifetime_check = Rc::clone(&lifetime);
            let read_cohort = domain.read_cohort.clone();
            let current_object = object.clone();
            let current_message = message.clone();
            let snapshot = publication.snapshot.clone();
            let fresh: Rc<dyn Fn() -> Result<()>> = Rc::new(move || {
                lifetime_check.check()?;
                if let Some(origin) = &origin_cancellation {
                    origin.check()?;
                }
                let clock = current_object.clock();
                let latest = clock
                    .observed_at
                    .checked_add(clock.uncertainty)
                    .ok_or_else(|| anyhow::anyhow!("protected source clock overflow"))?;
                current_message.current(latest)?;
                snapshot.authorizes(&current_message.plan, &deployment, clock.observed_at)?;
                current_object.verifier()?.validate_lease(
                    token.as_bytes(),
                    &read_cohort,
                    &current_object.timing_profile,
                    &head.floor,
                    &current_message.scope.full_key,
                    LeaseEffect::Read,
                    clock,
                )?;
                Ok(())
            });
            fresh()?;
            let permit = match transferred {
                Some(source) => source.permit,
                None => {
                    crate::direct_upload::provider_capacity::acquire_class_checked(
                        1,
                        crate::direct_upload::provider_capacity::Class::Bulk,
                        &|| fresh(),
                    )
                    .await?
                }
            };
            lifetime.retain_capacity(permit)?;
            let credential = publication.credential_text(
                &StorageCredentialSelector {
                    purpose: "read".into(),
                    generation: domain.read_cohort.credential.generation.get(),
                },
                &message.plan.deployment_id,
                object.clock().observed_at,
            )?;
            let surface = S3Surface::from_snapshot(
                &publication.snapshot,
                &message.plan.deployment_id,
                &prefix,
                Some(&credential),
                object.clock().observed_at,
            )?;
            let etag = match &message.operation {
                Operation::Range { original, .. } => original.source_object.etag.clone(),
                Operation::InspectRange { etag, .. } => etag.clone(),
                _ => anyhow::bail!("protected range absent"),
            };
            let signed = surface.oci_conditional_read_request(
                &path,
                false,
                &etag,
                None,
                Some((offset, bytes)),
                object.clock().observed_at,
            )?;
            let headers = Headers::new();
            for header in signed.required_headers {
                headers.set(&header.name, &header.value)?;
            }
            let mut init = RequestInit::new();
            init.with_method(Method::Get)
                .with_headers(headers)
                .with_redirect(worker::RequestRedirect::Manual);
            let controller = worker::web_sys::AbortController::new()
                .map_err(|_| anyhow::anyhow!("protected read cancellation unavailable"))?;
            let registration = lifetime.register(controller.clone().into(), "abort")?;
            let response = bounded(
                async {
                    fresh()?;
                    crate::direct_upload::provider_capacity::record_dispatch();
                    Ok(Fetch::Request(Request::new_with_init(&signed.url, &init)?)
                        .send_with_signal(&worker::AbortSignal::from(controller.signal()))
                        .await?)
                },
                &|| fresh(),
            )
            .await?;
            let end = offset
                .checked_add(bytes)
                .ok_or_else(|| anyhow::anyhow!("source range overflow"))?;
            ensure!(
                response.status_code() == 206
                    && response.headers().get("etag")?.as_deref() == Some(&etag)
                    && response
                        .headers()
                        .get("x-amz-version-id")?
                        .as_deref()
                        .is_none_or(|value| value == "null")
                    && response.headers().get("content-length")?.as_deref()
                        == Some(bytes.to_string().as_str())
                    && response.headers().get("content-range")?.as_deref()
                        == Some(
                            format!("bytes {}-{}/{}", offset, end - 1, closure.bytes.get())
                                .as_str()
                        )
                    && response
                        .headers()
                        .get("content-encoding")?
                        .as_deref()
                        .is_none_or(|value| value.eq_ignore_ascii_case("identity")),
                "protected conditional range identity differs"
            );
            let (_, body) = response.into_parts();
            let ResponseBody::Stream(body) = body else {
                anyhow::bail!("protected source stream absent");
            };
            let reader = Reader::new(body.into(), &lifetime)?;
            let stream = futures_util::stream::try_unfold(
                RangeState {
                    lifetime,
                    reader,
                    fresh,
                    registration,
                    controller,
                    counted: 0,
                    bytes,
                    ended: false,
                },
                |mut state| async move {
                    if state.ended {
                        return Ok(None);
                    }
                    let (view, done) = bounded(state.reader.read(), &|| (state.fresh)())
                        .await
                        .map_err(|_| {
                            worker::Error::RustError("protected source read refused".into())
                        })?;
                    state.counted = state
                        .counted
                        .checked_add(u64::from(view.length()))
                        .ok_or_else(|| {
                            worker::Error::RustError("protected source count overflow".into())
                        })?;
                    if state.counted > state.bytes || done && state.counted != state.bytes {
                        return Err(worker::Error::RustError(
                            "protected source length differs".into(),
                        ));
                    }
                    state.ended = done;
                    if done && view.length() == 0 {
                        return Ok(None);
                    }
                    Ok(Some((view.to_vec(), state)))
                },
            );
            let response = super::super::oci::byte_stream::adapt(
                Response::from_stream(stream)?.with_status(206),
            )?;
            response.headers().set(GUARD_HEADER, &signature)?;
            response.headers().set(
                source_protocol::RECEIPT_HEADER,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(receipt),
            )?;
            response.headers().set("etag", &etag)?;
            response
                .headers()
                .set("content-length", &bytes.to_string())?;
            response.headers().set(
                "content-range",
                &format!("bytes {}-{}/{}", offset, end - 1, closure.bytes.get()),
            )?;
            response
                .headers()
                .set("cache-control", "private, no-store")?;
            Ok::<_, anyhow::Error>(response)
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(_) => Response::error("protected source refused", 409),
        }
    }
}

fn source_path(message: &source_protocol::Request) -> Result<(String, String)> {
    if let Some(selector) = &message.selector {
        Ok((selector.source.prefix.clone(), selector.path.clone()))
    } else {
        match &message.plan.operation {
            StorageWorkOperation::InspectSha256 { path, .. }
            | StorageWorkOperation::HashOciRange { path, .. } => {
                Ok((message.plan.placement_prefix.clone(), path.clone()))
            }
            _ => anyhow::bail!("protected source plan lacks a read path"),
        }
    }
}

struct RangeState {
    lifetime: Rc<Lifetime>,
    reader: Reader,
    fresh: Rc<dyn Fn() -> Result<()>>,
    registration: Registration,
    controller: worker::web_sys::AbortController,
    counted: u64,
    bytes: u64,
    ended: bool,
}

impl Drop for RangeState {
    fn drop(&mut self) {
        // Abort the actual request before releasing its source gate, including
        // when a downstream consumer drops without polling Rust again.
        self.controller.abort();
        let _ = (&self.lifetime, &self.registration);
    }
}

async fn bounded<T>(
    work: impl std::future::Future<Output = Result<T>>,
    fresh: &dyn Fn() -> Result<()>,
) -> Result<T> {
    fresh()?;
    let stop = async {
        loop {
            worker::Delay::from(Duration::from_millis(50)).await;
            fresh()?;
        }
    };
    futures_util::pin_mut!(work, stop);
    match select(work, stop).await {
        Either::Left((result, _)) => {
            fresh()?;
            result
        }
        Either::Right((result, _)) => result,
    }
}
