//! Gate-held leased reads of genuinely immutable installed provider versions.
//!
//! Lookup has no closure effect. A range advances only the existing Read floor
//! under CAS, consumes one real transferred slot, and retains the exact source
//! gate and native abort/reader owners through EOF, error or cancellation.

use super::super::super::{
    config::Config,
    copy::{
        config::Domain,
        lifetime::{Lifetime, Registration},
        source_protocol::{self, Operation},
        stream::Reader,
    },
    protocol::{GUARD_HEADER, MAX_MESSAGE},
    state::Head,
    storage::{self, ExternalObjectGuard, HEAD},
};
use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    s3surface::{Method as S3Method, S3Surface},
    storage_authority::{external_object::copy::CopySourceObject, lease::LeaseEffect},
    storage_work::StorageCredentialSelector,
};
use base64::Engine as _;
use std::rc::Rc;
use worker::{Fetch, Headers, ListOptions, Method, Request, RequestInit, Response, ResponseBody};

pub(in crate::external_object) async fn fetch(
    guard: &ExternalObjectGuard,
    incoming: &Request,
    message: &source_protocol::Request,
    object: &Config,
    domain: &Domain,
    gate: futures_util::lock::OwnedMutexGuard<()>,
) -> Result<Response> {
    ensure!(
        domain.provider_contract.protected_versionless.is_none()
            && domain.provider_contract.versioned_conditional_range_read,
        "versioned source provider mode is not installed"
    );
    let (lease, effect) = match &message.operation {
        Operation::InspectVersionedLookup { read_lease } => {
            (read_lease.as_str(), LeaseEffect::Head)
        }
        Operation::InspectVersionedRange { read_lease, .. } => {
            (read_lease.as_str(), LeaseEffect::Read)
        }
        _ => anyhow::bail!("not a versioned typed source request"),
    };
    let selection = message
        .inspection
        .as_ref()
        .context("versioned selection absent")?;
    let store = guard.state.storage();
    crate::direct_guard::deny_legacy(&store).await?;
    let prior = storage::load_head(&store).await?;
    let head = match &prior {
        Some(head) => {
            head.validate(object, &message.scope)?;
            head.clone()
        }
        None => {
            ensure!(
                store
                    .list_with_options(ListOptions::new().limit(1))
                    .await?
                    .size()
                    == 0,
                "versioned inspection source has orphaned retained state"
            );
            Head::initialize_floor(object, &message.scope, &domain.read_cohort, object.clock())?
        }
    };
    super::require_idle(&head)?;
    let publication = crate::hybrid_binding::resolve_for_plan(&guard.env, &message.plan).await?;
    let deployment = guard.env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let read_floor = object
        .verifier()?
        .validate_lease(
            lease.as_bytes(),
            &domain.read_cohort,
            &object.timing_profile,
            &head.floor,
            &message.scope.full_key,
            effect,
            object.clock(),
        )?
        .next_floor;
    let check = || -> Result<()> {
        let clock = object.clock();
        message.current(
            clock
                .observed_at
                .checked_add(clock.uncertainty)
                .context("source clock overflow")?,
        )?;
        publication
            .snapshot
            .authorizes(&message.plan, &deployment, clock.observed_at)?;
        ensure!(
            super::super::super::executor::select_cohort(
                object,
                &publication,
                "read",
                domain.read_cohort.association.binding_write_revision.get()
            )? == &domain.read_cohort,
            "versioned source current Read publication differs"
        );
        object.verifier()?.validate_lease(
            lease.as_bytes(),
            &domain.read_cohort,
            &object.timing_profile,
            &read_floor,
            &message.scope.full_key,
            effect,
            clock,
        )?;
        Ok(())
    };
    check()?;
    // Only an actual range persists a read floor. Discovery cannot manufacture
    // positive source custody or a durable absent-object record.
    if effect == LeaseEffect::Read {
        let mut advanced = head.clone();
        advanced.floor = read_floor.clone();
        let encoded = serde_json::to_string(&advanced)?;
        let expected = prior.clone();
        store
            .transaction(move |transaction| {
                let encoded = encoded.clone();
                let expected = expected.clone();
                async move {
                    let current: Option<Head> = storage::decode(
                        storage::transaction_string(&transaction, HEAD).await?,
                        MAX_MESSAGE,
                    )
                    .map_err(storage::error)?;
                    if current != expected {
                        return Err(storage::error("versioned Read floor CAS refused"));
                    }
                    transaction.put(HEAD, encoded).await
                }
            })
            .await?;
    }
    let lifetime = Rc::new(Lifetime::new(incoming.inner().signal())?);
    lifetime.retain_source_gate(gate)?;
    crate::direct_upload::provider_capacity::policy::configure_bounded(
        &guard.env,
        u32::from(domain.provider_concurrency),
        3,
    )?;
    let transferred = if effect == LeaseEffect::Read {
        let ticket = message
            .capacity_transfer
            .as_ref()
            .context("versioned source ticket absent")?;
        crate::direct_upload::provider_capacity::transfer::accept(
            ticket,
            &message.capacity_digest()?,
        )?
    } else {
        None
    };
    let cancellation = transferred
        .as_ref()
        .map(|source| source.cancellation.clone());
    let fresh = || -> Result<()> {
        lifetime.check()?;
        if let Some(origin) = &cancellation {
            origin.check()?;
        }
        check()
    };
    fresh()?;
    let permit = match transferred {
        Some(source) => source.permit,
        None => {
            crate::direct_upload::provider_capacity::acquire_class_checked(
                1,
                if effect == LeaseEffect::Head {
                    crate::direct_upload::provider_capacity::Class::Metadata
                } else {
                    crate::direct_upload::provider_capacity::Class::Bulk
                },
                &fresh,
            )
            .await?
        }
    };
    lifetime.retain_capacity(permit)?;
    fresh()?;
    let credential = publication.credential_text(
        &StorageCredentialSelector {
            purpose: "read".into(),
            generation: domain.read_cohort.credential.generation.get(),
        },
        &deployment,
        object.clock().observed_at,
    )?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        &message.plan.placement_prefix,
        Some(&credential),
        object.clock().observed_at,
    )?;
    let headers = Headers::new();
    let (url, method) = match &message.operation {
        Operation::InspectVersionedLookup { .. } => (
            surface.object_url(S3Method::Head, &selection.path, object.clock().observed_at)?,
            Method::Head,
        ),
        Operation::InspectVersionedRange {
            source,
            offset,
            bytes,
            ..
        } => {
            let maximum = domain
                .provider_contract
                .maximum_copy_read_range_bytes
                .context("versioned accepted Read range bound absent")?
                .get() as u64;
            ensure!(
                *bytes <= maximum,
                "versioned range exceeds accepted Read bound"
            );
            let source_object = CopySourceObject {
                provider_version: source.provider_version.clone(),
                etag: source.etag.clone(),
                bytes: aos_hub_core::storage_authority::lease::LeaseInteger::new(i64::try_from(
                    source.size,
                )?)?,
                guard_stamp: None,
            };
            let signed = if source.size == 0 {
                surface.oci_conditional_read_request(
                    &selection.path,
                    false,
                    &source.etag,
                    source.provider_version.as_deref(),
                    None,
                    object.clock().observed_at,
                )?
            } else {
                surface.versioned_conditional_range_request(
                    &selection.path,
                    &source_object,
                    *offset,
                    *bytes,
                    object.clock().observed_at,
                    30,
                )?
            };
            for header in signed.required_headers {
                headers.set(&header.name, &header.value)?;
            }
            (signed.url, Method::Get)
        }
        _ => anyhow::bail!("versioned request mode differs"),
    };
    let controller = worker::web_sys::AbortController::new()
        .map_err(|_| anyhow::anyhow!("source abort unavailable"))?;
    let abort = AbortOnDrop(controller.clone());
    let registration = lifetime.register(controller.clone().into(), "abort")?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_redirect(worker::RequestRedirect::Manual);
    let response = super::super::super::copy::source::bounded(
        async {
            fresh()?;
            crate::direct_upload::provider_capacity::record_dispatch();
            Ok(Fetch::Request(Request::new_with_init(&url, &init)?)
                .send_with_signal(&worker::AbortSignal::from(controller.signal()))
                .await?)
        },
        &fresh,
    )
    .await?;
    // Every refusal after Fetch owns cancellation before the source gate/slot
    // can be released, even when the response is rejected before Reader::new.
    let mut unhanded = match response.body() {
        ResponseBody::Stream(body) => Some(
            super::super::super::oci::byte_stream::UnhandedStream::new(body.clone().into()),
        ),
        _ => None,
    };
    fresh()?;
    let h = response.headers();
    if effect == LeaseEffect::Head {
        let source = super::head_identity(
            message,
            response.status_code(),
            h.get("content-length")?.as_deref(),
            h.get("etag")?.as_deref(),
            h.get("x-amz-version-id")?.as_deref(),
            h.get("content-encoding")?.as_deref(),
        )?;
        let current = crate::hybrid_binding::resolve_for_plan(&guard.env, &message.plan).await?;
        ensure!(
            current.snapshot == publication.snapshot && storage::load_head(&store).await? == prior,
            "versioned source or publication changed during HEAD"
        );
        if prior.is_none() {
            ensure!(
                store
                    .list_with_options(ListOptions::new().limit(1))
                    .await?
                    .size()
                    == 0,
                "versioned inspection source gained orphaned retained state"
            );
        }
        fresh()?;
        let (body, signature) =
            source_protocol::sign_versioned_source(&storage::key(&guard.env)?, message, source)?;
        let headers = Headers::new();
        headers.set(GUARD_HEADER, &signature)?;
        headers.set("cache-control", "private, no-store")?;
        return Ok(Response::from_bytes(body)?.with_headers(headers));
    }
    let Operation::InspectVersionedRange {
        source,
        offset,
        bytes,
        ..
    } = &message.operation
    else {
        anyhow::bail!("versioned range mode differs");
    };
    super::validate_range(
        source,
        *offset,
        *bytes,
        response.status_code(),
        h.get("content-length")?.as_deref(),
        h.get("etag")?.as_deref(),
        h.get("x-amz-version-id")?.as_deref(),
        h.get("content-range")?.as_deref(),
        h.get("content-encoding")?.as_deref(),
    )?;
    let ResponseBody::Stream(body) = response.body() else {
        anyhow::bail!("versioned body absent");
    };
    let reader = Reader::new(body.clone().into(), &lifetime)?;
    if let Some(owner) = &mut unhanded {
        owner.disarm();
    }
    let (receipt, signature) = source_protocol::sign_versioned_source(
        &storage::key(&guard.env)?,
        message,
        Some(source.clone()),
    )?;
    let bytes = *bytes;
    let offset = *offset;
    let total = source.size;
    let etag = source.etag.clone();
    let version = source
        .provider_version
        .clone()
        .context("source version absent")?;
    let object = object.clone();
    let message = message.clone();
    let cohort = domain.read_cohort.clone();
    let floor = read_floor;
    let lease = lease.to_owned();
    let snapshot = publication.snapshot.clone();
    let observed = Rc::clone(&lifetime);
    let stream_fresh: Rc<dyn Fn() -> Result<()>> = Rc::new(move || {
        observed.check()?;
        if let Some(origin) = &cancellation {
            origin.check()?;
        }
        let clock = object.clock();
        message.current(
            clock
                .observed_at
                .checked_add(clock.uncertainty)
                .context("source clock overflow")?,
        )?;
        snapshot.authorizes(&message.plan, &deployment, clock.observed_at)?;
        object.verifier()?.validate_lease(
            lease.as_bytes(),
            &cohort,
            &object.timing_profile,
            &floor,
            &message.scope.full_key,
            LeaseEffect::Read,
            clock,
        )?;
        Ok(())
    });
    // The response header authenticates selection, not body success. The caller
    // counts through real EOF and records the independently computed digest.
    let stream = futures_util::stream::try_unfold(
        RangeState {
            lifetime,
            reader,
            fresh: stream_fresh,
            registration,
            abort,
            bytes,
            counted: 0,
            ended: false,
        },
        |mut state| async move {
            if state.ended {
                return Ok(None);
            }
            let (view, done) =
                super::super::super::copy::source::bounded(state.reader.read(), &|| {
                    (state.fresh)()
                })
                .await
                .map_err(|_| worker::Error::RustError("versioned source read refused".into()))?;
            state.counted = state
                .counted
                .checked_add(u64::from(view.length()))
                .ok_or_else(|| worker::Error::RustError("source count overflow".into()))?;
            if state.counted > state.bytes || done && state.counted != state.bytes {
                return Err(worker::Error::RustError(
                    "versioned source length differs".into(),
                ));
            }
            state.ended = done;
            if done && view.length() == 0 {
                return Ok(None);
            }
            Ok(Some((view.to_vec(), state)))
        },
    );
    let mut response = super::super::super::oci::byte_stream::adapt(
        Response::from_stream(stream)?.with_status(if total == 0 { 200 } else { 206 }),
    )?;
    response.headers_mut().set(GUARD_HEADER, &signature)?;
    response.headers_mut().set(
        source_protocol::RECEIPT_HEADER,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(receipt),
    )?;
    response.headers_mut().set("etag", &etag)?;
    response.headers_mut().set("x-amz-version-id", &version)?;
    response
        .headers_mut()
        .set("content-length", &bytes.to_string())?;
    if total > 0 {
        response.headers_mut().set(
            "content-range",
            &format!("bytes {}-{}/{}", offset, offset + bytes - 1, total),
        )?;
    }
    response
        .headers_mut()
        .set("cache-control", "private, no-store")?;
    Ok(response)
}

struct AbortOnDrop(worker::web_sys::AbortController);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct RangeState {
    lifetime: Rc<Lifetime>,
    reader: Reader,
    fresh: Rc<dyn Fn() -> Result<()>>,
    registration: Registration,
    abort: AbortOnDrop,
    bytes: u64,
    counted: u64,
    ended: bool,
}

impl Drop for RangeState {
    fn drop(&mut self) {
        self.abort.0.abort();
        let _ = (&self.lifetime, &self.registration);
    }
}
