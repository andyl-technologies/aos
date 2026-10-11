//! Leased source discovery without changing a permanent physical-key floor.
//!
//! Only a clean, gate-held provider 404 yields transient absence. An existing
//! object without a positive producer receipt remains unreadable. The reply is
//! not a durable tombstone, and no HEAD/receipt/fence is written here.

use std::rc::Rc;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    s3surface::{Method as S3Method, S3Surface},
    storage_authority::lease::LeaseEffect,
    storage_work::StorageCredentialSelector,
};
use worker::{Fetch, Headers, ListOptions, Method, Request, RequestInit, Response};

use super::super::{
    config::Config,
    copy::{
        config::Domain,
        lifetime::Lifetime,
        source_protocol::{self, Operation},
    },
    protocol::GUARD_HEADER,
    state::Head,
    storage::{self, ExternalObjectGuard},
};

pub(in crate::external_object) async fn fetch(
    guard: &ExternalObjectGuard,
    incoming: &Request,
    message: &source_protocol::Request,
    object: &Config,
    domain: &Domain,
    gate: futures_util::lock::OwnedMutexGuard<()>,
) -> Result<Response> {
    let Operation::InspectLookup { read_lease } = &message.operation else {
        anyhow::bail!("not a typed inspection lookup");
    };
    let selected = message.inspection.as_ref().context("typed source absent")?;
    let store = guard.state.storage();
    crate::direct_guard::deny_legacy(&store).await?;
    let prior = storage::load_head(&store).await?;
    let head = match &prior {
        Some(head) => {
            head.validate(object, &message.scope)?;
            require_idle(head)?;
            head.clone()
        }
        None => {
            ensure!(
                store
                    .list_with_options(ListOptions::new().limit(1))
                    .await?
                    .size()
                    == 0,
                "inspection source has orphaned retained state"
            );
            Head::initialize_floor(object, &message.scope, &domain.read_cohort, object.clock())?
        }
    };
    let closure = if head.visible_receipt.is_some() {
        Some(super::super::copy::closure::current(&guard.env, &store, &head, object).await?)
    } else {
        None
    };
    let deployment = guard.env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let publication = crate::hybrid_binding::resolve_for_plan(&guard.env, &message.plan).await?;
    let check = || -> Result<()> {
        let clock = object.clock();
        message.current(
            clock
                .observed_at
                .checked_add(clock.uncertainty)
                .context("inspection clock overflow")?,
        )?;
        publication
            .snapshot
            .authorizes(&message.plan, &deployment, clock.observed_at)?;
        ensure!(
            super::super::executor::select_cohort(
                object,
                &publication,
                "read",
                domain.read_cohort.association.binding_write_revision.get()
            )? == &domain.read_cohort,
            "inspection current read publication differs"
        );
        object.verifier()?.validate_lease(
            read_lease.as_bytes(),
            &domain.read_cohort,
            &object.timing_profile,
            &head.floor,
            &message.scope.full_key,
            LeaseEffect::Read,
            clock,
        )?;
        Ok(())
    };
    check()?;
    let lifetime = Rc::new(Lifetime::new(incoming.inner().signal())?);
    lifetime.retain_source_gate(gate)?;
    crate::direct_upload::provider_capacity::policy::configure_bounded(
        &guard.env,
        u32::from(domain.provider_concurrency),
        3,
    )?;
    let permit = crate::direct_upload::provider_capacity::acquire_class_checked(
        1,
        crate::direct_upload::provider_capacity::Class::Metadata,
        &|| {
            lifetime.check()?;
            check()
        },
    )
    .await?;
    lifetime.retain_capacity(permit)?;
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
    let url = surface.object_url(S3Method::Head, &selected.path, object.clock().observed_at)?;
    let controller = worker::web_sys::AbortController::new()
        .map_err(|_| anyhow::anyhow!("inspection HEAD cancellation unavailable"))?;
    let _registration = lifetime.register(controller.clone().into(), "abort")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Head)
        .with_redirect(worker::RequestRedirect::Manual);
    let response = super::super::copy::source::bounded(
        async {
            lifetime.check()?;
            check()?;
            crate::direct_upload::provider_capacity::record_dispatch();
            Ok(Fetch::Request(Request::new_with_init(&url, &init)?)
                .send_with_signal(&worker::AbortSignal::from(controller.signal()))
                .await?)
        },
        &|| {
            lifetime.check()?;
            check()
        },
    )
    .await?;
    check()?;
    let current = crate::hybrid_binding::resolve_for_plan(&guard.env, &message.plan).await?;
    ensure!(
        current.snapshot == publication.snapshot && storage::load_head(&store).await? == prior,
        "inspection source or publication changed during HEAD"
    );
    if prior.is_none() {
        ensure!(
            store
                .list_with_options(ListOptions::new().limit(1))
                .await?
                .size()
                == 0,
            "inspection source gained orphaned state"
        );
    }
    let etag = match response.status_code() {
        404 => {
            ensure!(closure.is_none(), "closed source disappeared");
            None
        }
        200 => {
            let closed = closure
                .as_ref()
                .context("existing source is not positively closed")?;
            let size: u64 = response
                .headers()
                .get("content-length")?
                .context("inspection HEAD size absent")?
                .parse()?;
            let etag = aos_hub_core::surface_write::strong_if_match_etag(
                &response
                    .headers()
                    .get("etag")?
                    .context("inspection HEAD tag absent")?,
            )?;
            ensure!(
                size == closed.bytes.get() as u64
                    && size <= selected.maximum_bytes
                    && closed.etag.as_ref().is_none_or(|value| value == &etag)
                    && response
                        .headers()
                        .get("x-amz-version-id")?
                        .as_deref()
                        .is_none_or(|version| version == "null"),
                "inspection HEAD differs from the retained versionless source"
            );
            Some(etag)
        }
        _ => anyhow::bail!("inspection HEAD did not establish a known result"),
    };
    check()?;
    let (body, signature) = source_protocol::sign_inspection_lookup(
        &storage::key(&guard.env)?,
        message,
        closure,
        etag,
    )?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &signature)?;
    headers.set("cache-control", "private, no-store")?;
    Ok(Response::from_bytes(body)?.with_headers(headers))
}

fn require_idle(head: &Head) -> Result<()> {
    ensure!(
        head.pending.is_none()
            && head.observation.is_none()
            && head.stage.is_none()
            && head.copy.is_none()
            && head.oci.is_none()
            && head.mirror.is_none(),
        "inspection source remains active or unknown"
    );
    Ok(())
}
