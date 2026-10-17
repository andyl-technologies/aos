//! Owned upstream ranges and conditional verification of retained mirror bytes.
//!
//! Actual provider identity is checked before body polling. The per-key owner
//! and provider permit survive pending Fetch and stay held through EOF or native
//! cancellation. Every provider range is at most the qualified part bound.

use std::rc::Rc;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    mirror_work::{MIRROR_PART_BYTES, MirrorVerifiedObject},
    storage_authority::lease::LeaseEffect,
};
use worker::{Headers, Method, Request, RequestInit, RequestRedirect};

use super::super::oci::transport;
use super::{provider::Provider, storage::Journal};
use crate::{
    direct_upload::provider_capacity::{self, Class},
    oci_projection::lifetime::{Owner, Scope},
};

/// Reads one approved public upstream range into the sole admitted part buffer.
pub(super) async fn upstream_part<R: 'static>(
    provider: &Provider<'_>,
    journal: &mut Journal,
    offset: u64,
    length: u64,
    root: Rc<Owner<R>>,
) -> Result<Vec<u8>> {
    provider.current()?;
    ensure!(
        !journal.session.destination
            && journal.session.pending.is_none()
            && length > 0
            && length <= MIRROR_PART_BYTES
            && offset
                .checked_add(length)
                .is_some_and(|end| end <= provider.original.verification.size()),
        "mirror upstream range escapes its original"
    );
    let base = url::Url::parse(&format!(
        "{}/",
        provider.original.upstream_base.trim_end_matches('/')
    ))?;
    let url = base.join(&provider.original.path)?;
    ensure!(
        url.origin() == base.origin() && url.path().starts_with(base.path()),
        "mirror source escaped approved origin/path"
    );
    aos_hub_core::url_guard::is_safe_remote_url(url.as_str())?;
    let headers = Headers::new();
    headers.set("range", &format!("bytes={offset}-{}", offset + length - 1))?;
    headers.set("accept-encoding", "identity")?;
    if let Some(tag) = &journal.session.progress.upstream_etag {
        headers.set("if-match", tag)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let fresh = provider.fresh();
    let permit = provider_capacity::acquire_class_checked(1, Class::Bulk, &|| {
        root.check_open()?;
        fresh()
    })
    .await?;
    let owner = Owner::new((Rc::clone(&root), permit));
    let _scope = Scope(Rc::clone(&owner));
    let (response, reader) = transport::fetch_owned(
        provider.state,
        Request::new_with_init(url.as_str(), &init)?,
        Rc::clone(&owner),
        Rc::clone(&fresh),
    )
    .await?;
    let full = offset == 0 && length == provider.original.verification.size();
    ensure!(
        response.status_code() == 206 || (full && response.status_code() == 200),
        "mirror upstream refused exact range or redirected"
    );
    if response.status_code() == 206 {
        ensure!(
            response.headers().get("content-range")?.as_deref()
                == Some(
                    format!(
                        "bytes {offset}-{}/{}",
                        offset + length - 1,
                        provider.original.verification.size()
                    )
                    .as_str()
                ),
            "mirror upstream changed original range geometry"
        );
    }
    ensure!(
        response
            .headers()
            .get("content-encoding")?
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "mirror upstream changed encoded representation"
    );
    let tag = response
        .headers()
        .get("etag")?
        .map(|tag| aos_hub_core::surface_write::strong_if_match_etag(&tag))
        .transpose()?;
    ensure!(
        journal
            .session
            .progress
            .upstream_etag
            .as_ref()
            .is_none_or(|prior| tag.as_ref() == Some(prior)),
        "mirror upstream changed retained incarnation"
    );
    // Identity refusal above occurs only after the returned body has a cancel
    // owner. The first actual tag is retained before any corresponding PUT.
    journal.retain_upstream_etag(tag).await?;
    fresh()?;
    let reader = reader.context("mirror upstream response body absent")?;
    let mut bytes = Vec::with_capacity(usize::try_from(length)?);
    read_exact(reader, length, &fresh, |view| {
        bytes.extend_from_slice(view);
        Ok(())
    })
    .await?;
    Ok(bytes)
}

/// Independently verifies the whole positive representation using bounded ranges.
pub(super) async fn verify<R: 'static>(
    provider: &Provider<'_>,
    journal: &mut Journal,
    root: Rc<Owner<R>>,
) -> Result<()> {
    let closed = journal
        .session
        .closed
        .clone()
        .context("mirror verification lacks positive completion")?;
    let mut verifier =
        crate::mirror_import::verify::Verifier::new(&provider.original.verification)?;
    let mut offset = 0_u64;
    while offset < closed.object.size {
        let length = (closed.object.size - offset).min(MIRROR_PART_BYTES);
        read_closed(
            provider,
            journal,
            Some((offset, length)),
            Rc::clone(&root),
            |view| verifier.feed(view),
        )
        .await?;
        offset += length;
    }
    if closed.object.size == 0 {
        read_closed(provider, journal, None, Rc::clone(&root), |view| {
            verifier.feed(view)
        })
        .await?;
    }
    let (sha256, plain) = verifier.finish()?;
    let nar_sha256 = plain.as_ref().map(|(_, sha256)| sha256.clone());
    let nar_size = plain.map(|(size, _)| size);
    journal
        .verified(MirrorVerifiedObject {
            object: closed.object,
            sha256,
            nar_sha256,
            nar_size,
        })
        .await
}

/// Consumes one actual positive conditional range while preserving its owner.
pub(super) async fn read_closed<R: 'static>(
    provider: &Provider<'_>,
    journal: &mut Journal,
    range: Option<(u64, u64)>,
    root: Rc<Owner<R>>,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let expected = journal
        .session
        .closed
        .clone()
        .context("mirror read lacks positive completion")?;
    let opened = open_closed(provider, journal, range, root).await?;
    let length = range.map_or(expected.object.size, |(_, length)| length);
    read_exact(Rc::clone(&opened.reader), length, &opened.fresh, |view| {
        consume(view)
    })
    .await?;
    let (_, retained) = super::storage::current(
        &provider.state.storage(),
        provider.object,
        provider.original,
        journal.session.destination,
    )
    .await?;
    ensure!(
        retained.closed.as_ref() == Some(&expected),
        "mirror positive source changed after actual EOF"
    );
    (opened.fresh)()
}

pub(super) struct Opened {
    pub reader: Rc<crate::direct_digest::Reader>,
    pub fresh: Rc<dyn Fn() -> Result<()>>,
    // The scope contains the exact key, pending SDK and capacity owners. It
    // remains attached to a handed-off stream until EOF or cancellation.
    pub scope: Box<dyn std::any::Any>,
}

pub(super) async fn open_closed<R: 'static>(
    provider: &Provider<'_>,
    journal: &mut Journal,
    range: Option<(u64, u64)>,
    root: Rc<Owner<R>>,
) -> Result<Opened> {
    provider.current()?;
    let expected = journal
        .session
        .closed
        .clone()
        .context("mirror read lacks positive completion")?;
    let length = range.map_or(expected.object.size, |(_, length)| length);
    ensure!(
        length <= MIRROR_PART_BYTES
            && range.is_none_or(|(offset, length)| length > 0
                && offset
                    .checked_add(length)
                    .is_some_and(|end| end <= expected.object.size)),
        "mirror conditional range exceeds qualified bound"
    );
    let cohort = &provider.domain.profile.profile.read_cohort;
    let token = super::super::stage::acquire_configured_lease(
        provider.env,
        provider.object,
        &provider.domain.issuer_installation,
        cohort,
        &cohort.admitted_prefix,
    )
    .await?;
    provider.current()?;
    let validated = provider.object.verifier()?.validate_lease(
        token.as_bytes(),
        cohort,
        &provider.object.timing_profile,
        &journal.head.floor,
        &expected.scope.full_key,
        LeaseEffect::Read,
        provider.object.clock(),
    )?;
    journal.retain_read_floor(validated.next_floor).await?;
    let current = provider.fresh();
    let object = provider.object.clone();
    let cohort = cohort.clone();
    let floor = journal.head.floor.clone();
    let full_key = expected.scope.full_key.clone();
    let fresh: Rc<dyn Fn() -> Result<()>> = Rc::new(move || {
        current()?;
        object.verifier()?.validate_lease(
            token.as_bytes(),
            &cohort,
            &object.timing_profile,
            &floor,
            &full_key,
            LeaseEffect::Read,
            object.clock(),
        )?;
        Ok(())
    });
    let surface = provider.surface(true)?;
    let path = provider.relative_key(&expected.scope.full_key)?;
    let signed = surface.oci_conditional_read_request(
        path,
        false,
        &expected.object.etag,
        expected.object.provider_version.as_deref(),
        range,
        provider.object.clock().observed_at,
    )?;
    aos_hub_core::url_guard::is_safe_remote_url(&signed.url)?;
    let headers = Headers::new();
    for header in signed.required_headers {
        headers.set(&header.name, &header.value)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let permit = provider_capacity::acquire_class_checked(1, Class::Bulk, &|| {
        root.check_open()?;
        fresh()
    })
    .await?;
    let owner = Owner::new((Rc::clone(&root), permit));
    let scope = Scope(Rc::clone(&owner));
    let (response, reader) = transport::fetch_owned(
        provider.state,
        Request::new_with_init(&signed.url, &init)?,
        Rc::clone(&owner),
        Rc::clone(&fresh),
    )
    .await?;
    ensure!(
        response.status_code() == (if range.is_some() { 206 } else { 200 })
            && response.headers().get("content-length")?.as_deref()
                == Some(length.to_string().as_str())
            && response.headers().get("etag")?.as_deref() == Some(expected.object.etag.as_str())
            && response
                .headers()
                .get("content-encoding")?
                .as_deref()
                .is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "mirror conditional read changed positive identity"
    );
    if let Some((offset, length)) = range {
        ensure!(
            response.headers().get("content-range")?.as_deref()
                == Some(
                    format!(
                        "bytes {offset}-{}/{}",
                        offset + length - 1,
                        expected.object.size
                    )
                    .as_str()
                ),
            "mirror conditional read changed exact range"
        );
    }
    let version = response
        .headers()
        .get("x-amz-version-id")?
        .filter(|version| version != "null");
    ensure!(
        version == expected.object.provider_version,
        "mirror conditional read changed actual provider version"
    );
    let reader = reader.context("mirror conditional read body absent")?;
    let (_, retained) = super::storage::current(
        &provider.state.storage(),
        provider.object,
        provider.original,
        journal.session.destination,
    )
    .await?;
    ensure!(
        retained.closed.as_ref() == Some(&expected),
        "mirror positive source changed before body handoff"
    );
    fresh()?;
    Ok(Opened {
        reader,
        fresh,
        scope: Box::new(scope),
    })
}

pub(super) async fn read_exact(
    reader: Rc<crate::direct_digest::Reader>,
    length: u64,
    fresh: &Rc<dyn Fn() -> Result<()>>,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut counted = 0_u64;
    loop {
        let (view, done) = transport::bounded(reader.read(), fresh.as_ref()).await?;
        counted = counted
            .checked_add(u64::from(view.length()))
            .context("mirror read count overflow")?;
        ensure!(
            counted <= length && (!done || counted == length),
            "mirror read differs from original body length"
        );
        consume(&view.to_vec())?;
        if done {
            return Ok(());
        }
    }
}
