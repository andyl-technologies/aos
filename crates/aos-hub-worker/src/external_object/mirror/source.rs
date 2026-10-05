//! Actual stage-key-owned conditional ranges consumed by mirror promotion.
//!
//! The source owns its key and one provider permit, but no part buffer. The
//! destination owns the sole part buffer and attaches the returned reader before
//! checking its signed closure. Source ownership lasts through EOF or cancellation.

use std::rc::Rc;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::mirror_work::{MIRROR_PART_BYTES, digest};
use base64::Engine as _;
use worker::Response;

use super::super::{oci::transport, storage::BINDING};
use super::{
    control::{Action, Control, RECEIPT_HEADER, Reply},
    provider::Provider,
    reads::Opened,
    runtime,
    storage::Journal,
};
use crate::oci_projection::lifetime::{Owner, Scope};

const SOURCE_RECEIPT: &str = "x-aos-external-mirror-source-receipt";

pub(super) async fn read<R: 'static>(
    provider: &Provider<'_>,
    journal: &Journal,
    control: &Control,
    number: u32,
    size: u64,
    root: Rc<Owner<R>>,
) -> Result<Vec<u8>> {
    provider.current()?;
    let mut selected = control.clone();
    selected.action = Action::SourceRange {
        part_number: number,
    };
    let name = runtime::address(provider.object, &selected, provider.plan)?;
    let (body, signature) = selected.sign(&super::super::storage::key(provider.env)?)?;
    let request = runtime::request(body, &signature, &name)?;
    let env = provider.env.clone();
    let fresh = provider.fresh();
    let owner = Owner::new(Rc::clone(&root));
    let scope = Scope(Rc::clone(&owner));
    // This is a DO relay, not a second provider invocation. The source handler
    // acquires the actual GET permit; after EOF it releases before our PUT.
    let response = async move {
        env.durable_object(BINDING)?
            .id_from_name(&name)?
            .get_stub()?
            .fetch_with_request(request)
            .await
    };
    let (response, reader) = transport::response_owned(
        provider.state,
        response,
        Rc::clone(&owner),
        Rc::clone(&fresh),
    )
    .await?;
    ensure!(
        response.status_code() == 200
            && response.headers().get("content-length")?.as_deref()
                == Some(size.to_string().as_str()),
        "mirror source range refused its exact body"
    );
    let receipt = response
        .headers()
        .get(SOURCE_RECEIPT)?
        .context("mirror source signed receipt absent")?;
    ensure!(
        receipt.len() <= (256_usize * 1024 * 4).div_ceil(3),
        "mirror source receipt exceeds bound"
    );
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(receipt)?;
    let signature = response
        .headers()
        .get(RECEIPT_HEADER)?
        .context("mirror source authentication absent")?;
    let reply = Reply::verify(
        &selected,
        &super::super::storage::key(provider.env)?,
        &bytes,
        &signature,
    )?;
    reply.progress.validate(provider.original)?;
    ensure!(
        reply.source_bytes == 0
            && reply.progress.stage_closure == journal.session.progress.stage_closure
            && reply.progress.verified == journal.session.progress.verified
            && reply.progress.stage_parts == journal.session.progress.stage_parts,
        "mirror source range replaced its verified original"
    );
    let reader = reader.context("mirror source range body absent")?;
    let mut bytes = Vec::with_capacity(usize::try_from(size)?);
    super::reads::read_exact(reader, size, &fresh, |view| {
        bytes.extend_from_slice(view);
        Ok(())
    })
    .await?;
    fresh()?;
    drop(scope);
    Ok(bytes)
}

pub(super) async fn stream<R: 'static>(
    provider: &Provider<'_>,
    journal: &mut Journal,
    control: &Control,
    number: u32,
    root: Rc<Owner<R>>,
) -> Result<Response> {
    ensure!(
        !journal.session.destination
            && journal.session.pending.is_none()
            && journal.session.progress.verified.is_some(),
        "mirror source has no verified private original"
    );
    let part = journal
        .session
        .progress
        .stage_parts
        .get(usize::try_from(number - 1)?)
        .context("mirror source part receipt absent")?;
    ensure!(
        part.part_number == number,
        "mirror source part order changed"
    );
    let offset = u64::from(number - 1) * MIRROR_PART_BYTES;
    let length = part.size;
    let opened = super::reads::open_closed(provider, journal, Some((offset, length)), root).await?;
    let reply = Reply {
        request_digest: digest(control)?,
        progress: journal.session.progress.clone(),
        source_bytes: 0,
    };
    let (receipt, signature) = reply.sign(control, &super::super::storage::key(provider.env)?)?;
    let state = Stream {
        opened,
        counted: 0,
        length,
        ended: false,
    };
    let stream = futures_util::stream::try_unfold(state, |mut state| async move {
        if state.ended {
            return Ok(None);
        }
        let (view, done) =
            transport::bounded(state.opened.reader.read(), state.opened.fresh.as_ref())
                .await
                .map_err(|_| worker::Error::RustError("mirror source range read refused".into()))?;
        state.counted = state
            .counted
            .checked_add(u64::from(view.length()))
            .ok_or_else(|| worker::Error::RustError("mirror source range count overflow".into()))?;
        if state.counted > state.length || (done && state.counted != state.length) {
            return Err(worker::Error::RustError(
                "mirror source range length changed".into(),
            ));
        }
        state.ended = done;
        if done && view.length() == 0 {
            return Ok(None);
        }
        Ok(Some((view.to_vec(), state)))
    });
    let response = super::super::oci::byte_stream::adapt(Response::from_stream(stream)?)?;
    response.headers().set(RECEIPT_HEADER, &signature)?;
    response.headers().set(
        SOURCE_RECEIPT,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(receipt),
    )?;
    response
        .headers()
        .set("content-length", &length.to_string())?;
    response
        .headers()
        .set("cache-control", "private, no-store")?;
    Ok(response)
}

struct Stream {
    opened: Opened,
    counted: u64,
    length: u64,
    ended: bool,
}
