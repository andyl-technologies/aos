//! Bounded External OCI final-body routing after current Native authorization.
//!
//! One 64 KiB peek distinguishes an empty final request. Nonempty bytes stay
//! beside storage: an origin-owned reader feeds a native byte transform with
//! that first view restored. Cancellation drops that reader; no whole chunk is
//! retained and no object body is sent to Native.

use std::time::Duration;

use anyhow::{ensure, Result};
use futures_util::future::{select, Either};
use worker::{Headers, Method, Request, RequestInit, RequestRedirect, Response, ResponseBody};

/// Confirms clean EOF without granting another chunk or retaining its body.
pub(super) async fn is_empty(original: &Request) -> Result<bool> {
    let Some(source) = original.inner().body() else {
        return Ok(true);
    };
    let reader = crate::direct_digest::Reader::new(source.into())?;
    let read = Box::pin(reader.read());
    let timeout = Box::pin(worker::Delay::from(Duration::from_secs(30)));
    let (first, done) = match select(read, timeout).await {
        Either::Left((result, _)) => result?,
        Either::Right(_) => anyhow::bail!("OCI completion replay initial read expired"),
    };
    ensure!(first.length() > 0 || done, "OCI completion replay returned an empty unfinished view");
    Ok(first.length() == 0 && done)
}

/// Produces a streaming PATCH or confirms actual clean EOF of an empty body.
pub(super) async fn patch(original: &Request) -> Result<Option<Request>> {
    let Some(source) = original.inner().body() else {
        return Ok(None);
    };
    let reader = crate::direct_digest::Reader::new(source.into())?;
    let read = Box::pin(reader.read());
    let timeout = Box::pin(worker::Delay::from(Duration::from_secs(30)));
    let (first, done) = match select(read, timeout).await {
        Either::Left((result, _)) => result?,
        Either::Right(_) => anyhow::bail!("OCI final body initial read expired"),
    };
    if first.length() == 0 {
        ensure!(done, "OCI final body returned an empty unfinished view");
        return Ok(None);
    }

    let stream = futures_util::stream::try_unfold(
        (reader, Some(first.to_vec()), done),
        |(reader, first, ended)| async move {
            if let Some(bytes) = first {
                return Ok::<_, worker::Error>(Some((bytes, (reader, None, ended))));
            }
            if ended {
                return Ok(None);
            }
            let (view, done) = reader.read().await
                .map_err(|_| worker::Error::RustError("OCI final body read failed".into()))?;
            if view.length() == 0 {
                if !done { return Err(worker::Error::RustError("OCI final body returned an empty unfinished view".into())); }
                return Ok(None);
            }
            Ok(Some((view.to_vec(), (reader, None, done))))
        },
    );
    let response = crate::external_object::oci::byte_stream::adapt(Response::from_stream(stream)?)?;
    let (_, body) = response.into_parts();
    let ResponseBody::Stream(body) = body else {
        anyhow::bail!("OCI final body bridge lacks its source");
    };
    let body = wasm_bindgen::JsValue::from(body);
    let mut body_owner = crate::external_object::oci::byte_stream::UnhandedStream::new(body.clone());

    let headers = Headers::new();
    for (name, value) in original.headers().entries() {
        if super::is_forwarded_header(&name) && name != "cf-connecting-ip" {
            continue;
        }
        headers.append(&name, &value)?;
    }
    headers.delete("content-length")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Patch).with_headers(headers)
        .with_redirect(RequestRedirect::Manual).with_body(Some(body));
    // The final digest belongs to the later PUT. This intermediate PATCH
    // uses the ordinary bodyless chunk preflight/completion contract.
    let mut patch_url = original.url()?;
    patch_url.set_query(None);
    let request = Request::new_with_init(patch_url.as_str(), &init)?;
    body_owner.disarm();
    Ok(Some(request))
}
