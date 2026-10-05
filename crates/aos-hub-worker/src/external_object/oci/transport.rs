//! Owned bounded provider Fetch through actual SDK settlement.
//!
//! Closing a caller stops new dispatch and cancels a handed-off reader. An SDK
//! promise with no abort handle retains the real key and provider permit until
//! it resolves, then rejects/cancels its late response. Deadline or absence
//! never settles a physical mutation journal.

use std::{cell::RefCell, future::Future, rc::Rc, time::Duration};
use anyhow::{Context as _, Result};
use futures_util::{future::{select, Either}, FutureExt as _};
use worker::{Fetch, Request, Response, State};
use crate::oci_projection::lifetime::Owner;

pub(in crate::external_object) async fn fetch_owned<R: 'static>(
    state: &State,
    request: Request,
    owner: Rc<Owner<R>>,
    fresh: Rc<dyn Fn() -> Result<()>>,
) -> Result<(Response, Option<Rc<crate::direct_digest::Reader>>)> {
    response_owned(state, async move {
        crate::direct_upload::provider_capacity::record_dispatch();
        Fetch::Request(request).send().await
    }, owner, fresh).await
}

/// Retains physical resources across an owned response promise and its reader.
/// The caller owns dispatch accounting; a DO relay is not an SDK operation.
pub(in crate::external_object) async fn response_owned<R: 'static>(
    state: &State,
    response: impl Future<Output = worker::Result<Response>> + 'static,
    owner: Rc<Owner<R>>,
    fresh: Rc<dyn Fn() -> Result<()>>,
) -> Result<(Response, Option<Rc<crate::direct_digest::Reader>>)> {
    let dispatch = Rc::clone(&fresh);
    let held = Rc::clone(&owner);
    let pending = async move {
        if let Err(error) = held.check_open().and_then(|_| dispatch()) {
            return Rc::new(RefCell::new(Some(Err(error))));
        }
        let response = response.await;
        if held.check_open().is_err() {
            if let Ok(response) = response {
                if let worker::ResponseBody::Stream(stream) = response.body() {
                    let mut raw = super::byte_stream::UnhandedStream::new(stream.clone().into());
                    if let Ok(reader) = crate::direct_digest::Reader::new(stream.clone().into()) {
                        reader.cancel();
                        raw.disarm();
                    }
                }
            }
            return Rc::new(RefCell::new(Some(Err(anyhow::anyhow!("external OCI invocation closed")))));
        }
        let result = response.map_err(anyhow::Error::from).and_then(|response| {
            let reader = match response.body() {
                worker::ResponseBody::Stream(stream) => {
                    // If BYOB construction fails, the actual returned native
                    // stream still receives a cancellation attempt before the
                    // physical resources can be released.
                    let mut raw = super::byte_stream::UnhandedStream::new(stream.clone().into());
                    let reader = crate::direct_digest::Reader::new(stream.clone().into())?;
                    raw.disarm();
                    Some(held.attach(reader)?)
                },
                _ => None,
            };
            Ok((response, reader))
        });
        Rc::new(RefCell::new(Some(result)))
    }.shared();
    let retained = pending.clone();
    state.wait_until(async move { let _ = retained.await; });
    bounded(async {
        let output = pending.await;
        let result = output.borrow_mut().take().context("OCI SDK response already handed off")?;
        result
    }, &|| { owner.check_open()?; fresh() }).await
}

pub(in crate::external_object) async fn bounded<T>(
    work: impl Future<Output = Result<T>>,
    fresh: &dyn Fn() -> Result<()>,
) -> Result<T> {
    fresh()?;
    let timer = async {
        loop {
            worker::Delay::from(Duration::from_millis(50)).await;
            fresh()?;
        }
    };
    futures_util::pin_mut!(work, timer);
    match select(work, timer).await {
        Either::Left((result, _)) => { fresh()?; result }
        Either::Right((result, _)) => result,
    }
}
