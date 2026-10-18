//! Bounded independent item scheduling with stable public response ordering.
//!
//! Every future owns one item through its dependent effects. Completion order
//! can differ from request order; failures remain values and do not cancel
//! neighboring work that may already have dispatched a provider effect.

use std::future::Future;

use aos_hub_core::direct_upload::{
    DirectItemError, DirectItemErrorCode, DirectSessionState, DirectSessionStatus,
    DirectUploadLogicalReply, DirectUploadResponse,
};

use futures_util::{stream, StreamExt as _};

pub(super) async fn bounded<I, T>(items: I, maximum: usize) -> Vec<T>
where
    I: IntoIterator,
    I::Item: Future<Output = T>,
{
    let mut results = stream::iter(
        items
            .into_iter()
            .enumerate()
            .map(|(index, future)| async move { (index, future.await) }),
    )
    .buffer_unordered(maximum.max(1))
    .collect::<Vec<_>>()
    .await;

    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, value)| value).collect()
}

pub(super) fn merge_status(response: &mut DirectUploadResponse, status: DirectSessionStatus) {
    if let Some(existing) = response
        .sessions
        .iter_mut()
        .find(|existing| existing.session == status.session)
    {
        *existing = status;
    } else {
        response.sessions.push(status);
    }
}

/// Projects physical readiness only after every required creation is acknowledged.
///
/// Native retains logical `Creating` while the Worker owns provider receipts.
/// Later lifecycle states remain authoritative even when creation is historical.
pub(super) fn created_state(
    state: DirectSessionState,
    creation: anyhow::Result<()>,
) -> anyhow::Result<DirectSessionState> {
    creation?;
    Ok(if state == DirectSessionState::Creating {
        DirectSessionState::Active
    } else {
        state
    })
}

pub(super) fn merge_reply(response: &mut DirectUploadResponse, reply: DirectUploadLogicalReply) {
    for status in reply.sessions {
        merge_status(response, status);
    }
    response.errors.extend(reply.errors);
}

pub(super) fn item_error(identity: &str, error: &anyhow::Error) -> DirectItemError {
    let code = if error.to_string().contains("unknown") {
        DirectItemErrorCode::BlockedUnknown
    } else {
        DirectItemErrorCode::Unavailable
    };
    DirectItemError {
        item_id: identity.into(),
        code,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
        task::Poll,
    };

    use super::bounded;

    #[test]
    fn acknowledged_creation_activates_only_the_initial_logical_state() {
        use aos_hub_core::direct_upload::DirectSessionState::*;

        assert_eq!(super::created_state(Creating, Ok(())).unwrap(), Active);
        for state in [
            Active,
            Freezing,
            CompletingStaging,
            StagedVerified,
            Promoting,
            Committed,
            Aborting,
            Aborted,
            BlockedUnknown,
            CleanupPending,
        ] {
            assert_eq!(super::created_state(state, Ok(())).unwrap(), state);
        }

        for message in ["creation refused", "creation outcome unknown"] {
            let result = super::created_state(Creating, Err(anyhow::anyhow!(message)));
            assert_eq!(result.unwrap_err().to_string(), message);
        }
    }

    #[tokio::test]
    async fn bounds_inflight_items_and_retains_out_of_order_failures() {
        let inflight = Rc::new(Cell::new(0));
        let peak = Rc::new(Cell::new(0));
        let completed = Rc::new(RefCell::new(Vec::new()));
        let outputs = bounded(
            (0..7).map(|index| {
                let inflight = Rc::clone(&inflight);
                let peak = Rc::clone(&peak);
                let completed = Rc::clone(&completed);

                async move {
                    inflight.set(inflight.get() + 1);
                    peak.set(peak.get().max(inflight.get()));
                    let mut remaining = if index == 0 { 12 } else { 1 };
                    futures_util::future::poll_fn(|context| {
                        if remaining == 0 {
                            return Poll::Ready(());
                        }

                        remaining -= 1;
                        context.waker().wake_by_ref();
                        Poll::Pending
                    })
                    .await;

                    completed.borrow_mut().push(index);
                    inflight.set(inflight.get() - 1);
                    if index == 3 {
                        Err(index)
                    } else {
                        Ok(index)
                    }
                }
            }),
            3,
        )
        .await;

        assert_eq!(peak.get(), 3);
        assert_eq!(inflight.get(), 0);
        assert_ne!(*completed.borrow(), (0..7).collect::<Vec<_>>());
        assert_eq!(
            outputs,
            vec![Ok(0), Ok(1), Ok(2), Err(3), Ok(4), Ok(5), Ok(6)]
        );
    }
}
