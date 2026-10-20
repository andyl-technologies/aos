//! Shares actual send/post/disposal behind genuine closed native borrowers.
//!
//! Concrete Create, Start, Recover and C17 Delete originals alone implement
//! the private mechanical interface. The interface has no factory,
//! account, capacity or callback and is inaccessible outside this module tree.

use super::*;
use aos_sandbox::{CreateStorageInventoryClosedV1, OriginalCreateStorageInventoryV1};
use super::storage_inventory::wait::InventoryWaitOriginalsV1;

mod native;
pub(super) use native::{NativeStorageIoV1, NativeStorageIoDisposalV1, StorageIoNativeFailureV1};

pub(super) enum StorageIoFailureV1 { Native, Wait, Shared }

pub(super) fn send_once<N: NativeStorageIoV1>(shared: &mut OriginalStoragePreparationClientFlightV1,
    wait: &mut InventoryWaitOriginalsV1<N::Failure>,
    before: &mut Option<Result<(), N::Failure>>,
    after: &mut Option<Result<(), N::Failure>>,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    original: &mut N,
) -> Result<StoragePreparationClientProgressV1, StorageIoFailureV1> {
    if shared.pending.is_some() || shared.inner.closed || wait.is_pending() {
        return Err(StorageIoFailureV1::Shared);
    }
    *before = Some(match original.session_journal_v1(&session.owner) {
        Ok(journal) => original.begin_send_once(journal, &session.socket, &session.transcript),
        Err(cause) => {
            shared.inner.protected_failure = Some(cause);
            Err(N::closed())
        }
    });
    let progress = if matches!(*before, Some(Ok(()))) {
        match original.preparation_descriptor_v4() {
            Ok(content) => shared.send_with_content_v4(session, content),
            Err(cause) => {
                *before = Some(Err(cause));
                StoragePreparationClientProgressV1::Closed
            }
        }
    } else { StoragePreparationClientProgressV1::Closed };
    if matches!(progress, StoragePreparationClientProgressV1::Closed)
        && shared.inner.failure_with_session(session).is_some() {
        original.mark_sdk_primary_before_post_v1();
    }
    *after = Some(shared.inner.observe_storage_io_post_v1(session, original));
    if !matches!(*before, Some(Ok(()))) { return Err(StorageIoFailureV1::Native); }
    if matches!(progress, StoragePreparationClientProgressV1::Closed) {
        return Err(StorageIoFailureV1::Shared);
    }
    if !matches!(*after, Some(Ok(()))) { return Err(StorageIoFailureV1::Native); }
    match progress {
        StoragePreparationClientProgressV1::Sent => {
            if original.finish_positive_io_once().is_err() {
                return Err(StorageIoFailureV1::Native);
            }
            Ok(progress)
        }
        StoragePreparationClientProgressV1::Pending => {
            let Some(native) = shared.inner.storage_sent.as_ref().and_then(|receipt| receipt.native.as_ref()) else {
                shared.inner.closed = true; return Err(StorageIoFailureV1::Shared);
            };
            let Ok(disposal) = original.prepare_pending_send_disposal_once(native, &session.socket) else {
                return Err(StorageIoFailureV1::Native);
            };
            // Native and Security posts are complete. Dispose the actual
            // whole no-consumption receipt before infallible peak reuse.
            drop(shared.inner.storage_sent.take());
            disposal.complete_after_receipt_disposal();
            shared.pending = None;
            *before = None;
            *after = None;
            if !wait.arm_send() {
                return Err(StorageIoFailureV1::Wait);
            }
            Ok(progress)
        }
        _ => { shared.inner.closed = true; Err(StorageIoFailureV1::Shared) }
    }
}

impl OriginalOutputClientFlightV1 {
    pub(super) fn observe_storage_io_post_v1<N: NativeStorageIoV1>(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut N,
    ) -> Result<(), N::Failure> {
        match original.session_journal_v1(&session.owner) {
            Ok(journal) => original.observe_io_post_once(journal, &session.socket, &session.transcript),
            Err(cause) => {
                self.protected_failure.get_or_insert(cause);
                Err(N::closed())
            }
        }
    }
}
