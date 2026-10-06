//! Hash-only receipts for frames actually exposed by an application body.
//!
//! The counters observe an already-polled frame. They never poll, buffer or
//! interpret a body, and an unread prefix never becomes a complete receipt.

use axum::body::Bytes;
use http_body::Frame;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::task::Poll;

#[derive(Default)]
pub(super) struct ObservedFrames {
    digest: Sha256,
    pub(super) bytes: u64,
    pub(super) eof: bool,
    pub(super) failed: bool,
    pub(super) overflow: bool,
    pub(super) trailers: bool,
}

impl ObservedFrames {
    pub(super) fn observe(&mut self, bytes: &[u8]) {
        if let Some(length) = self.bytes.checked_add(bytes.len() as u64) {
            self.bytes = length;
            self.digest.update(bytes);
        } else {
            self.overflow = true;
        }
    }

    pub(super) fn observe_result<E>(
        &mut self,
        result: &Poll<Option<Result<Frame<Bytes>, E>>>,
        ended: bool,
    ) {
        match result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    self.observe(bytes);
                }
                self.trailers |= frame.trailers_ref().is_some();
                self.eof |= ended;
            }
            Poll::Ready(None) => self.eof = true,
            Poll::Ready(Some(Err(_))) => self.failed = true,
            Poll::Pending => {}
        }
    }

    pub(super) fn receipt(&self) -> FrameReceipt {
        FrameReceipt {
            exposed_bytes: self.bytes.to_string(),
            exposed_sha256: hex::encode(self.digest.clone().finalize()),
            eof: self.eof,
            failed: self.failed,
            overflow: self.overflow,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FrameReceipt {
    pub(super) exposed_bytes: String,
    pub(super) exposed_sha256: String,
    pub(super) eof: bool,
    pub(super) failed: bool,
    pub(super) overflow: bool,
}
