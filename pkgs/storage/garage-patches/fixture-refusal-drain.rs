// SPDX-License-Identifier: AGPL-3.0-only
//! Owns bounded body disposal for the opt-in Garage transport fixture.
//!
//! Successful disposal requires HTTP-stream EOF and the existing payload
//! checksum task's success. Dropping this future aborts that task; neither
//! cancellation nor a partial body establishes a completed refusal drain.

use std::convert::TryFrom;
use std::time::Duration;

use futures::StreamExt;

use super::{ReqBody, StreamingChecksumReceiver};
use crate::signature::error::{CommonErrorDerivative, Error};

const MAXIMUM_BYTES: u64 = 64 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(90);

struct ChecksumTask(StreamingChecksumReceiver);

impl Drop for ChecksumTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn drain(body: ReqBody) -> Result<(), Error> {
    drain_bounded(body, MAXIMUM_BYTES, DEADLINE).await
}

async fn drain_bounded(body: ReqBody, maximum: u64, deadline: Duration) -> Result<(), Error> {
    let (mut stream, checksums) = body.streaming_with_checksums();
    let mut checksums = ChecksumTask(checksums);

    let disposal = async {
        let mut consumed = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let length = u64::try_from(chunk.len())
                .map_err(|_| Error::bad_request("Fixture refusal body size overflowed"))?;
            consumed = add_length(consumed, length, maximum)?;
        }

        // EOF does not drop filter_map's checksum-channel sender. Release it
        // before joining, or the checksum worker can wait forever for EOF.
        drop(stream);
        (&mut checksums.0)
            .await
            .map_err(|_| Error::bad_request("Fixture refusal checksum task did not complete"))??;
        Ok(())
    };

    tokio::time::timeout(deadline, disposal)
        .await
        .map_err(|_| Error::bad_request("Fixture refusal body deadline expired"))?
}

fn add_length(consumed: u64, length: u64, maximum: u64) -> Result<u64, Error> {
    consumed
        .checked_add(length)
        .filter(|total| *total <= maximum)
        .ok_or_else(|| Error::bad_request("Fixture refusal body exceeded its bound"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use futures::{stream, Stream};
    use hyper::body::{Bytes, Frame};
    use tokio::sync::Notify;

    use super::*;
    use crate::signature::checksum::{Checksummer, ExpectedChecksums};

    fn body<S>(stream: S) -> ReqBody
    where
        S: Stream<Item = Result<Frame<Bytes>, Error>> + Send + 'static,
    {
        ReqBody {
            stream: Mutex::new(stream.boxed()),
            checksummer: Checksummer::new(),
            expected_checksums: ExpectedChecksums::default(),
            trailer_algorithm: None,
        }
    }

    #[tokio::test]
    async fn fixture_refusal_full_bound_releases_sender_and_joins_real_checksums() {
        let chunk = Bytes::from(vec![0x5a; 1024 * 1024]);
        let frames = (0..64)
            .map(|_| Ok(Frame::data(chunk.clone())))
            .collect::<Vec<_>>();
        let mut request = body(stream::iter(frames));
        request.add_md5();

        let result = drain(request).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fixture_refusal_excess_body_and_invalid_checksum_do_not_complete() {
        let chunk = Bytes::from(vec![0x5a; 1024 * 1024]);
        let mut frames = (0..64)
            .map(|_| Ok(Frame::data(chunk.clone())))
            .collect::<Vec<_>>();
        frames.push(Ok(Frame::data(Bytes::from_static(b"x"))));

        assert!(drain(body(stream::iter(frames))).await.is_err());

        let mut request = body(stream::iter([Ok(Frame::data(Bytes::from_static(b"data")))]));
        request.add_expected_checksums(ExpectedChecksums {
            md5: Some("AAAAAAAAAAAAAAAAAAAAAA==".into()),
            ..ExpectedChecksums::default()
        });

        assert!(drain(request).await.is_err());
        assert!(add_length(u64::MAX, 1, u64::MAX).is_err());
    }

    #[tokio::test]
    async fn fixture_refusal_transport_error_and_deadline_do_not_complete() {
        let request = body(stream::iter([
            Ok(Frame::data(Bytes::from_static(b"partial"))),
            Err(Error::bad_request("Test body transport failed")),
        ]));

        assert!(drain(request).await.is_err());
        assert!(drain_bounded(
            body(stream::pending()),
            MAXIMUM_BYTES,
            Duration::from_millis(1)
        )
        .await
        .is_err());
    }

    struct DropNotice(Arc<AtomicUsize>);

    impl Drop for DropNotice {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn fixture_refusal_caller_cancellation_drops_actual_body_owner() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let notice = DropNotice(dropped.clone());
        let entered = Arc::new(Notify::new());
        let ready = entered.clone();
        let request = body(stream::poll_fn(move |_| {
            let _owner = &notice;
            ready.notify_one();
            std::task::Poll::Pending
        }));
        let task = tokio::spawn(drain(request));
        entered.notified().await;

        task.abort();
        assert!(task.await.is_err());

        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fixture_refusal_checksum_owner_aborts_real_pending_task_on_drop() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let notice = DropNotice(dropped.clone());
        let entered = Arc::new(Notify::new());
        let ready = entered.clone();
        let task = tokio::spawn(async move {
            let _owner = notice;
            ready.notify_one();
            futures::future::pending().await
        });
        let cancelled = task.abort_handle();
        let owner = ChecksumTask(task);
        entered.notified().await;

        drop(owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancelled.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("The aborted checksum task must finish within the test deadline");

        assert!(cancelled.is_finished());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
