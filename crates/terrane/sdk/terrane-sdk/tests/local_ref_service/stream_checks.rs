//! Pauses actual response polling across publication changes and token expiry.

use futures_util::StreamExt;
use tokio::sync::Notify;

use super::*;

struct PollGate {
    after_rows: usize,
    entered: Notify,
    release: Notify,
}

impl PollGate {
    fn new(after_rows: usize) -> Arc<Self> {
        Arc::new(Self {
            after_rows,
            entered: Notify::new(),
            release: Notify::new(),
        })
    }

    fn stream<T: Send + 'static>(self: &Arc<Self>, stream: ServiceStream<T>) -> ServiceStream<T> {
        let gate = self.clone();
        Box::pin(futures_util::stream::unfold(
            (stream, 0_usize),
            move |(mut stream, position)| {
                let gate = gate.clone();
                async move {
                    if position == gate.after_rows {
                        gate.entered.notify_one();
                        gate.release.notified().await;
                    }
                    let next = stream.next().await?;
                    Some((next, (stream, position + 1)))
                }
            },
        ))
    }
}

struct PausedReads {
    inner: Arc<NativeService>,
    gate: Arc<PollGate>,
}

#[allow(refining_impl_trait)]
impl RefService for PausedReads {
    async fn get_ref(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::GetRefRequest>,
    ) -> ServiceResult<v1::RefState> {
        self.inner.get_ref(context, request).await
    }

    async fn compare_and_swap_ref(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::CompareAndSwapRefRequest>,
    ) -> ServiceResult<v1::RefState> {
        self.inner.compare_and_swap_ref(context, request).await
    }

    async fn get_ref_log(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::GetRefLogRequest>,
    ) -> ServiceResult<ServiceStream<v1::RefLogEntry>> {
        let stream = self.inner.get_ref_log(context, request).await?;
        Ok(connectrpc::Response::new(self.gate.stream(stream.body)))
    }

    async fn watch_refs(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::WatchRefsRequest>,
    ) -> ServiceResult<ServiceStream<v1::RefEvent>> {
        self.inner.watch_refs(context, request).await
    }

    async fn list_refs(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::ListRefsRequest>,
    ) -> ServiceResult<ServiceStream<v1::RefState>> {
        let stream = self.inner.list_refs(context, request).await?;
        Ok(connectrpc::Response::new(self.gate.stream(stream.body)))
    }
}

async fn paused(
    fixture: &Fixture,
    after_rows: usize,
) -> Result<(Running, Arc<PollGate>), TestError> {
    let gate = PollGate::new(after_rows);
    let service = PausedReads {
        inner: Arc::new(LocalRefService::new(reader(fixture).await?, limits()?).await?),
        gate: gate.clone(),
    };
    let running = Running::start(Arc::new(service), fixture, true).await?;
    Ok((running, gate))
}

#[tokio::test]
async fn changed_publications_refuse_prepared_reflog_rows_and_listing_completion() -> TestResult {
    let fixture = Fixture::new().await?;
    let (running, gate) = paused(&fixture, 0).await?;
    let expected = fixture
        .repository
        .ref_head(MAIN, fixture.authority.token(), "sdk")
        .await?
        .ok_or("missing original head")?;

    let receive = async {
        let mut stream = running
            .client
            .get_ref_log_with_options(
                v1::GetRefLogRequest {
                    name: MAIN.into(),
                    from_sequence: expected.seq,
                    ..Default::default()
                },
                options(fixture.authority.token())?,
            )
            .await?;
        let error = stream
            .message()
            .await
            .err()
            .ok_or("stale reflog row escaped")?;
        Ok::<_, TestError>(error)
    };
    let change = async {
        gate.entered.notified().await;
        let result = fixture.commit_bytes(OLD).await;
        gate.release.notify_one();
        let commit = result?;
        assert_ne!(commit, expected.commit);
        Ok::<_, TestError>(())
    };

    let (received, changed) = tokio::join!(receive, change);
    changed?;
    assert_eq!(received?.code, ErrorCode::Unavailable);
    running.stop().await?;

    // A single disclosed row is followed by a gated terminal poll. Advancing
    // that real ref must refuse completion instead of blessing a stale listing.
    let (running, gate) = paused(&fixture, 1).await?;
    let receive = async {
        let mut stream = running
            .client
            .list_refs_with_options(
                v1::ListRefsRequest {
                    pattern: MAIN.into(),
                    ..Default::default()
                },
                options(fixture.authority.token())?,
            )
            .await?;
        let first = stream
            .message()
            .await?
            .ok_or("missing original listing row")?;
        assert_eq!(first.to_owned_message().name, MAIN);
        let error = stream
            .message()
            .await
            .err()
            .ok_or("changed listing completed")?;
        Ok::<_, TestError>(error)
    };
    let change = async {
        gate.entered.notified().await;
        let result = fixture.commit_bytes(NEW).await;
        gate.release.notify_one();
        result?;
        Ok::<_, TestError>(())
    };

    let (received, changed) = tokio::join!(receive, change);
    changed?;
    assert_eq!(received?.code, ErrorCode::Unavailable);
    running.stop().await
}

#[tokio::test]
async fn identity_expiry_refuses_prepared_empty_listing_completion() -> TestResult {
    let fixture = Fixture::new().await?;
    let (running, gate) = paused(&fixture, 0).await?;
    let until = TokioClock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        + 2;
    let token = attenuated(
        &fixture,
        Attenuation {
            not_after: Some(until),
            ..Default::default()
        },
    )?;
    let receive = async {
        let mut stream = running
            .client
            .list_refs_with_options(
                v1::ListRefsRequest {
                    pattern: "refs/heads/_/absent".into(),
                    ..Default::default()
                },
                options(&token)?,
            )
            .await?;
        let error = stream
            .message()
            .await
            .err()
            .ok_or("expired empty listing completed")?;
        Ok::<_, TestError>(error)
    };
    let expire = async {
        // Reaching this gate proves authentication and guarded enumeration
        // already succeeded. Expiry occurs before the original stream polls.
        gate.entered.notified().await;
        let wait = async {
            while TokioClock
                .now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                <= until
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Ok::<_, TestError>(())
        }
        .await;
        gate.release.notify_one();
        wait
    };

    let (received, expired) = tokio::join!(receive, expire);
    expired?;
    assert_eq!(received?.code, ErrorCode::Unauthenticated);
    running.stop().await
}
