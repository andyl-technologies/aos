//! Checks repository-backed reference RPC reads over real native sockets.
//!
//! Repositories and signed policy are genuine local publications. Content and
//! Tier handlers are deliberately unused transport fixtures. These cases do not
//! qualify CAS publication, resumable watch, distributed freshness or deployment.

#![cfg(all(feature = "tokio", unix))]

#[allow(
    dead_code,
    reason = "Other integration targets share this native fixture."
)]
#[path = "local_sdk/fixture.rs"]
mod fixture;
#[allow(
    dead_code,
    reason = "Only unused Content and Tier services are shared here."
)]
#[path = "distribution_transport/fixture.rs"]
mod transport_fixture;

use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::{
    ErrorCode, RequestContext, ServiceRequest, ServiceResult, ServiceStream,
    client::{CallOptions, ClientConfig, HttpClient},
};
use fixture::{Fixture, LocalRepository, MAIN, NEW, OLD, TestResult};
use terrane_format::auth::{self, Attenuation, Caveat, Grant, Token, Verbs};
use terrane_sdk::{
    repository::{LocalAuthorityIdentity, Repository},
    store::{Clock, TokioClock, TokioLocalFs},
    wire::{
        authentication::CapabilityAuthentication,
        client::{
            listing::{RefListLimits, list_refs},
            references::get_ref,
            reflog::{RefLogLimits, get_ref_log},
        },
        local_refs::{LocalRefLimits, LocalRefService, LocalRefServiceError},
        refs::RefCodec,
        services::{RefService, RefServiceClient},
        transport::{DistributionTransport, TransportError},
        v1,
    },
};

type NativeService = LocalRefService<
    terrane_sdk::bucket::FileBucket<
        TokioLocalFs,
        TokioClock,
        terrane_sdk::repository::MetadataValidator,
    >,
    TokioClock,
    TokioLocalFs,
>;
type TestError = Box<dyn std::error::Error>;

fn positive(value: usize) -> Result<NonZeroUsize, TestError> {
    NonZeroUsize::new(value).ok_or_else(|| "zero fixture bound".into())
}

fn limits() -> Result<LocalRefLimits, TestError> {
    Ok(LocalRefLimits {
        max_name_bytes: positive(1024)?,
        max_record_bytes: positive(4 * 1024 * 1024)?,
        max_entries: positive(64)?,
        max_content_bytes: positive(16 * 1024 * 1024)?,
    })
}

fn options(token: &[u8]) -> Result<CallOptions, TestError> {
    Ok(CallOptions::default()
        .with_timeout(Duration::from_secs(15))
        .with_max_message_size(4 * 1024 * 1024)
        .with_element_memory_limit(4 * 1024 * 1024)
        .try_with_header(
            "authorization",
            format!("Bearer {}", URL_SAFE_NO_PAD.encode(token)),
        )?)
}

fn request(name: &str) -> v1::GetRefRequest {
    v1::GetRefRequest {
        name: name.into(),
        ..Default::default()
    }
}

async fn reader(fixture: &Fixture) -> Result<Arc<LocalRepository>, TestError> {
    let (repository, authority) = Repository::open_local(
        &fixture.location,
        &LocalAuthorityIdentity {
            issuer: "local".into(),
            key_id: "initial".into(),
            owner_uid: fixture.owner,
        },
        fixture::policy()?,
        MAIN,
        TokioLocalFs,
        TokioClock,
    )
    .await?;
    // The RPC service owns no signing authority, even though this fixture's
    // writer retains its separate private authority for genuine concurrent work.
    drop(authority);
    Ok(Arc::new(repository))
}

struct Running {
    client: RefServiceClient<HttpClient>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    worker: tokio::task::JoinHandle<Result<(), TransportError>>,
}

impl Running {
    async fn start<R: RefService>(
        service: Arc<R>,
        fixture: &Fixture,
        authenticate: bool,
    ) -> Result<Self, TestError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let unused = Arc::new(transport_fixture::Services::default());
        let mut transport_limits = transport_fixture::limits();
        transport_limits.request_timeout = Duration::from_secs(20);
        let mut transport = DistributionTransport::from_listener(
            listener,
            unused.clone(),
            service,
            unused,
            None,
            transport_limits,
        )?;
        if authenticate {
            transport = transport.with_authentication(CapabilityAuthentication::new(
                TokioClock,
                vec![fixture.authority.issuer_key().clone()],
                positive(16384)?,
                false,
            ));
        }
        let (shutdown, signal) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(transport.serve(async {
            let _ = signal.await;
        }));
        let client = RefServiceClient::new(
            HttpClient::plaintext(),
            ClientConfig::new(format!("http://{address}").parse()?),
        );
        Ok(Self {
            client,
            shutdown,
            worker,
        })
    }

    async fn stop(self) -> TestResult {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(5), self.worker).await???;
        Ok(())
    }
}

async fn start(fixture: &Fixture, bounds: LocalRefLimits) -> Result<Running, TestError> {
    let service = LocalRefService::new(reader(fixture).await?, bounds).await?;
    Running::start(Arc::new(service), fixture, true).await
}

fn attenuated(fixture: &Fixture, attenuation: Attenuation) -> Result<Vec<u8>, TestError> {
    let secret: [u8; 32] = std::fs::read(fixture.location.authority.join("terminal.seed"))?
        .try_into()
        .map_err(|_| "invalid fixture terminal seed")?;
    Ok(Token::decode(fixture.authority.token())?
        .attenuate(attenuation, &secret, auth::public_key_from_secret(&secret))?
        .encode())
}

#[tokio::test]
async fn guarded_point_reads_preserve_whole_records_and_observe_actual_publication() -> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.commit_bytes(OLD).await?;
    let running = start(&fixture, limits()?).await?;
    let token = attenuated(
        &fixture,
        Attenuation {
            grants: Some(vec![Grant::new(MAIN.into(), Verbs::new(1)?)?]),
            caveats: vec![Caveat::Surface("sdk".into())],
            ..Default::default()
        },
    )?;

    let received = get_ref(
        &running.client,
        request(MAIN),
        options(&token)?,
        RefCodec::new(4 * 1024 * 1024)?,
    )
    .await?;
    let record = received
        .value
        .ok_or("missing actual ref value")?
        .verify(&first, "cdc-1m")?;
    assert_eq!(
        Some(&record),
        fixture
            .repository
            .ref_head(MAIN, fixture.authority.token(), "sdk")
            .await?
            .as_ref()
    );
    assert_eq!(
        received.home.ok_or("missing actual home")?.host,
        record.home.host.clone().unwrap_or_default()
    );
    assert!(!received.fenced);

    let second = fixture.commit_bytes(NEW).await?;
    let received = get_ref(
        &running.client,
        request(MAIN),
        options(&token)?,
        RefCodec::new(4 * 1024 * 1024)?,
    )
    .await?;
    let updated = received
        .value
        .ok_or("missing actual updated value")?
        .verify(&second, "cdc-1m")?;
    assert_ne!(updated, record);
    assert_eq!(
        Some(updated),
        fixture
            .repository
            .ref_head(MAIN, fixture.authority.token(), "sdk")
            .await?
    );
    running.stop().await
}

#[tokio::test]
async fn genuine_signatures_and_broad_grants_do_not_override_repository_acl() -> TestResult {
    let fixture = Fixture::new().await?;
    let running = start(&fixture, limits()?).await?;
    let now = TokioClock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let verified = auth::verify(
        fixture.authority.token(),
        &[fixture.authority.issuer_key().clone()],
        now,
    )?;
    let mut claims = verified.authority().clone();
    claims.subject = "outside-root-acl".into();
    claims.token_id = [94; 16];
    let issuer: [u8; 32] = std::fs::read(fixture.location.authority.join("issuer.seed"))?
        .try_into()
        .map_err(|_| "invalid fixture issuer seed")?;
    let foreign = Token::issue(claims, &issuer, auth::public_key_from_secret(&[95; 32]))?.encode();

    for (name, token) in [
        (MAIN, foreign.as_slice()),
        ("refs/heads/_/missing", foreign.as_slice()),
        ("refs/heads/_/missing", fixture.authority.token()),
    ] {
        let error = running
            .client
            .get_ref_with_options(request(name), options(token)?)
            .await
            .err()
            .ok_or("ref unexpectedly disclosed")?;
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(error.message.as_deref(), Some("not found"));
        let debug = format!("{error:?}");
        assert!(!debug.contains(&fixture.parent.to_string_lossy().to_string()));
        assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(token)));
    }
    let denied = list_refs(
        &running.client,
        v1::ListRefsRequest {
            pattern: "refs/**".into(),
            ..Default::default()
        },
        options(&foreign)?,
        RefCodec::new(4 * 1024 * 1024)?,
        RefListLimits {
            max_entries: positive(64)?,
            max_content_bytes: positive(16 * 1024 * 1024)?,
        },
    )
    .await?;
    assert!(denied.entries.is_empty());
    let error = running
        .client
        .get_ref_log_with_options(
            v1::GetRefLogRequest {
                name: MAIN.into(),
                ..Default::default()
            },
            options(&foreign)?,
        )
        .await
        .err()
        .ok_or("denied history unexpectedly disclosed")?;
    assert_eq!(error.code, ErrorCode::NotFound);
    running.stop().await
}

#[tokio::test]
async fn finite_listing_and_reflog_match_the_actual_committed_whole_records() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    fixture.commit_bytes(NEW).await?;
    let fork = fixture
        .repository
        .fork(
            MAIN,
            "refs/heads/_/fork",
            fixture.repository.source_request(
                &fixture.authority,
                fixture::metadata("Actual RPC listing fork"),
            ),
        )
        .await?;
    let running = start(&fixture, limits()?).await?;
    let received = list_refs(
        &running.client,
        v1::ListRefsRequest {
            pattern: "refs/heads/*/*".into(),
            ..Default::default()
        },
        options(fixture.authority.token())?,
        RefCodec::new(4 * 1024 * 1024)?,
        RefListLimits {
            max_entries: positive(64)?,
            max_content_bytes: positive(16 * 1024 * 1024)?,
        },
    )
    .await?;
    let listed = fixture
        .repository
        .list_refs("refs/heads/*/*", fixture.authority.token(), "sdk")
        .await?;
    assert_eq!(received.entries.len(), listed.len());
    for (received, actual) in received.entries.into_iter().zip(listed) {
        assert_eq!(received.name, actual.name());
        assert_eq!(
            received
                .value
                .ok_or("missing listed value")?
                .verify(&actual.record().commit, "cdc-1m")?,
            *actual.record()
        );
    }
    assert_eq!(
        fork,
        fixture
            .repository
            .ref_head("refs/heads/_/fork", fixture.authority.token(), "sdk")
            .await?
            .ok_or("missing genuine fork")?
    );

    let history = fixture
        .repository
        .ref_history(MAIN, 0, fixture.authority.token(), "sdk")
        .await?;
    for from in [0, history.head().ok_or("missing head")?.seq, u64::MAX] {
        let received = get_ref_log(
            &running.client,
            v1::GetRefLogRequest {
                name: MAIN.into(),
                from_sequence: from,
                ..Default::default()
            },
            options(fixture.authority.token())?,
            RefCodec::new(4 * 1024 * 1024)?,
            RefLogLimits {
                max_entries: positive(64)?,
                max_content_bytes: positive(16 * 1024 * 1024)?,
            },
        )
        .await?;
        let expected = fixture
            .repository
            .ref_history(MAIN, from, fixture.authority.token(), "sdk")
            .await?;
        assert_eq!(received.entries.len(), expected.entries().len());
        for (received, actual) in received.entries.into_iter().zip(expected.entries()) {
            assert_eq!(
                received
                    .observation
                    .verify(&actual.record.commit, "cdc-1m")?,
                *actual
            );
            assert!(received.message.is_empty());
        }
    }
    running.stop().await
}

#[tokio::test]
async fn malformed_requests_refuse_and_home_reads_satisfy_all_freshness_modes() -> TestResult {
    let fixture = Fixture::new().await?;
    let running = start(&fixture, limits()?).await?;
    let mut unknown = request(MAIN);
    unknown.freshness = buffa::EnumValue::Unknown(123);
    let mut unbounded = request(MAIN);
    unbounded.freshness = v1::Freshness::Bounded.into();
    for requested in [
        request("refs/heads/../main"),
        request(&"x".repeat(1025)),
        unknown,
        unbounded,
    ] {
        let error = running
            .client
            .get_ref_with_options(requested, options(fixture.authority.token())?)
            .await
            .err()
            .ok_or("invalid request succeeded")?;
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
    let expected = fixture
        .repository
        .ref_head(MAIN, fixture.authority.token(), "sdk")
        .await?
        .ok_or("missing actual head")?;
    for freshness in [
        v1::Freshness::Any,
        v1::Freshness::Bounded,
        v1::Freshness::Linearizable,
    ] {
        let mut requested = request(MAIN);
        requested.freshness = freshness.into();
        requested.bound_ms = 1;
        let state = running
            .client
            .get_ref_with_options(requested, options(fixture.authority.token())?)
            .await?
            .into_owned();
        assert_eq!(state.staleness_ms, 0);
        let record = RefCodec::new(4 * 1024 * 1024)?.decode_value(
            state.value.as_option().ok_or("missing native value")?,
            &expected.commit,
            "cdc-1m",
        )?;
        assert_eq!(record, expected);
    }
    for pattern in ["refs/heads/**:/root", "refs/heads/../main", ""] {
        let error = running
            .client
            .list_refs_with_options(
                v1::ListRefsRequest {
                    pattern: pattern.into(),
                    ..Default::default()
                },
                options(fixture.authority.token())?,
            )
            .await
            .err()
            .ok_or("malformed list request succeeded")?;
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
    running.stop().await
}

#[tokio::test]
async fn response_budgets_refuse_whole_results_at_exact_boundaries() -> TestResult {
    let fixture = Fixture::new().await?;
    let record = fixture
        .repository
        .ref_head(MAIN, fixture.authority.token(), "sdk")
        .await?
        .ok_or("missing actual head")?;
    let exact = MAIN.len()
        + record.encode()?.len()
        + "cdc-1m".len()
        + 32
        + record.home.region.as_deref().unwrap_or_default().len()
        + record.home.zone.as_deref().unwrap_or_default().len()
        + record.home.host.as_deref().unwrap_or_default().len();
    for (bytes, succeeds) in [(exact, true), (exact - 1, false)] {
        let mut bounds = limits()?;
        bounds.max_content_bytes = positive(bytes)?;
        let running = start(&fixture, bounds).await?;

        let result = running
            .client
            .get_ref_with_options(request(MAIN), options(fixture.authority.token())?)
            .await;

        if succeeds {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.err().ok_or("over-budget response succeeded")?.code,
                ErrorCode::InvalidArgument
            );
        }
        running.stop().await?;
    }
    let mut bounds = limits()?;
    bounds.max_entries = positive(1)?;
    fixture.commit_bytes(OLD).await?;
    fixture
        .repository
        .fork(
            MAIN,
            "refs/heads/_/fork",
            fixture
                .repository
                .source_request(&fixture.authority, fixture::metadata("Actual budget fork")),
        )
        .await?;
    let running = start(&fixture, bounds).await?;
    let error = running
        .client
        .list_refs_with_options(
            v1::ListRefsRequest {
                pattern: "refs/**".into(),
                ..Default::default()
            },
            options(fixture.authority.token())?,
        )
        .await
        .err()
        .ok_or("over-budget listing succeeded")?;
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    let error = running
        .client
        .get_ref_log_with_options(
            v1::GetRefLogRequest {
                name: MAIN.into(),
                ..Default::default()
            },
            options(fixture.authority.token())?,
        )
        .await
        .err()
        .ok_or("over-budget history succeeded")?;
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    running.stop().await
}

#[tokio::test]
async fn missing_authentication_and_unavailable_mutations_preserve_the_head() -> TestResult {
    let fixture = Fixture::new().await?;
    let repository = reader(&fixture).await?;
    let expected = fixture
        .repository
        .ref_head(MAIN, fixture.authority.token(), "sdk")
        .await?;
    for authenticate in [false, true] {
        let service = Arc::new(LocalRefService::new(repository.clone(), limits()?).await?);
        let running = Running::start(service, &fixture, authenticate).await?;
        let mut bad = fixture.authority.token().to_vec();
        bad[0] ^= 1;
        let credentials = if authenticate {
            vec![Vec::new(), bad]
        } else {
            vec![fixture.authority.token().to_vec()]
        };
        for token in credentials {
            let error = running
                .client
                .get_ref_with_options(request(MAIN), options(&token)?)
                .await
                .err()
                .ok_or("unauthenticated ref read succeeded")?;
            assert_eq!(error.code, ErrorCode::Unauthenticated);
        }
        if authenticate {
            let error = running
                .client
                .compare_and_swap_ref_with_options(
                    v1::CompareAndSwapRefRequest::default(),
                    options(fixture.authority.token())?,
                )
                .await
                .err()
                .ok_or("unimplemented CAS acknowledged")?;
            assert_eq!(error.code, ErrorCode::Unimplemented);
            let error = running
                .client
                .watch_refs_with_options(
                    v1::WatchRefsRequest::default(),
                    options(fixture.authority.token())?,
                )
                .await
                .err()
                .ok_or("unimplemented watch succeeded")?;
            assert_eq!(error.code, ErrorCode::Unimplemented);
        }
        running.stop().await?;
    }
    assert_eq!(
        fixture
            .repository
            .ref_head(MAIN, fixture.authority.token(), "sdk")
            .await?,
        expected
    );
    assert_eq!(
        repository
            .ref_head(MAIN, fixture.authority.token(), "sdk")
            .await?,
        expected
    );
    let repository = reader(&fixture).await?;
    let rejected = LocalRefService::new(
        Arc::new(
            Arc::try_unwrap(repository)
                .map_err(|_| "unexpected shared repository")?
                .with_read_driver(|original| original.clone()),
        ),
        limits()?,
    )
    .await;
    assert!(matches!(rejected, Err(LocalRefServiceError::Authority)));
    Ok(())
}

struct ExpiringDispatch {
    inner: Arc<NativeService>,
    until: u64,
    dispatched: Arc<AtomicBool>,
}

#[allow(refining_impl_trait)]
impl RefService for ExpiringDispatch {
    async fn get_ref(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, v1::GetRefRequest>,
    ) -> ServiceResult<v1::RefState> {
        self.dispatched.store(true, Ordering::SeqCst);
        while TokioClock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| {
                connectrpc::ConnectError::new(ErrorCode::Internal, "fixture clock unavailable")
            })?
            .as_secs()
            <= self.until
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
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
        self.inner.get_ref_log(context, request).await
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
        self.inner.list_refs(context, request).await
    }
}

#[tokio::test]
async fn identity_expiring_after_middleware_dispatch_cannot_reach_repository_data() -> TestResult {
    let fixture = Fixture::new().await?;
    let service = Arc::new(LocalRefService::new(reader(&fixture).await?, limits()?).await?);
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
    let dispatched = Arc::new(AtomicBool::new(false));
    let delayed = Arc::new(ExpiringDispatch {
        inner: service,
        until,
        dispatched: dispatched.clone(),
    });
    let running = Running::start(delayed, &fixture, true).await?;

    let error = running
        .client
        .get_ref_with_options(request(MAIN), options(&token)?)
        .await
        .err()
        .ok_or("expired dispatched token reached a ref")?;

    assert!(
        dispatched.load(Ordering::SeqCst),
        "middleware never authenticated the original request"
    );
    assert_eq!(error.code, ErrorCode::Unauthenticated);
    running.stop().await
}
