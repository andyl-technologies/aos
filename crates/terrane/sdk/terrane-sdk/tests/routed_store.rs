//! Exercises ordered routing and exact authority delivery through the public API.
//!
//! These injected children test combinator behavior and establish no physical
//! cache custody, provider conformance or native publication authority.

#![cfg(feature = "tokio")]
#![allow(
    clippy::unwrap_used,
    reason = "Fixture setup and assertions intentionally panic on failure."
)]

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
    refs::{Locality, RefLogReason, RefLogRecord, RefRecord},
};
use terrane_sdk::store::{
    ByteRange, Capabilities, CapabilityReport, ChunkPosition, ChunkUpload, Clock, ContentStore,
    ContentUpload, CorruptSubject, Durability, IdentityPrefix, RangeCapability, RefCapability,
    RefCasOutcome, RefLogAppendOutcome, RefStore, RefWatch, StoreErrorKind, StoreFailure,
    routed::{Routed, RoutingPolicy},
};

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn advance(&self, milliseconds: u64) {
        self.0.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + self.monotonic()
    }

    fn monotonic(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }

    async fn sleep(&self, duration: Duration) -> std::io::Result<()> {
        let end = self.monotonic() + duration;
        tokio::time::sleep(duration).await;
        self.0
            .fetch_max(u64::try_from(end.as_millis()).unwrap(), Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Hit,
    Absent,
    Unavailable,
    Corrupt,
    Pending,
    Denied,
}

#[derive(Debug, PartialEq)]
enum RefCall {
    Get(String),
    Cas(String, Box<(Option<RefRecord>, RefRecord)>),
    Append(String, u64, Box<RefLogRecord>),
    Read(String, u64),
    Watch(String, u64),
}

#[derive(Default)]
struct Calls {
    gets: Vec<(Identity, Option<ByteRange>)>,
    has: Vec<Vec<Identity>>,
    puts: usize,
    refs: Vec<RefCall>,
}

#[derive(Clone)]
struct Backend {
    capabilities: Capabilities,
    reply: Reply,
    held: Vec<Identity>,
    malformed_has: bool,
    retry_after: Option<Duration>,
    calls: Arc<Mutex<Calls>>,
}

fn identity(bytes: &[u8]) -> Identity {
    TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap()
}

fn body() -> Identity {
    identity(b"verified routed body")
}

fn record() -> RefRecord {
    RefRecord {
        commit: [7; 32],
        seq: 9,
        writer_epoch: 4,
        home: Locality {
            region: Some("region-a".into()),
            zone: None,
            host: None,
        },
        policy: None,
        candidate_id: Some([8; 32]),
    }
}

fn log_record() -> RefLogRecord {
    RefLogRecord {
        record: record(),
        previous_commit: Some([6; 32]),
        principal: "writer".into(),
        reason: RefLogReason::Commit,
        timestamp: 42,
        expected_previous: Some(None),
        committed_previous: None,
    }
}

impl Backend {
    fn new(reply: Reply, refs: RefCapability) -> Self {
        Self {
            capabilities: Capabilities {
                refs,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Region,
                sealed: false,
            },
            reply,
            held: vec![body()],
            malformed_has: false,
            retry_after: None,
            calls: Arc::default(),
        }
    }

    async fn response(&self, requested: &Identity) -> Result<(), StoreFailure> {
        match self.reply {
            Reply::Hit => Ok(()),
            Reply::Absent => Err(StoreFailure::new(StoreErrorKind::Absent(requested.clone()))),
            Reply::Unavailable => Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: self.retry_after,
            })),
            Reply::Corrupt => Err(StoreFailure::new(StoreErrorKind::Corrupt(
                CorruptSubject::Identity(requested.clone()),
            ))),
            Reply::Pending => std::future::pending().await,
            Reply::Denied => Err(StoreFailure::new(StoreErrorKind::Denied {
                verb: "read",
                pattern: "root".into(),
            })),
        }
    }
}

impl CapabilityReport for Backend {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[async_trait::async_trait]
impl ContentStore for Backend {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.calls.lock().unwrap().puts += 1;
        let ContentUpload::Chunk(upload) = upload else {
            panic!("unexpected upload kind")
        };
        self.response(upload.identity).await?;
        assert_eq!(upload.identity, &body());
        assert_eq!(upload.encoded, b"\0verified routed body");
        assert_eq!(upload.declared_plaintext_len, 20);
        assert_eq!(upload.position, ChunkPosition::Final);
        assert_eq!(upload.profile, &ChunkProfile::cdc_1m([7; 32]));
        Ok(upload.identity.clone())
    }

    async fn get(
        &self,
        requested: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.calls
            .lock()
            .unwrap()
            .gets
            .push((requested.clone(), range));
        self.response(requested).await?;
        if !self.held.contains(requested) {
            return Err(StoreFailure::new(StoreErrorKind::Absent(requested.clone())));
        }
        let bytes = b"\0verified routed body";
        TERRANE_V1.verify(requested, &bytes[1..]).unwrap();
        let range = range.unwrap_or(ByteRange {
            start: 0,
            length: bytes.len() as u64,
        });
        let end = range.start.checked_add(range.length).unwrap();
        Ok(bytes[usize::try_from(range.start).unwrap()..usize::try_from(end).unwrap()].to_vec())
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.calls.lock().unwrap().has.push(identities.to_vec());
        if matches!(self.reply, Reply::Absent) {
            return Ok(vec![false; identities.len()]);
        }
        self.response(identities.first().unwrap()).await?;
        if self.malformed_has {
            return Ok(Vec::new());
        }
        Ok(identities.iter().map(|id| self.held.contains(id)).collect())
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Ok(self.held.clone())
    }
}

struct Watch(VecDeque<RefLogRecord>);

#[async_trait::async_trait]
impl RefWatch for Watch {
    async fn next(&mut self) -> Result<Option<RefLogRecord>, StoreFailure> {
        Ok(self.0.pop_front())
    }
}

#[async_trait::async_trait]
impl RefStore for Backend {
    type Watch = Watch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.calls
            .lock()
            .unwrap()
            .refs
            .push(RefCall::Get(name.into()));
        Ok(Some(record()))
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        self.calls.lock().unwrap().refs.push(RefCall::Cas(
            name.into(),
            Box::new((expect.cloned(), new.clone())),
        ));
        Ok(RefCasOutcome::Conflict(Some(Box::new(record()))))
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        self.calls.lock().unwrap().refs.push(RefCall::Append(
            name.into(),
            seq,
            Box::new(record.clone()),
        ));
        Ok(RefLogAppendOutcome::Exists)
    }

    async fn ref_log_read(&self, name: &str, from: u64) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.calls
            .lock()
            .unwrap()
            .refs
            .push(RefCall::Read(name.into(), from));
        Ok(vec![log_record()])
    }

    async fn ref_watch(&self, name: &str, from: u64) -> Result<Self::Watch, StoreFailure> {
        self.calls
            .lock()
            .unwrap()
            .refs
            .push(RefCall::Watch(name.into(), from));
        Ok(Watch(VecDeque::from([log_record()])))
    }
}

fn policy() -> RoutingPolicy {
    RoutingPolicy {
        read_budget: Duration::from_millis(100),
        child_budget: Duration::from_millis(20),
        failure_threshold: 1,
        probe_interval: Duration::from_secs(5),
        max_children: 8,
        max_membership: 16,
    }
}

fn route(
    caches: Vec<Backend>,
    authority: Backend,
    position: usize,
    clock: TestClock,
) -> Routed<Backend, Backend, TestClock> {
    Routed::new(
        caches,
        authority,
        position,
        Locality::default(),
        clock,
        policy(),
    )
    .unwrap()
}

#[tokio::test]
async fn routes_in_configured_order_and_preserves_exact_ranges() {
    let first = Backend::new(Reply::Absent, RefCapability::None);
    let after = Backend::new(Reply::Hit, RefCapability::None);
    let authority = Backend::new(Reply::Hit, RefCapability::Cas);
    let routed = route(
        vec![first.clone(), after.clone()],
        authority.clone(),
        1,
        TestClock::default(),
    );
    let range = ByteRange {
        start: 1,
        length: 8,
    };

    assert_eq!(routed.get(&body(), Some(range)).await.unwrap(), b"verified");
    assert_eq!(
        first.calls.lock().unwrap().gets,
        vec![(body(), Some(range))]
    );
    assert_eq!(
        authority.calls.lock().unwrap().gets,
        vec![(body(), Some(range))]
    );
    assert!(after.calls.lock().unwrap().gets.is_empty());
}

#[tokio::test]
async fn corrupt_and_pending_children_fall_through_under_real_timers() {
    let corrupt = Backend::new(Reply::Corrupt, RefCapability::None);
    let pending = Backend::new(Reply::Pending, RefCapability::None);
    let authority = Backend::new(Reply::Hit, RefCapability::Cas);
    let routed = route(
        vec![corrupt.clone(), pending.clone()],
        authority.clone(),
        2,
        TestClock::default(),
    );

    assert_eq!(
        routed.get(&body(), None).await.unwrap(),
        b"\0verified routed body"
    );
    assert_eq!(corrupt.calls.lock().unwrap().gets.len(), 1);
    assert_eq!(pending.calls.lock().unwrap().gets.len(), 1);
    assert_eq!(authority.calls.lock().unwrap().gets.len(), 1);
}

#[tokio::test]
async fn clones_share_open_circuits_and_one_scheduled_probe() {
    let failed = Backend::new(Reply::Unavailable, RefCapability::None);
    let authority = Backend::new(Reply::Hit, RefCapability::Cas);
    let clock = TestClock::default();
    let routed = route(vec![failed.clone()], authority, 1, clock.clone());
    let cloned = routed.clone();

    routed.get(&body(), None).await.unwrap();
    cloned.get(&body(), None).await.unwrap();
    assert_eq!(failed.calls.lock().unwrap().gets.len(), 1);
    clock.advance(5000);
    let id = body();
    let (left, right) = tokio::join!(routed.get(&id, None), cloned.get(&id, None));
    left.unwrap();
    right.unwrap();
    assert_eq!(failed.calls.lock().unwrap().gets.len(), 2);
}

#[tokio::test]
async fn whole_request_deadline_never_attempts_a_later_child() {
    let first = Backend::new(Reply::Pending, RefCapability::None);
    let second = Backend::new(Reply::Pending, RefCapability::None);
    let authority = Backend::new(Reply::Hit, RefCapability::Cas);
    let mut limits = policy();
    limits.read_budget = Duration::from_millis(30);
    let routed = Routed::new(
        vec![first, second],
        authority.clone(),
        2,
        Locality::default(),
        TestClock::default(),
        limits,
    )
    .unwrap();

    assert!(matches!(
        routed.get(&body(), None).await.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    assert!(authority.calls.lock().unwrap().gets.is_empty());
}

#[tokio::test]
async fn membership_queries_only_unresolved_identities_without_inventing_absence() {
    let mut first = Backend::new(Reply::Hit, RefCapability::None);
    let mut second = first.clone();
    second.calls = Arc::default();
    let other = identity(b"other");
    first.held = vec![body()];
    second.held = vec![other.clone()];
    let authority = Backend::new(Reply::Hit, RefCapability::Cas);
    let routed = route(
        vec![first.clone(), second.clone()],
        authority.clone(),
        2,
        TestClock::default(),
    );

    assert_eq!(
        routed.has(&[body(), other.clone(), body()]).await.unwrap(),
        vec![true; 3]
    );
    assert_eq!(second.calls.lock().unwrap().has, vec![vec![other]]);
    assert!(authority.calls.lock().unwrap().has.is_empty());

    let mut malformed = Backend::new(Reply::Hit, RefCapability::None);
    malformed.malformed_has = true;
    let mut absent = Backend::new(Reply::Hit, RefCapability::Cas);
    absent.held.clear();
    let routed = route(vec![malformed], absent, 1, TestClock::default());
    assert!(matches!(
        routed.has(&[body()]).await.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
}

#[tokio::test]
async fn denial_is_terminal_and_upload_and_ref_operations_reach_only_authority() {
    let cache = Backend::new(Reply::Denied, RefCapability::None);
    let authority = Backend::new(Reply::Hit, RefCapability::Cas);
    let routed = route(
        vec![cache.clone()],
        authority.clone(),
        1,
        TestClock::default(),
    );
    assert!(matches!(
        routed.get(&body(), None).await.unwrap_err().kind(),
        StoreErrorKind::Denied { .. }
    ));
    assert!(authority.calls.lock().unwrap().gets.is_empty());

    let id = body();
    let profile = ChunkProfile::cdc_1m([7; 32]);
    assert_eq!(
        routed
            .put(ContentUpload::Chunk(ChunkUpload {
                encoded: b"\0verified routed body",
                identity: &id,
                declared_plaintext_len: 20,
                position: ChunkPosition::Final,
                profile: &profile,
            }))
            .await
            .unwrap(),
        id
    );
    assert_eq!(authority.calls.lock().unwrap().puts, 1);
    assert_eq!(cache.calls.lock().unwrap().puts, 0);

    let name = "refs/heads/routing-candidate";
    let old = record();
    let mut new = old.clone();
    new.seq += 1;
    let log = log_record();
    assert_eq!(routed.ref_get(name).await.unwrap(), Some(old.clone()));
    assert_eq!(
        routed.ref_cas(name, Some(&old), &new).await.unwrap(),
        RefCasOutcome::Conflict(Some(Box::new(old.clone())))
    );
    assert_eq!(
        routed.ref_log_append(name, 23, &log).await.unwrap(),
        RefLogAppendOutcome::Exists
    );
    assert_eq!(
        routed.ref_log_read(name, 17).await.unwrap(),
        vec![log.clone()]
    );
    let mut watch = routed.ref_watch(name, 19).await.unwrap();
    assert_eq!(watch.next().await.unwrap(), Some(log.clone()));
    assert_eq!(watch.next().await.unwrap(), None);
    assert_eq!(
        authority.calls.lock().unwrap().refs,
        vec![
            RefCall::Get(name.into()),
            RefCall::Cas(name.into(), Box::new((Some(old), new))),
            RefCall::Append(name.into(), 23, Box::new(log)),
            RefCall::Read(name.into(), 17),
            RefCall::Watch(name.into(), 19),
        ]
    );
    assert!(cache.calls.lock().unwrap().refs.is_empty());
}

#[test]
fn rejects_two_authorities_missing_authority_and_invalid_bounds() {
    let authority = Backend::new(Reply::Hit, RefCapability::Cas);
    let cache = Backend::new(Reply::Hit, RefCapability::None);
    let open = |caches, authority, position, limits| {
        Routed::new(
            caches,
            authority,
            position,
            Locality::default(),
            TestClock::default(),
            limits,
        )
    };
    assert!(open(vec![authority.clone()], authority.clone(), 1, policy()).is_err());
    assert!(open(vec![cache.clone()], cache.clone(), 1, policy()).is_err());
    assert!(open(vec![cache.clone()], authority.clone(), 2, policy()).is_err());
    let mut limits = policy();
    limits.read_budget = Duration::ZERO;
    assert!(open(vec![cache.clone()], authority.clone(), 1, limits).is_err());
    let mut limits = policy();
    limits.max_children = 1;
    assert!(open(vec![cache], authority, 1, limits).is_err());
}

#[tokio::test]
async fn exhausted_reads_preserve_shortest_reported_retry_without_claiming_absence() {
    let mut slow = Backend::new(Reply::Unavailable, RefCapability::None);
    slow.retry_after = Some(Duration::from_secs(9));
    let mut fast = Backend::new(Reply::Unavailable, RefCapability::None);
    fast.retry_after = Some(Duration::from_secs(2));
    let authority = Backend::new(Reply::Absent, RefCapability::Cas);
    let clock = TestClock::default();
    let routed = Routed::new(
        vec![fast, slow],
        authority,
        2,
        Locality::default(),
        clock.clone(),
        policy(),
    )
    .unwrap();

    let get = routed.get(&body(), None).await.unwrap_err();
    clock.advance(5000);
    let has = routed.has(&[body()]).await.unwrap_err();

    for error in [get, has] {
        assert!(
            matches!(error.kind(), StoreErrorKind::Unavailable { retry_after: Some(wait) } if *wait == Duration::from_secs(2))
        );
    }
}

#[tokio::test]
async fn authority_failure_and_pending_upload_never_acknowledge_or_write_a_cache() {
    for reply in [Reply::Unavailable, Reply::Pending] {
        let cache = Backend::new(Reply::Hit, RefCapability::None);
        let authority = Backend::new(reply, RefCapability::Cas);
        let routed = Routed::new(
            vec![cache.clone()],
            authority.clone(),
            1,
            Locality::default(),
            TestClock::default(),
            policy(),
        )
        .unwrap();
        let id = body();
        let profile = ChunkProfile::cdc_1m([7; 32]);
        let upload = ContentUpload::Chunk(ChunkUpload {
            identity: &id,
            encoded: b"\0verified routed body",
            declared_plaintext_len: 20,
            position: ChunkPosition::Final,
            profile: &profile,
        });

        let outcome = tokio::time::timeout(Duration::from_millis(20), routed.put(upload)).await;

        match reply {
            Reply::Unavailable => assert!(matches!(
                outcome.unwrap().unwrap_err().kind(),
                StoreErrorKind::Unavailable { .. }
            )),
            Reply::Pending => assert!(outcome.is_err()),
            _ => unreachable!(),
        }
        assert_eq!(authority.calls.lock().unwrap().puts, 1);
        assert_eq!(cache.calls.lock().unwrap().puts, 0);
    }
}
