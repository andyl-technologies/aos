//! Verifies routes whose actual child types expose no ref interface.

use super::*;

#[derive(Clone)]
struct ContentOnly(Backend);

impl CapabilityReport for ContentOnly {
    fn capabilities(&self) -> &Capabilities {
        self.0.capabilities()
    }
}

#[async_trait::async_trait]
impl ContentStore for ContentOnly {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.0.put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.0.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.0.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.0.list(prefix).await
    }
}

#[tokio::test]
async fn content_only_route_preserves_order_without_any_write_destination() {
    let first = Backend::new(Reply::Absent, RefCapability::None);
    let last = Backend::new(Reply::Hit, RefCapability::None);
    let mut bounded = policy();
    bounded.max_children = 2;
    let routed = Routed::cache_only(
        vec![ContentOnly(first.clone()), ContentOnly(last.clone())],
        Locality::default(),
        TestClock::default(),
        bounded,
    )
    .unwrap();
    assert_eq!(routed.capabilities().refs, RefCapability::None);

    let range = ByteRange {
        start: 1,
        length: 8,
    };
    assert_eq!(routed.get(&body(), Some(range)).await.unwrap(), b"verified");
    assert_eq!(first.calls.lock().unwrap().gets, [(body(), Some(range))]);
    assert_eq!(last.calls.lock().unwrap().gets, [(body(), Some(range))]);
    assert_eq!(
        routed
            .has(&[body(), identity(b"missing"), body()])
            .await
            .unwrap(),
        [true, false, true]
    );

    let id = body();
    let profile = ChunkProfile::cdc_1m([7; 32]);
    let result = routed
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded: b"\0verified routed body",
            identity: &id,
            declared_plaintext_len: 20,
            position: ChunkPosition::Final,
            profile: &profile,
        }))
        .await;
    assert!(matches!(
        result.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    let prefix = IdentityPrefix {
        kind: IdentityKind::Chunk,
        digest_prefix: Vec::new(),
    };
    assert!(matches!(
        routed.list(&prefix).await.unwrap_err().kind(),
        StoreErrorKind::Unsupported
    ));
    for child in [&first, &last] {
        assert_eq!(child.calls.lock().unwrap().puts, 0);
        assert!(child.calls.lock().unwrap().refs.is_empty());
    }
}

#[tokio::test]
async fn content_only_route_never_converts_failed_or_unqueried_children_into_absence() {
    let failing = Backend::new(Reply::Pending, RefCapability::None);
    let absent = Backend::new(Reply::Absent, RefCapability::None);
    let routed = Routed::cache_only(
        vec![ContentOnly(failing.clone()), ContentOnly(absent.clone())],
        Locality::default(),
        TestClock::default(),
        policy(),
    )
    .unwrap();

    assert!(matches!(
        routed.get(&body(), None).await.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    assert!(matches!(
        routed.clone().has(&[body()]).await.unwrap_err().kind(),
        StoreErrorKind::Unavailable { .. }
    ));
    assert_eq!(failing.calls.lock().unwrap().gets.len(), 1);
    assert!(failing.calls.lock().unwrap().has.is_empty());
    assert_eq!(absent.calls.lock().unwrap().has.len(), 1);

    let healthy = Routed::cache_only(
        vec![ContentOnly(absent)],
        Locality::default(),
        TestClock::default(),
        policy(),
    )
    .unwrap();
    assert!(
        matches!(healthy.get(&body(), None).await.unwrap_err().kind(), StoreErrorKind::Absent(id) if id == &body())
    );
    assert_eq!(
        healthy.has(&[body(), body()]).await.unwrap(),
        [false, false]
    );
    assert!(healthy.has(&[]).await.unwrap().is_empty());
}

#[test]
fn content_only_route_rejects_authority_claims_empty_routes_and_invalid_resources() {
    let construct = |children, bounds| {
        Routed::cache_only(children, Locality::default(), TestClock::default(), bounds)
    };
    assert!(construct(Vec::<ContentOnly>::new(), policy()).is_err());
    assert!(
        construct(
            vec![ContentOnly(Backend::new(Reply::Hit, RefCapability::Cas))],
            policy()
        )
        .is_err()
    );
    let child = ContentOnly(Backend::new(Reply::Hit, RefCapability::None));
    let mut too_many = policy();
    too_many.max_children = 1;
    assert!(construct(vec![child.clone(), child.clone()], too_many).is_err());
    let mut zero = policy();
    zero.child_budget = Duration::ZERO;
    assert!(construct(vec![child.clone()], zero).is_err());
    let mut excessive = policy();
    excessive.child_budget = excessive.read_budget + Duration::from_millis(1);
    assert!(construct(vec![child], excessive).is_err());
}
