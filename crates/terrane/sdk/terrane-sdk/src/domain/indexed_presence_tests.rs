//! Checks scoped index routing without content reads or manufactured Guard proof.
//!
//! These enforcement-layer decisions isolate the domain wrapper. They establish
//! neither current repository authorization nor native index conformance.

#![allow(
    clippy::unwrap_used,
    reason = "In-memory fixture assertions intentionally panic."
)]

use std::{
    collections::BTreeSet,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

use terrane_format::{
    auth::Verb,
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
    refs::Locality,
};

use super::{DomainAccess, DomainBinding, DomainStore};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, Durability,
    IdentityPrefix, IndexedContent, MAX_INDEXED_HASHES, RangeCapability, RefCapability,
    StoreErrorKind, StoreFailure,
};

#[derive(Clone, Copy)]
enum Reply {
    Exact,
    Short,
    Long,
    Failure,
}

struct IndexOnly {
    capabilities: Capabilities,
    present: BTreeSet<Digest>,
    queries: Mutex<Vec<Vec<Digest>>>,
    reply: Reply,
}

impl IndexOnly {
    fn new(present: &[Digest], reply: Reply) -> Self {
        Self {
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
            present: present.iter().copied().collect(),
            queries: Mutex::new(Vec::new()),
            reply,
        }
    }
}

impl CapabilityReport for IndexOnly {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for IndexOnly {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("membership must never write content")
    }

    async fn get(&self, _: &Identity, _: Option<ByteRange>) -> Result<Vec<u8>, StoreFailure> {
        panic!("membership must never read a content body")
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("membership must never fall back to ordinary has")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("membership must never discover content by listing")
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl IndexedContent for IndexOnly {
    async fn indexed_presence(&self, hashes: &[Digest]) -> Result<Vec<bool>, StoreFailure> {
        self.queries.lock().unwrap().push(hashes.to_vec());
        let mut present: Vec<_> = hashes
            .iter()
            .map(|hash| self.present.contains(hash))
            .collect();
        match self.reply {
            Reply::Exact => {}
            Reply::Short => {
                present.pop();
            }
            Reply::Long => present.push(true),
            Reply::Failure => {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        }
        Ok(present)
    }
}

fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("in-memory index operation must finish without I/O"),
    }
}

fn identity(bytes: &[u8]) -> Identity {
    TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap()
}

fn decision(domain: &str, readable: &[Identity]) -> DomainAccess {
    DomainAccess::authorized(
        DomainBinding {
            domain: domain.into(),
            reference: "refs/heads/main".into(),
            root: TERRANE_V1.calculate(IdentityKind::Node, b"scope").unwrap(),
            path: b"/".to_vec(),
        },
        Verb::Read,
        "index-scope-fixture".into(),
        [1; 16],
    )
    .unwrap()
    .with_read_identities(readable.to_vec())
}

#[test]
fn scoped_indexed_presence_filters_unreachable_hashes_before_index_query() {
    let readable = identity(b"readable");
    let missing = identity(b"readable but absent");
    let forbidden = identity(b"present outside the authorized path");
    let a = readable.terrane_v1_digest().unwrap();
    let b = missing.terrane_v1_digest().unwrap();
    let c = forbidden.terrane_v1_digest().unwrap();
    let store = DomainStore::new("public".into(), IndexOnly::new(&[a, c], Reply::Exact)).unwrap();
    let access = decision("public", &[readable, missing]);

    let present = ready(store.indexed_presence(&access, &[c, a, b, a, c])).unwrap();

    assert_eq!(present, [false, true, false, true, false]);
    assert_eq!(*store.backend.queries.lock().unwrap(), [vec![a, b, a]]);
}

#[test]
fn scoped_indexed_presence_bounds_empty_root_only_and_foreign_requests() {
    let readable = identity(b"selected");
    let hash = readable.terrane_v1_digest().unwrap();
    let store = DomainStore::new("public".into(), IndexOnly::new(&[hash], Reply::Exact)).unwrap();
    let access = decision("public", std::slice::from_ref(&readable));
    let root_only = decision("public", &[]);
    let foreign = decision("private:other", &[readable]);

    assert!(
        ready(store.indexed_presence(&access, &[]))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ready(store.indexed_presence(&root_only, &[hash])).unwrap(),
        [false]
    );
    let denied = ready(store.indexed_presence(&foreign, &[hash])).unwrap_err();
    let excessive =
        ready(store.indexed_presence(&access, &vec![hash; MAX_INDEXED_HASHES + 1])).unwrap_err();

    assert!(matches!(denied.kind(), StoreErrorKind::Denied { .. }));
    assert!(matches!(excessive.kind(), StoreErrorKind::Invalid(_)));
    assert!(store.backend.queries.lock().unwrap().is_empty());
}

#[test]
fn scoped_indexed_presence_rejects_short_long_and_failed_index_replies() {
    let readable = identity(b"selected");
    let hash = readable.terrane_v1_digest().unwrap();
    let access = decision("public", &[readable]);

    for reply in [Reply::Short, Reply::Long, Reply::Failure] {
        let store = DomainStore::new("public".into(), IndexOnly::new(&[hash], reply)).unwrap();

        let error = ready(store.indexed_presence(&access, &[hash, hash])).unwrap_err();

        match reply {
            Reply::Short | Reply::Long => {
                assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
            }
            Reply::Failure => assert_eq!(error.kind(), &StoreErrorKind::Unsupported),
            Reply::Exact => unreachable!(),
        }
        assert_eq!(*store.backend.queries.lock().unwrap(), [vec![hash, hash]]);
    }
}

#[test]
fn scoped_indexed_presence_accepts_maximum_request_order_and_duplicates() {
    let readable = identity(b"selected");
    let hash = readable.terrane_v1_digest().unwrap();
    let store = DomainStore::new("public".into(), IndexOnly::new(&[hash], Reply::Exact)).unwrap();
    let access = decision("public", &[readable]);
    let hashes: Vec<_> = (0..MAX_INDEXED_HASHES)
        .map(|index| if index % 3 == 0 { [0; 32] } else { hash })
        .collect();

    let present = ready(store.indexed_presence(&access, &hashes)).unwrap();

    assert_eq!(
        present,
        (0..MAX_INDEXED_HASHES)
            .map(|index| index % 3 != 0)
            .collect::<Vec<_>>()
    );
    let queries = store.backend.queries.lock().unwrap();
    assert_eq!(queries.len(), 1);
    assert_eq!(
        queries[0],
        hashes
            .into_iter()
            .filter(|digest| *digest == hash)
            .collect::<Vec<_>>()
    );
}
