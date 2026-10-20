//! Exercises bounded real Store futures, ordered errors and cancellation.

use super::super::FixtureValue;
use super::*;
use crate::store::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};
use terrane_format::refs::Locality;

struct Reads {
    ready: Mutex<BTreeSet<Digest>>,
    active: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
    failures: BTreeMap<Digest, StoreErrorKind>,
    bodies: BTreeMap<Digest, Vec<u8>>,
    capabilities: Capabilities,
}

impl Reads {
    fn new(failures: BTreeMap<Digest, StoreErrorKind>) -> Self {
        Self {
            ready: Mutex::new(BTreeSet::new()),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            failures,
            bodies: BTreeMap::new(),
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::WholeObjectOnly,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }

    fn release(&self, nodes: &[Digest]) {
        self.ready.lock().require().extend(nodes.iter().copied());
    }
}

struct Active<'a>(&'a Reads);

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl CapabilityReport for Reads {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for Reads {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("read frontier wrote content")
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        assert_eq!(identity.kind(), IdentityKind::Node);
        assert_eq!(range, None);
        let node = identity.terrane_v1_digest().require();
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        let _active = Active(self);
        poll_fn(|_| {
            if self.ready.lock().require().contains(&node) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        match self.failures.get(&node) {
            Some(kind) => Err(StoreFailure::with_source(
                kind.clone(),
                std::io::Error::other("exact frontier backend failure"),
            )),
            None => Ok(self
                .bodies
                .get(&node)
                .cloned()
                .unwrap_or_else(|| node.to_vec())),
        }
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("read frontier requested membership")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("read frontier enumerated storage")
    }
}

fn poll<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn delayed_first_read_polls_all_eight_and_bounds_completed_buffer() {
    let store = Reads::new(BTreeMap::new());
    let nodes = (0..WIDTH)
        .map(|n| [u8::try_from(n).require(); 32])
        .collect::<Vec<_>>();
    let mut frontier = Frontier::default();
    {
        let mut fill = Box::pin(frontier.fill(&store, &nodes));
        assert!(poll(fill.as_mut()).is_pending());
        assert_eq!(store.active.load(Ordering::SeqCst), WIDTH);
        assert_eq!(store.peak.load(Ordering::SeqCst), WIDTH);
        store.release(&nodes[1..]);
        assert!(poll(fill.as_mut()).is_pending());
        assert_eq!(store.active.load(Ordering::SeqCst), 1);
        store.release(&nodes[..1]);
        assert!(matches!(poll(fill.as_mut()), Poll::Ready(Ok(()))));
    }
    assert_eq!(frontier.outcomes.len(), WIDTH);
    assert_eq!(frontier.remaining(), 0);
    assert_eq!(store.calls.load(Ordering::SeqCst), WIDTH);
    for node in &nodes {
        assert_eq!(frontier.take(node).require().require(), node.to_vec());
    }
    assert_eq!(frontier.remaining(), WIDTH);
}

#[test]
fn fast_later_failure_cannot_replace_delayed_dfs_failure() {
    let first = [1; 32];
    let later = [2; 32];
    let store = Reads::new(BTreeMap::from([
        (first, StoreErrorKind::Unavailable { retry_after: None }),
        (
            later,
            StoreErrorKind::Denied {
                verb: "get",
                pattern: "later-node".to_owned(),
            },
        ),
    ]));
    store.release(&[later]);
    let revisions = SemanticRevisions {
        property: 3,
        attribute: 2,
        tree: 1,
    };
    let mut fetcher = Fetcher::new(&store, revisions, CDC_1M_MIN as u64).require();
    let pending = vec![Visit::root(later, None, Vec::new())];
    let mut frontier = Frontier::default();
    let failure = {
        let mut read = Box::pin(fetcher.read(first, &pending, &mut frontier));
        assert!(poll(read.as_mut()).is_pending());
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        store.release(&[first]);
        match poll(read.as_mut()) {
            Poll::Ready(Err(error)) => error,
            outcome => panic!("expected original first failure: {outcome:?}"),
        }
    };
    assert_eq!(failure.subject(), Some(first));
    let Error::Store { failure, .. } = failure else {
        panic!("store cause lost")
    };
    assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
    assert!(std::error::Error::source(&failure).is_some());
    let later_failure = match frontier.take(&later).require() {
        Err(failure) => failure,
        Ok(bytes) => panic!("expected retained later failure, received {bytes:?}"),
    };
    assert_eq!(
        later_failure.kind(),
        &StoreErrorKind::Denied {
            verb: "get",
            pattern: "later-node".to_owned()
        }
    );
}

#[test]
fn cancellation_drops_every_started_store_future() {
    let store = Arc::new(Reads::new(BTreeMap::new()));
    let nodes = [[1; 32], [2; 32], [3; 32]];
    let mut frontier = Frontier::default();
    {
        let mut fill = Box::pin(frontier.fill(store.as_ref(), &nodes));
        assert!(poll(fill.as_mut()).is_pending());
        assert_eq!(store.active.load(Ordering::SeqCst), 3);
    }
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    store.release(&nodes);
    assert_eq!(store.calls.load(Ordering::SeqCst), 3);
    assert!(frontier.outcomes.is_empty());
}

#[test]
fn invalid_prospective_branches_issue_no_reads() {
    let store = Reads::new(BTreeMap::new());
    let first = [1; 32];
    let invalid = [2; 32];
    store.release(&[first]);
    let revisions = SemanticRevisions {
        property: 3,
        attribute: 2,
        tree: 1,
    };
    let mut fetcher = Fetcher::new(&store, revisions, CDC_1M_MIN as u64).require();
    let pending = vec![
        Visit::root(invalid, None, vec![invalid]),
        Visit::root(invalid, None, vec![[9; 32]; MAX_GRAFT_DEPTH + 1]),
        Visit {
            node: invalid,
            is_root: false,
            role: None,
            physical: vec![invalid],
            roots: Vec::new(),
        },
        Visit {
            node: invalid,
            is_root: false,
            role: None,
            physical: vec![[9; 32]; usize::from(MAX_TREE_LEVEL) + 1],
            roots: Vec::new(),
        },
    ];
    let mut frontier = Frontier::default();
    let mut read = Box::pin(fetcher.read(first, &pending, &mut frontier));
    assert!(matches!(poll(read.as_mut()), Poll::Ready(Ok(_))));
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn long_cached_duplicate_and_invalid_prefixes_defer_distant_subjects() {
    for population in [WIDTH, 1_024, 4_096] {
        for prefix in ["cached", "duplicate", "invalid"] {
            let first = [1; 32];
            let repeated = [2; 32];
            let distant = [3; 32];
            let store = Reads::new(BTreeMap::from([(
                distant,
                StoreErrorKind::Unavailable { retry_after: None },
            )]));
            store.release(&[first, repeated]);
            let revisions = SemanticRevisions {
                property: 3,
                attribute: 2,
                tree: 1,
            };
            let mut fetcher = Fetcher::new(&store, revisions, CDC_1M_MIN as u64).require();
            if prefix == "cached" {
                fetcher.bytes.insert(repeated, repeated.to_vec());
            }
            let mut pending = vec![Visit::root(distant, None, Vec::new())];
            pending.extend((0..population).map(|_| {
                let roots = if prefix == "invalid" {
                    vec![repeated]
                } else {
                    Vec::new()
                };
                Visit::root(repeated, None, roots)
            }));
            let mut frontier = Frontier::default();

            {
                let mut read = Box::pin(fetcher.read(first, &pending, &mut frontier));
                assert!(
                    matches!(poll(read.as_mut()), Poll::Ready(Ok(_))),
                    "{prefix} prefix of {population} scheduled the distant blocked subject"
                );
            }
            let expected = if prefix == "duplicate" { 2 } else { 1 };
            assert_eq!(store.calls.load(Ordering::SeqCst), expected);
            assert_eq!(fetcher.work.gets, expected);
            assert!(!frontier.contains(&distant));
            assert_eq!(frontier.outcomes.len(), usize::from(prefix == "duplicate"));

            if prefix != "invalid" {
                let mut read = Box::pin(fetcher.read(repeated, &[], &mut frontier));
                assert!(matches!(
                    poll(read.as_mut()),
                    Poll::Ready(Ok(bytes)) if bytes == repeated.to_vec()
                ));
                assert_eq!(store.calls.load(Ordering::SeqCst), expected);
            }

            // Deferral changes acquisition timing, not the subject or failure.
            store.release(&[distant]);
            let failure = {
                let mut read = Box::pin(fetcher.read(distant, &[], &mut frontier));
                match poll(read.as_mut()) {
                    Poll::Ready(Err(error)) => error,
                    outcome => panic!("deferred original failure lost: {outcome:?}"),
                }
            };
            assert_eq!(failure.subject(), Some(distant));
            let Error::Store { failure, .. } = failure else {
                panic!("deferred store cause lost")
            };
            assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
            assert!(std::error::Error::source(&failure).is_some());
            assert_eq!(store.calls.load(Ordering::SeqCst), expected + 1);
        }
    }
}

#[test]
fn cached_namespace_still_checks_placement_depth_and_cycles() {
    use terrane_format::cbor;

    // An independently encoded empty root with a valid empty local binding.
    let mut bytes = vec![0xa3, 1, 0, 2, 0x80, 3, 0xa1];
    cbor::write_text(&mut bytes, "index-roots");
    bytes.push(0xa2);
    cbor::write_text(&mut bytes, "value");
    bytes.push(0xa0);
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(0xf4);
    let owner = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)
        .require()
        .terrane_v1_digest()
        .require();
    let mut store = Reads::new(BTreeMap::new());
    store.bodies.insert(owner, bytes);
    store.release(&[owner]);
    let mut checked = Box::pin(super::super::check_source_cached_context_guards(
        &store, owner,
    ));
    assert!(matches!(poll(checked.as_mut()), Poll::Ready(())));
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn unsupported_semantics_refuse_before_any_store_read() {
    let store = Reads::new(BTreeMap::new());
    let revisions = SemanticRevisions {
        property: 99,
        attribute: 2,
        tree: 1,
    };
    assert!(matches!(
        Fetcher::new(&store, revisions, CDC_1M_MIN as u64),
        Err(Error::Unsupported)
    ));
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
}
