//! Exercises read-only loading with independently assembled canonical wire data.

mod source;
mod source_failures;
mod wire;

use super::*;
use crate::store::*;
use std::error::Error as _;
use std::sync::Mutex;
use terrane_core::identity::{Identity, IdentityKind};
use terrane_core::refs::Locality;
use terrane_core::tree_format::{NodeItems, TreeUse, decode_node_for};
use wire::*;

const MINIMUM: u64 = CDC_1M_MIN as u64;
const REVISIONS: SemanticRevisions = SemanticRevisions {
    property: 3,
    attribute: 2,
    tree: 1,
};

/// Requires a fixture value while retaining a rejected Result's diagnostics.
pub(super) trait FixtureValue {
    /// The value required by the fixture's valid baseline or assertion.
    type Value;

    /// Panics when the fixture is rejected, retaining its diagnostic.
    fn require(self) -> Self::Value;
}

impl<T, E: fmt::Debug> FixtureValue for Result<T, E> {
    type Value = T;

    fn require(self) -> T {
        self.unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
    }
}

impl<T> FixtureValue for Option<T> {
    type Value = T;

    fn require(self) -> T {
        self.unwrap_or_else(|| panic!("required fixture value is absent"))
    }
}

#[test]
fn load_source_reads_unbound_namespace_without_auxiliary_reads() {
    source::prove_auxiliary_independence();
}

#[test]
fn load_source_preserves_shared_grafts_and_internal_physical_contexts() {
    source::prove_physical_contexts();
}

#[test]
fn load_source_keeps_typed_source_failures_and_selected_revisions() {
    source_failures::prove_failures();
}

struct ReadOnly {
    nodes: BTreeMap<Digest, Vec<u8>>,
    gets: Mutex<Vec<Digest>>,
    returned_bytes: Mutex<usize>,
    failure: Option<(Digest, StoreErrorKind)>,
    capabilities: Capabilities,
}

impl ReadOnly {
    fn new(nodes: BTreeMap<Digest, Vec<u8>>) -> Self {
        Self {
            nodes,
            gets: Mutex::new(Vec::new()),
            returned_bytes: Mutex::new(0),
            failure: None,
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
}

impl CapabilityReport for ReadOnly {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for ReadOnly {
    async fn put(&self, _: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        panic!("loader wrote content")
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        assert_eq!(identity.kind(), IdentityKind::Node);
        assert_eq!(range, None);
        let node = identity
            .terrane_v1_digest()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
        self.gets
            .lock()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .push(node);
        if let Some((subject, kind)) = &self.failure
            && *subject == node
        {
            return Err(StoreFailure::with_source(
                kind.clone(),
                std::io::Error::other("retained backend witness"),
            ));
        }
        self.nodes
            .get(&node)
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))
            .inspect(|bytes| {
                *self.returned_bytes.lock().require() += bytes.len();
            })
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("loader queried membership")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("loader listed storage")
    }
}

fn ready<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("fixture store completes synchronously"),
    }
}

fn loaded(store: &ReadOnly, owner: Digest) -> Loaded {
    ready(load(store, owner, "uid", REVISIONS, MINIMUM))
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
}

fn refused(fixture: Fixture) -> ErrorKind {
    let store = ReadOnly::new(fixture.nodes);
    match ready(load(&store, fixture.owner, "uid", REVISIONS, MINIMUM)) {
        Err(error) => error.kind(),
        Ok(raw) => match raw.sources() {
            Err(error) => error.kind(),
            Ok(source) => match raw.prepare(&source.trees) {
                Err(error) => error.kind(),
                Ok(_) => panic!("invalid graph prepared"),
            },
        },
    }
}

fn requested_bytes(fixture: &Fixture) -> usize {
    fixture
        .expected_requests
        .iter()
        .map(|node| fixture.nodes[node].len())
        .sum()
}

fn assert_requests(store: &ReadOnly, expected: &BTreeSet<Digest>) {
    let actual = store
        .gets
        .lock()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(actual.len(), expected.len());
    assert_eq!(actual.iter().copied().collect::<BTreeSet<_>>(), *expected);
}

#[test]
fn index_loader_loads_bound_hierarchical_graph_without_mutation() {
    let fixture = Fixture::small();
    let mut stored = fixture.nodes.clone();
    let unrelated = store_node(
        &mut stored,
        leaf(&[(b"unrelated".to_vec(), terminal([9; 32]))], None),
    );
    assert!(!fixture.expected_requests.contains(&unrelated));
    let store = ReadOnly::new(stored);
    let raw = loaded(&store, fixture.owner);
    let sources = raw
        .sources()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let prepared = raw
        .prepare(&sources.trees)
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));

    assert_eq!(raw.owner(), fixture.owner);
    assert_eq!(raw.index_root(), fixture.primary);
    assert_eq!(sources.trees.len(), 2);
    assert_eq!(raw.loading().namespace_roots, 3);
    // Literal graph: owner + two child occurrences, and nine auxiliary
    // visits (I, G, three owner routes, four shared child-route visits).
    // Only nine distinct addresses are fetched; owner binding adds one decode.
    assert_eq!(
        raw.loading(),
        Loading {
            gets: 9,
            fetched_bytes: requested_bytes(&fixture),
            identity_checks: 12,
            node_decodes: 13,
            namespace_roots: 3,
            carrier_checks: 9,
        }
    );
    assert_requests(&store, &fixture.expected_requests);
    // Reconstruction owns two distinct physical trees, one leaf apiece.
    assert_eq!(
        sources.work,
        Reconstruction {
            node_decodes: 4,
            identity_checks: 2,
            trees: 2,
            entries: 7,
            compared_nodes: 2,
        }
    );
    assert!(raw.loading().identity_checks > raw.loading().gets);
    assert_eq!(
        store
            .gets
            .lock()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .len(),
        raw.loading().gets
    );
    assert_eq!(prepared.preparation().verification.candidates, 2);
    assert_eq!(prepared.preparation().verification.missing_objects, 1);

    let candidates = prepared
        .candidates(b"\x01")
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(candidates.rows.len(), 1);
    let occurrences = candidates.rows[0]
        .occurrences()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(occurrences.rows.len(), 3);
    assert_eq!(
        occurrences
            .rows
            .iter()
            .map(|row| row.hops.len())
            .collect::<Vec<_>>(),
        vec![0, 1, 1]
    );
    let missing = prepared
        .all_missing()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(missing.rows.len(), 1);
    assert_eq!(
        missing.rows[0]
            .occurrences()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .rows
            .len(),
        3
    );
    assert_eq!(
        prepared
            .candidates(b"\x02")
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .rows[0]
            .occurrences()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .rows
            .len(),
        1
    );
    assert_eq!(
        prepared
            .candidates(b"\x03")
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .rows
            .len(),
        0
    );

    // Reconstruction is paid anew; preparation and queries never read the store.
    let again = raw
        .sources()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(again.work, sources.work);
    assert!(sources.work.entries > 0);
    assert_eq!(
        store
            .gets
            .lock()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .len(),
        raw.loading().gets
    );

    let roles = Fixture::shared_roles();
    let fetched_bytes = requested_bytes(&roles);
    let store = ReadOnly::new(roles.nodes);
    let raw = loaded(&store, roles.owner);
    let source = raw
        .sources()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    // I and G select different owner routes; both reach the same child P.
    assert_eq!(
        raw.loading(),
        Loading {
            gets: 8,
            fetched_bytes,
            identity_checks: 9,
            node_decodes: 10,
            namespace_roots: 3,
            carrier_checks: 6,
        }
    );
    assert_eq!(
        source.work,
        Reconstruction {
            node_decodes: 6,
            identity_checks: 3,
            trees: 3,
            entries: 4,
            compared_nodes: 3,
        }
    );
    assert_requests(&store, &roles.expected_requests);
    let prepared = raw
        .prepare(&source.trees)
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let present = prepared
        .candidates(b"\x01")
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let missing = prepared
        .all_missing()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let present = present.rows[0]
        .occurrences()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let missing = missing.rows[0]
        .occurrences()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(present.rows[0].key, b"a");
    assert_eq!(missing.rows[0].key, b"a");
    assert_eq!(present.rows[0].hops[0].key, b"p");
    assert_eq!(missing.rows[0].hops[0].key, b"m");
    assert_ne!(present.rows[0].source_root, missing.rows[0].source_root);
    assert_eq!(
        store
            .gets
            .lock()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .iter()
            .filter(|digest| **digest == roles.child)
            .count(),
        1
    );
    assert!(raw.loading().carrier_checks > raw.index.nodes.len());
}

#[test]
fn index_loader_preserves_physical_and_contextual_node_checks() {
    let fixture = Fixture::large();
    let store = ReadOnly::new(fixture.nodes.clone());
    let raw = loaded(&store, fixture.owner);
    let source = raw
        .sources()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let prepared = raw
        .prepare(&source.trees)
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert!(source.trees[&fixture.owner].root().level() > 0);
    let candidates = prepared
        .candidates(b"\x01")
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(
        candidates.rows[0]
            .occurrences()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .rows
            .len(),
        POPULATION
    );

    // Each mutation starts from the independently valid internal graph.
    for change in [
        ChildChange::Count,
        ChildChange::Weight,
        ChildChange::Separator,
        ChildChange::Level,
    ] {
        let mut corrupt = fixture.clone();
        corrupt.change_namespace_child(change);
        assert_eq!(refused(corrupt), ErrorKind::Invalid, "source {change:?}");
        let mut corrupt = fixture.clone();
        corrupt.change_route_child(change);
        assert_eq!(refused(corrupt), ErrorKind::Invalid, "route {change:?}");
    }
    let carriers = Fixture::internal_carriers();
    let store = ReadOnly::new(carriers.nodes.clone());
    let raw = loaded(&store, carriers.owner);
    let source = raw
        .sources()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let prepared = raw
        .prepare(&source.trees)
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    for root in [carriers.primary, carriers.gap] {
        let physical = decode_node_for(&carriers.nodes[&root], true, MINIMUM, TreeUse::Index)
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
        assert!(physical.level > 0);
    }
    let candidates = prepared
        .candidates(b"\x01")
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let missing = prepared
        .all_missing()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(candidates.rows.len(), POPULATION);
    assert_eq!(missing.rows.len(), POPULATION);
    for (present, absent) in candidates.rows.iter().zip(&missing.rows) {
        assert_eq!(present.object(), absent.object());
        assert_eq!(
            present
                .occurrences()
                .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
                .rows
                .len(),
            1
        );
        assert_eq!(
            absent
                .occurrences()
                .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
                .rows
                .len(),
            1
        );
    }
    for change in [
        ChildChange::Count,
        ChildChange::Weight,
        ChildChange::Separator,
        ChildChange::Level,
    ] {
        let mut corrupt = carriers.clone();
        corrupt.change_primary_child(change);
        assert_eq!(refused(corrupt), ErrorKind::Invalid, "primary {change:?}");
        let mut corrupt = carriers.clone();
        corrupt.change_gap_child(change);
        assert_eq!(refused(corrupt), ErrorKind::Invalid, "gap {change:?}");
    }
    let mut wrong_address = Fixture::small();
    wrong_address
        .nodes
        .get_mut(&wrong_address.child)
        .unwrap_or_else(|| panic!("fixture child absent"))
        .push(0);
    assert_eq!(refused(wrong_address), ErrorKind::Invalid);
    for bytes in [
        vec![0xa2, 1, 0x18, 0, 2, 0x80],
        vec![0xa2, 1, 0, 2, 0x80, 0],
    ] {
        let mut corrupt = Fixture::small();
        corrupt.replace_child(bytes);
        assert_eq!(refused(corrupt), ErrorKind::Invalid);
    }
    let mut wrong_geometry = Fixture::small();
    wrong_geometry.owner_rows[0].1 = file(OBJECT, Some(1), MINIMUM + 1, false);
    wrong_geometry.rebuild_owner();
    assert_eq!(refused(wrong_geometry), ErrorKind::Invalid);

    // The byte-identical empty leaf can be a namespace and primary in their own
    // contexts, but cannot supply a nonempty forwarding continuation or G.
    let empty = Fixture::empty_shared_contexts();
    let fetched_bytes = requested_bytes(&empty);
    let shared_empty = empty.primary;
    let empty_store = ReadOnly::new(empty.nodes);
    let raw = loaded(&empty_store, empty.owner);
    assert_eq!(
        raw.loading(),
        Loading {
            gets: 2,
            fetched_bytes,
            identity_checks: 3,
            node_decodes: 4,
            namespace_roots: 2,
            carrier_checks: 1,
        }
    );
    assert_requests(&empty_store, &empty.expected_requests);
    assert_eq!(
        empty_store
            .gets
            .lock()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .iter()
            .filter(|digest| **digest == shared_empty)
            .count(),
        1
    );
    let source = raw
        .sources()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(
        source.work,
        Reconstruction {
            node_decodes: 4,
            identity_checks: 2,
            trees: 2,
            entries: 1,
            compared_nodes: 2,
        }
    );
    assert!(
        raw.prepare(&source.trees)
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .candidates(b"\x01")
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .rows
            .is_empty()
    );
    let mut empty_route = Fixture::small();
    empty_route.replace_present_route(leaf(&[], None));
    assert_eq!(refused(empty_route), ErrorKind::Invalid);
    let mut empty_gap = Fixture::small();
    empty_gap.replace_gap(leaf(&[], None));
    assert_eq!(refused(empty_gap), ErrorKind::Invalid);

    // Cached primary bytes reused as a route still validate their new role.
    let mut wrong_role = Fixture::small();
    wrong_role.replace_present_route(leaf(
        &[(b"a".to_vec(), terminal(OBJECT))],
        Some(gap_binding(wrong_role.gap)),
    ));
    assert_eq!(refused(wrong_role), ErrorKind::Invalid);
    wire::check_cached_placement_and_limits();
    let fixture = Fixture::small();
    let store = ReadOnly::new(fixture.nodes);
    ready(loading::check_cached_context_guards(
        &store,
        fixture.owner,
        fixture.primary,
    ));
}

#[test]
fn index_loader_reports_missing_bindings_and_unavailable_evidence() {
    let mut empty_nodes = BTreeMap::new();
    let empty_owner = store_node(&mut empty_nodes, leaf(&[], None));
    let empty_store = ReadOnly::new(empty_nodes);
    let failure = ready(load(&empty_store, empty_owner, "uid", REVISIONS, MINIMUM))
        .err()
        .unwrap_or_else(|| panic!("empty owner without binding prepared"));
    assert!(matches!(failure, Error::MissingBinding(subject) if subject == empty_owner));
    assert_eq!(failure.kind(), ErrorKind::Incomplete);
    assert_requests(&empty_store, &BTreeSet::from([empty_owner]));

    let mut missing_binding = Fixture::small();
    missing_binding.owner = store_node(
        &mut missing_binding.nodes,
        leaf(&missing_binding.owner_rows, None),
    );
    assert_eq!(refused(missing_binding), ErrorKind::Incomplete);

    let fixture = Fixture::small();
    for subject in [
        fixture.owner,
        fixture.child,
        fixture.primary,
        fixture.present,
        fixture.gap,
        fixture.missing,
    ] {
        for kind in [
            StoreErrorKind::Absent(
                terrane_core::identity::TERRANE_V1
                    .from_digest(IdentityKind::Node, &subject)
                    .unwrap_or_else(|error| panic!("fixture failed: {error:?}")),
            ),
            StoreErrorKind::Unavailable { retry_after: None },
        ] {
            let mut store = ReadOnly::new(fixture.nodes.clone());
            store.failure = Some((subject, kind.clone()));
            let failure = ready(load(&store, fixture.owner, "uid", REVISIONS, MINIMUM))
                .err()
                .unwrap_or_else(|| panic!("expected fixture failure"));
            assert_eq!(failure.kind(), ErrorKind::Incomplete);
            assert_eq!(failure.subject(), Some(subject));
            let Error::Store {
                failure: original, ..
            } = &failure
            else {
                panic!("store source lost")
            };
            assert_eq!(original.kind(), &kind);
            assert_eq!(
                failure
                    .source()
                    .unwrap_or_else(|| panic!("missing diagnostic source"))
                    .source()
                    .unwrap_or_else(|| panic!("missing diagnostic source"))
                    .to_string(),
                "retained backend witness"
            );
        }
    }
    let store = ReadOnly::new(fixture.nodes);
    for revisions in [
        SemanticRevisions {
            property: 2,
            ..REVISIONS
        },
        SemanticRevisions {
            attribute: 1,
            ..REVISIONS
        },
        SemanticRevisions {
            tree: 2,
            ..REVISIONS
        },
    ] {
        assert_eq!(
            ready(load(&store, fixture.owner, "uid", revisions, MINIMUM))
                .err()
                .unwrap_or_else(|| panic!("expected fixture failure"))
                .kind(),
            ErrorKind::Unsupported
        );
    }
    assert_eq!(
        ready(load(&store, fixture.owner, "uid", REVISIONS, MINIMUM + 1))
            .err()
            .unwrap_or_else(|| panic!("expected fixture failure"))
            .kind(),
        ErrorKind::Unsupported
    );
    assert!(
        store
            .gets
            .lock()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .is_empty()
    );
}

#[test]
fn index_loader_refuses_divergent_relationships_and_keeps_work_separate() {
    for mutation in 0..16 {
        let mut fixture = Fixture::small();
        fixture.diverge(mutation);
        assert_eq!(
            refused(fixture),
            ErrorKind::Invalid,
            "relationship witness {mutation}"
        );
    }

    let fixture = Fixture::only_missing();
    let store = ReadOnly::new(fixture.nodes);
    let raw = loaded(&store, fixture.owner);
    let source = raw
        .sources()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let prepared = raw
        .prepare(&source.trees)
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let zero = prepared
        .candidates(b"\x01")
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert!(zero.rows.is_empty());
    assert_eq!(zero.work.candidates, 0);
    let missing = prepared
        .all_missing()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(missing.work.missing_rows, 1);
    let occurrences = missing.rows[0]
        .occurrences()
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    assert_eq!(occurrences.work.occurrences, 1);
    assert!(occurrences.work.route_rows > 0);
    assert!(prepared.preparation().verification.work.source_entries > 0);
    assert!(
        prepared
            .preparation()
            .verification
            .physical_work
            .node_decodes
            > 0
    );
    assert!(source.work.trees > 0);
    assert_eq!(
        raw.loading().gets,
        store
            .gets
            .lock()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
            .len()
    );
}
