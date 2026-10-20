//! Checks call-local relationship reuse through actual loading and preparation.
//!
//! Literal canonical fixtures provide immutable bytes, not history, authority or
//! receipts. Ordered backend GETs expose repeated work and original refusals.

#![allow(clippy::unwrap_used)]

use super::{Plan, SelectedInputs, check_relationships, plan};
use crate::guard::TreeEvidence;
use crate::indexing::{Error, ErrorKind, SemanticRevisions};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, Durability,
    IdentityPrefix, InvalidReason, RangeCapability, RefCapability, StoreErrorKind, StoreFailure,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as _;
use std::sync::Mutex;
use terrane_format::gc::publication::evidence::ConfiguredRegistryInputs;
use terrane_format::identity::{Digest, Identity, IdentityKind};
use terrane_format::properties::{self, PropertyName, RootLayer, Value};
use terrane_format::tree_format::TreeUse;

// Reuse the independently assembled source/I/P/G wires, not an index evaluator
// or an authority-bearing fixture. Compile them in this separate test context
// without widening the original fixture's visibility or changing its encodings.
#[allow(clippy::duplicate_mod)]
#[path = "../indexes/tests/wire.rs"]
mod wire;

const REVISIONS: SemanticRevisions = SemanticRevisions {
    property: 3,
    attribute: 2,
    tree: 1,
};

/// Keeps fixture construction failures as explicit test panics.
trait Required {
    type Value;

    /// Returns the expected fixture value.
    ///
    /// # Panics
    /// Panics when independent fixture construction fails.
    fn required(self) -> Self::Value;
}

impl<T, E: std::fmt::Debug> Required for Result<T, E> {
    type Value = T;

    fn required(self) -> T {
        self.unwrap_or_else(|error| panic!("relationship fixture failed: {error:?}"))
    }
}

struct ReadOnly {
    nodes: BTreeMap<Digest, Vec<u8>>,
    reads: Mutex<Vec<Digest>>,
    failure: Option<(Digest, StoreErrorKind)>,
    capabilities: Capabilities,
}

impl ReadOnly {
    fn new(nodes: BTreeMap<Digest, Vec<u8>>) -> Self {
        Self {
            nodes,
            reads: Mutex::default(),
            failure: None,
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::WholeObjectOnly,
                presign: false,
                locality: terrane_format::refs::Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }

    fn counts(&self) -> BTreeMap<Digest, usize> {
        let mut counts = BTreeMap::new();
        for subject in self.reads.lock().unwrap().iter() {
            *counts.entry(*subject).or_default() += 1;
        }
        counts
    }

    fn clear_reads(&self) {
        self.reads.lock().unwrap().clear();
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
        panic!("relationship validation wrote content")
    }

    async fn get(&self, id: &Identity, range: Option<ByteRange>) -> Result<Vec<u8>, StoreFailure> {
        assert_eq!(id.kind(), IdentityKind::Node);
        assert_eq!(range, None);
        let subject = id.terrane_v1_digest().unwrap();
        self.reads.lock().unwrap().push(subject);
        if let Some((failed, kind)) = &self.failure
            && *failed == subject
        {
            return Err(StoreFailure::with_source(
                kind.clone(),
                std::io::Error::other("original relationship backend refusal"),
            ));
        }
        self.nodes
            .get(&subject)
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(id.clone())))
    }

    async fn has(&self, _: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        panic!("relationship validation queried membership")
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("relationship validation listed storage")
    }
}

fn inputs() -> SelectedInputs {
    let mut names = PropertyName::ALL
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    SelectedInputs {
        selection: properties::selected::Selection::Active,
        registries: ConfiguredRegistryInputs {
            property_revision: 3,
            behavioral_properties: names,
            attribute_revision: 2,
            selector_revision: 1,
            tree_revision: 1,
            chunk_revision: 1,
            identity_profile: "terrane-v1".into(),
            later_properties: Vec::new(),
        },
        store: "public".into(),
        home: "local".into(),
        minimum: wire::MINIMUM,
    }
}

fn subjects(owner: Digest, attributes: &[&str], usages: &[TreeUse]) -> Plan {
    Plan {
        owners: usages
            .iter()
            .map(|usage| {
                (
                    owner,
                    attributes.iter().map(|name| (*name).to_owned()).collect(),
                    *usage,
                )
            })
            .collect(),
        revisions: REVISIONS,
    }
}

fn indexing_error(failure: &StoreFailure) -> &Error {
    failure.source().unwrap().downcast_ref::<Error>().unwrap()
}

fn all_nodes(graph: &wire::Graph, reads: usize) -> BTreeMap<Digest, usize> {
    graph
        .nodes
        .keys()
        .map(|subject| (*subject, reads))
        .collect()
}

#[tokio::test]
async fn repeated_grafts_reuse_one_complete_present_relationship() {
    let child = wire::Graph::small();
    let graph = wire::Graph::repeated();
    assert_eq!(graph.child, Some(child.owner));
    let store = ReadOnly::new(graph.nodes.clone());
    let evidence = TreeEvidence::load_tree(&store, graph.owner, &[], wire::MINIMUM)
        .await
        .unwrap();
    assert_eq!(
        evidence.nodes.keys().copied().collect::<BTreeSet<_>>(),
        graph.namespace
    );
    let selected = inputs();
    let occurrences = evidence.occurrences(wire::MINIMUM).unwrap();
    assert_eq!(occurrences.len(), 3);
    for occurrence in &occurrences {
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let effective = selected
            .selection
            .resolve(
                &layers,
                properties::Defaults {
                    store: &selected.store,
                    private_domain: &evidence.default_domain,
                    home: &selected.home,
                },
            )
            .unwrap();
        let expected = if occurrence.path == b"/h" {
            Vec::new()
        } else {
            vec!["uid"]
        };
        assert_eq!(
            effective.get(PropertyName::Index),
            Some(&Value::Names(expected))
        );
    }
    let planned = plan(&evidence, &selected).unwrap();
    assert_eq!(planned.owners.len(), 3);
    assert_eq!(
        planned
            .owners
            .iter()
            .filter(|(owner, _, _)| *owner == child.owner)
            .count(),
        2
    );
    store.clear_reads();

    check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap();

    // The parent's full routes reach both child routes, while the child's own
    // independent relationship reaches them once more. Only its duplicate
    // occurrence's otherwise identical relationship is omitted.
    assert_eq!(
        store.counts(),
        BTreeMap::from([
            (graph.owner, 1),
            (graph.primary, 1),
            (graph.present, 1),
            (graph.gap, 1),
            (graph.missing, 1),
            (child.owner, 2),
            (child.primary, 1),
            (child.present, 2),
            (child.gap, 1),
            (child.missing, 2),
        ])
    );
}

#[tokio::test]
async fn completed_relationship_reuse_stays_with_one_call_and_store() {
    let graph = wire::Graph::small();
    let planned = subjects(graph.owner, &["uid"], &[TreeUse::Ordinary; 2]);
    let store = ReadOnly::new(graph.nodes.clone());

    check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap();
    assert_eq!(store.counts(), all_nodes(&graph, 1));
    check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap();
    assert_eq!(store.counts(), all_nodes(&graph, 2));

    let mut other = ReadOnly::new(graph.nodes.clone());
    other.failure = Some((
        graph.primary,
        StoreErrorKind::Unavailable { retry_after: None },
    ));
    let failure = check_relationships(&other, &planned, wire::MINIMUM)
        .await
        .unwrap_err();
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(indexing_error(&failure).subject(), Some(graph.primary));
    assert_eq!(other.counts().get(&graph.primary), Some(&1));
}

#[tokio::test]
async fn completed_relationship_reuse_distinguishes_explicit_tree_usage() {
    let graph = wire::Graph::small();
    let store = ReadOnly::new(graph.nodes.clone());
    let planned = subjects(
        graph.owner,
        &["uid"],
        &[TreeUse::Ordinary, TreeUse::OverlayLayer],
    );

    check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap();
    assert_eq!(store.counts(), all_nodes(&graph, 2));

    let mut layered = graph.clone();
    layered.rows.push((b"z".to_vec(), vec![0xa1, 1, 5]));
    layered.rebind(Some(layered.primary), true);
    let store = ReadOnly::new(layered.nodes.clone());
    let planned = subjects(
        layered.owner,
        &["uid"],
        &[TreeUse::OverlayLayer, TreeUse::Ordinary],
    );
    let failure = check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap_err();
    assert_eq!(indexing_error(&failure).kind(), ErrorKind::Invalid);
    assert_eq!(indexing_error(&failure).subject(), Some(layered.owner));
    assert_eq!(store.counts().get(&layered.primary), Some(&1));
    assert_eq!(store.counts().get(&layered.owner), Some(&2));
}

fn two_attributes(gid: u8) -> wire::Graph {
    let mut graph = wire::Graph::small();
    let mut entry = wire::file(graph.object, None);
    entry[0] = 0xa5;
    entry.extend_from_slice(&[
        9, 0xa2, 0x63, b'g', b'i', b'd', gid, 0x63, b'u', b'i', b'd', 1,
    ]);
    graph.rows[0].1 = entry;
    let binding = wire::text(&wire::hex(graph.primary));
    let properties = wire::properties(vec![
        ("index", wire::names(&["gid", "uid"])),
        (
            "index-roots",
            wire::wrapper(
                wire::properties(vec![("gid", binding.clone()), ("uid", binding)]),
                false,
            ),
        ),
    ]);
    graph.owner = wire::insert(&mut graph.nodes, wire::leaf(&graph.rows, Some(properties)));
    graph
}

#[tokio::test]
async fn completed_relationship_reuse_distinguishes_attribute_and_full_preparation() {
    let graph = two_attributes(1);
    let planned = subjects(graph.owner, &["uid", "gid"], &[TreeUse::Ordinary; 2]);
    let store = ReadOnly::new(graph.nodes.clone());

    check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap();
    let mut expected = all_nodes(&graph, 2);
    // Rebinding leaves the previous addressed owner available but unreachable.
    expected.remove(&wire::Graph::small().owner);
    assert_eq!(store.counts(), expected);

    // Both bound I/P/G carriers remain valid; only independently recomputed gid
    // data diverges. Successful uid preparation cannot validate that attribute.
    let divergent = two_attributes(2);
    let store = ReadOnly::new(divergent.nodes.clone());
    let planned = subjects(divergent.owner, &["uid", "gid"], &[TreeUse::Ordinary]);
    let failure = check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap_err();
    assert_eq!(indexing_error(&failure).kind(), ErrorKind::Invalid);
    assert_eq!(indexing_error(&failure).subject(), Some(divergent.owner));
    assert_eq!(store.counts().get(&divergent.primary), Some(&2));
}

#[tokio::test]
async fn missing_bindings_are_rechecked_without_completed_relationship_reuse() {
    let mut graph = wire::Graph::small();
    graph.rebind(None, true);
    let store = ReadOnly::new(graph.nodes.clone());
    let planned = subjects(graph.owner, &["uid"], &[TreeUse::Ordinary; 2]);

    check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap();

    assert_eq!(store.counts(), BTreeMap::from([(graph.owner, 2)]));
    let failure = crate::indexing::load_for(
        &store,
        graph.owner,
        "uid",
        REVISIONS,
        wire::MINIMUM,
        TreeUse::Ordinary,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(failure, Error::MissingBinding(owner) if owner == graph.owner));
    assert_eq!(store.counts(), BTreeMap::from([(graph.owner, 3)]));
}

#[tokio::test]
async fn completed_relationship_reuse_cannot_cross_revisions_or_minimum() {
    let graph = wire::Graph::small();
    let store = ReadOnly::new(graph.nodes.clone());
    let mut planned = subjects(graph.owner, &["uid"], &[TreeUse::Ordinary; 2]);
    check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap();
    let before = store.counts();

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
        planned.revisions = revisions;
        let failure = check_relationships(&store, &planned, wire::MINIMUM)
            .await
            .unwrap_err();
        assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
        assert_eq!(indexing_error(&failure).kind(), ErrorKind::Unsupported);
        assert_eq!(store.counts(), before);
    }
    planned.revisions = REVISIONS;
    let failure = check_relationships(&store, &planned, wire::MINIMUM / 2)
        .await
        .unwrap_err();
    assert_eq!(failure.kind(), &StoreErrorKind::Unsupported);
    assert_eq!(store.counts(), before);
}

#[tokio::test]
async fn relationship_reuse_preserves_original_store_refusals_and_new_owner_divergence() {
    let graph = wire::Graph::small();
    let planned = subjects(graph.owner, &["uid"], &[TreeUse::Ordinary; 2]);
    let primary = terrane_format::identity::TERRANE_V1
        .from_digest(IdentityKind::Node, &graph.primary)
        .unwrap();
    for kind in [
        StoreErrorKind::Absent(primary),
        StoreErrorKind::Unavailable { retry_after: None },
        StoreErrorKind::Denied {
            verb: "get",
            pattern: "relationship witness".into(),
        },
    ] {
        let mut store = ReadOnly::new(graph.nodes.clone());
        store.failure = Some((graph.primary, kind.clone()));
        let failure = check_relationships(&store, &planned, wire::MINIMUM)
            .await
            .unwrap_err();
        assert_eq!(failure.kind(), &kind);
        if !matches!(kind, StoreErrorKind::Denied { .. }) {
            assert_eq!(indexing_error(&failure).subject(), Some(graph.primary));
            assert!(
                indexing_error(&failure)
                    .source()
                    .unwrap()
                    .source()
                    .is_some()
            );
        } else {
            assert!(failure.source().is_none());
        }
        assert_eq!(store.counts().get(&graph.primary), Some(&1));
    }

    let mut divergent = graph.clone();
    divergent.rows[0].1 = wire::file(divergent.object, Some(2));
    divergent.rebind(Some(divergent.primary), true);
    let mut nodes = graph.nodes.clone();
    nodes.extend(divergent.nodes.clone());
    let store = ReadOnly::new(nodes);
    let mut planned = subjects(graph.owner, &["uid"], &[TreeUse::Ordinary]);
    planned
        .owners
        .push((divergent.owner, vec!["uid".into()], TreeUse::Ordinary));

    let failure = check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap_err();
    assert_eq!(indexing_error(&failure).kind(), ErrorKind::Invalid);
    assert_eq!(indexing_error(&failure).subject(), Some(divergent.owner));
    assert_eq!(store.counts().get(&graph.primary), Some(&2));
}

#[tokio::test]
async fn repeated_occurrence_policy_and_structural_role_refusals_precede_reuse() {
    let mut graph = wire::Graph::repeated();
    let child = graph.child.unwrap();
    graph.rows[1].1 = wire::graft(
        child,
        Some(wire::properties(vec![(
            "index-roots",
            wire::wrapper(
                wire::properties(vec![(
                    "uid",
                    wire::text(&wire::hex(wire::Graph::small().primary)),
                )]),
                false,
            ),
        )])),
    );
    graph.rebind(Some(graph.primary), true);
    let store = ReadOnly::new(graph.nodes.clone());
    let evidence = TreeEvidence::load_tree(&store, graph.owner, &[], wire::MINIMUM)
        .await
        .unwrap();

    let failure = plan(&evidence, &inputs()).err().unwrap();
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "PROP-29" })
    );

    let mut structural = wire::Graph::small();
    structural.rows[0].1 = wire::file_with_pointer(structural.object, structural.present);
    structural.rebind(Some(structural.primary), true);
    let store = ReadOnly::new(structural.nodes.clone());
    let planned = subjects(structural.owner, &["uid"], &[TreeUse::Ordinary; 2]);
    let failure = check_relationships(&store, &planned, wire::MINIMUM)
        .await
        .unwrap_err();
    assert_eq!(indexing_error(&failure).kind(), ErrorKind::Invalid);
    assert_eq!(indexing_error(&failure).subject(), Some(structural.owner));
    assert_eq!(store.counts().get(&structural.primary), None);
}
