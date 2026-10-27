//! Checks invocation-local owner reuse against uncached pending-view preparation.
//!
//! Canonical staged Nodes pass the actual evidence loader. Fixture commits pass
//! the real token and signature verifier; neither fixture constructs completed
//! history, Original evidence, producer authority or publication receipts.

use std::collections::BTreeMap;
use std::error::Error as _;

use super::owner_preparation::OwnerPreparation;
use super::{PendingViewUse, SelectedInputs};
use crate::guard::{StagedUpload, TreeEvidence};
use crate::ref_advance::tests::{fixture, request, token};
use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};
use terrane_format::auth::{Request, Token, Verb};
use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::properties::{self, Defaults, PropertyName, RootLayer, Value};
use terrane_format::provenance::{VerifiedCommit, sign};
use terrane_format::refs::Locality;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{
    Attribute, ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const MINIMUM: u64 = 262144;
const EMPTY_NAMES: &[u8] = b"\x80";
const UID_NAMES: &[u8] = b"\x81\x63uid";

struct Graph {
    root: Digest,
    child: Digest,
    uploads: Vec<StagedUpload>,
}

fn entry(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn graft(root: Digest, index: &'static [u8]) -> Entry<'static> {
    entry(EntryKind::Tree {
        root,
        props: Some(vec![Property {
            name: "index",
            value: index,
        }]),
    })
}

fn structural_attribute(value: Entry<'static>) -> Entry<'static> {
    Entry {
        attrs: vec![Attribute {
            name: "index.occurrences",
            value: b"\x40",
        }],
        attrs_present: true,
        ..value
    }
}

impl Graph {
    /// Builds five occurrences of one child, including both sides and a present base.
    fn repeated(
        bad_role: Option<usize>,
        bad_override: Option<Property<'static>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let child = Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: entry(EntryKind::File {
                    mode: 0o644,
                    size: 1,
                    content: ContentRef::Inline([7; 32]),
                    link_id: None,
                }),
            }],
            Some(vec![Property {
                name: "index",
                value: UID_NAMES,
            }]),
            MINIMUM,
            TreeUse::Ordinary,
        )?;
        let child_id = child.root_identity();
        let mut roles = vec![
            graft(child_id, UID_NAMES),
            graft(child_id, EMPTY_NAMES),
            graft(child_id, UID_NAMES),
        ];
        if let Some(role) = bad_role {
            roles[role] = structural_attribute(roles[role].clone());
        }
        let base = roles.pop().ok_or("conflict base missing")?;
        let mut second = graft(child_id, EMPTY_NAMES);
        if let Some(property) = bad_override {
            second = entry(EntryKind::Tree {
                root: child_id,
                props: Some(vec![property]),
            });
        }
        let owner = Tree::build(
            vec![
                LeafItem {
                    key: b"a".to_vec(),
                    entry: graft(child_id, UID_NAMES),
                },
                LeafItem {
                    key: b"b".to_vec(),
                    entry: second,
                },
                LeafItem {
                    key: b"m".to_vec(),
                    entry: entry(EntryKind::Conflict {
                        candidates: roles,
                        base: Some(Some(Box::new(base))),
                    }),
                },
            ],
            Some(vec![
                Property {
                    name: "index",
                    value: EMPTY_NAMES,
                },
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "hashes",
                    value: EMPTY_NAMES,
                },
                Property {
                    name: "classify",
                    value: EMPTY_NAMES,
                },
                Property {
                    name: "strict-attrs",
                    value: b"\xf4",
                },
            ]),
            MINIMUM,
            TreeUse::Ordinary,
        )?;
        let uploads = owner
            .nodes()
            .chain(child.nodes())
            .map(|node| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes: node.encoded().to_vec(),
            })
            .collect();
        Ok(Self {
            root: owner.root_identity(),
            child: child_id,
            uploads,
        })
    }
}

/// Signs immutable fixture data without claiming owning history or current checks.
fn signed(
    graph: &Graph,
    keys: &[terrane_format::auth::IssuerKey],
) -> Result<VerifiedCommit, Box<dyn std::error::Error>> {
    signed_requirements(
        graph,
        keys,
        b"\xa4\x65index\x80\x66hashes\x80\x68classify\x80\x6cstrict-attrs\xf4",
    )
}

/// Signs an explicit requirement snapshot without asserting agreement with the Tree.
fn signed_requirements(
    graph: &Graph,
    keys: &[terrane_format::auth::IssuerKey],
    requirements: &[u8],
) -> Result<VerifiedCommit, Box<dyn std::error::Error>> {
    let mut proposed = request(Vec::new());
    let encoded_token = token();
    let verified = Token::decode(&encoded_token)?.verify(keys, 100)?;
    let authority = verified.authority();
    proposed.commit.tree = graph.root;
    proposed.commit.timestamp = 100;
    proposed.commit.provenance.issuer = authority.issuer.clone();
    proposed.commit.provenance.token_id = authority.token_id;
    proposed.commit.provenance.subject = authority.subject.clone();
    proposed.commit.provenance.kind = authority.kind;
    proposed.commit.provenance.workload_identity = authority.workload.clone();
    proposed.commit.provenance.observed_at = 100;
    proposed.commit.provenance.writer_epoch = 1;
    proposed.commit.provenance.embedded_token = Some(encoded_token);
    proposed.commit.profile_pair.conflicted = Some(true);
    proposed.commit.profile_pair.required_properties = Some(requirements.to_vec());
    Ok(sign(
        proposed.commit,
        &proposed.terminal_secret,
        keys,
        &Request {
            reference: b"refs/heads/_/main",
            verb: Verb::Commit,
            roots: &[],
            now: 100,
            surface: "sdk",
            locality: &Locality::default(),
            epochs: &[("refs/heads/_/main", 1)],
        },
        1,
    )?)
}

fn prepare_counted(
    inputs: &SelectedInputs,
    commit: &VerifiedCommit,
    evidence: &TreeEvidence,
    reuse: bool,
) -> Result<(PendingViewUse, Vec<Digest>, usize), StoreFailure> {
    let mut owners = if reuse {
        OwnerPreparation::new(evidence, inputs)
    } else {
        OwnerPreparation::without_reuse(evidence, inputs)
    };
    let pending = PendingViewUse::prepare_with_owners(commit, &mut owners)?;
    Ok((pending, owners.constructions, owners.entry_visits))
}

fn counts(roots: &[Digest]) -> BTreeMap<Digest, usize> {
    let mut counts = BTreeMap::new();
    for root in roots {
        *counts.entry(*root).or_default() += 1;
    }
    counts
}

fn refused<T>(result: Result<T, StoreFailure>) -> StoreFailure {
    match result {
        Err(failure) => failure,
        Ok(_) => panic!("invalid owner preparation succeeded"),
    }
}

#[tokio::test]
async fn repeated_owner_preparation_reuses_only_fixed_canonical_tree_work() -> TestResult {
    let repository = fixture().await;
    let graph = Graph::repeated(None, None)?;
    let inputs = repository.guard().completion_inputs_for(
        properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &[])?),
        2,
    )?;
    let commit = signed(&graph, repository.guard().keys())?;
    let evidence =
        TreeEvidence::load_tree(repository.store(), graph.root, &graph.uploads, MINIMUM).await?;

    let (cached, constructors, visits) = prepare_counted(&inputs, &commit, &evidence, true)?;
    let (uncached, uncached_constructors, uncached_visits) =
        prepare_counted(&inputs, &commit, &evidence, false)?;

    assert_eq!(cached, uncached);
    assert_eq!(
        cached,
        PendingViewUse::prepare(&inputs, &commit, &evidence)?
    );
    assert_eq!(
        counts(&constructors),
        BTreeMap::from([(graph.root, 1), (graph.child, 1)])
    );
    assert_eq!(
        counts(&uncached_constructors),
        BTreeMap::from([(graph.root, 2), (graph.child, 5)])
    );
    // The owner visits two grafts, one Conflict, two sides and its present base.
    // The child's single file is visited once, or once per uncached occurrence.
    assert_eq!(visits, 7);
    assert_eq!(uncached_visits, 11);
    assert_eq!(cached.policy.roots.len(), 6);
    Ok(())
}

#[tokio::test]
async fn owner_preparation_reuse_preserves_each_occurrence_policy_and_role() -> TestResult {
    let repository = fixture().await;
    let inputs = repository.guard().completion_inputs_for(
        properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &[])?),
        2,
    )?;
    let graph = Graph::repeated(None, None)?;
    let commit = signed(&graph, repository.guard().keys())?;
    let evidence =
        TreeEvidence::load_tree(repository.store(), graph.root, &graph.uploads, MINIMUM).await?;
    let (pending, _, _) = prepare_counted(&inputs, &commit, &evidence, true)?;
    let (uncached, _, _) = prepare_counted(&inputs, &commit, &evidence, false)?;
    assert_eq!(pending, uncached);
    assert_eq!(
        pending
            .policy
            .roots
            .iter()
            .map(|root| root.path.as_slice())
            .collect::<Vec<_>>(),
        vec![
            &b"/"[..],
            &b"/m"[..],
            &b"/m"[..],
            &b"/m"[..],
            &b"/b"[..],
            &b"/a"[..]
        ]
    );

    for (position, occurrence) in evidence.occurrences(MINIMUM)?.iter().enumerate() {
        let retained = &pending.policy.roots[position];
        assert_eq!(retained.root, occurrence.root);
        assert_eq!(retained.layers.len(), occurrence.layers.len());
        for (retained, (properties, overrides)) in retained.layers.iter().zip(&occurrence.layers) {
            assert_eq!(retained.properties, super::property_map(properties));
            assert_eq!(retained.overrides, super::property_map(overrides));
        }
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let resolved = inputs.selection.resolve(
            &layers,
            Defaults {
                store: &inputs.store,
                private_domain: &evidence.default_domain,
                home: &inputs.home,
            },
        )?;
        let expected = if matches!(position, 2 | 4 | 0) {
            Vec::new()
        } else {
            vec!["uid"]
        };
        assert_eq!(
            resolved.get(PropertyName::Index),
            Some(&Value::Names(expected))
        );
    }

    // Neither a successful shared child nor another Conflict role permits an
    // invalid structural attribute on either candidate or the present base.
    for role in 0..3 {
        let bad = Graph::repeated(Some(role), None)?;
        let commit = signed(&bad, repository.guard().keys())?;
        let evidence =
            TreeEvidence::load_tree(repository.store(), bad.root, &bad.uploads, MINIMUM).await?;
        let cached = refused(prepare_counted(&inputs, &commit, &evidence, true));
        let uncached = refused(prepare_counted(&inputs, &commit, &evidence, false));
        assert_eq!(
            cached.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
        );
        assert_eq!(
            cached
                .source()
                .and_then(|source| source.downcast_ref::<terrane_format::indexing::Error>()),
            Some(&terrane_format::indexing::Error::Schema)
        );
        assert_eq!(cached.kind(), uncached.kind());
        assert_eq!(cached.to_string(), uncached.to_string());
        let mut owners = OwnerPreparation::new(&evidence, &inputs);
        assert!(owners.check(bad.root).is_err());
        assert!(owners.check(bad.root).is_err());
        assert_eq!(owners.constructions, [bad.root, bad.root]);
    }

    for (property, expected_kind) in [
        (
            Property {
                name: "index",
                value: b"\x61x",
            },
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        ),
        (
            Property {
                name: "index-roots",
                value: b"\xa0",
            },
            StoreErrorKind::Unsupported,
        ),
    ] {
        let bad = Graph::repeated(None, Some(property))?;
        let commit = signed(&bad, repository.guard().keys())?;
        let evidence =
            TreeEvidence::load_tree(repository.store(), bad.root, &bad.uploads, MINIMUM).await?;
        let cached = refused(prepare_counted(&inputs, &commit, &evidence, true));
        let uncached = refused(prepare_counted(&inputs, &commit, &evidence, false));
        assert_eq!(cached.kind(), &expected_kind);
        assert_eq!(cached.kind(), uncached.kind());
        assert_eq!(cached.to_string(), uncached.to_string());
    }
    Ok(())
}

#[tokio::test]
async fn owner_preparation_reuse_never_crosses_inputs_geometry_or_invocations() -> TestResult {
    let repository = fixture().await;
    let graph = Graph::repeated(None, None)?;
    let inputs = repository.guard().completion_inputs_for(
        properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &[])?),
        2,
    )?;
    let commit = signed(&graph, repository.guard().keys())?;
    let mut evidence =
        TreeEvidence::load_tree(repository.store(), graph.root, &graph.uploads, MINIMUM).await?;
    let expected = BTreeMap::from([(graph.root, 1), (graph.child, 1)]);

    for _ in 0..2 {
        let (_, constructors, _) = prepare_counted(&inputs, &commit, &evidence, true)?;
        assert_eq!(counts(&constructors), expected);
    }
    for changed in [
        SelectedInputs {
            store: "different-store".into(),
            ..inputs.clone()
        },
        SelectedInputs {
            home: "different-home".into(),
            ..inputs.clone()
        },
        SelectedInputs {
            minimum: MINIMUM / 2,
            ..inputs.clone()
        },
        repository.guard().completion_inputs_for(
            properties::selected::Selection::Recorded(RecordedContext::new(2, 3, &[])?),
            2,
        )?,
        repository.guard().completion_inputs_for(
            properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &[])?),
            1,
        )?,
    ] {
        // The constructor is fresh even when a changed interpretation refuses
        // later policy. No previous invocation supplies a successful owner.
        let mut owners = OwnerPreparation::new(&evidence, &changed);
        owners.check(graph.child)?;
        assert_eq!(owners.constructions, [graph.child]);
        let cached = prepare_counted(&changed, &commit, &evidence, true);
        let uncached = prepare_counted(&changed, &commit, &evidence, false);
        match (cached, uncached) {
            (Ok((cached, _, _)), Ok((uncached, _, _))) => assert_eq!(cached, uncached),
            (Err(cached), Err(uncached)) => assert_eq!(cached.kind(), uncached.kind()),
            _ => panic!("changed interpretation differs with reuse disabled"),
        }
    }

    let missing = [0xff; 32];
    let mut owners = OwnerPreparation::new(&evidence, &inputs);
    assert!(owners.check(missing).is_err());
    assert!(owners.check(missing).is_err());
    assert_eq!(owners.constructions, [missing, missing]);
    drop(owners);

    evidence.ordinary_roots.clear();
    evidence.usage = TreeUse::Surface;
    let mut surface = OwnerPreparation::new(&evidence, &inputs);
    assert!(surface.check(graph.root).is_err());
    assert!(surface.check(graph.root).is_err());
    assert_eq!(surface.constructions, [graph.root, graph.root]);
    drop(surface);

    // A fresh attribute1 interpretation accepts the literal inert pointer,
    // while attribute2 must execute its own full candidate/base validation.
    let bad = Graph::repeated(Some(2), None)?;
    let bad_evidence =
        TreeEvidence::load_tree(repository.store(), bad.root, &bad.uploads, MINIMUM).await?;
    let legacy_attributes = SelectedInputs {
        registries: terrane_format::gc::publication::evidence::ConfiguredRegistryInputs {
            attribute_revision: 1,
            ..inputs.registries.clone()
        },
        ..inputs.clone()
    };
    let mut old = OwnerPreparation::new(&bad_evidence, &legacy_attributes);
    old.check(bad.root)?;
    assert_eq!(old.constructions, [bad.root]);
    let mut current = OwnerPreparation::new(&bad_evidence, &inputs);
    assert!(current.check(bad.root).is_err());
    assert_eq!(current.constructions, [bad.root]);
    Ok(())
}

#[tokio::test]
async fn requirements_root_reuse_preserves_failure_order_and_discards_failed_walks() -> TestResult {
    let repository = fixture().await;
    let inputs = repository.guard().completion_inputs_for(
        properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &[])?),
        2,
    )?;
    let graph = Graph::repeated(None, None)?;
    let commit = signed(&graph, repository.guard().keys())?;
    let mut evidence =
        TreeEvidence::load_tree(repository.store(), graph.root, &graph.uploads, MINIMUM).await?;

    // Canonical failure happens in the original signed-requirement position,
    // before a reusable Tree can exist, regardless of the reuse setting.
    evidence
        .nodes
        .get_mut(&graph.root)
        .ok_or("root missing")?
        .push(0xf6);
    for reuse in [true, false] {
        let mut owners = if reuse {
            OwnerPreparation::new(&evidence, &inputs)
        } else {
            OwnerPreparation::without_reuse(&evidence, &inputs)
        };
        let failure = refused(PendingViewUse::prepare_with_owners(&commit, &mut owners));
        assert_eq!(
            failure.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
        );
        assert_eq!(owners.constructions, [graph.root]);
        assert_eq!(owners.entry_visits, 0);
    }

    let bad = Graph::repeated(Some(2), None)?;
    let bad_evidence =
        TreeEvidence::load_tree(repository.store(), bad.root, &bad.uploads, MINIMUM).await?;
    let contradictory = signed_requirements(
        &bad,
        repository.guard().keys(),
        b"\xa4\x65index\x81\x63uid\x66hashes\x80\x68classify\x80\x6cstrict-attrs\xf4",
    )?;
    for reuse in [true, false] {
        let mut owners = if reuse {
            OwnerPreparation::new(&bad_evidence, &inputs)
        } else {
            OwnerPreparation::without_reuse(&bad_evidence, &inputs)
        };
        let failure = refused(PendingViewUse::prepare_with_owners(
            &contradictory,
            &mut owners,
        ));
        assert_eq!(
            failure.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
        );
        assert!(failure.source().is_none());
        assert_eq!(owners.constructions, [bad.root]);
        assert_eq!(owners.entry_visits, 0);
    }

    // A successful physical reconstruction does not validate attributes or
    // enter the successful-owner set. Its first failed walk consumes it.
    let signed_bad = signed(&bad, repository.guard().keys())?;
    let defaults = Defaults {
        store: &inputs.store,
        private_domain: &bad_evidence.default_domain,
        home: &inputs.home,
    };
    let mut owners = OwnerPreparation::new(&bad_evidence, &inputs);
    owners.check_requirements(&signed_bad, defaults)?;
    assert_eq!(owners.constructions, [bad.root]);
    let first = refused(owners.check(bad.root));
    assert_eq!(owners.constructions, [bad.root]);
    let retry = refused(owners.check(bad.root));
    assert_eq!(owners.constructions, [bad.root, bad.root]);
    assert_eq!(first.kind(), retry.kind());
    assert_eq!(
        first
            .source()
            .and_then(|source| source.downcast_ref::<terrane_format::indexing::Error>()),
        Some(&terrane_format::indexing::Error::Schema),
    );

    // An independently supplied malformed signed projection cannot retain a
    // Tree from an earlier requirements call within the same test owner.
    owners.check_requirements(&signed_bad, defaults)?;
    assert!(owners.check_requirements(&contradictory, defaults).is_err());
    let constructions = owners.constructions.len();
    assert!(owners.check(bad.root).is_err());
    assert_eq!(owners.constructions.len(), constructions + 1);
    Ok(())
}
