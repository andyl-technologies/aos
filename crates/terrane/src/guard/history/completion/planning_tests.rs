//! Checks paired pure preparation against the original adjacent call paths.
//!
//! Literal namespace and I/P/G wires supply independent occurrence and binding
//! expectations. Genuine native Original retention supplies full-history controls;
//! neither pending policies nor relationship subjects create completion authority.

use std::collections::BTreeSet;
use std::error::Error as _;

use super::planning::work::{self, Work};
use super::{PendingViewUse, SelectedInputs, active};
use crate::guard::{ConsumedResolver, HistoryObservation, TreeEvidence};
use crate::indexing::{Error, ErrorKind, SemanticRevisions};
use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};
use terrane_core::auth::{Request, Token, Verb};
use terrane_core::properties::semantics::RecordedContext;
use terrane_core::properties::{self, Defaults, PropertyName, RootLayer, Value};
use terrane_core::provenance::{EntryLocation, VerifiedCommit, sign};
use terrane_core::refs::Locality;
use terrane_core::tree_format::TreeUse;

// Recompile existing immutable/native fixture builders in this focused context,
// without changing their visibility, encodings, authority or original tests.
#[allow(clippy::duplicate_mod)]
#[path = "indexes/tests/native.rs"]
mod native;
#[allow(clippy::duplicate_mod)]
#[path = "indexes/tests/wire.rs"]
mod wire;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Keeps independent fixture failure as an explicit diagnostic panic.
trait Required {
    type Value;

    /// Returns the expected fixture value.
    ///
    /// # Panics
    /// Panics when fixture construction fails or an expected value is absent.
    fn required(self) -> Self::Value;
}

impl<T, E: std::fmt::Debug> Required for Result<T, E> {
    type Value = T;

    fn required(self) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("paired fixture failed: {error:?}"),
        }
    }
}

impl<T> Required for Option<T> {
    type Value = T;

    fn required(self) -> T {
        match self {
            Some(value) => value,
            None => panic!("paired fixture omitted expected data"),
        }
    }
}

fn refused<T>(result: Result<T, StoreFailure>) -> StoreFailure {
    match result {
        Err(failure) => failure,
        Ok(_) => panic!("paired preparation accepted invalid inputs"),
    }
}

fn indexing_error(failure: &StoreFailure) -> &Error {
    failure
        .source()
        .required()
        .downcast_ref::<Error>()
        .required()
}

/// Predicts five distinct child occurrences, including both candidates and base.
fn repeated(bad_role: Option<usize>, bad_override: Option<Vec<u8>>) -> wire::Graph {
    let mut graph = wire::Graph::repeated();
    let child = graph.child.required();
    let mut roles = vec![
        wire::graft(
            child,
            Some(wire::properties(vec![("index", wire::names(&["uid"]))])),
        ),
        wire::graft(
            child,
            Some(wire::properties(vec![("index", wire::names(&[]))])),
        ),
        wire::graft(
            child,
            Some(wire::properties(vec![("index", wire::names(&["uid"]))])),
        ),
    ];
    if let Some(role) = bad_role {
        // Graft field 9 follows its existing fields 1, 6 and 7. The canonical
        // structural attribute is invalid on this candidate/base namespace role.
        roles[role][0] = 0xa4;
        roles[role].push(9);
        roles[role].extend(wire::properties(vec![("index.occurrences", vec![0x40])]));
    }
    let base = roles.pop().required();
    let mut conflict = vec![0xa3, 1, 6, 12, 0x82];
    conflict.extend(roles.into_iter().flatten());
    conflict.push(13);
    conflict.extend(base);
    graph.rows.push((b"m".to_vec(), conflict));
    if let Some(overrides) = bad_override {
        graph.rows[1].1 = wire::graft(child, Some(overrides));
    }
    let bindings = wire::properties(vec![
        ("gid", wire::text(&wire::hex(graph.primary))),
        ("uid", wire::text(&wire::hex(graph.primary))),
    ]);
    graph.owner = wire::insert(
        &mut graph.nodes,
        wire::leaf(
            &graph.rows,
            Some(wire::properties(vec![
                (
                    "acl",
                    vec![
                        0x81, 0x82, 0x66, b'w', b'r', b'i', b't', b'e', b'r', 0x18, 0x1f,
                    ],
                ),
                ("domain", wire::text("public")),
                ("index", wire::names(&["uid"])),
                ("index-roots", wire::wrapper(bindings, false)),
                ("hashes", wire::names(&[])),
                ("classify", wire::names(&[])),
                ("strict-attrs", vec![0xf4]),
            ])),
        ),
    );
    graph.namespace = BTreeSet::from([child, graph.owner]);
    graph
}

async fn selected(
    fixture: &native::Fixture,
    attribute: u64,
) -> Result<(native::MeasuredGuard, SelectedInputs, TreeEvidence), Box<dyn std::error::Error>> {
    let guard = fixture.guard(attribute).await?;
    let inputs = guard.completion_inputs_for(
        properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &["future-name"])?),
        attribute,
    )?;
    let evidence =
        TreeEvidence::load_tree(guard.store(), fixture.graph.owner, &[], wire::MINIMUM).await?;
    Ok((guard, inputs, evidence))
}

/// Retains native history with an explicitly preserved later owner binding.
///
/// The shared constructor fixes Legacy authoring without later registrations.
/// Local preparation preserves its retention checks while reusing its history
/// guards, read adapters and selected-state observations unchanged.
async fn historical_fixture(
    graph: wire::Graph,
) -> Result<native::Fixture, Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;

    use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
    use crate::domain::DomainNamespace;
    use crate::guard::{AuthoringNamespaceProfile, Guard, StagedUpload};
    use crate::ref_advance::{CommitTiming, Coordinator};
    use crate::repository::Repository;
    use crate::store::{
        ContentStore, ContentUpload, MetaUpload, RefStore, TokioClock, TokioLocalFs,
    };
    use terrane_core::identity::IdentityKind;

    let seed = crate::ref_advance::tests::fixture().await;
    let root = seed.store().root().to_owned();
    let authority = seed.guard().configured_original_authority()?;
    let owner = std::fs::symlink_metadata(&root)?.uid();
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: root.clone(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: owner,
                control: None,
            }),
            chunk_profile_name: seed.guard().config().chunk_profile_name.clone(),
            chunk_profile: (*seed.guard().config().chunk_profile).clone(),
            locality: seed.guard().config().home.clone(),
        },
        TokioLocalFs,
        TokioClock,
        native::Validator,
    )
    .await?;

    // Revision 1 rejects an unregistered index-roots property. Preserve it as
    // inert later data during authoring; the separately installed revision 3
    // historical profile must still verify its complete I/P/G relationships.
    let guard = Guard::new_with_authoring_namespace_profile(
        bucket,
        TokioClock,
        seed.guard().keys().to_vec(),
        seed.guard().config().clone(),
        AuthoringNamespaceProfile::new(1, 3, &["index-roots"], 1)?,
    );
    let coordinator = Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )?,
        TokioLocalFs,
    );
    let repository = Repository::reopen_native_retention(
        coordinator,
        &DomainNamespace {
            root,
            domain: "public".into(),
        },
        authority.control(),
        owner,
    )
    .await?;

    let token = crate::ref_advance::tests::token();
    let mut session = repository
        .begin("refs/heads/_/historical", &token, "sdk")
        .await?;
    let mut request = crate::ref_advance::tests::request_file(Vec::new(), wire::BODY);
    request.commit.tree = graph.owner;
    request.uploads.retain(|upload| {
        !matches!(
            upload,
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                ..
            }
        )
    });
    request
        .uploads
        .extend(graph.nodes.values().map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: bytes.clone(),
        }));
    let before = native::selected(&repository).await?;
    let (commit, uploads) = repository
        .prepare_retained_history_fixture(&mut session, request)
        .await?;

    for upload in &uploads {
        let identity = repository
            .coordinator()
            .store()
            .put(upload.as_upload()?)
            .await?;
        if let StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        } = upload
        {
            assert_eq!(identity.terrane_v1_digest()?, wire::hash(bytes));
        }
    }
    let encoded = commit.commit().encode()?;
    let actual = repository
        .coordinator()
        .store()
        .put(ContentUpload::Meta(MetaUpload::new(
            IdentityKind::Commit,
            &encoded,
        )?))
        .await?;
    assert_eq!(actual.terrane_v1_digest()?, commit.identity());
    let fixture = native::Fixture {
        repository,
        commit,
        graph,
    };
    assert!(
        fixture
            .repository
            .coordinator()
            .store()
            .ref_get("refs/heads/_/historical")
            .await?
            .is_none()
    );
    let after = native::selected(&fixture.repository).await?;
    assert_eq!(before.0.guard, after.0.guard);
    assert_eq!(before.0.sources, after.0.sources);
    assert_eq!(before.0.branches, after.0.branches);
    assert_eq!(before.0.loss_generation, after.0.loss_generation);
    Ok(fixture)
}

fn assert_same_refusal(
    inputs: &SelectedInputs,
    commit: &VerifiedCommit,
    evidence: &TreeEvidence,
    kind: StoreErrorKind,
) {
    let original = refused(PendingViewUse::prepare(inputs, commit, evidence));
    let paired = refused(PendingViewUse::prepare_with_plan(inputs, commit, evidence));
    assert_eq!(original.kind(), &kind);
    assert_eq!(paired.kind(), original.kind());
    assert_eq!(paired.to_string(), original.to_string());
    assert_eq!(
        paired.source().map(ToString::to_string),
        original.source().map(ToString::to_string)
    );
}

/// Signs exact immutable fixture data without granting Original or history authority.
fn signed(
    graph: &wire::Graph,
    keys: &[terrane_core::auth::IssuerKey],
) -> Result<VerifiedCommit, Box<dyn std::error::Error>> {
    let mut proposed = crate::ref_advance::tests::request(Vec::new());
    let encoded = crate::ref_advance::tests::token();
    let verified = Token::decode(&encoded)?.verify(keys, 100)?;
    let authority = verified.authority();
    proposed.commit.tree = graph.owner;
    proposed.commit.timestamp = 100;
    proposed.commit.provenance.issuer = authority.issuer.clone();
    proposed.commit.provenance.token_id = authority.token_id;
    proposed.commit.provenance.subject = authority.subject.clone();
    proposed.commit.provenance.kind = authority.kind;
    proposed.commit.provenance.workload_identity = authority.workload.clone();
    proposed.commit.provenance.observed_at = 100;
    proposed.commit.provenance.writer_epoch = 1;
    proposed.commit.provenance.embedded_token = Some(encoded);
    proposed.commit.profile_pair.conflicted = Some(true);
    // Literal projection of the four requirement fields encoded on this owner.
    proposed.commit.profile_pair.required_properties = Some(
        b"\xa4\x65index\x81\x63uid\x66hashes\x80\x68classify\x80\x6cstrict-attrs\xf4".to_vec(),
    );
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

#[tokio::test]
async fn paired_preparation_preserves_pending_policy_and_relationship_plan() -> TestResult {
    let repository = crate::ref_advance::tests::fixture().await;
    let graph = repeated(None, None);
    let commit = signed(&graph, repository.guard().keys())?;
    let inputs = repository.guard().completion_inputs_for(
        properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &["future-name"])?),
        2,
    )?;
    let store = native::Memory::new(graph.nodes.clone());
    let evidence = TreeEvidence::load_tree(&store, graph.owner, &[], wire::MINIMUM).await?;
    let (paired, paired_work) =
        work::measure(|| PendingViewUse::prepare_with_plan(&inputs, &commit, &evidence));
    let (pending, plan) = paired?;
    let plan = plan.ok_or("non-Legacy preparation omitted relationship plan")?;
    let (reference, reference_work) = work::measure(|| {
        let pending = PendingViewUse::prepare(&inputs, &commit, &evidence)?;
        Ok::<_, StoreFailure>((pending, active::plan(&evidence, &inputs)?))
    });
    let (original, original_plan) = reference?;

    assert_eq!(pending, original);
    assert_eq!(plan, original_plan);
    assert_eq!(
        paired_work,
        Work {
            raw_nodes: 2,
            occurrence_walks: 1,
            occurrences: 6,
            resolutions: 6
        }
    );
    assert_eq!(
        reference_work,
        Work {
            raw_nodes: 4,
            occurrence_walks: 2,
            occurrences: 12,
            resolutions: 12
        }
    );
    assert_eq!(pending.context.view, commit.identity());
    assert_eq!(pending.context.original_root, graph.owner);
    assert_eq!(pending.inputs, inputs);
    assert_eq!(
        plan.revisions,
        SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1
        }
    );
    let child = graph.child.ok_or("shared child missing")?;
    assert_eq!(
        pending
            .policy
            .roots
            .iter()
            .map(|root| (root.root, root.path.as_slice()))
            .collect::<Vec<_>>(),
        vec![
            (graph.owner, &b"/"[..]),
            (child, &b"/m"[..]),
            (child, &b"/m"[..]),
            (child, &b"/m"[..]),
            (child, &b"/h"[..]),
            (child, &b"/g"[..]),
        ]
    );
    // Extra gid belongs to the containing owner only. Even the empty-index
    // child occurrences retain their own present uid binding for verification.
    assert_eq!(
        plan.owners,
        vec![
            (
                graph.owner,
                vec!["gid".into(), "uid".into()],
                TreeUse::Ordinary
            ),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
        ]
    );
    for (position, occurrence) in evidence.occurrences(wire::MINIMUM)?.iter().enumerate() {
        let retained = &pending.policy.roots[position];
        assert_eq!(retained.layers.len(), occurrence.layers.len());
        for (layer, (properties, overrides)) in retained.layers.iter().zip(&occurrence.layers) {
            assert_eq!(layer.properties, super::property_map(properties));
            assert_eq!(layer.overrides, super::property_map(overrides));
        }
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let effective = inputs.selection.resolve(
            &layers,
            Defaults {
                store: &inputs.store,
                private_domain: &evidence.default_domain,
                home: &inputs.home,
            },
        )?;
        assert_eq!(
            effective.get(PropertyName::Index),
            Some(&Value::Names(if matches!(position, 2 | 4) {
                Vec::new()
            } else {
                vec!["uid"]
            }))
        );
        assert_eq!(
            effective.active_index_roots().map(|bindings| bindings
                .as_bindings()
                .iter()
                .map(|binding| binding.attribute)
                .collect::<Vec<_>>()),
            Some(if position == 0 {
                vec!["gid", "uid"]
            } else {
                vec!["uid"]
            })
        );
    }
    assert_eq!(
        store.reads.lock().map_err(|_| "read log poisoned")?.len(),
        2
    );
    // A genuine layer-only whiteout changes the containing owner's effective
    // Tree use without changing its compatible child's use. Fresh canonical
    // loading supplies both certificates; no evidence field is manually altered.
    let properties = {
        let root = terrane_core::tree_format::decode_node_for(
            &graph.nodes[&graph.owner],
            true,
            wire::MINIMUM,
            TreeUse::Ordinary,
        )?;
        super::property_map(root.props.as_deref().ok_or("owner properties absent")?)
    };
    let mut layered = graph.clone();
    layered.rows.insert(0, (b"c".to_vec(), vec![0xa1, 1, 5]));
    layered.owner = wire::insert(
        &mut layered.nodes,
        wire::leaf(&layered.rows, Some(properties)),
    );
    let layer_store = native::Memory::new(layered.nodes.clone());
    let layer_evidence = TreeEvidence::load_tree_for(
        &layer_store,
        layered.owner,
        &[],
        wire::MINIMUM,
        TreeUse::OverlayLayer,
    )
    .await?;
    let layer_commit = signed(&layered, repository.guard().keys())?;
    let (layer_pending, layer_plan) =
        PendingViewUse::prepare_with_plan(&inputs, &layer_commit, &layer_evidence)?;
    assert_eq!(
        layer_pending,
        PendingViewUse::prepare(&inputs, &layer_commit, &layer_evidence)?
    );
    let layer_plan = layer_plan.ok_or("typed layer plan absent")?;
    assert_eq!(layer_plan, active::plan(&layer_evidence, &inputs)?);
    assert_eq!(
        layer_plan.owners,
        vec![
            (
                layered.owner,
                vec!["gid".into(), "uid".into()],
                TreeUse::OverlayLayer
            ),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
            (child, vec!["uid".into()], TreeUse::Ordinary),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn paired_preparation_preserves_role_policy_and_refusal_order() -> TestResult {
    let repository = crate::ref_advance::tests::fixture().await;
    let inputs = repository.guard().completion_inputs_for(
        properties::selected::Selection::Recorded(RecordedContext::new(3, 3, &["future-name"])?),
        2,
    )?;
    for role in 0..3 {
        let graph = repeated(Some(role), None);
        let commit = signed(&graph, repository.guard().keys())?;
        let store = native::Memory::new(graph.nodes.clone());
        let evidence = TreeEvidence::load_tree(&store, graph.owner, &[], wire::MINIMUM).await?;
        assert_same_refusal(
            &inputs,
            &commit,
            &evidence,
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        );
        let failure = refused(PendingViewUse::prepare_with_plan(
            &inputs, &commit, &evidence,
        ));
        assert_eq!(
            failure
                .source()
                .and_then(|source| source.downcast_ref::<terrane_core::indexing::Error>()),
            Some(&terrane_core::indexing::Error::Schema)
        );
    }

    // An ordinary file cannot acquire a structural Index role from a pointer.
    // Revision 1 still treats the same attribute as inert in standalone planning.
    let mut file_role = repeated(None, None);
    let properties = {
        let root = terrane_core::tree_format::decode_node_for(
            &file_role.nodes[&file_role.owner],
            true,
            wire::MINIMUM,
            TreeUse::Ordinary,
        )?;
        super::property_map(root.props.as_deref().ok_or("owner properties absent")?)
    };
    file_role.rows[0].1 = wire::file_with_pointer(file_role.object, file_role.present);
    file_role.owner = wire::insert(
        &mut file_role.nodes,
        wire::leaf(&file_role.rows, Some(properties)),
    );
    file_role.namespace = file_role
        .child
        .into_iter()
        .chain([file_role.owner])
        .collect();
    let commit = signed(&file_role, repository.guard().keys())?;
    let store = native::Memory::new(file_role.nodes.clone());
    let evidence = TreeEvidence::load_tree(&store, file_role.owner, &[], wire::MINIMUM).await?;
    assert_same_refusal(
        &inputs,
        &commit,
        &evidence,
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
    );
    let failure = refused(PendingViewUse::prepare_with_plan(
        &inputs, &commit, &evidence,
    ));
    assert_eq!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<terrane_core::indexing::Error>()),
        Some(&terrane_core::indexing::Error::Schema)
    );
    let mut inert = inputs.clone();
    inert.registries.attribute_revision = 1;
    assert_eq!(active::plan(&evidence, &inert)?.revisions.attribute, 1);

    for (name, value, expected) in [
        (
            "index-roots",
            wire::wrapper(wire::properties(Vec::new()), false),
            StoreErrorKind::Unsupported,
        ),
        (
            "index",
            wire::text("x"),
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        ),
    ] {
        let graph = repeated(None, Some(wire::properties(vec![(name, value)])));
        let commit = signed(&graph, repository.guard().keys())?;
        let store = native::Memory::new(graph.nodes.clone());
        let evidence = TreeEvidence::load_tree(&store, graph.owner, &[], wire::MINIMUM).await?;
        assert_same_refusal(&inputs, &commit, &evidence, expected);
        if name == "index-roots" {
            let standalone = refused(active::plan(&evidence, &inputs));
            assert_eq!(
                standalone.kind(),
                &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "PROP-29" })
            );
        }
    }
    let graph = repeated(None, None);
    let commit = signed(&graph, repository.guard().keys())?;
    let store = native::Memory::new(graph.nodes.clone());
    let evidence = TreeEvidence::load_tree(&store, graph.owner, &[], wire::MINIMUM).await?;
    let mut old_attributes = inputs.clone();
    old_attributes.registries.attribute_revision = 1;
    assert_same_refusal(
        &old_attributes,
        &commit,
        &evidence,
        StoreErrorKind::Unsupported,
    );
    // The unchanged plan-only fallback accepts this profile; pairing must not
    // route standalone callers through Pending's stronger Index support check.
    assert_eq!(
        active::plan(&evidence, &old_attributes)?
            .revisions
            .attribute,
        1
    );
    for field in 0..3 {
        let mut unsupported = inputs.clone();
        match field {
            0 => unsupported.registries.tree_revision = 2,
            1 => unsupported.registries.selector_revision = 2,
            _ => unsupported.registries.chunk_revision = 2,
        }
        assert_same_refusal(
            &unsupported,
            &commit,
            &evidence,
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        );
    }
    let mut differing = graph.clone();
    differing.rebind(None, false);
    let other = signed(&differing, repository.guard().keys())?;
    assert_same_refusal(
        &inputs,
        &other,
        &evidence,
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
    );

    // Legacy still prepares only policies, and the original wrapper never starts
    // a standalone plan. Use a real admitted Legacy view with its signed snapshot.
    let mut writer = repository
        .begin(
            "refs/heads/_/main",
            &crate::ref_advance::tests::token(),
            "sdk",
        )
        .await?;
    repository
        .advance(
            &mut writer,
            crate::ref_advance::tests::request_file(Vec::new(), b"legacy paired control"),
        )
        .await?;
    let admitted = repository
        .guard()
        .admit_policy(
            "refs/heads/_/main",
            None,
            &crate::ref_advance::tests::token(),
            "sdk",
        )
        .await?;
    let legacy = TreeEvidence::load_tree(
        repository.store(),
        admitted.commit.commit().tree,
        &[],
        wire::MINIMUM,
    )
    .await?;
    let (paired, counts) = work::measure(|| {
        PendingViewUse::prepare_with_plan(&admitted.completion_inputs, &admitted.commit, &legacy)
    });
    let (paired, plan) = paired?;
    assert!(plan.is_none());
    let (original, original_counts) = work::measure(|| {
        PendingViewUse::prepare(&admitted.completion_inputs, &admitted.commit, &legacy)
    });
    assert_eq!(paired, original?);
    assert_eq!(counts, original_counts);
    assert_eq!(
        counts,
        Work {
            raw_nodes: 1,
            occurrence_walks: 1,
            occurrences: 1,
            resolutions: 1
        }
    );
    Ok(())
}

#[tokio::test]
async fn paired_preparation_keeps_full_history_and_relationship_checks() -> TestResult {
    // The unregistered Legacy constructor must still refuse the later binding;
    // only explicit authoring registration permits this historical fixture.
    let Err(failure) = native::Fixture::new(wire::Graph::small()).await else {
        panic!("unregistered historical owner binding was admitted");
    };
    let Some(crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(failure))) =
        failure.downcast_ref::<crate::repository::Error>()
    else {
        panic!("historical owner registration refusal lost its typed admission cause");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Denied {
            verb: "commit",
            pattern: "refs/heads/_/historical".into()
        }
    );

    let fixture = historical_fixture(wire::Graph::small()).await?;
    let (guard, inputs, evidence) = selected(&fixture, 2).await?;
    let before = native::selected(&fixture.repository).await?;
    let (pending, plan) = PendingViewUse::prepare_with_plan(&inputs, &fixture.commit, &evidence)?;
    let plan = plan.ok_or("recorded relationship plan absent")?;
    let original = guard.original_commit(&fixture.commit.identity())?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    consumed.pending_view(&pending)?;
    assert!(consumed.finish().is_err());
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );

    // The paired plan still dispatches each actual auxiliary load and independently
    // preserves its typed backend failure. No pure subject is a relationship proof.
    for subject in [
        fixture.graph.primary,
        fixture.graph.present,
        fixture.graph.gap,
        fixture.graph.missing,
    ] {
        let identity = terrane_core::identity::TERRANE_V1
            .from_digest(terrane_core::identity::IdentityKind::Node, &subject)?;
        let mut memory = native::Memory::new(fixture.graph.nodes.clone());
        let kind = StoreErrorKind::Absent(identity);
        memory.failure = Some((subject, kind.clone()));
        let failure = refused(active::check_relationships(&memory, &plan, wire::MINIMUM).await);
        assert_eq!(failure.kind(), &kind);
        assert_eq!(indexing_error(&failure).subject(), Some(subject));
    }
    let valid = native::Memory::new(fixture.graph.nodes.clone());
    active::check_relationships(&valid, &plan, wire::MINIMUM).await?;
    assert_eq!(
        valid
            .reads
            .lock()
            .map_err(|_| "relationship read log poisoned")?
            .iter()
            .map(|(subject, _)| *subject)
            .collect::<BTreeSet<_>>(),
        fixture.graph.nodes.keys().copied().collect()
    );
    let profile = native::profile();
    assert_eq!(
        plan.revisions,
        SemanticRevisions {
            property: profile.property_revision,
            attribute: profile.attribute_revision,
            tree: profile.tree_revision,
        }
    );

    let mut missing_binding = fixture.graph.clone();
    missing_binding.rebind(None, true);
    let missing_store = native::Memory::new(missing_binding.nodes.clone());
    let missing_evidence =
        TreeEvidence::load_tree(&missing_store, missing_binding.owner, &[], wire::MINIMUM).await?;
    let gap_plan = active::plan(&missing_evidence, &inputs)?;
    active::check_relationships(&missing_store, &gap_plan, wire::MINIMUM).await?;
    assert!(
        matches!(crate::indexing::load(&missing_store, missing_binding.owner, "uid", plan.revisions, wire::MINIMUM).await, Err(Error::MissingBinding(owner)) if owner == missing_binding.owner)
    );

    // Even successful pure preparation cannot replace the fresh protected
    // Original read at the owning history boundary or manufacture completion.
    let path = original.baseline().authority().control().join(format!(
        "commit-{}.cbor",
        wire::hex(fixture.commit.identity())
    ));
    let bytes = std::fs::read(&path)?;
    std::fs::remove_file(&path)?;
    let refusal = guard
        .verified_history_observed(
            fixture.commit.identity(),
            HistoryObservation::default().tracked(&consumed),
        )
        .await;
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let refusal = refused(refusal);
    assert_eq!(
        refusal.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        refusal
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::NotFound)
    );
    assert!(consumed.finish().is_err());
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );

    let history = guard
        .verified_history_observed(
            fixture.commit.identity(),
            HistoryObservation::default().tracked(&consumed),
        )
        .await?;
    let completed = consumed.finish()?;
    assert_eq!(
        completed
            .view_interpretations
            .as_ref()
            .ok_or("completed view contexts absent")?,
        std::slice::from_ref(&pending.context)
    );
    assert_eq!(
        completed.views.as_slice(),
        std::slice::from_ref(&pending.policy)
    );
    let location = EntryLocation {
        commit: fixture.commit.identity(),
        root: fixture.graph.owner,
        path: b"a".to_vec(),
    };
    assert_eq!(
        history.attribute_producer(&location, "uid"),
        Ok(fixture.commit.identity())
    );
    let absent_value = EntryLocation {
        path: b"b".to_vec(),
        ..location.clone()
    };
    assert_eq!(
        history.attribute_producer(&absent_value, "uid"),
        Err(terrane_core::provenance::Rejected)
    );
    assert_eq!(
        history.attribute_producer(&location, "gid"),
        Err(terrane_core::provenance::Rejected)
    );
    assert!(!guard.store().node_reads().is_empty());
    // A fresh separately completed resolver runs the original full native path.
    assert_eq!(native::complete(&guard, &fixture.commit).await?, completed);

    let old_attributes = fixture.guard(1).await?;
    assert_eq!(
        refused(native::complete(&old_attributes, &fixture.commit).await).kind(),
        &StoreErrorKind::Unsupported
    );
    let current = fixture
        .repository
        .coordinator()
        .guard()
        .admit_policy(
            "refs/heads/_/historical",
            None,
            &crate::ref_advance::tests::token(),
            "sdk",
        )
        .await;
    assert_eq!(
        refused(current).kind(),
        &StoreErrorKind::Denied {
            verb: "admin",
            pattern: "refs/heads/_/historical".into()
        }
    );
    guard.store().assert_read_only();
    native::unchanged(&fixture, &before).await?;

    // Independently readdressed, canonical route/primary bytes prove an actual
    // relationship divergence, rather than a corrupt-object identity mismatch.
    let mut divergent = wire::Graph::small();
    let present = wire::insert(
        &mut divergent.nodes,
        wire::leaf(&[(b"z".to_vec(), wire::terminal(divergent.object))], None),
    );
    let mut key = vec![1];
    key.extend_from_slice(&divergent.object);
    let primary = wire::insert(
        &mut divergent.nodes,
        wire::leaf(
            &[(key, wire::forward(divergent.object, present))],
            Some(wire::properties(vec![(
                "index-gaps",
                wire::wrapper(wire::text(&wire::hex(divergent.gap)), false),
            )])),
        ),
    );
    divergent.rebind(Some(primary), true);
    let invalid = historical_fixture(divergent).await?;
    let (guard, inputs, evidence) = selected(&invalid, 2).await?;
    let (pending, plan) = PendingViewUse::prepare_with_plan(&inputs, &invalid.commit, &evidence)?;
    assert_eq!(pending.context.view, invalid.commit.identity());
    let failure = refused(
        active::check_relationships(
            guard.store(),
            &plan.ok_or("divergent plan absent")?,
            wire::MINIMUM,
        )
        .await,
    );
    assert_eq!(indexing_error(&failure).kind(), ErrorKind::Invalid);
    let original = guard.original_commit(&invalid.commit.identity())?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let failure = refused(
        guard
            .verified_history_observed(
                invalid.commit.identity(),
                HistoryObservation::default().tracked(&consumed),
            )
            .await,
    );
    assert_eq!(indexing_error(&failure).kind(), ErrorKind::Invalid);
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    guard.store().assert_read_only();
    Ok(())
}
