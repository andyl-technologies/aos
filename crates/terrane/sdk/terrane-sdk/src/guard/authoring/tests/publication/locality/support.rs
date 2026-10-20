//! Builds signed native graft fixtures and independently reconstructed canonical outputs.
//!
//! The exhaustive reference construction happens before the measured writer
//! invocation. Explicit model revisions describe ordinary data, never selected
//! history inputs or publication authority; the real native factory installs those.

use std::collections::BTreeMap;

use crate::guard::{CommitRequest, HistoryObservation, StagedUpload, invalid};
use crate::indexing::{self, SemanticRevisions};
use crate::repository::{CommitReport, PreparedTree};
use crate::store::{ContentStore, RefStore};
use terrane_format::{
    cbor,
    identity::{Digest, IdentityKind, TERRANE_V1},
    indexing::{IndexEvaluationRecipe, carrier::SemanticContext, evaluation},
    tree_builder::Tree,
    tree_format::{Attribute, Entry, EntryKind, LeafItem, Property, TreeUse},
};

use super::super::support::{self as publication, NativeRepository, REFERENCE};
use super::TestResult;

const MINIMUM: u64 = 262144;

/// Holds only owned inputs and independently predicted final bytes across awaits.
pub(super) struct Candidate {
    /// Genuine unsigned prepared root for the ordinary public producer.
    pub(super) tree: PreparedTree,
    /// One consumable signed-publication proposal, retaining its normal Chunk upload.
    pub(super) request: Option<CommitRequest>,
    /// Independently predicted completed namespace root.
    pub(super) final_root: Digest,
    /// Independently predicted completed indexed child root.
    pub(super) child: Digest,
    /// Equal immutable child that must remain unchanged during propagation.
    pub(super) stable: Digest,
    /// Full canonical namespace and auxiliary output model, outside measured work.
    pub(super) expected: BTreeMap<Digest, Vec<u8>>,
}

struct Shape {
    tree: PreparedTree,
    child: Digest,
    stable: Digest,
    nodes: BTreeMap<Digest, Vec<u8>>,
    index: evaluation::IndexData,
}

/// Builds a complete genuine candidate with old bindings retained for maintenance.
///
/// # Errors
/// Preserves native request, canonical tree, recipe and reference-model failures.
/// # Panics
/// Panics if independent literal or equivalent full-model outputs disagree.
pub(super) async fn candidate(
    repository: &NativeRepository,
    parents: Vec<Digest>,
    value: u64,
    previous: Option<&CommitReport>,
    population: usize,
    repeats: usize,
) -> Result<Candidate, Box<dyn std::error::Error>> {
    let (child_primary, child_nodes) = publication::expected(Some(value))?;
    let parent_binding = previous
        .map(|report| association(report, b"/"))
        .transpose()?;
    let child_binding = previous
        .map(|report| association(report, b"/g00"))
        .transpose()?
        .unwrap_or(child_primary);
    let initial_nodes = if previous.is_none() {
        child_nodes.clone()
    } else {
        BTreeMap::new()
    };
    let (template, mut request) = publication::request(
        repository,
        parents,
        Some(value),
        true,
        Some(child_binding),
        &initial_nodes,
    )
    .await?;

    // Borrowed Trees and reference-model graphs end in this synchronous block.
    let (proposed, completed, parent_nodes) = {
        let provisional = shape(&template, child_binding, None, population, repeats)?;
        let selected = parent_binding.unwrap_or(provisional.index.root);
        let proposed = shape(
            &template,
            child_binding,
            Some(selected),
            population,
            repeats,
        )?;
        assert_eq!(proposed.index.root, provisional.index.root);
        assert_eq!(proposed.index.nodes, provisional.index.nodes);

        let unbound_completed = shape(&template, child_primary, None, population, repeats)?;
        let completed = shape(
            &template,
            child_primary,
            Some(unbound_completed.index.root),
            population,
            repeats,
        )?;
        assert_eq!(completed.index.root, proposed.index.root);
        assert_eq!(completed.index.nodes, proposed.index.nodes);
        let parent_nodes = if previous.is_none() {
            proposed.index.nodes.clone()
        } else {
            BTreeMap::new()
        };
        (proposed, completed, parent_nodes)
    };
    let mut expected = completed.nodes;
    expected.extend(completed.index.nodes);
    expected.extend(child_nodes);

    let mut inputs = proposed.nodes;
    inputs.extend(initial_nodes);
    inputs.extend(parent_nodes);
    stage_inputs(&mut request, &proposed.tree, inputs)?;
    request.commit.tree = proposed.tree.root();

    Ok(Candidate {
        tree: proposed.tree,
        request: Some(request),
        final_root: completed.tree.root(),
        child: completed.child,
        stable: completed.stable,
        expected,
    })
}

/// Commits the exact owned proposal through real begin/sign/current/durable publication.
///
/// # Errors
/// Preserves genuine native session, Original, index and acknowledgment failures.
/// # Panics
/// Propagates genuine token and independent canonical-model fixture assertions.
pub(super) async fn publish(
    repository: &NativeRepository,
    value: u64,
    previous: Option<&CommitReport>,
    population: usize,
    repeats: usize,
) -> Result<(CommitReport, Candidate), Box<dyn std::error::Error>> {
    let token = crate::ref_advance::tests::token();
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    let parents = session
        .record()
        .map(|record| vec![record.commit])
        .unwrap_or_default();
    let mut candidate =
        candidate(repository, parents, value, previous, population, repeats).await?;
    // The duplicate owned copy remains an oracle; it is never submitted again.
    let tree = duplicate_prepared(&candidate.tree)?;
    let request = candidate.request.take().ok_or_else(invalid)?;
    let report = repository
        .commit_with_report(&mut session, tree, request)
        .await?;
    Ok((report, candidate))
}

/// Checks exact immutable outputs, selected whole record and completed source history.
///
/// # Errors
/// Preserves actual output reads, Original/history completion and selection failures.
/// # Panics
/// Panics if real publication disagrees with the independent canonical model.
pub(super) async fn assert_outputs(
    repository: &NativeRepository,
    report: &CommitReport,
    expected: &Candidate,
) -> TestResult {
    let guard = repository.coordinator().guard();
    let history = guard.verified_history(report.record.commit).await?;
    let commit = history.commit(&report.record.commit).ok_or_else(invalid)?;
    assert_eq!(commit.commit().tree, expected.final_root);
    assert_eq!(
        guard.store().ref_get(REFERENCE).await?,
        Some(report.record.clone())
    );
    assert_immutable(repository, expected).await?;
    let revisions = {
        let verified = guard.verified_tree(report.record.commit).await?;
        let root = verified.evidence.tree(expected.final_root, MINIMUM)?;
        for item in root.iter().filter(|item| item.key.starts_with(b"g")) {
            assert!(
                matches!(&item.entry.kind, EntryKind::Tree { root, .. } if *root == expected.child)
            );
        }
        let stable = root.get(b"unchanged").ok_or_else(invalid)?;
        assert!(matches!(&stable.kind, EntryKind::Tree { root, .. } if *root == expected.stable));
        let (_, profile) = guard.selected_view_profile(commit, HistoryObservation::default())?;
        assert_eq!(
            (
                profile.property_revision,
                profile.attribute_revision,
                profile.tree_revision
            ),
            (3, 2, 1)
        );
        SemanticRevisions {
            property: profile.property_revision,
            attribute: profile.attribute_revision,
            tree: profile.tree_revision,
        }
    };
    // These post-publication checks are outside the measured writer invocation.
    for operation in &report.index_work.operations {
        let loaded =
            indexing::load(guard.store(), operation.owner, "uid", revisions, MINIMUM).await?;
        let sources = loaded.sources()?;
        let prepared = loaded.prepare(&sources.trees)?;
        assert_eq!(prepared.root(), operation.association.index);
        assert!(prepared.all_missing()?.rows.is_empty());
        assert!(prepared.gap_root().is_none());
    }
    Ok(())
}

/// Checks that every independently predicted immutable output retains its exact bytes.
///
/// # Errors
/// Preserves actual immutable store reads and address construction failures.
/// # Panics
/// Panics if a previously admitted or newly completed canonical Node changes.
pub(super) async fn assert_immutable(
    repository: &NativeRepository,
    expected: &Candidate,
) -> TestResult {
    for (digest, bytes) in &expected.expected {
        let identity = TERRANE_V1.from_digest(IdentityKind::Node, digest)?;
        assert_eq!(
            repository
                .coordinator()
                .store()
                .get(&identity, None)
                .await?,
            *bytes
        );
    }
    Ok(())
}

/// Produces a real canonical Conflict candidate without inventing completed coverage.
///
/// # Errors
/// Preserves canonical Entry and prepared-root construction failures.
pub(super) fn conflict(candidate: &Candidate) -> Result<PreparedTree, Box<dyn std::error::Error>> {
    let root = candidate.tree.tree()?;
    let mut entries = root.iter().cloned().collect::<Vec<_>>();
    let selected = entries
        .iter_mut()
        .find(|item| item.key == b"g00")
        .ok_or_else(invalid)?;
    let original = selected.entry.clone();
    selected.entry = bare(EntryKind::Conflict {
        candidates: vec![original.clone(), original.clone()],
        base: Some(Some(Box::new(original))),
    });
    let tree = Tree::build(
        entries,
        root.props().map(<[_]>::to_vec),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    Ok(PreparedTree::from_tree(&tree)?)
}

/// Finds the genuinely published association selected at one actual occurrence.
///
/// # Errors
/// Rejects an absent actual occurrence association; it grants no permission.
pub(super) fn association(
    report: &CommitReport,
    path: &[u8],
) -> Result<Digest, Box<dyn std::error::Error>> {
    report
        .index_work
        .operations
        .iter()
        .find(|operation| operation.paths.iter().any(|actual| actual == path))
        .map(|operation| operation.association.index)
        .ok_or_else(|| Box::<dyn std::error::Error>::from(invalid()))
}

/// Reconstructs ordinary expected data without invoking native maintenance.
///
/// # Errors
/// Preserves canonical source, recipe and full reference-construction failures.
/// # Panics
/// Panics if the independently encoded one-file I/P/G oracle disagrees.
fn shape(
    template: &PreparedTree,
    child_binding: Digest,
    parent_binding: Option<Digest>,
    population: usize,
    repeats: usize,
) -> Result<Shape, Box<dyn std::error::Error>> {
    let original = template.tree()?;
    let child_roots = binding(child_binding);
    let mut child_properties = original.props().unwrap_or_default().to_vec();
    replace(&mut child_properties, "index-roots", &child_roots);
    let child = Tree::build(
        original.iter().cloned().collect(),
        Some(child_properties),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let child_data = evaluation::construct(
        &IndexEvaluationRecipe::new(child.root_identity(), "uid")?,
        &BTreeMap::from([(child.root_identity(), child.clone())]),
        MINIMUM,
        SemanticContext::new(3, 2, 1)?,
    )?;
    let inline = original
        .iter()
        .next()
        .and_then(|item| {
            item.entry
                .attrs
                .iter()
                .find(|attribute| attribute.name == "uid")
        })
        .ok_or_else(invalid)?;
    let mut decoder = cbor::Decoder::new(inline.value);
    let value = decoder.uint()?;
    decoder.finish()?;
    let literal = publication::expected(Some(value))?;
    assert_eq!(
        (child_data.root, &child_data.nodes),
        (literal.0, &literal.1)
    );

    let mut stable_entries = original.iter().cloned().collect::<Vec<_>>();
    for entry in &mut stable_entries {
        entry
            .entry
            .attrs
            .retain(|attribute| attribute.name != "uid");
        entry.entry.attrs.push(Attribute {
            name: "uid",
            value: b"\x03",
        });
        entry
            .entry
            .attrs
            .sort_by(|left, right| left.name.cmp(right.name));
    }
    let mut stable_properties = original.props().unwrap_or_default().to_vec();
    stable_properties.retain(|property| property.name != "index-roots");
    replace(&mut stable_properties, "index", b"\x80");
    let stable = Tree::build(
        stable_entries.clone(),
        Some(stable_properties),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let file = stable_entries.first().ok_or_else(invalid)?.entry.clone();
    let mut entries = (0..population)
        .map(|position| LeafItem {
            key: format!("f{position:05}").into_bytes(),
            entry: file.clone(),
        })
        .collect::<Vec<_>>();
    for position in 0..repeats {
        entries.push(LeafItem {
            key: format!("g{position:02}").into_bytes(),
            entry: graft(child.root_identity()),
        });
    }
    entries.push(LeafItem {
        key: b"unchanged".to_vec(),
        entry: graft(stable.root_identity()),
    });
    let roots = parent_binding.map(binding);
    let mut properties = original.props().unwrap_or_default().to_vec();
    properties.retain(|property| property.name != "index-roots");
    if let Some(roots) = &roots {
        replace(&mut properties, "index-roots", roots);
    }
    let tree = Tree::build(entries, Some(properties), MINIMUM, TreeUse::Ordinary)?;
    let graph = BTreeMap::from([
        (tree.root_identity(), tree.clone()),
        (child.root_identity(), child.clone()),
        (stable.root_identity(), stable.clone()),
    ]);
    let index = evaluation::construct(
        &IndexEvaluationRecipe::new(tree.root_identity(), "uid")?,
        &graph,
        MINIMUM,
        SemanticContext::new(3, 2, 1)?,
    )?;
    let mut nodes = BTreeMap::new();
    for source in [&tree, &child, &stable] {
        for node in source.nodes() {
            nodes.insert(node.identity(), node.encoded().to_vec());
        }
    }
    Ok(Shape {
        tree: PreparedTree::from_tree(&tree)?,
        child: child.root_identity(),
        stable: stable.root_identity(),
        nodes,
        index,
    })
}

fn stage_inputs(
    request: &mut CommitRequest,
    prepared: &PreparedTree,
    mut nodes: BTreeMap<Digest, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    for upload in &prepared.uploads {
        if let StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        } = upload
        {
            let identity = TERRANE_V1
                .calculate(IdentityKind::Node, bytes)?
                .terrane_v1_digest()?;
            nodes.remove(&identity);
        }
    }
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
        .extend(nodes.into_values().map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        }));
    Ok(())
}

fn duplicate_prepared(tree: &PreparedTree) -> Result<PreparedTree, Box<dyn std::error::Error>> {
    let decoded = tree.tree()?;
    Ok(PreparedTree::from_tree(&decoded)?)
}

fn binding(root: Digest) -> Vec<u8> {
    let hex = root
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 2);
    cbor::write_text(&mut bytes, "value");
    cbor::write_map(&mut bytes, 1);
    cbor::write_text(&mut bytes, "uid");
    cbor::write_text(&mut bytes, &hex);
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(0xf4);
    bytes
}

fn replace<'a>(properties: &mut Vec<Property<'a>>, name: &'a str, value: &'a [u8]) {
    properties.retain(|property| property.name != name);
    properties.push(Property { name, value });
    properties
        .sort_by(|left, right| (left.name.len(), left.name).cmp(&(right.name.len(), right.name)));
}

fn graft(root: Digest) -> Entry<'static> {
    bare(EntryKind::Tree { root, props: None })
}

fn bare<'a>(kind: EntryKind<'a>) -> Entry<'a> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}
