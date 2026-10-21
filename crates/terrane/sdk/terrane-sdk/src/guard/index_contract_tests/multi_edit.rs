//! Composes insertion, deletion, changed grafts and canonical resynchronization natively.

use std::collections::{BTreeMap, BTreeSet};

use super::native_fixture::{Fixture, NativeRepository, REFERENCE, TestResult};
use crate::guard::{CommitRequest, StagedUpload, TreeEvidence, invalid};
use crate::indexing::{self, SemanticRevisions};
use crate::repository::{CommitReport, PreparedTree};
use crate::store::{ContentStore, RefStore};
use terrane_format::{
    cbor,
    identity::{Digest, IdentityKind, TERRANE_V1},
    indexing::{
        IndexEvaluationRecipe,
        carrier::{SemanticContext, classify_entry},
        evaluation,
        incremental::PopulationMode,
        maintenance::{Coordinate, Predicate},
    },
    tree_builder::Tree,
    tree_format::{
        self, Attribute, ContentRef, Entry, EntryKind, LeafItem, NodeItems, Property, TreeUse,
    },
};

mod costs;
mod oracle;
mod physical;
mod source;

use oracle::{ExpectedWork, expected_work};

const MINIMUM: u64 = 262144;
const REPEATS: usize = 2;

struct Model {
    root: Digest,
    child: Digest,
    stable: Digest,
    maintenance_root: Digest,
    maintenance_child: Digest,
    sources: BTreeMap<Digest, Vec<u8>>,
    published_sources: BTreeMap<Digest, Vec<u8>>,
    indexes: BTreeMap<Digest, evaluation::IndexData>,
    request: Option<CommitRequest>,
    tree: PreparedTree,
}

/// Executes the increasing ordinary and deliberately cap-driven native edit populations.
///
/// # Errors
/// Preserves actual factory, canonical source, strict relationship and publication errors.
/// # Panics
/// Panics if immutable output, independently derived logical delta or stream work differs.
pub(super) async fn exercise(population: usize, adversarial: bool) -> TestResult {
    let mut diagnostic = crate::diagnostic_clock::FixtureScope::new(population, adversarial);
    let result = exercise_observed(population, adversarial, &mut diagnostic).await;
    diagnostic.finish_result(&result);
    result
}

async fn exercise_observed(
    population: usize,
    adversarial: bool,
    diagnostic: &mut crate::diagnostic_clock::FixtureScope,
) -> TestResult {
    eprintln!("multi-edit population={population} adversarial={adversarial} phase=factory");
    let fixture = Fixture::new_capacity().await?;
    let repository = &fixture.repository;
    let mut baseline = model(population, adversarial, false, None)?;
    eprintln!(
        "multi-edit population={population} adversarial={adversarial} initial_source_nodes={} initial_auxiliary_nodes={}",
        baseline.published_sources.len(),
        baseline
            .indexes
            .values()
            .map(|data| data.nodes.len())
            .sum::<usize>(),
    );
    prepare_initial_inputs(repository, &mut baseline).await?;
    eprintln!(
        "multi-edit population={population} adversarial={adversarial} phase=baseline-publication"
    );
    let first = publish(repository, &mut baseline, None).await?;
    eprintln!("multi-edit population={population} adversarial={adversarial} phase=baseline-output");
    assert_outputs(repository, &first, &baseline).await?;
    trace_subphase("baseline-output-complete");
    diagnostic.phase(crate::diagnostic_clock::Phase::Oracle);
    trace_subphase("replacement-model-before");
    let mut replacement = model(population, adversarial, true, Some((&first, &baseline)))?;
    trace_subphase("replacement-model-after");
    eprintln!(
        "multi-edit population={population} adversarial={adversarial} phase=independent-work"
    );
    let oracle = expected_work(&baseline, &replacement)?;
    eprintln!(
        "multi-edit population={population} adversarial={adversarial} phase=maintained-publication"
    );
    diagnostic.phase(crate::diagnostic_clock::Phase::MaintainedBegin);
    let second = publish(repository, &mut replacement, Some(diagnostic)).await?;
    diagnostic.phase(crate::diagnostic_clock::Phase::Reopen);
    trace_subphase("maintained-reopen-before");
    let reopened = fixture.reopen().await?;
    trace_subphase("maintained-reopen-after");
    diagnostic.phase(crate::diagnostic_clock::Phase::Output);
    trace_subphase("maintained-output-before");
    assert_outputs(&reopened, &second, &replacement).await?;
    trace_subphase("maintained-output-after");
    eprintln!(
        "multi-edit population={population} adversarial={adversarial} phase=independent-accounting"
    );
    diagnostic.phase(crate::diagnostic_clock::Phase::Accounting);
    assert_work(&second, &oracle, adversarial)?;
    for (root, expected) in &oracle {
        let boundary = expected.source.boundary
            + expected
                .batches
                .values()
                .map(physical::boundary_cost)
                .sum::<usize>();
        eprintln!(
            "multi-edit population={population} adversarial={adversarial} root={root} delta_input={} delta_data={} delta_route={} B={boundary} source_B={}",
            expected.input, expected.data, expected.route, expected.source.boundary
        );
    }
    assert_immutable(repository, &baseline).await?;
    assert_eq!(baseline.stable, replacement.stable);
    Ok(())
}

fn body(index: usize) -> Vec<u8> {
    format!("native multi-edit immutable content {index:02}").into_bytes()
}

fn file<'a>(object: Digest, size: u64, value: &'a [u8]) -> Entry<'a> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size,
            content: ContentRef::Inline(object),
            link_id: None,
        },
        attrs: vec![Attribute { name: "uid", value }],
        attrs_present: true,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn graft(root: Digest) -> Entry<'static> {
    Entry {
        kind: EntryKind::Tree { root, props: None },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn names(population: usize, object: Digest, adversarial: bool) -> TestResult<Vec<Vec<u8>>> {
    let terminal = Entry {
        kind: EntryKind::Index {
            targets: vec![object],
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let mut keys = Vec::new();
    for position in 0..=population {
        for salt in 0..100 {
            let key = format!("f{position:05}-{salt:02}-{}", "x".repeat(170)).into_bytes();
            let canonical = physical::leaf_bytes(
                &LeafItem {
                    key: key.clone(),
                    entry: terminal.clone(),
                },
                &[],
            )?;
            // Reject every possible probabilistic cut, using the actual canonical item.
            // Prefix compression only lowers L, so the maximum threshold is decisive.
            if !adversarial
                || physical::hash(&canonical)
                    >= ((1_u64 << 24) * canonical.len() as u64 / 8).min(1 << 32)
            {
                keys.push(key);
                break;
            }
        }
        if keys.len() != position + 1 {
            return Err("adversarial route-name search exhausted".into());
        }
    }
    Ok(keys)
}

fn uint(value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_uint(&mut bytes, value);
    bytes
}

fn binding(root: Digest) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 2);
    cbor::write_text(&mut bytes, "value");
    cbor::write_map(&mut bytes, 1);
    cbor::write_text(&mut bytes, "uid");
    cbor::write_text(
        &mut bytes,
        &root
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(0xf4);
    bytes
}

fn properties<'a>(roots: Option<&'a [u8]>, marker: &'a [u8]) -> Vec<Property<'a>> {
    let mut result = vec![
        Property {
            name: "acl",
            value: marker,
        },
        Property {
            name: "domain",
            value: b"\x66public",
        },
        Property {
            name: "index",
            value: b"\x81\x63uid",
        },
    ];
    if let Some(roots) = roots {
        result.push(Property {
            name: "index-roots",
            value: roots,
        });
    }
    result.sort_by(|left, right| (left.name.len(), left.name).cmp(&(right.name.len(), right.name)));
    result
}

fn nodes(tree: &Tree<'_>) -> BTreeMap<Digest, Vec<u8>> {
    tree.nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect()
}

fn index(tree: &Tree<'_>, graph: &BTreeMap<Digest, Tree<'_>>) -> TestResult<evaluation::IndexData> {
    Ok(evaluation::construct(
        &IndexEvaluationRecipe::new(tree.root_identity(), "uid")?,
        graph,
        MINIMUM,
        SemanticContext::new(3, 2, 1)?,
    )?)
}

fn association(report: &CommitReport, path: &[u8]) -> TestResult<Digest> {
    report
        .index_work
        .operations
        .iter()
        .find(|operation| operation.paths.iter().any(|actual| actual == path))
        .map(|operation| operation.association.index)
        .ok_or_else(|| invalid().into())
}

fn model(
    population: usize,
    adversarial: bool,
    changed: bool,
    previous: Option<(&CommitReport, &Model)>,
) -> TestResult<Model> {
    let bodies = (0..16).map(body).collect::<Vec<_>>();
    let objects = bodies
        .iter()
        .map(|body| {
            TERRANE_V1
                .calculate(IdentityKind::Chunk, body)?
                .terrane_v1_digest()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keys = names(population, objects[0], adversarial)?;
    let values = (0..population + 32)
        .map(|position| uint(position as u64 + 10))
        .collect::<Vec<_>>();
    let common = uint(3);
    let altered = uint(4);
    let marker = if changed {
        b"\x81\x82\x66writer\x0f".as_slice()
    } else {
        b"\x81\x82\x66writer\x18\x1f".as_slice()
    };
    let middle = population / 4;
    let mut entries = Vec::new();
    for position in 0..population {
        if changed && position == middle + 1 {
            continue;
        }
        let (object, value) = if position < population / 2 {
            (
                0,
                if changed && matches!(position, p if p == middle + 2 || p == middle + 3) {
                    &altered
                } else {
                    &common
                },
            )
        } else {
            (position % 16, &values[position])
        };
        entries.push(LeafItem {
            key: keys[position].clone(),
            entry: file(objects[object], bodies[object].len() as u64, value),
        });
    }
    if changed {
        let inserted = format!("{}-insert", String::from_utf8(keys[middle].clone())?).into_bytes();
        // This inserted route also excludes every probabilistic cut in adversarial mode.
        let inserted = if adversarial {
            adversarial_insert(&keys[middle], objects[0])?
        } else {
            inserted
        };
        entries.push(LeafItem {
            key: inserted,
            entry: file(objects[0], bodies[0].len() as u64, &common),
        });
    }
    let child_entries = (0..8)
        .map(|position| LeafItem {
            key: format!("child-{position:02}").into_bytes(),
            entry: file(
                objects[position + 1],
                bodies[position + 1].len() as u64,
                if changed && position < 3 {
                    &altered
                } else {
                    &common
                },
            ),
        })
        .collect::<Vec<_>>();
    let empty_names = b"\x80";
    let stable = Tree::build(
        vec![LeafItem {
            key: b"stable".to_vec(),
            entry: file(objects[15], bodies[15].len() as u64, &common),
        }],
        Some(vec![Property {
            name: "index",
            value: empty_names,
        }]),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let child_unbound = Tree::build(
        child_entries.clone(),
        Some(properties(None, b"\x81\x82\x66writer\x18\x1f")),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let child_index = index(
        &child_unbound,
        &BTreeMap::from([(child_unbound.root_identity(), child_unbound.clone())]),
    )?;
    let completed_child_binding = binding(child_index.root);
    let completed_child = Tree::build(
        child_entries.clone(),
        Some(properties(
            Some(&completed_child_binding),
            b"\x81\x82\x66writer\x18\x1f",
        )),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let proposed_child_binding = binding(
        previous
            .map(|(report, _)| association(report, b"/g00"))
            .transpose()?
            .unwrap_or(child_index.root),
    );
    let proposed_child = Tree::build(
        child_entries,
        Some(properties(
            Some(&proposed_child_binding),
            b"\x81\x82\x66writer\x18\x1f",
        )),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let root_unbound = root_tree(
        &entries,
        stable.root_identity(),
        marker,
        completed_child.root_identity(),
        None,
    )?;
    let root_index = index(
        &root_unbound,
        &BTreeMap::from([
            (root_unbound.root_identity(), root_unbound.clone()),
            (completed_child.root_identity(), completed_child.clone()),
            (stable.root_identity(), stable.clone()),
        ]),
    )?;
    let completed_root_binding = binding(root_index.root);
    let root = root_tree(
        &entries,
        stable.root_identity(),
        marker,
        completed_child.root_identity(),
        Some(&completed_root_binding),
    )?;
    let proposed_root_binding = binding(
        previous
            .map(|(report, _)| association(report, b"/"))
            .transpose()?
            .unwrap_or(root_index.root),
    );
    let proposed_root = root_tree(
        &entries,
        stable.root_identity(),
        marker,
        proposed_child.root_identity(),
        Some(&proposed_root_binding),
    )?;
    let maintenance_root = root_tree(
        &entries,
        stable.root_identity(),
        marker,
        completed_child.root_identity(),
        Some(&proposed_root_binding),
    )?;
    let mut published_sources = nodes(&root);
    published_sources.extend(nodes(&completed_child));
    published_sources.extend(nodes(&stable));
    let mut sources = published_sources.clone();
    sources.extend(nodes(&maintenance_root));
    sources.extend(nodes(&proposed_child));
    let indexes = BTreeMap::from([
        (root.root_identity(), root_index),
        (completed_child.root_identity(), child_index),
    ]);
    let tree = PreparedTree::from_tree(&proposed_root)?;
    let mut request = crate::ref_advance::tests::request(
        previous
            .map(|(report, _)| vec![report.record.commit])
            .unwrap_or_default(),
    );
    request.commit.tree = tree.root();
    request.uploads.clear();
    for plaintext in &bodies {
        request.uploads.extend(
            crate::ref_advance::tests::request_file(Vec::new(), plaintext)
                .uploads
                .into_iter()
                .filter(|upload| matches!(upload, StagedUpload::Chunk { .. })),
        );
    }
    let mut inputs = nodes(&proposed_child);
    inputs.extend(nodes(&stable));
    if previous.is_none() {
        for data in indexes.values() {
            inputs.extend(data.nodes.clone());
        }
    }
    request
        .uploads
        .extend(inputs.into_values().map(|bytes| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        }));
    Ok(Model {
        root: root.root_identity(),
        child: completed_child.root_identity(),
        stable: stable.root_identity(),
        maintenance_root: maintenance_root.root_identity(),
        maintenance_child: proposed_child.root_identity(),
        sources,
        published_sources,
        indexes,
        request: Some(request),
        tree,
    })
}

fn adversarial_insert(previous: &[u8], object: Digest) -> TestResult<Vec<u8>> {
    for salt in 0..100 {
        let key = [previous, format!("-insert-{salt:02}").as_bytes()].concat();
        let entry = Entry {
            kind: EntryKind::Index {
                targets: vec![object],
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        let bytes = physical::leaf_bytes(
            &LeafItem {
                key: key.clone(),
                entry,
            },
            &[],
        )?;
        if physical::hash(&bytes) >= ((1_u64 << 24) * bytes.len() as u64 / 8).min(1 << 32) {
            return Ok(key);
        }
    }
    Err("adversarial inserted key search exhausted".into())
}

// Initial immutable storage preparation precedes the writer budget. Real backend
// reads establish membership; the subsequent baseline still undergoes ordinary
// current admission, signing, Original retention and selected publication.
async fn prepare_initial_inputs(repository: &NativeRepository, model: &mut Model) -> TestResult {
    let request = model.request.as_mut().ok_or_else(invalid)?;
    let store = repository.coordinator().store();
    let roots = BTreeSet::from([model.root, model.child, model.stable]);
    let auxiliary = model
        .indexes
        .values()
        .flat_map(|data| data.nodes.keys().copied())
        .collect::<BTreeSet<_>>();
    let mut namespace = BTreeMap::new();
    let mut chunks = BTreeSet::new();

    for upload in request.uploads.iter().chain(model.tree.uploads.iter()) {
        match upload {
            StagedUpload::Chunk { identity, .. } => {
                let admitted = store.put(upload.as_upload()?).await?;
                assert_eq!(admitted, *identity);
                assert!(chunks.insert(identity.terrane_v1_digest()?));
            }
            StagedUpload::Meta { kind, bytes } => {
                assert_eq!(*kind, IdentityKind::Node);
                let digest = TERRANE_V1.calculate(*kind, bytes)?.terrane_v1_digest()?;
                if model.published_sources.contains_key(&digest) {
                    // PreparedTree staging may repeat a request Node. A repeated
                    // identity must carry exactly the same canonical body.
                    if let Some(previous) = namespace.insert(digest, bytes.clone()) {
                        assert_eq!(previous, *bytes);
                    }
                }
            }
        }
    }
    assert_eq!(chunks.len(), 16);
    assert_eq!(namespace.len(), model.published_sources.len());
    assert_eq!(roots.len(), 3);

    let overlay = namespace
        .into_iter()
        .map(|(digest, bytes)| {
            (
                digest,
                StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for root in &roots {
        let upload = overlay.get(root).ok_or_else(invalid)?;
        let admitted = store.put(upload.as_upload()?).await?;
        assert_eq!(admitted.terrane_v1_digest()?, *root);
    }
    let staged = overlay.into_values().collect::<Vec<_>>();
    let evidence = TreeEvidence::load_tree(store, model.tree.root(), &staged, MINIMUM).await?;
    request.reference_records = repository
        .coordinator()
        .guard()
        .existing_records(&evidence)
        .await?;

    // Actual backend reads verify occurrence-root and payload membership. Physical
    // descendants and every auxiliary Node remain ordinary baseline staged data.
    request.uploads.retain(|upload| match upload {
        StagedUpload::Chunk { identity, .. } => !identity
            .terrane_v1_digest()
            .is_ok_and(|digest| chunks.contains(&digest)),
        StagedUpload::Meta { kind, bytes } => !TERRANE_V1
            .calculate(*kind, bytes)
            .and_then(|identity| identity.terrane_v1_digest())
            .is_ok_and(|digest| roots.contains(&digest) && !auxiliary.contains(&digest)),
    });
    Ok(())
}

async fn publish(
    repository: &NativeRepository,
    model: &mut Model,
    mut diagnostic: Option<&mut crate::diagnostic_clock::FixtureScope>,
) -> TestResult<CommitReport> {
    let token = crate::ref_advance::tests::token();
    trace_subphase("publication-begin-before");
    let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
    trace_subphase("publication-begin-after");
    if let Some(diagnostic) = diagnostic.as_deref_mut() {
        diagnostic.phase(crate::diagnostic_clock::Phase::MaintainedTree);
    }
    trace_subphase("publication-tree-before");
    let tree = PreparedTree::from_tree(&model.tree.tree()?)?;
    trace_subphase("publication-tree-after");
    if let Some(diagnostic) = diagnostic {
        diagnostic.phase(crate::diagnostic_clock::Phase::MaintainedCommit);
    }
    trace_subphase("publication-commit-before");
    let report = repository
        .commit_with_report(
            &mut session,
            tree,
            model.request.take().ok_or_else(invalid)?,
        )
        .await?;
    trace_subphase("publication-commit-after");
    Ok(report)
}

async fn assert_outputs(
    repository: &NativeRepository,
    report: &CommitReport,
    expected: &Model,
) -> TestResult {
    let guard = repository.coordinator().guard();
    trace_subphase("verified-history-before");
    let history = guard.verified_history(report.record.commit).await?;
    trace_subphase("verified-history-after");
    assert_eq!(
        history
            .commit(&report.record.commit)
            .ok_or_else(invalid)?
            .commit()
            .tree,
        expected.root
    );
    trace_subphase("current-ref-before");
    assert_eq!(
        guard.store().ref_get(REFERENCE).await?,
        Some(report.record.clone())
    );
    trace_subphase("current-ref-after");
    trace_subphase("immutable-assertions-before");
    assert_immutable(repository, expected).await?;
    trace_subphase("immutable-assertions-after");
    for operation in &report.index_work.operations {
        let data = expected.indexes.get(&operation.owner).ok_or_else(invalid)?;
        assert_eq!(operation.association.index, data.root);
        trace_subphase("index-load-before");
        let loaded = indexing::load(
            guard.store(),
            operation.owner,
            "uid",
            SemanticRevisions {
                property: 3,
                attribute: 2,
                tree: 1,
            },
            MINIMUM,
        )
        .await?;
        trace_subphase("index-load-after");
        trace_subphase("index-sources-before");
        let source = loaded.sources()?;
        trace_subphase("index-sources-after");
        trace_subphase("index-prepare-before");
        let strict = loaded.prepare(&source.trees)?;
        trace_subphase("index-prepare-after");
        assert_eq!(strict.root(), data.root);
        trace_subphase("index-all-missing-before");
        assert!(strict.all_missing()?.rows.is_empty());
        trace_subphase("index-all-missing-after");
        assert!(strict.gap_root().is_none());
    }
    Ok(())
}

fn leaves<'a>(
    nodes: &'a BTreeMap<Digest, Vec<u8>>,
    root: Digest,
    usage: TreeUse,
) -> TestResult<Vec<LeafItem<'a>>> {
    let decoded =
        tree_format::decode_node_for(nodes.get(&root).ok_or_else(invalid)?, true, MINIMUM, usage)?;
    match decoded.items {
        NodeItems::Leaf(items) => Ok(items),
        NodeItems::Internal(children) => {
            let mut items = Vec::new();
            for child in children {
                items.extend(leaves(nodes, child.child, usage)?);
            }
            Ok(items)
        }
    }
}

fn tree<'a>(
    nodes: &'a BTreeMap<Digest, Vec<u8>>,
    root: Digest,
    usage: TreeUse,
) -> TestResult<Tree<'a>> {
    let decoded =
        tree_format::decode_node_for(nodes.get(&root).ok_or_else(invalid)?, true, MINIMUM, usage)?;
    let rebuilt = Tree::build(leaves(nodes, root, usage)?, decoded.props, MINIMUM, usage)?;
    assert_eq!(rebuilt.root_identity(), root);
    Ok(rebuilt)
}

fn auxiliary(data: &evaluation::IndexData) -> TestResult<BTreeMap<Coordinate, Digest>> {
    let mut result = BTreeMap::from([(Coordinate::Primary, data.root)]);
    for item in leaves(&data.nodes, data.root, TreeUse::Index)? {
        let key = terrane_format::indexing::IndexKey::decode(&item.key)?;
        let row = classify_entry(SemanticContext::new(3, 2, 1)?, &item.entry)?;
        let predicate = Predicate {
            object: key.object(),
            value: Some(key.value().to_vec()),
        };
        route_coordinates(
            data,
            predicate,
            Vec::new(),
            row.route().ok_or_else(invalid)?,
            &mut result,
        )?;
    }
    Ok(result)
}

fn route_coordinates(
    data: &evaluation::IndexData,
    predicate: Predicate,
    hops: Vec<Vec<u8>>,
    root: Digest,
    result: &mut BTreeMap<Coordinate, Digest>,
) -> TestResult {
    result.insert(
        Coordinate::Route {
            predicate: predicate.clone(),
            hops: hops.clone(),
        },
        root,
    );
    for item in leaves(&data.nodes, root, TreeUse::Index)? {
        if let Some(child) = classify_entry(SemanticContext::new(3, 2, 1)?, &item.entry)?.route() {
            let mut next = hops.clone();
            next.push(item.key);
            route_coordinates(data, predicate.clone(), next, child, result)?;
        }
    }
    Ok(())
}

fn assert_work(
    report: &CommitReport,
    expected: &BTreeMap<bool, ExpectedWork>,
    adversarial: bool,
) -> TestResult {
    assert_eq!(report.index_work.operations.len(), 2);
    for operation in &report.index_work.operations {
        let root = operation.paths == [b"/".to_vec()];
        let oracle = expected.get(&root).ok_or_else(invalid)?;
        let work = operation.update.as_ref().ok_or_else(invalid)?;
        assert_eq!(work.mode, PopulationMode::Existing);
        assert!(operation.initialization.is_none());
        assert!(operation.old_loading.is_some());
        assert!(operation.old_reconstruction.is_some());
        assert!(operation.old_index.is_some());
        assert_eq!(
            (work.delta_input, work.delta_data, work.delta_route),
            (oracle.input, oracle.data, oracle.route)
        );
        source::assert_work(work, &oracle.source);
        let expected_boundary = oracle.source.boundary
            + oracle
                .batches
                .values()
                .map(physical::boundary_cost)
                .sum::<usize>();
        assert_eq!(
            operation.boundary,
            Some(expected_boundary),
            "independently serialized auxiliary and namespace boundary work"
        );
        assert_eq!(work.batches.len(), oracle.batches.len());
        for batch in &work.batches {
            physical::assert_partition(&batch.work);
            let expected = oracle.batches.get(&batch.coordinate).ok_or_else(invalid)?;
            physical::assert_batch(batch, expected);
        }
        assert!(
            !oracle.reused.is_empty(),
            "unchanged canonical subtree must survive"
        );
        if root {
            assert!(
                oracle
                    .batches
                    .get(&Coordinate::Primary)
                    .ok_or_else(invalid)?
                    .old_level
                    > 0,
                "actual internal primary index"
            );
            assert_eq!(operation.paths, [b"/".to_vec()]);
            // The repeated root-local population belongs to object zero. Other
            // objects share uid=3 through grafts but have small local routes.
            let common_route = Coordinate::Route {
                predicate: Predicate {
                    object: TERRANE_V1
                        .calculate(IdentityKind::Chunk, &body(0))?
                        .terrane_v1_digest()?,
                    value: Some(uint(3)),
                },
                hops: Vec::new(),
            };
            let large = oracle.batches.get(&common_route).ok_or_else(invalid)?;
            assert!(large.old_level > 0, "actual internal occurrence tree");
            assert!(
                large
                    .regions
                    .iter()
                    .filter(|region| region.level == 0)
                    .count()
                    == 1,
                "overlapping leaf suffix processed once"
            );
            if adversarial {
                assert!(
                    large
                        .regions
                        .iter()
                        .filter(|region| region.level == 0)
                        .all(|region| region.resynchronized.is_none()),
                    "cap-driven shift reaches stream tail"
                );
            } else {
                let native = work
                    .batches
                    .iter()
                    .find(|batch| batch.coordinate == common_route)
                    .ok_or_else(invalid)?;
                assert!(
                    native
                        .work
                        .regions
                        .iter()
                        .any(|region| region.level == 0 && region.resynchronized.is_some()),
                    "ordinary canonical edit recovers an actual old leaf boundary"
                );
            }
        } else {
            assert_eq!(operation.paths.len(), REPEATS);
        }
    }
    costs::assert_report(report, expected, adversarial)?;
    Ok(())
}

async fn assert_immutable(repository: &NativeRepository, expected: &Model) -> TestResult {
    let entries: Vec<_> = expected
        .published_sources
        .iter()
        .chain(expected.indexes.values().flat_map(|data| data.nodes.iter()))
        .collect();
    let mut completed = 0;
    for group in entries.chunks(64) {
        let identities = group
            .iter()
            .map(|(digest, _)| TERRANE_V1.from_digest(IdentityKind::Node, *digest))
            .collect::<Result<Vec<_>, _>>()?;
        let values = repository
            .coordinator()
            .store()
            .get_many(&identities)
            .await?;
        assert_eq!(values.len(), group.len());
        for ((_, expected), actual) in group.iter().zip(values) {
            assert_eq!(actual, **expected);
        }

        completed += group.len();
        if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
            eprintln!(
                "multi-edit-subphase immutable-map-entries-completed={}",
                completed
            );
        }
    }
    Ok(())
}

fn trace_subphase(phase: &str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!("multi-edit-subphase phase={phase}");
    }
}

/// Builds the independently sorted containing root with two genuine graft occurrences.
fn root_tree<'a>(
    entries: &[LeafItem<'a>],
    stable: Digest,
    acl: &'a [u8],
    child: Digest,
    roots: Option<&'a [u8]>,
) -> Result<Tree<'a>, tree_format::Error> {
    let mut local = entries.to_vec();
    for position in 0..REPEATS {
        local.push(LeafItem {
            key: format!("g{position:02}").into_bytes(),
            entry: graft(child),
        });
    }
    local.push(LeafItem {
        key: b"unchanged".to_vec(),
        entry: graft(stable),
    });
    local.sort_by(|left, right| left.key.cmp(&right.key));
    Tree::build(
        local,
        Some(properties(roots, acl)),
        MINIMUM,
        TreeUse::Ordinary,
    )
}
