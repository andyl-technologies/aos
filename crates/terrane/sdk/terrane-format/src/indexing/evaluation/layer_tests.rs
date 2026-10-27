//! Checks retained Layer sources through public construction and verification APIs.

#![allow(clippy::unwrap_used, reason = "test fixture failures must panic")]

use super::*;
use alloc::vec;

const MINIMUM: u64 = CDC_1M_MIN as u64;
const OBJECT: Digest = [7; 32];

fn item(key: &[u8], kind: EntryKind<'static>, value: Option<&'static [u8]>) -> LeafItem<'static> {
    LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind,
            attrs: value
                .map(|value| vec![Attribute { name: "uid", value }])
                .unwrap_or_default(),
            attrs_present: value.is_some(),
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    }
}

fn file(key: &[u8], value: Option<&'static [u8]>) -> LeafItem<'static> {
    item(
        key,
        EntryKind::File {
            mode: 0o644,
            size: 10,
            content: ContentRef::Inline(OBJECT),
            link_id: None,
        },
        value,
    )
}

fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

#[test]
fn layer_index_preserves_regular_file_rows_and_exact_graft_occurrences() {
    let child = Tree::build(
        vec![
            file(b"file", Some(&[1])),
            item(b"hidden", EntryKind::Whiteout, None),
        ],
        None,
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let owner = Tree::build(
        vec![
            file(b"absent", None),
            item(b"deleted", EntryKind::Whiteout, None),
            item(
                b"g",
                EntryKind::Tree {
                    root: child.root_identity(),
                    props: None,
                },
                None,
            ),
            item(
                b"h",
                EntryKind::Tree {
                    root: child.root_identity(),
                    props: None,
                },
                None,
            ),
        ],
        None,
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let recipe = IndexEvaluationRecipe::new(owner.root_identity(), "uid").unwrap();
    let sources = BTreeMap::from([
        (child.root_identity(), child),
        (owner.root_identity(), owner),
    ]);

    let data = construct(&recipe, &sources, MINIMUM, context()).unwrap();
    let report = verify(&recipe, &sources, MINIMUM, context(), &data).unwrap();

    assert_eq!(report.candidates, 1);
    assert_eq!(report.missing_objects, 1);
    assert!(report.work.source_roots > sources.len());

    let arena = crate::indexing::maintenance::ByteArena::new(1_000_000).unwrap();
    let prepared =
        crate::indexing::incremental::PreparedSource::new(&recipe, &sources, MINIMUM, context())
            .unwrap();
    let (maintained, _) =
        crate::indexing::maintenance::initialize(&recipe, &prepared, &arena, MINIMUM, context())
            .unwrap();
    let next_owner = sources[&recipe.owner()]
        .insert(file(b"absent", Some(&[2])))
        .unwrap()
        .tree;
    let next_root = next_owner.root_identity();
    let mut next_sources = sources.clone();
    next_sources.insert(next_root, next_owner);
    let next_recipe = IndexEvaluationRecipe::new(next_root, "uid").unwrap();
    let replacement = crate::indexing::incremental::PreparedSource::new(
        &next_recipe,
        &next_sources,
        MINIMUM,
        context(),
    )
    .unwrap();
    let discovery = crate::indexing::incremental::discover(&prepared, &replacement).unwrap();
    let (updated, work) = crate::indexing::maintenance::update(&maintained, &discovery).unwrap();
    let (actual, _) = updated.materialize().unwrap();
    let expected = construct(&next_recipe, &next_sources, MINIMUM, context()).unwrap();
    assert_eq!(actual.root, expected.root);
    assert_eq!(actual.nodes, expected.nodes);
    assert_eq!(work.delta_data, 1);
    let checked = verify(&next_recipe, &next_sources, MINIMUM, context(), &actual).unwrap();
    assert_eq!(checked.candidates, 2);
    assert_eq!(checked.missing_objects, 0);

    for bytes in data.nodes.values() {
        let node = decode_node_for(bytes, true, MINIMUM, TreeUse::Index).unwrap();
        if let NodeItems::Leaf(items) = node.items {
            assert!(
                items
                    .iter()
                    .all(|item| matches!(item.entry.kind, EntryKind::Index { .. }))
            );
            assert!(
                items
                    .iter()
                    .all(|item| item.key != b"deleted" && item.key != b"hidden")
            );
        }
    }
}

#[test]
fn layer_index_keeps_ordinary_identity_and_rejects_nonnamespace_contexts() {
    let entries = vec![file(b"file", Some(&[1]))];
    let ordinary = Tree::build(entries.clone(), None, MINIMUM, TreeUse::Ordinary).unwrap();
    let layer = Tree::build(entries.clone(), None, MINIMUM, TreeUse::OverlayLayer).unwrap();
    assert_eq!(ordinary.root_identity(), layer.root_identity());
    assert_eq!(ordinary.root().encoded(), layer.root().encoded());
    let root = ordinary.root_identity();
    let recipe = IndexEvaluationRecipe::new(root, "uid").unwrap();

    let data = construct(
        &recipe,
        &BTreeMap::from([(root, ordinary)]),
        MINIMUM,
        context(),
    )
    .unwrap();
    let layered = BTreeMap::from([(root, layer)]);
    assert_eq!(
        construct(&recipe, &layered, MINIMUM, context())
            .unwrap()
            .root,
        data.root
    );
    verify(&recipe, &layered, MINIMUM, context(), &data).unwrap();

    for usage in [TreeUse::Surface, TreeUse::ConflictSurface] {
        let tree = Tree::build(entries.clone(), None, MINIMUM, usage).unwrap();
        let graph = BTreeMap::from([(root, tree)]);
        assert_eq!(
            construct(&recipe, &graph, MINIMUM, context()),
            Err(Error::Source)
        );
        assert_eq!(
            verify(&recipe, &graph, MINIMUM, context(), &data),
            Err(Error::Source)
        );
    }
    let empty = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Index).unwrap();
    let recipe = IndexEvaluationRecipe::new(empty.root_identity(), "uid").unwrap();
    assert_eq!(
        construct(
            &recipe,
            &BTreeMap::from([(empty.root_identity(), empty)]),
            MINIMUM,
            context()
        ),
        Err(Error::Source)
    );
}

#[test]
fn layer_index_rejects_divergent_rows_and_owner_identity() {
    let owner = Tree::build(
        vec![
            file(b"file", Some(&[1])),
            item(b"hidden", EntryKind::Whiteout, None),
        ],
        None,
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let root = owner.root_identity();
    let recipe = IndexEvaluationRecipe::new(root, "uid").unwrap();
    let sources = BTreeMap::from([(root, owner.clone())]);
    let mut data = construct(&recipe, &sources, MINIMUM, context()).unwrap();
    verify(&recipe, &sources, MINIMUM, context(), &data).unwrap();

    let empty = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Index).unwrap();
    data.root = empty.root_identity();
    data.nodes = BTreeMap::from([(empty.root_identity(), empty.root().encoded().to_vec())]);
    assert_eq!(
        verify(&recipe, &sources, MINIMUM, context(), &data),
        Err(Error::Relationship)
    );

    let misplaced = BTreeMap::from([([0; 32], owner)]);
    let wrong_recipe = IndexEvaluationRecipe::new([0; 32], "uid").unwrap();
    assert_eq!(
        construct(&wrong_recipe, &misplaced, MINIMUM, context()),
        Err(Error::Source)
    );
}
