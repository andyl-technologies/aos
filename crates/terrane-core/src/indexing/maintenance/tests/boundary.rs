//! Finds a genuine changed auxiliary ChildRef that destroys an old content cut.

use super::*;
use crate::{cbor, tree_builder::StoredNode, tree_format::NodeItems};

fn child_bytes(child: &StoredNode<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 4);
    cbor::write_bytes(&mut bytes, child.last_key().unwrap());
    cbor::write_bytes(&mut bytes, &child.identity());
    cbor::write_uint(&mut bytes, child.count());
    cbor::write_uint(&mut bytes, child.weight());
    bytes
}

// Expand TREE-21/22 independently: do not consult the production boundary
// helper or infer a content cut from the editor's accounting annotations.
fn content_cut(size: usize, length: usize, bytes: &[u8]) -> bool {
    if !(4096..65536).contains(&size) {
        return false;
    }
    let base = if size >= 32768 {
        1_u64 << 24
    } else {
        (1_u64 << 20) + (u64::try_from(size).unwrap() - 4096) * ((1 << 24) - (1 << 20)) / 28672
    };
    let hash = blake3::hash(bytes);
    let bytes = hash.as_bytes();
    u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        < (base * u64::try_from(length).unwrap() / 8).min(1 << 32)
}

/// Checks separate recovered leaf regions and shared unchanged middle Nodes.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_separated_recovery_and_middle() {
    let keys: Vec<_> = (0..24000)
        .map(|index| alloc::format!("item-{index:08}-{}", "x".repeat(180)).into_bytes())
        .collect();
    let mut graph = Graph::new();
    let owner = add(
        &mut graph,
        keys.iter()
            .map(|key| leaf(key, file(ONE, Some(VALUES[0]), false)))
            .collect(),
    );
    let previous = oracle::Model::new(&graph, owner);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let arena = ByteArena::new(16 * 1024 * 1024).unwrap();
    let (state, _) = prepare(
        &recipe,
        &source,
        &graph,
        &previous.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let coordinate = Coordinate::Route {
        predicate: Predicate {
            object: ONE,
            value: Some(VALUES[0].to_vec()),
        },
        hops: Vec::new(),
    };
    let mut scratch = MapWork::default();
    let tree = state.routes.get(&coordinate, &mut scratch).unwrap();
    let changed = graph[&owner]
        .edit_entries(
            &[1000, 22000].map(|index| (keys[index].clone(), Some(file(ONE, None, false)))),
        )
        .unwrap()
        .tree;
    let new_owner = changed.root_identity();
    let mut new_graph = graph.clone();
    new_graph.insert(new_owner, changed);
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let after = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let discovery = discover(&source, &after).unwrap();
    let (updated, work) = update(&state, &discovery).unwrap();
    let batch = work
        .batches
        .iter()
        .find(|batch| batch.coordinate == coordinate)
        .unwrap();
    let regions: Vec<_> = batch
        .work
        .regions
        .iter()
        .filter(|region| region.level == 0)
        .collect();
    assert_eq!(regions.len(), 2);
    assert!(regions[0].resynchronized.is_some());
    assert!(regions[1].resynchronized.is_some());
    assert!(regions[0].last < regions[1].invalidated);

    fn handles<'a>(node: Rc<StoredNode<'a>>, output: &mut Vec<Rc<StoredNode<'a>>>) {
        for child in node.children() {
            handles(Rc::clone(child), output);
        }
        output.push(node);
    }
    let mut before = Vec::new();
    let mut after = Vec::new();
    handles(tree.root_rc(), &mut before);
    let mut scratch = MapWork::default();
    handles(
        updated
            .routes
            .get(&coordinate, &mut scratch)
            .unwrap()
            .root_rc(),
        &mut after,
    );
    let mut old_leaves: Vec<_> = before.iter().filter(|node| node.level() == 0).collect();
    old_leaves.sort_by(|left, right| left.last_key().cmp(&right.last_key()));
    for (region, index) in regions.iter().zip([1000, 22000]) {
        let position = old_leaves
            .iter()
            .position(|node| node.last_key().unwrap() >= keys[index].as_slice())
            .unwrap();
        assert_eq!(
            region.invalidated.as_slice(),
            old_leaves[position.saturating_sub(1)].last_key().unwrap()
        );
        let endpoint = after
            .iter()
            .find(|node| node.level() == 0 && node.last_key() == Some(region.last.as_slice()))
            .unwrap();
        let NodeItems::Leaf(rows) = endpoint.items() else {
            unreachable!();
        };
        let mut previous = &[][..];
        let mut size = 0;
        let mut last_length = 0;
        for row in rows {
            last_length = trace::terminal(&row.key, previous).len();
            size += last_length;
            previous = &row.key;
        }
        assert!(size == 65536 || content_cut(size, last_length, &trace::terminal(previous, &[])));
    }
    let middle: Vec<_> = before
        .iter()
        .filter(|node| {
            node.level() == 0
                && node.first_key().unwrap() > regions[0].last.as_slice()
                && node.last_key().unwrap() < regions[1].invalidated.as_slice()
        })
        .collect();
    assert!(!middle.is_empty());
    for old in middle {
        let new = after
            .iter()
            .find(|new| new.identity() == old.identity())
            .unwrap();
        assert!(Rc::ptr_eq(old, new));
    }
    let replacement = oracle::Model::new(&new_graph, new_owner);
    oracle::assert_discovery(&previous, &replacement, &discovery);
    oracle::assert_routes(&previous, &replacement, &work);
    assert_result(&updated, &new_graph, new_owner, &replacement);
}

/// Checks a real changed ChildRef that destroys a nonterminal internal content cut.
///
/// # Panics
/// Panics if fixture construction or an asserted independent witness fails.
pub(super) fn assert_internal_content_cut() {
    let mut graph = Graph::new();
    let owner = add(
        &mut graph,
        (0..24000)
            .map(|index| {
                leaf(
                    alloc::format!("item-{index:08}-{}", "x".repeat(180)).as_bytes(),
                    file(ONE, Some(VALUES[0]), false),
                )
            })
            .collect(),
    );
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let source = PreparedSource::new(&recipe, &graph, MINIMUM, context()).unwrap();
    let previous = oracle::Model::new(&graph, owner);
    let arena = ByteArena::new(8 * 1024 * 1024).unwrap();
    let (state, _) = prepare(
        &recipe,
        &source,
        &graph,
        &previous.data,
        &arena,
        MINIMUM,
        context(),
    )
    .unwrap();
    let coordinate = Coordinate::Route {
        predicate: Predicate {
            object: ONE,
            value: Some(VALUES[0].to_vec()),
        },
        hops: Vec::new(),
    };
    let mut scratch = MapWork::default();
    let tree = state.routes.get(&coordinate, &mut scratch).unwrap();
    let mut parents: Vec<_> = tree.nodes().filter(|node| node.level() == 1).collect();
    parents.sort_by(|left, right| left.last_key().cmp(&right.last_key()));
    let mut witness = None;
    for (index, parent) in parents.iter().enumerate() {
        if parent.last_key() == tree.root().last_key() {
            continue;
        }
        let child = parent.children().last().unwrap();
        let old_ref = child_bytes(child);
        let size: usize = parent
            .children()
            .iter()
            .map(|child| child_bytes(child).len())
            .sum();
        if !content_cut(size, old_ref.len(), &old_ref) {
            continue;
        }
        let NodeItems::Leaf(items) = child.items() else {
            unreachable!();
        };
        for removed in 1..items.len().saturating_sub(1) {
            let mut rows = items.clone();
            let removed = rows.remove(removed);
            let replacement = Tree::build(rows, None, MINIMUM, TreeUse::Index).unwrap();
            if replacement.root().level() != 0
                || replacement.root().last_key() != child.last_key()
                || replacement.root().first_key() != child.first_key()
            {
                continue;
            }
            let new_ref = child_bytes(replacement.root());
            let new_size = size - old_ref.len() + new_ref.len();
            if !content_cut(new_size, new_ref.len(), &new_ref) {
                let independent_edit = tree.edit_entries(&[(removed.key.clone(), None)]).unwrap();
                if independent_edit
                    .tree
                    .nodes()
                    .any(|node| node.identity() == replacement.root_identity())
                {
                    witness = Some((
                        index,
                        removed.key,
                        old_ref,
                        new_ref,
                        size,
                        new_size,
                        replacement.root_identity(),
                    ));
                    break;
                }
            }
        }
        if witness.is_some() {
            break;
        }
    }
    let Some((index, key, old_ref, new_ref, old_size, new_size, child_identity)) = witness else {
        panic!("a changed real ChildRef must destroy a nonterminal internal content cut");
    };
    assert!(content_cut(old_size, old_ref.len(), &old_ref));
    assert!(!content_cut(new_size, new_ref.len(), &new_ref));
    let changed = graph[&owner]
        .edit_entries(&[(key.clone(), Some(file(ONE, None, false)))])
        .unwrap()
        .tree;
    let new_owner = changed.root_identity();
    let mut new_graph = graph.clone();
    new_graph.insert(new_owner, changed);
    let new_recipe = IndexEvaluationRecipe::new(new_owner, "uid").unwrap();
    let new_source = PreparedSource::new(&new_recipe, &new_graph, MINIMUM, context()).unwrap();
    let discovery = discover(&source, &new_source).unwrap();
    let (updated, work) = update(&state, &discovery).unwrap();
    let replacement = oracle::Model::new(&new_graph, new_owner);
    oracle::assert_discovery(&previous, &replacement, &discovery);
    oracle::assert_routes(&previous, &replacement, &work);
    check_phase_partition(&work);
    let batch = work
        .batches
        .iter()
        .find(|batch| batch.coordinate == coordinate)
        .unwrap();
    let region = batch
        .work
        .regions
        .iter()
        .find(|region| region.level == 1)
        .unwrap();
    let first_connected = parents[index.saturating_sub(1)].last_key().unwrap();
    assert_eq!(region.invalidated, first_connected);
    assert!(region.last.as_slice() > parents[index].last_key().unwrap());
    assert!(region.work.item_bytes_hashed > 0);
    let mut scratch = MapWork::default();
    let actual = updated.routes.get(&coordinate, &mut scratch).unwrap();
    assert!(actual.nodes().any(|node| node.identity() == child_identity));
    if let Some(recovered) = &region.resynchronized {
        assert_eq!(recovered, &region.last);
        let endpoint = actual
            .nodes()
            .find(|node| node.level() == 1 && node.last_key() == Some(recovered.as_slice()))
            .unwrap();
        let size: usize = endpoint
            .children()
            .iter()
            .map(|child| child_bytes(child).len())
            .sum();
        let last = child_bytes(endpoint.children().last().unwrap());
        assert!(size == 65536 || content_cut(size, last.len(), &last));
    } else {
        assert_eq!(region.last.as_slice(), tree.root().last_key().unwrap());
    }
    assert_result(&updated, &new_graph, new_owner, &replacement);
}
