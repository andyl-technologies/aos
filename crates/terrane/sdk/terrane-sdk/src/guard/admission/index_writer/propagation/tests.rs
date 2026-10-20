//! Checks canonical recursive graft replacement without granting native eligibility.
//!
//! These algorithm fixtures construct only immutable Trees and operation-local
//! plans. They are not completed history, Original or publication evidence.

use super::*;
use crate::guard::TreeEvidence;
use terrane_format::tree_format::{LeafItem, TreeUse};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Batches overlapping Conflict candidate/base links while retaining original entries.
///
/// # Errors
/// Preserves canonical fixture and actual prepared lookup/edit failures.
/// # Panics
/// Panics if slots, counters or immutable input preservation disagree.
#[test]
fn prepared_graft_targets_batch_conflict_candidates_and_present_base() -> TestResult {
    let old_a = directory(b"old-a")?;
    let old_b = directory(b"old-b")?;
    let new_a = directory(b"new-a")?;
    let new_b = directory(b"new-b")?;
    let original = tree(vec![
        item(
            b"mixed",
            bare(EntryKind::Conflict {
                candidates: vec![graft(old_a.root_identity()), graft(old_b.root_identity())],
                base: Some(Some(Box::new(graft(old_a.root_identity())))),
            }),
        ),
        item(b"unrelated", bare(EntryKind::Directory { mode: 0o755 })),
    ])?;
    let graph = graph(&[&old_a, &old_b, &original]);
    let grafts = validated(&graph, original.root_identity())?;
    let plans = [
        plan(&old_a, 1, 2, &grafts),
        plan(&old_b, 1, 1, &grafts),
        plan(&original, 0, 1, &grafts),
    ];
    let mut targets = PreparedTargets::new(&graph, &plans)?;
    let replacements = BTreeMap::from([
        (old_a.root_identity(), new_a.root_identity()),
        (old_b.root_identity(), new_b.root_identity()),
    ]);
    assert!(
        targets
            .take_edits(old_a.root_identity(), &old_a, &replacements)?
            .is_empty()
    );
    targets.complete(old_a.root_identity(), new_a.root_identity())?;
    assert!(
        targets
            .take_edits(old_b.root_identity(), &old_b, &replacements)?
            .is_empty()
    );
    targets.complete(old_b.root_identity(), new_b.root_identity())?;
    let edits = targets.take_edits(original.root_identity(), &original, &replacements)?;
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0].0, b"mixed");
    let updated = original.edit_entries(&edits)?;
    targets.complete(original.root_identity(), updated.tree.root_identity())?;
    assert_conflict(&original, old_a.root_identity(), old_b.root_identity())?;
    assert_conflict(&updated.tree, new_a.root_identity(), new_b.root_identity())?;
    assert_eq!(original.get(b"unrelated"), updated.tree.get(b"unrelated"));
    let preparation = targets.preparation();
    assert_eq!(preparation.owners, 3);
    assert_eq!(preparation.owner_occurrences, 4);
    assert_eq!(preparation.entry_visits, 0);
    assert_eq!(preparation.nested_entry_visits, 0);
    let validation = targets.validation();
    assert_eq!(validation.entry_visits, 4);
    assert_eq!(validation.nested_entry_visits, 7);
    assert_eq!(validation.graft_slots, 3);
    assert_eq!(validation.addresses, 3);
    assert_eq!(validation.key_bytes, 3 * b"mixed".len());
    assert_eq!(preparation.graft_slots, 3);
    assert_eq!(preparation.graft_occurrences, 3);
    let work = targets.work();
    assert_eq!(work.changed_targets, 3);
    assert_eq!(work.target_lookups, 3);
    assert_eq!(work.address_links, 3);
    assert_eq!(work.affected_occurrences, 3);
    assert_eq!(work.selected_entries, 1);
    assert_eq!(work.entry_lookups, 1);
    assert_eq!(work.nested_entry_visits, 4);
    assert_eq!(work.replacement_lookups, 3);
    assert_eq!(work.replaced_graft_slots, 3);
    assert_eq!(work.edited_entries, 1);
    Ok(())
}

/// Keeps physical target links and repeated containing-owner multiplicities distinct.
///
/// # Errors
/// Preserves canonical fixture and actual prepared lookup/edit failures.
/// # Panics
/// Panics if repeated links collapse or equal targets schedule work.
#[test]
fn prepared_graft_targets_keep_repeated_occurrences_and_skip_equal_targets() -> TestResult {
    let child = directory(b"old")?;
    let replacement = directory(b"new")?;
    let parent = tree(vec![
        item(b"a", graft(child.root_identity())),
        item(b"b", graft(child.root_identity())),
    ])?;
    let root = tree(vec![
        item(b"x", graft(parent.root_identity())),
        item(b"y", graft(parent.root_identity())),
    ])?;
    let graph = graph(&[&child, &parent, &root]);
    let grafts = validated(&graph, root.root_identity())?;
    let plans = [
        plan(&child, 2, 4, &grafts),
        plan(&parent, 1, 2, &grafts),
        plan(&root, 0, 1, &grafts),
    ];
    let mut unchanged = PreparedTargets::new(&graph, &plans)?;
    let mut equal = BTreeMap::new();
    for original in [&child, &parent, &root] {
        let owner = original.root_identity();
        assert!(unchanged.take_edits(owner, original, &equal)?.is_empty());
        equal.insert(owner, owner);
        unchanged.complete(owner, owner)?;
    }
    assert_eq!(unchanged.work(), IndexGraftPropagationWork::default());
    assert_eq!(unchanged.preparation().graft_occurrences, 6);

    let mut targets = PreparedTargets::new(&graph, &plans)?;
    let mut replacements = BTreeMap::new();
    assert!(
        targets
            .take_edits(child.root_identity(), &child, &replacements)?
            .is_empty()
    );
    replacements.insert(child.root_identity(), replacement.root_identity());
    targets.complete(child.root_identity(), replacement.root_identity())?;
    let parent_edits = targets.take_edits(parent.root_identity(), &parent, &replacements)?;
    assert_eq!(parent_edits.len(), 2);
    let new_parent = parent.edit_entries(&parent_edits)?;
    replacements.insert(parent.root_identity(), new_parent.tree.root_identity());
    targets.complete(parent.root_identity(), new_parent.tree.root_identity())?;
    let root_edits = targets.take_edits(root.root_identity(), &root, &replacements)?;
    assert_eq!(root_edits.len(), 2);
    let new_root = root.edit_entries(&root_edits)?;
    targets.complete(root.root_identity(), new_root.tree.root_identity())?;
    for key in [b"a", b"b"] {
        assert_target(&new_parent.tree, key, replacement.root_identity())?;
    }
    for key in [b"x", b"y"] {
        assert_target(&new_root.tree, key, new_parent.tree.root_identity())?;
    }
    let preparation = targets.preparation();
    assert_eq!((preparation.owners, preparation.owner_occurrences), (3, 7));
    assert_eq!(
        (
            preparation.entry_visits,
            preparation.graft_slots,
            preparation.graft_occurrences
        ),
        (0, 4, 6)
    );
    let work = targets.work();
    assert_eq!((work.changed_targets, work.target_lookups), (3, 3));
    assert_eq!((work.address_links, work.affected_occurrences), (4, 6));
    assert_eq!(
        (
            work.selected_entries,
            work.entry_lookups,
            work.edited_entries
        ),
        (4, 4, 4)
    );
    assert_eq!(work.replaced_graft_slots, 4);
    assert_target(&parent, b"a", child.root_identity())?;
    assert_target(&root, b"x", parent.root_identity())?;
    Ok(())
}

/// Refuses contradictory graph, ordering and repeated consumption without a result.
///
/// # Errors
/// Preserves canonical fixture construction failures.
/// # Panics
/// Panics if a malformed operation-local selector is accepted or reclassified.
#[test]
fn prepared_graft_targets_refuse_inconsistent_owned_lookup_inputs() -> TestResult {
    let child = directory(b"child")?;
    let parent = tree(vec![item(b"g", graft(child.root_identity()))])?;
    let graph = graph(&[&child, &parent]);
    let grafts = validated(&graph, parent.root_identity())?;
    assert_invalid(PreparedTargets::new(
        &graph,
        &[plan(&parent, 0, 1, &grafts), plan(&child, 1, 1, &grafts)],
    ));
    assert_invalid(PreparedTargets::new(
        &graph,
        &[plan(&child, 1, 1, &grafts), plan(&child, 1, 1, &grafts)],
    ));
    assert_invalid(PreparedTargets::new(
        &BTreeMap::new(),
        &[plan(&child, 1, 1, &grafts)],
    ));
    assert_invalid(PreparedTargets::new(&graph, &[plan(&child, 1, 0, &grafts)]));
    let separate = validated(&graph, parent.root_identity())?;
    assert_invalid(PreparedTargets::new(
        &graph,
        &[plan(&child, 1, 1, &grafts), plan(&parent, 0, 1, &separate)],
    ));
    assert_invalid(PreparedTargets::new(&graph, &[plan(&child, 0, 1, &grafts)]));
    let mut targets = PreparedTargets::new(
        &graph,
        &[plan(&child, 1, 1, &grafts), plan(&parent, 0, 1, &grafts)],
    )?;
    assert_invalid(targets.complete(child.root_identity(), parent.root_identity()));
    assert_invalid(targets.take_edits(child.root_identity(), &parent, &BTreeMap::new()));
    // A failed consuming call cannot qualify subsequent operation-local use.
    assert_invalid(targets.take_edits(child.root_identity(), &child, &BTreeMap::new()));
    Ok(())
}

fn directory(key: &[u8]) -> Result<Tree<'static>, Box<dyn std::error::Error>> {
    tree(vec![item(key, bare(EntryKind::Directory { mode: 0o755 }))])
}

fn tree(entries: Vec<LeafItem<'static>>) -> Result<Tree<'static>, Box<dyn std::error::Error>> {
    Ok(Tree::build(entries, None, 262144, TreeUse::Ordinary)?)
}

fn graph(trees: &[&Tree<'static>]) -> BTreeMap<Digest, Tree<'static>> {
    trees
        .iter()
        .map(|tree| (tree.root_identity(), (**tree).clone()))
        .collect()
}

// Uses the same complete canonical validator as actual acquisition. These
// unsigned algorithm fixtures still provide no history or current authority.
fn validated(
    graph: &BTreeMap<Digest, Tree<'_>>,
    root: Digest,
) -> Result<Arc<ValidatedGrafts>, Box<dyn std::error::Error>> {
    let mut evidence = TreeEvidence {
        usage: TreeUse::Ordinary,
        ordinary_roots: BTreeSet::new(),
        commit: None,
        root,
        default_domain: String::new(),
        nodes: graph
            .values()
            .flat_map(|tree| {
                tree.nodes()
                    .map(|node| (node.identity(), node.encoded().to_vec()))
            })
            .collect(),
        roots: graph.keys().copied().collect(),
        grafts: None,
    };
    evidence.validate_namespace(262144)?;
    assert!(evidence.validated_grafts(262145).is_err());
    Ok(evidence.validated_grafts(262144)?)
}

fn plan(
    tree: &Tree<'_>,
    depth: usize,
    occurrences: usize,
    grafts: &Arc<ValidatedGrafts>,
) -> OwnerPlan {
    OwnerPlan {
        owner: tree.root_identity(),
        depth: depth + 1,
        occurrences,
        attributes: BTreeMap::new(),
        grafts: Arc::clone(grafts),
    }
}

fn graft(root: Digest) -> Entry<'static> {
    bare(EntryKind::Tree { root, props: None })
}

fn item(key: &[u8], entry: Entry<'static>) -> LeafItem<'static> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

fn bare(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn assert_target(tree: &Tree<'_>, key: &[u8], expected: Digest) -> TestResult {
    let entry = tree.get(key).ok_or_else(invalid)?;
    assert!(matches!(&entry.kind, EntryKind::Tree { root, .. } if *root == expected));
    Ok(())
}

fn assert_conflict(tree: &Tree<'_>, a: Digest, b: Digest) -> TestResult {
    let entry = tree.get(b"mixed").ok_or_else(invalid)?;
    let EntryKind::Conflict { candidates, base } = &entry.kind else {
        panic!("expected actual canonical Conflict");
    };
    assert_eq!(candidates.len(), 2);
    assert!(matches!(&candidates[0].kind, EntryKind::Tree { root, .. } if *root == a));
    assert!(matches!(&candidates[1].kind, EntryKind::Tree { root, .. } if *root == b));
    let base = base.as_ref().and_then(Option::as_ref).ok_or_else(invalid)?;
    assert!(matches!(&base.kind, EntryKind::Tree { root, .. } if *root == a));
    Ok(())
}

fn assert_invalid<T>(result: Result<T, StoreFailure>) {
    match result {
        Err(error) => assert_eq!(error.kind(), invalid().kind()),
        Ok(_) => panic!("expected exact invalid selector refusal"),
    }
}
