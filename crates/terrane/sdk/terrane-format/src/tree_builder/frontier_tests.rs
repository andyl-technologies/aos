//! Checks ordered adoption-frontier complexity with real immutable nodes.

use alloc::{rc::Rc, vec, vec::Vec};

use super::batch_tests::{assert_bytes, assert_partition, directory, fixture, oracle};
use super::{Error, SpliceOutcome, StoredNode, SubtreeReplacement, Tree};
use crate::tree_format::TreeUse;

fn leaves(tree: &Tree<'static>) -> Vec<Rc<StoredNode<'static>>> {
    let mut stack = vec![tree.root_rc()];
    let mut leaves = Vec::new();
    while let Some(node) = stack.pop() {
        if node.level() == 0 {
            leaves.push(node);
        } else {
            stack.extend(node.children().iter().rev().cloned());
        }
    }
    leaves
}

fn patches(targets: &[Rc<StoredNode<'static>>]) -> Vec<SubtreeReplacement<'static>> {
    targets
        .iter()
        .map(|target| SubtreeReplacement {
            old_identity: target.identity(),
            target: Rc::clone(target),
        })
        .collect()
}

fn assert_targets(tree: &Tree<'_>, targets: &[Rc<StoredNode<'_>>]) -> Result<(), Error> {
    for target in targets {
        let present = tree
            .nodes()
            .find(|node| node.identity() == target.identity())
            .ok_or(Error::Node)?;
        assert!(core::ptr::eq(present, target.as_ref()));
    }
    Ok(())
}

fn original_distant_targets_use_one_linear_frontier_with_zero_sparse_edits() -> Result<(), Error> {
    let tree = Tree::build(fixture(48000), None, 262144, TreeUse::Ordinary)?;
    let nodes = leaves(&tree);
    for count in [8, 32, 64] {
        let targets: Vec<_> = nodes
            .iter()
            .skip(3)
            .step_by(5)
            .take(count)
            .cloned()
            .collect();
        assert_eq!(targets.len(), count);
        let SpliceOutcome::Applied(result) = tree.splice_subtrees(&patches(&targets))? else {
            return Err(Error::Node);
        };
        assert_bytes(&result.tree, &tree);
        assert_targets(&result.tree, &targets)?;
        assert_partition(&result.work);
        // No sparse spans exist to search. Targets form a separate ordered
        // output run, so no pairwise target-range comparison is necessary.
        assert_eq!(result.work.preparation.comparisons, 0);
        assert_eq!(result.work.preparation.frontier_checks, count);
    }
    Ok(())
}

fn mixed_sparse_and_distant_targets_have_linear_span_comparisons() -> Result<(), Error> {
    let tree = Tree::build(fixture(48000), None, 262144, TreeUse::Ordinary)?;
    let nodes = leaves(&tree);
    for count in [8, 32, 64] {
        let targets: Vec<_> = nodes
            .iter()
            .skip(8)
            .step_by(7)
            .take(count)
            .cloned()
            .collect();
        let edits: Vec<_> = nodes
            .iter()
            .skip(5)
            .step_by(7)
            .take(count)
            .map(|node| {
                let key = node.first_key().ok_or(Error::Node)?.to_vec();
                Ok((key.clone(), Some(directory(key, 0o700).entry)))
            })
            .collect::<Result<_, Error>>()?;
        let SpliceOutcome::Applied(result) =
            tree.edit_entries_with_subtrees(&edits, &patches(&targets))?
        else {
            return Err(Error::Node);
        };
        assert_bytes(&result.tree, &oracle(&tree, &edits)?);
        assert_targets(&result.tree, &targets)?;
        assert_partition(&result.work);
        // One span cursor advances at most once per sparse span, one coverage
        // comparison is made per target, then the two ordered runs merge once.
        assert!(result.work.preparation.comparisons <= count * 5);
        assert_eq!(result.work.preparation.frontier_checks, count);
        let middle = nodes.last().ok_or(Error::Node)?;
        let retained = result
            .tree
            .nodes()
            .find(|node| node.identity() == middle.identity())
            .ok_or(Error::Node)?;
        assert!(core::ptr::eq(retained, middle.as_ref()));
    }
    Ok(())
}

fn covered_targets_use_key_binary_lookup_and_require_exact_old_identity() -> Result<(), Error> {
    let entries = fixture(24000);
    let tree = Tree::build(entries.clone(), None, 262144, TreeUse::Ordinary)?;
    let nodes = leaves(&tree);
    let mut replacement = entries;
    let first = replacement.first_mut().ok_or(Error::Node)?;
    first.entry = directory(first.key.clone(), 0o700).entry;
    // This actual localized range edit processes one leaf stream to its tail.
    // Interior unchanged leaves genuinely survive with their canonical bytes.
    let range = tree.replace_range(&[], None, replacement)?;
    assert_eq!(
        range
            .work
            .regions
            .iter()
            .filter(|region| region.level == 0)
            .count(),
        1
    );
    let emitted_leaves: Vec<_> = range
        .emitted
        .iter()
        .filter(|node| node.level() == 0)
        .cloned()
        .collect();
    let targets: Vec<_> = nodes.iter().skip(5).step_by(3).take(64).cloned().collect();
    assert_eq!(targets.len(), 64);
    let last = tree.root().last_key().ok_or(Error::Node)?.to_vec();
    let span = super::mutation::Replacement {
        first: nodes
            .first()
            .and_then(|node| node.last_key())
            .ok_or(Error::Node)?
            .to_vec(),
        last: last.clone(),
        nodes: emitted_leaves.clone(),
    };
    let mut factory = super::Factory::new(262144, TreeUse::Ordinary);
    let injected =
        super::batch::inject(&tree, 0, vec![span], &targets, &mut factory)?.ok_or(Error::Node)?;
    assert_eq!(injected.len(), 1);
    let logarithmic_bound =
        usize::BITS as usize - emitted_leaves.len().leading_zeros() as usize + 2;
    assert!(factory.work.preparation.comparisons <= targets.len() * (logarithmic_bound + 2));
    assert!(factory.work.preparation.frontier_checks <= targets.len() * (logarithmic_bound + 2));
    for target in &targets {
        let present = injected[0]
            .nodes
            .iter()
            .find(|node| node.identity() == target.identity())
            .ok_or(Error::Node)?;
        assert!(Rc::ptr_eq(present, target));
    }
    assert_partition(&factory.work);

    // A matching last key cannot substitute for the predecessor identity.
    let target = targets.first().ok_or(Error::Node)?;
    let mut wrong = target.node().clone();
    let crate::tree_format::NodeItems::Leaf(items) = &mut wrong.items else {
        return Err(Error::Node);
    };
    let item = items.first_mut().ok_or(Error::Node)?;
    item.entry = directory(item.key.clone(), 0o711).entry;
    let mut factory = super::Factory::new(262144, TreeUse::Ordinary);
    let wrong = factory.make(wrong, Vec::new(), false)?;
    let mut candidates = emitted_leaves;
    let index = candidates
        .iter()
        .position(|node| node.last_key() == target.last_key())
        .ok_or(Error::Node)?;
    candidates[index] = wrong;
    // Isolate the injection phase from the independently prepared candidate.
    factory.work = super::Work::default();
    let rejected = super::batch::inject(
        &tree,
        0,
        vec![super::mutation::Replacement {
            first: nodes
                .first()
                .and_then(|node| node.last_key())
                .ok_or(Error::Node)?
                .to_vec(),
            last,
            nodes: candidates,
        }],
        &targets,
        &mut factory,
    )?;
    assert!(rejected.is_none());
    assert_partition(&factory.work);
    assert!(factory.work.preparation.frontier_checks > 0);
    Ok(())
}

/// Exercises all deterministic adoption-frontier bounds in the owning gate.
///
/// # Errors
/// Rejects invalid fixture construction, editing, or missing fixture frontiers.
///
/// # Panics
/// Panics if canonical bytes, sharing, identity refusal, or comparison bounds differ.
pub(super) fn run() -> Result<(), Error> {
    original_distant_targets_use_one_linear_frontier_with_zero_sparse_edits()?;
    mixed_sparse_and_distant_targets_have_linear_span_comparisons()?;
    covered_targets_use_key_binary_lookup_and_require_exact_old_identity()
}
