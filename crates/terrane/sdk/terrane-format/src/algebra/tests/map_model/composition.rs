//! Compares graft, split, flatten, overlay, and diff with plain map inputs.

use alloc::vec;
use alloc::vec::Vec;

use super::{EntryKind, Map, assert_map, build, entry, items, map, model, symlink};
use crate::algebra::tests::{Forest, effective_properties, graft_entry};
use crate::algebra::{self, Error, Overlay};
use crate::tree_format::{Attribute, ExtendedAttribute};

fn metadata(mut value: super::Entry<'static>) -> super::Entry<'static> {
    value.attrs = vec![Attribute {
        name: "test-tag",
        value: b"\x01",
    }];
    value.attrs_present = true;
    value.xattrs = vec![ExtendedAttribute {
        name: b"user.test-tag",
        value: b"metadata",
    }];
    value.xattrs_present = true;
    value.provenance = Some([9; 32]);
    value
}

fn target() -> Map<'static> {
    map(&[
        (b"dir", entry(EntryKind::Directory { mode: 0o700 })),
        (b"dir/file", symlink(b"nested")),
        (b"file", symlink(b"target")),
        (b"\xff", symlink(b"high")),
    ])
}

fn parent() -> Map<'static> {
    map(&[
        (b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        (b"mount/old", symlink(b"displaced")),
        (b"mount-", symlink(b"punctuation-before")),
        (b"mount0", symlink(b"punctuation-after")),
        (b"other", symlink(b"retained")),
    ])
}

/// Checks replacement and nested lookup without using graft to form its oracle.
///
/// # Panics
/// Panics if fixture construction fails or graft and lookup diverge from the model.
pub(in crate::algebra::tests) fn graft_witness() {
    let input = parent();
    let nested_map = map(&[(b"leaf", metadata(symlink(b"deep")))]);
    let nested_tree = build(&nested_map);
    let mut target_map = target();
    target_map.insert(b"nested".to_vec(), graft_entry(&nested_tree));
    let target_tree = build(&target_map);
    let parent_tree = build(&input);
    let mount = metadata(graft_entry(&target_tree));
    let forest = Forest(vec![target_tree, nested_tree]);

    assert!(model::graft(&input, b"mount", mount.clone(), false).is_err());
    assert_eq!(
        algebra::graft(&parent_tree, b"mount", mount.clone(), false, &forest).unwrap_err(),
        Error::InlineChildren
    );
    let expected = model::graft(&input, b"mount", mount.clone(), true).unwrap();
    let actual = algebra::graft(&parent_tree, b"mount", mount, true, &forest).unwrap();
    assert_map(&actual, &expected);
    assert_map(&forest.0[0], &target_map);
    assert_map(&forest.0[1], &nested_map);
    assert_eq!(
        algebra::lookup(&actual, b"mount/nested/leaf", &forest).unwrap(),
        nested_map.get(b"leaf".as_slice())
    );
    for (relative, value) in &target_map {
        let mut path = b"mount/".to_vec();
        path.extend_from_slice(relative);
        assert_eq!(
            algebra::lookup(&actual, &path, &forest).unwrap(),
            Some(value)
        );
    }
    assert!(
        algebra::lookup(&actual, b"mount/missing", &forest)
            .unwrap()
            .is_none()
    );

    let replacement = build(&map(&[(b"new", symlink(b"replacement"))]));
    let replacement_entry = graft_entry(&replacement);
    let forest = Forest(vec![forest.0[0].clone(), forest.0[1].clone(), replacement]);
    let expected = model::graft(&expected, b"mount", replacement_entry.clone(), false).unwrap();
    let actual = algebra::graft(&actual, b"mount", replacement_entry, false, &forest).unwrap();
    assert_map(&actual, &expected);
}

/// Checks exact relative range extraction and the graft target identity.
///
/// # Panics
/// Panics if fixture construction fails or split changes the modeled entries.
pub(in crate::algebra::tests) fn split_witness() {
    let input = parent();
    let expected = model::split(&input, b"mount");
    let actual = algebra::split(&build(&input), b"mount", &Forest(vec![])).unwrap();
    assert_map(&actual, &expected);

    let target_map = target();
    let target_tree = build(&target_map);
    let mounted = map(&[
        (b"mount", graft_entry(&target_tree)),
        (b"other", symlink(b"retained")),
    ]);
    let forest = Forest(vec![target_tree]);
    let actual = algebra::split(&build(&mounted), b"mount", &forest).unwrap();
    assert_map(&actual, &target_map);
    assert!(core::ptr::eq(actual.root(), forest.0[0].root()));
}

/// Checks authority refusal and every inlined value against prefixed map keys.
///
/// # Panics
/// Panics if fixture construction fails or flatten violates the modeled boundary.
pub(in crate::algebra::tests) fn flatten_witness() {
    let nested_map = map(&[(b"leaf", metadata(symlink(b"deep")))]);
    let nested_tree = build(&nested_map);
    let mut target_map = target();
    target_map.insert(b"nested".to_vec(), graft_entry(&nested_tree));
    target_map.insert(b"file".to_vec(), metadata(symlink(b"target")));
    let target_tree = build(&target_map);
    let mounted = map(&[
        (b"mount", metadata(graft_entry(&target_tree))),
        (b"other", symlink(b"retained")),
    ]);
    let parent_tree = build(&mounted);
    let forest = Forest(vec![target_tree, nested_tree]);
    let properties = effective_properties("private:fixture");
    let incompatible = effective_properties("private:other");

    assert!(model::flatten(&mounted, b"mount", &target_map, false).is_err());
    assert_eq!(
        algebra::flatten(&parent_tree, b"mount", &forest, &properties, &incompatible).unwrap_err(),
        Error::Boundary
    );
    let expected = model::flatten(&mounted, b"mount", &target_map, true).unwrap();
    let prepared =
        algebra::flatten(&parent_tree, b"mount", &forest, &properties, &properties).unwrap();
    let actual = prepared.materialize(&parent_tree).unwrap();
    assert_map(&actual, &expected);
    assert_eq!(
        algebra::lookup(&actual, b"mount/nested/leaf", &forest).unwrap(),
        nested_map.get(b"leaf".as_slice())
    );
    for relative in target_map.keys() {
        let mut path = b"mount/".to_vec();
        path.extend_from_slice(relative);
        assert_eq!(
            algebra::lookup(&parent_tree, &path, &forest).unwrap(),
            actual.get(&path)
        );
    }
}

/// Checks precedence, whiteouts, unsigned ordering, ranges, and canonical output.
///
/// # Panics
/// Panics if fixture construction fails or overlay differs from the ordered model.
pub(in crate::algebra::tests) fn overlay_witness() {
    let bottom = map(&[
        (b"a", symlink(b"bottom")),
        (b"b", symlink(b"bottom")),
        (b"c", symlink(b"bottom")),
        (b"z", symlink(b"bottom")),
        (b"\xff", symlink(b"high")),
    ]);
    let middle = map(&[
        (b"a", entry(EntryKind::Whiteout)),
        (b"b", symlink(b"middle")),
        (b"d", symlink(b"middle")),
        (b"z", entry(EntryKind::Whiteout)),
    ]);
    let top = map(&[
        (b"a", symlink(b"restored")),
        (b"b", symlink(b"top")),
        (b"c", entry(EntryKind::Whiteout)),
        (b"d", entry(EntryKind::Whiteout)),
        (b"e", symlink(b"top")),
    ]);
    let expected = model::overlay(&[&top, &middle, &bottom]);
    let trees = [build(&top), build(&middle), build(&bottom)];
    let layers = [&trees[0], &trees[1], &trees[2]];
    let overlay = Overlay::new(&layers);

    assert_eq!(overlay.entries(), items(&expected));
    for key in bottom
        .keys()
        .chain(middle.keys())
        .chain(top.keys())
        .chain(core::iter::once(&b"missing".to_vec()))
    {
        assert_eq!(overlay.get(key), expected.get(key));
    }
    for (start, end) in [
        (b"".as_slice(), None),
        (b"b".as_slice(), Some(b"z".as_slice())),
        (b"b".as_slice(), Some(b"b".as_slice())),
        (b"z".as_slice(), None),
    ] {
        let range: Map<'_> = expected
            .iter()
            .filter(|(key, _)| {
                key.as_slice() >= start && end.is_none_or(|end| key.as_slice() < end)
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(overlay.range(start, end), items(&range));
    }
    assert_map(&overlay.materialize().unwrap(), &expected);
}

/// Checks complete ordered changes, graft targets, metadata, and root properties.
///
/// # Panics
/// Panics if fixture construction fails or diff differs from the ordered model.
pub(in crate::algebra::tests) fn diff_witness() {
    let old_target = build(&target());
    let new_target = build(&map(&[(b"file", symlink(b"changed-target"))]));
    let old = map(&[
        (b"a", symlink(b"old")),
        (b"gone", symlink(b"removed")),
        (b"mount", graft_entry(&old_target)),
        (b"same", symlink(b"same")),
    ]);
    let metadata = metadata(symlink(b"same"));
    let new = map(&[
        (b"a", symlink(b"new")),
        (b"added", symlink(b"added")),
        (b"mount", graft_entry(&new_target)),
        (b"same", metadata),
        (b"\xff", symlink(b"high")),
    ]);
    let expected = model::diff(&old, &new);
    let old_tree = build(&old);
    let new_tree = build(&new);
    assert_eq!(algebra::diff(&old_tree, &new_tree), expected);
    assert!(
        expected
            .windows(2)
            .all(|pair| pair[0].path() < pair[1].path())
    );

    let changed_properties = new_tree.with_properties(Some(vec![])).unwrap().tree;
    let observed = algebra::diff_with_work(&old_tree, &changed_properties);
    assert_eq!(observed.changes, expected);
    assert_eq!(
        observed.properties.unwrap(),
        algebra::RootPropertiesChange {
            old: old_tree.props().map(<[_]>::to_vec),
            new: Some(Vec::new())
        }
    );
}
