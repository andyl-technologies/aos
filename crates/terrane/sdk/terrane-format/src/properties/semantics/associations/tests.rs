//! Checks owned ordinary associations without constructing authenticated history.

use super::{Error, RecordedAssociation, RecordedAssociations, RecordedContext};
use crate::{
    identity::Digest,
    properties::{Defaults, Error as PropertyError, PropertyName, RootLayer},
    tree_format::Property,
};
use alloc::{format, string::String, vec, vec::Vec};

// Independent fixed revision-one vocabulary, not the compiled registry list.
const LEGACY_NAMES: &[&str] = &[
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "ordinary-store",
        private_domain: "private:ordinary",
        home: "ordinary-home",
    }
}

fn association(view: Digest, root: Digest, revision: u64, later: &[&str]) -> RecordedAssociation {
    RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(revision, 3, later).expect("validated ordinary inputs"),
    )
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn recorded_associations_own_fixed_interpretations_and_preservation_names() {
    assert_send_sync::<RecordedAssociation>();
    assert_send_sync::<RecordedAssociations>();
    let root = [7; 32];
    let table = {
        let names = [String::from("é.future"), String::from("future.z")];
        let borrowed: Vec<_> = names.iter().map(String::as_str).collect();
        let mut entries = Vec::new();
        for revision in 1..=3 {
            let entry = association([revision as u8; 32], root, revision, &borrowed);
            assert_eq!(borrowed, ["é.future", "future.z"]);
            entries.push(entry);
        }
        RecordedAssociations::new(entries).expect("owned caller configuration")
    };
    let retained = table.clone();
    drop(table);
    assert_eq!(retained.len(), 3);

    for revision in 1..=3 {
        let view = [revision as u8; 32];
        let selected = retained.select(view, root).expect("exact mapping");
        assert_eq!(selected.view(), view);
        assert_eq!(selected.original_root(), root);
        assert_eq!(selected.revision(), revision);
        assert_eq!(selected.later_registered(), ["future.z", "é.future"]);

        selected
            .with_context(|context| {
                assert_eq!(context.revision(), revision);
                assert_eq!(context.later_registered(), ["future.z", "é.future"]);
                let mut expected = LEGACY_NAMES.to_vec();
                if revision >= 2 {
                    expected.push("index-roots");
                }
                if revision == 3 {
                    expected.push("index-gaps");
                }
                expected.sort_unstable();
                let mut actual: Vec<_> = context.behavioral_names().collect();
                actual.sort_unstable();
                assert_eq!(actual, expected);

                let effective = context.resolve(&[], defaults()).expect("fixed defaults");
                assert_eq!(
                    PropertyName::ALL
                        .iter()
                        .filter(|name| effective.get(**name).is_some())
                        .count(),
                    if revision == 1 { 33 } else { 34 }
                );
                assert_eq!(
                    effective.get(PropertyName::IndexRoots).is_some(),
                    revision >= 2
                );
                assert!(effective.get(PropertyName::IndexGaps).is_none());
            })
            .expect("temporary validated borrow");
        let owned_names = selected
            .with_context(|context| context.later_registered().to_vec())
            .expect("owned closure output");
        assert_eq!(owned_names, selected.later_registered());
    }

    // Canonical scalars are invalid active structural bindings. Compiled name
    // recognition must leave both bytes inert behind their recorded fences.
    for (revision, names) in [
        (1, vec!["index-roots", "index-gaps"]),
        (2, vec!["index-gaps"]),
    ] {
        let selected = association([8; 32], root, revision, &names);
        selected
            .with_context(|context| {
                for name in &names {
                    let properties = [Property {
                        name,
                        value: &[0x00],
                    }];
                    for layer in [
                        RootLayer {
                            properties: &properties,
                            overrides: &[],
                        },
                        RootLayer {
                            properties: &[],
                            overrides: &properties,
                        },
                    ] {
                        let effective = context
                            .resolve(&[layer], defaults())
                            .expect("preserved inert data");
                        assert!(effective.get(PropertyName::IndexGaps).is_none());
                        if revision == 1 {
                            assert!(effective.get(PropertyName::IndexRoots).is_none());
                        }
                        assert_eq!(properties[0].value, &[0]);
                    }
                }
            })
            .expect("owned recorded fence");
    }

    let max_name = format!("a{}", "é".repeat(127));
    assert_eq!(max_name.len(), 255);
    let copied = association([9; 32], root, 1, &[&max_name]);
    assert_eq!(copied.later_registered(), [max_name]);
    assert!(matches!(
        RecordedContext::new(1, 3, &[&"é".repeat(128)]),
        Err(PropertyError::Limit)
    ));
    let mut names: Vec<_> = (0..257)
        .map(|position| format!("{position:04}{}", "x".repeat(251)))
        .collect();
    names.push(String::from("y"));
    let borrowed: Vec<_> = names.iter().map(String::as_str).collect();
    assert_eq!(borrowed.iter().map(|name| name.len()).sum::<usize>(), 65536);
    let boundary = association([10; 32], root, 1, &borrowed);
    assert_eq!(boundary.later_registered().len(), 258);
    let mut oversized = borrowed.clone();
    oversized.push("z");
    assert!(matches!(
        RecordedContext::new(1, 3, &oversized),
        Err(PropertyError::Limit)
    ));
    for revision in [0, 4] {
        assert!(matches!(
            RecordedContext::new(revision, 3, &[]),
            Err(PropertyError::InvalidValue)
        ));
    }
    for (revision, names) in [
        (1, vec!["future", "future"]),
        (1, vec!["store"]),
        (2, vec!["index-roots"]),
        (3, vec!["index-gaps"]),
    ] {
        assert!(matches!(
            RecordedContext::new(revision, 3, &names),
            Err(PropertyError::InvalidValue)
        ));
    }
    assert!(matches!(
        RecordedContext::new(1, 3, &[""]),
        Err(PropertyError::Limit)
    ));
}

#[test]
fn recorded_associations_distinguish_views_and_refuse_conflicting_duplicates() {
    let view = [1; 32];
    let other_view = [2; 32];
    let root = [7; 32];
    let first = association(view, root, 1, &["future.z", "index-roots"]);
    let reordered = association(view, root, 1, &["index-roots", "future.z"]);
    let second = association(other_view, root, 3, &["future.other"]);
    let table = RecordedAssociations::new([first.clone(), reordered.clone(), second.clone()])
        .expect("identical sets coalesce, distinct views remain distinct");
    assert_eq!(table.len(), 2);
    assert_eq!(table.select(view, root), Ok(&first));
    assert_eq!(table.select(other_view, root), Ok(&second));
    let reversed = RecordedAssociations::new([second, reordered, first.clone()])
        .expect("input order does not choose an interpretation");
    assert_eq!(table, reversed);

    for conflicting in [
        association(view, [8; 32], 1, &["future.z", "index-roots"]),
        association(view, root, 2, &["future.z", "index-gaps"]),
        association(view, root, 1, &["future.changed", "index-roots"]),
    ] {
        for entries in [
            [first.clone(), conflicting.clone()],
            [conflicting, first.clone()],
        ] {
            assert_eq!(
                RecordedAssociations::new(entries),
                Err(Error::ConflictingView { view })
            );
        }
    }
    // Isolate revision conflict even when the preservation set is identical.
    assert_eq!(
        RecordedAssociations::new([
            association(view, root, 1, &["future"]),
            association(view, root, 2, &["future"]),
        ]),
        Err(Error::ConflictingView { view })
    );
}

#[test]
fn recorded_associations_refuse_missing_views_and_original_root_mismatches() {
    let view = [1; 32];
    let root = [7; 32];
    let empty = RecordedAssociations::new([]).expect("explicit empty configuration");
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty, RecordedAssociations::default());
    assert_eq!(empty.select(view, root), Err(Error::MissingView { view }));
    let table = RecordedAssociations::new([association(view, root, 1, &["index-roots"])])
        .expect("explicit mapping");
    assert!(!table.is_empty());
    let absent = [2; 32];
    assert_eq!(
        table.select(absent, root),
        Err(Error::MissingView { view: absent })
    );
    assert_eq!(
        table.select(view, [8; 32]),
        Err(Error::OriginalRootMismatch {
            view,
            expected: root,
            actual: [8; 32],
        })
    );
    assert_eq!(
        table.select(absent, [8; 32]),
        Err(Error::MissingView { view: absent })
    );
    assert_eq!(
        table
            .select(view, root)
            .expect("exact selection")
            .revision(),
        1
    );
    assert_eq!(table.len(), 1);
}
