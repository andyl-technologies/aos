//! Checks historical fences, inert bytes and owner-local structural behavior.

#![allow(
    clippy::unwrap_used,
    reason = "invalid canonical test fixtures must fail their assertions"
)]

use super::*;
use crate::indexing::IndexRoots;
use crate::properties::selected::Selection;
use alloc::vec;

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "test",
        private_domain: "private:test",
        home: "local",
    }
}

fn binding() -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 1);
    cbor::write_text(&mut bytes, "uid");
    cbor::write_text(&mut bytes, &"01".repeat(32));
    IndexRoots::decode_value(&bytes)
        .unwrap()
        .encode_binding()
        .unwrap()
}

#[test]
fn recorded_vocabularies_and_current_revision_are_exact() {
    for (revision, count) in [(1, 33), (2, 34), (3, 35)] {
        let context = RecordedContext::new(revision, 3, &[]).unwrap();
        let names: Vec<_> = context.behavioral_names().collect();
        assert_eq!(names.len(), count);
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(names.contains(&"index-roots"), revision >= 2);
        assert_eq!(names.contains(&"index-gaps"), revision >= 3);
    }
    for (revision, current) in [(0, 3), (4, 3), (1, 0), (1, 4), (3, 2)] {
        assert!(RecordedContext::new(revision, current, &[]).is_err());
    }
    let first = RecordedContext::new(1, 2, &["index-roots"]).unwrap();
    let second = RecordedContext::new(1, 3, &["index-roots"]).unwrap();
    assert_ne!(first, second);
    assert_ne!(Selection::Recorded(first), Selection::Recorded(second));
}

#[test]
fn resolution_unknown_revisions_and_unregistered_extensions_refuse() {
    assert!(RecordedContext::new(1, 3, &["domain"]).is_err());
    assert!(RecordedContext::new(1, 1, &["index-roots"]).is_err());
    assert!(RecordedContext::new(1, 2, &["index-gaps"]).is_err());
    assert!(RecordedContext::new(2, 2, &["index-gaps"]).is_err());
    assert!(RecordedContext::new(1, 3, &["index-gaps"]).is_ok());
    // An uncompiled name is an explicit operator preservation registration, not
    // an inferred behavioral property or authority recovered from stored data.
    assert!(RecordedContext::new(1, 1, &["future"]).is_ok());
    assert!(RecordedContext::new(2, 3, &["index-roots"]).is_err());
    assert!(RecordedContext::new(1, 3, &["future", "future"]).is_err());
    assert!(RecordedContext::new(1, 3, &[""]).is_err());
    for (revision, current) in [(0, 3), (4, 3), (1, 0), (1, 4), (3, 2)] {
        assert!(RecordedContext::new(revision, current, &[]).is_err());
    }
    let unknown = [Property {
        name: "future",
        value: b"\x00",
    }];
    assert!(
        RecordedContext::new(1, 3, &[])
            .unwrap()
            .resolve(
                &[RootLayer {
                    properties: &unknown,
                    overrides: &[]
                }],
                defaults()
            )
            .is_err()
    );
    let context = RecordedContext::new(1, 3, &["future", "index-roots"]).unwrap();
    assert_eq!(context.later_registered(), &["future", "index-roots"]);
}

#[test]
fn resolution_recorded_revisions_preserve_inert_later_names() {
    let context = RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap();
    let properties = [
        Property {
            name: "index-roots",
            value: b"\x00",
        },
        Property {
            name: "index-gaps",
            value: b"\x00",
        },
    ];
    let layers = [RootLayer {
        properties: &properties,
        overrides: &[],
    }];

    let effective = context.resolve(&layers, defaults()).unwrap();

    assert!(effective.active_index_roots().is_none());
    assert_eq!(properties[0].value, b"\x00");
    assert!(
        RecordedContext::new(1, 3, &[])
            .unwrap()
            .resolve(&layers, defaults())
            .is_err()
    );
    assert!(
        RecordedContext::new(2, 3, &["index-gaps"])
            .unwrap()
            .resolve(&layers, defaults())
            .is_err()
    );
    let malformed = [Property {
        name: "index-roots",
        value: b"\xff",
    }];
    assert!(
        context
            .resolve(
                &[RootLayer {
                    properties: &malformed,
                    overrides: &[]
                }],
                defaults()
            )
            .is_err()
    );
}

// Independent literal namespace defaults keep historical meaning separate from current selection.
fn expected_namespace_defaults(revision: u64) -> Vec<(&'static str, Value<'static>)> {
    use Value::*;
    let mut values = vec![
        ("acl", Grants(vec![])),
        ("baseline", Unset),
        ("chunk", Text("cdc-1m")),
        ("classify", Names(vec![])),
        ("compaction_threshold", Unsigned(5000)),
        ("compression", Text("zstd")),
        ("dedup", Text("domain")),
        ("degraded", Text("refuse")),
        ("domain", Text("private:test")),
        ("durability", Text("region")),
        ("encryption", Text("none")),
        ("gap_merge_bytes", Unsigned(262144)),
        ("hashes", Names(vec![])),
        ("home", Text("local")),
        ("index", Names(vec![])),
        ("merge", Names(vec!["prefer-trusted", "keep-conflict"])),
        ("on-release", Text("keep")),
        ("passthrough", Text("auto")),
        ("prefetch", Text("profile")),
        ("quota", Unset),
        ("reassembly", Text("smart")),
        ("redundancy", Text("none")),
        ("reflog_retain", Unsigned(7776000)),
        ("replicate", Text("async")),
        ("retain", Text("gc")),
        ("span_max_bytes", Unsigned(16777216)),
        ("store", Text("test")),
        ("strict-attrs", Boolean(false)),
        ("trust", Text("any")),
        ("warm", Names(vec![])),
        ("whole_pack_threshold", Unsigned(5000)),
        ("wipe", Text("zero")),
        ("writers", Text("one")),
    ];
    if revision >= 2 {
        values.push((
            "index-roots",
            Value::IndexRoots(crate::indexing::IndexRoots::decode_value(b"\xa0").unwrap()),
        ));
    }
    values.sort_by_key(|(name, _)| *name);
    values
}

#[test]
fn resolution_revisions_bind_defaults_and_graft_placement_exactly() {
    for revision in [1, 2, 3] {
        let context = RecordedContext::new(revision, 3, &[]).unwrap();
        let effective = context.resolve(&[], defaults()).unwrap();
        let mut actual: Vec<_> = PropertyName::ALL
            .iter()
            .filter_map(|name| {
                effective
                    .get(*name)
                    .map(|value| (name.as_str(), value.clone()))
            })
            .collect();
        actual.sort_by_key(|(name, _)| *name);
        assert_eq!(actual, expected_namespace_defaults(revision));
        assert_eq!(actual.len(), if revision == 1 { 33 } else { 34 });
        assert!(effective.get(PropertyName::IndexGaps).is_none());
        assert!(effective.active_index_roots().is_none());
    }
    let bytes = binding();
    let properties = [Property {
        name: "index-roots",
        value: &bytes,
    }];
    for revision in [2, 3] {
        let context = RecordedContext::new(revision, 3, &[]).unwrap();
        let own = context
            .resolve(
                &[RootLayer {
                    properties: &properties,
                    overrides: &[],
                }],
                defaults(),
            )
            .unwrap();
        assert!(own.active_index_roots().unwrap().get("uid").is_some());
        let descendant = context
            .resolve(
                &[
                    RootLayer {
                        properties: &properties,
                        overrides: &[],
                    },
                    RootLayer {
                        properties: &[],
                        overrides: &[],
                    },
                ],
                defaults(),
            )
            .unwrap();
        assert!(descendant.active_index_roots().is_none());
        assert!(
            context
                .resolve(
                    &[RootLayer {
                        properties: &[],
                        overrides: &properties
                    }],
                    defaults()
                )
                .is_err()
        );
    }
    let gap = [Property {
        name: "index-gaps",
        value: b"\x00",
    }];
    let older = RecordedContext::new(2, 3, &["index-gaps"]).unwrap();
    assert!(
        older
            .resolve(
                &[RootLayer {
                    properties: &gap,
                    overrides: &[]
                }],
                defaults()
            )
            .is_ok()
    );
    let current = RecordedContext::new(3, 3, &[]).unwrap();
    assert!(
        current
            .resolve(
                &[RootLayer {
                    properties: &gap,
                    overrides: &[]
                }],
                defaults()
            )
            .is_err()
    );
}

#[test]
fn revision_three_gaps_use_the_existing_primary_only_carrier_role() {
    use crate::{
        indexing::carrier::{self, GapBinding, Role, SemanticContext},
        tree_format::{Node, NodeItems},
    };
    let binding = GapBinding::new([7; 32]).encode_binding();
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![]),
        props: Some(vec![Property {
            name: "index-gaps",
            value: &binding,
        }]),
    };
    let context = SemanticContext::new(3, 2, 1).unwrap();

    assert_eq!(
        carrier::validate_node(context, Role::Primary, &node, true)
            .unwrap()
            .unwrap()
            .node(),
        [7; 32]
    );
    for role in [Role::Gap, Role::PresentRoute, Role::MissingRoute] {
        assert!(carrier::validate_node(context, role, &node, true).is_err());
    }
    assert!(carrier::validate_node(context, Role::Primary, &node, false).is_err());
    assert!(SemanticContext::new(2, 2, 1).is_err());
    let properties = node.props.as_ref().unwrap();
    assert!(
        RecordedContext::new(3, 3, &[])
            .unwrap()
            .resolve(
                &[RootLayer {
                    properties,
                    overrides: &[]
                }],
                defaults()
            )
            .is_err()
    );
}

#[test]
fn physical_node_decode_preserves_inert_later_arrays_before_selected_execution() {
    use crate::tree_format::{self, Node, NodeItems, TreeUse};
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![]),
        props: Some(vec![
            Property {
                name: "index-roots",
                value: b"\x81\x00",
            },
            Property {
                name: "index-gaps",
                value: b"\x81\x01",
            },
        ]),
    };
    let bytes = tree_format::encode_node(&node, true, 262144).unwrap();

    let decoded = tree_format::decode_node_for(&bytes, true, 262144, TreeUse::Ordinary).unwrap();
    let properties = decoded.props.as_deref().unwrap();
    let effective = RecordedContext::new(1, 3, &["index-roots", "index-gaps"])
        .unwrap()
        .resolve(
            &[RootLayer {
                properties,
                overrides: &[],
            }],
            defaults(),
        )
        .unwrap();

    assert!(effective.active_index_roots().is_none());
    assert_eq!(
        properties
            .iter()
            .find(|property| property.name == "index-roots")
            .unwrap()
            .value,
        b"\x81\x00"
    );
    assert_eq!(
        properties
            .iter()
            .find(|property| property.name == "index-gaps")
            .unwrap()
            .value,
        b"\x81\x01"
    );
    assert_eq!(
        tree_format::encode_node(&decoded, true, 262144).unwrap(),
        bytes
    );
}
