//! Checks ordinary layer data without constructing authenticated view evidence.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    cbor,
    identity::{IdentityKind, TERRANE_V1},
    properties::{Defaults, PropertyName, RootLayer, Value, semantics::RecordedContext},
};
use alloc::{vec, vec::Vec};

const MINIMUM: u64 = 262144;

fn uint(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_uint(&mut out, value);
    out
}

fn text(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_text(&mut out, value);
    out
}

fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_bytes(&mut out, value);
    out
}

fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_array(&mut out, values.len());
    for value in values {
        out.extend_from_slice(value);
    }
    out
}

fn map(values: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_map(&mut out, values.len());
    for (key, value) in values {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    out
}

fn bindings(values: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut rows: Vec<_> = values
        .iter()
        .map(|(name, value)| (text(name), value.clone()))
        .collect();
    rows.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
    map(&rows)
}

fn index_binding(hex: &str) -> Vec<u8> {
    map(&[
        (text("value"), map(&[(text("uid"), text(&hex.repeat(32)))])),
        (text("inherit"), vec![0xf4]),
    ])
}

fn file() -> Vec<u8> {
    map(&[
        (uint(1), uint(1)),
        (uint(2), uint(420)),
        (uint(3), uint(1)),
        (uint(4), array(&[uint(0), bytes(&[9; 32])])),
    ])
}

fn graft(root: Digest, overrides: Option<Vec<u8>>) -> Vec<u8> {
    let mut fields = vec![(uint(1), uint(4)), (uint(6), bytes(&root))];
    if let Some(overrides) = overrides {
        fields.push((uint(7), overrides));
    }
    map(&fields)
}

// Literal CBOR Nodes bypass the owning Node/Tree encoder. Each test's history
// insertion still verifies canonical physical bytes and immutable identities.
fn node(rows: &[(&[u8], Vec<u8>)], props: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let items: Vec<_> = rows
        .iter()
        .map(|(key, entry)| array(&[bytes(key), uint(0), entry.clone()]))
        .collect();
    map(&[
        (uint(1), uint(0)),
        (uint(2), array(&items)),
        (uint(3), bindings(props)),
    ])
}

fn store(history: &mut VerifiedHistory, wire: Vec<u8>) -> Digest {
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &wire)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    history.insert_tree(root, &[(root, wire)]).unwrap();
    root
}

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "default",
        home: "west",
        private_domain: "private:test",
    }
}

#[test]
fn policy_layers_preserve_occurrence_roles_and_legacy_projection() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let owner = index_binding("ab");
    let replacement_owner = index_binding("cd");
    let original = text("original");
    let child = store(
        &mut history,
        node(
            &[(b"file", file())],
            &[("store", original.clone()), ("index-roots", owner.clone())],
        ),
    );
    let replacement_a = text("replacement-a");
    let replacement_b = text("replacement-b");
    let parent = store(
        &mut history,
        node(
            &[
                (
                    b"a",
                    graft(
                        child,
                        Some(bindings(&[
                            ("store", replacement_a.clone()),
                            ("index-roots", replacement_owner.clone()),
                        ])),
                    ),
                ),
                (
                    b"b",
                    graft(child, Some(bindings(&[("store", replacement_b.clone())]))),
                ),
                (b"empty", graft(child, Some(bindings(&[])))),
                (b"plain", graft(child, None)),
            ],
            &[("trust", text("strict"))],
        ),
    );
    let legacy = RecordedContext::new(1, 3, &["index-roots"]).unwrap();
    let active = RecordedContext::new(2, 3, &[]).unwrap();

    // The view tag is ordinary fixture selection metadata. No Commit or
    // authenticated view is fabricated by these physical traversal assertions.
    for (prefix, replacement) in [
        (b"a".as_slice(), &replacement_a),
        (b"b".as_slice(), &replacement_b),
    ] {
        let mut path = prefix.to_vec();
        path.extend_from_slice(b"/file");
        let (location, layers) = history
            .policy_layers_from_root([5; 32], parent, &path)
            .unwrap();
        assert_eq!(
            location,
            EntryLocation {
                commit: [5; 32],
                root: child,
                path: b"file".to_vec()
            }
        );
        assert_eq!(layers.len(), 2);
        assert_eq!(
            layers[0].location,
            EntryLocation {
                commit: [5; 32],
                root: parent,
                path: path.clone()
            }
        );
        assert_eq!(layers[0].occurrence, b"");
        assert_eq!(layers[0].overrides, None);
        assert_eq!(layers[1].occurrence, prefix);
        assert_eq!(layers[1].location, location);
        assert_eq!(
            layers[1].properties,
            vec![
                Property {
                    name: "store",
                    value: &original
                },
                Property {
                    name: "index-roots",
                    value: &owner
                }
            ]
        );
        let overrides = layers[1].overrides.as_deref().unwrap();
        assert_eq!(
            overrides[0],
            Property {
                name: "store",
                value: replacement
            }
        );
        if prefix == b"a" {
            assert_eq!(
                overrides,
                &[
                    Property {
                        name: "store",
                        value: &replacement_a
                    },
                    Property {
                        name: "index-roots",
                        value: &replacement_owner
                    }
                ]
            );
        }
        let raw_layers: Vec<_> = layers
            .iter()
            .map(|layer| RootLayer {
                properties: &layer.properties,
                overrides: layer.overrides.as_deref().unwrap_or(&[]),
            })
            .collect();
        let resolved = legacy.resolve(&raw_layers, defaults()).unwrap();
        let expected_store = if prefix == b"a" {
            "replacement-a"
        } else {
            "replacement-b"
        };
        assert_eq!(
            resolved.get(PropertyName::Store),
            Some(&Value::Text(expected_store))
        );

        assert!(resolved.get(PropertyName::IndexRoots).is_none());
        assert_eq!(
            resolved.get(PropertyName::Trust),
            Some(&Value::Text("strict"))
        );
        assert_eq!(active.validate_map(&layers[1].properties), Ok(()));
        if prefix == b"a" {
            assert!(active.validate_graft_overrides(overrides).is_err());
            assert!(active.resolve(&raw_layers, defaults()).is_err());
        } else {
            assert!(active.resolve(&raw_layers, defaults()).is_ok());
        }
        let projected = legacy_properties(layers);
        // Independently enumerate the original retain-then-append order.
        let expected_child = if prefix == b"a" {
            vec![
                Property {
                    name: "store",
                    value: replacement,
                },
                Property {
                    name: "index-roots",
                    value: &replacement_owner,
                },
            ]
        } else {
            vec![
                Property {
                    name: "index-roots",
                    value: &owner,
                },
                Property {
                    name: "store",
                    value: replacement,
                },
            ]
        };
        assert_eq!(projected[1], expected_child);
        assert_eq!(
            projected[0],
            vec![Property {
                name: "trust",
                value: &text("strict")
            }]
        );
    }
    let middle_store = text("middle-original");
    let middle_baseline = text("middle-baseline");
    let middle = store(
        &mut history,
        node(
            &[(b"inner", graft(child, None))],
            &[
                ("store", middle_store.clone()),
                ("baseline", middle_baseline.clone()),
            ],
        ),
    );
    let middle_override = text("middle-override");
    let outer = store(
        &mut history,
        node(
            &[(
                b"a",
                graft(
                    middle,
                    Some(bindings(&[("store", middle_override.clone())])),
                ),
            )],
            &[("trust", text("strict"))],
        ),
    );
    let (nested_location, nested) = history
        .policy_layers_from_root([5; 32], outer, b"a/inner/file")
        .unwrap();
    assert_eq!(
        nested_location,
        EntryLocation {
            commit: [5; 32],
            root: child,
            path: b"file".to_vec()
        }
    );
    assert_eq!(nested.len(), 3);
    for (layer, root, prefix, remaining) in [
        (
            &nested[0],
            outer,
            b"".as_slice(),
            b"a/inner/file".as_slice(),
        ),
        (
            &nested[1],
            middle,
            b"a".as_slice(),
            b"inner/file".as_slice(),
        ),
        (&nested[2], child, b"a/inner".as_slice(), b"file".as_slice()),
    ] {
        assert_eq!(
            layer.location,
            EntryLocation {
                commit: [5; 32],
                root,
                path: remaining.to_vec()
            }
        );
        assert_eq!(layer.occurrence, prefix);
    }
    assert_eq!(
        nested[0].properties,
        vec![Property {
            name: "trust",
            value: &text("strict")
        }]
    );
    assert_eq!(
        nested[1].properties,
        vec![
            Property {
                name: "store",
                value: &middle_store
            },
            Property {
                name: "baseline",
                value: &middle_baseline
            }
        ]
    );
    assert_eq!(
        nested[1].overrides,
        Some(vec![Property {
            name: "store",
            value: &middle_override
        }])
    );
    assert_eq!(
        nested[2].properties,
        vec![
            Property {
                name: "store",
                value: &original
            },
            Property {
                name: "index-roots",
                value: &owner
            }
        ]
    );
    assert_eq!(nested[2].overrides, None);
    let projected = legacy_properties(nested);
    assert_eq!(
        projected[1],
        vec![
            Property {
                name: "baseline",
                value: &middle_baseline
            },
            Property {
                name: "store",
                value: &middle_override
            }
        ]
    );
    let (terminal, top) = history
        .policy_layers_from_root([5; 32], parent, b"a")
        .unwrap();
    assert_eq!(terminal.root, parent);
    assert_eq!(terminal.path, b"a");
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].overrides, None);
    let (_, empty) = history
        .policy_layers_from_root([5; 32], parent, b"empty/file")
        .unwrap();
    let (_, absent) = history
        .policy_layers_from_root([5; 32], parent, b"plain/file")
        .unwrap();
    assert_eq!(empty[1].overrides, Some(vec![]));
    assert_eq!(absent[1].overrides, None);
    assert_eq!(legacy_properties(empty), legacy_properties(absent));
    assert!(history.locate_policy_layers([5; 32], b"a/file").is_err());
    assert!(history.locate([5; 32], b"a/file").is_err());
}

#[test]
fn policy_layers_keep_physical_key_missing_path_and_depth_refusals() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let leaf = store(&mut history, node(&[(b"file", file())], &[]));
    for invalid in [
        b"".as_slice(),
        b"/file",
        b"a//file",
        b"../file",
        b"missing",
        b"file/child",
    ] {
        assert!(
            history
                .policy_layers_from_root([5; 32], leaf, invalid)
                .is_err()
        );
    }
    for width in [256, 4097] {
        assert!(
            history
                .policy_layers_from_root([5; 32], leaf, &vec![b'x'; width])
                .is_err()
        );
    }
    let missing = store(
        &mut history,
        node(&[(b"child", graft([99; 32], None))], &[]),
    );
    assert!(
        history
            .policy_layers_from_root([5; 32], missing, b"child/file")
            .is_err()
    );
    let mut root = leaf;
    let mut path = b"file".to_vec();
    for depth in 1..=65 {
        root = store(&mut history, node(&[(b"child", graft(root, None))], &[]));
        let mut next = b"child/".to_vec();
        next.extend_from_slice(&path);
        path = next;
        let result = history.policy_layers_from_root([5; 32], root, &path);
        if depth <= 64 {
            assert_eq!(result.unwrap().1.len(), depth + 1);
        } else {
            assert!(result.is_err());
        }
    }
    let inert_value = uint(0);
    let inert = store(
        &mut history,
        node(
            &[(b"file", file())],
            &[("index-roots", inert_value.clone())],
        ),
    );
    let (_, layers) = history
        .policy_layers_from_root([5; 32], inert, b"file")
        .unwrap();
    assert_eq!(
        layers[0].properties,
        vec![Property {
            name: "index-roots",
            value: &inert_value
        }]
    );
    let selected = [RootLayer {
        properties: &layers[0].properties,
        overrides: &[],
    }];
    assert!(
        RecordedContext::new(1, 3, &["index-roots"])
            .unwrap()
            .resolve(&selected, defaults())
            .is_ok()
    );
    assert!(
        RecordedContext::new(1, 3, &[])
            .unwrap()
            .resolve(&selected, defaults())
            .is_err()
    );
    assert!(
        RecordedContext::new(2, 3, &[])
            .unwrap()
            .resolve(&selected, defaults())
            .is_err()
    );
    // Preserve the physical property grammar: canonical bstr is not an allowed
    // property-value merely because a preserve-only resolver could retain it.
    let invalid = node(&[(b"file", file())], &[("index-roots", bytes(b"opaque"))]);
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &invalid)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    assert!(history.insert_tree(root, &[(root, invalid)]).is_err());
}
