//! Checks recorded revisions against independent raw property values.

use super::*;
use alloc::vec;
use alloc::vec::Vec;

// Frozen D-102 wire vocabulary, independent of the compiled enum ordering.
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
        store: "authority",
        private_domain: "private:root",
        home: "region-a",
    }
}

fn text(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_text(&mut bytes, value);
    bytes
}

fn binding(value: &[u8], inherit: bool) -> Vec<u8> {
    let mut bytes = vec![0xa2, 0x65];
    bytes.extend_from_slice(b"value");
    bytes.extend_from_slice(value);
    bytes.push(0x67);
    bytes.extend_from_slice(b"inherit");
    bytes.push(if inherit { 0xf5 } else { 0xf4 });
    bytes
}

#[test]
fn resolution_recorded_revisions_preserve_inert_later_names() {
    // Scalars and a true-inherit wrapper are canonical but invalid active
    // structural bindings. Compiled recognition must not activate either.
    let invalid_roots = binding(&[0x00], true);
    let invalid_gaps = [0x00];
    let saved_roots = invalid_roots.clone();
    let roots = [Property {
        name: "index-roots",
        value: &invalid_roots,
    }];
    let gaps = [Property {
        name: "index-gaps",
        value: &invalid_gaps,
    }];
    let later_names = ["index-roots", "index-gaps"];
    let legacy = RecordedContext::new(1, 3, &later_names).expect("trusted later names");
    let preserved = legacy.later_registered();
    assert_eq!(
        preserved
            .iter()
            .map(alloc::string::String::as_str)
            .collect::<Vec<_>>(),
        ["index-gaps", "index-roots"],
    );
    assert_eq!(later_names, ["index-roots", "index-gaps"]);
    for actual in preserved {
        assert!(
            !legacy
                .behavioral_names()
                .any(|name| name == actual.as_str())
        );
    }
    for properties in [&roots[..], &gaps[..]] {
        legacy.validate_map(properties).expect("inert root data");
        legacy
            .validate_graft_overrides(properties)
            .expect("inert graft data");
        for layer in [
            RootLayer {
                properties,
                overrides: &[],
            },
            RootLayer {
                properties: &[],
                overrides: properties,
            },
        ] {
            let effective = legacy
                .resolve(&[layer], defaults())
                .expect("inert resolution");
            assert!(effective.get(PropertyName::IndexRoots).is_none());
            assert!(effective.get(PropertyName::IndexGaps).is_none());
        }
    }
    assert_eq!(roots[0].value, saved_roots);
    assert_eq!(gaps[0].value, &[0]);
    assert!(
        RecordedContext::new(2, 3, &[])
            .expect("revision 2")
            .validate_map(&roots)
            .is_err()
    );
    let second = RecordedContext::new(2, 3, &["index-gaps"]).expect("revision 2 extension");
    second.validate_map(&gaps).expect("inert gap");
    second
        .validate_graft_overrides(&gaps)
        .expect("inert gap override");
    let resolved = second
        .resolve(
            &[RootLayer {
                properties: &gaps,
                overrides: &gaps,
            }],
            defaults(),
        )
        .expect("inert gap resolution");
    assert!(resolved.get(PropertyName::IndexGaps).is_none());
    assert!(
        RecordedContext::new(3, 3, &[])
            .expect("revision 3")
            .validate_map(&gaps)
            .is_err()
    );

    let noncanonical = [Property {
        name: "index-gaps",
        value: &[0x18, 0x00],
    }];
    assert!(second.validate_map(&noncanonical).is_err());
    let oversized = vec![0; 65536];
    assert_eq!(
        second.validate_map(&[Property {
            name: "index-gaps",
            value: &oversized
        }]),
        Err(Error::Limit)
    );
}

#[test]
fn resolution_revisions_bind_defaults_and_graft_placement_exactly() {
    let mut roots_value = vec![0xa1, 0x63];
    roots_value.extend_from_slice(b"uid");
    roots_value.extend_from_slice(&text(&"ab".repeat(32)));
    let roots_bytes = binding(&roots_value, false);
    let roots = [Property {
        name: "index-roots",
        value: &roots_bytes,
    }];
    // Exact independent raw binding with lowercase hexadecimal Node pointer.
    let gap_bytes = binding(&text(&"ab".repeat(32)), false);
    let gaps = [Property {
        name: "index-gaps",
        value: &gap_bytes,
    }];
    for revision in 1..=3 {
        let context = RecordedContext::new(revision, 3, &[]).expect("supported revision");
        let effective = context.resolve(&[], defaults()).expect("defaults");
        let mut expected_behavior = LEGACY_NAMES.to_vec();
        if revision >= 2 {
            expected_behavior.push("index-roots");
        }
        let mut expected_defaults = expected_behavior.clone();
        if revision == 3 {
            expected_behavior.push("index-gaps");
        }
        expected_behavior.sort_unstable();
        expected_defaults.sort_unstable();
        let behavior: Vec<_> = context.behavioral_names().collect();
        let mut registry_order: Vec<_> = PropertyName::ALL
            .iter()
            .copied()
            .filter(|name| context.supports(*name))
            .map(PropertyName::as_str)
            .collect();
        registry_order.sort_unstable();
        assert_eq!(behavior, registry_order);
        assert!(context.later_registered().is_empty());
        let mut actual_behavior: Vec<_> = behavior.to_vec();
        let mut actual_defaults: Vec<_> = PropertyName::ALL
            .iter()
            .filter(|name| effective.get(**name).is_some())
            .map(|name| name.as_str())
            .collect();
        actual_behavior.sort_unstable();
        actual_defaults.sort_unstable();
        assert_eq!(actual_behavior, expected_behavior);
        assert_eq!(actual_defaults, expected_defaults);
        assert_eq!(context.behavioral_names().count(), 32 + revision as usize);
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
        if revision >= 2 {
            context.validate_map(&roots).expect("owner binding");
            let owner_policy = context
                .resolve(
                    &[RootLayer {
                        properties: &roots,
                        overrides: &[],
                    }],
                    defaults(),
                )
                .expect("owner pointer");
            let Some(Value::IndexRoots(owner_roots)) = owner_policy.get(PropertyName::IndexRoots)
            else {
                panic!("typed owner roots");
            };
            assert_eq!(owner_roots.get("uid"), Some([0xab; 32]));
            assert_eq!(
                context.validate_graft_overrides(&roots),
                Err(Error::InvalidValue)
            );
            let resolved = context
                .resolve(
                    &[
                        RootLayer {
                            properties: &roots,
                            overrides: &[],
                        },
                        RootLayer {
                            properties: &[],
                            overrides: &[],
                        },
                    ],
                    defaults(),
                )
                .expect("owner-only binding");
            assert_eq!(
                resolved.get(PropertyName::IndexRoots),
                effective.get(PropertyName::IndexRoots)
            );
        } else {
            assert_eq!(context.validate_map(&roots), Err(Error::UnknownProperty));
        }
        if revision == 3 {
            super::super::validate_property(&gaps[0]).expect("valid structural syntax");
            assert_eq!(context.validate_map(&gaps), Err(Error::InvalidValue));
            assert_eq!(
                context.validate_graft_overrides(&gaps),
                Err(Error::InvalidValue)
            );
        }
    }
    let inherited_roots = binding(&[0xa0], true);
    assert!(
        RecordedContext::new(2, 3, &[])
            .expect("revision 2")
            .validate_map(&[Property {
                name: "index-roots",
                value: &inherited_roots
            }])
            .is_err()
    );
}

#[test]
fn resolution_unknown_revisions_and_unregistered_extensions_refuse() {
    for revision in [0, 4, u64::MAX] {
        assert!(matches!(
            RecordedContext::new(revision, 3, &[]),
            Err(Error::InvalidValue)
        ));
    }
    for extensions in [
        &["store"][..],
        &["future", "future"][..],
        &["index-roots"][..],
    ] {
        assert!(RecordedContext::new(2, 3, extensions).is_err());
    }
    assert!(RecordedContext::new(3, 3, &["index-gaps"]).is_err());
    assert!(RecordedContext::new(1, 3, &[""]).is_err());

    // Name limits count UTF-8 bytes; owned names use canonical byte order
    // without changing the independently supplied caller vocabulary.
    let boundary = alloc::format!("{}z", "é".repeat(127));
    assert_eq!(boundary.len(), 255);
    let later_names = ["z", boundary.as_str(), "aa"];
    let context = RecordedContext::new(1, 3, &later_names).expect("255-byte UTF-8 name");
    let preserved = context.later_registered();
    assert_eq!(
        preserved
            .iter()
            .map(alloc::string::String::as_str)
            .collect::<Vec<_>>(),
        ["aa", "z", boundary.as_str()],
    );
    assert_eq!(later_names, ["z", boundary.as_str(), "aa"]);
    let oversized_name = "é".repeat(128);
    assert!(matches!(
        RecordedContext::new(1, 3, &[&oversized_name]),
        Err(Error::Limit)
    ));

    let mut names: Vec<_> = (0..257)
        .map(|position| alloc::format!("{position:04}{}z", "é".repeat(125)))
        .collect();
    names.push(alloc::string::String::from("x"));
    let names: Vec<_> = names.iter().map(|name| name.as_str()).collect();
    assert_eq!(names.iter().map(|name| name.len()).sum::<usize>(), 65536);
    let original_names = names.clone();
    let context = RecordedContext::new(1, 3, &names).expect("exact vocabulary byte bound");
    let mut expected: Vec<_> = names
        .iter()
        .map(|name| alloc::string::String::from(*name))
        .collect();
    expected.sort();
    assert_eq!(context.later_registered(), expected);
    assert_eq!(names, original_names);
    assert_eq!(
        context
            .later_registered()
            .iter()
            .map(|name| name.len())
            .sum::<usize>(),
        65536
    );
    let mut oversized_names = names.clone();
    oversized_names.push("y");
    assert!(matches!(
        RecordedContext::new(1, 3, &oversized_names),
        Err(Error::Limit)
    ));

    let properties = [Property {
        name: "future",
        value: &[0x00],
    }];
    let old = RecordedContext::new(1, 3, &[]).expect("revision 1");
    assert_eq!(old.validate_map(&properties), Err(Error::UnknownProperty));
    assert_eq!(
        old.resolve(
            &[RootLayer {
                properties: &properties,
                overrides: &[]
            }],
            defaults()
        ),
        Err(Error::UnknownProperty)
    );
    let trusted = RecordedContext::new(1, 3, &["future"]).expect("trusted schema");
    trusted
        .validate_map(&properties)
        .expect("canonical inert value");
    let duplicate = [properties[0], properties[0]];
    assert_eq!(trusted.validate_map(&duplicate), Err(Error::InvalidValue));
    let trailing = [Property {
        name: "future",
        value: &[0x00, 0x00],
    }];
    assert!(trusted.validate_map(&trailing).is_err());
}

#[test]
fn recorded_paths_preserve_inheritance_wipe_domains_and_depth() {
    let store = text("owner-store");
    let override_store = binding(&text("local-store"), false);
    let public = text("public");
    let global = text("global");
    let owner = [Property {
        name: "store",
        value: &store,
    }];
    let local = [Property {
        name: "store",
        value: &override_store,
    }];
    let public_map = [
        Property {
            name: "domain",
            value: &public,
        },
        Property {
            name: "dedup",
            value: &global,
        },
    ];
    let invalid_domain = [Property {
        name: "dedup",
        value: &global,
    }];
    for revision in 1..=3 {
        let context = RecordedContext::new(revision, 3, &[]).expect("revision");
        let own = context
            .resolve(
                &[RootLayer {
                    properties: &owner,
                    overrides: &local,
                }],
                defaults(),
            )
            .expect("local override");
        assert_eq!(
            own.get(PropertyName::Store),
            Some(&Value::Text("local-store"))
        );
        let child = context
            .resolve(
                &[
                    RootLayer {
                        properties: &owner,
                        overrides: &local,
                    },
                    RootLayer {
                        properties: &[],
                        overrides: &[],
                    },
                ],
                defaults(),
            )
            .expect("noninherit override hides owner");
        assert_eq!(
            child.get(PropertyName::Store),
            Some(&Value::Text("authority"))
        );
        let policy = context
            .resolve(
                &[RootLayer {
                    properties: &public_map,
                    overrides: &[],
                }],
                defaults(),
            )
            .expect("public global dedup");
        assert_eq!(policy.get(PropertyName::Wipe), Some(&Value::Text("none")));
        assert_eq!(
            context.resolve(
                &[RootLayer {
                    properties: &invalid_domain,
                    overrides: &[]
                }],
                defaults()
            ),
            Err(Error::Domain)
        );
        let empty = RootLayer {
            properties: &[],
            overrides: &[],
        };
        context
            .resolve(&vec![empty; 65], defaults())
            .expect("64 graft edges");
        assert_eq!(
            context.resolve(&vec![empty; 66], defaults()),
            Err(Error::Limit)
        );
    }
}
