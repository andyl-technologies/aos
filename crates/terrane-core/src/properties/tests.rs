//! Exercises property resolution, commit requirements, and disclosure checks.

use super::*;
use crate::cbor;
use crate::tree_format::{Attribute, ContentRef, Entry, EntryKind, Property};
use alloc::vec;
use alloc::vec::Vec;

fn text(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_text(&mut bytes, value);
    bytes
}

fn names(values: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, values.len());
    for value in values {
        cbor::write_text(&mut bytes, value);
    }
    bytes
}

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "authority",
        private_domain: "private:root",
        home: "region-a",
    }
}

fn file() -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: 1,
            content: ContentRef::Inline([7; 32]),
            link_id: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

#[test]
fn resolution_registry_defaults_and_path_overrides() {
    let default = resolve(&[], defaults()).expect("defaults");
    assert_eq!(PropertyName::ALL.len(), 33);
    for name in PropertyName::ALL {
        assert!(default.get(*name).is_some());
        assert_eq!(PropertyName::parse(name.as_str()), Ok(*name));
    }
    assert_eq!(default.domain(), Ok(Domain::Private("root")));
    assert_eq!(default.get(PropertyName::Wipe), Some(&Value::Text("zero")));

    let a = text("store-a");
    let b = text("store-b");
    let c = text("store-c");
    let parent = [Property {
        name: "store",
        value: &a,
    }];
    let child = [Property {
        name: "store",
        value: &b,
    }];
    let overrides = [Property {
        name: "store",
        value: &c,
    }];
    let resolved = resolve(
        &[
            RootLayer {
                properties: &parent,
                overrides: &[],
            },
            RootLayer {
                properties: &child,
                overrides: &overrides,
            },
        ],
        defaults(),
    )
    .expect("graft overrides");
    assert_eq!(
        resolved.get(PropertyName::Store),
        Some(&Value::Text("store-c"))
    );
    let alternate_path = resolve(
        &[RootLayer {
            properties: &child,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("different view path");
    assert!(!resolved.same_boundaries(&alternate_path));
}

#[test]
fn resolution_attr_by_requires_registered_attribute_names() {
    let selector = |name: &str| {
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, 3);
        cbor::write_text(&mut bytes, "attr-by");
        cbor::write_text(&mut bytes, name);
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, "preset");
        cbor::write_text(&mut bytes, "any");
        bytes
    };

    let maximum_tag = alloc::format!("tag.{}", "x".repeat(251));
    let maximum_unicode_tag = alloc::format!("tag.{}x", "é".repeat(125));
    for name in [
        "hash.sha256",
        "class.elf",
        "provenance.reintroduced-from",
        "nar.size",
        "tag.custom",
        maximum_tag.as_str(),
        maximum_unicode_tag.as_str(),
    ] {
        let value = selector(name);
        assert!(
            validate_property(&Property {
                name: "trust",
                value: &value
            })
            .is_ok(),
            "registered attribute {name}"
        );
    }

    let oversized_tag = alloc::format!("tag.{}", "x".repeat(252));
    for name in [
        "",
        "unknown",
        "nar.custom",
        "hash.custom",
        "tag.",
        oversized_tag.as_str(),
    ] {
        let value = selector(name);
        assert!(
            validate_property(&Property {
                name: "trust",
                value: &value
            })
            .is_err(),
            "unregistered attribute {name}"
        );
    }
}

#[test]
fn resolution_rejects_unregistered_and_invalid_values() {
    assert_eq!(
        validate_property(&Property {
            name: "unknown",
            value: &[0]
        }),
        Err(Error::UnknownProperty)
    );
    assert!(
        validate_property(&Property {
            name: "strict-attrs",
            value: &[0]
        })
        .is_err()
    );
    for (name, value) in [
        ("encryption", "aes:key"),
        ("chunk", "unknown"),
        ("compression", "zstd:unregistered"),
        ("durability", "regions(0)"),
        ("redundancy", "replicated(2,ack=3)"),
    ] {
        assert!(
            validate_property(&Property {
                name,
                value: &text(value)
            })
            .is_err()
        );
    }
    for name in ["compaction_threshold", "whole_pack_threshold"] {
        let mut bytes = Vec::new();
        cbor::write_uint(&mut bytes, 10001);
        assert!(
            validate_property(&Property {
                name,
                value: &bytes
            })
            .is_err()
        );
    }
    assert!(
        validate_property(&Property {
            name: "hashes",
            value: &names(&["sha256", "sha256"])
        })
        .is_err()
    );
    assert!(
        validate_property(&Property {
            name: "hashes",
            value: &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        })
        .is_err()
    );
    assert_eq!(
        resolve(
            &[RootLayer {
                properties: &[],
                overrides: &[]
            }; 66],
            defaults()
        ),
        Err(Error::Limit)
    );
}

#[test]
fn resolution_preserves_later_registered_without_behavior() {
    let encoded = names(&["opaque"]);
    let property = [Property {
        name: "later-property",
        value: &encoded,
    }];
    validate_preserved_map(&property, &["later-property"]).expect("preserve future registry");
    assert_eq!(property[0].value, encoded);
    let effective = resolve_with_registry(
        &[RootLayer {
            properties: &property,
            overrides: &[],
        }],
        defaults(),
        &["later-property"],
    )
    .expect("unknown registered behavior ignored");
    assert_eq!(
        effective.get(PropertyName::Store),
        Some(&Value::Text("authority"))
    );
    assert_eq!(
        validate_preserved_map(&property, &[]),
        Err(Error::UnknownProperty)
    );
}

#[test]
fn required_attrs_reject_only_changed_entries() {
    let hash_names = names(&["sha256"]);
    let map = [Property {
        name: "hashes",
        value: &hash_names,
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &map,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("require hash");
    let entry = file();
    let change = EntryChange {
        entry: &entry,
        properties: &policy,
        reference_domains: &[Domain::Public],
        graft_properties: None,
    };
    assert_eq!(
        validate_commit(&[change], &[]),
        Err(Error::MissingAttribute)
    );
    validate_commit(&[], &[]).expect("existing entries untouched");
    let report = completeness(&[(&entry, &policy)], PropertyName::Hashes, &[], &[])
        .expect("tree-derived gaps");
    assert_eq!(
        report,
        Completeness {
            complete: 0,
            incomplete: 1
        }
    );
    assert!(report.backfill_required());

    let mut hash = Vec::new();
    cbor::write_bytes(&mut hash, &[3; 32]);
    let derived = [DerivedAttribute {
        object: [7; 32],
        attribute: Attribute {
            name: "hash.sha256",
            value: &hash,
        },
    }];
    validate_commit(&[change], &derived).expect("side-table avoids content reads");
    assert_eq!(
        completeness(&[(&entry, &policy)], PropertyName::Hashes, &derived, &[])
            .expect("complete")
            .complete,
        1
    );
    let mut changed = entry.clone();
    changed.attrs.push(Attribute {
        name: "hash.sha256",
        value: &hash,
    });
    validate_commit(
        &[EntryChange {
            entry: &changed,
            ..change
        }],
        &[],
    )
    .expect("inline hash");
}

#[test]
fn required_attrs_strict_names_and_inline_consistency() {
    let map = [Property {
        name: "strict-attrs",
        value: &[0xf5],
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &map,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("strict");
    let mut hash = Vec::new();
    cbor::write_bytes(&mut hash, &[3; 32]);
    let mut entry = file();
    entry.attrs.push(Attribute {
        name: "unregistered",
        value: &[0],
    });
    let source = [Domain::Public];
    let change = EntryChange {
        entry: &entry,
        properties: &policy,
        reference_domains: &source,
        graft_properties: None,
    };
    assert_eq!(
        validate_commit(&[change], &[]),
        Err(Error::UnknownAttribute)
    );
    let lenient = resolve(&[], defaults()).expect("lenient");
    validate_commit(
        &[EntryChange {
            properties: &lenient,
            ..change
        }],
        &[],
    )
    .expect("unknown attrs preserved");
    assert!(registered_attribute("tag.custom"));
    assert!(!registered_attribute("nar.custom"));
    assert!(!registered_attribute("tag."));

    let hash_names = names(&["sha256"]);
    let map = [Property {
        name: "hashes",
        value: &hash_names,
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &map,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("hash policy");
    let mut alternate = Vec::new();
    cbor::write_bytes(&mut alternate, &[4; 32]);
    entry.attrs = vec![Attribute {
        name: "hash.sha256",
        value: &hash,
    }];
    let derived = [DerivedAttribute {
        object: [7; 32],
        attribute: Attribute {
            name: "hash.sha256",
            value: &alternate,
        },
    }];
    assert_eq!(
        validate_commit(
            &[EntryChange {
                entry: &entry,
                properties: &policy,
                reference_domains: &source,
                graft_properties: None
            }],
            &derived
        ),
        Err(Error::InvalidValue)
    );
}

#[test]
fn domain_reference_closed_order_and_metadata_fail_closed() {
    let domains = [
        Domain::Public,
        Domain::Tenant("a"),
        Domain::Tenant("b"),
        Domain::Group("a"),
        Domain::Group("b"),
        Domain::Private("a"),
        Domain::Private("b"),
    ];
    for target in domains {
        for source in domains {
            let expected = target == source
                || source == Domain::Public
                || matches!(
                    (target, source),
                    (Domain::Group(_) | Domain::Private(_), Domain::Tenant(_))
                        | (Domain::Private(_), Domain::Group(_))
                );
            assert_eq!(target.permits_reference(source), expected);
        }
    }
    let public = text("public");
    let map = [Property {
        name: "domain",
        value: &public,
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &map,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("public root");
    let entry = file();
    let change = EntryChange {
        entry: &entry,
        properties: &policy,
        reference_domains: &[Domain::Private("secret")],
        graft_properties: None,
    };
    assert_eq!(validate_commit(&[change], &[]), Err(Error::Domain));
    assert_eq!(
        validate_commit(
            &[EntryChange {
                reference_domains: &[],
                ..change
            }],
            &[]
        ),
        Err(Error::IncompleteContext)
    );
    validate_commit(
        &[EntryChange {
            reference_domains: &[Domain::Public],
            ..change
        }],
        &[],
    )
    .expect("public reference");
}

#[test]
fn domain_reference_boundary_acl_narrowing() {
    let private = resolve(&[], defaults()).expect("private");
    let public_bytes = text("public");
    let public_props = [Property {
        name: "domain",
        value: &public_bytes,
    }];
    let public = resolve(
        &[RootLayer {
            properties: &public_props,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("public");
    validate_boundary_transition(&public, &private, false).expect("narrow disclosure");
    assert_eq!(
        validate_boundary_transition(&private, &public, true),
        Err(Error::Domain)
    );
    let acl = [0x81, 0x82, 0x61, b'a', 0x14];
    let acl_props = [Property {
        name: "acl",
        value: &acl,
    }];
    let child = resolve(
        &[RootLayer {
            properties: &acl_props,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("grants");
    assert_eq!(
        validate_boundary_transition(&private, &child, false),
        Err(Error::Authority)
    );
    validate_boundary_transition(&private, &child, true).expect("ancestor admin");
    validate_boundary_transition(&child, &private, false).expect("narrow ACL");
}

fn binding(value: &[u8], inherit: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 2);
    cbor::write_text(&mut bytes, "value");
    bytes.extend_from_slice(value);
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(if inherit { 0xf5 } else { 0xf4 });
    bytes
}

#[test]
fn resolution_non_inheriting_binding_skips_to_nearest_eligible_ancestor() {
    let outer = text("outer");
    let local = binding(&text("local"), false);
    let root_props = [Property {
        name: "store",
        value: &outer,
    }];
    let child_props = [Property {
        name: "store",
        value: &local,
    }];
    let layers = [
        RootLayer {
            properties: &root_props,
            overrides: &[],
        },
        RootLayer {
            properties: &child_props,
            overrides: &[],
        },
    ];
    let local_policy = resolve(&layers, defaults()).expect("own non-inheriting value");
    assert_eq!(
        local_policy.get(PropertyName::Store),
        Some(&Value::Text("local"))
    );
    let descendant = resolve(
        &[
            layers[0],
            layers[1],
            RootLayer {
                properties: &[],
                overrides: &[],
            },
        ],
        defaults(),
    )
    .expect("skip non-inheriting ancestor");
    assert_eq!(
        descendant.get(PropertyName::Store),
        Some(&Value::Text("outer"))
    );
    let override_layer = RootLayer {
        properties: &root_props,
        overrides: &child_props,
    };
    let grandchild = resolve(
        &[
            override_layer,
            RootLayer {
                properties: &[],
                overrides: &[],
            },
        ],
        defaults(),
    )
    .expect("graft override replaces binding");
    assert_eq!(
        grandchild.get(PropertyName::Store),
        Some(&Value::Text("authority"))
    );
    let acl = binding(&[0x80], false);
    assert!(
        validate_property(&Property {
            name: "acl",
            value: &acl
        })
        .is_err()
    );
}

#[test]
fn resolution_quota_trust_and_conditional_wipe_defaults() {
    let mut quota = Vec::new();
    cbor::write_map(&mut quota, 2);
    cbor::write_text(&mut quota, "bytes-per-root");
    cbor::write_uint(&mut quota, 42);
    cbor::write_text(&mut quota, "bytes-per-principal-unreferenced");
    cbor::write_uint(&mut quota, 7);
    assert_eq!(
        validate_property(&Property {
            name: "quota",
            value: &quota
        })
        .expect("quota")
        .1,
        Value::Quota {
            root: 42,
            principal: 7
        }
    );
    let mut selector = Vec::new();
    cbor::write_array(&mut selector, 2);
    cbor::write_text(&mut selector, "not");
    selector.extend_from_slice(&names(&["kind", "human"]));
    assert_eq!(
        validate_property(&Property {
            name: "trust",
            value: &selector
        })
        .expect("selector")
        .1,
        Value::Selector(&selector)
    );
    assert!(
        validate_property(&Property {
            name: "trust",
            value: &names(&["attested", "unregistered"])
        })
        .is_err()
    );
    let domain = text("public");
    let properties = [Property {
        name: "domain",
        value: &domain,
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &properties,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("public");
    assert_eq!(policy.get(PropertyName::Wipe), Some(&Value::Text("none")));
}

#[test]
fn required_attrs_classification_and_index_gaps() {
    let classifications = names(&["elf"]);
    let indexed = names(&["class.magic"]);
    let map = [
        Property {
            name: "classify",
            value: &classifications,
        },
        Property {
            name: "index",
            value: &indexed,
        },
    ];
    let policy = resolve(
        &[RootLayer {
            properties: &map,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("classification requirements");
    let magic = text("elf");
    let non_elf = text("text");
    let mut entry = file();
    entry.attrs.push(Attribute {
        name: "class.magic",
        value: &magic,
    });
    let source = [Domain::Public];
    let change = EntryChange {
        entry: &entry,
        properties: &policy,
        reference_domains: &source,
        graft_properties: None,
    };
    assert_eq!(
        validate_commit(&[change], &[]),
        Err(Error::MissingAttribute)
    );
    entry.attrs[0].value = &non_elf;
    validate_commit(
        &[EntryChange {
            entry: &entry,
            properties: &policy,
            reference_domains: &source,
            graft_properties: None,
        }],
        &[],
    )
    .expect("nonmatching classifier needs only magic");
    assert_eq!(
        completeness(&[(&entry, &policy)], PropertyName::Index, &[], &[])
            .expect("missing index")
            .incomplete,
        1
    );
    assert_eq!(
        completeness(
            &[(&entry, &policy)],
            PropertyName::Index,
            &[],
            &["class.magic"]
        )
        .expect("verified index")
        .complete,
        1
    );
}

#[test]
fn domain_reference_graft_overrides_and_dedup_scope() {
    let public = text("public");
    let private = text("private:target");
    let public_props = [Property {
        name: "domain",
        value: &public,
    }];
    let private_props = [Property {
        name: "domain",
        value: &private,
    }];
    let parent = resolve(
        &[RootLayer {
            properties: &public_props,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("public parent");
    let target = resolve(
        &[RootLayer {
            properties: &private_props,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("private target effective policy");
    let entry = Entry {
        kind: EntryKind::Tree {
            root: [8; 32],
            props: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let change = EntryChange {
        entry: &entry,
        properties: &parent,
        reference_domains: &[Domain::Public],
        graft_properties: Some(&target),
    };
    validate_commit(&[change], &[]).expect("public target narrowed at graft");
    assert_eq!(
        validate_commit(
            &[EntryChange {
                reference_domains: &[Domain::Private("target")],
                ..change
            }],
            &[]
        ),
        Err(Error::Domain)
    );
    let global = text("global");
    let props = [Property {
        name: "dedup",
        value: &global,
    }];
    assert_eq!(
        resolve(
            &[RootLayer {
                properties: &props,
                overrides: &[]
            }],
            defaults()
        ),
        Err(Error::Domain)
    );
}

#[test]
fn domain_reference_conflict_candidates_checked_individually() {
    let public = text("public");
    let props = [Property {
        name: "domain",
        value: &public,
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &props,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("public");
    let conflict = Entry {
        kind: EntryKind::Conflict {
            candidates: vec![file(), file()],
            base: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let nested_base = Entry {
        kind: EntryKind::Conflict {
            candidates: vec![file(), file()],
            base: Some(Some(alloc::boxed::Box::new(conflict.clone()))),
        },
        ..conflict.clone()
    };
    validate_commit(
        &[EntryChange {
            entry: &nested_base,
            properties: &policy,
            reference_domains: &[Domain::Public; 4],
            graft_properties: None,
        }],
        &[],
    )
    .expect("conflict bases are full entries");

    let invalid_candidate = Entry {
        kind: EntryKind::Conflict {
            candidates: vec![conflict.clone(), file()],
            base: None,
        },
        ..conflict.clone()
    };
    assert_eq!(
        validate_commit(
            &[EntryChange {
                entry: &invalid_candidate,
                properties: &policy,
                reference_domains: &[Domain::Public; 3],
                graft_properties: None,
            }],
            &[]
        ),
        Err(Error::InvalidValue)
    );

    let sources = [Domain::Public, Domain::Public];
    let change = EntryChange {
        entry: &conflict,
        properties: &policy,
        reference_domains: &sources,
        graft_properties: None,
    };
    validate_commit(&[change], &[]).expect("valid conflict preserved");
    assert_eq!(
        validate_commit(
            &[EntryChange {
                reference_domains: &[Domain::Public, Domain::Private("secret")],
                ..change
            }],
            &[]
        ),
        Err(Error::Domain)
    );
    assert_eq!(
        validate_commit(
            &[EntryChange {
                reference_domains: &[Domain::Public],
                ..change
            }],
            &[]
        ),
        Err(Error::IncompleteContext)
    );
}

#[test]
fn required_attrs_strict_completeness_tracks_names() {
    let props = [Property {
        name: "strict-attrs",
        value: &[0xf5],
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &props,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("strict");
    let mut entry = file();
    entry.attrs.push(Attribute {
        name: "unknown",
        value: &[0],
    });
    assert_eq!(
        completeness(&[(&entry, &policy)], PropertyName::StrictAttrs, &[], &[])
            .expect("strict name report")
            .incomplete,
        1
    );
}

#[test]
fn domain_reference_context_resolves_each_candidate_identity() {
    struct Context;

    impl CommitContext for Context {
        fn reference_domain(
            &mut self,
            identity: crate::identity::Digest,
        ) -> Result<Domain<'_>, Error> {
            if identity == [7; 32] {
                Ok(Domain::Public)
            } else {
                Err(Error::IncompleteContext)
            }
        }

        fn graft_policy(
            &self,
            _entry: &Entry<'_>,
            _parent: &EffectiveProperties<'_>,
        ) -> Result<&EffectiveProperties<'_>, Error> {
            Err(Error::IncompleteContext)
        }
    }

    let policy = resolve(&[], defaults()).expect("private");
    let mut other = file();
    if let EntryKind::File { content, .. } = &mut other.kind {
        *content = ContentRef::Inline([8; 32]);
    }
    let conflict = Entry {
        kind: EntryKind::Conflict {
            candidates: vec![file(), other],
            base: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    assert_eq!(
        validate_commit_with_context(&[(&conflict, &policy)], &[], &mut Context),
        Err(Error::IncompleteContext)
    );
    validate_commit_with_context(&[(&file(), &policy)], &[], &mut Context).expect("metadata found");
}

#[test]
fn domain_reference_graft_acl_widening_requires_verified_admin() {
    let parent = resolve(&[], defaults()).expect("private parent");
    let grants = [0x81, 0x82, 0x61, b'a', 0x14];
    let props = [Property {
        name: "acl",
        value: &grants,
    }];
    let target = resolve(
        &[RootLayer {
            properties: &props,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("target grants");
    let entry = Entry {
        kind: EntryKind::Tree {
            root: [8; 32],
            props: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let change = EntryChange {
        entry: &entry,
        properties: &parent,
        reference_domains: &[Domain::Public],
        graft_properties: Some(&target),
    };
    assert_eq!(validate_commit(&[change], &[]), Err(Error::Authority));

    struct AdminContext<'a> {
        target: &'a EffectiveProperties<'a>,
    }

    impl CommitContext for AdminContext<'_> {
        fn reference_domain(
            &mut self,
            _identity: crate::identity::Digest,
        ) -> Result<Domain<'_>, Error> {
            Ok(Domain::Public)
        }

        fn graft_policy(
            &self,
            _entry: &Entry<'_>,
            _parent: &EffectiveProperties<'_>,
        ) -> Result<&EffectiveProperties<'_>, Error> {
            Ok(self.target)
        }

        fn ancestor_admin(&self, _parent: &EffectiveProperties<'_>) -> bool {
            true
        }
    }

    validate_commit_with_context(
        &[(&entry, &parent)],
        &[],
        &mut AdminContext { target: &target },
    )
    .expect("verified ancestor admin");
}

#[test]
fn domain_reference_graft_rejects_unregistered_property_bindings() {
    let policy = resolve(&[], defaults()).expect("private root");
    let entry = Entry {
        kind: EntryKind::Tree {
            root: [8; 32],
            props: Some(vec![Property {
                name: "unknown",
                value: &[0],
            }]),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let change = EntryChange {
        entry: &entry,
        properties: &policy,
        reference_domains: &[Domain::Public],
        graft_properties: Some(&policy),
    };
    assert_eq!(validate_commit(&[change], &[]), Err(Error::UnknownProperty));
}
