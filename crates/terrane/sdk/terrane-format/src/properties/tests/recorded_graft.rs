//! Exercises selected raw graft validation through the real commit validator.

use super::*;
use crate::auth::Verb;
use crate::identity::Digest;
use crate::properties::selected::Selection;
use crate::properties::semantics::RecordedContext;
use core::cell::Cell;

struct Context<'a> {
    target: &'a EffectiveProperties<'a>,
    selected: Option<&'a Selection>,
    later: &'a [&'a str],
    domain: Domain<'a>,
    administrator: bool,
    references: Vec<Digest>,
    grafts: Cell<usize>,
}

impl CommitContext for Context<'_> {
    fn reference_domain(&mut self, identity: Digest) -> Result<Domain<'_>, Error> {
        self.references.push(identity);
        Ok(self.domain)
    }

    fn graft_policy(
        &self,
        _entry: &Entry<'_>,
        _parent: &EffectiveProperties<'_>,
    ) -> Result<&EffectiveProperties<'_>, Error> {
        self.grafts.set(self.grafts.get() + 1);
        Ok(self.target)
    }

    fn ancestor_admin(&self, _parent: &EffectiveProperties<'_>) -> bool {
        self.administrator
    }

    fn later_registered_properties(&self) -> &[&str] {
        self.later
    }

    fn property_selection(&self) -> Option<&Selection> {
        self.selected
    }
}

fn context<'a>(
    target: &'a EffectiveProperties<'a>,
    selected: Option<&'a Selection>,
) -> Context<'a> {
    Context {
        target,
        selected,
        later: &[],
        domain: Domain::Public,
        administrator: false,
        references: Vec::new(),
        grafts: Cell::new(0),
    }
}

fn graft<'a>(properties: Vec<Property<'a>>, root: Digest) -> Entry<'a> {
    Entry {
        kind: EntryKind::Tree {
            root,
            props: Some(properties),
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn recorded(revision: u64, later: &[&str]) -> Selection {
    Selection::Recorded(
        RecordedContext::new(revision, 3, later).expect("registered recorded fixture context"),
    )
}

/// Checks preserved graft bindings through the actual commit validator.
///
/// # Panics
/// Panics when fixture construction fails or preservation assertions fail.
pub(super) fn preserves_trusted_later_bindings() {
    for (revision, later) in [
        (1, vec!["index-roots", "index-gaps", "future-note"]),
        (2, vec!["index-gaps", "future-note"]),
        (3, vec!["future-note"]),
    ] {
        let selected = recorded(revision, &later);
        let parent = selected
            .resolve(&[], defaults())
            .expect("recorded parent defaults");
        let overrides: Vec<_> = later
            .iter()
            .map(|name| Property {
                name,
                value: b"\x00",
            })
            .collect();
        let target = selected
            .resolve(
                &[
                    RootLayer {
                        properties: &[],
                        overrides: &[],
                    },
                    RootLayer {
                        properties: &[],
                        overrides: &overrides,
                    },
                ],
                defaults(),
            )
            .expect("trusted later overrides resolve inertly");
        let entry = graft(overrides.clone(), [8; 32]);
        let original = entry.clone();
        let mut supplied = context(&target, Some(&selected));

        validate_commit_with_context(&[(&entry, &parent)], &[], &mut supplied)
            .expect("selected graft admission preserves trusted later bindings");

        assert_eq!(entry, original, "revision {revision} raw bytes retained");
        assert_eq!(supplied.references, [[8; 32]]);
        assert_eq!(supplied.grafts.get(), 1);
        assert_eq!(target, parent, "preserved values contribute no policy");
        assert!(target.active_index_roots().is_none());
        assert!(target.get(PropertyName::IndexGaps).is_none());
    }

    // Existing implementations with no selected input retain their current
    // semantics and trusted extension contract through the same entrypoint.
    let policy = resolve(&[], defaults()).expect("current compatibility defaults");
    let entry = graft(
        vec![Property {
            name: "future-note",
            value: b"\x00",
        }],
        [9; 32],
    );
    let mut compatibility = context(&policy, None);
    compatibility.later = &["future-note"];
    validate_commit_with_context(&[(&entry, &policy)], &[], &mut compatibility)
        .expect("default context preserves its trusted later registration");
    assert_eq!(compatibility.references, [[9; 32]]);
}

fn refuses_raw(selection: Selection, name: &str, value: &[u8]) {
    let parent = selection
        .resolve(&[], defaults())
        .expect("selected refusal fixture defaults");
    let entry = graft(vec![Property { name, value }], [8; 32]);
    let mut supplied = context(&parent, Some(&selection));

    assert!(validate_commit_with_context(&[(&entry, &parent)], &[], &mut supplied).is_err());
    assert!(
        supplied.references.is_empty(),
        "raw refusal precedes reference use"
    );
    assert_eq!(supplied.grafts.get(), 0);
}

fn grants(principals: &[(&str, u8)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, principals.len());
    for (principal, mask) in principals {
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, principal);
        cbor::write_uint(&mut bytes, u64::from(*mask));
    }
    bytes
}

fn boundary_control(parent_acl: &[(&str, u8)], child_acl: &[(&str, u8)], admin: bool) {
    let selected = recorded(1, &["index-roots", "index-gaps", "future-note"]);
    let parent_bytes = grants(parent_acl);
    let child_bytes = grants(child_acl);
    let parent_map = [Property {
        name: "acl",
        value: &parent_bytes,
    }];
    let child_map = [Property {
        name: "acl",
        value: &child_bytes,
    }];
    let parent = selected
        .resolve(
            &[RootLayer {
                properties: &parent_map,
                overrides: &[],
            }],
            defaults(),
        )
        .expect("parent authority fixture resolves");
    let target = selected
        .resolve(
            &[RootLayer {
                properties: &child_map,
                overrides: &[],
            }],
            defaults(),
        )
        .expect("child authority fixture resolves");
    let entry = graft(
        vec![Property {
            name: "future-note",
            value: b"\x00",
        }],
        [8; 32],
    );
    let mut supplied = context(&target, Some(&selected));
    supplied.administrator = admin;

    assert_eq!(
        validate_commit_with_context(&[(&entry, &parent)], &[], &mut supplied),
        Err(Error::Authority)
    );
    assert_eq!(supplied.references, [[8; 32]]);
    assert_eq!(
        supplied.grafts.get(),
        1,
        "authority refusal after selected raw validation"
    );
}

/// Checks placement, domain and authority refusals through the commit validator.
///
/// # Panics
/// Panics when fixture construction fails or refusal assertions fail.
pub(super) fn keeps_placement_and_policy_refusals() {
    for selection in [Selection::Active, recorded(2, &[]), recorded(3, &[])] {
        refuses_raw(selection, "index-roots", b"\x00");
    }
    refuses_raw(recorded(3, &[]), "index-gaps", b"\x00");
    refuses_raw(Selection::Legacy, "future-note", b"\x00");
    refuses_raw(recorded(1, &[]), "index-roots", b"\x00");
    refuses_raw(recorded(1, &[]), "future-note", b"\x00");
    for wire in [b"\x18\x00".as_slice(), b"\x00\x00", b"\xa1\x61x"] {
        refuses_raw(recorded(1, &["future-note"]), "future-note", wire);
    }
    assert!(RecordedContext::new(4, 4, &[]).is_err());

    let selected = recorded(1, &["future-note"]);
    let parent = selected
        .resolve(&[], defaults())
        .expect("recorded domain fixture defaults");
    let public = [Property {
        name: "domain",
        value: b"\x66public",
    }];
    let target = selected
        .resolve(
            &[RootLayer {
                properties: &public,
                overrides: &[],
            }],
            defaults(),
        )
        .expect("public target domain fixture resolves");
    let entry = graft(
        vec![Property {
            name: "future-note",
            value: b"\x00",
        }],
        [8; 32],
    );
    let mut supplied = context(&target, Some(&selected));
    assert_eq!(
        validate_commit_with_context(&[(&entry, &parent)], &[], &mut supplied),
        Err(Error::Domain)
    );
    assert_eq!(supplied.grafts.get(), 1);
    supplied.domain = Domain::Tenant("narrow");
    let public_parent = target.clone();
    assert_eq!(
        validate_commit_with_context(&[(&entry, &public_parent)], &[], &mut supplied),
        Err(Error::Domain)
    );

    let commit = Verb::Commit as u8;
    boundary_control(
        &[("writer", commit)],
        &[("writer", commit), ("new", commit)],
        false,
    );
    boundary_control(&[("writer", 16)], &[("writer", commit)], false);
    boundary_control(&[("writer", 16)], &[("writer", commit)], true);

    // Raw checks also apply to grafts carried as conflict candidates and bases.
    let valid = graft(
        vec![Property {
            name: "future-note",
            value: b"\x00",
        }],
        [9; 32],
    );
    let invalid = graft(
        vec![Property {
            name: "unknown",
            value: b"\x00",
        }],
        [10; 32],
    );
    for kind in [
        EntryKind::Conflict {
            candidates: vec![valid.clone(), invalid.clone()],
            base: None,
        },
        EntryKind::Conflict {
            candidates: vec![valid.clone(), valid.clone()],
            base: Some(Some(alloc::boxed::Box::new(invalid))),
        },
    ] {
        let mut conflict = valid.clone();
        conflict.kind = kind;
        let mut supplied = context(&parent, Some(&selected));
        assert_eq!(
            validate_commit_with_context(&[(&conflict, &parent)], &[], &mut supplied),
            Err(Error::UnknownProperty)
        );
        assert_eq!(supplied.references, vec![[9; 32]; supplied.grafts.get()]);
    }

    let mut compatibility = context(&parent, None);
    let active_binding = graft(
        vec![Property {
            name: "index-roots",
            value: b"\x00",
        }],
        [8; 32],
    );
    assert_eq!(
        validate_commit_with_context(&[(&active_binding, &parent)], &[], &mut compatibility),
        Err(Error::InvalidValue)
    );
}
