//! Exercises resolved ownership, recipe binding, and missing-context rejection.

#![allow(clippy::unwrap_used)]

use alloc::vec;
use alloc::vec::Vec;

use super::{DomainError, OperationDomains};
use crate::algebra::{self, Error, MergePolicy, Overlay, Recipe, Roots, TrustContext};
use crate::identity::Digest;
use crate::properties::{self, Defaults, RootLayer};
use crate::tree_builder::Tree;
use crate::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};

fn entry(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn value(target: &'static [u8]) -> Entry<'static> {
    entry(EntryKind::Symlink { target })
}

fn tree(items: &[(&[u8], Entry<'static>)]) -> Tree<'static> {
    Tree::build(
        items
            .iter()
            .map(|(key, entry)| LeafItem {
                key: key.to_vec(),
                entry: entry.clone(),
            })
            .collect(),
        None,
        4096,
        TreeUse::Ordinary,
    )
    .unwrap()
}

struct Forest(Vec<Tree<'static>>);

impl<'a> Roots<'a> for Forest {
    fn resolve(&self, root: &Digest) -> Option<&Tree<'a>> {
        self.0.iter().find(|tree| tree.root_identity() == *root)
    }
}

fn graft_entry(tree: &Tree<'_>) -> Entry<'static> {
    entry(EntryKind::Tree {
        root: tree.root_identity(),
        props: None,
    })
}

fn bind(domains: &mut OperationDomains, root: Digest, label: &str) {
    let mut encoded = Vec::new();
    crate::cbor::write_text(&mut encoded, label);
    let properties = [Property {
        name: "domain",
        value: &encoded,
    }];
    let effective = properties::resolve(
        &[RootLayer {
            properties: &properties,
            overrides: &[],
        }],
        Defaults {
            store: "authority",
            private_domain: "private:fallback",
            home: "local",
        },
    )
    .unwrap();
    domains.bind_resolved(root, &effective).unwrap();
}

fn label<'t>(tree: &'t Tree<'_>) -> &'t str {
    let property = tree
        .props()
        .unwrap()
        .iter()
        .find(|property| property.name == "domain")
        .unwrap();
    let (_, properties::Value::Text(label)) = properties::validate_property(property).unwrap()
    else {
        panic!("expected domain label");
    };
    label
}

#[test]
fn graft_preserves_exact_previous_private_ownership() {
    let source = tree(&[(b"retained", value(b"data"))]);
    let target = tree(&[(b"target", value(b"target"))]);
    let roots = Forest(vec![target.clone()]);
    let default_label = alloc::format!(
        "private:{}",
        source
            .root_identity()
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect::<alloc::string::String>()
    );

    for old_owner in [default_label.as_str(), "private:inherited-owner"] {
        let mut domains = OperationDomains::new();
        bind(&mut domains, source.root_identity(), old_owner);

        let grafted = algebra::graft_with_domains(
            &source,
            b"mount",
            graft_entry(&target),
            false,
            &roots,
            &domains,
        )
        .unwrap();
        assert_eq!(label(&grafted), old_owner);
        assert_ne!(grafted.root_identity(), source.root_identity());
        assert_eq!(grafted.get(b"retained"), source.get(b"retained"));

        let prepared = algebra::prepare_graft_with_domains(
            &source,
            b"mount",
            &graft_entry(&target),
            false,
            &domains,
        )
        .unwrap();
        let result = prepared
            .materialize(&source, &roots, &mut algebra::RootGraph::new())
            .unwrap();
        assert_eq!(result.tree.root_identity(), grafted.root_identity());
        let decoded = Recipe::decode(&result.recipe).unwrap();
        assert_eq!(decoded.as_recipe().encode(), result.recipe);
        assert!(decoded.bind_domains(&domains).is_ok());
    }

    assert_eq!(
        algebra::graft(&source, b"mount", graft_entry(&target), false, &roots).unwrap_err(),
        Error::DomainContext(DomainError::Missing(source.root_identity()))
    );
}

#[test]
fn split_preserves_inherited_private_and_tenant_ownership() {
    let source = tree(&[
        (b"directory", entry(EntryKind::Directory { mode: 0o755 })),
        (b"directory/file", value(b"data")),
    ]);

    for old_owner in ["private:ancestor", "tenant:ancestor"] {
        let mut domains = OperationDomains::new();
        bind(&mut domains, source.root_identity(), old_owner);

        let split =
            algebra::split_with_domains(&source, b"directory", &Forest(vec![]), &domains).unwrap();
        let prepared =
            algebra::prepare_split_with_domains(&source, b"directory", &domains).unwrap();
        let prepared_split = prepared.materialize().unwrap();
        assert_eq!(label(&split), old_owner);
        assert_eq!(prepared_split.root_identity(), split.root_identity());
    }

    assert!(matches!(
        algebra::split(&source, b"directory", &Forest(vec![])),
        Err(Error::DomainContext(DomainError::Missing(_)))
    ));
}

#[test]
fn overlay_recipes_bind_effective_domain_and_require_verification() {
    let top = tree(&[(b"a", value(b"top"))]);
    let bottom = tree(&[(b"b", value(b"bottom"))]);
    let layers = [&top, &bottom];
    let overlay = Overlay::new(&layers);
    let mut domains = OperationDomains::new();
    bind(&mut domains, top.root_identity(), "private:owner");
    let mut other_domains = OperationDomains::new();
    bind(
        &mut other_domains,
        top.root_identity(),
        "private:other-owner",
    );

    let result = overlay
        .materialize_with_recipe_and_domains(&domains)
        .unwrap();
    let other = overlay
        .materialize_with_recipe_and_domains(&other_domains)
        .unwrap();
    assert_eq!(label(&result.tree), "private:owner");
    assert_ne!(result.recipe, other.recipe);
    assert_ne!(result.tree.root_identity(), other.tree.root_identity());

    let decoded = Recipe::decode(&result.recipe).unwrap();
    let Recipe::OverlayWithDomains {
        domains: evidence, ..
    } = decoded.as_recipe()
    else {
        panic!("expected ownership evidence");
    };
    assert!(matches!(
        overlay.materialize_with_domains(evidence),
        Err(Error::DomainContext(DomainError::Unverified))
    ));
    assert!(decoded.clone().bind_domains(&other_domains).is_err());
    let rebound = decoded.bind_domains(&domains).unwrap();
    let Recipe::OverlayWithDomains {
        domains: verified, ..
    } = rebound.as_recipe()
    else {
        panic!("expected rebound evidence");
    };
    assert_eq!(
        overlay
            .materialize_with_domains(verified)
            .unwrap()
            .root_identity(),
        result.tree.root_identity()
    );
    assert!(matches!(
        overlay.materialize(),
        Err(Error::DomainContext(DomainError::Missing(_)))
    ));
}

#[test]
fn merge_preserves_effective_ownership_at_each_changed_graft_root() {
    let base_target = tree(&[(b"a", value(b"base")), (b"b", value(b"base"))]);
    let our_target = tree(&[(b"a", value(b"ours")), (b"b", value(b"base"))]);
    let their_target = tree(&[(b"a", value(b"base")), (b"b", value(b"theirs"))]);
    let base = tree(&[(b"mount", graft_entry(&base_target))]);
    let ours = tree(&[(b"mount", graft_entry(&our_target))]);
    let theirs = tree(&[(b"mount", graft_entry(&their_target))]);
    let mut domains = OperationDomains::new();
    bind(&mut domains, ours.root_identity(), "private:outer-owner");
    bind(
        &mut domains,
        our_target.root_identity(),
        "private:inner-owner",
    );
    let roots = Forest(vec![base_target, our_target, their_target]);

    let mut only_outer = OperationDomains::new();
    bind(&mut only_outer, ours.root_identity(), "private:outer-owner");
    assert!(matches!(
        algebra::merge_with_domains(
            &base,
            &ours,
            &theirs,
            &[MergePolicy::KeepConflict],
            &TrustContext::any(),
            &roots,
            &only_outer
        ),
        Err(Error::DomainContext(DomainError::Missing(_)))
    ));

    let result = algebra::merge_with_domains(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::KeepConflict],
        &TrustContext::any(),
        &roots,
        &domains,
    )
    .unwrap();
    assert_eq!(label(&result.tree), "private:outer-owner");
    assert_eq!(result.derived_roots.len(), 1);
    assert_eq!(label(&result.derived_roots[0]), "private:inner-owner");
    assert_eq!(result.derived_roots[0].get(b"a"), Some(&value(b"ours")));
    assert_eq!(result.derived_roots[0].get(b"b"), Some(&value(b"theirs")));

    let decoded = Recipe::decode(&result.recipe).unwrap();
    assert_eq!(decoded.as_recipe().encode(), result.recipe);
    assert!(decoded.bind_domains(&domains).is_ok());
    assert!(matches!(
        algebra::merge(
            &base,
            &ours,
            &theirs,
            &[MergePolicy::KeepConflict],
            &TrustContext::any(),
            &roots
        ),
        Err(Error::DomainContext(DomainError::Missing(_)))
    ));
}

#[test]
fn flatten_preserves_resolved_parent_private_owner() {
    let target = tree(&[(b"file", value(b"data"))]);
    let parent = tree(&[(b"mount", graft_entry(&target))]);
    let roots = Forest(vec![target]);
    let effective = properties::resolve(
        &[],
        Defaults {
            store: "authority",
            private_domain: "private:ancestor",
            home: "local",
        },
    )
    .unwrap();

    let prepared = algebra::flatten(&parent, b"mount", &roots, &effective, &effective).unwrap();
    let result = prepared.materialize(&parent).unwrap();
    assert_eq!(label(&result), "private:ancestor");
    assert_eq!(result.get(b"mount/file"), Some(&value(b"data")));
}

#[test]
fn merge_fast_forward_preserves_unchanged_root_without_domain_reencoding() {
    let base = tree(&[(b"a", value(b"base"))]);
    let theirs = tree(&[(b"a", value(b"changed"))]);
    let result = algebra::merge(
        &base,
        &base,
        &theirs,
        &[],
        &TrustContext::any(),
        &Forest(vec![]),
    )
    .unwrap();

    assert_eq!(result.tree.root_identity(), theirs.root_identity());
    assert_eq!(result.tree.props(), None);
    assert!(result.fast_forward);
    assert_eq!(result.expanded_nodes, 0);
}

#[test]
fn conflicting_effective_bindings_are_rejected() {
    let root = tree(&[]).root_identity();
    let mut domains = OperationDomains::new();
    bind(&mut domains, root, "private:owner");
    let other = properties::resolve(
        &[],
        Defaults {
            store: "authority",
            private_domain: "private:other",
            home: "local",
        },
    )
    .unwrap();

    assert_eq!(
        domains.bind_resolved(root, &other),
        Err(DomainError::Ambiguous(root))
    );
}

#[test]
fn graft_retains_graft_override_owner_instead_of_raw_root_domain() {
    let raw_domain = b"\x71private:raw-owner";
    let source = tree(&[])
        .with_properties(Some(vec![Property {
            name: "domain",
            value: raw_domain,
        }]))
        .unwrap()
        .tree;
    let target = tree(&[(b"file", value(b"data"))]);
    let roots = Forest(vec![target.clone()]);
    let mut domains = OperationDomains::new();
    bind(
        &mut domains,
        source.root_identity(),
        "private:mounted-owner",
    );

    let result = algebra::graft_with_domains(
        &source,
        b"mount",
        graft_entry(&target),
        false,
        &roots,
        &domains,
    )
    .unwrap();

    assert_eq!(label(&result), "private:mounted-owner");
    assert_eq!(label(&source), "private:raw-owner");
}

#[test]
fn fold_filters_preserve_the_source_owner_before_merging() {
    let base = tree(&[(b"retained", value(b"base"))]);
    let ours = tree(&[(b"retained", value(b"ours"))]);
    let theirs = tree(&[
        (b"excluded", value(b"private")),
        (b"retained", value(b"base")),
    ]);
    let mut domains = OperationDomains::new();
    bind(&mut domains, ours.root_identity(), "private:destination");
    bind(&mut domains, theirs.root_identity(), "private:incoming");

    let result = algebra::fold_with_domains(
        &base,
        &ours,
        &theirs,
        [[1; 32], [2; 32]],
        &[MergePolicy::KeepConflict],
        &TrustContext::any(),
        &Forest(vec![]),
        |path, _| path != b"excluded",
        algebra::Retirement::Delete,
        &domains,
    )
    .unwrap();

    assert_eq!(result.excluded, vec![b"excluded".to_vec()]);
    assert!(result.merged.tree.get(b"excluded").is_none());
    assert_eq!(
        label(result.merged.derived_roots.last().unwrap()),
        "private:incoming"
    );
    assert!(matches!(
        algebra::fold(
            &base,
            &ours,
            &theirs,
            [[1; 32], [2; 32]],
            &[],
            &TrustContext::any(),
            &Forest(vec![]),
            |path, _| path != b"excluded",
            algebra::Retirement::Delete
        ),
        Err(Error::DomainContext(DomainError::Missing(_)))
    ));
}
