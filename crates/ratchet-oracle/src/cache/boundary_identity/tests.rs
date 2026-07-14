//! Tests for the MEMO-2 source-Merkle boundary-identity map.
//!
//! The unit tests drive the pure DAG fold ([`fold_identities`]) on synthetic
//! package facts so the soundness and decline behaviour is exercised without the
//! parser; the integration test builds the map against the real package set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use super::*;

/// Builds a synthetic facts map. Each entry is
/// `(name, fingerprint_seed, &[(formal_name, has_default)])`; the fingerprint is
/// `[seed; 32]` so tests can perturb one package's source deterministically.
fn facts(entries: &[(&str, u8, &[(&str, bool)])]) -> BTreeMap<String, PackageFacts> {
    entries
        .iter()
        .map(|(name, seed, formals)| {
            (
                (*name).to_string(),
                PackageFacts {
                    fingerprint: [*seed; 32],
                    formals: formals
                        .iter()
                        .map(|(fname, has_default)| Formal {
                            name: (*fname).to_string(),
                            has_default: *has_default,
                        })
                        .collect(),
                },
            )
        })
        .collect()
}

/// Folds a synthetic facts map with a framework set of exactly `mkDerivation`.
fn fold(
    facts: &BTreeMap<String, PackageFacts>,
    framework_identity: &[u8; 32],
) -> BoundaryIdentityMap {
    let packages: BTreeSet<String> = facts.keys().cloned().collect();
    let framework: BTreeSet<&str> = ["mkDerivation"].into_iter().collect();
    let overrides: BTreeSet<&str> = BTreeSet::new();
    let classifier = FormalClassifier {
        packages: &packages,
        framework: &framework,
        overrides: &overrides,
    };
    fold_identities(facts, &classifier, framework_identity)
}

/// A dependency-source edit flips the dependent's identity, while a package
/// outside the reverse-dependency cone is unchanged.
#[test]
fn dependency_edit_flips_dependent_but_not_unrelated() {
    let base = facts(&[
        ("leaf", 1, &[("mkDerivation", false)]),
        ("mid", 2, &[("mkDerivation", false), ("leaf", false)]),
        ("unrelated", 3, &[("mkDerivation", false)]),
    ]);
    let fw = [9u8; 32];
    let before = fold(&base, &fw);

    // Perturb only `leaf`'s source fingerprint.
    let mut edited = base.clone();
    edited.get_mut("leaf").expect("leaf present").fingerprint = [42u8; 32];
    let after = fold(&edited, &fw);

    assert_ne!(
        before.identity("leaf"),
        after.identity("leaf"),
        "editing leaf changes its own identity"
    );
    assert_ne!(
        before.identity("mid"),
        after.identity("mid"),
        "editing a dependency flips the dependent's identity"
    );
    assert_eq!(
        before.identity("unrelated"),
        after.identity("unrelated"),
        "a package outside the reverse-dependency cone is unchanged"
    );
}

/// A framework-source edit (frameworkIdentity change) flips every boundary key.
#[test]
fn framework_edit_invalidates_the_whole_set() {
    let graph = facts(&[
        ("leaf", 1, &[("mkDerivation", false)]),
        ("mid", 2, &[("mkDerivation", false), ("leaf", false)]),
    ]);
    let before = fold(&graph, &[9u8; 32]);
    let after = fold(&graph, &[10u8; 32]);
    for name in ["leaf", "mid"] {
        assert_ne!(
            before.identity(name),
            after.identity(name),
            "a framework edit flips every boundary ({name})"
        );
    }
}

/// An unresolved formal with no default declines the boundary, and the decline
/// propagates to every dependent; an unresolved formal WITH a default does not
/// decline (it is covered by the file fingerprint).
#[test]
fn decline_propagates_but_defaulted_formal_does_not_decline() {
    let graph = facts(&[
        // `bad` takes an unknown formal with no default → declines.
        ("bad", 1, &[("mkDerivation", false), ("mystery", false)]),
        // `needs_bad` depends on `bad` → declines transitively.
        ("needs_bad", 2, &[("mkDerivation", false), ("bad", false)]),
        // `ok` takes an unknown formal WITH a default → keyable.
        ("ok", 3, &[("mkDerivation", false), ("extraConfig", true)]),
    ]);
    let map = fold(&graph, &[9u8; 32]);

    assert!(map.is_declined("bad"), "no-default unknown formal declines");
    assert!(
        map.is_declined("needs_bad"),
        "decline propagates to dependents"
    );
    assert!(map.identity("bad").is_none());
    assert!(map.identity("needs_bad").is_none());
    assert!(
        map.identity("ok").is_some(),
        "an unknown formal with a default is covered by the fingerprint, not a decline"
    );
}

/// The fold is deterministic and independent of formal declaration order.
#[test]
fn identity_is_order_independent_and_deterministic() {
    let a = facts(&[
        ("leaf", 1, &[("mkDerivation", false)]),
        ("mid", 2, &[("leaf", false), ("mkDerivation", false)]),
    ]);
    let b = facts(&[
        ("leaf", 1, &[("mkDerivation", false)]),
        // Same formals, reversed order.
        ("mid", 2, &[("mkDerivation", false), ("leaf", false)]),
    ]);
    let fw = [7u8; 32];
    assert_eq!(
        fold(&a, &fw).identity("mid"),
        fold(&b, &fw).identity("mid"),
        "formal order does not affect the identity"
    );
}

/// Locates the repository root from this crate's manifest directory, or `None`
/// when the expected package set is not present (e.g. an isolated build tree).
fn repo_pkgs_root() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .to_path_buf();
    let pkgs = root.join("pkgs");
    pkgs.is_dir().then_some(root)
}

/// The map builds against the real package set: nearly every package keys, the
/// framework identity is non-trivial, and the build is deterministic.
#[test]
fn builds_against_the_real_package_set() {
    let Some(root) = repo_pkgs_root() else {
        // Not in a repo checkout (isolated build tree); nothing to build against.
        return;
    };
    let cache_root =
        std::env::temp_dir().join(format!("aos-nix-memo2-boundary-{}", std::process::id()));
    let config = BoundaryIdentityConfig {
        pkgs_root: root.join("pkgs"),
        framework_roots: vec![
            root.join("lib"),
            root.join("stdenv"),
            root.join("pkgs/build-support"),
        ],
        parse_cache_root: cache_root,
    };
    let map = build_boundary_identity_map(&config).expect("map builds");
    eprintln!(
        "boundary_identity real-set: keyed={} declined={}",
        map.keyed_len(),
        map.declined_len()
    );

    assert!(
        map.keyed_len() >= 200,
        "most of the ~265 package files key (got {})",
        map.keyed_len()
    );
    assert!(
        map.declined_len() <= 10,
        "declines are rare (got {})",
        map.declined_len()
    );
    assert_ne!(
        map.framework_identity(),
        [0u8; 32],
        "framework identity is computed from real source"
    );

    // Deterministic: a second build yields identical identities.
    let again = build_boundary_identity_map(&config).expect("map rebuilds");
    let first: Vec<_> = map.iter().map(|(n, id)| (n.to_string(), id)).collect();
    let second: Vec<_> = again.iter().map(|(n, id)| (n.to_string(), id)).collect();
    assert_eq!(first, second, "identity build is deterministic");
}
