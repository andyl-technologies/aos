//! Compares published recipe bytes with separately constructed public models.
//!
//! These tests exercise field encoding only. Inert trust and decoded domain
//! records do not supply verified views or authorize tree materialization.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "independent reference fixtures must match the constructed test models"
)]

use terrane_core::algebra::{MergePolicy, OperationDomains, Recipe, TrustContext};
use terrane_core::tree_format::{Entry, EntryKind, encode_entry};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));
const ROOTS: [[u8; 32]; 3] = [[1; 32], [2; 32], [3; 32]];

fn hexadecimal(name: &str, block: usize) -> Vec<u8> {
    let marker = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1);
    let section = REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n##")
        .next()
        .unwrap();
    let raw = section
        .split("```hex\n")
        .nth(block + 1)
        .unwrap()
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = raw
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);

    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn compare(name: &str, model: &Recipe<'_>) -> terrane_core::algebra::OwnedRecipe {
    let expected_wire = hexadecimal(name, 0);
    let expected_hash: [u8; 32] = hexadecimal(name, 1).try_into().unwrap();

    assert_eq!(model.encode(), expected_wire, "{name}");
    assert_eq!(model.identity().unwrap(), expected_hash, "{name}");
    let decoded = Recipe::decode(&expected_wire).unwrap();
    assert_eq!(decoded.as_recipe().encode(), expected_wire, "{name}");
    assert_eq!(
        decoded.as_recipe().identity().unwrap(),
        expected_hash,
        "{name}"
    );

    decoded
}

#[test]
fn published_overlay_models_preserve_order_and_optional_domain_presence() {
    let ordered = [ROOTS[2], ROOTS[0], ROOTS[1]];
    for (name, roots) in [
        ("recipe-overlay-empty", &[][..]),
        ("recipe-overlay-ordered", &ordered[..]),
    ] {
        let model = Recipe::Overlay(roots);
        let decoded = compare(name, &model);
        assert_eq!(decoded.as_recipe(), model);
    }

    let domains = OperationDomains::new();
    let model = Recipe::OverlayWithDomains {
        roots: &ROOTS,
        domains: &domains,
    };
    let decoded = compare("recipe-overlay-empty-domains", &model);
    let Recipe::OverlayWithDomains { roots, .. } = decoded.as_recipe() else {
        panic!("present empty domain argument must retain its recipe variant");
    };
    assert_eq!(roots, ROOTS);
}

#[test]
fn published_graft_models_preserve_complete_entry_replacement_and_arguments() {
    let entry = Entry {
        kind: EntryKind::Tree {
            root: ROOTS[1],
            props: None,
        },
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    };
    let entry_wire = encode_entry(&entry, 262_144).unwrap();
    let domains = OperationDomains::new();
    for (replace, label) in [(false, "preserve"), (true, "replace")] {
        for recorded_domains in [None, Some(&domains)] {
            let suffix = if recorded_domains.is_some() {
                "-empty-domains"
            } else {
                ""
            };
            let name = format!("recipe-graft-{label}{suffix}");
            let model = Recipe::Graft {
                parent: ROOTS[0],
                target: ROOTS[1],
                at: b"subtree",
                entry: &entry_wire,
                replace,
                domains: recorded_domains,
            };
            let decoded = compare(&name, &model);
            let Recipe::Graft {
                parent,
                target,
                at,
                entry: decoded_entry,
                replace: decoded_replace,
                domains: decoded_domains,
            } = decoded.as_recipe()
            else {
                panic!("graft input must decode to a graft model");
            };

            assert_eq!((parent, target, at), (ROOTS[0], ROOTS[1], &b"subtree"[..]));
            assert_eq!(decoded_entry, entry_wire);
            assert_eq!(decoded_replace, replace);
            assert_eq!(decoded_domains.is_some(), recorded_domains.is_some());
        }
    }
}

#[test]
fn published_merge_models_preserve_operand_policy_and_inert_trust_fields() {
    let inert = TrustContext::any();
    let domains = OperationDomains::new();
    let all = [
        MergePolicy::PreferOurs,
        MergePolicy::PreferTheirs,
        MergePolicy::PreferTrusted,
        MergePolicy::PreferNewer,
        MergePolicy::KeepConflict,
        MergePolicy::Error,
    ];
    let ordered = [all[1], all[0], all[4], all[5]];
    for (name, policies, recorded_domains) in [
        ("empty-policy", &[][..], None),
        ("ordered-policy", &ordered[..], None),
        ("empty-domains", &all[4..5], Some(&domains)),
        ("inert-trust", &all[..], None),
        ("inert-trust-empty-domains", &all[..], Some(&domains)),
    ] {
        let model = Recipe::Merge {
            base: ROOTS[0],
            ours: ROOTS[1],
            theirs: ROOTS[2],
            policies,
            trust: &inert,
            domains: recorded_domains,
        };
        let decoded = compare(&format!("recipe-merge-{name}"), &model);
        let Recipe::Merge {
            base,
            ours,
            theirs,
            policies: decoded_policies,
            trust,
            domains: decoded_domains,
        } = decoded.as_recipe()
        else {
            panic!("merge input must decode to a merge model");
        };

        assert_eq!([base, ours, theirs], ROOTS);
        assert_eq!(decoded_policies, policies);
        assert_eq!(trust, &inert);
        assert_eq!(decoded_domains.is_some(), recorded_domains.is_some());
    }
}

#[test]
fn published_negative_recipe_wires_require_structural_rejection() {
    for name in [
        "recipe-unknown-operation",
        "recipe-graft-target-mismatch",
        "recipe-graft-missing-entry",
        "recipe-merge-wrong-arity",
        "recipe-merge-missing-trust",
    ] {
        assert!(Recipe::decode(&hexadecimal(name, 0)).is_err(), "{name}");
    }
}
