//! Checks multikey random merges against map policy facts and signed histories.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::{Entry, EntryKind, Map, assert_map, build, entry, model, symlink};
use crate::algebra::signed_fixture::{SignedSide, signed_history};
use crate::algebra::tests::{Forest, untrusted};
use crate::algebra::{self, Error, MergePolicy, TrustContext};
use crate::provenance::{Preset, Selector};

fn sample(state: &mut u64) -> Option<Entry<'static>> {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    match (*state >> 32) % 5 {
        0 => None,
        1 => Some(symlink(b"one")),
        2 => Some(symlink(b"two")),
        3 => Some(symlink(b"three")),
        _ => Some(symlink(b"four")),
    }
}

fn put(map: &mut Map<'static>, key: &[u8], value: Option<Entry<'static>>) {
    match value {
        Some(value) => {
            map.insert(key.to_vec(), value);
        }
        None => {
            map.remove(key);
        }
    }
}

fn inputs(state: &mut u64) -> [Map<'static>; 3] {
    let mut maps = [Map::new(), Map::new(), Map::new()];
    for number in 0..48 {
        let key = alloc::format!("key-{number:03}").into_bytes();
        let base = sample(state);
        // Preserve unilateral edits as well as overlapping independent changes.
        let ours = if number % 4 == 0 {
            base.clone()
        } else {
            sample(state)
        };
        let theirs = if number % 4 == 1 {
            base.clone()
        } else {
            sample(state)
        };
        for (map, value) in maps.iter_mut().zip([base, ours, theirs]) {
            put(map, &key, value);
        }
    }

    // Each round requires these semantic categories, independent of random draws.
    let fixed = [
        (
            b"forced-conflict".as_slice(),
            [
                Some(symlink(b"base")),
                Some(symlink(b"ours")),
                Some(symlink(b"theirs")),
            ],
        ),
        (
            b"forced-delete",
            [Some(symlink(b"base")), None, Some(symlink(b"theirs"))],
        ),
        (
            b"forced-add",
            [None, Some(symlink(b"ours")), Some(symlink(b"theirs"))],
        ),
        (
            b"forced-ours",
            [
                Some(symlink(b"base")),
                Some(symlink(b"ours")),
                Some(symlink(b"base")),
            ],
        ),
        (
            b"forced-theirs",
            [
                Some(symlink(b"base")),
                Some(symlink(b"base")),
                Some(symlink(b"theirs")),
            ],
        ),
        (
            b"forced-agree",
            [
                Some(symlink(b"base")),
                Some(symlink(b"same")),
                Some(symlink(b"same")),
            ],
        ),
        (b"forced-both-delete", [Some(symlink(b"base")), None, None]),
        (
            b"forced-their-delete",
            [Some(symlink(b"base")), Some(symlink(b"ours")), None],
        ),
    ];
    for (key, values) in fixed {
        for (map, value) in maps.iter_mut().zip(values) {
            put(map, key, value);
        }
    }
    maps
}

/// Compares every current policy and symmetric policy ordering on complete maps.
///
/// # Panics
/// Panics if signed fixtures fail verification or a merge differs from the model.
pub(in crate::algebra::tests) fn randomized_merge_witness() {
    whiteouts_and_prior_conflicts();

    let mut state = 0x74657272616e65;
    let policy_cases = [
        vec![],
        vec![MergePolicy::KeepConflict],
        vec![MergePolicy::PreferOurs],
        vec![MergePolicy::PreferTheirs],
        vec![MergePolicy::Error],
        vec![MergePolicy::PreferTrusted, MergePolicy::KeepConflict],
        vec![MergePolicy::PreferTrusted, MergePolicy::PreferOurs],
        vec![MergePolicy::PreferNewer, MergePolicy::KeepConflict],
        vec![MergePolicy::PreferNewer, MergePolicy::PreferTheirs],
        vec![
            MergePolicy::PreferTrusted,
            MergePolicy::PreferNewer,
            MergePolicy::KeepConflict,
        ],
        vec![MergePolicy::KeepConflict, MergePolicy::Error],
        vec![MergePolicy::PreferTrusted, MergePolicy::Error],
    ];
    for round in 0..24 {
        let maps = inputs(&mut state);
        let trees = maps.each_ref().map(build);
        let evidence = model::Evidence {
            baseline: match round % 4 {
                0 => [true, false],
                1 => [false, true],
                2 => [true, true],
                _ => [false, false],
            },
            timestamps: match round % 3 {
                0 => [100, 150],
                1 => [150, 100],
                _ => [100, 100],
            },
        };
        let (history, views) = signed_history(
            [
                SignedSide {
                    tree: &trees[1],
                    child: None,
                    baseline: evidence.baseline[0],
                    time: evidence.timestamps[0],
                },
                SignedSide {
                    tree: &trees[2],
                    child: None,
                    baseline: evidence.baseline[1],
                    time: evidence.timestamps[1],
                },
            ],
            "private:fixture",
        );
        let evaluators = views.map(|view| {
            crate::provenance::TrustContext::new(
                &history,
                view,
                Selector::preset(Preset::Strict),
                "private:fixture",
                Some("baseline"),
            )
            .unwrap()
        });
        let trust = TrustContext::from_verified(evaluators.to_vec()).unwrap();
        let reversed_trust =
            TrustContext::from_verified(vec![evaluators[1].clone(), evaluators[0].clone()])
                .unwrap();
        let reversed_evidence = model::Evidence {
            baseline: [evidence.baseline[1], evidence.baseline[0]],
            timestamps: [evidence.timestamps[1], evidence.timestamps[0]],
        };
        let roots = Forest(vec![]);

        for policies in &policy_cases {
            let expected = model::merge(&maps[0], &maps[1], &maps[2], policies, evidence);
            let actual = algebra::merge(&trees[0], &trees[1], &trees[2], policies, &trust, &roots);
            match (&expected, actual) {
                (Err(()), Err(Error::Conflict)) => {}
                (Ok(expected), Ok(actual)) => {
                    assert_map(&actual.tree, expected);
                    assert_eq!(
                        actual.conflicted,
                        expected
                            .values()
                            .any(|value| matches!(value.kind, EntryKind::Conflict { .. }))
                    );
                }
                (expected, actual) => panic!(
                    "round {round}, policies {policies:?}: expected {expected:?}, observed {actual:?}"
                ),
            }

            if policies
                .iter()
                .any(|policy| matches!(policy, MergePolicy::PreferOurs | MergePolicy::PreferTheirs))
            {
                continue;
            }
            let reversed_expected =
                model::merge(&maps[0], &maps[2], &maps[1], policies, reversed_evidence);
            let reversed = algebra::merge(
                &trees[0],
                &trees[2],
                &trees[1],
                policies,
                &reversed_trust,
                &roots,
            );
            match (&expected, reversed_expected, reversed) {
                (Err(()), Err(()), Err(Error::Conflict)) => {}
                (Ok(expected), Ok(reversed_expected), Ok(reversed)) => {
                    assert_map(&reversed.tree, &reversed_expected);
                    assert_eq!(
                        symmetric_values(expected),
                        symmetric_values(&reversed_expected)
                    );
                }
                (expected, reversed_expected, reversed) => panic!(
                    "round {round}, reversed {policies:?}: {expected:?}, {reversed_expected:?}, {reversed:?}"
                ),
            }
        }
    }
}

// Keep side order in exact model equality; ignore only that order for symmetry.
#[derive(Debug, Eq, PartialEq)]
struct SymmetricValue {
    candidates: Vec<Vec<u8>>,
    base: Option<Vec<u8>>,
}

fn symmetric_values(map: &Map<'static>) -> BTreeMap<Vec<u8>, SymmetricValue> {
    map.iter()
        .map(|(key, value)| {
            let encode = |entry| crate::tree_format::encode_entry(entry, 4096).unwrap();
            let normalized = match &value.kind {
                EntryKind::Conflict { candidates, base } => {
                    let mut candidates: Vec<_> = candidates.iter().map(encode).collect();
                    candidates.sort();
                    SymmetricValue {
                        candidates,
                        base: base
                            .as_ref()
                            .and_then(|base| base.as_ref().map(|base| encode(base))),
                    }
                }
                _ => SymmetricValue {
                    candidates: vec![encode(value)],
                    base: None,
                },
            };
            (key.clone(), normalized)
        })
        .collect()
}

fn whiteouts_and_prior_conflicts() {
    let prior = entry(EntryKind::Conflict {
        candidates: vec![symlink(b"prior-ours"), entry(EntryKind::Whiteout)],
        base: Some(None),
    });
    let base = super::map(&[(b"deleted", symlink(b"base")), (b"prior", symlink(b"base"))]);
    let ours = super::map(&[(b"deleted", entry(EntryKind::Whiteout)), (b"prior", prior)]);
    let theirs = super::map(&[
        (b"deleted", symlink(b"changed")),
        (b"prior", symlink(b"changed")),
    ]);
    let trees = [build(&base), build(&ours), build(&theirs)];
    let evidence = model::Evidence {
        baseline: [false; 2],
        timestamps: [0; 2],
    };

    // Overlay whiteouts are legitimate merge values but cannot be signed as
    // ordinary immutable views by this fixture's provenance insertion path.
    for policies in [
        vec![],
        vec![MergePolicy::KeepConflict],
        vec![MergePolicy::PreferOurs],
        vec![MergePolicy::PreferTheirs],
        vec![MergePolicy::Error],
    ] {
        let expected = model::merge(&base, &ours, &theirs, &policies, evidence);
        let actual = algebra::merge(
            &trees[0],
            &trees[1],
            &trees[2],
            &policies,
            &untrusted(),
            &Forest(vec![]),
        );
        match (expected, actual) {
            (Ok(expected), Ok(actual)) => assert_map(&actual.tree, &expected),
            (Err(()), Err(Error::Conflict)) => {}
            (expected, actual) => {
                panic!("whiteout/prior-conflict policies {policies:?}: {expected:?}, {actual:?}")
            }
        }
    }
}
