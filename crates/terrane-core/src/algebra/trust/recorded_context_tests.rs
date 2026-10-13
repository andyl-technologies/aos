//! Binds ordinary explicit interpretations into complete recipe models.
#![allow(clippy::unwrap_used)]
// Private fixture modules share one immutable independent primitive model.
#[allow(clippy::duplicate_mod)]
#[path = "../../provenance/trust/encoding/recorded_models.rs"]
mod models;
use super::*;
use crate::algebra::{MergePolicy, Recipe};
use alloc::{string::String, vec};
use models::*;

fn map(fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut result = head(5, fields.len() as u64);
    for (key, value) in fields {
        result.extend_from_slice(key);
        result.extend_from_slice(value);
    }
    result
}

#[test]
fn trusted_recorded_context_recipe_keys_bind_complete_interpretations() {
    let selector = array(&[text("preset"), text("any")]);
    let roots = [[6; 32], [7; 32], [8; 32]];
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    let mut keys = Vec::new();
    for case in 0..11 {
        let revision = match case {
            9 => 2,
            10 => 3,
            _ => 1,
        };
        let selected = evidence(1, "private:test", "uid", "uid");
        let mut ours = context(
            revision,
            &vocabulary(revision),
            &[if case == 7 {
                "future.other"
            } else {
                "future.value"
            }],
            if case == 8 {
                Some(selected.as_slice())
            } else {
                None
            },
        );
        // The last root field is the independently supplied original namespace
        // association; selected nested evidence retains its own location root.
        let root_field = bytes(&[2; 32]);
        let offset = ours
            .windows(root_field.len())
            .rposition(|w| w == root_field)
            .unwrap();
        ours.splice(offset..offset + root_field.len(), bytes(&roots[1]));
        // Each common-field variant changes exactly one input of the fixed base.
        // Separate revision variants carry only the required vocabulary additions.
        let replacement = match case {
            1 => Some((bytes(&[1; 32]), bytes(&[10; 32]))),
            // This is a syntax-valid claim control; only external view evidence
            // can reject its association with a different physical operand.
            2 => Some((bytes(&roots[1]), bytes(&[11; 32]))),
            3 => Some((text("private:test"), text("private:other"))),
            4 => Some((
                bytes(&array(&[text("preset"), text("any")])),
                bytes(&array(&[text("preset"), text("strict")])),
            )),
            5 => Some((text(""), vec![0xf6])),
            6 => Some((uint(262144), uint(524288))),
            _ => None,
        };
        if let Some((before, after)) = replacement {
            let offset = ours
                .windows(before.len())
                .position(|window| window == before)
                .unwrap();
            ours.splice(offset..offset + before.len(), after);
        }
        crate::provenance::validate_canonical_context(&ours).unwrap();
        let mut theirs = context(2, &vocabulary(2), &["index-gaps"], None);
        for (before, after) in [
            (bytes(&[1; 32]), bytes(&[3; 32])),
            (bytes(&[2; 32]), bytes(&roots[2])),
        ] {
            let offset = theirs
                .windows(before.len())
                .position(|w| w == before)
                .unwrap();
            theirs.splice(offset..offset + before.len(), after);
        }
        for (folded, fold) in [
            vec![0xf6],
            array(&[
                bytes(&roots[0]),
                bytes(&roots[2]),
                bytes(&[9; 32]),
                array(&[bytes(b"excluded")]),
                text("private:incoming"),
            ]),
        ]
        .into_iter()
        .enumerate()
        {
            let incoming = if folded == 0 { roots[2] } else { [9; 32] };
            let operands = [roots[0], roots[1], incoming];
            // Fold replaces only the incoming operand; its recorded original
            // root remains eight in the unchanged complete context above.
            let configuration = array(&[array(&[bytes(&ours), bytes(&theirs)]), fold]);
            let trust = TrustContext {
                selector: selector.clone(),
                evaluator_version: String::from("terrane-verified-path/v1"),
                configuration: configuration.clone(),
                accepted: Vec::new(),
                any: false,
                timestamps: Vec::new(),
                evaluators: Vec::new(),
                authenticated: false,
                filter: None,
            };
            let recipe = Recipe::Merge {
                base: roots[0],
                ours: roots[1],
                theirs: incoming,
                policies: &policies,
                trust: &trust,
                domains: None,
            };
            let expected_trust = map(&[
                (uint(1), selector.clone()),
                (uint(2), text("terrane-verified-path/v1")),
                (uint(3), configuration.clone()),
                (uint(4), array(&[])),
            ]);
            let expected = map(&[
                (uint(1), text("merge")),
                (
                    uint(2),
                    array(&operands.iter().map(|r| bytes(r)).collect::<Vec<_>>()),
                ),
                (
                    uint(3),
                    map(&[
                        (text("trust"), expected_trust),
                        (
                            text("policy"),
                            array(&[text("prefer-trusted"), text("keep-conflict")]),
                        ),
                    ]),
                ),
            ]);
            assert_eq!(recipe.encode(), expected);
            let decoded = Recipe::decode(&expected).unwrap();
            assert_eq!(decoded.as_recipe(), recipe);
            let mut preimage = b"terrane-memo-v1\0".to_vec();
            preimage.extend_from_slice(&expected);
            let key = recipe.identity().unwrap();
            assert_eq!(key, *blake3::hash(&preimage).as_bytes());
            assert!(!keys.contains(&key));
            keys.push(key);
        }
    }
}
