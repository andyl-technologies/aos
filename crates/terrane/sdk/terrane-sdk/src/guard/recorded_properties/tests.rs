//! Checks installed interpretation data and genuinely verified evaluator inputs.
//!
//! The supplied associations are independent fixture configuration. Signing and
//! verification establish history; configuration does not manufacture authority.

#![allow(
    clippy::expect_used,
    reason = "independent test fixtures must validate"
)]

use super::*;
#[cfg(feature = "std")]
use crate::guard::{Guard, GuardConfig};
#[cfg(feature = "std")]
use terrane_format::{
    auth::{self, Authority, Grant, IssuerKey, Request, Token, Verb, Verbs},
    identity::{IdentityKind, TERRANE_V1},
    provenance::{Preset, sign, verify},
    refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance},
};
use terrane_format::{
    properties::{PropertyName, Value, semantics::RecordedContext},
    tree_format::Property,
};

// This adapter is only an assertion facade over the owning Native table. It
// stores no associations and cannot construct protected Original/completion.
#[cfg(feature = "std")]
struct PropertyTestInterpretations<'a, S, C>(&'a Guard<S, C>);

#[cfg(feature = "std")]
impl<S, C> Guard<S, C> {
    fn property_test_interpretations(&self) -> PropertyTestInterpretations<'_, S, C> {
        PropertyTestInterpretations(self)
    }
}

#[cfg(feature = "std")]
impl<S, C> PropertyTestInterpretations<'_, S, C> {
    fn select(
        &self,
        view: Digest,
        root: Digest,
    ) -> Result<SelectedReadInterpretation, StoreFailure> {
        self.0
            .select_view(view, root, crate::guard::HistoryObservation::default())
    }

    fn check_retained(
        &self,
        retained: &SelectedReadInterpretation,
        view: Digest,
        root: Digest,
    ) -> Result<(), StoreFailure> {
        if &self.select(view, root)? != retained {
            return Err(crate::guard::invalid());
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
const MINIMUM: u64 = 262144;

// Fixed historical vocabulary, independently enumerated rather than ALL.
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

fn association(view: Digest, root: Digest, revision: u64, later: &[&str]) -> RecordedAssociation {
    RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(revision, 3, later).expect("independent registered context"),
    )
}

#[cfg(feature = "std")]
fn config() -> GuardConfig {
    GuardConfig {
        store_name: "ordinary-store".to_owned(),
        private_domain: "private:ordinary".to_owned(),
        home: Locality::default(),
        initial_acl: Vec::new(),
        min_chunk_size: MINIMUM,
        storage_domain: "public".to_owned(),
        chunk_profile_name: "cdc-1m".to_owned(),
        chunk_profile: Box::new(terrane_format::chunking::ChunkProfile::cdc_1m([0; 32])),
        policy_authority: None,
    }
}

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "ordinary-store",
        private_domain: "private:ordinary",
        home: "local",
    }
}

#[cfg(feature = "std")]
#[test]
fn explicit_read_configuration_refuses_missing_view_root_and_mode_mismatches() {
    let view = [1; 32];
    let root = [7; 32];
    let table = {
        let owned = [String::from("é.future"), String::from("index-roots")];
        let names: Vec<_> = owned.iter().map(String::as_str).collect();
        RecordedAssociations::new([
            association(view, root, 1, &names),
            association([2; 32], root, 3, &[]),
        ])
        .expect("different views may share physical roots")
    };
    let copied = table.clone();
    let guard = Guard::new_with_recorded_views((), (), Vec::new(), config(), table);
    let selected = guard
        .property_test_interpretations()
        .select(view, root)
        .expect("exact selection");
    let SelectedReadInterpretation::Recorded(entry) = &selected else {
        panic!("explicit mode")
    };
    assert_eq!(entry.view(), view);
    assert_eq!(entry.original_root(), root);
    assert_eq!(entry.revision(), 1);
    assert_eq!(entry.later_registered(), ["index-roots", "é.future"]);
    let retained = selected.clone();
    drop(selected);

    assert!(
        guard
            .property_test_interpretations()
            .select([9; 32], root)
            .is_err()
    );
    assert!(
        guard
            .property_test_interpretations()
            .select(view, [8; 32])
            .is_err()
    );
    let empty = Guard::new_with_recorded_views(
        (),
        (),
        Vec::new(),
        config(),
        RecordedAssociations::default(),
    );
    assert!(
        empty
            .property_test_interpretations()
            .select(view, root)
            .is_err()
    );
    let equivalent = Guard::new_with_recorded_views((), (), Vec::new(), config(), copied);
    equivalent
        .property_test_interpretations()
        .check_retained(&retained, view, root)
        .expect("equivalent independent installations agree");
    let legacy = Guard::new((), (), Vec::new(), config());
    assert!(
        legacy
            .property_test_interpretations()
            .check_retained(&retained, view, root)
            .is_err()
    );
    assert!(
        guard
            .property_test_interpretations()
            .check_retained(&SelectedReadInterpretation::Legacy, view, root,)
            .is_err()
    );
    let conflicting = ReadInterpretations::Recorded(Arc::new(
        RecordedAssociations::new([association(view, root, 2, &["é.future"])]).expect("table"),
    ));
    assert!(conflicting.check_retained(&retained, view, root).is_err());
    let different_names = ReadInterpretations::Recorded(Arc::new(
        RecordedAssociations::new([association(view, root, 1, &["index-roots"])])
            .expect("different preservation configuration"),
    ));
    assert!(
        different_names
            .check_retained(&retained, view, root)
            .is_err()
    );
    assert!(
        guard
            .property_test_interpretations()
            .check_retained(&retained, [2; 32], root)
            .is_err()
    );
    assert!(
        RecordedAssociations::new([
            association(view, root, 1, &["index-roots"]),
            association(view, root, 2, &[]),
        ])
        .is_err()
    );
    assert!(
        RecordedAssociations::new([
            association(view, root, 1, &["index-roots"]),
            association(view, [8; 32], 1, &["index-roots"]),
        ])
        .is_err()
    );
    assert!(
        RecordedAssociations::new([
            association(view, root, 1, &["index-roots"]),
            association(view, root, 1, &["index-gaps", "index-roots"]),
        ])
        .is_err()
    );
    for revision in [0, 4] {
        assert!(RecordedContext::new(revision, 3, &[]).is_err());
    }
    assert!(RecordedContext::new(1, 3, &["future", "future"]).is_err());
}

#[test]
fn retained_read_configuration_preserves_fixed_graft_interpretations() {
    // Scalars are canonical data, but deliberately invalid active pointer shapes.
    let inert = [
        Property {
            name: "index-gaps",
            value: &[0],
        },
        Property {
            name: "index-roots",
            value: &[0],
        },
    ];
    let original = inert;
    for revision in 1..=3 {
        let later: &[&str] = match revision {
            1 => &["index-gaps", "index-roots"],
            2 => &["index-gaps"],
            _ => &[],
        };
        let installed = ReadInterpretations::Recorded(Arc::new(
            RecordedAssociations::new([association(
                [revision as u8; 32],
                [7; 32],
                revision,
                later,
            )])
            .expect("explicit installation"),
        ));
        let selected = installed
            .select([revision as u8; 32], [7; 32])
            .expect("selected");
        let SelectedReadInterpretation::Recorded(entry) = &selected else {
            panic!("recorded")
        };
        entry
            .with_context(|context| {
                let mut expected = LEGACY_NAMES.to_vec();
                if revision >= 2 {
                    expected.push("index-roots");
                }
                if revision == 3 {
                    expected.push("index-gaps");
                }
                expected.sort_unstable();
                let mut actual: Vec<_> = context.behavioral_names().collect();
                actual.sort_unstable();
                assert_eq!(actual, expected);
            })
            .expect("retained names");
        let effective = selected.resolve(&[], defaults()).expect("fixed defaults");
        for name in LEGACY_NAMES {
            assert!(
                effective
                    .get(PropertyName::parse(name).expect("fixed name"))
                    .is_some()
            );
        }
        assert_eq!(
            effective.get(PropertyName::IndexRoots).is_some(),
            revision >= 2
        );
        assert!(effective.get(PropertyName::IndexGaps).is_none());

        let preserved = if revision == 1 {
            &inert[..]
        } else {
            &inert[..1]
        };
        let paths = [
            RootLayer {
                properties: preserved,
                overrides: &[],
            },
            RootLayer {
                properties: &[],
                overrides: preserved,
            },
            RootLayer {
                properties: preserved,
                overrides: preserved,
            },
        ];
        for end in 1..=paths.len() {
            let result = selected.resolve(&paths[..end], defaults());
            if revision == 3 {
                assert!(result.is_err());
            } else {
                assert_eq!(result.expect("inert at every prefix"), effective);
            }
        }
        // An unfenced newer name never acquires preservation from compiled code.
        if revision == 1 {
            let untrusted = SelectedReadInterpretation::Recorded(Arc::new(association(
                [9; 32],
                [7; 32],
                1,
                &[],
            )));
            assert!(untrusted.resolve(&paths[..1], defaults()).is_err());
        }
    }
    assert_eq!(inert, original);

    // Independent owner binding: false wrapper, uid -> lowercase Node digest.
    let pointer = text(&"ab".repeat(32));
    let mut value = vec![0xa1, 0x63];
    value.extend_from_slice(b"uid");
    value.extend_from_slice(&pointer);
    let mut binding = vec![0xa2, 0x65];
    binding.extend_from_slice(b"value");
    binding.extend_from_slice(&value);
    binding.extend_from_slice(b"\x67inherit\xf4");
    let owner = [Property {
        name: "index-roots",
        value: &binding,
    }];
    let selected =
        SelectedReadInterpretation::Recorded(Arc::new(association([2; 32], [7; 32], 2, &[])));
    let parent = RootLayer {
        properties: &owner,
        overrides: &[],
    };
    let empty = RootLayer {
        properties: &[],
        overrides: &[],
    };
    let own = selected
        .resolve(&[parent], defaults())
        .expect("owner-local binding");
    let Some(Value::IndexRoots(roots)) = own.get(PropertyName::IndexRoots) else {
        panic!("typed roots")
    };
    assert_eq!(roots.get("uid"), Some([0xab; 32]));
    let descendants = selected
        .resolve(&[parent, empty], defaults())
        .expect("does not inherit");
    assert_eq!(
        descendants,
        selected.resolve(&[], defaults()).expect("defaults")
    );
    assert!(
        selected
            .resolve(
                &[RootLayer {
                    properties: &[],
                    overrides: &owner
                }],
                defaults()
            )
            .is_err()
    );
    assert_eq!(owner[0].value, binding);

    let mut gap_binding = vec![0xa2, 0x65];
    gap_binding.extend_from_slice(b"value");
    gap_binding.extend_from_slice(&pointer);
    gap_binding.extend_from_slice(b"\x67inherit\xf4");
    let gaps = [Property {
        name: "index-gaps",
        value: &gap_binding,
    }];
    let active =
        SelectedReadInterpretation::Recorded(Arc::new(association([3; 32], [7; 32], 3, &[])));
    for layer in [
        RootLayer {
            properties: &gaps,
            overrides: &[],
        },
        RootLayer {
            properties: &[],
            overrides: &gaps,
        },
    ] {
        assert!(active.resolve(&[layer], defaults()).is_err());
    }
    assert_eq!(gaps[0].value, gap_binding);

    // Two occurrences share local bytes but retain distinct graft-local policy.
    let shared = SelectedReadInterpretation::Recorded(Arc::new(association(
        [1; 32],
        [7; 32],
        1,
        &["index-gaps", "index-roots"],
    )));
    let left_overrides = [Property {
        name: "retain",
        value: b"\x67forever",
    }];
    let right_overrides = [Property {
        name: "retain",
        value: b"\x62gc",
    }];
    let ancestor = RootLayer {
        properties: &inert,
        overrides: &[],
    };
    let left = shared
        .resolve(
            &[
                ancestor,
                RootLayer {
                    properties: &inert,
                    overrides: &left_overrides,
                },
            ],
            defaults(),
        )
        .expect("first shared-root occurrence");
    let right = shared
        .resolve(
            &[
                ancestor,
                RootLayer {
                    properties: &inert,
                    overrides: &right_overrides,
                },
            ],
            defaults(),
        )
        .expect("second shared-root occurrence");
    assert_eq!(
        left.get(PropertyName::Retain),
        Some(&Value::Text("forever"))
    );
    assert_eq!(right.get(PropertyName::Retain), Some(&Value::Text("gc")));
    assert_eq!(
        shared
            .resolve(&[ancestor], defaults())
            .expect("same-context ancestor"),
        shared
            .resolve(&[], defaults())
            .expect("same-context defaults")
    );
    assert_eq!(inert, original);
    assert_eq!(left_overrides[0].value, b"\x67forever");
    assert_eq!(right_overrides[0].value, b"\x62gc");
}

// Independent primitive CBOR assembly supplies the complete expected context.
fn head(major: u8, value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=255 => output.extend_from_slice(&[(major << 5) | 24, value as u8]),
        256..=65535 => {
            output.push((major << 5) | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            output.push((major << 5) | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
    output
}

#[cfg(feature = "std")]
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut output = head(2, value.len() as u64);
    output.extend_from_slice(value);
    output
}

fn text(value: &str) -> Vec<u8> {
    let mut output = head(3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
    output
}

#[cfg(feature = "std")]
fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut output = head(4, values.len() as u64);
    for value in values {
        output.extend_from_slice(value);
    }
    output
}

#[cfg(feature = "std")]
fn expected_context(view: Digest, root: Digest, revision: u64, later: &[&str]) -> Vec<u8> {
    let mut names = LEGACY_NAMES.to_vec();
    if revision >= 2 {
        names.push("index-roots");
    }
    if revision == 3 {
        names.push("index-gaps");
    }
    names.sort_unstable();
    let mut later = later.to_vec();
    later.sort_unstable();
    array(&[
        head(0, 3),
        bytes(&view),
        text("private:ordinary"),
        bytes(&array(&[text("preset"), text("any")])),
        vec![0xf6],
        head(0, MINIMUM),
        vec![0xf6],
        array(&[
            bytes(&root),
            head(0, revision),
            array(&names.iter().map(|name| text(name)).collect::<Vec<_>>()),
            array(&later.iter().map(|name| text(name)).collect::<Vec<_>>()),
        ]),
    ])
}

#[cfg(feature = "std")]
fn checked_history(
    selection: terrane_format::properties::selected::Selection,
) -> (VerifiedHistory, Digest, Digest) {
    // Empty canonical leaf: {1:0, 2:[], 3:{}}. No invented history flags.
    let wire = vec![0xa3, 1, 0, 2, 0x80, 3, 0xa0];
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &wire)
        .expect("Node identity")
        .terrane_v1_digest()
        .expect("registered identity");
    let mut history = VerifiedHistory::new(MINIMUM);
    history
        .insert_tree(root, &[(root, wire)])
        .expect("canonical complete tree");
    let keys = vec![IssuerKey {
        issuer: "issuer".to_owned(),
        key_id: "issuer-key".to_owned(),
        public_key: auth::public_key_from_secret(&[7; 32]),
        retirement: None,
    }];
    let token = Token::issue(
        Authority {
            issuer: "issuer".to_owned(),
            key_id: "issuer-key".to_owned(),
            subject: "build/baseline".to_owned(),
            kind: PrincipalKind::Workload,
            groups: vec!["baseline".to_owned()],
            not_after: 200,
            not_before: Some(50),
            token_id: [3; 16],
            grants: vec![
                Grant::new(
                    "refs/heads/main".to_owned(),
                    Verbs::new(4).expect("Commit verb"),
                )
                .expect("grant"),
            ],
            workload: Some("workload-identity".to_owned()),
        },
        &[7; 32],
        auth::public_key_from_secret(&[9; 32]),
    )
    .expect("authenticated token");
    let commit = Commit {
        tree: root,
        parents: Vec::new(),
        provenance: Provenance {
            issuer: "issuer".to_owned(),
            token_id: [3; 16],
            subject: "build/baseline".to_owned(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("workload-identity".to_owned()),
            process: "test/sdk".to_owned(),
            observed_at: 100,
            writer_epoch: 4,
            source: CommitSource::Built,
            embedded_token: Some(token.encode()),
        },
        timestamp: 100,
        message: "ordinary fixture".to_owned(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".to_owned(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: None,
    };
    let locality = Locality::default();
    let request = Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &[],
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    };
    let signed = sign(commit, &[9; 32], &keys, &request, 4).expect("signed fixture");
    let verified =
        verify(signed.commit(), &keys, &request, 4).expect("independently verified signature");
    assert_eq!(signed.identity(), verified.identity());
    let view = verified.identity();
    history
        .insert_commit_selected(verified, selection)
        .expect("checked history insertion");
    (history, view, root)
}

#[cfg(feature = "std")]
#[test]
fn selected_read_configuration_constructs_checked_recorded_evaluators() {
    let mut contexts = Vec::new();
    for (revision, later) in [
        (1, vec!["index-roots", "index-gaps"]),
        (2, vec!["index-gaps"]),
        (3, vec![]),
    ] {
        let (history, view, root) =
            checked_history(terrane_format::properties::selected::Selection::Recorded(
                RecordedContext::new(revision, 3, &later).expect("independent selected history"),
            ));
        let guard = Guard::new_with_recorded_views(
            (),
            (),
            Vec::new(),
            config(),
            RecordedAssociations::new([association(view, root, revision, &later)])
                .expect("caller table"),
        );
        let selected = guard
            .property_test_interpretations()
            .select(view, root)
            .expect("actual native selection");
        let trust = selected
            .evaluator(
                &history,
                (view, root),
                Selector::preset(Preset::Any),
                "private:ordinary",
                None,
            )
            .expect("checked recorded constructor");
        assert_eq!(
            trust.canonical_context(),
            expected_context(view, root, revision, &later)
        );
        contexts.push(trust.canonical_context().to_vec());
        for selection in [(view, [9; 32]), ([9; 32], root)] {
            assert!(
                selected
                    .evaluator(
                        &history,
                        selection,
                        Selector::preset(Preset::Any),
                        "private:ordinary",
                        None
                    )
                    .is_err()
            );
        }
        assert!(
            selected
                .evaluator(
                    &VerifiedHistory::new(MINIMUM),
                    (view, root),
                    Selector::preset(Preset::Any),
                    "private:ordinary",
                    None
                )
                .is_err()
        );
        // Even a caller table claiming a wrong association cannot override history.
        let false_root = SelectedReadInterpretation::Recorded(Arc::new(association(
            view, [9; 32], revision, &later,
        )));
        assert!(
            false_root
                .evaluator(
                    &history,
                    (view, [9; 32]),
                    Selector::preset(Preset::Any),
                    "private:ordinary",
                    None
                )
                .is_err()
        );
    }
    assert_ne!(contexts[0], contexts[1]);
    assert_ne!(contexts[1], contexts[2]);
    let (history, view, root) =
        checked_history(terrane_format::properties::selected::Selection::Legacy);
    let legacy = SelectedReadInterpretation::Legacy
        .evaluator(
            &history,
            (view, root),
            Selector::preset(Preset::Any),
            "private:ordinary",
            None,
        )
        .expect("deliberate legacy evaluator");
    assert_ne!(legacy.canonical_context(), contexts[2]);
}
