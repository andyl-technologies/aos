//! Checks ordinary configuration retention through the actual adapter constructor.
//!
//! Caller-supplied tables are data, not authenticated view associations. Marker
//! stores and clocks exercise no protected setup, backend or authority workflow.
#![allow(clippy::expect_used, reason = "independent test data must validate")]

use super::*;
use crate::guard::GuardConfig;
use crate::guard::recorded_properties::SelectedReadInterpretation;
use std::cell::Cell;
use std::rc::Rc;
use terrane_format::auth::IssuerKey;
use terrane_format::chunking::ChunkProfile;
use terrane_format::identity::Digest;
use terrane_format::properties::semantics::{
    RecordedContext,
    associations::{RecordedAssociation, RecordedAssociations},
};
use terrane_format::properties::{Defaults, PropertyName, RootLayer, Value};
use terrane_format::refs::Locality;
use terrane_format::tree_format::Property;

// Frozen revision-one vocabulary, independent of the compiled enumeration.
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

fn config() -> GuardConfig {
    GuardConfig {
        store_name: "ordinary-store".to_owned(),
        private_domain: "private:ordinary".to_owned(),
        home: Locality {
            region: Some("region".to_owned()),
            zone: Some("zone".to_owned()),
            host: Some("host".to_owned()),
        },
        initial_acl: vec![("fixture/reader".to_owned(), 1)],
        min_chunk_size: 262144,
        storage_domain: "public".to_owned(),
        chunk_profile_name: "cdc-1m".to_owned(),
        chunk_profile: Box::new(ChunkProfile::cdc_1m([9; 32])),
        policy_authority: Some("refs/heads/policy".to_owned()),
    }
}

fn keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "ordinary-issuer".to_owned(),
        key_id: "ordinary-key".to_owned(),
        public_key: [5; 32],
        retirement: Some(123),
    }]
}

fn assert_configuration<S, C>(guard: &Guard<S, C>) {
    assert_eq!(guard.keys.len(), 1);
    let key = &guard.keys[0];
    assert_eq!(key.issuer, "ordinary-issuer");
    assert_eq!(key.key_id, "ordinary-key");
    assert_eq!(key.public_key, [5; 32]);
    assert_eq!(key.retirement, Some(123));

    let retained = &guard.config;
    assert_eq!(retained.store_name, "ordinary-store");
    assert_eq!(retained.private_domain, "private:ordinary");
    assert_eq!(retained.home.region.as_deref(), Some("region"));
    assert_eq!(retained.home.zone.as_deref(), Some("zone"));
    assert_eq!(retained.home.host.as_deref(), Some("host"));
    assert_eq!(retained.initial_acl, [("fixture/reader".to_owned(), 1)]);
    assert_eq!(retained.min_chunk_size, 262144);
    assert_eq!(retained.storage_domain, "public");
    assert_eq!(retained.chunk_profile_name, "cdc-1m");
    assert_eq!(*retained.chunk_profile, ChunkProfile::cdc_1m([9; 32]));
    assert_eq!(
        retained.policy_authority.as_deref(),
        Some("refs/heads/policy")
    );

    // The shared data-only constructor never fills protected evidence. Actual
    // held/setup callers preserve their separate existing checked-state steps.
    assert!(
        guard
            .original_verifier
            .read()
            .expect("ordinary lock")
            .is_none()
    );
    assert!(
        guard
            .original_baselines
            .read()
            .expect("ordinary lock")
            .is_empty()
    );
    assert!(
        guard
            .original_commits
            .read()
            .expect("ordinary lock")
            .is_empty()
    );
}

fn association(view: Digest, root: Digest, revision: u64, later: &[&str]) -> RecordedAssociation {
    RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(revision, 3, later).expect("fixed context"),
    )
}

fn assert_selected(
    selected: &SelectedReadInterpretation,
    view: Digest,
    root: Digest,
    revision: u64,
    later: &[&str],
) {
    let SelectedReadInterpretation::Recorded(entry) = selected else {
        panic!("recorded mode must remain explicit")
    };
    assert_eq!(entry.view(), view);
    assert_eq!(entry.original_root(), root);
    assert_eq!(entry.revision(), revision);
    assert_eq!(entry.later_registered(), later);

    let mut expected = LEGACY_NAMES.to_vec();
    if revision >= 2 {
        expected.push("index-roots");
    }
    if revision == 3 {
        expected.push("index-gaps");
    }
    expected.sort_unstable();
    entry
        .with_context(|context| {
            assert_eq!(context.revision(), revision);
            let mut actual = context.behavioral_names().collect::<Vec<_>>();
            actual.sort_unstable();
            assert_eq!(actual, expected);
            assert_eq!(context.later_registered(), later);
        })
        .expect("owned context");
}

#[derive(Clone, Copy)]
enum ExpectedMode {
    Legacy,
    EmptyRecorded,
    CurrentRecorded,
}

fn assert_mode<S, C>(guard: &Guard<S, C>, expected: ExpectedMode, view: Digest, root: Digest) {
    let selection = guard.test_interpretations();
    match expected {
        ExpectedMode::Legacy => {
            assert_eq!(
                guard.interpretation,
                crate::guard::history::completion::InterpretationSelection::Legacy,
            );
            assert_eq!(
                selection.select(view, root).expect("deliberate Legacy"),
                SelectedReadInterpretation::Legacy
            );
        }
        ExpectedMode::EmptyRecorded => {
            assert_eq!(
                guard.interpretation,
                crate::guard::history::completion::InterpretationSelection::Active,
            );
            assert!(selection.select(view, root).is_err());
            assert!(selection.select([9; 32], root).is_err());
        }
        ExpectedMode::CurrentRecorded => {
            assert_eq!(
                guard.interpretation,
                crate::guard::history::completion::InterpretationSelection::Active,
            );
            let selected = selection.select(view, root).expect("explicit current");
            assert_selected(&selected, view, root, 3, &[]);
        }
    }
}

// This adapter is only an assertion facade over the owning Native table. It
// stores no associations and cannot construct protected Original/completion.
struct TestInterpretations<'a, S, C>(&'a Guard<S, C>);

impl<S, C> Guard<S, C> {
    fn test_interpretations(&self) -> TestInterpretations<'_, S, C> {
        TestInterpretations(self)
    }
}

impl<S, C> TestInterpretations<'_, S, C> {
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

#[test]
fn adapter_configuration_preserves_legacy_and_explicit_modes() {
    let view = [1; 32];
    let root = [7; 32];
    // Each branch uses the exact constructor shared by all three production
    // adapters; neither empty data nor explicit current semantics means legacy.
    for (expected, table) in [
        (ExpectedMode::Legacy, None),
        (
            ExpectedMode::EmptyRecorded,
            Some(RecordedAssociations::default()),
        ),
        (
            ExpectedMode::CurrentRecorded,
            Some(
                RecordedAssociations::new([association(view, root, 3, &[])])
                    .expect("current table"),
            ),
        ),
    ] {
        let source = match table {
            None => Guard::new((), (), keys(), config()),
            Some(table) => Guard::new_with_recorded_views((), (), keys(), config(), table),
        };
        let store = Rc::new(String::from("replacement-store"));
        let clock = Rc::new(Cell::new(41));
        let first = source.read_configuration_adapter(Rc::clone(&store), Rc::clone(&clock));
        assert!(Rc::ptr_eq(&first.store, &store));
        assert!(Rc::ptr_eq(&first.clock, &clock));
        assert_configuration(&first);

        let second_store = Rc::new(vec![String::from("second-store")]);
        let second_clock = Rc::new(Cell::new(42));
        let second =
            first.read_configuration_adapter(Rc::clone(&second_store), Rc::clone(&second_clock));
        drop(first);
        assert!(Rc::ptr_eq(&second.store, &second_store));
        assert_eq!(second.store.as_ref(), &[String::from("second-store")]);
        assert!(Rc::ptr_eq(&second.clock, &second_clock));
        assert_eq!(second.clock.get(), 42);
        assert_configuration(&second);

        assert_mode(&second, expected, view, root);
        assert!(source.shares_view_selection_configuration(&second));
        drop(source);
        // The replacement values outlive the source without requiring Send or
        // a backend/Clock implementation; this operation is ordinary data only.
        assert_eq!(second.clock.get(), 42);
        assert_mode(&second, expected, view, root);
    }
}

#[test]
fn adapter_configuration_retains_per_view_fences_and_refuses_missing_pairs() {
    let root = [7; 32];
    let views = [[1; 32], [2; 32], [3; 32]];
    let table = {
        let owned = [
            String::from("é.future"),
            String::from("index-roots"),
            String::from("index-gaps"),
        ];
        let later = owned.iter().map(String::as_str).collect::<Vec<_>>();
        RecordedAssociations::new([
            association(views[0], root, 1, &later),
            association(views[1], root, 2, &["index-gaps"]),
            association(views[2], root, 3, &[]),
        ])
        .expect("distinct views may share physical bytes")
    };
    let source = Guard::new_with_recorded_views((), (), keys(), config(), table);
    let first = source.read_configuration_adapter(Rc::new("first"), Rc::new(Cell::new(1)));
    let second = first.read_configuration_adapter(Rc::new("second"), Rc::new(Cell::new(2)));
    let retained = source
        .test_interpretations()
        .select(views[0], root)
        .expect("source selection");
    second
        .test_interpretations()
        .check_retained(&retained, views[0], root)
        .expect("same complete installation");
    drop(source);
    drop(first);

    for (index, later) in [
        &["index-gaps", "index-roots", "é.future"][..],
        &["index-gaps"][..],
        &[][..],
    ]
    .into_iter()
    .enumerate()
    {
        let selected = second
            .test_interpretations()
            .select(views[index], root)
            .expect("owned per-view selection");
        assert_selected(&selected, views[index], root, index as u64 + 1, later);
        assert!(
            second
                .test_interpretations()
                .select(views[index], [8; 32])
                .is_err()
        );
    }
    assert!(second.test_interpretations().select([9; 32], root).is_err());
    assert!(
        second
            .test_interpretations()
            .check_retained(&retained, views[1], root)
            .is_err()
    );

    for (revision, later) in [
        (1, vec!["index-gaps", "index-roots"]),
        (2, vec!["index-gaps", "é.future"]),
        (3, vec!["é.future"]),
    ] {
        let changed = Guard::new_with_recorded_views(
            (),
            (),
            keys(),
            config(),
            RecordedAssociations::new([association(views[0], root, revision, &later)])
                .expect("independent changed table"),
        );
        let adapter = changed.read_configuration_adapter(Rc::new("changed"), Rc::new(Cell::new(3)));
        assert!(
            adapter
                .test_interpretations()
                .check_retained(&retained, views[0], root)
                .is_err()
        );
    }
    let legacy = Guard::new((), (), keys(), config())
        .read_configuration_adapter(Rc::new("legacy"), Rc::new(Cell::new(4)));
    assert!(
        legacy
            .test_interpretations()
            .check_retained(&retained, views[0], root)
            .is_err()
    );
    assert!(
        second
            .test_interpretations()
            .check_retained(&SelectedReadInterpretation::Legacy, views[0], root)
            .is_err()
    );

    for conflicting in [
        association(
            views[0],
            [8; 32],
            1,
            &["index-gaps", "index-roots", "é.future"],
        ),
        association(views[0], root, 2, &["index-gaps", "é.future"]),
        association(views[0], root, 1, &["index-gaps", "index-roots"]),
    ] {
        assert!(
            RecordedAssociations::new([
                association(
                    views[0],
                    root,
                    1,
                    &["index-gaps", "index-roots", "é.future"]
                ),
                conflicting
            ])
            .is_err()
        );
    }
    for revision in [0, 4] {
        assert!(RecordedContext::new(revision, 3, &[]).is_err());
    }
    assert!(RecordedContext::new(1, 3, &["future", "future"]).is_err());
    assert!(RecordedContext::new(1, 3, &["domain"]).is_err());
}

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "ordinary-store",
        private_domain: "private:ordinary",
        home: "region",
    }
}

#[test]
fn adapter_configuration_preserves_recorded_graft_semantics() {
    let root = [7; 32];
    let view = [1; 32];
    // Canonical zero is physical data, but invalid active pointer syntax. A
    // recognized later name must still remain inert under a retained revision.
    let inert = [Property {
        name: "index-roots",
        value: b"\x00",
    }];
    let left = [Property {
        name: "retain",
        value: b"\x67forever",
    }];
    let right = [Property {
        name: "retain",
        value: b"\x62gc",
    }];
    let original = (inert, left, right);
    for revision in 1..=3 {
        let later: &[&str] = if revision == 1 { &["index-roots"] } else { &[] };
        let source = Guard::new_with_recorded_views(
            (),
            (),
            keys(),
            config(),
            RecordedAssociations::new([association(view, root, revision, later)])
                .expect("configured revision"),
        );
        let adapter = source
            .read_configuration_adapter(Rc::new("first"), Rc::new(Cell::new(1)))
            .read_configuration_adapter(Rc::new("second"), Rc::new(Cell::new(2)));
        drop(source);
        let selected = adapter
            .test_interpretations()
            .select(view, root)
            .expect("retained interpretation");
        let parent = RootLayer {
            properties: &inert,
            overrides: &[],
        };
        let left_path = [
            parent,
            RootLayer {
                properties: &inert,
                overrides: &left,
            },
        ];
        let right_path = [
            parent,
            RootLayer {
                properties: &inert,
                overrides: &right,
            },
        ];
        if revision == 1 {
            let left_result = selected
                .resolve(&left_path, defaults())
                .expect("first occurrence stays inert");
            let right_result = selected
                .resolve(&right_path, defaults())
                .expect("second occurrence stays inert");
            assert_eq!(
                left_result.get(PropertyName::Retain),
                Some(&Value::Text("forever"))
            );
            assert_eq!(
                right_result.get(PropertyName::Retain),
                Some(&Value::Text("gc"))
            );
            assert_eq!(
                selected.resolve(&[parent], defaults()).expect("ancestor"),
                selected.resolve(&[], defaults()).expect("defaults")
            );
        } else {
            assert!(selected.resolve(&left_path, defaults()).is_err());
            assert!(selected.resolve(&right_path, defaults()).is_err());
        }
    }
    assert_eq!((inert, left, right), original);

    // Exact independent false wrapper binds uid to a lowercase Node digest.
    let mut binding = b"\xa2\x65value\xa1\x63uid\x78\x40".to_vec();
    binding.extend_from_slice("ab".repeat(32).as_bytes());
    binding.extend_from_slice(b"\x67inherit\xf4");
    let owners = [Property {
        name: "index-roots",
        value: &binding,
    }];
    for revision in 1..=3 {
        let later: &[&str] = if revision == 1 { &["index-roots"] } else { &[] };
        let adapter = Guard::new_with_recorded_views(
            (),
            (),
            keys(),
            config(),
            RecordedAssociations::new([association(view, root, revision, later)])
                .expect("configured owner"),
        )
        .read_configuration_adapter(Rc::new("owner"), Rc::new(Cell::new(1)));
        let selected = adapter
            .test_interpretations()
            .select(view, root)
            .expect("retained owner mode");
        let local = selected
            .resolve(
                &[RootLayer {
                    properties: &owners,
                    overrides: &[],
                }],
                defaults(),
            )
            .expect("local binding");
        let graft = [RootLayer {
            properties: &[],
            overrides: &owners,
        }];
        if revision == 1 {
            assert_eq!(
                local,
                selected.resolve(&[], defaults()).expect("inert defaults")
            );
            assert!(selected.resolve(&graft, defaults()).is_ok());
        } else {
            let Some(Value::IndexRoots(roots)) = local.get(PropertyName::IndexRoots) else {
                panic!("active owner binding")
            };
            assert_eq!(roots.get("uid"), Some([0xab; 32]));
            assert!(selected.resolve(&graft, defaults()).is_err());
            assert_eq!(
                selected
                    .resolve(
                        &[
                            RootLayer {
                                properties: &owners,
                                overrides: &[]
                            },
                            RootLayer {
                                properties: &[],
                                overrides: &[]
                            }
                        ],
                        defaults()
                    )
                    .expect("owner pointer does not inherit"),
                selected.resolve(&[], defaults()).expect("defaults")
            );
        }
        assert_eq!(owners[0].value, binding);
    }

    let gaps = [Property {
        name: "index-gaps",
        value: b"\x00",
    }];
    for revision in 1..=3 {
        let later: &[&str] = if revision < 3 { &["index-gaps"] } else { &[] };
        let adapter = Guard::new_with_recorded_views(
            (),
            (),
            keys(),
            config(),
            RecordedAssociations::new([association(view, root, revision, later)])
                .expect("configured gaps"),
        )
        .read_configuration_adapter(Rc::new("gaps"), Rc::new(Cell::new(1)));
        let selected = adapter
            .test_interpretations()
            .select(view, root)
            .expect("retained gaps mode");
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
            let result = selected.resolve(&[layer], defaults());
            if revision < 3 {
                let resolved = result.expect("later gap metadata remains inert");
                assert_eq!(
                    resolved,
                    selected
                        .resolve(&[], defaults())
                        .expect("namespace defaults")
                );
                assert!(resolved.get(PropertyName::IndexGaps).is_none());
            } else {
                assert!(result.is_err());
            }
        }
        assert_eq!(gaps[0].value, b"\x00");
    }
}
