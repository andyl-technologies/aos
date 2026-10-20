//! Checks data-only replacement adapters against the actual shared production constructor.
//!
//! Marker stores and clocks establish configuration ownership only. No signed
//! view, protected Original record, native backend or permission is manufactured.

use super::*;
use crate::guard::GuardConfig;
use std::cell::Cell;
use std::rc::Rc;
use terrane_format::auth::IssuerKey;
use terrane_format::chunking::ChunkProfile;
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::properties::{Defaults, PropertyName, RootLayer, Value};
use terrane_format::refs::Locality;
use terrane_format::tree_format::Property;

type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;

// Fixed historical vocabulary is independent of the current compiled registry.
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
        store_name: "ordinary-store".into(),
        private_domain: "private:ordinary".into(),
        home: Locality {
            region: Some("region".into()),
            zone: Some("zone".into()),
            host: Some("host".into()),
        },
        initial_acl: vec![("fixture/reader".into(), 1)],
        min_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: Box::new(ChunkProfile::cdc_1m([9; 32])),
        policy_authority: Some("refs/heads/policy".into()),
    }
}

fn keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "ordinary-issuer".into(),
        key_id: "ordinary-key".into(),
        public_key: [5; 32],
        retirement: Some(123),
    }]
}

fn entry(view: Digest, root: Digest, revision: u64, later: &[&str]) -> TestResult<ViewSelection> {
    Ok(ViewSelection::new(
        view,
        root,
        Selection::Recorded(RecordedContext::new(revision, 3, later)?),
        1,
    )?)
}

fn installed(entries: Vec<ViewSelection>) -> TestResult<Guard<(), ()>> {
    Ok(Guard::new((), (), keys(), config())
        .with_recorded_authoring(RecordedContext::new(3, 3, &[])?, 2)?
        .with_view_selections(entries)?)
}

fn selected<S, C>(guard: &Guard<S, C>, view: Digest, root: Digest) -> TestResult<SelectedInputs> {
    Ok(guard.selected_view_inputs(view, root, HistoryObservation::default())?)
}

fn assert_configuration<S, C>(guard: &Guard<S, C>) -> TestResult {
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

    // The shared configuration constructor cannot manufacture protected trust.
    assert!(
        guard
            .original_verifier
            .read()
            .map_err(|_| "poisoned ordinary verifier state")?
            .is_none()
    );
    assert!(
        guard
            .original_baselines
            .read()
            .map_err(|_| "poisoned ordinary baseline state")?
            .is_empty()
    );
    assert!(
        guard
            .original_commits
            .read()
            .map_err(|_| "poisoned ordinary commit state")?
            .is_empty()
    );
    Ok(())
}

fn assert_recorded(inputs: &SelectedInputs, revision: u64, later: &[&str]) -> TestResult {
    let Selection::Recorded(context) = &inputs.selection else {
        return Err("explicit Recorded adapter became Legacy or latest Active".into());
    };
    assert_eq!(context.revision(), revision);
    assert_eq!(context.current_revision(), 3);
    assert_eq!(context.later_registered(), later);
    let mut names = LEGACY_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if revision >= 2 {
        names.push("index-roots".into());
    }
    if revision >= 3 {
        names.push("index-gaps".into());
    }
    names.sort();
    assert_eq!(
        context.behavioral_names().collect::<Vec<_>>(),
        names.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_eq!(inputs.registries.property_revision, revision);
    assert_eq!(inputs.registries.behavioral_properties, names);
    assert_eq!(inputs.registries.later_properties, later);
    assert_eq!(inputs.registries.attribute_revision, 1);
    Ok(())
}

enum Mode {
    Legacy,
    MissingRecorded,
    CurrentRecorded,
}

#[test]
fn adapter_configuration_preserves_legacy_and_explicit_modes() -> TestResult {
    let view = [1; 32];
    let root = [7; 32];
    for (mode, source) in [
        (Mode::Legacy, Guard::new((), (), keys(), config())),
        (Mode::MissingRecorded, installed(Vec::new())?),
        (
            Mode::CurrentRecorded,
            installed(vec![entry(view, root, 3, &[])?])?,
        ),
    ] {
        let store = Rc::new(String::from("replacement-store"));
        let clock = Rc::new(Cell::new(41));
        let first = source.configuration_adapter(Rc::clone(&store), Rc::clone(&clock));
        assert!(Rc::ptr_eq(&first.store, &store));
        assert!(Rc::ptr_eq(&first.clock, &clock));
        assert_configuration(&first)?;
        let second_store = Rc::new(vec![String::from("second-store")]);
        let second_clock = Rc::new(Cell::new(42));
        let second =
            first.configuration_adapter(Rc::clone(&second_store), Rc::clone(&second_clock));
        drop(first);
        assert!(Rc::ptr_eq(&second.store, &second_store));
        assert_eq!(second.store.as_ref(), &[String::from("second-store")]);
        assert!(Rc::ptr_eq(&second.clock, &second_clock));
        assert_eq!(second.clock.get(), 42);
        assert_configuration(&second)?;
        assert!(Arc::ptr_eq(
            &source.view_selections.installed,
            &second.view_selections.installed
        ));
        let before = selected(&source, view, root);
        drop(source);
        assert_eq!(second.clock.get(), 42);
        match mode {
            Mode::Legacy => {
                assert_eq!(before?.selection, Selection::Legacy);
                assert_eq!(selected(&second, view, root)?.selection, Selection::Legacy);
            }
            Mode::MissingRecorded => {
                assert!(before.is_err());
                assert!(selected(&second, view, root).is_err());
                assert!(selected(&second, [9; 32], root).is_err());
            }
            Mode::CurrentRecorded => {
                let before = before?;
                assert_recorded(&before, 3, &[])?;
                assert_eq!(selected(&second, view, root)?, before);
            }
        }
    }
    Ok(())
}

#[test]
fn adapter_configuration_retains_per_view_fences_and_refuses_missing_pairs() -> TestResult {
    let root = [7; 32];
    let views = [[1; 32], [2; 32], [3; 32]];
    let entries = {
        let owned = [
            String::from("index-gaps"),
            String::from("index-roots"),
            String::from("é.future"),
        ];
        let later = owned.iter().map(String::as_str).collect::<Vec<_>>();
        vec![
            entry(views[0], root, 1, &later)?,
            entry(views[1], root, 2, &["index-gaps"])?,
            entry(views[2], root, 3, &[])?,
        ]
    };
    let source = installed(entries)?;
    let first = source.configuration_adapter(Rc::new("first"), Rc::new(Cell::new(1)));
    let second = first.configuration_adapter(Rc::new("second"), Rc::new(Cell::new(2)));
    let retained = selected(&source, views[0], root)?;
    assert_eq!(selected(&second, views[0], root)?, retained);
    drop(source);
    drop(first);
    assert_configuration(&second)?;
    for (index, later) in [
        &["index-gaps", "index-roots", "é.future"][..],
        &["index-gaps"][..],
        &[][..],
    ]
    .into_iter()
    .enumerate()
    {
        assert_recorded(
            &selected(&second, views[index], root)?,
            index as u64 + 1,
            later,
        )?;
        assert!(selected(&second, views[index], [8; 32]).is_err());
    }
    assert!(selected(&second, [9; 32], root).is_err());
    assert_ne!(selected(&second, views[1], root)?, retained);
    for (revision, later) in [
        (1, vec!["index-gaps", "index-roots"]),
        (2, vec!["index-gaps", "é.future"]),
        (3, vec!["é.future"]),
    ] {
        let changed = installed(vec![entry(views[0], root, revision, &later)?])?;
        let adapter = changed.configuration_adapter(Rc::new("changed"), Rc::new(Cell::new(3)));
        assert_ne!(selected(&adapter, views[0], root)?, retained);
    }
    let legacy = Guard::new((), (), keys(), config())
        .configuration_adapter(Rc::new("legacy"), Rc::new(Cell::new(4)));
    assert_ne!(selected(&legacy, views[0], root)?, retained);
    assert_ne!(
        selected(&second, views[0], root)?.selection,
        Selection::Legacy
    );
    for conflicting in [
        entry(
            views[0],
            [8; 32],
            1,
            &["index-gaps", "index-roots", "é.future"],
        )?,
        entry(views[0], root, 2, &["index-gaps", "é.future"])?,
        entry(views[0], root, 1, &["index-gaps", "index-roots"])?,
    ] {
        assert!(
            installed(vec![
                entry(
                    views[0],
                    root,
                    1,
                    &["index-gaps", "index-roots", "é.future"]
                )?,
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
    Ok(())
}

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "ordinary-store",
        private_domain: "private:ordinary",
        home: "local",
    }
}

#[test]
fn adapter_configuration_preserves_recorded_graft_semantics() -> TestResult {
    let root = [7; 32];
    let view = [1; 32];
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
        let source = installed(vec![entry(view, root, revision, later)?])?;
        let adapter = source
            .configuration_adapter(Rc::new("first"), Rc::new(Cell::new(1)))
            .configuration_adapter(Rc::new("second"), Rc::new(Cell::new(2)));
        drop(source);
        let selected = selected(&adapter, view, root)?.selection;
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
            assert_eq!(
                selected
                    .resolve(&left_path, defaults())?
                    .get(PropertyName::Retain),
                Some(&Value::Text("forever"))
            );
            assert_eq!(
                selected
                    .resolve(&right_path, defaults())?
                    .get(PropertyName::Retain),
                Some(&Value::Text("gc"))
            );
            assert_eq!(
                selected.resolve(&[parent], defaults())?,
                selected.resolve(&[], defaults())?
            );
        } else {
            assert!(selected.resolve(&left_path, defaults()).is_err());
            assert!(selected.resolve(&right_path, defaults()).is_err());
        }
    }
    assert_eq!((inert, left, right), original);
    let mut binding = b"\xa2\x65value\xa1\x63uid\x78\x40".to_vec();
    binding.extend_from_slice("ab".repeat(32).as_bytes());
    binding.extend_from_slice(b"\x67inherit\xf4");
    let owners = [Property {
        name: "index-roots",
        value: &binding,
    }];
    for revision in 1..=3 {
        let later: &[&str] = if revision == 1 { &["index-roots"] } else { &[] };
        let adapter = installed(vec![entry(view, root, revision, later)?])?
            .configuration_adapter(Rc::new("owner"), Rc::new(Cell::new(1)));
        let selected = selected(&adapter, view, root)?.selection;
        let local = selected.resolve(
            &[RootLayer {
                properties: &owners,
                overrides: &[],
            }],
            defaults(),
        )?;
        let graft = [RootLayer {
            properties: &[],
            overrides: &owners,
        }];
        if revision == 1 {
            assert_eq!(local, selected.resolve(&[], defaults())?);
            assert!(selected.resolve(&graft, defaults()).is_ok());
        } else {
            assert_eq!(
                local
                    .active_index_roots()
                    .ok_or("active local owner binding absent")?
                    .get("uid"),
                Some([0xab; 32])
            );
            assert!(selected.resolve(&graft, defaults()).is_err());
            assert_eq!(
                selected.resolve(
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
                )?,
                selected.resolve(&[], defaults())?
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
        let adapter = installed(vec![entry(view, root, revision, later)?])?
            .configuration_adapter(Rc::new("gaps"), Rc::new(Cell::new(1)));
        let selected = selected(&adapter, view, root)?.selection;
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
                assert_eq!(result?, selected.resolve(&[], defaults())?);
            } else {
                assert!(result.is_err());
            }
        }
        assert_eq!(gaps[0].value, b"\x00");
    }
    Ok(())
}

#[test]
fn explicit_read_configuration_refuses_missing_view_root_and_mode_mismatches() -> TestResult {
    let view = [1; 32];
    let root = [7; 32];
    let entries = {
        let owned = [String::from("index-roots"), String::from("é.future")];
        let later = owned.iter().map(String::as_str).collect::<Vec<_>>();
        vec![entry(view, root, 1, &later)?, entry([2; 32], root, 3, &[])?]
    };
    let copied = entries.clone();
    let guard = installed(entries)?;
    let retained = selected(&guard, view, root)?;
    assert_recorded(&retained, 1, &["index-roots", "é.future"])?;
    assert!(selected(&guard, [9; 32], root).is_err());
    assert!(selected(&guard, view, [8; 32]).is_err());
    assert!(selected(&installed(Vec::new())?, view, root).is_err());
    let equivalent = installed(copied)?;
    assert_eq!(selected(&equivalent, view, root)?, retained);
    let legacy = Guard::new((), (), Vec::new(), config());
    assert_ne!(selected(&legacy, view, root)?.selection, retained.selection);
    assert_ne!(selected(&guard, view, root)?.selection, Selection::Legacy);
    assert_ne!(
        selected(
            &installed(vec![entry(view, root, 2, &["é.future"])?])?,
            view,
            root
        )?,
        retained
    );
    assert_ne!(
        selected(
            &installed(vec![entry(view, root, 1, &["index-roots"])?])?,
            view,
            root
        )?,
        retained
    );
    assert_ne!(selected(&guard, [2; 32], root)?, retained);
    for conflicting in [
        entry(view, root, 2, &[])?,
        entry(view, [8; 32], 1, &["index-roots"])?,
        entry(view, root, 1, &["index-gaps", "index-roots"])?,
    ] {
        assert!(installed(vec![entry(view, root, 1, &["index-roots"])?, conflicting]).is_err());
    }
    for revision in [0, 4] {
        assert!(RecordedContext::new(revision, 3, &[]).is_err());
    }
    assert!(RecordedContext::new(1, 3, &["future", "future"]).is_err());
    Ok(())
}

#[test]
fn retained_read_configuration_preserves_fixed_graft_interpretations() -> TestResult {
    let inert = [
        Property {
            name: "index-gaps",
            value: b"\x00",
        },
        Property {
            name: "index-roots",
            value: b"\x00",
        },
    ];
    let original = inert;
    for revision in 1..=3 {
        let later: &[&str] = match revision {
            1 => &["index-gaps", "index-roots"],
            2 => &["index-gaps"],
            _ => &[],
        };
        let guard = installed(vec![entry([revision as u8; 32], [7; 32], revision, later)?])?;
        let owned = selected(&guard, [revision as u8; 32], [7; 32])?;
        assert_recorded(&owned, revision, later)?;
        drop(guard);
        let selection = owned.selection;
        let effective = selection.resolve(&[], defaults())?;
        for name in LEGACY_NAMES {
            assert!(effective.get(PropertyName::parse(name)?).is_some());
        }
        assert!(effective.active_index_roots().is_none());
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
            let result = selection.resolve(&paths[..end], defaults());
            if revision == 3 {
                assert!(result.is_err());
            } else {
                assert_eq!(result?, effective);
            }
        }
        if revision == 1 {
            let untrusted = selected(
                &installed(vec![entry([9; 32], [7; 32], 1, &[])?])?,
                [9; 32],
                [7; 32],
            )?
            .selection;
            assert!(untrusted.resolve(&paths[..1], defaults()).is_err());
        }
    }
    assert_eq!(inert, original);
    // The same actual adapter rules also check local binding, noninheritance,
    // graft placement, namespace gaps and distinct repeated-root retain values.
    adapter_configuration_preserves_recorded_graft_semantics()?;
    Ok(())
}
